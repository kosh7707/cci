/*
 * cci_core_ref.inc — Pure-SW CCI encrypt/decrypt (no OpenSSL)
 *
 * Include this file after:
 *   #define CCI_KEY_BYTES  16 or 32
 *   #include "aes_portable.inc"
 *
 * For SHA-256 hash:
 *   #include "sha256_portable.inc"
 *   (do NOT define CCI_USE_BLAKE3)
 *
 * For BLAKE3 hash:
 *   #define CCI_USE_BLAKE3 1
 *   #include "blake3.h"
 *   (sha256_portable.inc not needed)
 *
 * Hash input:  M = pad32(|A|) || A || pad32(|P|) || P || n2
 * CTR IV:      n1 || 0x00000001
 * Tag:         T = H(M)[0..15] XOR keystream[|P|..|P|+15]
 */

#include <string.h>
#include <stdlib.h>
#include "crypto_aead.h"

/* ---- helpers ---- */

static void pad32_be(unsigned char out[4], unsigned long long v)
{
  out[0] = (unsigned char)(v >> 24);
  out[1] = (unsigned char)(v >> 16);
  out[2] = (unsigned char)(v >> 8);
  out[3] = (unsigned char)(v);
}

static int ct_eq(const unsigned char *x, const unsigned char *y, size_t n)
{
  unsigned int r = 0;
  size_t i;
  for (i = 0; i < n; ++i) r |= (unsigned int)(x[i] ^ y[i]);
  r = (r | (0U - r)) >> 31;
  return -(int)r;
}

static int regions_overlap(const unsigned char *a, size_t alen,
                           const unsigned char *b, size_t blen)
{
  const unsigned char *ae, *be;
  if (alen == 0 || blen == 0) return 0;
  ae = a + alen;
  be = b + blen;
  return !(ae <= b || be <= a);
}

/* ---- hash helpers ---- */

#if defined(CCI_USE_BLAKE3) && CCI_USE_BLAKE3

static void cci_hash16(
  unsigned char out16[16],
  const unsigned char *ad, unsigned long long adlen,
  const unsigned char *p, unsigned long long plen,
  const unsigned char *n2)
{
  unsigned char pad[4], full[32];
  blake3_hasher bh;
  blake3_hasher_init(&bh);
  pad32_be(pad, adlen); blake3_hasher_update(&bh, pad, 4);
  if (adlen) blake3_hasher_update(&bh, ad, (size_t)adlen);
  pad32_be(pad, plen); blake3_hasher_update(&bh, pad, 4);
  if (plen) blake3_hasher_update(&bh, p, (size_t)plen);
  blake3_hasher_update(&bh, n2, 16);
  blake3_hasher_finalize(&bh, full);
  memcpy(out16, full, 16);
}

#else /* SHA-256 */

static void cci_hash16(
  unsigned char out16[16],
  const unsigned char *ad, unsigned long long adlen,
  const unsigned char *p, unsigned long long plen,
  const unsigned char *n2)
{
  unsigned char pad[4], full[32];
  sha256_state st;
  sha256_init(&st);
  pad32_be(pad, adlen); sha256_update(&st, pad, 4);
  if (adlen) sha256_update(&st, ad, (size_t)adlen);
  pad32_be(pad, plen); sha256_update(&st, pad, 4);
  if (plen) sha256_update(&st, p, (size_t)plen);
  sha256_update(&st, n2, 16);
  sha256_final(&st, full);
  memcpy(out16, full, 16);
}

#endif

/* ================================================================== */
/* encrypt                                                            */
/* ================================================================== */

int crypto_aead_encrypt(
  unsigned char *c, unsigned long long *clen,
  const unsigned char *m, unsigned long long mlen,
  const unsigned char *ad, unsigned long long adlen,
  const unsigned char *nsec,
  const unsigned char *npub,
  const unsigned char *k
)
{
  unsigned char iv[16];
  unsigned char hbuf[16];
  unsigned char tmask[16];
  int i;
  (void)nsec;

  memcpy(iv, npub, 12);
  iv[12] = 0; iv[13] = 0; iv[14] = 0; iv[15] = 1;

  unsigned char n2_local[16];
  memcpy(n2_local, npub + 12, 16);

  /* Hash plaintext */
  cci_hash16(hbuf, ad, adlen, m, mlen, n2_local);

  /* CTR encrypt plaintext + generate tag mask */
  aes_ctr_encrypt(m, c, (size_t)mlen, tmask, k, iv);

  /* Tag = hash XOR tmask */
  for (i = 0; i < 16; ++i) c[mlen + i] = (unsigned char)(hbuf[i] ^ tmask[i]);
  *clen = mlen + 16;

  return 0;
}

/* ================================================================== */
/* decrypt                                                            */
/* ================================================================== */

int crypto_aead_decrypt(
  unsigned char *m, unsigned long long *mlen,
  unsigned char *nsec,
  const unsigned char *c, unsigned long long clen,
  const unsigned char *ad, unsigned long long adlen,
  const unsigned char *npub,
  const unsigned char *k
)
{
  unsigned char iv[16];
  unsigned char tmask[16];
  unsigned char calc[16], tag[16];
  unsigned long long plen;
  unsigned char *dst;
  unsigned char *ptmp = 0;
  int need_safe, i;
  (void)nsec;

  if (clen < 16) return -1;
  plen = clen - 16;

  memcpy(iv, npub, 12);
  iv[12] = 0; iv[13] = 0; iv[14] = 0; iv[15] = 1;

  unsigned char n2_save[16];
  memcpy(n2_save, npub + 12, 16);

  need_safe = regions_overlap(m, (size_t)plen, ad, (size_t)adlen)
           || regions_overlap(m, (size_t)plen, c, (size_t)clen)
           || regions_overlap(m, (size_t)plen, npub, 28);

  dst = m;
  if (need_safe && plen) {
    ptmp = (unsigned char *)malloc((size_t)plen);
    if (!ptmp) return -1;
    dst = ptmp;
  }

  /* CTR decrypt + generate tag mask */
  aes_ctr_encrypt(c, dst, (size_t)plen, tmask, k, iv);

  /* Hash decrypted plaintext */
  cci_hash16(calc, ad, adlen, dst, plen, n2_save);

  /* Verify tag */
  for (i = 0; i < 16; ++i) tag[i] = (unsigned char)(c[plen + i] ^ tmask[i]);
  if (ct_eq(tag, calc, 16) != 0) {
    if (ptmp) free(ptmp);
    return -1;
  }

  if (ptmp && plen) memcpy(m, ptmp, (size_t)plen);
  if (ptmp) free(ptmp);
  *mlen = plen;

  return 0;
}
