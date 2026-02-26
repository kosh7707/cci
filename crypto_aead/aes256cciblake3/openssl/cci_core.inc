/*
 * cci_core.inc — Parameterized CCI encrypt/decrypt (one-pass)
 *
 * Include this file after defining:
 *   CCI_KEY_BYTES   — 16 or 32
 *   CCI_KEY_BITS    — 128 or 256
 *   CCI_CTR_EVP     — EVP_aes_128_ctr or EVP_aes_256_ctr
 *
 * For EVP-based hashes, also define:
 *   CCI_HASH_FN     — e.g. EVP_sha256
 *
 * For BLAKE3, define:
 *   CCI_USE_BLAKE3  — 1
 *   (and include blake3.h before this file)
 *
 * Hash input:  M = pad32(|A|) || A || pad32(|P|) || P || n2
 * CTR IV:      n1 || 0x00000001
 * Tag:         T = H(M)[0..15] XOR keystream[|P|..|P|+15]
 *
 * Three performance tiers:
 *
 * 1. FAST PATH (hash input ≤ 576B):
 *    Build hash input contiguously on the stack → single EVP_Digest()
 *    or blake3_default_hash() call.  Eliminates EVP_MD_CTX alloc/free
 *    overhead and reduces 5 DigestUpdate calls to 0.
 *
 * 2. SMALL CTR + STREAMING HASH (mlen ≤ 64, large AD):
 *    Streaming EVP_DigestInit/Update/Final + low-level AES CTR.
 *
 * 3. ONE-PASS INTERLEAVED (mlen > 64):
 *    Hash and CTR interleaved chunk-by-chunk for cache locality.
 *    EVP CTR for AES-NI pipelining (aesni_ctr32_encrypt_blocks).
 *    BLAKE3 uses streaming hasher API (no malloc buffer).
 */

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/modes.h>
#include <string.h>
#include <stdlib.h>
#include "crypto_aead.h"

/* Chunk size for interleaved hash+CTR processing. */
#define CCI_CHUNK 4096

/* Maximum hash input size for the stack-buffer fast path.
 * hash_input = 4 + adlen + 4 + mlen + 16 = adlen + mlen + 24.
 * 576B covers mlen≤64 with adlen≤488 (all practical TLS cases). */
#define CCI_FAST_HASH_MAX 576

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
  for (size_t i = 0; i < n; ++i) r |= (unsigned int)(x[i] ^ y[i]);
  r = (r | (0U - r)) >> 31;
  return -(int)r;
}

static int regions_overlap(const unsigned char *a, size_t alen,
                           const unsigned char *b, size_t blen)
{
  if (alen == 0 || blen == 0) return 0;
  const unsigned char *ae = a + alen, *be = b + blen;
  return !(ae <= b || be <= a);
}

/* Build contiguous hash input on a pre-allocated buffer.
 * Returns the total length written. */
static size_t build_hash_input(
  unsigned char *buf,
  const unsigned char *ad, unsigned long long adlen,
  const unsigned char *p, unsigned long long plen,
  const unsigned char *n2)
{
  size_t pos = 0;
  pad32_be(buf + pos, adlen); pos += 4;
  if (adlen) { memcpy(buf + pos, ad, (size_t)adlen); pos += (size_t)adlen; }
  pad32_be(buf + pos, plen); pos += 4;
  if (plen) { memcpy(buf + pos, p, (size_t)plen); pos += (size_t)plen; }
  memcpy(buf + pos, n2, 16); pos += 16;
  return pos;
}

/* One-shot hash → first 16 bytes of digest. */
#if !defined(CCI_USE_BLAKE3) || !CCI_USE_BLAKE3
static int hash_oneshot16(const unsigned char *in, size_t inlen,
                          unsigned char out16[16])
{
  unsigned char full[EVP_MAX_MD_SIZE]; unsigned int olen = 0;
  if (!EVP_Digest(in, inlen, full, &olen, CCI_HASH_FN(), 0)) return -1;
  memcpy(out16, full, 16);
  return 0;
}
#endif

#if defined(CCI_USE_BLAKE3) && CCI_USE_BLAKE3
static void blake3_hash16(const unsigned char *in, size_t inlen,
                          unsigned char out16[16])
{
  unsigned char out32[32];
  blake3_default_hash(in, inlen, out32);
  memcpy(out16, out32, 16);
}
#endif

/* ---- low-level CTR helper (small messages ≤64B) ---- */

static void ctr_small(
  const unsigned char *in, unsigned char *out, size_t len,
  unsigned char tmask[16],
  const unsigned char *k, const unsigned char iv[16])
{
  AES_KEY aeskey;
  AES_set_encrypt_key(k, CCI_KEY_BITS, &aeskey);
  unsigned char ivec[16]; memcpy(ivec, iv, 16);
  unsigned char ecount_buf[16]; memset(ecount_buf, 0, sizeof ecount_buf);
  unsigned int num = 0;
  if (len) CRYPTO_ctr128_encrypt(in, out, len, &aeskey, ivec, ecount_buf, &num, (block128_f)AES_encrypt);
  CRYPTO_ctr128_encrypt((const unsigned char *)"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                        tmask, 16, &aeskey, ivec, ecount_buf, &num, (block128_f)AES_encrypt);
}

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
  (void)nsec;
  int result = 0;
  EVP_CIPHER_CTX *ctr = 0;
  unsigned char iv[16];
  unsigned char hbuf[16];
  unsigned char tmask[16];

  if (adlen > 536870912) goto error;
  if (mlen > 536870912) goto error;

  memcpy(iv, npub, 12);
  iv[12] = 0; iv[13] = 0; iv[14] = 0; iv[15] = 1;

  unsigned char n2_local[16];
  memcpy(n2_local, npub + 12, 16);

  {
    size_t hash_total = (size_t)adlen + (size_t)mlen + 24;

    if (hash_total <= CCI_FAST_HASH_MAX && mlen <= 64) {
      /* ============================================================ */
      /* FAST PATH: stack buffer + one-shot hash + low-level CTR      */
      /* ============================================================ */
      unsigned char hm[CCI_FAST_HASH_MAX];
      size_t hm_len = build_hash_input(hm, ad, adlen, m, mlen, n2_local);

#if defined(CCI_USE_BLAKE3) && CCI_USE_BLAKE3
      blake3_hash16(hm, hm_len, hbuf);
#else
      if (hash_oneshot16(hm, hm_len, hbuf) != 0) goto error;
#endif

      ctr_small(m, c, (size_t)mlen, tmask, k, iv);

    } else if (mlen <= 64) {
      /* ============================================================ */
      /* SMALL CTR + large AD: streaming hash, low-level CTR          */
      /* ============================================================ */
#if defined(CCI_USE_BLAKE3) && CCI_USE_BLAKE3
      blake3_hasher bh;
      blake3_hasher_init(&bh);
      { unsigned char pad[4]; pad32_be(pad, adlen);
        blake3_hasher_update(&bh, pad, 4); }
      if (adlen) blake3_hasher_update(&bh, ad, (size_t)adlen);
      { unsigned char pad[4]; pad32_be(pad, mlen);
        blake3_hasher_update(&bh, pad, 4); }
      if (mlen) blake3_hasher_update(&bh, m, (size_t)mlen);
      blake3_hasher_update(&bh, n2_local, 16);
      { unsigned char out32[32];
        blake3_hasher_finalize(&bh, out32); memcpy(hbuf, out32, 16); }
#else
      unsigned char pad[4];
      EVP_MD_CTX *hctx = EVP_MD_CTX_new();
      if (!hctx) goto error;
      if (!EVP_DigestInit_ex(hctx, CCI_HASH_FN(), 0)) { EVP_MD_CTX_free(hctx); goto error; }
      pad32_be(pad, adlen); EVP_DigestUpdate(hctx, pad, 4);
      if (adlen) EVP_DigestUpdate(hctx, ad, (size_t)adlen);
      pad32_be(pad, mlen); EVP_DigestUpdate(hctx, pad, 4);
      if (mlen) EVP_DigestUpdate(hctx, m, (size_t)mlen);
      EVP_DigestUpdate(hctx, n2_local, 16);
      { unsigned char full[EVP_MAX_MD_SIZE]; unsigned int olen = 0;
        EVP_DigestFinal_ex(hctx, full, &olen); memcpy(hbuf, full, 16); }
      EVP_MD_CTX_free(hctx);
#endif

      ctr_small(m, c, (size_t)mlen, tmask, k, iv);

    } else {
      /* ============================================================ */
      /* LARGE PATH: one-pass interleaved hash + EVP CTR              */
      /* Uses EVP CTR for AES-NI pipelining performance.              */
      /* ============================================================ */
      int outlen = 0;
      static const unsigned char z16[16] = {0};

      ctr = EVP_CIPHER_CTX_new(); if (!ctr) goto error;
      if (!EVP_EncryptInit_ex(ctr, CCI_CTR_EVP(), 0, 0, 0)) goto error;
      if (!EVP_EncryptInit_ex(ctr, 0, 0, k, iv)) goto error;

#if defined(CCI_USE_BLAKE3) && CCI_USE_BLAKE3
      /* BLAKE3: streaming hasher + interleaved EVP CTR */
      blake3_hasher bh;
      blake3_hasher_init(&bh);
      { unsigned char pad[4]; pad32_be(pad, adlen);
        blake3_hasher_update(&bh, pad, 4); }
      if (adlen) blake3_hasher_update(&bh, ad, (size_t)adlen);
      { unsigned char pad[4]; pad32_be(pad, mlen);
        blake3_hasher_update(&bh, pad, 4); }

      unsigned long long off = 0;
      while (off < mlen) {
        size_t chunk = (size_t)(mlen - off);
        if (chunk > CCI_CHUNK) chunk = CCI_CHUNK;
        blake3_hasher_update(&bh, m + off, chunk);
        if (!EVP_EncryptUpdate(ctr, c + off, &outlen, m + off, (int)chunk))
          goto error;
        off += chunk;
      }
      if (!EVP_EncryptUpdate(ctr, tmask, &outlen, z16, 16)) goto error;

      blake3_hasher_update(&bh, n2_local, 16);
      { unsigned char out32[32];
        blake3_hasher_finalize(&bh, out32); memcpy(hbuf, out32, 16); }
#else
      /* EVP hash: interleaved with EVP CTR */
      unsigned char pad[4];
      EVP_MD_CTX *hctx = EVP_MD_CTX_new();
      if (!hctx) goto error;
      if (!EVP_DigestInit_ex(hctx, CCI_HASH_FN(), 0)) { EVP_MD_CTX_free(hctx); goto error; }

      pad32_be(pad, adlen); EVP_DigestUpdate(hctx, pad, 4);
      if (adlen) EVP_DigestUpdate(hctx, ad, (size_t)adlen);
      pad32_be(pad, mlen); EVP_DigestUpdate(hctx, pad, 4);

      unsigned long long off = 0;
      while (off < mlen) {
        size_t chunk = (size_t)(mlen - off);
        if (chunk > CCI_CHUNK) chunk = CCI_CHUNK;
        EVP_DigestUpdate(hctx, m + off, chunk);
        if (!EVP_EncryptUpdate(ctr, c + off, &outlen, m + off, (int)chunk))
          { EVP_MD_CTX_free(hctx); goto error; }
        off += chunk;
      }
      if (!EVP_EncryptUpdate(ctr, tmask, &outlen, z16, 16)) { EVP_MD_CTX_free(hctx); goto error; }

      EVP_DigestUpdate(hctx, n2_local, 16);
      { unsigned char full[EVP_MAX_MD_SIZE]; unsigned int olen = 0;
        EVP_DigestFinal_ex(hctx, full, &olen); memcpy(hbuf, full, 16); }
      EVP_MD_CTX_free(hctx);
#endif
    }
  }

  /* tag = H XOR tmask */
  for (int i = 0; i < 16; ++i) c[mlen + i] = (unsigned char)(hbuf[i] ^ tmask[i]);
  *clen = mlen + 16;

  goto cleanup;
  error: result = -111;
  cleanup:
  if (ctr) { EVP_CIPHER_CTX_free(ctr); ctr = 0; }
  return result;
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
  (void)nsec;
  int result = 0;
  EVP_CIPHER_CTX *ctr = 0;
  unsigned char *ptmp = 0;
  unsigned char iv[16];
  unsigned char tagmask[16];
  unsigned char calc[16];
  unsigned long long plen;
  int need_safe;

  if (adlen > 536870912) goto error;
  if (clen > 536870912) goto error;
  if (clen < 16) goto forgery;
  plen = clen - 16;

  memcpy(iv, npub, 12);
  iv[12] = 0; iv[13] = 0; iv[14] = 0; iv[15] = 1;

  unsigned char n2_save[16];
  memcpy(n2_save, npub + 12, 16);

  need_safe = regions_overlap(m, (size_t)plen, ad, (size_t)adlen)
           || regions_overlap(m, (size_t)plen, c, (size_t)clen)
           || regions_overlap(m, (size_t)plen, npub, 28);

  {
    size_t hash_total = (size_t)adlen + (size_t)plen + 24;
    unsigned char *dst = m;
    if (need_safe && plen) {
      ptmp = (unsigned char *)malloc((size_t)plen);
      if (!ptmp) goto error;
      dst = ptmp;
    }

    if (hash_total <= CCI_FAST_HASH_MAX && plen <= 64) {
      /* ============================================================ */
      /* FAST PATH: low-level CTR decrypt → stack hash → verify       */
      /* ============================================================ */
      ctr_small(c, dst, (size_t)plen, tagmask, k, iv);

      unsigned char hm[CCI_FAST_HASH_MAX];
      size_t hm_len = build_hash_input(hm, ad, adlen, dst, plen, n2_save);

#if defined(CCI_USE_BLAKE3) && CCI_USE_BLAKE3
      blake3_hash16(hm, hm_len, calc);
#else
      if (hash_oneshot16(hm, hm_len, calc) != 0) goto error;
#endif

    } else if (plen <= 64) {
      /* ============================================================ */
      /* SMALL CTR + large AD: streaming hash                         */
      /* ============================================================ */
      ctr_small(c, dst, (size_t)plen, tagmask, k, iv);

#if defined(CCI_USE_BLAKE3) && CCI_USE_BLAKE3
      blake3_hasher bh;
      blake3_hasher_init(&bh);
      { unsigned char pad[4]; pad32_be(pad, adlen);
        blake3_hasher_update(&bh, pad, 4); }
      if (adlen) blake3_hasher_update(&bh, ad, (size_t)adlen);
      { unsigned char pad[4]; pad32_be(pad, plen);
        blake3_hasher_update(&bh, pad, 4); }
      if (plen) blake3_hasher_update(&bh, dst, (size_t)plen);
      blake3_hasher_update(&bh, n2_save, 16);
      { unsigned char out32[32];
        blake3_hasher_finalize(&bh, out32); memcpy(calc, out32, 16); }
#else
      unsigned char pad[4];
      EVP_MD_CTX *hctx = EVP_MD_CTX_new();
      if (!hctx) goto error;
      if (!EVP_DigestInit_ex(hctx, CCI_HASH_FN(), 0)) { EVP_MD_CTX_free(hctx); goto error; }
      pad32_be(pad, adlen); EVP_DigestUpdate(hctx, pad, 4);
      if (adlen) EVP_DigestUpdate(hctx, ad, (size_t)adlen);
      pad32_be(pad, plen); EVP_DigestUpdate(hctx, pad, 4);
      if (plen) EVP_DigestUpdate(hctx, dst, (size_t)plen);
      EVP_DigestUpdate(hctx, n2_save, 16);
      { unsigned char full[EVP_MAX_MD_SIZE]; unsigned int olen = 0;
        EVP_DigestFinal_ex(hctx, full, &olen); memcpy(calc, full, 16); }
      EVP_MD_CTX_free(hctx);
#endif

    } else {
      /* ============================================================ */
      /* LARGE PATH: one-pass interleaved CTR decrypt + hash          */
      /* Uses EVP CTR for AES-NI pipelining performance.              */
      /* ============================================================ */
      int outlen = 0;

      ctr = EVP_CIPHER_CTX_new(); if (!ctr) goto error;
      if (!EVP_DecryptInit_ex(ctr, CCI_CTR_EVP(), 0, 0, 0)) goto error;
      if (!EVP_DecryptInit_ex(ctr, 0, 0, k, iv)) goto error;

#if defined(CCI_USE_BLAKE3) && CCI_USE_BLAKE3
      /* BLAKE3: streaming hasher + interleaved EVP CTR decrypt */
      blake3_hasher bh;
      blake3_hasher_init(&bh);
      { unsigned char pad[4]; pad32_be(pad, adlen);
        blake3_hasher_update(&bh, pad, 4); }
      if (adlen) blake3_hasher_update(&bh, ad, (size_t)adlen);
      { unsigned char pad[4]; pad32_be(pad, plen);
        blake3_hasher_update(&bh, pad, 4); }

      unsigned long long off = 0;
      while (off < plen) {
        size_t chunk = (size_t)(plen - off);
        if (chunk > CCI_CHUNK) chunk = CCI_CHUNK;
        if (!EVP_DecryptUpdate(ctr, dst + off, &outlen, c + off, (int)chunk))
          goto error;
        blake3_hasher_update(&bh, dst + off, chunk);
        off += chunk;
      }
      if (!EVP_DecryptUpdate(ctr, tagmask, &outlen,
          (const unsigned char *)"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16)) goto error;

      blake3_hasher_update(&bh, n2_save, 16);
      { unsigned char out32[32];
        blake3_hasher_finalize(&bh, out32); memcpy(calc, out32, 16); }
#else
      /* EVP hash: interleaved with EVP CTR decrypt */
      unsigned char pad[4];
      EVP_MD_CTX *hctx = EVP_MD_CTX_new();
      if (!hctx) goto error;
      if (!EVP_DigestInit_ex(hctx, CCI_HASH_FN(), 0)) { EVP_MD_CTX_free(hctx); goto error; }

      pad32_be(pad, adlen); EVP_DigestUpdate(hctx, pad, 4);
      if (adlen) EVP_DigestUpdate(hctx, ad, (size_t)adlen);
      pad32_be(pad, plen); EVP_DigestUpdate(hctx, pad, 4);

      unsigned long long off = 0;
      while (off < plen) {
        size_t chunk = (size_t)(plen - off);
        if (chunk > CCI_CHUNK) chunk = CCI_CHUNK;
        if (!EVP_DecryptUpdate(ctr, dst + off, &outlen, c + off, (int)chunk))
          { EVP_MD_CTX_free(hctx); goto error; }
        EVP_DigestUpdate(hctx, dst + off, chunk);
        off += chunk;
      }
      if (!EVP_DecryptUpdate(ctr, tagmask, &outlen,
          (const unsigned char *)"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16))
        { EVP_MD_CTX_free(hctx); goto error; }

      EVP_DigestUpdate(hctx, n2_save, 16);
      { unsigned char full[EVP_MAX_MD_SIZE]; unsigned int olen = 0;
        EVP_DigestFinal_ex(hctx, full, &olen); memcpy(calc, full, 16); }
      EVP_MD_CTX_free(hctx);
#endif
    }

    /* verify tag */
    {
      unsigned char tag[16];
      for (int i = 0; i < 16; ++i) tag[i] = (unsigned char)(c[plen + i] ^ tagmask[i]);
      if (ct_eq(tag, calc, 16) != 0) goto forgery;
    }

    if (ptmp && plen) memcpy(m, ptmp, (size_t)plen);
    *mlen = plen;
  }

  goto cleanup;
  forgery: result = -1; goto cleanup;
  error: result = -111;
  cleanup:
  if (ptmp) { free(ptmp); ptmp = 0; }
  if (ctr) { EVP_CIPHER_CTX_free(ctr); ctr = 0; }
  return result;
}
