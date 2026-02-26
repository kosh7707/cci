/*
 * Pure software ChaCha20-Poly1305 reference implementation (RFC 8439).
 * Composed from SUPERCOP building blocks:
 *   ChaCha20: crypto_stream/chacha20/e/ref (D.J.Bernstein)
 *   Poly1305: crypto_onetimeauth/poly1305/ref (D.J.Bernstein)
 *
 * Public domain.
 */

#include "crypto_aead.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

static int regions_overlap(const void *a, size_t alen,
                           const void *b, size_t blen) {
  const unsigned char *pa = (const unsigned char *)a;
  const unsigned char *pb = (const unsigned char *)b;
  if (!alen || !blen) return 0;
  return pa < pb + blen && pb < pa + alen;
}

/* ================================================================== */
/* ChaCha20 quarter-round core (RFC 8439 / IETF variant)              */
/* ================================================================== */

static uint32_t rotl32(uint32_t v, int c) { return (v << c) | (v >> (32 - c)); }

#define QUARTERROUND(a,b,c,d) \
  x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 16); \
  x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 12); \
  x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a],  8); \
  x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c],  7);

static uint32_t load32_le(const unsigned char *p)
{
  return (uint32_t)p[0]
    | ((uint32_t)p[1] << 8)
    | ((uint32_t)p[2] << 16)
    | ((uint32_t)p[3] << 24);
}

static void store32_le(unsigned char *p, uint32_t v)
{
  p[0] = (unsigned char)(v);
  p[1] = (unsigned char)(v >> 8);
  p[2] = (unsigned char)(v >> 16);
  p[3] = (unsigned char)(v >> 24);
}

static void store64_le(unsigned char *p, uint64_t v)
{
  int i;
  for (i = 0; i < 8; ++i) { p[i] = (unsigned char)(v & 0xFF); v >>= 8; }
}

static void chacha20_block(unsigned char out[64], const uint32_t input[16])
{
  uint32_t x[16];
  int i;
  for (i = 0; i < 16; ++i) x[i] = input[i];
  for (i = 0; i < 10; ++i) {
    QUARTERROUND(0, 4, 8, 12)
    QUARTERROUND(1, 5, 9, 13)
    QUARTERROUND(2, 6, 10, 14)
    QUARTERROUND(3, 7, 11, 15)
    QUARTERROUND(0, 5, 10, 15)
    QUARTERROUND(1, 6, 11, 12)
    QUARTERROUND(2, 7, 8, 13)
    QUARTERROUND(3, 4, 9, 14)
  }
  for (i = 0; i < 16; ++i) store32_le(out + 4 * i, x[i] + input[i]);
}

static void chacha20_init(uint32_t state[16], const unsigned char *key,
                           uint32_t counter, const unsigned char *nonce)
{
  static const unsigned char sigma[16] = {
    'e','x','p','a','n','d',' ','3','2','-','b','y','t','e',' ','k'
  };
  state[0]  = load32_le(sigma + 0);
  state[1]  = load32_le(sigma + 4);
  state[2]  = load32_le(sigma + 8);
  state[3]  = load32_le(sigma + 12);
  state[4]  = load32_le(key + 0);
  state[5]  = load32_le(key + 4);
  state[6]  = load32_le(key + 8);
  state[7]  = load32_le(key + 12);
  state[8]  = load32_le(key + 16);
  state[9]  = load32_le(key + 20);
  state[10] = load32_le(key + 24);
  state[11] = load32_le(key + 28);
  state[12] = counter;
  state[13] = load32_le(nonce + 0);
  state[14] = load32_le(nonce + 4);
  state[15] = load32_le(nonce + 8);
}

static void chacha20_xor(unsigned char *out, const unsigned char *in,
                          unsigned long long len,
                          const unsigned char *key, uint32_t counter,
                          const unsigned char *nonce)
{
  uint32_t state[16];
  unsigned char block[64];
  unsigned long long i;
  chacha20_init(state, key, counter, nonce);
  while (len > 0) {
    unsigned long long take = len < 64 ? len : 64;
    chacha20_block(block, state);
    for (i = 0; i < take; ++i) out[i] = in[i] ^ block[i];
    state[12]++;
    out += take;
    in += take;
    len -= take;
  }
}

/* ================================================================== */
/* Poly1305 one-time authenticator (D.J.Bernstein, SUPERCOP ref)      */
/* ================================================================== */

static void poly1305_add(unsigned int h[17], const unsigned int c[17])
{
  unsigned int j, u = 0;
  for (j = 0; j < 17; ++j) { u += h[j] + c[j]; h[j] = u & 255; u >>= 8; }
}

static void poly1305_squeeze(unsigned int h[17])
{
  unsigned int j, u = 0;
  for (j = 0; j < 16; ++j) { u += h[j]; h[j] = u & 255; u >>= 8; }
  u += h[16]; h[16] = u & 3;
  u = 5 * (u >> 2);
  for (j = 0; j < 16; ++j) { u += h[j]; h[j] = u & 255; u >>= 8; }
  u += h[16]; h[16] = u;
}

static const unsigned int poly1305_minusp[17] = {
  5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252
};

static void poly1305_freeze(unsigned int h[17])
{
  unsigned int horig[17];
  unsigned int j, negative;
  for (j = 0; j < 17; ++j) horig[j] = h[j];
  poly1305_add(h, poly1305_minusp);
  negative = -(h[16] >> 7);
  for (j = 0; j < 17; ++j) h[j] ^= negative & (horig[j] ^ h[j]);
}

static void poly1305_mulmod(unsigned int h[17], const unsigned int r[17])
{
  unsigned int hr[17];
  unsigned int i, j, u;
  for (i = 0; i < 17; ++i) {
    u = 0;
    for (j = 0; j <= i; ++j) u += h[j] * r[i - j];
    for (j = i + 1; j < 17; ++j) u += 320 * h[j] * r[i + 17 - j];
    hr[i] = u;
  }
  for (i = 0; i < 17; ++i) h[i] = hr[i];
  poly1305_squeeze(h);
}

static void poly1305_auth(unsigned char out[16],
                           const unsigned char *msg, unsigned long long msglen,
                           const unsigned char key[32])
{
  unsigned int j;
  unsigned int r[17], h[17], c[17];

  r[0] = key[0];   r[1] = key[1];   r[2] = key[2];   r[3] = key[3] & 15;
  r[4] = key[4] & 252; r[5] = key[5]; r[6] = key[6]; r[7] = key[7] & 15;
  r[8] = key[8] & 252; r[9] = key[9]; r[10] = key[10]; r[11] = key[11] & 15;
  r[12] = key[12] & 252; r[13] = key[13]; r[14] = key[14]; r[15] = key[15] & 15;
  r[16] = 0;

  for (j = 0; j < 17; ++j) h[j] = 0;

  while (msglen > 0) {
    for (j = 0; j < 17; ++j) c[j] = 0;
    for (j = 0; (j < 16) && (j < msglen); ++j) c[j] = msg[j];
    c[j] = 1;
    msg += j;
    msglen -= j;
    poly1305_add(h, c);
    poly1305_mulmod(h, r);
  }

  poly1305_freeze(h);

  for (j = 0; j < 16; ++j) c[j] = key[j + 16];
  c[16] = 0;
  poly1305_add(h, c);
  for (j = 0; j < 16; ++j) out[j] = (unsigned char)h[j];
}

/* ================================================================== */
/* Constant-time 16-byte verify                                       */
/* ================================================================== */

static int cp_verify16(const unsigned char *x, const unsigned char *y)
{
  unsigned int diff = 0;
  int i;
  for (i = 0; i < 16; ++i) diff |= x[i] ^ y[i];
  return (1 & ((diff - 1) >> 8)) - 1;
}

/* ================================================================== */
/* RFC 8439 AEAD: build mac_data and authenticate                     */
/* ================================================================== */

/*
 * mac_data = pad16(ad) || pad16(ct) || le64(adlen) || le64(ctlen)
 */
static void rfc8439_poly1305_tag(unsigned char tag[16],
                                  const unsigned char *ad, unsigned long long adlen,
                                  const unsigned char *ct, unsigned long long ctlen,
                                  const unsigned char poly_key[32])
{
  unsigned long long padded_adlen = (adlen + 15) & ~15ULL;
  unsigned long long padded_ctlen = (ctlen + 15) & ~15ULL;
  unsigned long long mac_len = padded_adlen + padded_ctlen + 16;
  unsigned char *mac_data = (unsigned char *)malloc((size_t)mac_len);
  unsigned long long off;

  /* pad16(ad) */
  if (adlen > 0) memcpy(mac_data, ad, (size_t)adlen);
  if (padded_adlen > adlen) memset(mac_data + adlen, 0, (size_t)(padded_adlen - adlen));
  off = padded_adlen;

  /* pad16(ct) */
  if (ctlen > 0) memcpy(mac_data + off, ct, (size_t)ctlen);
  if (padded_ctlen > ctlen) memset(mac_data + off + ctlen, 0, (size_t)(padded_ctlen - ctlen));
  off += padded_ctlen;

  /* le64(adlen) || le64(ctlen) */
  store64_le(mac_data + off, (uint64_t)adlen);
  store64_le(mac_data + off + 8, (uint64_t)ctlen);

  poly1305_auth(tag, mac_data, mac_len, poly_key);
  free(mac_data);
}

/* ================================================================== */
/* RFC 8439 AEAD encrypt / decrypt                                    */
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
  uint32_t state[16];
  unsigned char block0[64], poly_key[32];
  (void)nsec;

  unsigned char *ad_copy = NULL;
  const unsigned char *ad_ptr = ad;

  *clen = mlen + 16;

  /* Save ad if it overlaps with the output buffer */
  if (adlen > 0 && regions_overlap(c, (size_t)(mlen + 16), ad, (size_t)adlen)) {
    ad_copy = (unsigned char *)malloc((size_t)adlen);
    if (!ad_copy) return -1;
    memcpy(ad_copy, ad, (size_t)adlen);
    ad_ptr = ad_copy;
  }

  /* Generate Poly1305 key from first ChaCha20 block (counter=0) */
  chacha20_init(state, k, 0, npub);
  chacha20_block(block0, state);
  memcpy(poly_key, block0, 32);

  /* Encrypt plaintext with ChaCha20 (counter=1) */
  chacha20_xor(c, m, mlen, k, 1, npub);

  /* Compute Poly1305 tag */
  rfc8439_poly1305_tag(c + mlen, ad_ptr, adlen, c, mlen, poly_key);

  if (ad_copy) free(ad_copy);
  return 0;
}

int crypto_aead_decrypt(
  unsigned char *m, unsigned long long *mlen,
  unsigned char *nsec,
  const unsigned char *c, unsigned long long clen,
  const unsigned char *ad, unsigned long long adlen,
  const unsigned char *npub,
  const unsigned char *k
)
{
  uint32_t state[16];
  unsigned char block0[64], poly_key[32];
  unsigned char computed_tag[16];
  unsigned long long plen;
  (void)nsec;

  if (clen < 16) return -1;
  plen = clen - 16;
  *mlen = plen;

  /* Generate Poly1305 key */
  chacha20_init(state, k, 0, npub);
  chacha20_block(block0, state);
  memcpy(poly_key, block0, 32);

  /* Verify tag over ciphertext */
  rfc8439_poly1305_tag(computed_tag, ad, adlen, c, plen, poly_key);
  if (cp_verify16(computed_tag, c + plen) != 0) return -1;

  /* Decrypt */
  chacha20_xor(m, c, plen, k, 1, npub);

  return 0;
}
