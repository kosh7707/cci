/*
 * Pure software AES-256-GCM reference implementation.
 * No AES-NI, no PCLMULQDQ — bit-level GF(2^128) and table-less AES.
 *
 * Sources:
 *   GCM:    SUPERCOP crypto_aead/aes256gcmv1/ref (D.J.Bernstein)
 *   AES:    SUPERCOP crypto_core/aes256encrypt/ref (D.J.Bernstein)
 *   Verify: SUPERCOP crypto_verify/16/ref
 */

#include "crypto_aead.h"
#include <string.h>

/* ================================================================== */
/* Pure-C AES-256 block encrypt (no tables, no AES-NI)                */
/* ================================================================== */

static unsigned char aes_multiply(unsigned int c, unsigned int d)
{
  unsigned char f[8], g[8], h[15];
  unsigned char result;
  int i, j;
  for (i = 0; i < 8; ++i) f[i] = (c >> i) & 1;
  for (i = 0; i < 8; ++i) g[i] = (d >> i) & 1;
  for (i = 0; i < 15; ++i) h[i] = 0;
  for (i = 0; i < 8; ++i)
    for (j = 0; j < 8; ++j) h[i + j] ^= f[i] & g[j];
  for (i = 6; i >= 0; --i) {
    h[i + 0] ^= h[i + 8];
    h[i + 1] ^= h[i + 8];
    h[i + 3] ^= h[i + 8];
    h[i + 4] ^= h[i + 8];
    h[i + 8] ^= h[i + 8];
  }
  result = 0;
  for (i = 0; i < 8; ++i) result |= h[i] << i;
  return result;
}

static unsigned char aes_square(unsigned char c) { return aes_multiply(c, c); }
static unsigned char aes_xtime(unsigned char c) { return aes_multiply(c, 2); }

static unsigned char aes_bytesub(unsigned char c)
{
  unsigned char c3 = aes_multiply(aes_square(c), c);
  unsigned char c7 = aes_multiply(aes_square(c3), c);
  unsigned char c63 = aes_multiply(aes_square(aes_square(aes_square(c7))), c7);
  unsigned char c127 = aes_multiply(aes_square(c63), c);
  unsigned char c254 = aes_square(c127);
  unsigned char f[8], hh[8], result;
  int i;
  for (i = 0; i < 8; ++i) f[i] = (c254 >> i) & 1;
  hh[0] = f[0] ^ f[4] ^ f[5] ^ f[6] ^ f[7] ^ 1;
  hh[1] = f[1] ^ f[5] ^ f[6] ^ f[7] ^ f[0] ^ 1;
  hh[2] = f[2] ^ f[6] ^ f[7] ^ f[0] ^ f[1];
  hh[3] = f[3] ^ f[7] ^ f[0] ^ f[1] ^ f[2];
  hh[4] = f[4] ^ f[0] ^ f[1] ^ f[2] ^ f[3];
  hh[5] = f[5] ^ f[1] ^ f[2] ^ f[3] ^ f[4] ^ 1;
  hh[6] = f[6] ^ f[2] ^ f[3] ^ f[4] ^ f[5] ^ 1;
  hh[7] = f[7] ^ f[3] ^ f[4] ^ f[5] ^ f[6];
  result = 0;
  for (i = 0; i < 8; ++i) result |= hh[i] << i;
  return result;
}

static void aes256_encrypt(unsigned char *out, const unsigned char *in,
                            const unsigned char *k)
{
  unsigned char expanded[4][60];
  unsigned char state[4][4], newstate[4][4];
  unsigned char roundconstant;
  int i, j, r;

  for (j = 0; j < 8; ++j)
    for (i = 0; i < 4; ++i)
      expanded[i][j] = k[j * 4 + i];

  roundconstant = 1;
  for (j = 8; j < 60; ++j) {
    unsigned char temp[4];
    if (j % 4)
      for (i = 0; i < 4; ++i) temp[i] = expanded[i][j - 1];
    else if (j % 8)
      for (i = 0; i < 4; ++i) temp[i] = aes_bytesub(expanded[i][j - 1]);
    else {
      for (i = 0; i < 4; ++i) temp[i] = aes_bytesub(expanded[(i + 1) % 4][j - 1]);
      temp[0] ^= roundconstant;
      roundconstant = aes_xtime(roundconstant);
    }
    for (i = 0; i < 4; ++i)
      expanded[i][j] = temp[i] ^ expanded[i][j - 8];
  }

  for (j = 0; j < 4; ++j)
    for (i = 0; i < 4; ++i)
      state[i][j] = in[j * 4 + i] ^ expanded[i][j];

  for (r = 0; r < 14; ++r) {
    for (i = 0; i < 4; ++i)
      for (j = 0; j < 4; ++j)
        newstate[i][j] = aes_bytesub(state[i][j]);
    for (i = 0; i < 4; ++i)
      for (j = 0; j < 4; ++j)
        state[i][j] = newstate[i][(j + i) % 4];
    if (r < 13)
      for (j = 0; j < 4; ++j) {
        unsigned char a0 = state[0][j];
        unsigned char a1 = state[1][j];
        unsigned char a2 = state[2][j];
        unsigned char a3 = state[3][j];
        state[0][j] = aes_xtime(a0 ^ a1) ^ a1 ^ a2 ^ a3;
        state[1][j] = aes_xtime(a1 ^ a2) ^ a2 ^ a3 ^ a0;
        state[2][j] = aes_xtime(a2 ^ a3) ^ a3 ^ a0 ^ a1;
        state[3][j] = aes_xtime(a3 ^ a0) ^ a0 ^ a1 ^ a2;
      }
    for (i = 0; i < 4; ++i)
      for (j = 0; j < 4; ++j)
        state[i][j] ^= expanded[i][r * 4 + 4 + j];
  }

  for (j = 0; j < 4; ++j)
    for (i = 0; i < 4; ++i)
      out[j * 4 + i] = state[i][j];
}

/* ================================================================== */
/* Constant-time 16-byte verify                                       */
/* ================================================================== */

static int verify16(const unsigned char *x, const unsigned char *y)
{
  unsigned int diff = 0;
  int i;
  for (i = 0; i < 16; ++i) diff |= x[i] ^ y[i];
  return (1 & ((diff - 1) >> 8)) - 1;
}

/* ================================================================== */
/* GCM helper functions (bit-level GF(2^128))                         */
/* ================================================================== */

#define AES(out, in, k) aes256_encrypt(out, in, k)

static void gcm_store32(unsigned char *x, unsigned long long u)
{
  int i;
  for (i = 3; i >= 0; --i) { x[i] = (unsigned char)u; u >>= 8; }
}

static void gcm_store64(unsigned char *x, unsigned long long u)
{
  int i;
  for (i = 7; i >= 0; --i) { x[i] = (unsigned char)u; u >>= 8; }
}

static void addmul(unsigned char *a,
                    const unsigned char *x, unsigned long long xlen,
                    const unsigned char *y)
{
  int i, j;
  unsigned char abits[128], ybits[128], prodbits[256];
  for (i = 0; i < (int)xlen; ++i) a[i] ^= x[i];
  for (i = 0; i < 128; ++i) abits[i] = (a[i / 8] >> (7 - (i % 8))) & 1;
  for (i = 0; i < 128; ++i) ybits[i] = (y[i / 8] >> (7 - (i % 8))) & 1;
  for (i = 0; i < 256; ++i) prodbits[i] = 0;
  for (i = 0; i < 128; ++i)
    for (j = 0; j < 128; ++j)
      prodbits[i + j] ^= abits[i] & ybits[j];
  for (i = 127; i >= 0; --i) {
    prodbits[i] ^= prodbits[i + 128];
    prodbits[i + 1] ^= prodbits[i + 128];
    prodbits[i + 2] ^= prodbits[i + 128];
    prodbits[i + 7] ^= prodbits[i + 128];
    prodbits[i + 128] ^= prodbits[i + 128];
  }
  for (i = 0; i < 16; ++i) a[i] = 0;
  for (i = 0; i < 128; ++i) a[i / 8] |= (prodbits[i] << (7 - (i % 8)));
}

/* ================================================================== */
/* GCM encrypt / decrypt                                              */
/* ================================================================== */

static const unsigned char gcm_zero[16] = {0};

int crypto_aead_encrypt(
  unsigned char *c, unsigned long long *clen,
  const unsigned char *m, unsigned long long mlen,
  const unsigned char *ad, unsigned long long adlen,
  const unsigned char *nsec,
  const unsigned char *npub,
  const unsigned char *k
)
{
  unsigned char kcopy[32];
  unsigned char H[16], J[16], T[16], accum[16], stream[16], finalblock[16];
  unsigned long long i, index;
  (void)nsec;

  for (i = 0; i < 32; ++i) kcopy[i] = k[i];

  *clen = mlen + 16;
  gcm_store64(finalblock, 8 * adlen);
  gcm_store64(finalblock + 8, 8 * mlen);

  AES(H, gcm_zero, kcopy);

  for (i = 0; i < 12; ++i) J[i] = npub[i];
  index = 1;
  gcm_store32(J + 12, index);
  AES(T, J, kcopy);

  for (i = 0; i < 16; ++i) accum[i] = 0;

  while (adlen > 0) {
    unsigned long long blocklen = 16;
    if (adlen < blocklen) blocklen = adlen;
    addmul(accum, ad, blocklen, H);
    ad += blocklen;
    adlen -= blocklen;
  }

  while (mlen > 0) {
    unsigned long long blocklen = 16;
    if (mlen < blocklen) blocklen = mlen;
    ++index;
    gcm_store32(J + 12, index);
    AES(stream, J, kcopy);
    for (i = 0; i < blocklen; ++i) c[i] = m[i] ^ stream[i];
    addmul(accum, c, blocklen, H);
    c += blocklen;
    m += blocklen;
    mlen -= blocklen;
  }

  addmul(accum, finalblock, 16, H);
  for (i = 0; i < 16; ++i) c[i] = T[i] ^ accum[i];
  return 0;
}

int crypto_aead_decrypt(
  unsigned char *m, unsigned long long *outputmlen,
  unsigned char *nsec,
  const unsigned char *c, unsigned long long clen,
  const unsigned char *ad, unsigned long long adlen,
  const unsigned char *npub,
  const unsigned char *k
)
{
  unsigned char kcopy[32];
  unsigned char H[16], J[16], T[16], accum[16], stream[16], finalblock[16];
  unsigned long long mlen, origmlen, index, i;
  const unsigned char *origc;
  (void)nsec;

  for (i = 0; i < 32; ++i) kcopy[i] = k[i];

  if (clen < 16) return -1;
  mlen = clen - 16;

  gcm_store64(finalblock, 8 * adlen);
  gcm_store64(finalblock + 8, 8 * mlen);

  AES(H, gcm_zero, kcopy);

  for (i = 0; i < 12; ++i) J[i] = npub[i];
  index = 1;
  gcm_store32(J + 12, index);
  AES(T, J, kcopy);

  for (i = 0; i < 16; ++i) accum[i] = 0;

  while (adlen > 0) {
    unsigned long long blocklen = 16;
    if (adlen < blocklen) blocklen = adlen;
    addmul(accum, ad, blocklen, H);
    ad += blocklen;
    adlen -= blocklen;
  }

  origc = c;
  origmlen = mlen;
  while (mlen > 0) {
    unsigned long long blocklen = 16;
    if (mlen < blocklen) blocklen = mlen;
    addmul(accum, c, blocklen, H);
    c += blocklen;
    mlen -= blocklen;
  }

  addmul(accum, finalblock, 16, H);
  for (i = 0; i < 16; ++i) accum[i] ^= T[i];
  if (verify16(accum, c) != 0) return -1;

  c = origc;
  mlen = origmlen;
  *outputmlen = mlen;

  while (mlen > 0) {
    unsigned long long blocklen = 16;
    if (mlen < blocklen) blocklen = mlen;
    ++index;
    gcm_store32(J + 12, index);
    AES(stream, J, kcopy);
    for (i = 0; i < blocklen; ++i) m[i] = c[i] ^ stream[i];
    c += blocklen;
    m += blocklen;
    mlen -= blocklen;
  }

  return 0;
}
