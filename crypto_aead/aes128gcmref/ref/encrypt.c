/*
 * Pure software AES-128-GCM reference implementation.
 * Table-based AES (256B sbox) + 4-bit Shoup table GHASH.
 * No AES-NI, no PCLMULQDQ.
 *
 * AES: table-based with pre-expanded round keys (same as CCM-ref)
 * GHASH: 4-bit multiplication table (Shoup's method)
 */

#include "crypto_aead.h"
#include <string.h>
#include <stdint.h>

/* ================================================================== */
/* Table-based AES-128 (256B sbox, pre-expanded key)                  */
/* ================================================================== */

static const uint8_t sbox[256] = {
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static uint8_t rcon(uint8_t i)
{
  uint8_t c = 1;
  while (i > 1) { c = (uint8_t)((c << 1) ^ ((c & 0x80) ? 0x1B : 0)); --i; }
  return c;
}

static void subword(uint8_t w[4])
{
  w[0] = sbox[w[0]]; w[1] = sbox[w[1]]; w[2] = sbox[w[2]]; w[3] = sbox[w[3]];
}

static void rotword(uint8_t w[4])
{
  uint8_t t = w[0]; w[0] = w[1]; w[1] = w[2]; w[2] = w[3]; w[3] = t;
}

static void aes128_key_expand(const uint8_t key[16], uint8_t rk[176])
{
  memcpy(rk, key, 16);
  uint8_t temp[4];
  int i = 16, r = 1;
  while (i < 176) {
    temp[0] = rk[i-4]; temp[1] = rk[i-3]; temp[2] = rk[i-2]; temp[3] = rk[i-1];
    if ((i % 16) == 0) { rotword(temp); subword(temp); temp[0] ^= rcon((uint8_t)r++); }
    rk[i] = rk[i-16] ^ temp[0]; rk[i+1] = rk[i-15] ^ temp[1];
    rk[i+2] = rk[i-14] ^ temp[2]; rk[i+3] = rk[i-13] ^ temp[3];
    i += 4;
  }
}

static uint8_t xtime(uint8_t x) { return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1B : 0)); }

static void subbytes_shiftrows(uint8_t s[16])
{
  uint8_t t[16];
  int i;
  for (i = 0; i < 16; ++i) t[i] = sbox[s[i]];
  s[0]=t[0]; s[4]=t[4]; s[8]=t[8]; s[12]=t[12];
  s[1]=t[5]; s[5]=t[9]; s[9]=t[13]; s[13]=t[1];
  s[2]=t[10]; s[6]=t[14]; s[10]=t[2]; s[14]=t[6];
  s[3]=t[15]; s[7]=t[3]; s[11]=t[7]; s[15]=t[11];
}

static void mixcolumns(uint8_t s[16])
{
  int c;
  for (c = 0; c < 4; ++c) {
    int ii = 4 * c;
    uint8_t a0 = s[ii+0], a1 = s[ii+1], a2 = s[ii+2], a3 = s[ii+3];
    s[ii+0] = (uint8_t)(xtime(a0) ^ (a1 ^ xtime(a1)) ^ a2 ^ a3);
    s[ii+1] = (uint8_t)(a0 ^ xtime(a1) ^ (a2 ^ xtime(a2)) ^ a3);
    s[ii+2] = (uint8_t)(a0 ^ a1 ^ xtime(a2) ^ (a3 ^ xtime(a3)));
    s[ii+3] = (uint8_t)((a0 ^ xtime(a0)) ^ a1 ^ a2 ^ xtime(a3));
  }
}

static void addroundkey(uint8_t s[16], const uint8_t *rk)
{
  int i;
  for (i = 0; i < 16; ++i) s[i] ^= rk[i];
}

static void aes128_encrypt_block(uint8_t out[16], const uint8_t in[16],
                                  const uint8_t rk[176])
{
  uint8_t s[16];
  int r;
  memcpy(s, in, 16);
  addroundkey(s, rk);
  for (r = 1; r <= 9; ++r) { subbytes_shiftrows(s); mixcolumns(s); addroundkey(s, rk + 16*r); }
  subbytes_shiftrows(s);
  addroundkey(s, rk + 160);
  memcpy(out, s, 16);
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
/* 4-bit table GHASH (Shoup method)                                   */
/* ================================================================== */

/*
 * Reduction table for GF(2^128) right-shift-by-4.
 * Polynomial: x^128 + x^7 + x^2 + x + 1.
 * ghash_R[v] = 16-bit value to XOR into bytes 0..1 when 4 bits
 * with value v fall off the right side during a 4-bit right-shift.
 */
static const uint16_t ghash_R[16] = {
  0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0,
  0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0
};

/*
 * Precompute M[0..15] where M[i] = i * H in GF(2^128).
 *
 * Basis (GCM nibble bit ordering):
 *   M[8] = H,  M[4] = H*x,  M[2] = H*x^2,  M[1] = H*x^3
 * where x means GCM right-shift-by-1 with reduction.
 * Compound entries built by XOR.
 */
static void ghash_setup(unsigned char M[16][16], const unsigned char H[16])
{
  int i, k;
  unsigned char lsb;

  memset(M[0], 0, 16);
  memcpy(M[8], H, 16);

  /* M[4] = H*x = rightshift(H) with GCM reduction */
  memcpy(M[4], M[8], 16);
  lsb = M[4][15] & 1;
  for (k = 15; k > 0; --k) M[4][k] = (M[4][k] >> 1) | (M[4][k-1] << 7);
  M[4][0] >>= 1;
  if (lsb) M[4][0] ^= 0xe1;

  /* M[2] = H*x^2 */
  memcpy(M[2], M[4], 16);
  lsb = M[2][15] & 1;
  for (k = 15; k > 0; --k) M[2][k] = (M[2][k] >> 1) | (M[2][k-1] << 7);
  M[2][0] >>= 1;
  if (lsb) M[2][0] ^= 0xe1;

  /* M[1] = H*x^3 */
  memcpy(M[1], M[2], 16);
  lsb = M[1][15] & 1;
  for (k = 15; k > 0; --k) M[1][k] = (M[1][k] >> 1) | (M[1][k-1] << 7);
  M[1][0] >>= 1;
  if (lsb) M[1][0] ^= 0xe1;

  /* Remaining entries by XOR of basis elements */
  for (i = 3; i < 16; i++) {
    int lo, hi;
    if ((i & (i - 1)) == 0) continue;  /* powers of 2 already done */
    lo = i & (-i);
    hi = i ^ lo;
    for (k = 0; k < 16; k++) M[i][k] = M[lo][k] ^ M[hi][k];
  }
}

/*
 * acc = (acc XOR x) * H  using 4-bit Shoup table.
 * x is zero-padded to 16 bytes.  M is the precomputed table.
 */
static void addmul(unsigned char *acc,
                    const unsigned char *x, unsigned long long xlen,
                    unsigned char M[16][16])
{
  int i, k;
  unsigned char nib;
  unsigned char Z[16];

  for (i = 0; i < (int)xlen; ++i) acc[i] ^= x[i];

  memset(Z, 0, 16);

  for (i = 15; i >= 0; --i) {
    /* low nibble */
    nib = Z[15] & 0x0f;
    for (k = 15; k > 0; --k) Z[k] = (Z[k] >> 4) | (Z[k-1] << 4);
    Z[0] >>= 4;
    Z[0] ^= (unsigned char)(ghash_R[nib] >> 8);
    Z[1] ^= (unsigned char)(ghash_R[nib] & 0xff);
    nib = acc[i] & 0x0f;
    for (k = 0; k < 16; ++k) Z[k] ^= M[nib][k];

    /* high nibble */
    nib = Z[15] & 0x0f;
    for (k = 15; k > 0; --k) Z[k] = (Z[k] >> 4) | (Z[k-1] << 4);
    Z[0] >>= 4;
    Z[0] ^= (unsigned char)(ghash_R[nib] >> 8);
    Z[1] ^= (unsigned char)(ghash_R[nib] & 0xff);
    nib = (acc[i] >> 4) & 0x0f;
    for (k = 0; k < 16; ++k) Z[k] ^= M[nib][k];
  }

  memcpy(acc, Z, 16);
}

/* ================================================================== */
/* GCM helpers                                                        */
/* ================================================================== */

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

static const unsigned char gcm_zero[16] = {0};

/* ================================================================== */
/* GCM encrypt                                                        */
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
  unsigned char rk[176];
  unsigned char H[16], M[16][16];
  unsigned char J[16], T[16], accum[16], stream[16], finalblock[16];
  unsigned long long i, index;
  (void)nsec;

  aes128_key_expand(k, rk);

  *clen = mlen + 16;
  gcm_store64(finalblock, 8 * adlen);
  gcm_store64(finalblock + 8, 8 * mlen);

  aes128_encrypt_block(H, gcm_zero, rk);
  ghash_setup(M, H);

  for (i = 0; i < 12; ++i) J[i] = npub[i];
  index = 1;
  gcm_store32(J + 12, index);
  aes128_encrypt_block(T, J, rk);

  for (i = 0; i < 16; ++i) accum[i] = 0;

  while (adlen > 0) {
    unsigned long long blocklen = 16;
    if (adlen < blocklen) blocklen = adlen;
    addmul(accum, ad, blocklen, M);
    ad += blocklen;
    adlen -= blocklen;
  }

  while (mlen > 0) {
    unsigned long long blocklen = 16;
    if (mlen < blocklen) blocklen = mlen;
    ++index;
    gcm_store32(J + 12, index);
    aes128_encrypt_block(stream, J, rk);
    for (i = 0; i < blocklen; ++i) c[i] = m[i] ^ stream[i];
    addmul(accum, c, blocklen, M);
    c += blocklen;
    m += blocklen;
    mlen -= blocklen;
  }

  addmul(accum, finalblock, 16, M);
  for (i = 0; i < 16; ++i) c[i] = T[i] ^ accum[i];
  return 0;
}

/* ================================================================== */
/* GCM decrypt                                                        */
/* ================================================================== */

int crypto_aead_decrypt(
  unsigned char *m, unsigned long long *outputmlen,
  unsigned char *nsec,
  const unsigned char *c, unsigned long long clen,
  const unsigned char *ad, unsigned long long adlen,
  const unsigned char *npub,
  const unsigned char *k
)
{
  unsigned char rk[176];
  unsigned char H[16], M[16][16];
  unsigned char J[16], T[16], accum[16], stream[16], finalblock[16];
  unsigned long long mlen, origmlen, index, i;
  const unsigned char *origc;
  (void)nsec;

  if (clen < 16) return -1;
  mlen = clen - 16;

  aes128_key_expand(k, rk);

  gcm_store64(finalblock, 8 * adlen);
  gcm_store64(finalblock + 8, 8 * mlen);

  aes128_encrypt_block(H, gcm_zero, rk);
  ghash_setup(M, H);

  for (i = 0; i < 12; ++i) J[i] = npub[i];
  index = 1;
  gcm_store32(J + 12, index);
  aes128_encrypt_block(T, J, rk);

  for (i = 0; i < 16; ++i) accum[i] = 0;

  while (adlen > 0) {
    unsigned long long blocklen = 16;
    if (adlen < blocklen) blocklen = adlen;
    addmul(accum, ad, blocklen, M);
    ad += blocklen;
    adlen -= blocklen;
  }

  origc = c;
  origmlen = mlen;
  while (mlen > 0) {
    unsigned long long blocklen = 16;
    if (mlen < blocklen) blocklen = mlen;
    addmul(accum, c, blocklen, M);
    c += blocklen;
    mlen -= blocklen;
  }

  addmul(accum, finalblock, 16, M);
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
    aes128_encrypt_block(stream, J, rk);
      for (i = 0; i < blocklen; ++i) m[i] = c[i] ^ stream[i];
    c += blocklen;
    m += blocklen;
    mlen -= blocklen;
  }

  return 0;
}
