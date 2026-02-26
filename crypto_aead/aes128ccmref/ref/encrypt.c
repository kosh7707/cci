/*
 * Pure software AES-128-CCM reference implementation.
 * Table-based AES (256B sbox), no AES-NI.
 *
 * Source: CCI backup/Portable-C/aes128ccm (adapted for sandbox api.h)
 */

#include "crypto_aead.h"
#include <string.h>
#include <stdint.h>

#ifndef CRYPTO_ABYTES
#define CRYPTO_ABYTES    16
#endif
#ifndef CRYPTO_NPUBBYTES
#define CRYPTO_NPUBBYTES 12
#endif

/* ================================================================== */
/* Constant-time 16-byte verify                                       */
/* ================================================================== */

static int ccm_verify16(const unsigned char *x, const unsigned char *y)
{
  unsigned int r = 0;
  int i;
  for (i = 0; i < 16; ++i) r |= (unsigned int)(x[i] ^ y[i]);
  r = (r | (0U - r)) >> 31;
  return -(int)r;
}

/* ================================================================== */
/* Table-based AES-128 (256B sbox)                                    */
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
/* CCM helpers                                                        */
/* ================================================================== */

static void set_be(unsigned char *p, unsigned long long v, int len)
{
  int i;
  for (i = len - 1; i >= 0; --i) { p[i] = (unsigned char)(v & 0xFF); v >>= 8; }
}

static void xor_inplace(unsigned char *dst, const unsigned char *src, size_t n)
{
  size_t i;
  for (i = 0; i < n; ++i) dst[i] ^= src[i];
}

static void cbc_mac_encrypt(unsigned char X[16], const unsigned char kexp[176])
{
  unsigned char tmp[16];
  aes128_encrypt_block(tmp, X, kexp);
  memcpy(X, tmp, 16);
}

static void ccm_mac_b0(unsigned char X[16], const unsigned char *npub,
                        int L, unsigned long long mlen, unsigned long long adlen)
{
  unsigned char B0[16];
  unsigned char flags = 0;
  if (adlen > 0) flags |= 1u << 6;
  flags |= (unsigned char)(((CRYPTO_ABYTES - 2) / 2 & 0x07) << 3);
  flags |= (unsigned char)((L - 1) & 0x07);
  B0[0] = flags;
  memcpy(B0 + 1, npub, CRYPTO_NPUBBYTES);
  memset(B0 + 1 + CRYPTO_NPUBBYTES, 0, (size_t)(16 - 1 - CRYPTO_NPUBBYTES));
  set_be(B0 + 16 - L, mlen, L);
  memcpy(X, B0, 16);
}

static void mac_aad(unsigned char X[16], const unsigned char *ad,
                     unsigned long long adlen, const unsigned char kexp[176])
{
  unsigned long long processed = 0;
  size_t offset = 2;
  if (adlen == 0) return;
  X[0] ^= (unsigned char)((adlen >> 8) & 0xFF);
  X[1] ^= (unsigned char)(adlen & 0xFF);
  while (processed < adlen) {
    size_t use_len = 16 - offset;
    if (use_len > (size_t)(adlen - processed)) use_len = (size_t)(adlen - processed);
    xor_inplace(X + offset, ad + processed, use_len);
    processed += use_len;
    offset += use_len;
    if (offset == 16 || processed == adlen) { cbc_mac_encrypt(X, kexp); offset = 0; }
  }
}

static void mac_msg(unsigned char X[16], const unsigned char *m,
                     unsigned long long mlen, const unsigned char kexp[176])
{
  unsigned long long processed = 0;
  size_t offset = 0;
  while (processed < mlen) {
    size_t use_len = 16 - offset;
    if (use_len > (size_t)(mlen - processed)) use_len = (size_t)(mlen - processed);
    xor_inplace(X + offset, m + processed, use_len);
    processed += use_len;
    offset += use_len;
    if (offset == 16 || processed == mlen) { cbc_mac_encrypt(X, kexp); offset = 0; }
  }
}

static void build_ctr(unsigned char ctr[16], const unsigned char *npub,
                       int L, unsigned long long counter)
{
  ctr[0] = (unsigned char)((L - 1) & 0x07);
  memcpy(ctr + 1, npub, CRYPTO_NPUBBYTES);
  memset(ctr + 1 + CRYPTO_NPUBBYTES, 0, (size_t)(16 - 1 - CRYPTO_NPUBBYTES));
  set_be(ctr + 16 - L, counter, L);
}

static int check_mlen_fits_L(unsigned long long mlen, int L)
{
  unsigned long long limit;
  if (L <= 0 || L > 8) return 0;
  limit = 1ULL;
  limit <<= (8 * L);
  return mlen < limit;
}

/* ================================================================== */
/* CCM encrypt / decrypt                                              */
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
  const int L = 15 - CRYPTO_NPUBBYTES;
  unsigned char kexp[176], npub_copy[12];
  unsigned char X[16], ctr[16], Sblk[16];
  unsigned char *out;
  unsigned long long processed, counter;
  (void)nsec;

  if (!check_mlen_fits_L(mlen, L)) return -1;
  aes128_key_expand(k, kexp);
  memcpy(npub_copy, npub, CRYPTO_NPUBBYTES);
  *clen = mlen + CRYPTO_ABYTES;

  /* CBC-MAC */
  ccm_mac_b0(X, npub_copy, L, mlen, adlen);
  cbc_mac_encrypt(X, kexp);
  mac_aad(X, ad, adlen, kexp);
  mac_msg(X, m, mlen, kexp);

  /* CTR encryption */
  out = c;
  processed = 0;
  counter = 1;
  while (processed < mlen) {
    size_t take = (size_t)((mlen - processed) < 16ULL ? (mlen - processed) : 16ULL);
    unsigned char mblock[16];
    size_t ii;
    memset(mblock, 0, 16);
    if (take) memcpy(mblock, m + processed, take);
    build_ctr(ctr, npub_copy, L, counter);
    aes128_encrypt_block(Sblk, ctr, kexp);
    for (ii = 0; ii < take; ++ii) out[ii] = (unsigned char)(mblock[ii] ^ Sblk[ii]);
    processed += take;
    out += take;
    ++counter;
  }

  /* Encrypt tag */
  build_ctr(ctr, npub_copy, L, 0);
  aes128_encrypt_block(Sblk, ctr, kexp);
  {
    int i;
    for (i = 0; i < CRYPTO_ABYTES; ++i) out[i] = (unsigned char)(X[i] ^ Sblk[i]);
  }
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
  unsigned long long plen, processed, counter;
  const int L = 15 - CRYPTO_NPUBBYTES;
  unsigned char kexp[176], npub_copy[12];
  unsigned char X[16], ctr[16], Sblk[16], expected[16];
  const unsigned char *ct, *tag;
  (void)nsec;

  if (clen < CRYPTO_ABYTES) return -1;
  plen = clen - CRYPTO_ABYTES;
  *mlen = plen;
  if (!check_mlen_fits_L(plen, L)) return -1;

  aes128_key_expand(k, kexp);
  memcpy(npub_copy, npub, CRYPTO_NPUBBYTES);
  ct = c;
  tag = c + plen;

  /* CBC-MAC over B0 + AAD */
  ccm_mac_b0(X, npub_copy, L, plen, adlen);
  cbc_mac_encrypt(X, kexp);
  mac_aad(X, ad, adlen, kexp);

  /* Decrypt + MAC message */
  processed = 0;
  counter = 1;
  while (processed < plen) {
    size_t take = (size_t)((plen - processed) < 16ULL ? (plen - processed) : 16ULL);
    unsigned char cblock[16];
    size_t ii;
    memset(cblock, 0, 16);
    if (take) memcpy(cblock, ct + processed, take);
    build_ctr(ctr, npub_copy, L, counter);
    aes128_encrypt_block(Sblk, ctr, kexp);
    for (ii = 0; ii < take; ++ii) cblock[ii] ^= Sblk[ii];
    xor_inplace(X, cblock, take);
    if (((processed + take) % 16 == 0) || (processed + take == plen))
      cbc_mac_encrypt(X, kexp);
    processed += take;
    ++counter;
  }

  /* Verify tag */
  build_ctr(ctr, npub_copy, L, 0);
  aes128_encrypt_block(Sblk, ctr, kexp);
  {
    int i;
    for (i = 0; i < 16; ++i) expected[i] = (unsigned char)(X[i] ^ Sblk[i]);
  }
  if (ccm_verify16(expected, tag) != 0) return -1;

  /* Output plaintext */
  processed = 0;
  counter = 1;
  while (processed < plen) {
    size_t take = (size_t)((plen - processed) < 16ULL ? (plen - processed) : 16ULL);
    unsigned char cblock[16];
    size_t ii;
    memset(cblock, 0, 16);
    if (take) memcpy(cblock, ct + processed, take);
    build_ctr(ctr, npub_copy, L, counter);
    aes128_encrypt_block(Sblk, ctr, kexp);
    for (ii = 0; ii < take; ++ii) m[processed + ii] = (unsigned char)(cblock[ii] ^ Sblk[ii]);
    processed += take;
    ++counter;
  }

  return 0;
}
