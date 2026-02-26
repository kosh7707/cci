/*
 * sha256_portable.inc — Streaming SHA-256 (SUPERCOP hashblocks-based)
 *
 * Provides:
 *   sha256_state          — streaming context
 *   sha256_init(state)
 *   sha256_update(state, data, len)
 *   sha256_final(state, out32)
 *
 * The block compression function is inlined from
 * SUPERCOP crypto_hashblocks/sha256/ref/blocks.c (D.J.Bernstein).
 */

#include <string.h>

/* ================================================================== */
/* SHA-256 block compression (SUPERCOP hashblocks/sha256/ref)          */
/* ================================================================== */

typedef unsigned int sha256_uint32;

static sha256_uint32 sha256_load_be(const unsigned char *x)
{
  return (sha256_uint32)(x[3])
    | (((sha256_uint32)(x[2])) << 8)
    | (((sha256_uint32)(x[1])) << 16)
    | (((sha256_uint32)(x[0])) << 24);
}

static void sha256_store_be(unsigned char *x, sha256_uint32 u)
{
  x[3] = (unsigned char)u; u >>= 8;
  x[2] = (unsigned char)u; u >>= 8;
  x[1] = (unsigned char)u; u >>= 8;
  x[0] = (unsigned char)u;
}

#define SHA256_SHR(x,c) ((x) >> (c))
#define SHA256_ROTR(x,c) (((x) >> (c)) | ((x) << (32 - (c))))

#define SHA256_Ch(x,y,z) ((x & y) ^ (~x & z))
#define SHA256_Maj(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
#define SHA256_Sigma0(x) (SHA256_ROTR(x, 2) ^ SHA256_ROTR(x,13) ^ SHA256_ROTR(x,22))
#define SHA256_Sigma1(x) (SHA256_ROTR(x, 6) ^ SHA256_ROTR(x,11) ^ SHA256_ROTR(x,25))
#define SHA256_sigma0(x) (SHA256_ROTR(x, 7) ^ SHA256_ROTR(x,18) ^ SHA256_SHR(x, 3))
#define SHA256_sigma1(x) (SHA256_ROTR(x,17) ^ SHA256_ROTR(x,19) ^ SHA256_SHR(x,10))

#define SHA256_M(w0,w14,w9,w1) w0 = SHA256_sigma1(w14) + w9 + SHA256_sigma0(w1) + w0;

#define SHA256_EXPAND \
  SHA256_M(w0 ,w14,w9 ,w1 ) SHA256_M(w1 ,w15,w10,w2 ) \
  SHA256_M(w2 ,w0 ,w11,w3 ) SHA256_M(w3 ,w1 ,w12,w4 ) \
  SHA256_M(w4 ,w2 ,w13,w5 ) SHA256_M(w5 ,w3 ,w14,w6 ) \
  SHA256_M(w6 ,w4 ,w15,w7 ) SHA256_M(w7 ,w5 ,w0 ,w8 ) \
  SHA256_M(w8 ,w6 ,w1 ,w9 ) SHA256_M(w9 ,w7 ,w2 ,w10) \
  SHA256_M(w10,w8 ,w3 ,w11) SHA256_M(w11,w9 ,w4 ,w12) \
  SHA256_M(w12,w10,w5 ,w13) SHA256_M(w13,w11,w6 ,w14) \
  SHA256_M(w14,w12,w7 ,w15) SHA256_M(w15,w13,w8 ,w0 )

#define SHA256_F(w,k) \
  T1 = hh + SHA256_Sigma1(ee) + SHA256_Ch(ee,ff,gg) + k + w; \
  T2 = SHA256_Sigma0(aa) + SHA256_Maj(aa,bb,cc); \
  hh = gg; gg = ff; ff = ee; ee = dd + T1; \
  dd = cc; cc = bb; bb = aa; aa = T1 + T2;

/* Process complete 64-byte blocks. Returns remaining bytes count. */
static int sha256_hashblocks(unsigned char *statebytes,
                              const unsigned char *in,
                              unsigned long long inlen)
{
  sha256_uint32 state[8];
  sha256_uint32 aa, bb, cc, dd, ee, ff, gg, hh, T1, T2;

  aa = sha256_load_be(statebytes +  0); state[0] = aa;
  bb = sha256_load_be(statebytes +  4); state[1] = bb;
  cc = sha256_load_be(statebytes +  8); state[2] = cc;
  dd = sha256_load_be(statebytes + 12); state[3] = dd;
  ee = sha256_load_be(statebytes + 16); state[4] = ee;
  ff = sha256_load_be(statebytes + 20); state[5] = ff;
  gg = sha256_load_be(statebytes + 24); state[6] = gg;
  hh = sha256_load_be(statebytes + 28); state[7] = hh;

  while (inlen >= 64) {
    sha256_uint32 w0  = sha256_load_be(in +  0);
    sha256_uint32 w1  = sha256_load_be(in +  4);
    sha256_uint32 w2  = sha256_load_be(in +  8);
    sha256_uint32 w3  = sha256_load_be(in + 12);
    sha256_uint32 w4  = sha256_load_be(in + 16);
    sha256_uint32 w5  = sha256_load_be(in + 20);
    sha256_uint32 w6  = sha256_load_be(in + 24);
    sha256_uint32 w7  = sha256_load_be(in + 28);
    sha256_uint32 w8  = sha256_load_be(in + 32);
    sha256_uint32 w9  = sha256_load_be(in + 36);
    sha256_uint32 w10 = sha256_load_be(in + 40);
    sha256_uint32 w11 = sha256_load_be(in + 44);
    sha256_uint32 w12 = sha256_load_be(in + 48);
    sha256_uint32 w13 = sha256_load_be(in + 52);
    sha256_uint32 w14 = sha256_load_be(in + 56);
    sha256_uint32 w15 = sha256_load_be(in + 60);

    SHA256_F(w0 ,0x428a2f98) SHA256_F(w1 ,0x71374491)
    SHA256_F(w2 ,0xb5c0fbcf) SHA256_F(w3 ,0xe9b5dba5)
    SHA256_F(w4 ,0x3956c25b) SHA256_F(w5 ,0x59f111f1)
    SHA256_F(w6 ,0x923f82a4) SHA256_F(w7 ,0xab1c5ed5)
    SHA256_F(w8 ,0xd807aa98) SHA256_F(w9 ,0x12835b01)
    SHA256_F(w10,0x243185be) SHA256_F(w11,0x550c7dc3)
    SHA256_F(w12,0x72be5d74) SHA256_F(w13,0x80deb1fe)
    SHA256_F(w14,0x9bdc06a7) SHA256_F(w15,0xc19bf174)

    SHA256_EXPAND

    SHA256_F(w0 ,0xe49b69c1) SHA256_F(w1 ,0xefbe4786)
    SHA256_F(w2 ,0x0fc19dc6) SHA256_F(w3 ,0x240ca1cc)
    SHA256_F(w4 ,0x2de92c6f) SHA256_F(w5 ,0x4a7484aa)
    SHA256_F(w6 ,0x5cb0a9dc) SHA256_F(w7 ,0x76f988da)
    SHA256_F(w8 ,0x983e5152) SHA256_F(w9 ,0xa831c66d)
    SHA256_F(w10,0xb00327c8) SHA256_F(w11,0xbf597fc7)
    SHA256_F(w12,0xc6e00bf3) SHA256_F(w13,0xd5a79147)
    SHA256_F(w14,0x06ca6351) SHA256_F(w15,0x14292967)

    SHA256_EXPAND

    SHA256_F(w0 ,0x27b70a85) SHA256_F(w1 ,0x2e1b2138)
    SHA256_F(w2 ,0x4d2c6dfc) SHA256_F(w3 ,0x53380d13)
    SHA256_F(w4 ,0x650a7354) SHA256_F(w5 ,0x766a0abb)
    SHA256_F(w6 ,0x81c2c92e) SHA256_F(w7 ,0x92722c85)
    SHA256_F(w8 ,0xa2bfe8a1) SHA256_F(w9 ,0xa81a664b)
    SHA256_F(w10,0xc24b8b70) SHA256_F(w11,0xc76c51a3)
    SHA256_F(w12,0xd192e819) SHA256_F(w13,0xd6990624)
    SHA256_F(w14,0xf40e3585) SHA256_F(w15,0x106aa070)

    SHA256_EXPAND

    SHA256_F(w0 ,0x19a4c116) SHA256_F(w1 ,0x1e376c08)
    SHA256_F(w2 ,0x2748774c) SHA256_F(w3 ,0x34b0bcb5)
    SHA256_F(w4 ,0x391c0cb3) SHA256_F(w5 ,0x4ed8aa4a)
    SHA256_F(w6 ,0x5b9cca4f) SHA256_F(w7 ,0x682e6ff3)
    SHA256_F(w8 ,0x748f82ee) SHA256_F(w9 ,0x78a5636f)
    SHA256_F(w10,0x84c87814) SHA256_F(w11,0x8cc70208)
    SHA256_F(w12,0x90befffa) SHA256_F(w13,0xa4506ceb)
    SHA256_F(w14,0xbef9a3f7) SHA256_F(w15,0xc67178f2)

    aa += state[0]; bb += state[1]; cc += state[2]; dd += state[3];
    ee += state[4]; ff += state[5]; gg += state[6]; hh += state[7];
    state[0] = aa; state[1] = bb; state[2] = cc; state[3] = dd;
    state[4] = ee; state[5] = ff; state[6] = gg; state[7] = hh;

    in += 64;
    inlen -= 64;
  }

  sha256_store_be(statebytes +  0, state[0]);
  sha256_store_be(statebytes +  4, state[1]);
  sha256_store_be(statebytes +  8, state[2]);
  sha256_store_be(statebytes + 12, state[3]);
  sha256_store_be(statebytes + 16, state[4]);
  sha256_store_be(statebytes + 20, state[5]);
  sha256_store_be(statebytes + 24, state[6]);
  sha256_store_be(statebytes + 28, state[7]);

  return (int)inlen;
}

/* ================================================================== */
/* Streaming SHA-256 wrapper                                          */
/* ================================================================== */

typedef struct {
  unsigned char h[32];      /* running hash state (big-endian) */
  unsigned char buf[64];    /* partial block buffer */
  size_t buf_len;           /* bytes in buf */
  unsigned long long total; /* total bytes processed */
} sha256_state;

static const unsigned char sha256_iv[32] = {
  0x6a,0x09,0xe6,0x67, 0xbb,0x67,0xae,0x85,
  0x3c,0x6e,0xf3,0x72, 0xa5,0x4f,0xf5,0x3a,
  0x51,0x0e,0x52,0x7f, 0x9b,0x05,0x68,0x8c,
  0x1f,0x83,0xd9,0xab, 0x5b,0xe0,0xcd,0x19
};

static void sha256_init(sha256_state *st)
{
  memcpy(st->h, sha256_iv, 32);
  st->buf_len = 0;
  st->total = 0;
}

static void sha256_update(sha256_state *st, const unsigned char *data, size_t len)
{
  st->total += len;

  /* Fill partial buffer */
  if (st->buf_len > 0) {
    size_t need = 64 - st->buf_len;
    if (len < need) {
      memcpy(st->buf + st->buf_len, data, len);
      st->buf_len += len;
      return;
    }
    memcpy(st->buf + st->buf_len, data, need);
    sha256_hashblocks(st->h, st->buf, 64);
    data += need;
    len -= need;
    st->buf_len = 0;
  }

  /* Process full blocks directly */
  if (len >= 64) {
    size_t blocks = len & ~(size_t)63;
    sha256_hashblocks(st->h, data, blocks);
    data += blocks;
    len -= blocks;
  }

  /* Buffer remainder */
  if (len > 0) {
    memcpy(st->buf, data, len);
    st->buf_len = len;
  }
}

static void sha256_final(sha256_state *st, unsigned char out[32])
{
  unsigned long long total_bits = st->total * 8;
  unsigned char pad[128]; /* at most 2 blocks */
  size_t pad_len;
  size_t i;

  /* PKCS padding: append 0x80, then zeros, then 64-bit big-endian bit count */
  pad_len = st->buf_len;
  memcpy(pad, st->buf, st->buf_len);
  pad[pad_len++] = 0x80;

  /* Pad to 56 mod 64 */
  if (pad_len > 56) {
    while (pad_len < 64) pad[pad_len++] = 0;
    sha256_hashblocks(st->h, pad, 64);
    pad_len = 0;
  }
  while (pad_len < 56) pad[pad_len++] = 0;

  /* Append bit length (big-endian 64-bit) */
  for (i = 0; i < 8; ++i)
    pad[56 + i] = (unsigned char)(total_bits >> (56 - 8 * i));

  sha256_hashblocks(st->h, pad, 64);
  memcpy(out, st->h, 32);
}

/* Clean up macros */
#undef SHA256_SHR
#undef SHA256_ROTR
#undef SHA256_Ch
#undef SHA256_Maj
#undef SHA256_Sigma0
#undef SHA256_Sigma1
#undef SHA256_sigma0
#undef SHA256_sigma1
#undef SHA256_M
#undef SHA256_EXPAND
#undef SHA256_F
