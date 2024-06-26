/*
BLAKE2 reference source code package - reference C implementations

Copyright 2012, Samuel Neves <sneves@dei.uc.pt>.  You may use this under the
terms of the CC0, the OpenSSL Licence, or the Apache Public License 2.0, at
your option.  The terms of these licenses can be found at:

- CC0 1.0 Universal : http://creativecommons.org/publicdomain/zero/1.0
- OpenSSL license   : https://www.openssl.org/source/license.html
- Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0

More information about the BLAKE2 hash function can be found at
https://blake2.net.
*/

#include "stdafx.h"
#ifndef __STDC_LIMIT_MACROS
#define __STDC_LIMIT_MACROS
#include <stdint.h>
#endif
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include "tunsafe_types.h"
#include "blake2s.h"
#include "crypto_ops.h"

#ifndef BLAKE2S_WITH_ASM
#define BLAKE2S_WITH_ASM 1
#endif  // BLAKE2S_WITH_ASM

#if !defined(__cplusplus) && (!defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901L)
#if   defined(_MSC_VER)
#define BLAKE2_INLINE __inline
#elif defined(__GNUC__)
#define BLAKE2_INLINE __inline__
#else
#define BLAKE2_INLINE
#endif
#else
#define BLAKE2_INLINE inline
#endif

static BLAKE2_INLINE uint32_t load32(const void *src) {
#if defined(ARCH_CPU_LITTLE_ENDIAN)
  uint32_t w;
  memcpy(&w, src, sizeof w);
  return w;
#else
  const uint8_t *p = (const uint8_t *)src;
  return ((uint32_t)(p[0]) << 0) |
    ((uint32_t)(p[1]) << 8) |
    ((uint32_t)(p[2]) << 16) |
    ((uint32_t)(p[3]) << 24);
#endif
}

static BLAKE2_INLINE uint16_t load16(const void *src) {
#if defined(ARCH_CPU_LITTLE_ENDIAN)
  uint16_t w;
  memcpy(&w, src, sizeof w);
  return w;
#else
  const uint8_t *p = (const uint8_t *)src;
  return ((uint16_t)(p[0]) << 0) |
    ((uint16_t)(p[1]) << 8);
#endif
}

static BLAKE2_INLINE void store16(void *dst, uint16_t w) {
#if defined(ARCH_CPU_LITTLE_ENDIAN)
  memcpy(dst, &w, sizeof w);
#else
  uint8_t *p = (uint8_t *)dst;
  *p++ = (uint8_t)w; w >>= 8;
  *p++ = (uint8_t)w;
#endif
}

static BLAKE2_INLINE void store32(void *dst, uint32_t w) {
#if defined(ARCH_CPU_LITTLE_ENDIAN)
  memcpy(dst, &w, sizeof w);
#else
  uint8_t *p = (uint8_t *)dst;
  p[0] = (uint8_t)(w >> 0);
  p[1] = (uint8_t)(w >> 8);
  p[2] = (uint8_t)(w >> 16);
  p[3] = (uint8_t)(w >> 24);
#endif
}

static BLAKE2_INLINE uint32_t rotr32(const uint32_t w, const unsigned c) {
  return (w >> c) | (w << (32 - c));
}

static BLAKE2_INLINE uint64_t rotr64(const uint64_t w, const unsigned c) {
  return (w >> c) | (w << (64 - c));
}

static const uint32_t blake2s_IV[8] = {
  0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
  0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL
};

static const uint8_t blake2s_sigma[10][16] =
{
  {0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15} ,
  {14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3} ,
  {11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4} ,
  {7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8} ,
  {9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13} ,
  {2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9} ,
  {12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11} ,
  {13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10} ,
  {6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5} ,
  {10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0} ,
};

static void blake2s_set_lastnode(blake2s_state *S) {
  S->f[1] = (uint32_t)-1;
}

/* Some helper functions, not necessarily useful */
static int blake2s_is_lastblock(const blake2s_state *S) {
  return S->f[0] != 0;
}

static void blake2s_set_lastblock(blake2s_state *S) {
  if (S->last_node) blake2s_set_lastnode(S);

  S->f[0] = (uint32_t)-1;
}

static void blake2s_increment_counter(blake2s_state *S, const uint32_t inc) {
  S->t[0] += inc;
  S->t[1] += (S->t[0] < inc);
}

void blake2s_init_with_len(blake2s_state *S, size_t outlen, size_t keylen) {
  memset(S, 0, sizeof(blake2s_state));

  blake2s_param *P = &S->param;
  size_t i;

  /* Move interval verification here? */
  assert(outlen && outlen <= BLAKE2S_OUTBYTES);

  P->digest_length = (uint8_t)outlen;
  S->outlen = (uint8_t)outlen;
  P->key_length = (uint8_t)keylen;
  P->fanout = 1;
  P->depth = 1;
  //  store32(&P.leaf_length, 0);
  //  store32(&P.node_offset, 0);
  //  store16(&P.xof_length, 0);
  //  P.node_depth = 0;
  //  P.inner_length = 0;
  /* memset(P->reserved, 0, sizeof(P->reserved) ); */
  //  memset(P.salt, 0, sizeof(P.salt));
  //  memset(P.personal, 0, sizeof(P.personal));
  for (i = 0; i < 8; ++i)
    S->h[i] = load32(&S->h[i]) ^ blake2s_IV[i];

}

/* Sequential blake2s initialization */
void blake2s_init(blake2s_state *S, size_t outlen) {
  blake2s_init_with_len(S, outlen, 0);
}

void blake2s_init_key(blake2s_state *S, size_t outlen, const void *key, size_t keylen) {
  uint8_t block[BLAKE2S_BLOCKBYTES];

  assert(outlen && outlen <= BLAKE2S_OUTBYTES);
  assert(key && keylen && keylen <= BLAKE2S_KEYBYTES);

  blake2s_init_with_len(S, outlen, keylen);

  memset(block, 0, BLAKE2S_BLOCKBYTES);
  memcpy(block, key, keylen);
  blake2s_update(S, block, BLAKE2S_BLOCKBYTES);
  memzero_crypto(block, BLAKE2S_BLOCKBYTES); /* Burn the key from stack */
}

#define G(r,i,a,b,c,d)                      \
  do {                                      \
    a = a + b + m[blake2s_sigma[r][2*i+0]]; \
    d = rotr32(d ^ a, 16);                  \
    c = c + d;                              \
    b = rotr32(b ^ c, 12);                  \
    a = a + b + m[blake2s_sigma[r][2*i+1]]; \
    d = rotr32(d ^ a, 8);                   \
    c = c + d;                              \
    b = rotr32(b ^ c, 7);                   \
  } while(0)

#define ROUND(r)                    \
  do {                              \
    G(r,0,v[ 0],v[ 4],v[ 8],v[12]); \
    G(r,1,v[ 1],v[ 5],v[ 9],v[13]); \
    G(r,2,v[ 2],v[ 6],v[10],v[14]); \
    G(r,3,v[ 3],v[ 7],v[11],v[15]); \
    G(r,4,v[ 0],v[ 5],v[10],v[15]); \
    G(r,5,v[ 1],v[ 6],v[11],v[12]); \
    G(r,6,v[ 2],v[ 7],v[ 8],v[13]); \
    G(r,7,v[ 3],v[ 4],v[ 9],v[14]); \
  } while(0)

static void blake2s_compress(blake2s_state *S, const uint8_t in[BLAKE2S_BLOCKBYTES]) {
  uint32_t m[16];
  uint32_t v[16];
  size_t i;

  for (i = 0; i < 16; ++i) {
    m[i] = load32(in + i * sizeof(m[i]));
  }

  for (i = 0; i < 8; ++i) {
    v[i] = S->h[i];
  }

  v[8] = blake2s_IV[0];
  v[9] = blake2s_IV[1];
  v[10] = blake2s_IV[2];
  v[11] = blake2s_IV[3];
  v[12] = S->t[0] ^ blake2s_IV[4];
  v[13] = S->t[1] ^ blake2s_IV[5];
  v[14] = S->f[0] ^ blake2s_IV[6];
  v[15] = S->f[1] ^ blake2s_IV[7];

  ROUND(0);
  ROUND(1);
  ROUND(2);
  ROUND(3);
  ROUND(4);
  ROUND(5);
  ROUND(6);
  ROUND(7);
  ROUND(8);
  ROUND(9);

  for (i = 0; i < 8; ++i) {
    S->h[i] = S->h[i] ^ v[i] ^ v[i + 8];
  }
}

#undef G
#undef ROUND


#if defined(ARCH_CPU_X86_FAMILY)
#include "blake2s-sse-impl.h"
#endif


static inline void blake2s_compress_impl(blake2s_state *S, const uint8_t block[BLAKE2S_BLOCKBYTES]) {
#if defined(ARCH_CPU_X86_64) && BLAKE2S_WITH_ASM
  blake2s_compress_sse(S, block);
#else
  blake2s_compress(S, block);
#endif
}

void blake2s_update(blake2s_state *S, const void *pin, size_t inlen) {
  const unsigned char * in = (const unsigned char *)pin;
  if (inlen > 0) {
    size_t left = S->buflen;
    size_t fill = BLAKE2S_BLOCKBYTES - left;
    if (inlen > fill) {
      S->buflen = 0;
      memcpy(S->buf + left, in, fill); /* Fill buffer */
      blake2s_increment_counter(S, BLAKE2S_BLOCKBYTES);
      blake2s_compress_impl(S, S->buf); /* Compress */
      in += fill; inlen -= fill;
      while (inlen > BLAKE2S_BLOCKBYTES) {
        blake2s_increment_counter(S, BLAKE2S_BLOCKBYTES);
        blake2s_compress_impl(S, in);
        in += BLAKE2S_BLOCKBYTES;
        inlen -= BLAKE2S_BLOCKBYTES;
      }
    }
    memcpy(S->buf + S->buflen, in, inlen);
    S->buflen += inlen;
  }
}

void blake2s_final(blake2s_state *S, void *out, size_t outlen) {
  size_t i;

  assert(out != NULL && outlen >= S->outlen);
  assert(!blake2s_is_lastblock(S));

  blake2s_increment_counter(S, (uint32_t)S->buflen);
  blake2s_set_lastblock(S);
  memset(S->buf + S->buflen, 0, BLAKE2S_BLOCKBYTES - S->buflen); /* Padding */
  blake2s_compress_impl(S, S->buf);

  for (i = 0; i < 8; ++i) /* Output full hash to temp buffer */
    store32(&S->h[i], S->h[i]);

  memcpy(out, S->h, outlen);
}

SAFEBUFFERS void blake2s(void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen) {
  blake2s_state S;

  /* Verify parameters */
  assert(!((NULL == in && inlen > 0)));
  assert(out);
  assert(!(NULL == key && keylen > 0));
  assert(!(!outlen || outlen > BLAKE2S_OUTBYTES));
  assert(!(keylen > BLAKE2S_KEYBYTES));

  if (keylen > 0) {
    blake2s_init_key(&S, outlen, key, keylen);
  } else {
    blake2s_init(&S, outlen);
  }
  blake2s_update(&S, (const uint8_t *)in, inlen);
  blake2s_final(&S, out, outlen);
}

SAFEBUFFERS void blake2s_hmac(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen, const uint8_t *key, size_t keylen) {
  blake2s_state b2s;
  uint64_t temp[BLAKE2S_OUTBYTES / 8];
  uint64_t key_temp[BLAKE2S_BLOCKBYTES / 8] = { 0 };

  if (keylen > BLAKE2S_BLOCKBYTES) {
    blake2s_init(&b2s, BLAKE2S_OUTBYTES);
    blake2s_update(&b2s, key, keylen);
    blake2s_final(&b2s, key_temp, BLAKE2S_OUTBYTES);
  } else {
    memcpy(key_temp, key, keylen);
  }

  for (size_t i = 0; i < BLAKE2S_BLOCKBYTES / 8; i++)
    key_temp[i] ^= 0x3636363636363636ull;

  blake2s_init(&b2s, BLAKE2S_OUTBYTES);
  blake2s_update(&b2s, key_temp, BLAKE2S_BLOCKBYTES);
  blake2s_update(&b2s, in, inlen);
  blake2s_final(&b2s, temp, BLAKE2S_OUTBYTES);

  for (size_t i = 0; i < BLAKE2S_BLOCKBYTES / 8; i++)
    key_temp[i] ^= 0x5c5c5c5c5c5c5c5cull ^ 0x3636363636363636ull;

  blake2s_init(&b2s, BLAKE2S_OUTBYTES);
  blake2s_update(&b2s, key_temp, BLAKE2S_BLOCKBYTES);
  blake2s_update(&b2s, temp, BLAKE2S_OUTBYTES);
  blake2s_final(&b2s, temp, BLAKE2S_OUTBYTES);

  memcpy(out, temp, outlen);
  memzero_crypto(key_temp, sizeof(key_temp));
  memzero_crypto(temp, sizeof(temp));
}

SAFEBUFFERS
void blake2s_hkdf(uint8 *dst1, size_t dst1_size,
                  uint8 *dst2, size_t dst2_size,
                  uint8 *dst3, size_t dst3_size,
                  const uint8 *data, size_t data_size,
                  const uint8 *key, size_t key_size) {
  struct {
    uint8 prk[BLAKE2S_OUTBYTES];
    uint8 temp[BLAKE2S_OUTBYTES + 1];
  } t;
  blake2s_hmac(t.prk, BLAKE2S_OUTBYTES, data, data_size, key, key_size);
  // first-key = HMAC(secret, 0x1)
  t.temp[0] = 0x1;
  blake2s_hmac(t.temp, BLAKE2S_OUTBYTES, t.temp, 1, t.prk, BLAKE2S_OUTBYTES);
  memcpy(dst1, t.temp, dst1_size);
  if (dst2 != NULL) {
    // second-key = HMAC(secret, first-key || 0x2)
    t.temp[BLAKE2S_OUTBYTES] = 0x2;
    blake2s_hmac(t.temp, BLAKE2S_OUTBYTES, t.temp, BLAKE2S_OUTBYTES + 1, t.prk,  BLAKE2S_OUTBYTES);
    memcpy(dst2, t.temp, dst2_size);
    if (dst3 != NULL) {
      // third-key = HMAC(secret, second-key || 0x3)
      t.temp[BLAKE2S_OUTBYTES] = 0x3;
      blake2s_hmac(t.temp, BLAKE2S_OUTBYTES, t.temp, BLAKE2S_OUTBYTES + 1, t.prk, BLAKE2S_OUTBYTES);
      memcpy(dst3, t.temp, dst3_size);
    }
  }
  memzero_crypto(&t, sizeof(t));
}


#if defined(SUPERCOP)
int crypto_hash(unsigned char *out, unsigned char *in, unsigned long long inlen) {
  return blake2s(out, BLAKE2S_OUTBYTES in, inlen, NULL, 0);
}
#endif

#if defined(BLAKE2S_SELFTEST)
#include <string.h>
#include "blake2-kat.h"
int main(void) {
  uint8_t key[BLAKE2S_KEYBYTES];
  uint8_t buf[BLAKE2_KAT_LENGTH];
  size_t i, step;

  for (i = 0; i < BLAKE2S_KEYBYTES; ++i)
    key[i] = (uint8_t)i;

  for (i = 0; i < BLAKE2_KAT_LENGTH; ++i)
    buf[i] = (uint8_t)i;

  /* Test simple API */
  for (i = 0; i < BLAKE2_KAT_LENGTH; ++i) {
    uint8_t hash[BLAKE2S_OUTBYTES];
    blake2s(hash, BLAKE2S_OUTBYTES, buf, i, key, BLAKE2S_KEYBYTES);

    if (0 != memcmp(hash, blake2s_keyed_kat[i], BLAKE2S_OUTBYTES)) {
      goto fail;
    }
  }

  /* Test streaming API */
  for (step = 1; step < BLAKE2S_BLOCKBYTES; ++step) {
    for (i = 0; i < BLAKE2_KAT_LENGTH; ++i) {
      uint8_t hash[BLAKE2S_OUTBYTES];
      blake2s_state S;
      uint8_t * p = buf;
      size_t mlen = i;
      int err = 0;

      if ((err = blake2s_init_key(&S, BLAKE2S_OUTBYTES, key, BLAKE2S_KEYBYTES)) < 0) {
        goto fail;
      }

      while (mlen >= step) {
        if ((err = blake2s_update(&S, p, step)) < 0) {
          goto fail;
        }
        mlen -= step;
        p += step;
      }
      if ((err = blake2s_update(&S, p, mlen)) < 0) {
        goto fail;
      }
      if ((err = blake2s_final(&S, hash, BLAKE2S_OUTBYTES)) < 0) {
        goto fail;
      }

      if (0 != memcmp(hash, blake2s_keyed_kat[i], BLAKE2S_OUTBYTES)) {
        goto fail;
      }
    }
  }

  puts("ok");
  return 0;
fail:
  puts("error");
  return -1;
}
#endif
