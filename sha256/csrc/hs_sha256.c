/*
 * Copyright (C) 2006-2009 Vincent Hanquez <vincent@snarc.org>
 *               2016      Herbert Valerio Riedel <hvr@gnu.org>
 *               2024      Leon P Smith
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <ghcautoconf.h>

#include "hs_hashstring_memcmp.h"
#include "hs_sha256.h"

#define ptr_uint32_aligned(ptr) (!((uintptr_t)(ptr) & 0x3))

static inline uint32_t
ror32(const uint32_t word, const unsigned shift)
{
  /* GCC usually transforms this into a 'ror'-insn */
  return (word >> shift) | (word << (32 - shift));
}

static inline uint32_t
cpu_to_be32(const uint32_t hl)
{
#if WORDS_BIGENDIAN
  return hl;
#elif __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3)
  return __builtin_bswap32(hl);
#else
  /* GCC usually transforms this into a bswap insn */
  return ((hl & 0xff000000) >> 24) |
         ((hl & 0x00ff0000) >> 8)  |
         ((hl & 0x0000ff00) << 8)  |
         ( hl               << 24);
#endif
}

static inline void
cpu_to_be32_array(uint32_t *restrict dest, const uint32_t *restrict src, unsigned wordcnt)
{
  while (wordcnt--)
    *dest++ = cpu_to_be32(*src++);
}

static inline uint64_t
cpu_to_be64(const uint64_t hll)
{
#if WORDS_BIGENDIAN
  return hll;
#elif __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3)
  return __builtin_bswap64(hll);
#else
  return ((uint64_t)cpu_to_be32(hll & 0xffffffff) << 32LL) | cpu_to_be32(hll >> 32);
#endif
}

const uint32_t hs_sha256_init[SHA256_STATE_LEN] = {
  0x6a09e667,
  0xbb67ae85,
  0x3c6ef372,
  0xa54ff53a,
  0x510e527f,
  0x9b05688c,
  0x1f83d9ab,
  0x5be0cd19
};

const uint8_t hs_sha256_padding[SHA256_BLOCK_SIZE + 1] = { 0x80, };

/* 232 times the cube root of the first 64 primes 2..311 */
static const uint32_t k[] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define e0(x)       (ror32(x, 2) ^ ror32(x,13) ^ ror32(x,22))
#define e1(x)       (ror32(x, 6) ^ ror32(x,11) ^ ror32(x,25))
#define s0(x)       (ror32(x, 7) ^ ror32(x,18) ^ (x >> 3))
#define s1(x)       (ror32(x,17) ^ ror32(x,19) ^ (x >> 10))

static void
sha256_do_chunk_aligned(uint32_t state[const restrict SHA256_STATE_LEN], uint32_t w[const restrict 64])
{
  int i;

  for (i = 16; i < 64; i++)
    w[i] = s1(w[i - 2]) + w[i - 7] + s0(w[i - 15]) + w[i - 16];

  uint32_t a = state[0];
  uint32_t b = state[1];
  uint32_t c = state[2];
  uint32_t d = state[3];
  uint32_t e = state[4];
  uint32_t f = state[5];
  uint32_t g = state[6];
  uint32_t h = state[7];

#define R(a, b, c, d, e, f, g, h, k, w)             \
    t1 = h + e1(e) + (g ^ (e & (f ^ g))) + k + w;   \
    t2 = e0(a) + ((a & b) | (c & (a | b)));         \
    d += t1;                                        \
    h = t1 + t2;

  for (i = 0; i < 64; i += 8) {
    uint32_t t1, t2;

    R(a, b, c, d, e, f, g, h, k[i + 0], w[i + 0]);
    R(h, a, b, c, d, e, f, g, k[i + 1], w[i + 1]);
    R(g, h, a, b, c, d, e, f, k[i + 2], w[i + 2]);
    R(f, g, h, a, b, c, d, e, k[i + 3], w[i + 3]);
    R(e, f, g, h, a, b, c, d, k[i + 4], w[i + 4]);
    R(d, e, f, g, h, a, b, c, k[i + 5], w[i + 5]);
    R(c, d, e, f, g, h, a, b, k[i + 6], w[i + 6]);
    R(b, c, d, e, f, g, h, a, k[i + 7], w[i + 7]);
  }

#undef R

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
  state[5] += f;
  state[6] += g;
  state[7] += h;
}

static void
sha256_do_chunk
(uint32_t state[const restrict SHA256_STATE_LEN],
 const uint8_t buf[const restrict SHA256_BLOCK_SIZE])
{
  /*
  printf(  "state:   ");
  for (int i = 0; i < SHA256_STATE_LEN; i++)
    printf("%08x", state[i]);
  printf("\nbuffer:  ");
  for (int i = 0; i < SHA256_BLOCK_SIZE; i++)
    printf("%02x", buf[i]);
  printf("\n");
  */
  uint32_t w[64]; /* only first 16 words are filled in */
  if (ptr_uint32_aligned(buf)) { /* aligned buf */
    cpu_to_be32_array(w, (const uint32_t *)buf, 16);
  } else { /* unaligned buf */
    memcpy(w + 16, buf, 64);
#if !WORDS_BIGENDIAN
    cpu_to_be32_array(w, w + 16, 16);
#endif
  }
  sha256_do_chunk_aligned(state, w);
  explicit_bzero(&w, sizeof(w));
  /*
  printf(  "state':  ");
  for (int i = 0; i < SHA256_STATE_LEN; i++)
    printf("%08x", state[i]);
  printf("\n");
  */
}

size_t
hs_sha256_update
(const uint32_t state[const SHA256_STATE_LEN],
 const uint8_t *const data,
 size_t const datalen,
 uint32_t out[const SHA256_STATE_LEN])
{
  if (out != state) memcpy(out, state, SHA256_DIGEST_SIZE);
  if (data == NULL) return 0;
  size_t i = 0;
  size_t dataLeft = datalen;
  while (dataLeft >= SHA256_BLOCK_SIZE) {
      sha256_do_chunk(out, data + i);
      i += SHA256_BLOCK_SIZE;
      dataLeft -= SHA256_BLOCK_SIZE;
  }
  return i;
}

void
hs_sha256_update_ctx
(const sha256_ctx *const in,
 const uint8_t *const data,
 const size_t datalen,
 sha256_ctx *const out)
{
  const size_t bufferlen = in->count & 0x3F;
  if ( data == NULL || datalen == 0 ) {
    if (in != out) memcpy(out, in, sizeof(sha256_ctx) + bufferlen);
  } else if ( datalen + bufferlen < SHA256_BLOCK_SIZE ) {
    if (in != out) memcpy(out, in, sizeof(sha256_ctx) + bufferlen);
    memcpy(out->buffer + bufferlen, data, datalen);
    out->count += datalen;
  } else if ( bufferlen == 0 ) {
    const size_t processedLen = hs_sha256_update(in->state, data, datalen, out->state);
    out->count = in->count + datalen;
    memcpy(out->buffer, data + processedLen, datalen - processedLen);
  } else {
    // Don't assume the output has enough extra space for a full buffer
    uint8_t mybuf[SHA256_BLOCK_SIZE] __attribute__ ((aligned (4)));
    memcpy(mybuf, in->buffer, bufferlen);
    size_t processedDataLen = SHA256_BLOCK_SIZE - bufferlen;
    memcpy(mybuf + bufferlen, data, processedDataLen);
    hs_sha256_update(in->state, mybuf, SHA256_BLOCK_SIZE, out->state);
    processedDataLen += hs_sha256_update( out->state,
					  data + processedDataLen,
					  datalen - processedDataLen,
					  out->state );
    out->count = in->count + datalen;
    memcpy(out->buffer, data + processedDataLen, datalen - processedDataLen );
  }
}

void
hs_sha256_promote_to_ctx
(const uint32_t state[const SHA256_STATE_LEN],
 uint64_t const blockcount,
 const uint8_t *const data,
 size_t const datalen,
 sha256_ctx *const out)
{
  hs_sha256_update(state, data, datalen, out->state);
  out->count = (blockcount << 6) + datalen;
  size_t const bufferlen = datalen & 0x3F;
  if (data != NULL && bufferlen > 0) {
    memcpy(out->buffer, data + (datalen - bufferlen), bufferlen);
  }
}

void
hs_sha256_encode_state
(const uint32_t in[const SHA256_STATE_LEN],
 uint8_t out[const SHA256_DIGEST_SIZE])
{
#if WORDS_BIGENDIAN
  memcpy(out, (uint8_t *)in, SHA256_DIGEST_SIZE);
#else
  if(ptr_uint32_aligned(out)) {
    cpu_to_be32_array((uint32_t *)out, in, SHA256_STATE_LEN);
  } else {
    for (int i = 0; i < SHA256_STATE_LEN; i++) {
      int pos = i << 2;
      out[pos  ] = (in[i] >> 24) & 0xFF;
      out[pos+1] = (in[i] >> 16) & 0xFF;
      out[pos+2] = (in[i] >>  8) & 0xFF;
      out[pos+3] = (in[i]      ) & 0xFF;
    }
  }
#endif
}

void
hs_sha256_decode_state
(const uint8_t in[const SHA256_DIGEST_SIZE],
 uint32_t out[const SHA256_STATE_LEN])
{
#if WORDS_BIGENDIAN
  memcpy((uint8_t *)out, in, SHA256_DIGEST_SIZE);
#else
  if(ptr_uint32_aligned(in)) {
    cpu_to_be32_array(out, (uint32_t *)in, SHA256_STATE_LEN);
  } else {
    for (int i = 0; i < SHA256_DIGEST_SIZE; i += 4) {
      out [i >> 2]
        = ((uint32_t)in[i  ]) << 24
        | ((uint32_t)in[i+1]) << 16
        | ((uint32_t)in[i+2]) <<  8
        | ((uint32_t)in[i+3]);
    }
  }
#endif
}

// The unpinned ByteArray approach I'm taking to the FFI seems to
// necessitate this kind of accessor functions.  It'd be nice
// to simply use #{peek sha256_ctx, count} style accessors from
// haskell, but I'm not sure that works with this approach.
uint64_t
hs_sha256_get_count
(const sha256_ctx *const ctx)
{
  return ctx->count;
}

void
hs_sha256_init_ctx
(sha256_ctx *const out)
{
  hs_sha256_promote_to_ctx(hs_sha256_init, 0, NULL, 0, out);
}

void
hs_sha256_finalize_ctx_bits
(const sha256_ctx *const in,
 const uint8_t *const data,
 uint64_t const datalenbits,
 uint8_t out[const SHA256_DIGEST_SIZE])
{
  uint8_t buffer[SHA256_BLOCK_SIZE] __attribute__ ((aligned (4)));
  uint32_t state[SHA256_STATE_LEN];
  size_t bufferPos = in->count & 0x3F;
  size_t bufferLeft = SHA256_BLOCK_SIZE - bufferPos;
  size_t dataLeft = datalenbits >> 3;
  size_t dataPos;
  memcpy(buffer, in->buffer, bufferPos);
  if (data == NULL || datalenbits < 8) {
    memcpy(state, in, SHA256_DIGEST_SIZE);
    dataPos = 0;
  } else if (dataLeft < bufferLeft) {
    memcpy(state, in, SHA256_DIGEST_SIZE);
    dataPos = dataLeft;
    memcpy(buffer + bufferPos, data, dataLeft);
    bufferPos += dataLeft;
  } else {
    memcpy(buffer + bufferPos, data, bufferLeft);
    hs_sha256_update(in->state, buffer, SHA256_BLOCK_SIZE, state);
    dataPos = bufferLeft;
    dataLeft -= bufferLeft;
    size_t processedLen = hs_sha256_update(state, data + dataPos, dataLeft, state);
    dataPos += processedLen;
    dataLeft -= processedLen;
    memcpy(buffer, data + dataPos, dataLeft);
    bufferPos = dataLeft;
  }

  uint8_t bitsLeft = datalenbits & 7;

  // we need this conditional to avoid dereferencing past the end of "data"
  uint8_t lastByte = bitsLeft == 0 ? 0x80
    : (data[dataPos] & (0xFF << (8 - bitsLeft))) | 1 << (7 - bitsLeft);

  buffer[bufferPos++] = lastByte;

  if (bufferPos <= 56) {
    memset(buffer + bufferPos, 0, 56 - bufferPos);
  } else {
    memset(buffer + bufferPos, 0, 64 - bufferPos);
    sha256_do_chunk(state,buffer);
    memset(buffer, 0, 56);
  }

  uint64_t finalBitLen = (in->count << 3) + datalenbits ;

  buffer[56] = (finalBitLen >> 56) & 0xFF;
  buffer[57] = (finalBitLen >> 48) & 0xFF;
  buffer[58] = (finalBitLen >> 40) & 0xFF;
  buffer[59] = (finalBitLen >> 32) & 0xFF;
  buffer[60] = (finalBitLen >> 24) & 0xFF;
  buffer[61] = (finalBitLen >> 16) & 0xFF;
  buffer[62] = (finalBitLen >>  8) & 0xFF;
  buffer[63] = (finalBitLen      ) & 0xFF;

  sha256_do_chunk(state, buffer);

  hs_sha256_encode_state(state, out);

  explicit_bzero(&state, sizeof(state));
  explicit_bzero(&buffer, sizeof(buffer));
}

int
hs_sha256_const_memcmp_uint32be
(const uint32_t *const a,
 const uint32_t *const b,
 uint32_t const n )
{
  int d, out = 0;
  uint32_t i = n;
  while (i > 0) {
    i--;
    for (int j = 0; j < 32; j += 8 ) {
      d = ((a[i] >> j) & 0xFF) - ((b[i] >> j) & 0xFF);
      out = d == 0 ? out : d;
    }
  }
  return out;
}

// constant-ish time memcmp, could be better, but should be pretty good
// doesn't handle nulls, must be passed a non-null argument!
int
hs_sha256_const_memcmp_ctx
(const sha256_ctx *const a,
 const sha256_ctx *const b )
{
  int d;
  if ( (d = hs_sha256_const_memcmp_uint32be(a->state, b->state, SHA256_STATE_LEN)) ) return d;
  int x = a->count & 0x3F;
  int y = b->count & 0x3F;
  int n = (x < y) ? x : y;
  if ( (d = hs_hashstring_const_memcmp(a->buffer, b->buffer, n)) ) return d;
  if ( (d = x - y) ) return d;
  // does this last comparison even matter in practice?
  if (a->count == b->count) return 0;
  if (a->count < b->count) return -1;
  return 1;
}
