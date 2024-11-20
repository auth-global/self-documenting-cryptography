#pragma once

#include <stdint.h>
// #include <stddef.h>
// #include <assert.h>
// #include <string.h>

#define SHA256_BLOCK_SIZE   64
#define SHA256_DIGEST_SIZE  32
#define SHA256_STATE_LEN     8

typedef struct sha256_ctx
{
  uint32_t state[SHA256_STATE_LEN];
  uint64_t count;
  uint8_t  buffer[];
} sha256_ctx;

uint64_t
hs_sha256_update
(const uint32_t state[const SHA256_STATE_LEN],
 uint64_t const count,
 const uint8_t *const buffer,
 const uint8_t *const data,
 size_t const datalen,
 uint32_t out[const SHA256_STATE_LEN]);

void
hs_sha256_update_ctx
(const sha256_ctx *const in,
 const uint8_t *const data,
 const size_t datalen,
 sha256_ctx  *const out);

void
hs_sha256_promote_to_ctx
(const uint32_t state[const SHA256_STATE_LEN],
 uint64_t const blockcount,
 const uint8_t *const data,
 size_t const datalen,
 sha256_ctx *const out);

void
hs_sha256_finalize
(const uint32_t state[const SHA256_STATE_LEN],
 uint64_t const count,
 const uint8_t *const buffer,
 const uint8_t *const data,
 size_t const datalen,
 uint8_t out[const SHA256_DIGEST_SIZE]);

void
hs_sha256_finalize_ctx
(const sha256_ctx *const in,
 const uint8_t *const data,
 size_t const datalen,
 uint8_t out[const SHA256_DIGEST_SIZE]);

void
hs_sha256_finalize_ctx_bits
(const sha256_ctx *const in,
 const uint8_t *const bits,
 uint64_t const bitlen,
 uint8_t out[const SHA256_DIGEST_SIZE]);

void
hs_sha256_finalize_bits
(const uint32_t state[const SHA256_STATE_LEN],
 uint64_t const count,
 const uint8_t *const buffer,
 const uint8_t *const bits,
 uint64_t const bitlen,
 uint8_t out[const SHA256_DIGEST_SIZE]);

void
hs_sha256_encode_state
(const uint32_t in[const SHA256_STATE_LEN],
 uint8_t out[const SHA256_DIGEST_SIZE]);

void
hs_sha256_decode_state
(const uint8_t in[const SHA256_DIGEST_SIZE],
 uint32_t out[const SHA256_STATE_LEN]);

uint64_t
hs_sha256_get_count
(const sha256_ctx *const ctx);

uint8_t *
hs_sha256_get_buffer
(sha256_ctx *const ctx);

uint32_t *
hs_sha256_get_state
(sha256_ctx *const ctx);

void
hs_sha256_cons
(const uint32_t state[const SHA256_STATE_LEN],
 uint64_t const blockcount,
 const uint8_t *const buffer,
 size_t const bufferlen,
 sha256_ctx *const out);

void
hs_sha256_init_ctx
(sha256_ctx *const out);

int
hs_sha256_const_memcmp
( const uint8_t *const a,
  const uint8_t *const b,
  size_t const n );

int
hs_sha256_const_memcmp_ctx
(const sha256_ctx *const a,
 const sha256_ctx *const b);

int
hs_sha256_const_memcmp_uint32be
(const uint32_t *const a,
 const uint32_t *const b,
 uint32_t const n );

extern const uint32_t hs_sha256_init[SHA256_STATE_LEN];

extern const uint8_t hs_sha256_padding[(SHA256_BLOCK_SIZE + 1)];
