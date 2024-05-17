#pragma once

// #include <stdint.h>
// #include <stddef.h>
// #include <assert.h>
// #include <string.h>

#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE	32
#define SHA256_STATE_LEN 8

typedef struct sha256_ctx
{
  uint32_t state[SHA256_STATE_LEN];
  uint64_t count;
  uint8_t  buffer[];
} sha256_ctx;

uint64_t hs_sha256_update
  (const uint32_t state[const restrict SHA256_STATE_LEN],
   uint64_t const count,
   const uint8_t *const buffer,
   const uint8_t *const data,
   size_t const datalen,
   uint32_t out[const restrict SHA256_STATE_LEN]);

void hs_sha256_update_ctx
  (const sha256_ctx *const restrict in,
   const uint8_t *const data,
   const size_t datalen,
   sha256_ctx  *const restrict out);

/*
uint64_t hs_sha256_mutate
  (uint32_t inout[SHA256_STATE_LEN],
   uint64_t const count,
   const uint8_t **buffer,
   const uint8_t *const data,
   size_t const datalen)

void hs_sha256_mutate_ctx
  (sha256_ctx  *const inout,
   const uint8_t *const data,
   const size_t datalen);
*/

/*
void hs_sha256_finalize
  (const sha256_ctx *const in,
   uint8_t *const out);

void hs_sha256_finalize_bits
  (const sha256_ctx *const in,
   const uint8_t *const bits,
   const uint64_t bitlen,
   uint8_t *const out);
*/

void hs_sha256_encode_state
  (const uint32_t in[const restrict SHA256_STATE_LEN],
   uint8_t out[const restrict SHA256_DIGEST_SIZE]);

void hs_sha256_decode_state
  (const uint8_t in[const restrict SHA256_DIGEST_SIZE],
   uint32_t out[const restrict SHA256_STATE_LEN]);

extern const uint32_t hs_sha256_init[const SHA256_STATE_LEN];

extern const uint8_t hs_sha256_padding[const (SHA256_BLOCK_SIZE + 1)];
