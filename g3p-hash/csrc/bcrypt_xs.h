#pragma once

#include <stdint.h>
#include "g3p_blf.h"

#define BCRYPT_XS_MAX_KEY_LENGTH 72
#define BCRYPT_XS_MAX_SALT_LENGTH G3P_BLF_CTX_LENGTH  // i.e. 4168

void
bcrypt_xs
( const char *key0, uint16_t key0bytes, const char *salt0, uint16_t salt0bytes,
  const char *keyL, uint16_t keyLbytes, const char *saltL, uint16_t saltLbytes,
  const char *keyR, uint16_t keyRbytes, const char *saltR, uint16_t saltRbytes,
  const char *saltZ, uint32_t saltZbytes, uint32_t rounds, char *output );

void
bcrypt_xs_ctr_dump
( const char *key0, uint16_t key0bytes, const char *salt0, uint16_t salt0bytes,
  const char *keyL, uint16_t keyLbytes, const char *saltL, uint16_t saltLbytes,
  const char *keyR, uint16_t keyRbytes, const char *saltR, uint16_t saltRbytes,
  uint32_t rounds, char output[G3P_BLF_CTX_LENGTH] );

void
bcrypt_xs_expand
( G3P_blf_ctx *state,
  const char *key0, uint16_t key0bytes, const char *salt0, uint16_t salt0bytes,
  const char *keyL, uint16_t keyLbytes, const char *saltL, uint16_t saltLbytes,
  const char *keyR, uint16_t keyRbytes, const char *saltR, uint16_t saltRbytes,
  uint32_t rounds );

void
bcrypt_xs_ctr_expand
( G3P_blf_ctx *state,
  const char *key0, uint16_t key0bytes, const char *salt0, uint16_t salt0bytes,
  const char *keyL, uint16_t keyLbytes, const char *saltL, uint16_t saltLbytes,
  const char *keyR, uint16_t keyRbytes, const char *saltR, uint16_t saltRbytes,
  uint32_t rounds );

void
bcrypt_xs_output
( const G3P_blf_ctx * state,
  const char *saltZ, uint32_t saltZbytes,
  uint8_t *output );
