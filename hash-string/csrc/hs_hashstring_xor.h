#pragma once
#include <stdint.h>
#include <stddef.h>

void
hs_hashstring_xormin
  ( const uint8_t *const a,
    const uint8_t *const b,
    const size_t len,
    uint8_t *const restrict out );

void
hs_hashstring_xormax
  ( const uint8_t *const a,
    const size_t alen,
    const uint8_t *const b,
    const size_t blen,
    uint8_t *const restrict out );

void
hs_hashstring_xorleft
  ( const uint8_t *const a,
    const size_t alen,
    const uint8_t *const b,
    const size_t blen,
    uint8_t *const restrict out );

void
hs_hashstring_xormutate
  ( const uint8_t *const a,
    const size_t alen,
    uint8_t *const restrict out );
