#include <hs_hashstring_xor.h>
#include <string.h>

void
hs_hashstring_xormin
  ( const uint8_t *const restrict a,
    const uint8_t *const restrict b,
    const size_t len,
    uint8_t *const restrict out )
{
  for(size_t i = 0; i < len; i++) {
    out[i] = a[i] ^ b[i];
  }
}

void
hs_hashstring_xormax
  ( const uint8_t *const restrict a,
    const size_t alen,
    const uint8_t *const restrict b,
    const size_t blen,
    uint8_t *const restrict out )
{
  if (alen <= blen) {
    hs_hashstring_xormin(a,b,alen,out);
    memcpy(out + alen, b + alen, blen - alen);
  } else {
    hs_hashstring_xormin(a,b,blen,out);
    memcpy(out + blen, a + blen, alen - blen);
  }
}

void
hs_hashstring_xorleft
  ( const uint8_t *const restrict a,
    const size_t alen,
    const uint8_t *const restrict b,
    const size_t blen,
    uint8_t *const restrict out )
{
  if (alen <= blen) {
    hs_hashstring_xormin(a,b,alen,out);
  } else {
    hs_hashstring_xormin(a,b,blen,out);
    memcpy(out + blen, a + blen, alen - blen);
  }
}
void
hs_hashstring_xormutate
  ( const uint8_t *const restrict a,
    const size_t len,
    uint8_t *const restrict out )
{
  for(size_t i = 0; i < len; i++) {
    out[i] ^= a[i];
  }
}
