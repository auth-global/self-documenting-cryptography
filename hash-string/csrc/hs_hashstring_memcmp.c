#include <stdint.h>
#include "hs_hashstring_memcmp.h"

int
hs_hashstring_const_memcmp
( const uint8_t *const a,
  const uint8_t *const b,
  size_t const n )
{
  int d, out = 0;
  size_t i = n;
  while (i > 0) {
    i--;
    d = a[i] - b[i];
    out = d == 0 ? out : d;
  }
  return out;
}
