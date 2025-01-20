/*
	Copyright (c) 2014 Steve "Sc00bz" Thomas (steve at tobtu dot com)

	Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software and associated documentation files (the "Software"), to deal
	in the Software without restriction, including without limitation the rights
	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	copies of the Software, and to permit persons to whom the Software is
	furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in all
	copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
	SOFTWARE.
*/

#include "g3p_bcrypt_base64.h"
#include <stdint.h>

// ************************
// *** Helper Functions ***
// ************************

// Base64 character set:
// ./         [A-Z]      [a-z]     [0-9]
// 0x2e-0x2f, 0x41-0x5a, 0x61-0x7a, 0x30-0x39

static inline int base64Decode6BitsDotSlash(uint8_t src)
{
  int ch  = (unsigned char) src;
  int ret = -1;

  // if (ch > 0x2d && ch < 0x30) ret += ch - 0x2e + 1; // -45
  ret += (((0x2d - ch) & (ch - 0x30)) >> 8) & (ch - 45);

  // if (ch > 0x40 && ch < 0x5b) ret += ch - 0x41 + 2 + 1; // -62
  ret += (((0x40 - ch) & (ch - 0x5b)) >> 8) & (ch - 62);

  // if (ch > 0x60 && ch < 0x7b) ret += ch - 0x61 + 28 + 1; // -68
  ret += (((0x60 - ch) & (ch - 0x7b)) >> 8) & (ch - 68);

  // if (ch > 0x2f && ch < 0x3a) ret += ch - 0x30 + 54 + 1; // 7
  ret += (((0x2f - ch) & (ch - 0x3a)) >> 8) & (ch + 7);

  return ret;
}

static inline int base64Decode3BytesDotSlash(uint8_t dest[3], const uint8_t src[4])
{
  int c0 = base64Decode6BitsDotSlash(src[0]);
  int c1 = base64Decode6BitsDotSlash(src[1]);
  int c2 = base64Decode6BitsDotSlash(src[2]);
  int c3 = base64Decode6BitsDotSlash(src[3]);

  dest[0] = (uint8_t) ((c0 << 2) | (c1 >> 4));
  dest[1] = (uint8_t) ((c1 << 4) | (c2 >> 2));
  dest[2] = (uint8_t) ((c2 << 6) |  c3      );
  return ((c0 | c1 | c2 | c3) >> 8) & 1;
}

static inline uint8_t base64Encode6BitsDotSlash(unsigned int src)
{
  src += 0x2e;

  // if (in > 0x2f) in += 0x41 - 0x30; // 17
  src += ((0x2f - src) >> 8) & 17;

  // if (in > 0x5a) in += 0x61 - 0x5b; // 6
  src += ((0x5a - src) >> 8) & 6;

  // if (in > 0x7a) in += 0x30 - 0x7b; // -75
  src -= ((0x7a - src) >> 8) & 75;

  return (char) src;
}

static inline void base64Encode3BytesDotSlash(uint8_t dest[4], const uint8_t src[3])
{
  unsigned int b0 = src[0];
  unsigned int b1 = src[1];
  unsigned int b2 = src[2];

  dest[0] = base64Encode6BitsDotSlash(              b0 >> 2       );
  dest[1] = base64Encode6BitsDotSlash(((b0 << 4) | (b1 >> 4)) & 63);
  dest[2] = base64Encode6BitsDotSlash(((b1 << 2) | (b2 >> 6)) & 63);
  dest[3] = base64Encode6BitsDotSlash(  b2                    & 63);
}



// **********************
// *** Main Functions ***
// **********************

// Base64 character set "./[A-Z][a-z][0-9]"
void G3P_bcrypt_base64Encode(char *dest, const void *src, size_t srcLen)
{
  if (dest == NULL || src == NULL || srcLen == 0) return;
  for (; srcLen >= 3; srcLen -= 3) {
    base64Encode3BytesDotSlash((uint8_t *)dest, (const uint8_t*) src);
    dest += 4;
    src   = (const uint8_t*) src + 3;
  }
  if (srcLen > 0) {
    uint8_t tmp[3] = {0, 0, 0};
    uint8_t tmpdest[4];

    for (size_t i = 0; i < srcLen; i++) {
      tmp[i] = ((const uint8_t*) src)[i];
    }
    base64Encode3BytesDotSlash(tmpdest, tmp);
    dest[0] = tmpdest[0];
    dest[1] = tmpdest[1];
    if (srcLen == 2) {
      dest[2] = tmpdest[2];
    }
  }
}

int G3P_bcrypt_base64Decode(void *dest, const char *src, size_t srcLen)
{
  if (src == NULL || srcLen == 0) return 0;
  if (dest == NULL) return 1;
  int err = 0;

  for (; srcLen > 4; srcLen -= 4) {
    err |= base64Decode3BytesDotSlash((uint8_t*) dest, (uint8_t*)src);
    dest  = (uint8_t*) dest + 3;
    src  += 4;
  }
  if (srcLen > 0) {
    size_t  i;
    uint8_t tmpOut[3];
    uint8_t tmpIn[4] = {'A', 'A', 'A', 'A'};

    for (i = 0; i < srcLen; i++) {
      tmpIn[i] = src[i];
    }
    if (i < 2) {
      err = 1;
    }
    srcLen = i - 1;
    err |= base64Decode3BytesDotSlash(tmpOut, tmpIn);
    for (i = 0; i < srcLen; i++) {
      ((uint8_t*) dest)[i] = tmpOut[i];
    }
  }
  return err;
}
