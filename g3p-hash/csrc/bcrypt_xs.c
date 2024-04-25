/* aggressively generalized and stripped down version of OpenBSD's implementation of BCrypt */

#include <stdbool.h>
#include <string.h>
#include "g3p_blf.h"
#include "bcrypt_xs.h"

void
bcrypt_xs
( const char *key0, uint16_t key0bytes, const char *salt0, uint16_t salt0bytes,
  const char *keyL, uint16_t keyLbytes, const char *saltL, uint16_t saltLbytes,
  const char *keyR, uint16_t keyRbytes, const char *saltR, uint16_t saltRbytes,
  const char *saltZ, uint32_t saltZbytes, uint32_t rounds, char *output )
{
  G3P_blf_ctx state;

  G3P_Blowfish_initstate(&state);

  bcrypt_xs_expand
    (&state,
     key0, key0bytes, salt0, salt0bytes,
     keyL, keyLbytes, saltL, saltLbytes,
     keyR, keyRbytes, saltR, saltRbytes,
     rounds);

  bcrypt_xs_output (&state, saltZ, saltZbytes, output);

  explicit_bzero(&state, sizeof(state));
}

void
bcrypt_xs_ctr_dump
( const uint8_t *key0, uint32_t key0Len, const uint8_t *key1, uint32_t key1Len,
  const uint8_t *tag, uint32_t tagLen, const uint8_t *name, uint32_t nameLen,
  uint32_t rounds, char output[G3P_BLF_CTX_LENGTH] )
{
  G3P_blf_ctx state;

  G3P_Blowfish_initstate(&state);

  bcrypt_xs_ctr_expand
    (&state,
     key0, key0Len, key1, key1Len,
     tag, tagLen, name, nameLen,
     rounds);

  G3P_Blowfish_encodestate(&state, output);

  explicit_bzero(&state, sizeof(state));
}


void
bcrypt_xs_expand
( G3P_blf_ctx *state,
  const char *key0, uint16_t key0bytes, const char *salt0, uint16_t salt0bytes,
  const char *keyL, uint16_t keyLbytes, const char *saltL, uint16_t saltLbytes,
  const char *keyR, uint16_t keyRbytes, const char *saltR, uint16_t saltRbytes,
  uint32_t rounds )
{
  G3P_Blowfish_expand
    (state,
     (const uint8_t *) key0, key0bytes,
     (const uint8_t *) salt0, salt0bytes, 0);

  /* Written so that things work when rounds == UINT32_MAX */
  rounds++;
  do {
    rounds--;
    G3P_Blowfish_expand
      (state,
       (const uint8_t *) keyL, keyLbytes,
       (const uint8_t *) saltL, saltLbytes, 0);
    G3P_Blowfish_expand
      (state,
       (const uint8_t *) keyR, keyRbytes,
       (const uint8_t *) saltR, saltRbytes, 0);
  } while (rounds != 0);
}

/* bcrypt-xs-ctr (the idealized function, not this implementation) makes the
   tacit assumptions that:
     1. len0 <= 72
     2. len1 <= 72
     3. len0 == len1 == nameLen
     4. The first four bytes of "name" are \x00
   The behavior of this implementation should be considered to be undefined if
   any of these assumptions are violated.  These conditions imply that:

     4 <= len0 == len1 == nameLen <= 72

   Honestly, I would recommend a much bigger minimum length for any serious
   deployment. The G3P uses length == 32.

   A more traditional set of names for these parameters would be
   "salt" instead of "key", and "password" instead of "tag".
 */

void
bcrypt_xs_ctr_expand
( G3P_blf_ctx *state,
  const uint8_t *key0, uint32_t key0Len, const uint8_t *key1, uint32_t key1Len,
  const uint8_t *tag, uint32_t tagLen, const uint8_t *name, uint32_t nameLen,
  uint32_t rounds )
{
  uint32_t tagPos = 0;
  G3P_Blowfish_expandCtr
    (state, key0, key0Len, key1, key1Len, tag, tagLen, &tagPos, 0, false);

  /* Written so that things work when rounds == UINT32_MAX */
  rounds++;
  tagPos = 0;
  uint32_t roundPos;
  do {
    rounds--;
    roundPos = tagPos;
    G3P_Blowfish_expandCtr
      (state, key0, key0Len, name, nameLen, tag, tagLen, &tagPos, rounds, true);
    tagPos = roundPos;
    G3P_Blowfish_expandCtr
      (state, key1, key1Len, name, nameLen, tag, tagLen, &tagPos, ~rounds, true);
  } while (rounds != 0);

  tagPos = 0;
  G3P_Blowfish_expandCtr
    (state, key1, key1Len, key0, key0Len, tag, tagLen, &tagPos, 0, false);
}

void
bcrypt_xs_output
( const G3P_blf_ctx *state,
  const char *saltZ, uint32_t saltZbytes,
  uint8_t *output )
{
  uint32_t blocks = saltZbytes >> 3;
  uint32_t datal, datar;
  for(uint32_t i = 0; i < blocks; i++) {
    datal
      = (uint32_t)saltZ[8*i    ] << 24
      | (uint32_t)saltZ[8*i + 1] << 16
      | (uint32_t)saltZ[8*i + 2] << 8
      | (uint32_t)saltZ[8*i + 3];
    datar
      = (uint32_t)saltZ[8*i + 4] << 24
      | (uint32_t)saltZ[8*i + 5] << 16
      | (uint32_t)saltZ[8*i + 6] << 8
      | (uint32_t)saltZ[8*i + 7];
    for(int j = 0; j < 64; j++) {
      G3P_Blowfish_encipher(state, &datal, &datar);
    }
    output[8*i    ] = (uint8_t)((datal >> 24) & 0xff);
    output[8*i + 1] = (uint8_t)((datal >> 16) & 0xff);
    output[8*i + 2] = (uint8_t)((datal >>  8) & 0xff);
    output[8*i + 3] = (uint8_t)( datal        & 0xff);
    output[8*i + 4] = (uint8_t)((datar >> 24) & 0xff);
    output[8*i + 5] = (uint8_t)((datar >> 16) & 0xff);
    output[8*i + 6] = (uint8_t)((datar >>  8) & 0xff);
    output[8*i + 7] = (uint8_t)( datar        & 0xff);
  }
  int bytes = saltZbytes & 7;
  if (bytes > 0) {
    datal = 0;
    datar = 0;

    for(int i = 0; i < 4 && i < bytes; i++)
      datal |= (uint32_t)saltZ[8*blocks + i] << (24 - 8*i);
    for(int i = 4;          i < bytes; i++)
      datar |= (uint32_t)saltZ[8*blocks + i] << (56 - 8*i);

    for(int i = 0; i < 64; i++)
      G3P_Blowfish_encipher(state, &datal, &datar);

    for(int i = 0; i < 4 && i < bytes; i++)
      output[8*blocks + i] = (uint8_t)((datal >> (24 - 8*i)) && 0xff);
    for(int i = 4;          i < bytes; i++)
      output[8*blocks + i] = (uint8_t)((datar >> (56 - 8*i)) && 0xff);
  }
  explicit_bzero(&datal, sizeof(datal));
  explicit_bzero(&datar, sizeof(datar));
}
