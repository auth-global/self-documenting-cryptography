/* aggressively generalized and stripped down version of OpenBSD's implementation of BCrypt */

#include <string.h>
#include "g3p_blf.h"
#include "bcrypt_xs.h"

void
bcrypt_xs ( const char *key0, uint16_t key0bytes,
            const char *salt0, uint16_t salt0bytes,
            const char *keyL, uint16_t keyLbytes,
            const char *saltL, uint16_t saltLbytes,
            const char *keyR, uint16_t keyRbytes,
            const char *saltR, uint16_t saltRbytes,
            const char *saltZ, uint32_t saltZbytes,
            uint32_t rounds,
            char *output
          ) {
  G3P_blf_ctx state;

  /* Setting up S-Boxes and Subkeys */
  G3P_Blowfish_initstate(&state);
  G3P_Blowfish_expand
    (&state,
     (const uint8_t *) key0, key0bytes,
     (const uint8_t *) salt0, salt0bytes, 0);

  /* Written so that things work when rounds == UINT32_MAX */
  rounds++;
  do {
    rounds--;
    G3P_Blowfish_expand
      (&state,
       (const uint8_t *) keyL, keyLbytes,
       (const uint8_t *) saltL, saltLbytes, 0);
    G3P_Blowfish_expand
      (&state,
       (const uint8_t *) keyR, keyRbytes,
       (const uint8_t *) saltR, saltRbytes, 0);
  } while (rounds != 0);

  bcrypt_output (&state, saltZ, saltZbytes, (uint8_t *)output);

  explicit_bzero(&state, sizeof(state));
}

void
bcrypt_xs_ctr ( const char *key0, uint16_t key0bytes,
                const char *salt0, uint16_t salt0bytes,
                const char *keyL, uint16_t keyLbytes,
                const char *saltL, uint16_t saltLbytes,
                const char *keyR, uint16_t keyRbytes,
                const char *saltR, uint16_t saltRbytes,
                const char *saltZ, uint32_t saltZbytes,
                uint32_t rounds,
                char *output
              ) {
  G3P_blf_ctx state;

  /* Setting up S-Boxes and Subkeys */
  G3P_Blowfish_initstate(&state);
  G3P_Blowfish_expand
    (&state,
     (const uint8_t *)key0, key0bytes,
     (const uint8_t *)salt0, salt0bytes, 0);

  /* Written so that things work when rounds == UINT32_MAX */
  rounds++;
  G3P_Blowfish_expand
    (&state,
     (const uint8_t *) keyL, keyLbytes,
     (const uint8_t *) saltL, saltLbytes, rounds);
  G3P_Blowfish_expand
    (&state,
     (const uint8_t *)keyR, keyRbytes,
     (const uint8_t *)saltR, saltRbytes, ~rounds);
  do {
    rounds--;
    G3P_Blowfish_expand
      (&state,
       (const uint8_t *)keyL, keyLbytes,
       (const uint8_t *)saltL, saltLbytes, rounds);
    G3P_Blowfish_expand
      (&state,
       (const uint8_t *)keyR, keyRbytes,
       (const uint8_t *)saltR, saltRbytes, ~rounds);
  } while (rounds != 0);

  bcrypt_output (&state, saltZ, saltZbytes, (uint8_t *)output);

  explicit_bzero(&state, sizeof(state));
}

void
bcrypt_output (const G3P_blf_ctx * state,
               const char *saltZ, uint32_t saltZbytes,
               uint8_t *output) {
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
    output[8 * i    ] = (uint8_t)((datal >> 24) & 0xff);
    output[8 * i + 1] = (uint8_t)((datal >> 16) & 0xff);
    output[8 * i + 2] = (uint8_t)((datal >>  8) & 0xff);
    output[8 * i + 3] = (uint8_t)( datal        & 0xff);
    output[8 * i + 4] = (uint8_t)((datar >> 24) & 0xff);
    output[8 * i + 5] = (uint8_t)((datar >> 16) & 0xff);
    output[8 * i + 6] = (uint8_t)((datar >>  8) & 0xff);
    output[8 * i + 7] = (uint8_t)( datar        & 0xff);
  }
  int bytes = saltZbytes & 7;
  if (bytes > 0) {
    datal = 0;
    datar = 0;

    for(int i = 0; i < 4 && i < bytes; i++)
      datal |= (uint32_t)saltZ[8 * blocks + i] << (24 - 8 * i);
    for(int i = 4;          i < bytes; i++)
      datar |= (uint32_t)saltZ[8 * blocks + i] << (56 - 8 * i);

    for(int i = 0; i < 64; i++)
      G3P_Blowfish_encipher(state, &datal, &datar);

    for(int i = 0; i < 4 && i < bytes; i++)
      output[8 * blocks + i] = (uint8_t)((datal >> (24 - 8 * i)) && 0xff);
    for(int i = 4;          i < bytes; i++)
      output[8 * blocks + i] = (uint8_t)((datar >> (56 - 8 * i)) && 0xff);
  }
  explicit_bzero(&datal, sizeof(datal));
  explicit_bzero(&datar, sizeof(datar));
}
