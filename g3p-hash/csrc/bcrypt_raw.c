/* lightly modified and aggressively stripped down version of OpenBSD's implementation of BCrypt */

#include <string.h>
#include "g3p_blf.h"
#include "bcrypt_raw.h"

#define BCRYPT_WORDS 6

void
bcrypt_raw(const char key[BCRYPT_RAW_KEY_LENGTH],
	   const char salt[BCRYPT_RAW_SALT_LENGTH],
	   char output[BCRYPT_RAW_OUTPUT_LENGTH],
	   uint32_t rounds) {
        G3P_blf_ctx state;
        uint8_t ciphertext[BCRYPT_RAW_OUTPUT_LENGTH] = "OrpheanBeholderScryDoubt";
	uint32_t cdata[BCRYPT_WORDS];
	
	/* Setting up S-Boxes and Subkeys */
	G3P_Blowfish_initstate(&state);
	G3P_Blowfish_expandstate(&state,
	    (const uint8_t *) salt, BCRYPT_RAW_SALT_LENGTH,
	    (const uint8_t *) key, BCRYPT_RAW_KEY_LENGTH);

	/* Written so that things work when rounds == UINT32_MAX */ 
	rounds++;
	do {
		G3P_Blowfish_expand0state(&state, (const uint8_t *) key, BCRYPT_RAW_KEY_LENGTH);
		G3P_Blowfish_expand0state(&state, (const uint8_t *) salt, BCRYPT_RAW_SALT_LENGTH);
		rounds--;
	} while (rounds != 0);

	uint16_t j = 0;
	for (uint32_t i = 0; i < BCRYPT_WORDS; i++)
		cdata[i] = G3P_Blowfish_stream2word(ciphertext, 4 * BCRYPT_WORDS, &j);

	/* Now do the encryption */
	for (uint32_t k = 0; k < 64; k++)
		G3P_blf_enc(&state, cdata, BCRYPT_WORDS / 2);

	for (uint32_t i = 0; i < BCRYPT_WORDS; i++) {
		ciphertext[4 * i + 3] = cdata[i] & 0xff;
		cdata[i] = cdata[i] >> 8;
		ciphertext[4 * i + 2] = cdata[i] & 0xff;
		cdata[i] = cdata[i] >> 8;
		ciphertext[4 * i + 1] = cdata[i] & 0xff;
		cdata[i] = cdata[i] >> 8;
		ciphertext[4 * i + 0] = cdata[i] & 0xff;
	}

	memcpy(output, ciphertext, BCRYPT_RAW_OUTPUT_LENGTH);
	explicit_bzero(&state, sizeof(state));
	explicit_bzero(ciphertext, sizeof(ciphertext));
        explicit_bzero(cdata, sizeof(cdata));
}
