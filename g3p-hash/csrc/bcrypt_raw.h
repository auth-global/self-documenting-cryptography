#pragma once

#include <stdint.h>

#define BCRYPT_RAW_KEY_LENGTH 72
#define BCRYPT_RAW_SALT_LENGTH 16
#define BCRYPT_RAW_OUTPUT_LENGTH 24

void
bcrypt_raw(const char key[BCRYPT_RAW_KEY_LENGTH],
	   const char salt[BCRYPT_RAW_SALT_LENGTH],
	   char output[BCRYPT_RAW_OUTPUT_LENGTH],
	   uint32_t rounds);
