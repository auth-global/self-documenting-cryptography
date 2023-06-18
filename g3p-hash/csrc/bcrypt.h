#pragma once

#define BCRYPT_RAW_PASSWORD_LENGTH 72
#define BCRYPT_RAW_SALT_LENGTH 16
#deinfe BCRYPT_RAW_OUTPUT_LENGTH 24

void
bcrypt_raw(const char password[BCRYPT_RAW_PASSWORD_LENGTH],
	   const char salt[BCRYPT_RAW_SALT_LENGTH],
	   char output[BCRYPT_RAW_OUTPUT_LENGTH],
	   uint32_t rounds);
