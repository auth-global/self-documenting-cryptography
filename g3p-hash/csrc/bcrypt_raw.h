#pragma once

#include <stdint.h>

#define BCRYPT_RAW_MAX_INPUT_LENGTH 72
#define BCRYPT_RAW_OUTPUT_LENGTH 24

void
bcrypt_raw ( const char *key, uint32_t keybytes,
             const char *salt, uint32_t saltbytes,
             char output[BCRYPT_RAW_OUTPUT_LENGTH],
             uint32_t rounds);
