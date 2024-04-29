#pragma once
/* $OpenBSD: blf.h,v 1.8 2021/11/29 01:04:45 djm Exp $ */
/*
 * Blowfish - a fast block cipher designed by Bruce Schneier
 *
 * Copyright 1997 Niels Provos <provos@physnet.uni-hamburg.de>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* Schneier specifies a maximum key length of 56 bytes.
 * This ensures that every key bit affects every cipher
 * bit.  However, the subkeys can hold up to 72 bytes.
 * Warning: For normal blowfish encryption only 56 bytes
 * of the key affect all cipherbits.
 */

#include <stdbool.h>
#include <stdint.h>

#define G3P_BLF_N	16			/* Number of Subkeys */
#define G3P_BLF_MAXKEYLEN ((G3P_BLF_N-2)*4)	/* 448 bits */
#define G3P_BLF_MAXUTILIZED ((G3P_BLF_N+2)*4)	/* 576 bits */
#define G3P_BLF_CTX_LENGTH 4168

/* Blowfish context */
typedef struct BlowfishContext {
	uint32_t S[4][256];	/* S-Boxes */
	uint32_t P[G3P_BLF_N + 2];	/* Subkeys */
} G3P_blf_ctx;

/* Raw access to customized Blowfish
 *	G3P_blf_key is just:
 *	G3P_Blowfish_initstate( state )
 *	G3P_Blowfish_expand0state( state, key, keylen )
 */

void G3P_Blowfish_encipher(const G3P_blf_ctx *, uint32_t *, uint32_t *);
void G3P_Blowfish_decipher(const G3P_blf_ctx *, uint32_t *, uint32_t *);
void G3P_Blowfish_initstate(G3P_blf_ctx *);
void G3P_Blowfish_expand(G3P_blf_ctx *c,
                         const uint8_t *key, uint16_t keybytes,
                         const uint8_t *salt, uint16_t saltbytes,
                         uint32_t ctr);
uint32_t
G3P_Blowfish_expandCtr
( G3P_blf_ctx *c,
  const uint8_t *key, uint32_t keyLen,
  const uint8_t *name, uint32_t nameLen,
  const uint8_t *tag, uint32_t tagLen, uint32_t tagPos,
  uint32_t ctr, bool keyIsFirst );

uint32_t G3P_Blowfish_readP(const G3P_blf_ctx *c, uint8_t i);
uint32_t G3P_Blowfish_readS(const G3P_blf_ctx *c, uint8_t i, uint8_t j);

void G3P_Blowfish_encodestate(const G3P_blf_ctx *c, uint8_t out[G3P_BLF_CTX_LENGTH]);
void G3P_Blowfish_decodestate(const uint8_t in[G3P_BLF_CTX_LENGTH], G3P_blf_ctx *c);

uint32_t
G3P_thenCycle(uint32_t *np,
              const uint8_t *a, uint32_t al, uint32_t *ap,
              const uint8_t *b, uint32_t bl, uint32_t *bp);
