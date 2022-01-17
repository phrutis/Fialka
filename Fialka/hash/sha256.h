/*
 * This file is part of the VanitySearch distribution (https://github.com/JeanLucPons/VanitySearch).
 * Copyright (c) 2019 Jean Luc PONS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

//#ifndef SHA256_H
#define SHA256_H
#ifndef SHA256_H_INCLUDED
#define SHA256_H_INCLUDED
#include <string>
#define SHA256_HASH_LENGTH 32
#include "../includeAll.h"

void sha256(uint8_t *input, int length, uint8_t *digest);
void sha256_33(uint8_t *input, uint8_t *digest);
void sha256_65(uint8_t *input, uint8_t *digest);
void sha256_checksum(uint8_t *input, int length, uint8_t *checksum);
void sha256sse_1B(uint32_t *i0, uint32_t *i1, uint32_t *i2, uint32_t *i3,
                  uint8_t *d0, uint8_t *d1, uint8_t *d2, uint8_t *d3);
void sha256sse_2B(uint32_t *i0, uint32_t *i1, uint32_t *i2, uint32_t *i3,
                  uint8_t *d0, uint8_t *d1, uint8_t *d2, uint8_t *d3);
void sha256sse_checksum(uint32_t *i0, uint32_t *i1, uint32_t *i2, uint32_t *i3,
                        uint8_t *d0, uint8_t *d1, uint8_t *d2, uint8_t *d3);
std::string sha256_hex(unsigned char *digest);
void sha256sse_test();

extern uint32_t sha256_h[8];

extern void sha256Begin(HashState* hs);
extern void sha256WriteByte(HashState* hs, uint8_t byte);
extern void sha256Finish(HashState* hs);
extern void sha256FinishDouble(HashState* hs);
extern void sha256(uint8_t* message, uint32_t length);
void sha256_double(unsigned char* bufIN, unsigned short length);
#endif // #ifndef SHA256_H_INCLUDED
