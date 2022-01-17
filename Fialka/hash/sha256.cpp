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
#include "../includeAll.h"
#include <string.h>
#include "sha256.h"

#define BSWAP

/// Internal SHA-256 implementation.
namespace _sha256
{

static const unsigned char pad[64] = { 0x80 };

#ifndef WIN64
#define _byteswap_ulong __builtin_bswap32
#define _byteswap_uint64 __builtin_bswap64
inline uint32_t _rotr(uint32_t x, uint8_t r)
{
    asm("rorl %1,%0" : "+r"(x) : "c"(r));
    return x;
}
#endif

#define ROR(x,n) _rotr(x, n)
#define S0(x) (ROR(x,2) ^ ROR(x,13) ^ ROR(x,22))
#define S1(x) (ROR(x,6) ^ ROR(x,11) ^ ROR(x,25))
#define s0(x) (ROR(x,7) ^ ROR(x,18) ^ (x >> 3))
#define s1(x) (ROR(x,17) ^ ROR(x,19) ^ (x >> 10))

#define Maj(x,y,z) ((x&y)^(x&z)^(y&z))
//#define Ch(x,y,z)  ((x&y)^(~x&z))

// The following functions are equivalent to the above
//#define Maj(x,y,z) ((x & y) | (z & (x | y)))
#define Ch(x,y,z) (z ^ (x & (y ^ z)))

// SHA-256 round
#define Round(a, b, c, d, e, f, g, h, k, w) \
    t1 = h + S1(e) + Ch(e,f,g) + k + (w); \
    t2 = S0(a) + Maj(a,b,c); \
    d += t1; \
    h = t1 + t2;

#ifdef BSWAP
#define WRITEBE32(ptr,x) *((uint32_t *)(ptr)) = _byteswap_ulong(x)
#define WRITEBE64(ptr,x) *((uint64_t *)(ptr)) = _byteswap_uint64(x)
#define READBE32(ptr) (uint32_t)_byteswap_ulong(*(uint32_t *)(ptr))
#else
#define WRITEBE32(ptr,x) *(ptr) = x
#define WRITEBE64(ptr,x) *(ptr) = x
#define READBE32(ptr) *(uint32_t *)(ptr)
#endif

// Initialise state
void Initialize(uint32_t *s)
{

    s[0] = 0x6a09e667ul;
    s[1] = 0xbb67ae85ul;
    s[2] = 0x3c6ef372ul;
    s[3] = 0xa54ff53aul;
    s[4] = 0x510e527ful;
    s[5] = 0x9b05688cul;
    s[6] = 0x1f83d9abul;
    s[7] = 0x5be0cd19ul;

}


// Perform SHA-256 transformations, process 64-byte chunks
void Transform(uint32_t *s, const unsigned char *chunk)
{
    uint32_t t1;
    uint32_t t2;
    uint32_t a = s[0], b = s[1], c = s[2], d = s[3], e = s[4], f = s[5], g = s[6], h = s[7];
    uint32_t w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15;

    Round(a, b, c, d, e, f, g, h, 0x428a2f98, w0 = READBE32(chunk + 0));
    Round(h, a, b, c, d, e, f, g, 0x71374491, w1 = READBE32(chunk + 4));
    Round(g, h, a, b, c, d, e, f, 0xb5c0fbcf, w2 = READBE32(chunk + 8));
    Round(f, g, h, a, b, c, d, e, 0xe9b5dba5, w3 = READBE32(chunk + 12));
    Round(e, f, g, h, a, b, c, d, 0x3956c25b, w4 = READBE32(chunk + 16));
    Round(d, e, f, g, h, a, b, c, 0x59f111f1, w5 = READBE32(chunk + 20));
    Round(c, d, e, f, g, h, a, b, 0x923f82a4, w6 = READBE32(chunk + 24));
    Round(b, c, d, e, f, g, h, a, 0xab1c5ed5, w7 = READBE32(chunk + 28));
    Round(a, b, c, d, e, f, g, h, 0xd807aa98, w8 = READBE32(chunk + 32));
    Round(h, a, b, c, d, e, f, g, 0x12835b01, w9 = READBE32(chunk + 36));
    Round(g, h, a, b, c, d, e, f, 0x243185be, w10 = READBE32(chunk + 40));
    Round(f, g, h, a, b, c, d, e, 0x550c7dc3, w11 = READBE32(chunk + 44));
    Round(e, f, g, h, a, b, c, d, 0x72be5d74, w12 = READBE32(chunk + 48));
    Round(d, e, f, g, h, a, b, c, 0x80deb1fe, w13 = READBE32(chunk + 52));
    Round(c, d, e, f, g, h, a, b, 0x9bdc06a7, w14 = READBE32(chunk + 56));
    Round(b, c, d, e, f, g, h, a, 0xc19bf174, w15 = READBE32(chunk + 60));

    Round(a, b, c, d, e, f, g, h, 0xe49b69c1, w0 += s1(w14) + w9 + s0(w1));
    Round(h, a, b, c, d, e, f, g, 0xefbe4786, w1 += s1(w15) + w10 + s0(w2));
    Round(g, h, a, b, c, d, e, f, 0x0fc19dc6, w2 += s1(w0) + w11 + s0(w3));
    Round(f, g, h, a, b, c, d, e, 0x240ca1cc, w3 += s1(w1) + w12 + s0(w4));
    Round(e, f, g, h, a, b, c, d, 0x2de92c6f, w4 += s1(w2) + w13 + s0(w5));
    Round(d, e, f, g, h, a, b, c, 0x4a7484aa, w5 += s1(w3) + w14 + s0(w6));
    Round(c, d, e, f, g, h, a, b, 0x5cb0a9dc, w6 += s1(w4) + w15 + s0(w7));
    Round(b, c, d, e, f, g, h, a, 0x76f988da, w7 += s1(w5) + w0 + s0(w8));
    Round(a, b, c, d, e, f, g, h, 0x983e5152, w8 += s1(w6) + w1 + s0(w9));
    Round(h, a, b, c, d, e, f, g, 0xa831c66d, w9 += s1(w7) + w2 + s0(w10));
    Round(g, h, a, b, c, d, e, f, 0xb00327c8, w10 += s1(w8) + w3 + s0(w11));
    Round(f, g, h, a, b, c, d, e, 0xbf597fc7, w11 += s1(w9) + w4 + s0(w12));
    Round(e, f, g, h, a, b, c, d, 0xc6e00bf3, w12 += s1(w10) + w5 + s0(w13));
    Round(d, e, f, g, h, a, b, c, 0xd5a79147, w13 += s1(w11) + w6 + s0(w14));
    Round(c, d, e, f, g, h, a, b, 0x06ca6351, w14 += s1(w12) + w7 + s0(w15));
    Round(b, c, d, e, f, g, h, a, 0x14292967, w15 += s1(w13) + w8 + s0(w0));

    Round(a, b, c, d, e, f, g, h, 0x27b70a85, w0 += s1(w14) + w9 + s0(w1));
    Round(h, a, b, c, d, e, f, g, 0x2e1b2138, w1 += s1(w15) + w10 + s0(w2));
    Round(g, h, a, b, c, d, e, f, 0x4d2c6dfc, w2 += s1(w0) + w11 + s0(w3));
    Round(f, g, h, a, b, c, d, e, 0x53380d13, w3 += s1(w1) + w12 + s0(w4));
    Round(e, f, g, h, a, b, c, d, 0x650a7354, w4 += s1(w2) + w13 + s0(w5));
    Round(d, e, f, g, h, a, b, c, 0x766a0abb, w5 += s1(w3) + w14 + s0(w6));
    Round(c, d, e, f, g, h, a, b, 0x81c2c92e, w6 += s1(w4) + w15 + s0(w7));
    Round(b, c, d, e, f, g, h, a, 0x92722c85, w7 += s1(w5) + w0 + s0(w8));
    Round(a, b, c, d, e, f, g, h, 0xa2bfe8a1, w8 += s1(w6) + w1 + s0(w9));
    Round(h, a, b, c, d, e, f, g, 0xa81a664b, w9 += s1(w7) + w2 + s0(w10));
    Round(g, h, a, b, c, d, e, f, 0xc24b8b70, w10 += s1(w8) + w3 + s0(w11));
    Round(f, g, h, a, b, c, d, e, 0xc76c51a3, w11 += s1(w9) + w4 + s0(w12));
    Round(e, f, g, h, a, b, c, d, 0xd192e819, w12 += s1(w10) + w5 + s0(w13));
    Round(d, e, f, g, h, a, b, c, 0xd6990624, w13 += s1(w11) + w6 + s0(w14));
    Round(c, d, e, f, g, h, a, b, 0xf40e3585, w14 += s1(w12) + w7 + s0(w15));
    Round(b, c, d, e, f, g, h, a, 0x106aa070, w15 += s1(w13) + w8 + s0(w0));

    Round(a, b, c, d, e, f, g, h, 0x19a4c116, w0 += s1(w14) + w9 + s0(w1));
    Round(h, a, b, c, d, e, f, g, 0x1e376c08, w1 += s1(w15) + w10 + s0(w2));
    Round(g, h, a, b, c, d, e, f, 0x2748774c, w2 += s1(w0) + w11 + s0(w3));
    Round(f, g, h, a, b, c, d, e, 0x34b0bcb5, w3 += s1(w1) + w12 + s0(w4));
    Round(e, f, g, h, a, b, c, d, 0x391c0cb3, w4 += s1(w2) + w13 + s0(w5));
    Round(d, e, f, g, h, a, b, c, 0x4ed8aa4a, w5 += s1(w3) + w14 + s0(w6));
    Round(c, d, e, f, g, h, a, b, 0x5b9cca4f, w6 += s1(w4) + w15 + s0(w7));
    Round(b, c, d, e, f, g, h, a, 0x682e6ff3, w7 += s1(w5) + w0 + s0(w8));
    Round(a, b, c, d, e, f, g, h, 0x748f82ee, w8 += s1(w6) + w1 + s0(w9));
    Round(h, a, b, c, d, e, f, g, 0x78a5636f, w9 += s1(w7) + w2 + s0(w10));
    Round(g, h, a, b, c, d, e, f, 0x84c87814, w10 += s1(w8) + w3 + s0(w11));
    Round(f, g, h, a, b, c, d, e, 0x8cc70208, w11 += s1(w9) + w4 + s0(w12));
    Round(e, f, g, h, a, b, c, d, 0x90befffa, w12 += s1(w10) + w5 + s0(w13));
    Round(d, e, f, g, h, a, b, c, 0xa4506ceb, w13 += s1(w11) + w6 + s0(w14));
    Round(c, d, e, f, g, h, a, b, 0xbef9a3f7, w14 + s1(w12) + w7 + s0(w15));
    Round(b, c, d, e, f, g, h, a, 0xc67178f2, w15 + s1(w13) + w8 + s0(w0));

    s[0] += a;
    s[1] += b;
    s[2] += c;
    s[3] += d;
    s[4] += e;
    s[5] += f;
    s[6] += g;
    s[7] += h;

}

// Compute SHA256(SHA256(chunk))[0]
void Transform2(uint32_t *s, const unsigned char *chunk)
{

    uint32_t t1;
    uint32_t t2;
    uint32_t w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15;

    uint32_t a = 0x6a09e667ul;
    uint32_t b = 0xbb67ae85ul;
    uint32_t c = 0x3c6ef372ul;
    uint32_t d = 0xa54ff53aul;
    uint32_t e = 0x510e527ful;
    uint32_t f = 0x9b05688cul;
    uint32_t g = 0x1f83d9abul;
    uint32_t h = 0x5be0cd19ul;

    Round(a, b, c, d, e, f, g, h, 0x428a2f98, w0 = READBE32(chunk + 0));
    Round(h, a, b, c, d, e, f, g, 0x71374491, w1 = READBE32(chunk + 4));
    Round(g, h, a, b, c, d, e, f, 0xb5c0fbcf, w2 = READBE32(chunk + 8));
    Round(f, g, h, a, b, c, d, e, 0xe9b5dba5, w3 = READBE32(chunk + 12));
    Round(e, f, g, h, a, b, c, d, 0x3956c25b, w4 = READBE32(chunk + 16));
    Round(d, e, f, g, h, a, b, c, 0x59f111f1, w5 = READBE32(chunk + 20));
    Round(c, d, e, f, g, h, a, b, 0x923f82a4, w6 = READBE32(chunk + 24));
    Round(b, c, d, e, f, g, h, a, 0xab1c5ed5, w7 = READBE32(chunk + 28));
    Round(a, b, c, d, e, f, g, h, 0xd807aa98, w8 = READBE32(chunk + 32));
    Round(h, a, b, c, d, e, f, g, 0x12835b01, w9 = READBE32(chunk + 36));
    Round(g, h, a, b, c, d, e, f, 0x243185be, w10 = READBE32(chunk + 40));
    Round(f, g, h, a, b, c, d, e, 0x550c7dc3, w11 = READBE32(chunk + 44));
    Round(e, f, g, h, a, b, c, d, 0x72be5d74, w12 = READBE32(chunk + 48));
    Round(d, e, f, g, h, a, b, c, 0x80deb1fe, w13 = READBE32(chunk + 52));
    Round(c, d, e, f, g, h, a, b, 0x9bdc06a7, w14 = READBE32(chunk + 56));
    Round(b, c, d, e, f, g, h, a, 0xc19bf174, w15 = READBE32(chunk + 60));

    Round(a, b, c, d, e, f, g, h, 0xe49b69c1, w0 += s1(w14) + w9 + s0(w1));
    Round(h, a, b, c, d, e, f, g, 0xefbe4786, w1 += s1(w15) + w10 + s0(w2));
    Round(g, h, a, b, c, d, e, f, 0x0fc19dc6, w2 += s1(w0) + w11 + s0(w3));
    Round(f, g, h, a, b, c, d, e, 0x240ca1cc, w3 += s1(w1) + w12 + s0(w4));
    Round(e, f, g, h, a, b, c, d, 0x2de92c6f, w4 += s1(w2) + w13 + s0(w5));
    Round(d, e, f, g, h, a, b, c, 0x4a7484aa, w5 += s1(w3) + w14 + s0(w6));
    Round(c, d, e, f, g, h, a, b, 0x5cb0a9dc, w6 += s1(w4) + w15 + s0(w7));
    Round(b, c, d, e, f, g, h, a, 0x76f988da, w7 += s1(w5) + w0 + s0(w8));
    Round(a, b, c, d, e, f, g, h, 0x983e5152, w8 += s1(w6) + w1 + s0(w9));
    Round(h, a, b, c, d, e, f, g, 0xa831c66d, w9 += s1(w7) + w2 + s0(w10));
    Round(g, h, a, b, c, d, e, f, 0xb00327c8, w10 += s1(w8) + w3 + s0(w11));
    Round(f, g, h, a, b, c, d, e, 0xbf597fc7, w11 += s1(w9) + w4 + s0(w12));
    Round(e, f, g, h, a, b, c, d, 0xc6e00bf3, w12 += s1(w10) + w5 + s0(w13));
    Round(d, e, f, g, h, a, b, c, 0xd5a79147, w13 += s1(w11) + w6 + s0(w14));
    Round(c, d, e, f, g, h, a, b, 0x06ca6351, w14 += s1(w12) + w7 + s0(w15));
    Round(b, c, d, e, f, g, h, a, 0x14292967, w15 += s1(w13) + w8 + s0(w0));

    Round(a, b, c, d, e, f, g, h, 0x27b70a85, w0 += s1(w14) + w9 + s0(w1));
    Round(h, a, b, c, d, e, f, g, 0x2e1b2138, w1 += s1(w15) + w10 + s0(w2));
    Round(g, h, a, b, c, d, e, f, 0x4d2c6dfc, w2 += s1(w0) + w11 + s0(w3));
    Round(f, g, h, a, b, c, d, e, 0x53380d13, w3 += s1(w1) + w12 + s0(w4));
    Round(e, f, g, h, a, b, c, d, 0x650a7354, w4 += s1(w2) + w13 + s0(w5));
    Round(d, e, f, g, h, a, b, c, 0x766a0abb, w5 += s1(w3) + w14 + s0(w6));
    Round(c, d, e, f, g, h, a, b, 0x81c2c92e, w6 += s1(w4) + w15 + s0(w7));
    Round(b, c, d, e, f, g, h, a, 0x92722c85, w7 += s1(w5) + w0 + s0(w8));
    Round(a, b, c, d, e, f, g, h, 0xa2bfe8a1, w8 += s1(w6) + w1 + s0(w9));
    Round(h, a, b, c, d, e, f, g, 0xa81a664b, w9 += s1(w7) + w2 + s0(w10));
    Round(g, h, a, b, c, d, e, f, 0xc24b8b70, w10 += s1(w8) + w3 + s0(w11));
    Round(f, g, h, a, b, c, d, e, 0xc76c51a3, w11 += s1(w9) + w4 + s0(w12));
    Round(e, f, g, h, a, b, c, d, 0xd192e819, w12 += s1(w10) + w5 + s0(w13));
    Round(d, e, f, g, h, a, b, c, 0xd6990624, w13 += s1(w11) + w6 + s0(w14));
    Round(c, d, e, f, g, h, a, b, 0xf40e3585, w14 += s1(w12) + w7 + s0(w15));
    Round(b, c, d, e, f, g, h, a, 0x106aa070, w15 += s1(w13) + w8 + s0(w0));

    Round(a, b, c, d, e, f, g, h, 0x19a4c116, w0 += s1(w14) + w9 + s0(w1));
    Round(h, a, b, c, d, e, f, g, 0x1e376c08, w1 += s1(w15) + w10 + s0(w2));
    Round(g, h, a, b, c, d, e, f, 0x2748774c, w2 += s1(w0) + w11 + s0(w3));
    Round(f, g, h, a, b, c, d, e, 0x34b0bcb5, w3 += s1(w1) + w12 + s0(w4));
    Round(e, f, g, h, a, b, c, d, 0x391c0cb3, w4 += s1(w2) + w13 + s0(w5));
    Round(d, e, f, g, h, a, b, c, 0x4ed8aa4a, w5 += s1(w3) + w14 + s0(w6));
    Round(c, d, e, f, g, h, a, b, 0x5b9cca4f, w6 += s1(w4) + w15 + s0(w7));
    Round(b, c, d, e, f, g, h, a, 0x682e6ff3, w7 += s1(w5) + w0 + s0(w8));
    Round(a, b, c, d, e, f, g, h, 0x748f82ee, w8 += s1(w6) + w1 + s0(w9));
    Round(h, a, b, c, d, e, f, g, 0x78a5636f, w9 += s1(w7) + w2 + s0(w10));
    Round(g, h, a, b, c, d, e, f, 0x84c87814, w10 += s1(w8) + w3 + s0(w11));
    Round(f, g, h, a, b, c, d, e, 0x8cc70208, w11 += s1(w9) + w4 + s0(w12));
    Round(e, f, g, h, a, b, c, d, 0x90befffa, w12 += s1(w10) + w5 + s0(w13));
    Round(d, e, f, g, h, a, b, c, 0xa4506ceb, w13 += s1(w11) + w6 + s0(w14));
    Round(c, d, e, f, g, h, a, b, 0xbef9a3f7, w14 + s1(w12) + w7 + s0(w15));
    Round(b, c, d, e, f, g, h, a, 0xc67178f2, w15 + s1(w13) + w8 + s0(w0));

    w0 = 0x6a09e667ul + a;
    w1 = 0xbb67ae85ul + b;
    w2 = 0x3c6ef372ul + c;
    w3 = 0xa54ff53aul + d;
    w4 = 0x510e527ful + e;
    w5 = 0x9b05688cul + f;
    w6 = 0x1f83d9abul + g;
    w7 = 0x5be0cd19ul + h;
    w8 = 0x80000000;
    w9 = 0;
    w10 = 0;
    w11 = 0;
    w12 = 0;
    w13 = 0;
    w14 = 0;
    w15 = 0x100;

    a = 0x6a09e667ul;
    b = 0xbb67ae85ul;
    c = 0x3c6ef372ul;
    d = 0xa54ff53aul;
    e = 0x510e527ful;
    f = 0x9b05688cul;
    g = 0x1f83d9abul;
    h = 0x5be0cd19ul;

    Round(a, b, c, d, e, f, g, h, 0x428a2f98, w0);
    Round(h, a, b, c, d, e, f, g, 0x71374491, w1);
    Round(g, h, a, b, c, d, e, f, 0xb5c0fbcf, w2);
    Round(f, g, h, a, b, c, d, e, 0xe9b5dba5, w3);
    Round(e, f, g, h, a, b, c, d, 0x3956c25b, w4);
    Round(d, e, f, g, h, a, b, c, 0x59f111f1, w5);
    Round(c, d, e, f, g, h, a, b, 0x923f82a4, w6);
    Round(b, c, d, e, f, g, h, a, 0xab1c5ed5, w7);
    Round(a, b, c, d, e, f, g, h, 0xd807aa98, w8);
    Round(h, a, b, c, d, e, f, g, 0x12835b01, w9);
    Round(g, h, a, b, c, d, e, f, 0x243185be, w10);
    Round(f, g, h, a, b, c, d, e, 0x550c7dc3, w11);
    Round(e, f, g, h, a, b, c, d, 0x72be5d74, w12);
    Round(d, e, f, g, h, a, b, c, 0x80deb1fe, w13);
    Round(c, d, e, f, g, h, a, b, 0x9bdc06a7, w14);
    Round(b, c, d, e, f, g, h, a, 0xc19bf174, w15);

    Round(a, b, c, d, e, f, g, h, 0xe49b69c1, w0 += s1(w14) + w9 + s0(w1));
    Round(h, a, b, c, d, e, f, g, 0xefbe4786, w1 += s1(w15) + w10 + s0(w2));
    Round(g, h, a, b, c, d, e, f, 0x0fc19dc6, w2 += s1(w0) + w11 + s0(w3));
    Round(f, g, h, a, b, c, d, e, 0x240ca1cc, w3 += s1(w1) + w12 + s0(w4));
    Round(e, f, g, h, a, b, c, d, 0x2de92c6f, w4 += s1(w2) + w13 + s0(w5));
    Round(d, e, f, g, h, a, b, c, 0x4a7484aa, w5 += s1(w3) + w14 + s0(w6));
    Round(c, d, e, f, g, h, a, b, 0x5cb0a9dc, w6 += s1(w4) + w15 + s0(w7));
    Round(b, c, d, e, f, g, h, a, 0x76f988da, w7 += s1(w5) + w0 + s0(w8));
    Round(a, b, c, d, e, f, g, h, 0x983e5152, w8 += s1(w6) + w1 + s0(w9));
    Round(h, a, b, c, d, e, f, g, 0xa831c66d, w9 += s1(w7) + w2 + s0(w10));
    Round(g, h, a, b, c, d, e, f, 0xb00327c8, w10 += s1(w8) + w3 + s0(w11));
    Round(f, g, h, a, b, c, d, e, 0xbf597fc7, w11 += s1(w9) + w4 + s0(w12));
    Round(e, f, g, h, a, b, c, d, 0xc6e00bf3, w12 += s1(w10) + w5 + s0(w13));
    Round(d, e, f, g, h, a, b, c, 0xd5a79147, w13 += s1(w11) + w6 + s0(w14));
    Round(c, d, e, f, g, h, a, b, 0x06ca6351, w14 += s1(w12) + w7 + s0(w15));
    Round(b, c, d, e, f, g, h, a, 0x14292967, w15 += s1(w13) + w8 + s0(w0));

    Round(a, b, c, d, e, f, g, h, 0x27b70a85, w0 += s1(w14) + w9 + s0(w1));
    Round(h, a, b, c, d, e, f, g, 0x2e1b2138, w1 += s1(w15) + w10 + s0(w2));
    Round(g, h, a, b, c, d, e, f, 0x4d2c6dfc, w2 += s1(w0) + w11 + s0(w3));
    Round(f, g, h, a, b, c, d, e, 0x53380d13, w3 += s1(w1) + w12 + s0(w4));
    Round(e, f, g, h, a, b, c, d, 0x650a7354, w4 += s1(w2) + w13 + s0(w5));
    Round(d, e, f, g, h, a, b, c, 0x766a0abb, w5 += s1(w3) + w14 + s0(w6));
    Round(c, d, e, f, g, h, a, b, 0x81c2c92e, w6 += s1(w4) + w15 + s0(w7));
    Round(b, c, d, e, f, g, h, a, 0x92722c85, w7 += s1(w5) + w0 + s0(w8));
    Round(a, b, c, d, e, f, g, h, 0xa2bfe8a1, w8 += s1(w6) + w1 + s0(w9));
    Round(h, a, b, c, d, e, f, g, 0xa81a664b, w9 += s1(w7) + w2 + s0(w10));
    Round(g, h, a, b, c, d, e, f, 0xc24b8b70, w10 += s1(w8) + w3 + s0(w11));
    Round(f, g, h, a, b, c, d, e, 0xc76c51a3, w11 += s1(w9) + w4 + s0(w12));
    Round(e, f, g, h, a, b, c, d, 0xd192e819, w12 += s1(w10) + w5 + s0(w13));
    Round(d, e, f, g, h, a, b, c, 0xd6990624, w13 += s1(w11) + w6 + s0(w14));
    Round(c, d, e, f, g, h, a, b, 0xf40e3585, w14 += s1(w12) + w7 + s0(w15));
    Round(b, c, d, e, f, g, h, a, 0x106aa070, w15 += s1(w13) + w8 + s0(w0));

    Round(a, b, c, d, e, f, g, h, 0x19a4c116, w0 += s1(w14) + w9 + s0(w1));
    Round(h, a, b, c, d, e, f, g, 0x1e376c08, w1 += s1(w15) + w10 + s0(w2));
    Round(g, h, a, b, c, d, e, f, 0x2748774c, w2 += s1(w0) + w11 + s0(w3));
    Round(f, g, h, a, b, c, d, e, 0x34b0bcb5, w3 += s1(w1) + w12 + s0(w4));
    Round(e, f, g, h, a, b, c, d, 0x391c0cb3, w4 += s1(w2) + w13 + s0(w5));
    Round(d, e, f, g, h, a, b, c, 0x4ed8aa4a, w5 += s1(w3) + w14 + s0(w6));
    Round(c, d, e, f, g, h, a, b, 0x5b9cca4f, w6 += s1(w4) + w15 + s0(w7));
    Round(b, c, d, e, f, g, h, a, 0x682e6ff3, w7 += s1(w5) + w0 + s0(w8));
    Round(a, b, c, d, e, f, g, h, 0x748f82ee, w8 += s1(w6) + w1 + s0(w9));
    Round(h, a, b, c, d, e, f, g, 0x78a5636f, w9 += s1(w7) + w2 + s0(w10));
    Round(g, h, a, b, c, d, e, f, 0x84c87814, w10 += s1(w8) + w3 + s0(w11));
    Round(f, g, h, a, b, c, d, e, 0x8cc70208, w11 += s1(w9) + w4 + s0(w12));
    Round(e, f, g, h, a, b, c, d, 0x90befffa, w12 += s1(w10) + w5 + s0(w13));
    Round(d, e, f, g, h, a, b, c, 0xa4506ceb, w13 += s1(w11) + w6 + s0(w14));
    Round(c, d, e, f, g, h, a, b, 0xbef9a3f7, w14 + s1(w12) + w7 + s0(w15));
    Round(b, c, d, e, f, g, h, a, 0xc67178f2, w15 + s1(w13) + w8 + s0(w0));

    s[0] = 0x6a09e667ul + a;

}

} // namespace sha256


////// SHA-256

class CSHA256
{
private:
    uint32_t s[8];
    unsigned char buf[64];
    uint64_t bytes;

public:
    static const size_t OUTPUT_SIZE = 32;

    CSHA256();
    void Write(const unsigned char *data, size_t len);
    void Finalize(unsigned char hash[OUTPUT_SIZE]);

};

CSHA256::CSHA256()
{
    bytes = 0;
    s[0] = 0x6a09e667ul;
    s[1] = 0xbb67ae85ul;
    s[2] = 0x3c6ef372ul;
    s[3] = 0xa54ff53aul;
    s[4] = 0x510e527ful;
    s[5] = 0x9b05688cul;
    s[6] = 0x1f83d9abul;
    s[7] = 0x5be0cd19ul;
}

void CSHA256::Write(const unsigned char *data, size_t len)
{
    const unsigned char *end = data + len;
    size_t bufsize = bytes % 64;
    if (bufsize && bufsize + len >= 64) {
        // Fill the buffer, and process it.
        memcpy(buf + bufsize, data, 64 - bufsize);
        bytes += 64 - bufsize;
        data += 64 - bufsize;
        _sha256::Transform(s, buf);
        bufsize = 0;
    }
    while (end >= data + 64) {
        // Process full chunks directly from the source.
        _sha256::Transform(s, data);
        bytes += 64;
        data += 64;
    }
    if (end > data) {
        // Fill the buffer with what remains.
        memcpy(buf + bufsize, data, end - data);
        bytes += end - data;
    }
}

void CSHA256::Finalize(unsigned char hash[OUTPUT_SIZE])
{
    unsigned char sizedesc[8];
    WRITEBE64(sizedesc, bytes << 3);
    Write(_sha256::pad, 1 + ((119 - (bytes % 64)) % 64));
    Write(sizedesc, 8);
    WRITEBE32(hash, s[0]);
    WRITEBE32(hash + 4, s[1]);
    WRITEBE32(hash + 8, s[2]);
    WRITEBE32(hash + 12, s[3]);
    WRITEBE32(hash + 16, s[4]);
    WRITEBE32(hash + 20, s[5]);
    WRITEBE32(hash + 24, s[6]);
    WRITEBE32(hash + 28, s[7]);
}

void sha256(unsigned char *input, int length, unsigned char *digest)
{

	CSHA256 sha;
	sha.Write(input, length);
	sha.Finalize(digest);

}

const uint8_t sizedesc_32[8] = { 0, 0, 0, 0, 0, 0, 1, 0 };
const uint8_t sizedesc_33[8] = { 0, 0, 0, 0, 0, 0, 1, 8 };
const uint8_t sizedesc_65[8] = { 0, 0, 0, 0, 0, 0, 2, 8 };

void sha256_33(unsigned char *input, unsigned char *digest)
{

    uint32_t s[8];

    _sha256::Initialize(s);
    memcpy(input + 33, _sha256::pad, 23);
    memcpy(input + 56, sizedesc_33, 8);
    _sha256::Transform(s, input);

    WRITEBE32(digest, s[0]);
    WRITEBE32(digest + 4, s[1]);
    WRITEBE32(digest + 8, s[2]);
    WRITEBE32(digest + 12, s[3]);
    WRITEBE32(digest + 16, s[4]);
    WRITEBE32(digest + 20, s[5]);
    WRITEBE32(digest + 24, s[6]);
    WRITEBE32(digest + 28, s[7]);


}

void sha256_65(unsigned char *input, unsigned char *digest)
{

    uint32_t s[8];

    memcpy(input + 65, _sha256::pad, 55);
    memcpy(input + 120, sizedesc_65, 8);

    _sha256::Initialize(s);
    _sha256::Transform(s, input);
    _sha256::Transform(s, input + 64);

    WRITEBE32(digest, s[0]);
    WRITEBE32(digest + 4, s[1]);
    WRITEBE32(digest + 8, s[2]);
    WRITEBE32(digest + 12, s[3]);
    WRITEBE32(digest + 16, s[4]);
    WRITEBE32(digest + 20, s[5]);
    WRITEBE32(digest + 24, s[6]);
    WRITEBE32(digest + 28, s[7]);

}

void sha256_checksum(uint8_t *input, int length, uint8_t *checksum)
{

    uint32_t s[8];
    uint8_t b[64];
    memcpy(b, input, length);
    memcpy(b + length, _sha256::pad, 56 - length);
    WRITEBE64(b + 56, length << 3);
    _sha256::Transform2(s, b);
    WRITEBE32(checksum, s[0]);

}

std::string sha256_hex(unsigned char *digest)
{

    char buf[2 * 32 + 1];
    buf[2 * 32] = 0;
    for (int i = 0; i < 32; i++)
        sprintf(buf + i * 2, "%02x", digest[i]);
    return std::string(buf);

}

static const uint32_t k[64] = {
0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

/** Rotate right.
  * \param x The integer to rotate right.
  * \param n Number of times to rotate right.
  * \return The rotated integer.
  */
static uint32_t rotateRight(uint32_t x, uint8_t n)
{
    return (x >> n) | (x << (32 - n));
}

/** Function defined as (4.2) in section 4.1.2 of FIPS PUB 180-3.
  * \param x First input integer.
  * \param y Second input integer.
  * \param z Third input integer.
  * \return Non-linear combination of x, y and z.
  */
static uint32_t ch(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ ((~x) & z);
}

/** Function defined as (4.3) in section 4.1.2 of FIPS PUB 180-3.
  * \param x First input integer.
  * \param y Second input integer.
  * \param z Third input integer.
  * \return Non-linear combination of x, y and z.
  */
static uint32_t maj(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

/** Function defined as (4.4) in section 4.1.2 of FIPS PUB 180-3.
  * \param x Input integer.
  * \return Transformed integer.
  */
static uint32_t bigSigma0(uint32_t x)
{
    return rotateRight(x, 2) ^ rotateRight(x, 13) ^ rotateRight(x, 22);
}

/** Function defined as (4.5) in section 4.1.2 of FIPS PUB 180-3.
  * \param x Input integer.
  * \return Transformed integer.
  */
static uint32_t bigSigma1(uint32_t x)
{
    return rotateRight(x, 6) ^ rotateRight(x, 11) ^ rotateRight(x, 25);
}

/** Function defined as (4.6) in section 4.1.2 of FIPS PUB 180-3.
  * \param x Input integer.
  * \return Transformed integer.
  */
static uint32_t littleSigma0(uint32_t x)
{
    return rotateRight(x, 7) ^ rotateRight(x, 18) ^ (x >> 3);
}

/** Function defined as (4.7) in section 4.1.2 of FIPS PUB 180-3.
  * \param x Input integer.
  * \return Transformed integer.
  */
static uint32_t littleSigma1(uint32_t x)
{
    return rotateRight(x, 17) ^ rotateRight(x, 19) ^ (x >> 10);
}

/** Update hash value based on the contents of a full message buffer.
  * This is an implementation of HashState#hashBlock().
  * This implements the pseudo-code in section 6.2.2 of FIPS PUB 180-3.
  * \param hs The hash state to update.
  */
static void sha256Block(HashState* hs)
{
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t t1, t2;
    uint8_t t;
    uint32_t w[64];

    for (t = 0; t < 16; t++)
    {
        w[t] = hs->m[t];
    }
    for (t = 16; t < 64; t++)
    {
        w[t] = littleSigma1(w[t - 2]) + w[t - 7] + littleSigma0(w[t - 15]) + w[t - 16];
    }
    a = hs->h[0];
    b = hs->h[1];
    c = hs->h[2];
    d = hs->h[3];
    e = hs->h[4];
    f = hs->h[5];
    g = hs->h[6];
    h = hs->h[7];
    for (t = 0; t < 64; t++)
    {
        t1 = h + bigSigma1(e) + ch(e, f, g) + LOOKUP_DWORD(k[t]) + w[t];
        t2 = bigSigma0(a) + maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    hs->h[0] += a;
    hs->h[1] += b;
    hs->h[2] += c;
    hs->h[3] += d;
    hs->h[4] += e;
    hs->h[5] += f;
    hs->h[6] += g;
    hs->h[7] += h;
}

/** Begin calculating hash for new message.
  * See section 5.3.3 of FIPS PUB 180-3.
  * \param hs The hash state to initialise.
  */
void sha256Begin(HashState* hs)
{
    hs->message_length = 0;
    hs->hashBlock = sha256Block;
    hs->is_big_endian = true;
    hs->h[0] = 0x6a09e667;
    hs->h[1] = 0xbb67ae85;
    hs->h[2] = 0x3c6ef372;
    hs->h[3] = 0xa54ff53a;
    hs->h[4] = 0x510e527f;
    hs->h[5] = 0x9b05688c;
    hs->h[6] = 0x1f83d9ab;
    hs->h[7] = 0x5be0cd19;
    clearM(hs);
}

/** Add one more byte to the message buffer and call sha256Block()
  * if the message buffer is full.
  * \param hs The hash state to act on. The hash state must be one that has
  *           been initialised using sha256Begin() at some time in the past.
  * \param byte The byte to add.
  */
void sha256WriteByte(HashState* hs, uint8_t byte)
{
    hashWriteByte(hs, byte);
}

/** Finalise the hashing of a message by writing appropriate padding and
  * length bytes.
  * \param hs The hash state to act on. The hash state must be one that has
  *           been initialised using sha256Begin() at some time in the past.
  */
void sha256Finish(HashState* hs)
{
    hashFinish(hs);
}

/** Just like sha256Finish(), except this does a double SHA-256 hash. A
  * double SHA-256 hash is sometimes used in the Bitcoin protocol.
  * \param hs The hash state to act on. The hash state must be one that has
  *           been initialised using sha256Begin() at some time in the past.
  */
void c(HashState* hs)
{
    uint8_t temp[32];
    uint8_t i;

    sha256Finish(hs);
    writeHashToByteArray(temp, hs, true);
    sha256Begin(hs);
    for (i = 0; i < 32; i++)
    {
        sha256WriteByte(hs, temp[i]);
    }
    sha256Finish(hs);
}

//#ifdef TEST_SHA256

/** Where hash value will be stored after sha256() returns. */
uint32_t sha256_h[8];
/** Calculate SHA-256 hash of a message. The result is returned in #h.
  * \param message The message to calculate the hash of. This must be a byte
  *                array of the size specified by length.
  * \param length The length (in bytes) of the message.
  */
void sha256(uint8_t* message, uint32_t length)
{
    uint32_t i;
    HashState hs;

    sha256Begin(&hs);
    for (i = 0; i < length; i++)
    {
        sha256WriteByte(&hs, message[i]);
    }
    sha256Finish(&hs);
    memcpy(sha256_h, hs.h, 32);
}

/********************************************
函数名称：双hash，sha256^2
入参：bufIN 数据首地址，length 数据长度
hash结果保存在h中
********************************************/
void sha256_double(unsigned char* bufIN, unsigned short length)
{
    unsigned char i;

    sha256(bufIN, length);
    for (i = 0; i < 8; i++)                        //对结果进行从小端->大端转换
    {
        BigendChang((unsigned char*)(&sha256_h[i]), 4);
    }
    sha256((unsigned char*)sha256_h, 32);           //再次做hash sha256
    for (i = 0; i < 8; i++)                        //对结果进行从小端->大端转换
    {
        BigendChang((unsigned char*)(&sha256_h[i]), 4);
    }

}


/********************************************/
unsigned char sha256startflag = 0;  //
void sha256Startwn(void)
{
    if (sha256startflag == 0)
    {
        //	sha256Begin(&hs_wn);                        //开始sha256初始化
        sha256startflag = 1;
    }

}
