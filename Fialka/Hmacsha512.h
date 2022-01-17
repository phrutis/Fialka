/** \file hmac_sha512.h
  *
  * \brief Describes constants and functions exported by hmac_sha512.c.
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef HMAC_SHA512_H_INCLUDED
#define HMAC_SHA512_H_INCLUDED


/** Number of bytes a SHA-512 hash requires. */
#define SHA512_HASH_LENGTH		64

extern void hmacSha512(uint8_tt *out, const uint8_tt *key, const unsigned int key_length, const uint8_tt *text, const unsigned int text_length);

#endif // #ifndef HMAC_SHA512_H_INCLUDED
