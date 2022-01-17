/** Derive a key using the specified password and salt, using HMAC-SHA512 as
  * the underlying pseudo-random function. The derived key length is fixed
  * at #SHA512_HASH_LENGTH bytes.
  *
  * This code here is based on section 5.3 ("PBKDF Specification") of
  * NIST SP 800-132 (obtained from
  * http://csrc.nist.gov/publications/nistpubs/800-132/nist-sp800-132.pdf on
  * 30 March 2013).
  * \param out A byte array where the resulting derived key will be written.
  *            This must have space for #SHA512_HASH_LENGTH bytes.
  * \param password Byte array specifying the password to use in PBKDF2.
  * \param password_length The length (in bytes) of the password.
  * \param salt Byte array specifying the salt to use in PBKDF2.
  * \param salt_length The length (in bytes) of the salt.
  * \warning salt cannot be too long; salt_length must be less than or equal
  *          to #SHA512_HASH_LENGTH - 4.
  */
#include "includeall.h"



void pbkdf2_hmac_sha512(const uint8_tt *pass, int passlen, uint8_tt *salt, int saltlen, uint32_tt iterations, uint8_tt *key, int keylen, void (*progress_callback)(uint32_tt current, uint32_tt total))
{
	const uint32_tt HMACLEN = 512/8;
	uint32_tt i, j, k;
	uint8_tt f[HMACLEN], g[HMACLEN];
	uint32_tt blocks = keylen / HMACLEN;
	if (keylen & (HMACLEN - 1)) {
		blocks++;
	}
	for (i = 1; i <= blocks; i++) {
		salt[saltlen    ] = (i >> 24) & 0xFF;
		salt[saltlen + 1] = (i >> 16) & 0xFF;
		salt[saltlen + 2] = (i >> 8) & 0xFF;
		salt[saltlen + 3] = i & 0xFF;
        hmacSha512(g,pass, passlen, salt, saltlen + 4);
		memcpy(f, g, HMACLEN);
		for (j = 1; j < iterations; j++) {
        hmacSha512(g,pass, passlen, g,HMACLEN);
			for (k = 0; k < HMACLEN; k++) {
				f[k] ^= g[k];
			}
			if (progress_callback && (j % 256 == 255)) {
				progress_callback(j + 1, iterations);
			}
		
		}
		if (i == blocks && (keylen & (HMACLEN - 1))) {
			memcpy(key + HMACLEN * (i - 1), f, keylen & (HMACLEN - 1));
		} else {
			memcpy(key + HMACLEN * (i - 1), f, HMACLEN);
		}
	}
}


