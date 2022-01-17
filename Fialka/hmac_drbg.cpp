#include "includeall.h"


/** Calculate a 32 byte HMAC of an arbitrary message and key using SHA-256 as
  * the hash function.
  * The code in here is based on the description in section 5
  * ("HMAC SPECIFICATION") of FIPS PUB 198.
  *
  * The message can be split up into two separate parts, (denoted by the
  * parameters text1 and text2). This is done because the HMAC_DRBG update
  * function uses a message which is concatenated from two pieces of data.
  * Allowing the message to be split into two parts absolves the caller of
  * the responsibility of concatenating those pieces into a separate,
  * contiguous buffer.
  * \param out A byte array where the HMAC-SHA256 hash value will be written.
  *            This must have space for #SHA256_HASH_LENGTH bytes.
  * \param key A byte array containing the key to use in the HMAC-SHA256
  *            calculation. The key can be of any length.
  * \param key_length The length, in bytes, of the key.
  * \param text1 A byte array containing the first part of the message to use
  *              in the HMAC-SHA256 calculation. The message can be of any
  *              length.
  * \param text1_length The length, in bytes, of the first part of the
  *                     message.
  * \param text2 A byte array containing the second part of the message to use
  *              in the HMAC-SHA256 calculation. This part will be appended to
  *              the first part of the message. This parameter is optional; it
  *              can be NULL.
  * \param text2_length The length, in bytes, of the second part of the
  *                     message.
  */
static void hmacSha256(uint8_tt *out, const uint8_tt *key, const unsigned int key_length, const uint8_tt *text1, const unsigned int text1_length, const uint8_tt *text2, const unsigned int text2_length)
{
	unsigned int i;
	uint8_tt hash[SHA256_HASH_LENGTH];
	uint8_tt padded_key[64];
	HashState hs;

	// Determine key.
	memset(padded_key, 0, sizeof(padded_key));
	if (key_length <= sizeof(padded_key))
	{
		memcpy(padded_key, key, key_length);
	}
	else
	{
		sha256Begin(&hs);
		for (i = 0; i < key_length; i++)
		{
			sha256WriteByte(&hs, key[i]);
		}
		sha256Finish(&hs);
		writeHashToByteArray(padded_key, &hs, true);
	}
	// Calculate hash = H((K_0 XOR ipad) || text).
	sha256Begin(&hs);
	for (i = 0; i < sizeof(padded_key); i++)
	{
		sha256WriteByte(&hs, (uint8_tt)(padded_key[i] ^ 0x36));
	}
	// Note that text = text1 || text2.
	if (text1 != NULL)
	{
		for (i = 0; i < text1_length; i++)
		{
			sha256WriteByte(&hs, text1[i]);
		}
	}
	if (text2 != NULL)
	{
		for (i = 0; i < text2_length; i++)
		{
			sha256WriteByte(&hs, text2[i]);
		}
	}
	sha256Finish(&hs);
	writeHashToByteArray(hash, &hs, true);
	// Calculate H((K_0 XOR opad) || hash).
	sha256Begin(&hs);
	for (i = 0; i < sizeof(padded_key); i++)
	{
		sha256WriteByte(&hs, (uint8_tt)(padded_key[i] ^ 0x5c));
	}
	for (i = 0; i < sizeof(hash); i++)
	{
		sha256WriteByte(&hs, hash[i]);
	}
	sha256Finish(&hs);
	writeHashToByteArray(out, &hs, true);
}
/** HMAC_DRBG update function. This is a function common to all HMAC_DRBG
  * operations. This function updates the internal state of the DRBG, mixing
  * in some (optional) provided data.
  * \param state The HMAC_DRBG state to update.
  * \param provided_data Optional data to mix into internal state. This may be
  *                      NULL to indicate that there is no provided data.
  *                      Note that there is a difference between "no provided
  *                      data" (specified by passing NULL for this parameter)
  *                      and a zero length string (specified by passing a
  *                      pointer to a zero length byte array for this
  *                      parameter, and passing provided_data_length = 0).
  * \param provided_data_length Length of provided data, in bytes.
  */
static void drbgUpdate(HMACDRBGState *state, const uint8_tt *provided_data, const unsigned int provided_data_length)
{
	uint8_tt temp[SHA256_HASH_LENGTH + 1];

	// This algorithm is described in pages 45-46 of NIST SP 800-90A.
	// 1. K = HMAC (K, V || 0x00 || provided_data).
	memcpy(temp, state->v, sizeof(state->v));
	temp[SHA256_HASH_LENGTH] = 0x00;
	hmacSha256(state->key, state->key, sizeof(state->key), temp, sizeof(temp), provided_data, provided_data_length);
	// 2. V = HMAC (K, V).
	hmacSha256(state->v, state->key, sizeof(state->key), state->v, sizeof(state->v), NULL, 0);
	// 3. If (provided_data = Null), then return K and V.
	if (provided_data != NULL)
	{
		// 4. K = HMAC (K, V || 0x01 || provided_data).
		memcpy(temp, state->v, sizeof(state->v));
		temp[SHA256_HASH_LENGTH] = 0x01;
		hmacSha256(state->key, state->key, sizeof(state->key), temp, sizeof(temp), provided_data, provided_data_length);
		// 5. V = HMAC (K, V).
		hmacSha256(state->v, state->key, sizeof(state->key), state->v, sizeof(state->v), NULL, 0);
		// 6. Return K and V.
	}
}
/** Instantiate a HMAC_DRBG state using some seed material.
  * In the terminology of NIST SP 800-90A, the seed material consists of
  * entropy_input, nonce and personalization_string concatenated together.
  * It is the responsibility of the caller to perform this concatenation.
  * This function doesn't do the concatenation because that would require
  * dynamic memory allocation.
  * \param state The HMAC_DRBG state to instantiate.
  * \param seed_material The seed material to seed the HMAC_DRBG state with.
  *                      This may be of arbitrary length and will usually
  *                      consist of several entropy sources concatenated
  *                      together.
  * \param seed_material_length Length of seed material in bytes.
  */
void drbgInstantiate(HMACDRBGState *state, const uint8_tt *seed_material, const unsigned int seed_material_length)
{
	memset(state->key, 0x00, sizeof(state->key));
	memset(state->v, 0x01, sizeof(state->v));
	drbgUpdate(state, seed_material, seed_material_length);
}

/** Mix in some more entropy into a HMAC_DRBG state.
  * In the terminology of NIST SP 800-90A, the reseed material consists of
  * entropy_input and additional_input concatenated together.
  * It is the responsibility of the caller to perform this concatenation.
  * This function doesn't do the concatenation because that would require
  * dynamic memory allocation.
  * \param state The HMAC_DRBG state to reseed and update. The state must
  *              have been previously instantiated using drbgInstantiate().
  * \param reseed_material The material to reseed the HMAC_DRBG state with.
  *                        This may be of arbitrary length and will usually
  *                        consist of several entropy sources concatenated
  *                        together.
  * \param reseed_material_length Length of reseed material in bytes.
  */
void drbgReseed(HMACDRBGState *state, const uint8_tt *reseed_material, const unsigned int reseed_material_length)
{
	drbgUpdate(state, reseed_material, reseed_material_length);
}

/** Generate some (deterministic) random bytes from a HMAC_DRBG state.
  * \param out Byte array which will receive the random bytes. This must be
  *            large enough to store requested_bytes bytes.
  * \param state The HMAC_DRBG state to get bytes from. The state must
  *              have been previously instantiated using drbgInstantiate().
  * \param requested_bytes Number of bytes to generate.
  * \param additional_input Optional additional data to mix into HMAC_DRBG
  *                         state. This may be NULL to indicate that there is
  *                         no additional input.
  * \param additional_input_length Length of additional input, in number of
  *                                bytes.
  */
void drbgGenerate(uint8_tt *out, HMACDRBGState *state, const unsigned int requested_bytes, const uint8_tt *additional_input, const unsigned int additional_input_length)
{
	unsigned int bytes;
	unsigned int copy_size;

	if (additional_input != NULL)
	{
		drbgUpdate(state, additional_input, additional_input_length);
	}
	bytes = 0;
	while (bytes < requested_bytes)
	{
		// V = HMAC (Key, V).
		hmacSha256(state->v, state->key, sizeof(state->key), state->v, sizeof(state->v), NULL, 0);
		copy_size = MIN(requested_bytes - bytes, sizeof(state->v));
		memcpy(&(out[bytes]), state->v, copy_size);
		bytes += copy_size;
	}
	drbgUpdate(state, additional_input, additional_input_length);
}



