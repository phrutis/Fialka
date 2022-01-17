#include "includeAll.h"

const char base58_char_list[58] = {
'1', '2', '3', '4', '5', '6', '7', '8', '9', 'A',
'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'L',
'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g',
'h', 'i', 'j', 'k', 'm', 'n', 'o', 'p', 'q', 'r',
's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};

void bip32SeedToNode(unsigned char *master_node, const unsigned char *seed, const unsigned int seed_length)
{
	hmacSha512(master_node, (const unsigned char *)"Bitcoin seed", 12, seed, seed_length);
}

bool bip32DerivePrivate(BigNum256 out, const uint8_tt *master_node, const uint32_tt *path, const unsigned int path_length)
{
	uint8_tt current_node[NODE_LENGTH];
	uint8_tt temp[NODE_LENGTH];
	uint8_tt hmac_data[37]; // 1 for prefix + 32 for public/private key + 4 for "i"
	uint8_tt serialised[ECDSA_MAX_SERIALISE_SIZE];
	uint8_tt serialised_size;
	unsigned int i;
	PointAffine p;

	memcpy(current_node, master_node, sizeof(current_node));
	for (i = 0; i < path_length; i++)
	{
		if ((path[i] & 0x80000000) != 0)
		{
			hmac_data[0] = 0x00;
			memcpy(&(hmac_data[1]), current_node, 32);
		}
		else
		{
			setToG(&p);
			memcpy(temp, current_node, 32);
			swapEndian256(temp);
			pointMultiply(&p, temp);

			serialised_size = ecdsaSerialise(serialised, &p, true);
			if (serialised_size != 33)
			{
				return true;
			}
			memcpy(hmac_data, serialised, 33);
		}
		writeU32BigEndian(&(hmac_data[33]), path[i]);
		hmacSha512(temp, &(current_node[32]), 32, hmac_data, sizeof(hmac_data));
		swapEndian256(current_node);
		swapEndian256(temp);
		if (bigCompare(temp, (BigNum256)secp256k1_n) != BIGCMP_LESS)
		{
			return true;
		}
		setFieldToN();
		bigAdd(temp, temp, current_node);
		if (bigIsZero(temp))
		{
			return true;
		}
		swapEndian256(temp);
		memcpy(current_node, temp, sizeof(current_node));
	}
	memcpy(out, current_node, 32);
	swapEndian256(out);
	return false;
}

void bip32SeedToNode2(unsigned char* master_node, const unsigned char* seed, const unsigned int seed_length)
{
	hmacSha512(master_node, (const unsigned char*)"Bitcoin seed", 12, seed, seed_length);
}

bool bip32DerivePrivate2(BigNum256 out, const uint8_tt* master_node, const uint32_tt* path, const unsigned int path_length)
{
	uint8_tt current_node[NODE_LENGTH];
	uint8_tt temp[NODE_LENGTH];
	uint8_tt hmac_data[37]; // 1 for prefix + 32 for public/private key + 4 for "i"
	uint8_tt serialised[ECDSA_MAX_SERIALISE_SIZE];
	uint8_tt serialised_size;
	unsigned int i;
	PointAffine p;

	memcpy(current_node, master_node, sizeof(current_node));
	for (i = 0; i < path_length; i++)
	{
		if ((path[i] & 0x80000000) != 0)
		{
			hmac_data[0] = 0x00;
			memcpy(&(hmac_data[1]), current_node, 32);
		}
		else
		{
			setToG(&p);
			memcpy(temp, current_node, 32);
			swapEndian256(temp);
			pointMultiply(&p, temp);

			serialised_size = ecdsaSerialise(serialised, &p, true);
			if (serialised_size != 33)
			{
				return true;
			}
			memcpy(hmac_data, serialised, 33);
		}
		writeU32BigEndian(&(hmac_data[33]), path[i]);
		hmacSha512(temp, &(current_node[32]), 32, hmac_data, sizeof(hmac_data));
		swapEndian256(current_node);
		swapEndian256(temp);
		if (bigCompare(temp, (BigNum256)secp256k1_n) != BIGCMP_LESS)
		{
			return true;
		}
		setFieldToN();
		bigAdd(temp, temp, current_node);
		if (bigIsZero(temp))
		{
			return true;
		}
		swapEndian256(temp);
		memcpy(current_node, temp, sizeof(current_node));
	}
	memcpy(out, current_node, 32);
	swapEndian256(out);
	return false;
}


void bip32SeedToNode3(unsigned char* master_node, const unsigned char* seed, const unsigned int seed_length)
{
	hmacSha512(master_node, (const unsigned char*)"Bitcoin seed", 12, seed, seed_length);
}

bool bip32DerivePrivate3(BigNum256 out, const uint8_tt* master_node, const uint32_tt* path, const unsigned int path_length)
{
	uint8_tt current_node[NODE_LENGTH];
	uint8_tt temp[NODE_LENGTH];
	uint8_tt hmac_data[37]; // 1 for prefix + 32 for public/private key + 4 for "i"
	uint8_tt serialised[ECDSA_MAX_SERIALISE_SIZE];
	uint8_tt serialised_size;
	unsigned int i;
	PointAffine p;

	memcpy(current_node, master_node, sizeof(current_node));
	for (i = 0; i < path_length; i++)
	{
		if ((path[i] & 0x80000000) != 0)
		{
			hmac_data[0] = 0x00;
			memcpy(&(hmac_data[1]), current_node, 32);
		}
		else
		{
			setToG(&p);
			memcpy(temp, current_node, 32);
			swapEndian256(temp);
			pointMultiply(&p, temp);

			serialised_size = ecdsaSerialise(serialised, &p, true);
			if (serialised_size != 33)
			{
				return true;
			}
			memcpy(hmac_data, serialised, 33);
		}
		writeU32BigEndian(&(hmac_data[33]), path[i]);
		hmacSha512(temp, &(current_node[32]), 32, hmac_data, sizeof(hmac_data));
		swapEndian256(current_node);
		swapEndian256(temp);
		if (bigCompare(temp, (BigNum256)secp256k1_n) != BIGCMP_LESS)
		{
			return true;
		}
		setFieldToN();
		bigAdd(temp, temp, current_node);
		if (bigIsZero(temp))
		{
			return true;
		}
		swapEndian256(temp);
		memcpy(current_node, temp, sizeof(current_node));
	}
	memcpy(out, current_node, 32);
	swapEndian256(out);
	return false;
}



void bip32SeedToNode4(unsigned char* master_node, const unsigned char* seed, const unsigned int seed_length)
{
	hmacSha512(master_node, (const unsigned char*)"Bitcoin seed", 12, seed, seed_length);
}

bool bip32DerivePrivate4(BigNum256 out, const uint8_tt* master_node, const uint32_tt* path, const unsigned int path_length)
{
	uint8_tt current_node[NODE_LENGTH];
	uint8_tt temp[NODE_LENGTH];
	uint8_tt hmac_data[37]; // 1 for prefix + 32 for public/private key + 4 for "i"
	uint8_tt serialised[ECDSA_MAX_SERIALISE_SIZE];
	uint8_tt serialised_size;
	unsigned int i;
	PointAffine p;

	memcpy(current_node, master_node, sizeof(current_node));
	for (i = 0; i < path_length; i++)
	{
		if ((path[i] & 0x80000000) != 0)
		{
			hmac_data[0] = 0x00;
			memcpy(&(hmac_data[1]), current_node, 32);
		}
		else
		{
			setToG(&p);
			memcpy(temp, current_node, 32);
			swapEndian256(temp);
			pointMultiply(&p, temp);

			serialised_size = ecdsaSerialise(serialised, &p, true);
			if (serialised_size != 33)
			{
				return true;
			}
			memcpy(hmac_data, serialised, 33);
		}
		writeU32BigEndian(&(hmac_data[33]), path[i]);
		hmacSha512(temp, &(current_node[32]), 32, hmac_data, sizeof(hmac_data));
		swapEndian256(current_node);
		swapEndian256(temp);
		if (bigCompare(temp, (BigNum256)secp256k1_n) != BIGCMP_LESS)
		{
			return true;
		}
		setFieldToN();
		bigAdd(temp, temp, current_node);
		if (bigIsZero(temp))
		{
			return true;
		}
		swapEndian256(temp);
		memcpy(current_node, temp, sizeof(current_node));
	}
	memcpy(out, current_node, 32);
	swapEndian256(out);
	return false;
}


void bip32SeedToNode5(unsigned char* master_node, const unsigned char* seed, const unsigned int seed_length)
{
	hmacSha512(master_node, (const unsigned char*)"Bitcoin seed", 12, seed, seed_length);
}

bool bip32DerivePrivate5(BigNum256 out, const uint8_tt* master_node, const uint32_tt* path, const unsigned int path_length)
{
	uint8_tt current_node[NODE_LENGTH];
	uint8_tt temp[NODE_LENGTH];
	uint8_tt hmac_data[37]; // 1 for prefix + 32 for public/private key + 4 for "i"
	uint8_tt serialised[ECDSA_MAX_SERIALISE_SIZE];
	uint8_tt serialised_size;
	unsigned int i;
	PointAffine p;

	memcpy(current_node, master_node, sizeof(current_node));
	for (i = 0; i < path_length; i++)
	{
		if ((path[i] & 0x80000000) != 0)
		{
			hmac_data[0] = 0x00;
			memcpy(&(hmac_data[1]), current_node, 32);
		}
		else
		{
			setToG(&p);
			memcpy(temp, current_node, 32);
			swapEndian256(temp);
			pointMultiply(&p, temp);

			serialised_size = ecdsaSerialise(serialised, &p, true);
			if (serialised_size != 33)
			{
				return true;
			}
			memcpy(hmac_data, serialised, 33);
		}
		writeU32BigEndian(&(hmac_data[33]), path[i]);
		hmacSha512(temp, &(current_node[32]), 32, hmac_data, sizeof(hmac_data));
		swapEndian256(current_node);
		swapEndian256(temp);
		if (bigCompare(temp, (BigNum256)secp256k1_n) != BIGCMP_LESS)
		{
			return true;
		}
		setFieldToN();
		bigAdd(temp, temp, current_node);
		if (bigIsZero(temp))
		{
			return true;
		}
		swapEndian256(temp);
		memcpy(current_node, temp, sizeof(current_node));
	}
	memcpy(out, current_node, 32);
	swapEndian256(out);
	return false;
}
void bip32SeedToNode6(unsigned char* master_node, const unsigned char* seed, const unsigned int seed_length)
{
	hmacSha512(master_node, (const unsigned char*)"Bitcoin seed", 12, seed, seed_length);
}

bool bip32DerivePrivate6(BigNum256 out, const uint8_tt* master_node, const uint32_tt* path, const unsigned int path_length)
{
	uint8_tt current_node[NODE_LENGTH];
	uint8_tt temp[NODE_LENGTH];
	uint8_tt hmac_data[37]; // 1 for prefix + 32 for public/private key + 4 for "i"
	uint8_tt serialised[ECDSA_MAX_SERIALISE_SIZE];
	uint8_tt serialised_size;
	unsigned int i;
	PointAffine p;

	memcpy(current_node, master_node, sizeof(current_node));
	for (i = 0; i < path_length; i++)
	{
		if ((path[i] & 0x80000000) != 0)
		{
			hmac_data[0] = 0x00;
			memcpy(&(hmac_data[1]), current_node, 32);
		}
		else
		{
			setToG(&p);
			memcpy(temp, current_node, 32);
			swapEndian256(temp);
			pointMultiply(&p, temp);

			serialised_size = ecdsaSerialise(serialised, &p, true);
			if (serialised_size != 33)
			{
				return true;
			}
			memcpy(hmac_data, serialised, 33);
		}
		writeU32BigEndian(&(hmac_data[33]), path[i]);
		hmacSha512(temp, &(current_node[32]), 32, hmac_data, sizeof(hmac_data));
		swapEndian256(current_node);
		swapEndian256(temp);
		if (bigCompare(temp, (BigNum256)secp256k1_n) != BIGCMP_LESS)
		{
			return true;
		}
		setFieldToN();
		bigAdd(temp, temp, current_node);
		if (bigIsZero(temp))
		{
			return true;
		}
		swapEndian256(temp);
		memcpy(current_node, temp, sizeof(current_node));
	}
	memcpy(out, current_node, 32);
	swapEndian256(out);
	return false;
}
void bip32SeedToNode7(unsigned char* master_node, const unsigned char* seed, const unsigned int seed_length)
{
	hmacSha512(master_node, (const unsigned char*)"Bitcoin seed", 12, seed, seed_length);
}

bool bip32DerivePrivate7(BigNum256 out, const uint8_tt* master_node, const uint32_tt* path, const unsigned int path_length)
{
	uint8_tt current_node[NODE_LENGTH];
	uint8_tt temp[NODE_LENGTH];
	uint8_tt hmac_data[37]; // 1 for prefix + 32 for public/private key + 4 for "i"
	uint8_tt serialised[ECDSA_MAX_SERIALISE_SIZE];
	uint8_tt serialised_size;
	unsigned int i;
	PointAffine p;

	memcpy(current_node, master_node, sizeof(current_node));
	for (i = 0; i < path_length; i++)
	{
		if ((path[i] & 0x80000000) != 0)
		{
			hmac_data[0] = 0x00;
			memcpy(&(hmac_data[1]), current_node, 32);
		}
		else
		{
			setToG(&p);
			memcpy(temp, current_node, 32);
			swapEndian256(temp);
			pointMultiply(&p, temp);

			serialised_size = ecdsaSerialise(serialised, &p, true);
			if (serialised_size != 33)
			{
				return true;
			}
			memcpy(hmac_data, serialised, 33);
		}
		writeU32BigEndian(&(hmac_data[33]), path[i]);
		hmacSha512(temp, &(current_node[32]), 32, hmac_data, sizeof(hmac_data));
		swapEndian256(current_node);
		swapEndian256(temp);
		if (bigCompare(temp, (BigNum256)secp256k1_n) != BIGCMP_LESS)
		{
			return true;
		}
		setFieldToN();
		bigAdd(temp, temp, current_node);
		if (bigIsZero(temp))
		{
			return true;
		}
		swapEndian256(temp);
		memcpy(current_node, temp, sizeof(current_node));
	}
	memcpy(out, current_node, 32);
	swapEndian256(out);
	return false;
}
void bip32SeedToNode8(unsigned char* master_node, const unsigned char* seed, const unsigned int seed_length)
{
	hmacSha512(master_node, (const unsigned char*)"Bitcoin seed", 12, seed, seed_length);
}

bool bip32DerivePrivate8(BigNum256 out, const uint8_tt* master_node, const uint32_tt* path, const unsigned int path_length)
{
	uint8_tt current_node[NODE_LENGTH];
	uint8_tt temp[NODE_LENGTH];
	uint8_tt hmac_data[37]; // 1 for prefix + 32 for public/private key + 4 for "i"
	uint8_tt serialised[ECDSA_MAX_SERIALISE_SIZE];
	uint8_tt serialised_size;
	unsigned int i;
	PointAffine p;

	memcpy(current_node, master_node, sizeof(current_node));
	for (i = 0; i < path_length; i++)
	{
		if ((path[i] & 0x80000000) != 0)
		{
			hmac_data[0] = 0x00;
			memcpy(&(hmac_data[1]), current_node, 32);
		}
		else
		{
			setToG(&p);
			memcpy(temp, current_node, 32);
			swapEndian256(temp);
			pointMultiply(&p, temp);

			serialised_size = ecdsaSerialise(serialised, &p, true);
			if (serialised_size != 33)
			{
				return true;
			}
			memcpy(hmac_data, serialised, 33);
		}
		writeU32BigEndian(&(hmac_data[33]), path[i]);
		hmacSha512(temp, &(current_node[32]), 32, hmac_data, sizeof(hmac_data));
		swapEndian256(current_node);
		swapEndian256(temp);
		if (bigCompare(temp, (BigNum256)secp256k1_n) != BIGCMP_LESS)
		{
			return true;
		}
		setFieldToN();
		bigAdd(temp, temp, current_node);
		if (bigIsZero(temp))
		{
			return true;
		}
		swapEndian256(temp);
		memcpy(current_node, temp, sizeof(current_node));
	}
	memcpy(out, current_node, 32);
	swapEndian256(out);
	return false;
}

void bip32SeedToNode9(unsigned char* master_node, const unsigned char* seed, const unsigned int seed_length)
{
	hmacSha512(master_node, (const unsigned char*)"Bitcoin seed", 12, seed, seed_length);
}

bool bip32DerivePrivate9(BigNum256 out, const uint8_tt* master_node, const uint32_tt* path, const unsigned int path_length)
{
	uint8_tt current_node[NODE_LENGTH];
	uint8_tt temp[NODE_LENGTH];
	uint8_tt hmac_data[37]; // 1 for prefix + 32 for public/private key + 4 for "i"
	uint8_tt serialised[ECDSA_MAX_SERIALISE_SIZE];
	uint8_tt serialised_size;
	unsigned int i;
	PointAffine p;

	memcpy(current_node, master_node, sizeof(current_node));
	for (i = 0; i < path_length; i++)
	{
		if ((path[i] & 0x80000000) != 0)
		{
			hmac_data[0] = 0x00;
			memcpy(&(hmac_data[1]), current_node, 32);
		}
		else
		{
			setToG(&p);
			memcpy(temp, current_node, 32);
			swapEndian256(temp);
			pointMultiply(&p, temp);

			serialised_size = ecdsaSerialise(serialised, &p, true);
			if (serialised_size != 33)
			{
				return true;
			}
			memcpy(hmac_data, serialised, 33);
		}
		writeU32BigEndian(&(hmac_data[33]), path[i]);
		hmacSha512(temp, &(current_node[32]), 32, hmac_data, sizeof(hmac_data));
		swapEndian256(current_node);
		swapEndian256(temp);
		if (bigCompare(temp, (BigNum256)secp256k1_n) != BIGCMP_LESS)
		{
			return true;
		}
		setFieldToN();
		bigAdd(temp, temp, current_node);
		if (bigIsZero(temp))
		{
			return true;
		}
		swapEndian256(temp);
		memcpy(current_node, temp, sizeof(current_node));
	}
	memcpy(out, current_node, 32);
	swapEndian256(out);
	return false;
}

void bip32SeedToNode10(unsigned char* master_node, const unsigned char* seed, const unsigned int seed_length)
{
	hmacSha512(master_node, (const unsigned char*)"Bitcoin seed", 12, seed, seed_length);
}

bool bip32DerivePrivate10(BigNum256 out, const uint8_tt* master_node, const uint32_tt* path, const unsigned int path_length)
{
	uint8_tt current_node[NODE_LENGTH];
	uint8_tt temp[NODE_LENGTH];
	uint8_tt hmac_data[37]; // 1 for prefix + 32 for public/private key + 4 for "i"
	uint8_tt serialised[ECDSA_MAX_SERIALISE_SIZE];
	uint8_tt serialised_size;
	unsigned int i;
	PointAffine p;

	memcpy(current_node, master_node, sizeof(current_node));
	for (i = 0; i < path_length; i++)
	{
		if ((path[i] & 0x80000000) != 0)
		{
			hmac_data[0] = 0x00;
			memcpy(&(hmac_data[1]), current_node, 32);
		}
		else
		{
			setToG(&p);
			memcpy(temp, current_node, 32);
			swapEndian256(temp);
			pointMultiply(&p, temp);

			serialised_size = ecdsaSerialise(serialised, &p, true);
			if (serialised_size != 33)
			{
				return true;
			}
			memcpy(hmac_data, serialised, 33);
		}
		writeU32BigEndian(&(hmac_data[33]), path[i]);
		hmacSha512(temp, &(current_node[32]), 32, hmac_data, sizeof(hmac_data));
		swapEndian256(current_node);
		swapEndian256(temp);
		if (bigCompare(temp, (BigNum256)secp256k1_n) != BIGCMP_LESS)
		{
			return true;
		}
		setFieldToN();
		bigAdd(temp, temp, current_node);
		if (bigIsZero(temp))
		{
			return true;
		}
		swapEndian256(temp);
		memcpy(current_node, temp, sizeof(current_node));
	}
	memcpy(out, current_node, 32);
	swapEndian256(out);
	return false;
}
void bip32SeedToNode11(unsigned char* master_node, const unsigned char* seed, const unsigned int seed_length)
{
	hmacSha512(master_node, (const unsigned char*)"Bitcoin seed", 12, seed, seed_length);
}

bool bip32DerivePrivate11(BigNum256 out, const uint8_tt* master_node, const uint32_tt* path, const unsigned int path_length)
{
	uint8_tt current_node[NODE_LENGTH];
	uint8_tt temp[NODE_LENGTH];
	uint8_tt hmac_data[37]; // 1 for prefix + 32 for public/private key + 4 for "i"
	uint8_tt serialised[ECDSA_MAX_SERIALISE_SIZE];
	uint8_tt serialised_size;
	unsigned int i;
	PointAffine p;

	memcpy(current_node, master_node, sizeof(current_node));
	for (i = 0; i < path_length; i++)
	{
		if ((path[i] & 0x80000000) != 0)
		{
			hmac_data[0] = 0x00;
			memcpy(&(hmac_data[1]), current_node, 32);
		}
		else
		{
			setToG(&p);
			memcpy(temp, current_node, 32);
			swapEndian256(temp);
			pointMultiply(&p, temp);

			serialised_size = ecdsaSerialise(serialised, &p, true);
			if (serialised_size != 33)
			{
				return true;
			}
			memcpy(hmac_data, serialised, 33);
		}
		writeU32BigEndian(&(hmac_data[33]), path[i]);
		hmacSha512(temp, &(current_node[32]), 32, hmac_data, sizeof(hmac_data));
		swapEndian256(current_node);
		swapEndian256(temp);
		if (bigCompare(temp, (BigNum256)secp256k1_n) != BIGCMP_LESS)
		{
			return true;
		}
		setFieldToN();
		bigAdd(temp, temp, current_node);
		if (bigIsZero(temp))
		{
			return true;
		}
		swapEndian256(temp);
		memcpy(current_node, temp, sizeof(current_node));
	}
	memcpy(out, current_node, 32);
	swapEndian256(out);
	return false;
}
void bip32SeedToNode12(unsigned char* master_node, const unsigned char* seed, const unsigned int seed_length)
{
	hmacSha512(master_node, (const unsigned char*)"Bitcoin seed", 12, seed, seed_length);
}

bool bip32DerivePrivate12(BigNum256 out, const uint8_tt* master_node, const uint32_tt* path, const unsigned int path_length)
{
	uint8_tt current_node[NODE_LENGTH];
	uint8_tt temp[NODE_LENGTH];
	uint8_tt hmac_data[37]; // 1 for prefix + 32 for public/private key + 4 for "i"
	uint8_tt serialised[ECDSA_MAX_SERIALISE_SIZE];
	uint8_tt serialised_size;
	unsigned int i;
	PointAffine p;

	memcpy(current_node, master_node, sizeof(current_node));
	for (i = 0; i < path_length; i++)
	{
		if ((path[i] & 0x80000000) != 0)
		{
			hmac_data[0] = 0x00;
			memcpy(&(hmac_data[1]), current_node, 32);
		}
		else
		{
			setToG(&p);
			memcpy(temp, current_node, 32);
			swapEndian256(temp);
			pointMultiply(&p, temp);

			serialised_size = ecdsaSerialise(serialised, &p, true);
			if (serialised_size != 33)
			{
				return true;
			}
			memcpy(hmac_data, serialised, 33);
		}
		writeU32BigEndian(&(hmac_data[33]), path[i]);
		hmacSha512(temp, &(current_node[32]), 32, hmac_data, sizeof(hmac_data));
		swapEndian256(current_node);
		swapEndian256(temp);
		if (bigCompare(temp, (BigNum256)secp256k1_n) != BIGCMP_LESS)
		{
			return true;
		}
		setFieldToN();
		bigAdd(temp, temp, current_node);
		if (bigIsZero(temp))
		{
			return true;
		}
		swapEndian256(temp);
		memcpy(current_node, temp, sizeof(current_node));
	}
	memcpy(out, current_node, 32);
	swapEndian256(out);
	return false;
}


