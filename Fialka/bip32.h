/** \file bip32.h
  *
  * \brief Describes function and constants exported and used by bip32.c.
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef BIP32_H_INCLUDED
#define BIP32_H_INCLUDED

/** Length (in number of bytes) of a BIP32 node, a.k.a. extended private
  * key. */
#define NODE_LENGTH		64
/** Length of write canary (for testing writing beyond the end of an array),
  * in bytes. */
#define CANARY_LENGTH					32
/** Length of serialised BIP32 extended private key, in bytes. */
#define SERIALISED_BIP32_KEY_LENGTH		82

/** Test vector for BIP32 key derivation. */
struct BIP32TestVector
{
	/** Master seed. */
	unsigned char master[256];
	/** Length of master seed, in bytes. */
	unsigned int master_length;
	/** Key derivation path. */
	unsigned long path[16];
	/** Number of steps in derivation path. */
	unsigned int path_length;
	/** Expected private key, as a base58-encoded serialised extended private key
	  * as described in the BIP32 specification. */
	char base58_private[256];
};

extern const char base58_char_list[58];
extern const struct BIP32TestVector test_vectors[12];

extern void bip32SeedToNode(unsigned char *master_node, const unsigned char *seed, const unsigned int seed_length);
extern void bip32SeedToNode2(unsigned char* master_node, const unsigned char* seed, const unsigned int seed_length);
extern void bip32SeedToNode3(unsigned char* master_node, const unsigned char* seed, const unsigned int seed_length);
extern void bip32SeedToNode4(unsigned char* master_node, const unsigned char* seed, const unsigned int seed_length);
extern void bip32SeedToNode5(unsigned char* master_node, const unsigned char* seed, const unsigned int seed_length);
extern void bip32SeedToNode6(unsigned char* master_node, const unsigned char* seed, const unsigned int seed_length);
extern void bip32SeedToNode7(unsigned char* master_node, const unsigned char* seed, const unsigned int seed_length);
extern void bip32SeedToNode8(unsigned char* master_node, const unsigned char* seed, const unsigned int seed_length);
extern void bip32SeedToNode9(unsigned char* master_node, const unsigned char* seed, const unsigned int seed_length);
extern void bip32SeedToNode10(unsigned char* master_node, const unsigned char* seed, const unsigned int seed_length);
extern void bip32SeedToNode11(unsigned char* master_node, const unsigned char* seed, const unsigned int seed_length);
extern void bip32SeedToNode12(unsigned char* master_node, const unsigned char* seed, const unsigned int seed_length);

extern bool bip32DerivePrivate(BigNum256 out, const unsigned char *master_node, const unsigned long *path, const unsigned int path_length);
extern bool bip32DerivePrivate2(BigNum256 out, const unsigned char* master_node, const unsigned long* path, const unsigned int path_length);
extern bool bip32DerivePrivate3(BigNum256 out, const unsigned char* master_node, const unsigned long* path, const unsigned int path_length);
extern bool bip32DerivePrivate4(BigNum256 out, const unsigned char* master_node, const unsigned long* path, const unsigned int path_length);
extern bool bip32DerivePrivate5(BigNum256 out, const unsigned char* master_node, const unsigned long* path, const unsigned int path_length);
extern bool bip32DerivePrivate6(BigNum256 out, const unsigned char* master_node, const unsigned long* path, const unsigned int path_length);
extern bool bip32DerivePrivate7(BigNum256 out, const unsigned char* master_node, const unsigned long* path, const unsigned int path_length);
extern bool bip32DerivePrivate8(BigNum256 out, const unsigned char* master_node, const unsigned long* path, const unsigned int path_length);
extern bool bip32DerivePrivate9(BigNum256 out, const unsigned char* master_node, const unsigned long* path, const unsigned int path_length);
extern bool bip32DerivePrivate10(BigNum256 out, const unsigned char* master_node, const unsigned long* path, const unsigned int path_length);
extern bool bip32DerivePrivate11(BigNum256 out, const unsigned char* master_node, const unsigned long* path, const unsigned int path_length);
extern bool bip32DerivePrivate12(BigNum256 out, const unsigned char* master_node, const unsigned long* path, const unsigned int path_length);

#endif // #ifndef BIP32_H_INCLUDED
