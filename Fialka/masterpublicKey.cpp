#include "includeAll.h"

/**************************
函数名称：大小端转换
*************************/
void BigendChang(unsigned char *buf,unsigned char len)
{
	unsigned char x=0;
	unsigned char i;
	for(i=0;i<(len/2);i++)
	{
     x=buf[i];
     buf[i]=buf[len-1-i];
     buf[len-1-i]=x;
	}
}
/** Get the master public key of the currently loaded wallet. Every public key
  * (and address) in a wallet can be derived from the master public key and
  * chain code. However, even with posession of the master public key, all
  * private keys are still secret.
  * \param out_public_key The master public key will be written here.
  * \param out_chain_code The chain code will be written here. This must be a
  *                       byte array with space for 32 bytes.
  * \return #WALLET_NO_ERROR on success, or one of #WalletErrorsEnum if an
  *         error occurred.
  */
void getMasterPublicKey(PointAffine *out_public_key, uint8_tt *out_chain_code,unsigned char*master_node)
{
	uint8_tt local_seed[NODE_LENGTH]; // need a local copy to modify
	BigNum256 k_par;

	memcpy(local_seed,master_node, NODE_LENGTH);
	memcpy(out_chain_code, &(local_seed[32]), 32);
	k_par = (BigNum256)local_seed;
	swapEndian256(k_par); // since seed is big-endian
	setFieldToN();
	bigModulo(k_par, k_par); // just in case
	setToG(out_public_key);
	pointMultiply(out_public_key, k_par);


    swapEndian256(out_public_key->x);//small->big-endian
    swapEndian256(out_public_key->y);//small->big-endian

}