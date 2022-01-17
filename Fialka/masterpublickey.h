#ifndef MASTERPUBLICKEY_H_
#define MASTERPUBLICKEY_H_
void BigendChang(unsigned char *buf,unsigned char len);

void getMasterPublicKey(PointAffine *out_public_key, uint8_tt *out_chain_code,unsigned char*master_node);
#endif
