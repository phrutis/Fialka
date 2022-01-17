/**
 * Copyright (c) 2013-2014 Tomas Dzetkulic
 * Copyright (c) 2013-2014 Pavol Rusnak
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */
#include "includeAll.h"


int mlen = 0;                //字符个数
char mnemo[24 * 10]={0};     //字符存储内存

//const char *mnemonic_generate(int strength)
//{
////	if (strength % 32 || strength < 128 || strength > 256) {
////		return 0;
////	}
//	uint8_t data[32];
////	random_buffer(data, 32);
//	return mnemonic_from_data(data, strength / 8);
//}

/*****************************
函数名称：二进制数转换助记符
入参：data 被转换数据首地址，len 被转换数据长度,langunge 语言选择 0 English，1 chinese simply
*****************************/
void mnemonic_from_data(uint8_tt *data, int len,unsigned char langunge)
{
	uint8_tt bits[32 + 1];
	int i, j, idx;
	char *p = mnemo;

    memset(mnemo,0,sizeof(mnemo));
	mlen = len * 3 / 4;  //字符个数计算
    sha256(data,len);
	// checksum
	bits[len] = (unsigned char)(sha256_h[0]>>24);
	// data
	memcpy(bits, data, len);


	for (i = 0; i < mlen; i++) 
	{
		idx = 0;
		for (j = 0; j < 11; j++) 
		{
			idx <<= 1;
			idx += (bits[(i * 11 + j) / 8] & (1 << (7 - ((i * 11 + j) % 8)))) > 0;
		}

		switch(langunge)
		{
		case 0:		
			  strcpy(p, wordlist_english[idx]);
		      p += strlen(wordlist_english[idx]);
		break;
		case 1:
		      memcpy(p,&wordlist_chinesesimply[idx][0],3);//UTF8汉子为3字节表示
		      p += 3;			  
		break;
		}

		*p = (i < mlen - 1) ? ' ' : 0;
		p++;
	}
}

int mnemonic_check(const char *mnemonic)
{
//	if (!mnemonic) {
//		return 0;
//	}
//
//	uint32_t i, n;
//
//	i = 0; n = 0;
//	while (mnemonic[i]) {
//		if (mnemonic[i] == ' ') {
//			n++;
//		}
//		i++;
//	}
//	n++;
//	// check number of words
//	if (n != 12 && n != 18 && n != 24) {
//		return 0;
//	}
//
//	char current_word[10];
//	uint32_t j, k, ki, bi;
//	uint8_t bits[32 + 1];
//	memset(bits, 0, sizeof(bits));
//	i = 0; bi = 0;
//	while (mnemonic[i]) {
//		j = 0;
//		while (mnemonic[i] != ' ' && mnemonic[i] != 0) {
//			if (j >= sizeof(current_word)) {
//				return 0;
//			}
//			current_word[j] = mnemonic[i];
//			i++; j++;
//		}
//		current_word[j] = 0;
//		if (mnemonic[i] != 0) i++;
//		k = 0;
//		for (;;) {
//			if (!wordlist[k]) { // word not found
//				return 0;
//			}
//			if (strcmp(current_word, wordlist[k]) == 0) { // word found on index k
//				for (ki = 0; ki < 11; ki++) {
//					if (k & (1 << (10 - ki))) {
//						bits[bi / 8] |= 1 << (7 - (bi % 8));
//					}
//					bi++;
//				}
//				break;
//			}
//			k++;
//		}
//	}
//	if (bi != n * 11) {
//		return 0;
//	}
//	bits[32] = bits[n * 4 / 3];
//	sha256_Raw(bits, n * 4 / 3, bits);
//	if (n == 12) {
//		return (bits[0] & 0xF0) == (bits[32] & 0xF0); // compare first 4 bits
//	} else
//	if (n == 18) {
//		return (bits[0] & 0xFC) == (bits[32] & 0xFC); // compare first 6 bits
//	} else
//	if (n == 24) {
//		return bits[0] == bits[32]; // compare 8 bits
//	}
	return 0;
}


/*******************************
函数名称:助记符转换成64字节SEED，用于bip32进行处理
入参：mnemonic 助记符首地址，passphrase 助记符加密密钥，seed 64字节输出种子首地址
********************************/
void mnemonic_to_seed(const char *mnemonic, const char *passphrase, uint8_tt *seed, void (*progress_callback)(uint32_tt current, uint32_tt total))
{
	uint8_tt salt[8 + 256 + 4];
	int saltlen = 0;//strlen(passphrase);
	if(passphrase!=0){saltlen =strlen(passphrase);}

	memcpy(salt, "mnemonic", 8);
	memcpy(salt + 8, passphrase, saltlen);
	saltlen += 8;
	pbkdf2_hmac_sha512((const uint8_tt *)mnemonic, strlen(mnemonic), salt, saltlen, BIP39_PBKDF2_ROUNDS, seed, 512 / 8, progress_callback);
}

//const char * const *mnemonic_wordlist(void)
//{
////	return wordlist;
//}
