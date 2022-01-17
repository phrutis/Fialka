#ifndef _PBKDF2_H_
#define _PBKDF2_H_

extern void pbkdf2_hmac_sha512(const uint8_tt *pass, int passlen, uint8_tt *salt, int saltlen, uint32_tt iterations, uint8_tt *key, int keylen, void (*progress_callback)(uint32_tt current, uint32_tt total));

#endif
