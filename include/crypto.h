#ifndef _CRYPTO
#define _CRYPTO

#include "gmssl/sm4.h"
#include "gmssl/hmac.h"
#include "gmssl/rand.h"

#define KEYLEN 16

extern __uint8_t Sm4_iv[KEYLEN];
extern __uint8_t hmac_key[KEYLEN];

void my_sm4_cbc_padding_encrypt(const unsigned char* Sm4_key, const unsigned char* Sm4_iv,  unsigned char* msg, size_t mlen, unsigned char* ciphertext, size_t* clen, int DEBUG);
void my_sm4_cbc_padding_decrypt(const unsigned char* Sm4_key, const unsigned char* Sm4_iv,  unsigned char* ciphertext, size_t clen, unsigned char* msg, size_t* mlen, int DEBUG);
void my_sm3_hmac(const __uint8_t* key, size_t keylen, const __uint8_t* msg, size_t msglen, __uint8_t* hmac); //hmac为32字节
void generate_session_key(__uint8_t* sessionkey, __uint8_t* nonce1, __uint8_t* nonce2, int len);

#endif