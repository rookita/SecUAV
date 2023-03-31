#include "gmssl/sm4.h"
#include "gmssl/rand.h"

void my_sm4_cbc_padding_encrypt(const unsigned char* Sm4_key, const unsigned char* Sm4_iv, unsigned char* msg, size_t mlen, unsigned char* ciphertext, size_t* clen, int DEBUG);
void my_sm4_cbc_padding_decrypt(const unsigned char* Sm4_key, const unsigned char* Sm4_iv, unsigned char* ciphertext, size_t clen, unsigned char* msg, size_t* mlen, int DEBUG);