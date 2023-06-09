#include <stdio.h>
#include "../include/crypto.h"
#include "../include/utils.h"

__uint8_t Sm4_iv[KEYLEN] = "0123456789abcde";
__uint8_t hmac_key[KEYLEN] = "Secret HMAC Keyy";

void my_sm4_cbc_padding_encrypt(const unsigned char* Sm4_key,
                                const unsigned char* Sm4_iv, unsigned char* msg,
                                size_t mlen, unsigned char* ciphertext,
                                size_t* clen, int DEBUG) {
    SM4_KEY sm4_key;
    sm4_set_encrypt_key(&sm4_key, Sm4_key);
    sm4_cbc_padding_encrypt(&sm4_key, Sm4_iv, msg, mlen, ciphertext, clen);
    if (DEBUG) {
        printf("-----------------encrypt---------------\n");
        printf("plaintext: ");
        print_char_arr(msg, mlen);
        printf("key: ");
        print_char_arr(Sm4_key, KEYLEN);
        printf("iv: ");
        print_char_arr(Sm4_iv, KEYLEN);
        printf("ciphertext: ");
        print_char_arr(ciphertext, *clen);
    }
}

void my_sm4_cbc_encrypt(const unsigned char* Sm4_key,
                        const unsigned char* Sm4_iv, unsigned char* msg,
                        size_t mlen, unsigned char* ciphertext, int DEBUG) {
    SM4_KEY sm4_key;
    sm4_set_encrypt_key(&sm4_key, Sm4_key);
    sm4_cbc_encrypt(&sm4_key, Sm4_iv, msg, mlen / SM4_BLOCK_SIZE, ciphertext);
    if (DEBUG) {
        printf("-----------------encrypt---------------\n");
        printf("plaintext: ");
        print_char_arr(msg, mlen);
        printf("key: ");
        print_char_arr(Sm4_key, KEYLEN);
        printf("iv: ");
        print_char_arr(Sm4_iv, KEYLEN);
        printf("ciphertext: ");
        print_char_arr(ciphertext, mlen);
    }
}

void my_sm4_cbc_padding_decrypt(const unsigned char* Sm4_key,
                                const unsigned char* Sm4_iv,
                                unsigned char* ciphertext, size_t clen,
                                unsigned char* msg, size_t* mlen, int DEBUG) {
    SM4_KEY sm4_key;
    if (DEBUG) {
        printf("-----------------decrypt---------------\n");
        printf("ciphertext: ");
        print_char_arr(ciphertext, clen);
        printf("key: ");
        print_char_arr(Sm4_key, KEYLEN);
        printf("iv: ");
        print_char_arr(Sm4_iv, KEYLEN);
    }
    sm4_set_decrypt_key(&sm4_key, Sm4_key);
    sm4_cbc_padding_decrypt(&sm4_key, Sm4_iv, ciphertext, clen, msg, mlen);
}

void my_sm4_cbc_decrypt(const unsigned char* Sm4_key,
                        const unsigned char* Sm4_iv, unsigned char* ciphertext,
                        size_t clen, unsigned char* msg, int DEBUG) {
    SM4_KEY sm4_key;
    if (DEBUG) {
        printf("-----------------decrypt---------------\n");
        printf("ciphertext: ");
        print_char_arr(ciphertext, clen);
        printf("key: ");
        print_char_arr(Sm4_key, KEYLEN);
        printf("iv: ");
        print_char_arr(Sm4_iv, KEYLEN);
    }
    sm4_set_decrypt_key(&sm4_key, Sm4_key);
    sm4_cbc_decrypt(&sm4_key, Sm4_iv, ciphertext, clen / SM4_BLOCK_SIZE, msg);
}

void my_sm3_hmac(const __uint8_t* key, size_t keylen, const __uint8_t* msg,
                 size_t msglen, __uint8_t* hmac) {
    sm3_hmac(key, keylen, msg, msglen, hmac);
}

void generate_session_key(__uint8_t* sessionkey, __uint8_t* nonce1,
                          __uint8_t* nonce2, int len) { // hmac(K || N1 || N2)
    __uint8_t* mbuf = (__uint8_t*)malloc(len + len);
    __uint8_t* hmac = (__uint8_t*)malloc(32);
    memset(sessionkey, 0, len);
    memset(mbuf, 0, 2 * len);
    memset(hmac, 0, 32);
    strncat(mbuf, nonce1, len);
    strncat(mbuf, nonce2, len);
    my_sm3_hmac(hmac_key, KEYLEN, mbuf, 2 * len, hmac);
    strncpy(sessionkey, hmac, len);
    free(mbuf);
    free(hmac);
}