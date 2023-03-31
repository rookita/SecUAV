#include <stdio.h>
#include "../include/crypto.h"
#include "../include/utils.h"

void my_sm4_cbc_padding_encrypt(const unsigned char* Sm4_key, const unsigned char* Sm4_iv, unsigned char* msg, size_t mlen, unsigned char* ciphertext, size_t* clen, int DEBUG){
	SM4_KEY sm4_key;
  if (DEBUG){
    printf("-----------------encrypt---------------\n");
    printf("r: ");
    print_char_arr(msg, mlen);
	  printf("key: ");
	  print_char_arr(Sm4_key, 16);
	  printf("iv: ");
	  print_char_arr(Sm4_iv, 16);
  }

	sm4_set_encrypt_key(&sm4_key, Sm4_key);
	sm4_cbc_padding_encrypt(&sm4_key, Sm4_iv, msg, mlen, ciphertext, clen);
}

void my_sm4_cbc_padding_decrypt(const unsigned char* Sm4_key, const unsigned char* Sm4_iv, unsigned char* ciphertext, size_t clen, unsigned char* msg, size_t* mlen, int DEBUG){
	SM4_KEY sm4_key;
  if (DEBUG){
    printf("-----------------decrypt---------------\n");
    printf("encrypted_r: ");
    print_char_arr(ciphertext, clen);
    printf("key: ");
	  print_char_arr(Sm4_key, 16);
	  printf("iv: ");
	  print_char_arr(Sm4_iv, 16);
  }
	sm4_set_decrypt_key(&sm4_key, Sm4_key);
	sm4_cbc_padding_decrypt(&sm4_key, Sm4_iv, ciphertext, clen, msg, mlen);
  printf("decrypted_r: ");
  print_char_arr(msg, *mlen);
}