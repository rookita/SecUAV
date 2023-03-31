#include "../include/crypto.h"
#include "../include/socket.h"
#include "../include/utils.h"

#define DEBUG 1
#define MY_IP "192.168.8.130"
#define MY_PORT 6666
#define DEST_IP "192.168.8.187"
#define DEST_PORT 6666

int main()
{
  //PART 1
  int cfd = My_Socket_init(MY_IP, MY_PORT);
  struct sockaddr_in dest_addr;
  Dest_Socket_init(&dest_addr, DEST_IP, DEST_PORT);

  //PART2
  unsigned char Sm4_key[16] = "Secret Key12345";
  unsigned char Sm4_iv[16] = "0123456789abcde";
  
  //PART3
  Message uav_msg = {0};
  size_t mlen = sizeof(uav_msg.r);
  size_t decrypted_mlen = 0;
  unsigned char* r = (unsigned char*) malloc(mlen * sizeof(unsigned char));
  unsigned char* decrypted_r = (unsigned char*) malloc(mlen * sizeof(unsigned char));
  //unsigned char decrypted_r[16];
  rand_bytes(r, mlen);
  //size_t clen = mlen%16 ? (mlen + (16 - mlen%16)) : mlen;
  size_t clen = 0;
  my_sm4_cbc_padding_encrypt(Sm4_key, Sm4_iv, r, mlen, uav_msg.r, &clen, DEBUG);
  uav_msg.type = 0;
  uav_msg.id = 1;
  uav_msg.rlen = clen;
  
  my_sm4_cbc_padding_decrypt(Sm4_key, Sm4_iv, uav_msg.r, clen, decrypted_r, &decrypted_mlen, DEBUG);
  
  if (DEBUG){
    printf("r: ");
	  print_char_arr(r, mlen);
    printf("encrypted_r: ");
	  print_char_arr(uav_msg.r, clen);
    printf("decrypted_r: ");
	  print_char_arr(decrypted_r, decrypted_mlen);
  }

  //PART 4
  pthread_t id;
  Recive_func_arg ReciveFunArg;
  strcpy(ReciveFunArg.Sm4_key, Sm4_key);
  strcpy(ReciveFunArg.Sm4_iv, Sm4_iv);
  ReciveFunArg.decrypted_r = decrypted_r;
  int ret = pthread_create(&id,NULL,receive,(void* )&ReciveFunArg);
  if (-1 == ret) print_err("pthread_create failed", __LINE__, errno);

  //printf("decrypted_r: ");
	//print_char_arr(ReciveFunArg.decrypted_r, mlen);
  while(1){}
  send_msg(cfd, &uav_msg, (struct sockaddr* )&dest_addr);
  free(r);
  //free(decrypted_r);
  return 0;
}