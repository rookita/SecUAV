#include "../include/crypto.h"
#include "../include/socket.h"
#include "../include/utils.h"
#include "../include/uav.h"

#define DEBUG 1

#define MY_IP "192.168.8.130"
#define MY_PORT 6666

Uav all_uav[10];
int main()
{
  Uav_init(&all_uav[0], 0, MY_IP, MY_PORT);
  Uav_init(&all_uav[1], 1, "192.168.8.187", 6666);
  
  //PART 1
  int cfd = My_Socket_init(MY_IP, MY_PORT);
  struct sockaddr_in dest_addr;
  Dest_Socket_init(&dest_addr, all_uav[1].IP, all_uav[1].PORT);

  //PART2
  unsigned char Sm4_key[16] = "Secret Key12345";
  unsigned char Sm4_iv[16] = "0123456789abcde";
  
  /*
  //PART3
  Auth auth_msg = {0};
  int type = 0;
  size_t mlen = sizeof(auth_msg.r);
  size_t decrypted_mlen = 0;
  unsigned char* r = (unsigned char*) malloc(mlen * sizeof(unsigned char));
  unsigned char* decrypted_r = (unsigned char*) malloc(mlen * sizeof(unsigned char));
  //unsigned char decrypted_r[16];
  rand_bytes(r, mlen);
  //size_t clen = mlen%16 ? (mlen + (16 - mlen%16)) : mlen;
  size_t clen = 0;
  my_sm4_cbc_padding_encrypt(Sm4_key, Sm4_iv, r, mlen, auth_msg.r, &clen, DEBUG);
  auth_msg.id = 0;
  auth_msg.rlen = clen;
  
  my_sm4_cbc_padding_decrypt(Sm4_key, Sm4_iv, auth_msg.r, clen, decrypted_r, &decrypted_mlen, DEBUG);
  
  if (DEBUG){
    printf("r: ");
	  print_char_arr(r, mlen);
    printf("encrypted_r: ");
	  print_char_arr(auth_msg.r, clen);
    printf("decrypted_r: ");
	  print_char_arr(decrypted_r, decrypted_mlen);
  }
  */
  

  //PART 4
  unsigned char* decrypted_r = (unsigned char*) malloc(20 * sizeof(unsigned char));
  pthread_t id;
  Recive_func_arg ReciveFunArg;
  strcpy(ReciveFunArg.Sm4_key, Sm4_key);
  strcpy(ReciveFunArg.Sm4_iv, Sm4_iv);
  ReciveFunArg.decrypted_r = decrypted_r;
  int ret = pthread_create(&id,NULL,receive,(void* )&ReciveFunArg);
  if (-1 == ret) print_err("pthread_create failed", __LINE__, errno);

  //printf("decrypted_r: ");
	//print_char_arr(ReciveFunArg.decrypted_r, mlen);
  
  int flag = -1;
  while(1){
    printf("====================menu====================\n");
    printf("0:Send Auth Msg\t 1:xxxxxx\t 2:xxxxxx\n");
    scanf("%d", &flag);
    switch (flag)
    {
    case 0:
      int rlen = 15;
      unsigned char* r = (unsigned char*) malloc(rlen);
      unsigned char Dest_IP[20];
      int Dest_PORT;
      Auth auth_msg = {0};
      generate_auth_message(&auth_msg, rlen, all_uav[0].id, r);
      unsigned char* encrypted_r = (unsigned char*) malloc(2 * auth_msg.rlen * sizeof(unsigned char));
      size_t clen;
      printf("origin randnum is: ");
      print_char_arr(auth_msg.r, auth_msg.rlen);
      my_sm4_cbc_padding_encrypt(Sm4_key, Sm4_iv, auth_msg.r, auth_msg.rlen, encrypted_r, &clen, DEBUG);
      auth_msg.r = encrypted_r;
      auth_msg.rlen = clen;
      printf("encrypted randnum is: ");
      print_char_arr(auth_msg.r, auth_msg.rlen);
      printf("Input Dest IP: ");
      scanf("%s", Dest_IP);
      printf("Input Dest PORT: ");
      scanf("%d", &Dest_PORT);
      send_auth_msg(cfd, &auth_msg, Dest_IP, Dest_PORT);
      printf("Send Success!\n");
      free(encrypted_r);
      break;
    default:
      break;
    }
  }
  return 0;
}