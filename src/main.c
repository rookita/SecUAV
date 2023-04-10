#include "../include/crypto.h"
#include "../include/socket.h"
#include "../include/utils.h"
#include "../include/auth_table.h"
#include "../include/drone.h"
#include "../include/message.h"

#define DEBUG 1

#define MY_INDEX 0
#define DEST_INDEX 1


int main()
{  
  Drone alldrone[10];
  drone_init(alldrone);
  int cfd = My_Socket_init(alldrone[MY_INDEX].IP, alldrone[MY_INDEX].PORT);
  AuthNode* head = initList();
  __uint8_t* mynonce = (__uint8_t*) malloc(16);
  __uint8_t* othernonce = (__uint8_t*) malloc(16);

  pthread_t id;
  Recive_func_arg ReciveFunArg;
  ReciveFunArg.my_index = MY_INDEX;
  ReciveFunArg.alldrone = alldrone;
  ReciveFunArg.sock_fd = cfd;
  ReciveFunArg.head = head;

  int ret = pthread_create(&id,NULL,receive,(void* )&ReciveFunArg);
  if (-1 == ret) print_err("pthread_create failed", __LINE__, errno);

  int flag = -1;
  while(1){
    printf("====================menu====================\n");
    printf("0:Send Auth Msg\t 1:xxxxxx\t 2:xxxxxx\n");
    scanf("%d", &flag);
    switch (flag)
    {
    case 0:
      int rlen = 16;
      __uint8_t* mynonce = (unsigned char*) malloc(rlen);
      AuthMsg auth_msg = {0};
      auth_msg.index = 1;
      auth_msg.srcid = alldrone[MY_INDEX].id;
      auth_msg.destid = alldrone[DEST_INDEX].id;
      rand_bytes(auth_msg.nonce, rlen);
      auth_msg.noncelen = rlen;

      printf("mynonce is: ");
      print_char_arr(auth_msg.nonce, rlen);
      char index = 1;
      insertNode(head, alldrone[DEST_INDEX].id, auth_msg.nonce, NULL, 0, 0, index);
      
      send_padding_msg(cfd, (void*)&auth_msg, sizeof(auth_msg), 0x1, alldrone[DEST_INDEX].IP, alldrone[DEST_INDEX].PORT);
      printf("Send Success!\n");
      break;
    default:
      break;
    }
  }
  return 0;
}