#include "../include/crypto.h"
#include "../include/socket.h"
#include "../include/utils.h"
#include "../include/auth_table.h"

#define DEBUG 1

#define MY_ID 1
#define MY_IP "192.168.8.130"
#define MY_PORT 6666

int main()
{
  int cfd = My_Socket_init(MY_IP, MY_PORT);
  AuthNode* head = initList();
  __uint8_t* mynonce = (__uint8_t*) malloc(16);
  __uint8_t* othernonce = (__uint8_t*) malloc(16);

  pthread_t id;
  Recive_func_arg ReciveFunArg;
  ReciveFunArg.myid = MY_ID;
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
      __uint8_t Dest_IP[20] = "192.168.8.187";
      int Dest_PORT = 6666;
      int Dest_ID = 2;

      AuthMsg auth_msg = {0};
      auth_msg.index = 1;
      auth_msg.srcid = 1;
      auth_msg.destid = Dest_ID;
      rand_bytes(auth_msg.mynonce, rlen);
      auth_msg.noncelen = rlen;

      printf("mynonce is: ");
      print_char_arr(auth_msg.mynonce, rlen);
      
      insertNode(head, Dest_ID, auth_msg.mynonce, NULL, 0, 0);
      send_auth_msg(cfd, &auth_msg, Dest_IP, Dest_PORT);
      printf("Send Success!\n");
      break;
    default:
      break;
    }
  }
  return 0;
}