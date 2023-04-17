#include "../include/crypto.h"
#include "../include/socket.h"
#include "../include/utils.h"
#include "../include/auth_table.h"
#include "../include/drone.h"
#include "../include/message.h"

#define DEBUG 1

#define DEST_ID 2


int main()
{  
  Drone alldrone[11];
  drone_init(alldrone);
  Response response[10];
  response_init(response, 10);
  char local_ip[13];
  get_local_ip("ens18", local_ip);
  char MY_ID = find_drone(alldrone, local_ip);
  if (MY_ID == -1){
    printf("error!\n");
    return 0;
  }
  printf("my_ip : %s, my_id : %d\n", local_ip, MY_ID);
  int cfd = My_Socket_init(alldrone[MY_ID].IP, alldrone[MY_ID].PORT);
  AuthNode* head = initList();
  __uint8_t* mynonce = (__uint8_t*) malloc(NONCELEN);
  __uint8_t* othernonce = (__uint8_t*) malloc(NONCELEN);

  pthread_t id;
  Recive_func_arg ReciveFunArg;
  ReciveFunArg.my_id = MY_ID;
  ReciveFunArg.alldrone = alldrone;
  ReciveFunArg.sock_fd = cfd;
  ReciveFunArg.head = head;
  ReciveFunArg.response = response;

  int ret = pthread_create(&id,NULL,receive,(void* )&ReciveFunArg);
  if (-1 == ret) print_err("pthread_create failed", __LINE__, errno);
  int flag = -1;
  while(1){
    printf("====================menu====================\n");
    printf("0:Print Auth Table\n");
    printf("1:Authenticate\t 2:Update Session Key\t 3:xxxxxx\n");
    scanf("%d", &flag);
    switch (flag)
    {
    case 0:
      printf("Auth Table is:\n");
      printAuthtable(head);
      break;
    case 1:
      __uint8_t* mynonce = (unsigned char*) malloc(NONCELEN);
      AuthMsg auth_msg = {0};
      auth_msg.index = 1;
      auth_msg.srcid = alldrone[MY_ID].id;
      auth_msg.destid = alldrone[DEST_ID].id;
      rand_bytes(auth_msg.nonce, NONCELEN);
      auth_msg.noncelen = NONCELEN;

      printf("mynonce is: ");
      print_char_arr(auth_msg.nonce, NONCELEN);
      char index = 1;
      if (auth_msg.srcid < auth_msg.destid){
        insertNode(head, alldrone[DEST_ID].id, auth_msg.nonce, NULL, 0);
      }
      else{
        insertNode(head, alldrone[DEST_ID].id, NULL, auth_msg.nonce, 0);
      }
      send_padding_msg(cfd, (void*)&auth_msg, sizeof(auth_msg), 0x1, alldrone[DEST_ID].IP, alldrone[DEST_ID].PORT);
      printf("Send Success!\n");
      break;
    case 2:
      Update(cfd, alldrone[MY_ID].id, alldrone, head, response);
      break;
    default:
      break;
    }
  }
  return 0;
}