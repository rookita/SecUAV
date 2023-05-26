#include "../include/crypto.h"
#include "../include/socket.h"
#include "../include/utils.h"
#include "../include/auth_table.h"
#include "../include/drone.h"
#include "../include/message.h"
#include "../include/test.h"
#include "../include/mytime.h"
#include "../include/config.h"

Recive_func_arg* rfa;
UpdateInfo* updateif;
int main()
{  
  config_t* conf = confRead("./config");
  Drone alldrone[DRONENUM+1];
  drone_init(alldrone);
  
  Response response[DRONENUM];
  response_init(response, DRONENUM);

  char local_ip[13];
  get_local_ip(local_ip);
  char MY_ID = find_drone_by_ip(alldrone, local_ip);
  if (MY_ID == -1){
    printf("error!\n");
    return 0;
  }
  //testSm4Time(16,1980);while(1);
  //testHmacTime(32);while(1);
  char DEST_ID = MY_ID + 1;
  printf("my_ip : %s, my_id : %d\n", local_ip, MY_ID);
  int cfd = My_Socket_init(alldrone[MY_ID].IP, alldrone[MY_ID].PORT);
  AuthNode* head = initList();
  __uint8_t* mynonce = (__uint8_t*) malloc(NONCELEN);
  __uint8_t* othernonce = (__uint8_t*) malloc(NONCELEN);

  char DEBUG = atoi(confGet(conf, "debug"));
  int updateinterval = atoi(confGet(conf, "updateinterval"));
  int droneNum = atoi(confGet(conf, "dronenum"));
  printf("updateinterval: %d\n", updateinterval);

  pthread_t id;

  Recive_func_arg ReciveFunArg;
  ReciveFunArg.my_id = MY_ID;
  ReciveFunArg.alldrone = alldrone;
  ReciveFunArg.sock_fd = cfd;
  ReciveFunArg.head = head;
  ReciveFunArg.DEBUG = DEBUG;
  rfa = &ReciveFunArg;
  
  int ret = pthread_create(&id,NULL,receive,(void* )&ReciveFunArg);
  if (-1 == ret) print_err("pthread_create failed", __LINE__, errno);
  wrapperOfUpdate(updateinterval, updateinterval);
  
  ReceiveUpdate receiveupdate[DRONENUM];
  receiveupdate_init(receiveupdate, DRONENUM);
  UpdateInfo ui= {0};
  ui.updateinterval =  updateinterval;
  ui.response = response;
  ui.receiveupdate = (ReceiveUpdate*)&receiveupdate;
  updateif = &ui;
  //testWorstGroupCreate(cfd, alldrone, MY_ID, head, droneNum);
  //testBestGroupCreate(cfd, alldrone, MY_ID, head);
  //testCertificationTime(cfd, alldrone, MY_ID, head);
  //testJoinTime(cfd, alldrone, MY_ID, head, droneNum);
  //testCRTime(cfd, alldrone, MY_ID, head, 64);
  testOriginGroupCreateTime(cfd, alldrone, MY_ID, head, 8);
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
      printAuthtable(head, 1);
      break;
    case 1:
      AuthNode* p = searchList(head, DEST_ID);
      if (p != NULL && p->flag == 1){
        printf("drone-%d already authed\n", DEST_ID);
        continue;
      }
      __uint8_t* mynonce = (unsigned char*) malloc(NONCELEN);
      AuthMsg auth_msg = {0};
      auth_msg.index = 1;
      auth_msg.srcid = alldrone[MY_ID].id;
      auth_msg.destid = alldrone[DEST_ID].id;
      rand_bytes(auth_msg.nonce, NONCELEN);
      auth_msg.noncelen = NONCELEN;
      printf("mynonce is: ");
      print_char_arr(auth_msg.nonce, NONCELEN);
      if (auth_msg.srcid < auth_msg.destid){
        insertNode(head, alldrone[DEST_ID].id, auth_msg.nonce, NULL, 0, 0, 0);
      }
      else{
        insertNode(head, alldrone[DEST_ID].id, NULL, auth_msg.nonce, 0, 0, 0);
      }
      send_padding_msg_thread(cfd, (void*)&auth_msg, sizeof(auth_msg), 0x1, alldrone[DEST_ID].IP, alldrone[DEST_ID].PORT);
      printf("Send Auth msg to drone-%d!\n", DEST_ID);
      break;
    case 2:
      Update(cfd, alldrone[MY_ID].id, alldrone, head, response, DEBUG);
      break;
    default:
      break;
    }
  }
  return 0;
}
