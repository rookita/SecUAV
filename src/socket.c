#include "../include/socket.h"
#include "../include/utils.h"
#include "../include/crypto.h"

#define MAXLEN 1024
#define DEBUG 1

void *receive(void* arg) {
  Recive_func_arg* rfa = (Recive_func_arg *)arg;
  int ret = 0;
  void* msg = malloc(MAXLEN);
  struct sockaddr_in src_addr = {0};
  int src_addr_size = sizeof(src_addr);
  
  while(1) {
    bzero(msg, MAXLEN);
    ret = recvfrom(rfa->sock_fd, msg, MAXLEN,0, (struct sockaddr *)&src_addr, &src_addr_size); 
    if (-1 == ret) {
      print_err("recv failed",__LINE__,errno);
    }
    else if (ret > 0){
      if (*(char*)msg == 0){   //auth message
        AuthMsg auth_msg = {0};
        char* src = msg + 1;
        size_t auth_msg_len = sizeof(auth_msg);
        memmove(&auth_msg, src, auth_msg_len);  //去掉消息前一个字节
        printf("msg: ");print_char_arr(msg, auth_msg_len+1);

        if (auth_msg.destid == rfa->myid){
          switch(auth_msg.index){
            case 1: //reciver
              AuthNode* node = insertNode(rfa->head, auth_msg.srcid, NULL, auth_msg.mynonce, 0, 0);
              __uint8_t* mynonce = (__uint8_t*) malloc(16);
              __uint8_t hmac[32];
              rand_bytes(mynonce, 16);
              strncpy(node->mynounce, mynonce, 16);
              __uint8_t mbuf[34];
              strncat(mbuf, &auth_msg.srcid, 1);strncat(mbuf, &auth_msg.destid, 1);strncat(mbuf,node->mynounce, 16);strncat(mbuf, node->othernounce, 16);
              my_sm3_hmac(hmac_key, sizeof(*hmac_key), mbuf, sizeof(*mbuf), hmac);
              AuthMsg my_auth_msg = {0};
              my_auth_msg.index = 2;
              my_auth_msg.destid = auth_msg.srcid;
              my_auth_msg.srcid = auth_msg.destid;
              strncpy(my_auth_msg.mynonce, mynonce, 16);
              my_auth_msg.noncelen = 16;
              strncpy(my_auth_msg.hmac, hmac, 32);
              if (DEBUG){
                printf("auth msg :\n");
                printAuthMsg(&my_auth_msg);
              }
              send_auth_msg(rfa->sock_fd, &my_auth_msg, "192.168.8.187", 6666);
              break;
            case 2: //sender
              //查找table,验证并计算hmac发送给对方
              AuthNode* p2 = searchList(rfa->head, auth_msg.srcid);
              if (p2 != NULL){
                 __uint8_t mbuf[34];__uint8_t hmac[32];
                 strncat(mbuf, &auth_msg.destid, 1);strncat(mbuf, &auth_msg.srcid, 1);strncat(mbuf, auth_msg.mynonce, 16);strncat(mbuf, p2->mynounce, 16);
                 
                 my_sm3_hmac(hmac_key, sizeof(*hmac_key), mbuf, sizeof(*mbuf), hmac);
                 if ( isEqual(auth_msg.hmac, hmac, 32) ){   //验证通过
                    strncpy(p2->othernounce, auth_msg.mynonce, 16);
                    memset(mbuf, 0, 40);memset(hmac, 0, 32);
                    strncat(mbuf, &auth_msg.destid, 4);strncat(mbuf, &auth_msg.srcid, 4);strncat(mbuf, p2->mynounce, 16);strncat(mbuf, p2->othernounce, 16);
                    my_sm3_hmac(hmac_key, sizeof(*hmac_key), mbuf, sizeof(*mbuf), hmac);
                    
                    printf("mbuf: ");print_char_arr(mbuf, 40);
                    printf("id1: %d\n", auth_msg.destid);
                    printf("id2: %d\n", auth_msg.srcid);
                    printf("nonce1: ");print_char_arr(p2->mynounce, 16);
                    printf("nonce2: ");print_char_arr(p2->othernounce, 16);
                    printf("hmac_key: ");print_char_arr(hmac_key, 16);
                    printf("hmac: ");print_char_arr(hmac, 32);

                    strncpy(p2->othernounce, auth_msg.mynonce, 16);
                    AuthMsg my_auth_msg = {0};
                    my_auth_msg.index = 3;
                    my_auth_msg.destid = auth_msg.srcid;
                    my_auth_msg.srcid = auth_msg.destid;
                    my_auth_msg.noncelen = 16;
                    strncpy(my_auth_msg.hmac, hmac, 32);
                    p2->flag = 1;
                    p2->direct = 1;
                    printf("%d auth success!\n\n", auth_msg.srcid);
                    printList(rfa->head);
                    if (DEBUG){
                      printf("auth msg :\n");
                      printAuthMsg(&my_auth_msg);
                    }
                    send_auth_msg(rfa->sock_fd, &my_auth_msg, "192.168.8.187", 6666);
                 }
              else {
                printf("hmac is not equal!\n");
                }
              }
              else{
                printf("case2 Node is not valid!!!\n");
              }
              break;
            case 3: //reciver
              //查找table,验证hamc
              AuthNode* p3 = searchList(rfa->head, auth_msg.srcid);
              
              if (p3 != NULL){
                 __uint8_t mbuf[34];__uint8_t hmac[32];
                 strncat(mbuf, &auth_msg.srcid, 4);strncat(mbuf, &auth_msg.destid, 4);strncat(mbuf,p3->othernounce, 16);strncat(mbuf, p3->mynounce, 16);
                 my_sm3_hmac(hmac_key, sizeof(*hmac_key), mbuf, sizeof(*mbuf), hmac);
                 if ( isEqual(auth_msg.hmac, hmac, 32) ){   //验证通过
                    p3->direct = 1;
                    p3->flag = 1;
                    printList(rfa->head);
                    printf("%d auth success!\n\n", auth_msg.srcid);
                 }
                  else {
                    printf("case3 hmac is not equal!\n");
                    printf("mbuf: ");print_char_arr(mbuf, 40);
                    printf("id1: %d\n", auth_msg.srcid);
                    printf("id2: %d\n", auth_msg.destid);
                    printf("nonce1: ");print_char_arr(p3->othernounce, 16);
                    printf("nonce2: ");print_char_arr(p3->mynounce, 16);
                    printf("hmac: ");print_char_arr(hmac,32);
                    printf("hmac_key: ");print_char_arr(hmac_key, 16);
                  }
              }
              else{
                printf("case3 Node is not valid!!!\n");
              }
              break;
          }
        }       
        if (DEBUG){
          printf("\n");
          printf("AUTH MESSAGE!!\n");
          printf("index = %d\n", auth_msg.index);
          printf("src id = %d\n", auth_msg.srcid);
          printf("dest id = %d\n", auth_msg.destid);
          printf("noncelen:%ld\n", auth_msg.noncelen);
          printf("nonce: ");print_char_arr(auth_msg.mynonce, auth_msg.noncelen);
          printf("hmac: ");print_char_arr(auth_msg.hmac, 32);
          printf("\n");
        }
      }
    }
  }
  free(msg);
}

void send_auth_msg(int cfd, AuthMsg* auth_msg, unsigned char* Dest_IP, int Dest_PORT){
  struct sockaddr_in dest_addr;
  Dest_Socket_init(&dest_addr, Dest_IP, Dest_PORT);
  int len = sizeof(*auth_msg);
  char* padding_msg = malloc((len + 1) * sizeof(char));
  char* dest = padding_msg + 1;
  //printf("%d\n",len);
  memmove((void* )dest, (void* )auth_msg, len);
  //printf("padding_msg: ");
  //print_char_arr(padding_msg, len+1);
  send_msg(cfd, (void*)padding_msg, len+1, (struct sockaddr*)&dest_addr);
  free(padding_msg);
}

int send_msg(int cfd, void* msg, int len, struct sockaddr* addr){
  int ret = 0;
  //print_char_arr(msg, len);
  ret = sendto(cfd, (void *)msg, len, 0, addr, sizeof(*addr));
  return ret;
}

int My_Socket_init(const unsigned char* IP, int PORT){
  int ret = -1;
  int cfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (-1 == cfd) {
    print_err("socket failed", __LINE__, errno);
  }
  struct sockaddr_in my_addr;
  my_addr.sin_family = AF_INET; 
  my_addr.sin_port = htons(PORT); 
  my_addr.sin_addr.s_addr = inet_addr(IP); 
  ret = bind(cfd, (struct sockaddr*)&my_addr, sizeof(my_addr));
  if ( -1 == ret) {
    print_err("bind failed",__LINE__,errno);
  }
  return cfd;
}

void Dest_Socket_init(struct sockaddr_in* dest_addr, const unsigned char* IP, int PORT){
  dest_addr->sin_family = AF_INET; 
  dest_addr->sin_port = htons(PORT); 
  dest_addr->sin_addr.s_addr = inet_addr(IP);
}