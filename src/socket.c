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
      if (*(char*)msg == 1){   //auth message
        AuthMsg auth_msg = {0};
        pre_auth_message(msg, &auth_msg, sizeof(auth_msg), DEBUG); //预处理
        if (auth_msg.destid == rfa->alldrone[rfa->my_index].id){
          if (DEBUG){
            printf("[info]>>>recive msg \n");
            printAuthMsg(&auth_msg);
          }
          switch(auth_msg.index){
            case 1: //reciver
              if (DEBUG)
                printf("##########CASE ONE DEBUG INFO START##########\n");
              AuthNode* node = insertNode(rfa->head, auth_msg.srcid, NULL, auth_msg.mynonce, 0, 0);
              __uint8_t* mynonce = (__uint8_t*) malloc (16);
              __uint8_t* mbuf = (__uint8_t*) malloc (34);
              __uint8_t* hmac = (__uint8_t*) malloc (32);
              rand_bytes(mynonce, 16);
              strncpy(node->mynonce, mynonce, 16);
              strncat(mbuf, &auth_msg.srcid, 1);strncat(mbuf, &auth_msg.destid, 1);strncat(mbuf,node->mynonce, 16);strncat(mbuf, node->othernonce, 16);
              if (DEBUG){
                printf("[info]>>the mbuf of hmac is ");
                print_char_arr(mbuf, 32);
              }
              my_sm3_hmac(hmac_key, sizeof(*hmac_key), mbuf, sizeof(*mbuf), hmac);
              AuthMsg my_auth_msg = {0};
              generate_auth_message(&my_auth_msg, 2, auth_msg.destid, auth_msg.srcid, mynonce, 16, hmac);
              if (DEBUG){
                printf("[info]>>>recive auth request.will send msg is");
                printAuthMsg(&my_auth_msg);
              }
              send_auth_msg(rfa->sock_fd, &my_auth_msg, rfa->alldrone[(int)(auth_msg.srcid) - 1].IP, rfa->alldrone[(int)(auth_msg.srcid)- 1].PORT);
              free(mynonce);free(mbuf);free(hmac);
              if (DEBUG)
                printf("##########CASE ONE DEBUG INFO END##########\n");
              break;

            case 2: //sender
              //查找table,验证并计算hmac发送给对方
              if (DEBUG)
                printf("##########CASE TWO DEBUG INFO START##########\n");
              AuthNode* p2 = searchList(rfa->head, auth_msg.srcid);
              if (p2 != NULL){
                __uint8_t* mbuf = (__uint8_t*) malloc (34);
                __uint8_t* hmac = (__uint8_t*) malloc (32);
                 strncat(mbuf, &auth_msg.destid, 1);strncat(mbuf, &auth_msg.srcid, 1);strncat(mbuf, auth_msg.mynonce, 16);strncat(mbuf, p2->mynonce, 16);
                 my_sm3_hmac(hmac_key, sizeof(*hmac_key), mbuf, sizeof(*mbuf), hmac);
                 
                 if ( isEqual(auth_msg.hmac, hmac, 32) ){   //验证通过
                    if (DEBUG)
                      printf("[info]>>> hmac right\n");
                    strncpy(p2->othernonce, auth_msg.mynonce, 16);
                    memset(mbuf, 0, 34);memset(hmac, 0, 32);
                    strncat(mbuf, &auth_msg.destid, 1);strncat(mbuf, &auth_msg.srcid, 1);strncat(mbuf, p2->mynonce, 16);strncat(mbuf, p2->othernonce, 16);
                    my_sm3_hmac(hmac_key, sizeof(*hmac_key), mbuf, sizeof(*mbuf), hmac);
                    /*
                    if (DEBUG){
                      printf("mbuf: ");print_char_arr(mbuf, 34);
                      printf("id1: %d\n", auth_msg.destid);
                      printf("id2: %d\n", auth_msg.srcid);
                      printf("nonce1: ");print_char_arr(p2->mynonce, 16);
                      printf("nonce2: ");print_char_arr(p2->othernonce, 16);
                      printf("hmac: ");print_char_arr(hmac, 32);
                    }
                    */
                    strncpy(p2->othernonce, auth_msg.mynonce, 16);
                    AuthMsg my_auth_msg = {0};
                    generate_auth_message(&my_auth_msg, 3, auth_msg.destid, auth_msg.srcid, NULL, 16, hmac);
                    p2->flag = 1;
                    p2->direct = 1;
                    printf("[info]>>>%d auth success!\n\n", auth_msg.srcid);
                    if (DEBUG){
                      printf("[info]>> auth table is \n");
                      printList(rfa->head);
                      printf("[info]>>>auth msg is \n");
                      printAuthMsg(&my_auth_msg);
                    }
                    send_auth_msg(rfa->sock_fd, &my_auth_msg, rfa->alldrone[(int)(auth_msg.srcid) - 1].IP, rfa->alldrone[(int)(auth_msg.srcid) - 1].PORT);
                 }

              else {
                printf("[info]>>>case2 hmac is not equal!\n");
                printf("[info]>>>compute_hmac is");print_char_arr(hmac, 32);
                printf("[info]>>>recive_hmac is");print_char_arr(auth_msg.hmac, 32);
                }
              free(mbuf);free(hmac);
              }
              else{
                printf("[info]>>Dont found the id\n");
              }
              if (DEBUG)
                printf("##########CASE TWO DEBUG INFO END##########\n");
              break;

            case 3: //reciver
              //查找table,验证hamc
              AuthNode* p3 = searchList(rfa->head, auth_msg.srcid);
              if (DEBUG)
                printf("##########CASE THREE DEBUG INFO START##########\n");
              if (p3 != NULL){
                  __uint8_t* mbuf = (__uint8_t*) malloc (34);
                  __uint8_t* hmac = (__uint8_t*) malloc (32);
                 strncat(mbuf, &auth_msg.srcid, 4);strncat(mbuf, &auth_msg.destid, 4);strncat(mbuf,p3->othernonce, 16);strncat(mbuf, p3->mynonce, 16);
                 my_sm3_hmac(hmac_key, sizeof(*hmac_key), mbuf, sizeof(*mbuf), hmac);
                 if ( isEqual(auth_msg.hmac, hmac, 32) ){   //验证通过
                    if (DEBUG)
                      printf("[info]>>> hmac right\n");
                    p3->direct = 1;
                    p3->flag = 1;
                    printf("%d auth success!\n\n", auth_msg.srcid);
                    if (DEBUG){
                      printf("[info]>> auth table is \n");
                      printList(rfa->head);
                    }
                 }
                  else {
                    printf("[info]>>>case3 hmac is not equal!\n");
                    printf("[info]>>>compute_hmac is");print_char_arr(hmac, 32);
                    printf("[info]>>>recive_hmac is");print_char_arr(auth_msg.hmac, 32);
                  }
                  free(mbuf);free(hmac);
              }
              else{
                printf("[info]>>Dont found the id\n");
              }
              printf("##########CASE THREE DEBUG INFO END##########\n");
              break;
          }
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
  padding_msg[0] = 1;
  char* dest = padding_msg + 1;
  //printf("%d\n",len);
  memmove((void* )dest, (void* )auth_msg, len);
  printf("padding_msg: ");
  print_char_arr(padding_msg, len+1);
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