#include "../include/socket.h"
#include "../include/utils.h"
#include "../include/crypto.h"
#include "../include/message.h"

#define MAXLEN 1024


struct send_func_arg Sendfunarg = {0};
pthread_mutex_t mutex; 

void *receive(void* arg) {
  struct recive_func_arg* rfa = (struct recive_func_arg *)arg;
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
      int msg_type = *(char*)msg;
      switch(msg_type){
        case 1:   //auth msg
          handle_auth_message(msg, rfa->DEBUG);
          break;
        case 2:   //share msg
          handle_share_message(msg, rfa->DEBUG);
          break;
        case 3:
          handle_update_message(msg, rfa->DEBUG);
          break;
        case 4:
          handle_update_share_msg(msg, rfa->DEBUG);
          break;
      }
    }
  }
  free(msg);
}

void sfa_init(Send_func_arg* sfa){
  sfa->sock_fd = -1;
  sfa->padding = -1;
  sfa->Dest_PORT = -1;
  sfa->len = -1;
  memset(sfa->msg, 0, 1024);
  memset(sfa->Dest_IP, 0, 13);
}

void send_padding_msg_thread(int cfd, void* msg, int len, char padding, unsigned char* Dest_IP, int Dest_PORT){
  pthread_mutex_lock(&mutex);
  sfa_init(&Sendfunarg);
  pthread_t id;
  Sendfunarg.sock_fd = cfd;
  mystrncpy(Sendfunarg.msg, msg, len);
  Sendfunarg.len = len;
  Sendfunarg.padding = padding;
  //printf("padding0: %d\n", padding);
  mystrncpy(Sendfunarg.Dest_IP, Dest_IP, 13);
  Sendfunarg.Dest_PORT = Dest_PORT;
  int ret = pthread_create(&id,NULL,send_padding_msg,(void* )&Sendfunarg);
  if (-1 == ret) print_err("pthread_create failed", __LINE__, errno);
}

void* send_padding_msg(void* arg){
  struct send_func_arg* sfa = (struct send_func_arg*)arg;
  struct sockaddr_in dest_addr;
  //printf("padding1: %d\n", sfa->padding);
  Dest_Socket_init(&dest_addr, sfa->Dest_IP, sfa->Dest_PORT);
  //__uint8_t* padding_msg = malloc((len + 1) * sizeof(char));
  __uint8_t padding_msg[sfa->len+1];
  memset(padding_msg, 0, sfa->len+1);
  add_byte(padding_msg, sfa->msg, sfa->len, sfa->padding);
  send_msg(sfa->sock_fd, (void*)padding_msg, sfa->len+1, (struct sockaddr*)&dest_addr);
  pthread_mutex_unlock(&mutex);
  //free(padding_msg);
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