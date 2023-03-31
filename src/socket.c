#include "../include/socket.h"
#include "../include/utils.h"
#include "../include/crypto.h"

int cfd = -1;
void *receive(void* arg) {
  Recive_func_arg* rfa = (Recive_func_arg *)arg;
  int ret = 0;
  Message uav_msg = {0};
  struct sockaddr_in src_addr = {0};
  int src_addr_size = sizeof(src_addr);
  while(1) {
    bzero(&uav_msg, sizeof(uav_msg));
    ret = recvfrom(cfd, &uav_msg, sizeof(uav_msg),0, (struct sockaddr *)&src_addr, &src_addr_size); 
    if (-1 == ret) {
      print_err("recv failed",__LINE__,errno);
    }
    else if (ret > 0){

      printf("uav id = %d\n", uav_msg.id);
      printf("uav_msg type = %d\n", uav_msg.type);
      printf("uav_msg r: ");
      print_char_arr(uav_msg.r, uav_msg.rlen);
      printf("uav_msg rlen = %ld\n", uav_msg.rlen);

      if (uav_msg.type == 0){
        size_t len;
        my_sm4_cbc_padding_decrypt(rfa->Sm4_key, rfa->Sm4_iv, uav_msg.r, uav_msg.rlen, rfa->decrypted_r, &len, 0);
        print_char_arr(rfa->decrypted_r, uav_msg.rlen);
      }

      printf("src_ip %s,src_port %d\n",\
      inet_ntoa(src_addr.sin_addr),ntohs(src_addr.sin_port));
    }
  }
}

int send_msg(int cfd, Message* uav_msg, struct sockaddr* addr){
  int ret = 0;
  //while(1)
  	ret = sendto(cfd, (void *)uav_msg, sizeof(*uav_msg), 0, addr, sizeof(*addr));
  return ret;
}

int My_Socket_init(const unsigned char* IP, int PORT){
  int ret = -1;
  cfd = socket(AF_INET, SOCK_DGRAM, 0);
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