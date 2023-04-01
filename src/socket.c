#include "../include/socket.h"
#include "../include/utils.h"
#include "../include/crypto.h"

#define MAXLEN 1024
#define DEBUG 1

void *receive(void* arg) {
  Recive_func_arg* rfa = (Recive_func_arg *)arg;
  int ret = 0;
  char* msg = malloc(MAXLEN);
  struct sockaddr_in src_addr = {0};
  int src_addr_size = sizeof(src_addr);
  
  while(1) {
    bzero(msg, MAXLEN);
    ret = recvfrom(rfa->sock_fd, &msg, MAXLEN,0, (struct sockaddr *)&src_addr, &src_addr_size); 
    if (-1 == ret) {
      print_err("recv failed",__LINE__,errno);
    }
    else if (ret > 0){
      if (*msg == 0){   //auth message
        Auth auth_msg = {0};
        char* src = msg + 1;
        size_t auth_msg_len = sizeof(auth_msg);
        memmove(&auth_msg, src, auth_msg_len);
        print_char_arr(msg, auth_msg_len+1);
        
        if (DEBUG){
          printf("AUTH MESSAGE!!\n");
          printf("uav id = %d\n", auth_msg.id);
          printf("auth_msg r: ");
          print_char_arr(auth_msg.r, auth_msg.rlen);
        }
        size_t len;
        my_sm4_cbc_padding_decrypt(rfa->Sm4_key, rfa->Sm4_iv, auth_msg.r, auth_msg.rlen, rfa->decrypted_r, &len, 0);
        if(DEBUG){
          printf("decrypted_r:");
          print_char_arr(rfa->decrypted_r, auth_msg.rlen);
          printf("src_ip %s,src_port %d\n", inet_ntoa(src_addr.sin_addr),ntohs(src_addr.sin_port));
        }
      }
    }
  }
}

void send_auth_msg(int cfd, Auth* auth_msg, unsigned char* Dest_IP, int Dest_PORT){
  struct sockaddr_in dest_addr;
  Dest_Socket_init(&dest_addr, Dest_IP, Dest_PORT);
  int len = sizeof(*auth_msg);
  char* padding_msg = malloc((len + 1) * sizeof(char));
  char* dest = padding_msg + 1;
  //printf("%d\n",len);
  memmove((void* )dest, (void* )auth_msg, len);
  printf("padding_msg: ");
  print_char_arr(padding_msg, len+1);
  send_msg(cfd, padding_msg, (struct sockaddr*)&dest_addr);
  free(padding_msg);
}

int send_msg(int cfd, void* msg, struct sockaddr* addr){
  int ret = 0;
  ret = sendto(cfd, (void *)msg, sizeof(*msg), 0, addr, sizeof(*addr));
  
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