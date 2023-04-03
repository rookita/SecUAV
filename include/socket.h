#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include "message.h"


typedef struct recive_func_arg{
  unsigned char Sm4_key[16];
  unsigned char Sm4_iv[16];
  unsigned char* decrypted_r;
  int sock_fd;
}Recive_func_arg;

void *receive(void* arg);
int send_msg(int cfd, void* msg, int len, struct sockaddr* addr);
int My_Socket_init(const unsigned char* IP, int PORT);
void Dest_Socket_init(struct sockaddr_in* dest_addr, const unsigned char* IP, int PORT);
void send_auth_msg(int cfd, Auth* auth_msg, unsigned char* Dest_IP, int Dest_PORT);

