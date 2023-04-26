#ifndef _SOCKET
#define _SOCKET

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
#include "auth_table.h"
#include "drone.h"
#include "auth_table.h"

struct response;

typedef struct recive_func_arg{
  int sock_fd;
  int my_id;
  char DEBUG;
  Drone* alldrone;
  struct response* response;
  AuthNode* head;
}Recive_func_arg;

typedef struct send_func_arg{
  int sock_fd;
  unsigned char msg[1024];
  int len;
  char padding;
  unsigned char Dest_IP[13];
  int Dest_PORT;
}Send_func_arg;

extern struct send_func_arg Sendfunarg;
extern pthread_mutex_t mutex; 

void sfa_init(Send_func_arg* sfa);
void *receive(void* arg);
int send_msg(int cfd, void* msg, int len, struct sockaddr* addr);
int My_Socket_init(const unsigned char* IP, int PORT);
void Dest_Socket_init(struct sockaddr_in* dest_addr, const unsigned char* IP, int PORT);
void send_padding_msg_thread(int cfd, void* msg, int len, char padding, unsigned char* Dest_IP, int Dest_PORT);
void* send_padding_msg(void* arg);

#endif