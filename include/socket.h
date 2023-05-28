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

typedef struct GlobalVars {
    int cfd;
    char myId;
    Drone* allDrone;
    AuthNode* head;
    char Debug;
} GlobalVars;

typedef struct ThreadSendMsgType {
    int cfd;
    unsigned char msg[2000];
    int len;
    char padding;
    unsigned char DestIP[13];
    int DestPort;
} ThreadSendMsgType;

void tSMInit(ThreadSendMsgType* tSM);
void* receive(void* arg);
int mySocketInit(const unsigned char* IP, int PORT);
void destSocketInit(struct sockaddr_in* destAddr, const unsigned char* IP,
                    int port);
void sendPaddingMsgThread(int cfd, void* msg, int len, char padding,
                          unsigned char* DestIP, int destPort);
void* sendPaddingMsg(void* arg);
int sendMsg(int cfd, void* msg, int len, struct sockaddr* addr);

#endif