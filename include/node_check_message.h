#ifndef _NODE_CHECK_MESSAGE
#define _NODE_CHECK_MESSAGE

#include "basic_message.h"

typedef struct NodeCheckMsg {
    struct MessageHeader header;
    char index; // send or response??
    __uint8_t newnonce[NONCELEN];
} NodeCheckMsg;

extern void shareAuthTable();

void generateNodeCheckMsg(NodeCheckMsg* nodeCheckMsg, char index,
                          MessageHeader* header, __uint8_t* newnonce);
void printNodeCheckMsg(NodeCheckMsg* nodeCheckMsg);
void sendNodeCheckMsg(NodeCheckMsg* nodeCheckMsg, int msgLen,
                      unsigned char* DestIP, int DestPort, __uint8_t* Sm4_key);
void nodeCheckToOne(char dest_id);
void nodeCheck(Response* response);
void receiveNodeCheckMessage(void* msg);
void* listenUpdateResponse(void* args);

#endif