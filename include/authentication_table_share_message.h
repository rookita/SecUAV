#ifndef _AUTH_TABEL_SHARE_MESSAGE
#define _AUTH_TABEL_SHARE_MESSAGE

#include "basic_message.h"

typedef struct AuthenticationTableShareMsg {
    struct MessageHeader header;
    char id[DRONENUM];
    size_t num;
    __uint8_t nonce[NONCELEN * DRONENUM];
} AuthenticationTableShareMsg;

void printAuthenticationTableShareMsg(
    AuthenticationTableShareMsg* update_share_msg);
void sendAuthTableShareMsg(AuthenticationTableShareMsg* authTableShareMsg,
                           int msgLen, unsigned char* DestIP, int DestPort,
                           __uint8_t* Sm4_key);
void shareAuthTable();
void receiveAuthTableShareMsg(void* msg);
void regularUpdate(int sigum);

#endif