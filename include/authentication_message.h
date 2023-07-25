#ifndef _AUTH_MESSAGE
#define _AUTH_MESSAGE

#include "basic_message.h"

typedef struct AuthenticationMsg {
    char index;                // 认证进行到第几步
    struct MessageHeader header;
    __uint8_t nonce[NONCELEN]; // 随机数
    __uint8_t hmac[32];
} AuthenticationMsg;

void generateAuthMessage(AuthenticationMsg* authMsg, char index,
                         MessageHeader* header, __uint8_t* nonce,
                         __uint8_t* hmac);
void sendAuthMessage(AuthenticationMsg* authMsg, unsigned char* DestIP,
                     int DestPort, int msgLen);

void auth(char index, char destId, __uint8_t* nonce, char repeat);
void printAuthenticationMsg(AuthenticationMsg* authMsg);
void receiveAuthMessage(void* originMsg);

extern void nonceShare(AuthNode* p, char type, char dont_share);
#endif