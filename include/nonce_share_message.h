#ifndef _NONCE_SHARE_MESSAGE
#define _NONCE_SHARE_MESSAGE

#include "basic_message.h"

typedef struct NonceShareMsg {
    struct MessageHeader header;
    char shareId[DRONENUM];
    size_t shareNum;
    __uint8_t yourNonce[NONCELEN];
    __uint8_t shareNonce[NONCELEN * DRONENUM];
} NonceShareMsg;

void generateShareMessage(NonceShareMsg* shareMsg, char shareId,
                          MessageHeader* header, __uint8_t* yourNonce,
                          __uint8_t* shareNonce);
void sendShareMessage(NonceShareMsg* shareMsg, size_t msgLen,
                      unsigned char* DestIP, int DestPort, __uint8_t* Sm4_key);

void printNonceShareMsg(NonceShareMsg* shareMsg);
void nonceShare(AuthNode* p, char type, char dont_share);
void receiveShareMessage(void* msg);

#endif