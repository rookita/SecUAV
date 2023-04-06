#ifndef _MESSAGE
#define _MESSAGE

#include <stdlib.h>


//认证消息
typedef struct auth_msg {
  char index; //认证进行到第几步
  int srcid;
  int destid;
  __uint8_t mynonce[16]; //随机数
  __uint8_t hmac[32];
  size_t noncelen;
}AuthMsg;

void generate_auth_message(AuthMsg* auth_msg, int rlen, int id, unsigned char* r);

#endif