#ifndef _MESSAGE
#define _MESSAGE

#include <stdlib.h>


//认证消息
typedef struct auth {
  int id;
  unsigned char* r; //随机数
  size_t rlen;
}Auth;

void generate_auth_message(Auth* auth_msg, int rlen, int id, unsigned char* r);

#endif