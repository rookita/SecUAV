#ifndef _MESSAGE
#define _MESSAGE

#include <stdlib.h>


//认证消息
typedef struct auth {
  int id;
  size_t rlen;
  unsigned char r[16]; //随机数
}Auth;

void generate_auth_message(Auth* auth_msg, int rlen, int id, unsigned char* r);

#endif