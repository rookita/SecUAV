#include <stdlib.h>
#define RANDNUM_SIZE 15

typedef struct message {
  int id;
  int type;
  unsigned char r[RANDNUM_SIZE]; //随机数
  size_t rlen;
}Message;