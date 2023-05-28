#ifndef _BASIC_MESSAGE
#define _BASIC_MESSAGE

#include "socket.h"
#include "auth_table.h"
#include "crypto.h"
#include "utils.h"
#include "drone.h"
#include <stdlib.h>

#define NONCELEN 16

typedef struct MessageHeader {
    char srcId;
    char destId;
} MessageHeader;

typedef struct response {
    char id;
    char isresponsed;
    char num;
} Response;

typedef struct receive_update { // 用于判断触发节点是否丢失
    char id;
    char flag; // flag = 1表示收到触发节点的更新消息
} ReceiveUpdate;

typedef struct update_info {
    int updateinterval;
    Response* response;
    __uint8_t nonce[NONCELEN];
    ReceiveUpdate* receiveupdate;
} UpdateInfo;

extern GlobalVars* gV;
extern UpdateInfo* updateif;

void response_init(Response* response, size_t len);
void receiveupdate_init(ReceiveUpdate* receiveupdate, size_t len);
Response* response_find(Response* response, char id);
ReceiveUpdate* receiveupdate_find(ReceiveUpdate* receiveupdate, char id);
char response_check(Response* response);
void removeMessageType(void* originMsg, void* destMsg, size_t messageLen);

#endif