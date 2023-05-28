#include "../include/basic_message.h"

void removeMessageType(void* originMsg, void* destMsg, size_t messageLen) {
    void* start = originMsg + 1;
    memmove(destMsg, start, messageLen);
}

// response初始化
void response_init(Response* response, size_t len) {
    int i = 0;
    for (i = 0; i < len; i++) {
        response[i].id = -1;
        response[i].isresponsed = -1;
        response[i].num = 0;
    }
}

// recieve_update初始化
void receiveupdate_init(ReceiveUpdate* receiveupdate, size_t len) {
    int i = 0;
    for (i = 0; i < len; i++) {
        receiveupdate[i].id = gV->allDrone[i].id;
        receiveupdate[i].flag = 0;
    }
}

// 寻找drone-{id}的response
Response* response_find(Response* response, char id) {
    int i = 0;
    for (i = 0; i < response[0].num; i++) {
        if (response[i].id == id) return &(response[i]);
    }
    return NULL;
}

// 寻找drone-{id}的response
ReceiveUpdate* receiveupdate_find(ReceiveUpdate* receiveupdate, char id) {
    int i = 0;
    for (i = 0; i < DRONENUM; i++) {
        if (receiveupdate[i].id == id) return &(receiveupdate[i]);
    }
    return NULL;
}

// 判断是否所有drone已经回复
char response_check(Response* response) {
    printf("num: %d\n", response[0].num);
    int i = 0;
    for (i = 0; i < response[0].num; i++) {
        if (response[i].isresponsed != 1) return 0;
    }
    return 1;
}