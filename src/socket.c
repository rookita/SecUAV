#include "../include/socket.h"
#include "../include/utils.h"
#include "../include/crypto.h"
#include "../include/message.h"

#define MAXLEN 2000

void* receive(void* arg) {
    int ret = 0;
    void* msg = malloc(MAXLEN);
    struct sockaddr_in src_addr = {0};
    int src_addr_size = sizeof(src_addr);

    while (1) {
        bzero(msg, MAXLEN);
        ret = recvfrom(gV->cfd, msg, MAXLEN, 0, (struct sockaddr*)&src_addr,
                       &src_addr_size);

        if (-1 == ret) {
            print_err("recv failed", __LINE__, errno);
        }

        else if (ret > 0) {
            // print_char_arr(msg, 200);
            int msg_type = *(char*)msg;
            switch (msg_type) {
            case 1: // auth msg

                receiveAuthMessage(msg);
                break;

            case 2: // share msg

                receiveShareMessage(msg);
                break;

            case 3: receiveNodeCheckMessage(msg); break;

            case 4: receiveAuthTableShareMsg(msg); break;
            }
        }
    }

    free(msg);
}

void tSMInit(ThreadSendMsgType* tSM) {
    tSM->cfd = -1;
    tSM->padding = -1;
    tSM->DestPort = -1;
    tSM->len = -1;
    memset(tSM->msg, 0, MAXLEN);
    memset(tSM->DestIP, 0, 13);
}

void sendPaddingMsgThread(int cfd, void* msg, int len, char padding,
                          unsigned char* DestIp, int DestPort) {
    ThreadSendMsgType* tSM =
        (ThreadSendMsgType*)malloc(sizeof(ThreadSendMsgType));

    if (tSM == NULL) {
        printf("tSM malloc error!\n");
        return;
    }
    pthread_t id;

    tSM->cfd = cfd;
    mystrncpy(tSM->msg, msg, len);
    tSM->len = len;
    tSM->padding = padding;
    tSM->DestPort = DestPort;
    mystrncpy(tSM->DestIP, DestIp, 13);

    int ret = pthread_create(&id, NULL, sendPaddingMsg, (void*)tSM);
    if (-1 == ret) print_err("pthread_create failed", __LINE__, errno);
    // printf("Send Success!\n");
}

void* sendPaddingMsg(void* arg) {
    struct ThreadSendMsgType* tSM = (struct ThreadSendMsgType*)arg;
    struct sockaddr_in destAddr;

    destSocketInit(&destAddr, tSM->DestIP, tSM->DestPort);
    __uint8_t paddingMsg[tSM->len + 1];
    memset(paddingMsg, 0, tSM->len + 1);
    addBytes(paddingMsg, tSM->msg, tSM->len, &(tSM->padding), 1);

    sendMsg(tSM->cfd, (void*)paddingMsg, tSM->len + 1,
            (struct sockaddr*)&destAddr);

    if (tSM != NULL) free(tSM);
}

int sendMsg(int cfd, void* msg, int len, struct sockaddr* addr) {
    int ret = 0;
    ret = sendto(cfd, (void*)msg, len, 0, addr, sizeof(*addr));
    return ret;
}

int mySocketInit(const unsigned char* IP, int port) {
    int ret = -1;
    int cfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (-1 == cfd) { print_err("socket failed", __LINE__, errno); }
    struct sockaddr_in myAddr;

    myAddr.sin_family = AF_INET;
    myAddr.sin_port = htons(port);
    myAddr.sin_addr.s_addr = inet_addr(IP);

    ret = bind(cfd, (struct sockaddr*)&myAddr, sizeof(myAddr));

    if (-1 == ret) { print_err("bind failed", __LINE__, errno); }
    return cfd;
}

void destSocketInit(struct sockaddr_in* destAddr, const unsigned char* IP,
                    int port) {
    destAddr->sin_family = AF_INET;
    destAddr->sin_port = htons(port);
    destAddr->sin_addr.s_addr = inet_addr(IP);
}