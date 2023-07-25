#include "../include/test.h"
#include <unistd.h>
#include <time.h>

// 测试链式结构群组建立
void testWorstGroupCreate(char myId, int droneNum) { // chain

    printf(
        "=============================START TEST!!! I am drone-%d=============================\n",
        myId);
    char destId = myId + 1;
    printf("%d\n", gV->allDrone[myId].leaderID);
    if (myId == gV->allDrone[myId].leaderID) { return; }
    if (findDroneById(gV->allDrone, destId) == 0
        || compareDroneGroup(gV->allDrone, myId, destId) != 0) {
        return;
    }
    unsigned char nonce[NONCELEN];
    while (1) {
        memset(nonce, 0, NONCELEN);
        printf("start_time: %ld\n", clock());
        sleep(myId);
        if (myId < droneNum) {
            AuthNode* node = searchList(gV->head, destId);
            if (node == NULL) {
                rand_bytes(nonce, NONCELEN);
                printf("nonce is ");
                print_char_arr(nonce, NONCELEN);
                auth(0x0, destId, nonce, 0);
            }

            // 已经发起过认证
            else if (node != NULL && node->flag != 1) {
                AuthNode* node = searchList(gV->head, destId);
                if (node == NULL) {
                    printf("error\n");
                    return;
                }
                if (myId < destId)
                    auth(node->index, destId, node->nonce1, 1);
                else
                    auth(node->index, destId, node->nonce2, 1);
            } else {
                break;
            }
        }
    }
    printf(
        "=============================TEST END!!! I am drone-%d=============================\n",
        myId);
}

// 测试二叉树结构群组建立
void testBestGroupCreate(int cfd, Drone* alldrone, char myId,
                         AuthNode* head) { // 二叉树
    printf(
        "=============================START TEST!!! I am drone-%d=============================\n",
        myId);
    if (myId == gV->allDrone[myId].leaderID) { return; }
    int count = 1, dn = DRONENUM, i, destId = 0;
    int interval = 1, start = 1, drone;
    unsigned char nonce[NONCELEN];
    AuthNode* p = NULL;
    AuthenticationMsg authMsg = {0};

    while (dn != 1) { // 2^count == dn
        dn = dn / 2;
        count++;
    }

    printf("count: %d\n", count);

    for (i = 0; i < count; i++) {
        if (start > myId) sleep(100000);
        interval = 2 * interval;
        drone = start;
        printf("start: %d; interval: %d\n", start, interval);
        while (drone < DRONENUM) {
            if (drone == myId) {
                destId = myId + 1;
                break;
            } else if (drone > myId) {
                break;
            }
            drone = drone + interval;
        }

        if (destId != 0) {
            while (1) {
                p = searchList(head, destId);
                // 首次发送
                if (p == NULL) {
                    memset(nonce, 0, NONCELEN);
                    rand_bytes(nonce, NONCELEN);
                    auth(0x0, destId, nonce, 0);
                    printf("start_time: %ld\n", clock());
                    printf("Send authMsg to drone-%d!\n", destId);
                }

                // 已经发起过认证
                else if (p != NULL && p->flag != 1) {
                    AuthNode* node = searchList(gV->head, destId);
                    if (node == NULL) {
                        printf("error\n");
                        return;
                    }
                    if (myId < destId)
                        auth(node->index, destId, node->nonce1, 1);
                    else
                        auth(node->index, destId, node->nonce2, 1);
                } else {
                    break;
                }
                sleep(10);
            }
            destId = 0;
        } else { // destId == 0
            sleep(8);
        }
        start = 2 * start;
    }

    printf(
        "=============================TEST END!!! I am drone-%d=============================\n",
        myId);
}

// 测试两方认证时间
void testCertificationTime(int cfd, Drone* alldrone, char myId,
                           AuthNode* head) {
    printf(
        "=============================START TEST!!! I am drone-%d=============================\n",
        myId);
    int destId = 0;

    if (myId == 1) { destId = 2; }

    sleep(5); // 等待对方无人机上线
    unsigned char nonce[NONCELEN];
    memset(nonce, 0, NONCELEN);
    rand_bytes(nonce, NONCELEN);
    AuthenticationMsg authMsg = {0};
    MessageHeader header = {0};
    header.srcId = myId;
    header.destId = destId;

    generateAuthMessage(&authMsg, 0x1, &header, nonce, NULL);

    insertNode(head, alldrone[destId].id, authMsg.nonce, NULL, 0, 0,
               0); // myId < destId

    printf("mynonce is: ");
    print_char_arr(authMsg.nonce, NONCELEN);

    // printf("start_time: %ld\n", clock());
    sendPaddingMsgThread(cfd, (void*)&authMsg, sizeof(authMsg), 0x1,
                         alldrone[destId].IP, alldrone[destId].PORT);
    printf("Send authMsg to drone-%d!\n", destId);
}

// 测试节点加入群组时间
void testJoinTime(int cfd, Drone* alldrone, char myId, AuthNode* head,
                  int droneNum) {
    printf("start_time: %ld\n", clock());
    printf(
        "=============================START TEST!!! I am drone-%d=============================\n",
        myId);
    char destId = myId + 1;
    if (findDroneById(alldrone, destId) == 0) { // 无对应无人机
        return;
    }
    while (1) {
        sleep(myId);
        if (myId == 1) sleep(100);
        if (myId < droneNum) {
            AuthNode* p = searchList(head, destId);
            if (p == NULL) {
                unsigned char nonce[NONCELEN];
                memset(nonce, 0, NONCELEN);
                rand_bytes(nonce, NONCELEN);
                AuthenticationMsg authMsg = {0};
                MessageHeader header = {0};
                header.srcId = myId;
                header.destId = destId;

                generateAuthMessage(&authMsg, 0x1, &header, nonce, NULL);

                printf("mynonce is: ");
                print_char_arr(authMsg.nonce, NONCELEN);

                if (header.srcId < header.destId) {
                    insertNode(head, alldrone[destId].id, authMsg.nonce, NULL,
                               0, 0, 0);

                } else {
                    insertNode(head, alldrone[destId].id, NULL, authMsg.nonce,
                               0, 0, 0);
                }
                // printf("start_time: %ld\n", clock());

                sendPaddingMsgThread(cfd, (void*)&authMsg, sizeof(authMsg), 0x1,
                                     alldrone[destId].IP,
                                     alldrone[destId].PORT);
                printf("Send authMsg to drone-%d!\n", destId);

            } else if (p != NULL && p->flag != 1 && p->index == 0) {
                unsigned char nonce[NONCELEN];
                memset(nonce, 0, NONCELEN);
                rand_bytes(nonce, NONCELEN);
                AuthenticationMsg authMsg = {0};
                MessageHeader header = {0};
                header.srcId = myId;
                header.destId = destId;

                generateAuthMessage(&authMsg, 0x1, &header, nonce, NULL);

                printf("mynonce is: ");
                print_char_arr(authMsg.nonce, NONCELEN);

                if (header.srcId < header.destId) {
                    memset(p->nonce1, 0, NONCELEN);
                    mystrncpy(p->nonce1, authMsg.nonce, NONCELEN);
                }

                else {
                    memset(p->nonce2, 0, NONCELEN);
                    mystrncpy(p->nonce2, authMsg.nonce, NONCELEN);
                }

                sendPaddingMsgThread(cfd, (void*)&authMsg, sizeof(authMsg), 0x1,
                                     alldrone[destId].IP,
                                     alldrone[destId].PORT);
                printf("Send Auth msg to drone-%d!\n", destId);
            }

            else {
                break;
            }
        }
    }
    printf(
        "=============================TEST END!!! I am drone-%d=============================\n",
        myId);
}

void testSm4Time(int keyLen, int msgLen) {
    printf("keyLen: %d\n", keyLen);
    __uint8_t* key = (__uint8_t*)malloc(keyLen);
    __uint8_t* msg = (__uint8_t*)malloc(msgLen);
    __uint8_t* ciphertext = (__uint8_t*)malloc(msgLen);
    int i = 0;
    printf("start_time: %ld\n", clock());
    for (i = 0; i < 10; i++) {
        memset(key, 0, keyLen);
        memset(msg, 0, msgLen);
        memset(ciphertext, 0, msgLen);
        rand_bytes(key, keyLen);
        rand_bytes(msg, msgLen);
        printf("plantext: ");
        print_char_arr(msg, msgLen);
        my_sm4_cbc_encrypt(key, gV->allDrone[gV->myId].Sm4_iv, msg, msgLen,
                           ciphertext, 0);
        printf("ciphertext: ");
        print_char_arr(ciphertext, msgLen);
        memset(msg, 0, msgLen);
        my_sm4_cbc_decrypt(key, gV->allDrone[gV->myId].Sm4_iv, ciphertext,
                           msgLen, msg, 0);
        printf("decode_text: ");
        print_char_arr(msg, msgLen);
    }
    printf("end_time: %ld\n", clock());
    free(key);
    free(msg);
    free(ciphertext);
}

// 测试HMAC耗时
void testHmacTime(int keyLen, int msgLen) {
    printf("keyLen: %d\n", keyLen);
    __uint8_t* key = (__uint8_t*)malloc(keyLen);
    __uint8_t* msg = (__uint8_t*)malloc(msgLen);
    __uint8_t hmac[32];
    int i = 0;
    printf("start_time: %ld\n", clock());
    for (i = 0; i < 10; i++) {
        memset(key, 0, keyLen);
        memset(msg, 0, msgLen);
        memset(hmac, 0, 32);
        rand_bytes(key, keyLen);
        rand_bytes(msg, msgLen);
        printf("plantext: ");
        print_char_arr(msg, msgLen);
        my_sm3_hmac(key, keyLen, msg, msgLen, hmac);
        printf("hmac: ");
        print_char_arr(hmac, 32);
    }
    printf("end_time: %ld\n", clock());
    free(msg);
    free(key);
}

// 测试挑战-应答时间
void testCRTime(int cfd, Drone* alldrone, char myId, AuthNode* head,
                int droneNum) {
    printf(
        "=============================START TEST!!! I am drone-%d=============================\n",
        myId);
    if (myId != 1) { return; }
    int destId = myId, i;
    unsigned char nonce[NONCELEN];
    AuthNode* p = NULL;
    AuthenticationMsg authMsg = {0};

    MessageHeader header = {0};
    header.srcId = myId;
    header.destId = destId;

    generateAuthMessage(&authMsg, 0x1, &header, nonce, NULL);

    for (i = 0; i < droneNum - 1; i++) {
        destId++;
        if (destId != 0) {
            while (1) {
                p = searchList(head, destId);

                if (p == NULL) { // 未发起过认证
                    memset(nonce, 0, NONCELEN);
                    rand_bytes(nonce, NONCELEN);
                    memset(&authMsg, 0, sizeof(authMsg));
                    MessageHeader header = {0};
                    header.srcId = myId;
                    header.destId = destId;

                    generateAuthMessage(&authMsg, 0x1, &header, nonce, NULL);

                    printf("mynonce is: ");
                    print_char_arr(authMsg.nonce, NONCELEN);

                    if (header.srcId < header.destId) {
                        insertNode(head, alldrone[destId].id, authMsg.nonce,
                                   NULL, 0, 0, 0);
                    } else {
                        insertNode(head, alldrone[destId].id, NULL,
                                   authMsg.nonce, 0, 0, 0);
                    }

                    sendPaddingMsgThread(cfd, (void*)&authMsg, sizeof(authMsg),
                                         0x1, alldrone[destId].IP,
                                         alldrone[destId].PORT);
                    printf("start_time: %ld\n", clock());
                    printf("Send Auth msg to drone-%d!\n", destId);

                }

                else if (p->flag != 1 && p->index == 0) { // 对方没收到

                    unsigned char nonce[NONCELEN];
                    memset(nonce, 0, NONCELEN);
                    rand_bytes(nonce, NONCELEN);
                    memset(&authMsg, 0, sizeof(authMsg));
                    MessageHeader header = {0};
                    header.srcId = myId;
                    header.destId = destId;

                    generateAuthMessage(&authMsg, 0x1, &header, nonce, NULL);

                    printf("mynonce is: ");
                    print_char_arr(authMsg.nonce, NONCELEN);

                    if (header.srcId < header.destId) {
                        memset(p->nonce1, 0, NONCELEN);
                        mystrncpy(p->nonce1, authMsg.nonce, NONCELEN);

                    } else {
                        memset(p->nonce2, 0, NONCELEN);
                        mystrncpy(p->nonce2, authMsg.nonce, NONCELEN);
                    }

                    sendPaddingMsgThread(cfd, (void*)&authMsg, sizeof(authMsg),
                                         0x1, alldrone[destId].IP,
                                         alldrone[destId].PORT);
                    printf("start_time: %ld\n", clock());
                    printf("Send Auth msg to drone-%d!\n", destId);

                } else { // 对方已收到
                    break;
                }
                sleep(2);
            }
        }
        sleep(1);
    }
    printf(
        "=============================TEST END!!! I am drone-%d=============================\n",
        myId);
}

// 测试无信任传递群组建立时间
void testOriginGroupCreateTime(int cfd, Drone* alldrone, char myId,
                               AuthNode* head, int droneNum) {
    printf(
        "=============================START TEST!!! I am drone-%d=============================\n",
        myId);
    int destId = myId, i;
    unsigned char nonce[NONCELEN];
    AuthNode* p = NULL;
    AuthenticationMsg authMsg = {0};
    MessageHeader header = {0};

    for (i = 0; i < droneNum - 1; i++) {
        destId++;
        if (destId != 0 && destId <= droneNum) {
            while (1) {
                p = searchList(head, destId);
                if (p == NULL) { // 未发起过认证
                    memset(nonce, 0, NONCELEN);
                    rand_bytes(nonce, NONCELEN);
                    memset(&authMsg, 0, sizeof(authMsg));

                    header.srcId = myId;
                    header.destId = destId;

                    generateAuthMessage(&authMsg, 0x1, &header, nonce, NULL);

                    printf("mynonce is: ");
                    print_char_arr(authMsg.nonce, NONCELEN);

                    if (header.srcId < header.destId) {
                        insertNode(head, alldrone[destId].id, authMsg.nonce,
                                   NULL, 0, 0, 0);
                    } else {
                        insertNode(head, alldrone[destId].id, NULL,
                                   authMsg.nonce, 0, 0, 0);
                    }
                    sendPaddingMsgThread(cfd, (void*)&authMsg, sizeof(authMsg),
                                         0x1, alldrone[destId].IP,
                                         alldrone[destId].PORT);
                    printf("start_time: %ld\n", clock());
                    printf("Send Auth msg to drone-%d!\n", destId);
                }

                else if (p->flag != 1 && p->index == 0) { // 对方没收到

                    unsigned char nonce[NONCELEN];
                    memset(nonce, 0, NONCELEN);
                    rand_bytes(nonce, NONCELEN);
                    memset(&authMsg, 0, sizeof(authMsg));
                    MessageHeader header = {0};
                    header.srcId = myId;
                    header.destId = destId;

                    generateAuthMessage(&authMsg, 0x1, &header, nonce, NULL);

                    printf("mynonce is: ");
                    print_char_arr(authMsg.nonce, NONCELEN);

                    if (header.srcId < header.destId) {
                        memset(p->nonce1, 0, NONCELEN);
                        mystrncpy(p->nonce1, authMsg.nonce, NONCELEN);

                    }

                    else {
                        memset(p->nonce2, 0, NONCELEN);
                        mystrncpy(p->nonce2, authMsg.nonce, NONCELEN);
                    }

                    sendPaddingMsgThread(cfd, (void*)&authMsg, sizeof(authMsg),
                                         0x1, alldrone[destId].IP,
                                         alldrone[destId].PORT);
                    printf("start_time: %ld\n", clock());
                    printf("Send Auth msg to drone-%d!\n", destId);
                }

                else { // 对方已收到
                    break;
                }
                sleep(2);
            }
        }
        sleep(1);
    }
    printf(
        "=============================TEST END!!! I am drone-%d=============================\n",
        myId);
}

void testHashChain(char id) {
    unsigned char res1[32];
    unsigned char res2[32];
    unsigned char res3[32];
    my_sm3(gV->allDrone[id].hashChainKey, 32, res1);
    my_sm3(res1, 32, res2);
    getHashChain(gV->allDrone[id].hashChainKey, 32, 10, res3);
    printf("res1:");
    print_char_arr(res1, 32);
    printf("res2:");
    print_char_arr(res2, 32);
    printf("res3:");
    print_char_arr(res3, 32);
}