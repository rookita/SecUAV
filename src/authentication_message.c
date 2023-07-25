#include "../include/authentication_message.h"

/**
 * @brief 生成认证消息
 *
 * @param authMsg 认证消息地址
 * @param index
 * @param header
 * @param nonce
 * @param hmac
 */
void generateAuthMessage(AuthenticationMsg* authMsg, char index,
                         MessageHeader* header, __uint8_t* nonce,
                         __uint8_t* hmac) {
    authMsg->index = index;
    authMsg->header.srcId = header->srcId;
    authMsg->header.destId = header->destId;

    if (nonce != NULL) mystrncpy(authMsg->nonce, nonce, NONCELEN);

    if (hmac != NULL) mystrncpy(authMsg->hmac, hmac, 32);
}

/**
 * @brief 向网络层发送认证消息
 *
 * @param authMsg
 * @param DestIP
 * @param DestPort
 * @param msgLen
 */
void sendAuthMessage(AuthenticationMsg* authMsg, unsigned char* DestIP,
                     int DestPort, int msgLen) {
    sendPaddingMsgThread(gV->cfd, (void*)authMsg, msgLen, 0x1, DestIP,
                         DestPort); // 0x1表示authMsg的类型
}

/**
 * @brief 打印认证消息
 *
 * @param authMsg
 */
void printAuthenticationMsg(AuthenticationMsg* authMsg) {
    printf("index : %d\n", authMsg->index);
    printf("srcId : %d\n", authMsg->header.srcId);
    printf("destId : %d\n", authMsg->header.destId);
    printf("nonce : ");
    print_char_arr(authMsg->nonce, NONCELEN);
    printf("hmac : ");
    print_char_arr(authMsg->hmac, 32);
}

/**
 * @brief 发起对无人机的认证
 *
 * @param index
 * @param destId
 * @param nonce
 * @param repeat 判断是否是首次发送
 * @return ** void
 */
void auth(char index, char destId, __uint8_t* nonce, char repeat) {
    char myId = gV->myId;
    MessageHeader header = {0};
    header.srcId = myId;
    header.destId = destId;

    AuthenticationMsg authMsg = {0};

    if (index == 0) {
        generateAuthMessage(&authMsg, index, &header, nonce, NULL);
        // 首次发送，需在认证状态表中插入
        if (repeat == 0) {
            insertNode(gV->head, gV->allDrone[destId].id, authMsg.nonce, NULL,
                       0, 0, 0);
        }

        printf("will send authMsg: \n");
        printAuthenticationMsg(&authMsg);
    }

    else if (index == 1 || index == 2) {
        __uint8_t mbuf[34];
        memset(mbuf, 0, 2 * NONCELEN + 2);
        AuthNode* node = searchList(gV->head, destId);
        if (node == NULL) {
            printf("error\n");
            return;
        }

        if (myId < destId) {
            mystrncat(mbuf, &authMsg.header.srcId, 0, 1);
            mystrncat(mbuf, &authMsg.header.destId, 1, 1);
            mystrncat(mbuf, node->nonce1, 2, NONCELEN);
            mystrncat(mbuf, node->nonce2, 2 + NONCELEN, NONCELEN);
            mystrncpy(authMsg.nonce, node->nonce1, NONCELEN);
        }
        authMsg.header = header;
        if (index == 1)
            authMsg.index = 1;
        else
            authMsg.index = 2;
        my_sm3_hmac(gV->allDrone[gV->myId].hmac_key, KEYLEN, mbuf,
                    sizeof(*mbuf), authMsg.hmac);
    }

    else if (index == 3) {
        __uint8_t m[2 * NONCELEN];
        AuthNode* node = searchList(gV->head, destId);

        if (node == NULL) {
            printf("error\n");
            return;
        }

        mystrncat(m, node->nonce1, 0, NONCELEN);
        mystrncat(m, node->nonce2, NONCELEN, NONCELEN);
        generateAuthMessage(&authMsg, 0x3, &header, NULL, NULL);

        my_sm4_cbc_encrypt(node->sessionkey1, gV->allDrone[gV->myId].Sm4_iv, m,
                           2 * NONCELEN, authMsg.hmac, gV->Debug);
    }

    sendPaddingMsgThread(gV->cfd, (void*)&authMsg, sizeof(authMsg), 0x1,
                         gV->allDrone[destId].IP, gV->allDrone[destId].PORT);
}
/**
 * @brief 对收到的认证消息进行处理
 *
 * @param originMsg
 */
void receiveAuthMessage(void* originMsg) {
    AuthenticationMsg authMsg = {0};

    removeMessageType(originMsg, &authMsg, sizeof(authMsg));

    if (authMsg.header.destId == gV->myId) {
        if (gV->Debug) {
            printf("[info]>>>recive msg \n");
            printAuthenticationMsg(&authMsg);
        }
        AuthNode* node = NULL;
        switch (authMsg.index) {
        case 0: // 收到认证消息
            if (gV->Debug)
                printf("##########CASE ONE DEBUG INFO START##########\n");

            node = searchList(gV->head, authMsg.header.srcId);
            if (node != NULL) { return; } // 收到重复消息，直接舍弃
            __uint8_t nonce[NONCELEN];
            __uint8_t mbuf[34];
            __uint8_t hmac[32];
            memset(nonce, 0, NONCELEN); // 生成回应的随机数
            memset(mbuf, 0, 2 * NONCELEN + 2);
            memset(hmac, 0, 32);

            rand_bytes(nonce, NONCELEN);

            node =
                insertNode(gV->head, authMsg.header.srcId, NULL, authMsg.nonce,
                           0, 1, 0); // 其他无人机随机数为nonce2
            mystrncpy(node->nonce1, nonce, NONCELEN); // 自己随机数为nonce1
            mystrncat(mbuf, &authMsg.header.srcId, 0,
                      1); // otherId || myId || myNonce || otherNonce
            mystrncat(mbuf, &authMsg.header.destId, 1, 1);
            mystrncat(mbuf, node->nonce1, 2, NONCELEN);
            mystrncat(mbuf, node->nonce2, 2 + NONCELEN, NONCELEN);

            my_sm3_hmac(gV->allDrone[gV->myId].hmac_key, 16, mbuf,
                        2 * NONCELEN + 2, hmac);
            if (gV->Debug) {
                printf("[info]>>mbuf:  ");
                print_char_arr(mbuf, 2 * NONCELEN + 2);
                printf("hmac: ");
                print_char_arr(hmac, 32);
            }
            AuthenticationMsg myAuthMsg = {0};
            MessageHeader header = {0};
            header.srcId = authMsg.header.destId;
            header.destId = authMsg.header.srcId;

            generateAuthMessage(&myAuthMsg, 0x1, &header, nonce, hmac);

            if (gV->Debug) {
                printf("[info]>>>will send msg \n");
                printAuthenticationMsg(&myAuthMsg);
            }

            sendPaddingMsgThread(gV->cfd, (void*)&myAuthMsg, sizeof(myAuthMsg),
                                 0x1, gV->allDrone[authMsg.header.srcId].IP,
                                 gV->allDrone[authMsg.header.srcId].PORT);
            // free(nonce2);free(mbuf);free(hmac);
            if (gV->Debug)
                printf("##########CASE ONE DEBUG INFO END##########\n");
            break;

        case 1: // 验证hmac,发送自己生成的hmac
            if (gV->Debug)
                printf("##########CASE TWO DEBUG INFO START##########\n");

            node = searchList(gV->head, authMsg.header.srcId);

            if (node != NULL) {
                __uint8_t* mbuf = (__uint8_t*)malloc(2 * NONCELEN + 2);
                __uint8_t* hmac = (__uint8_t*)malloc(32);
                memset(mbuf, 0, 2 * NONCELEN + 2);
                memset(hmac, 0, 32);

                mystrncpy(node->nonce2, authMsg.nonce, NONCELEN);

                mystrncat(mbuf, &authMsg.header.destId, 0, 1);
                mystrncat(mbuf, &authMsg.header.srcId, 1, 1);
                mystrncat(mbuf, node->nonce2, 2, NONCELEN);
                mystrncat(mbuf, node->nonce1, 2 + NONCELEN, NONCELEN);

                my_sm3_hmac(gV->allDrone[gV->myId].hmac_key, 16, mbuf,
                            2 * NONCELEN + 2, hmac);

                if (isEqual(authMsg.hmac, hmac, 32)) { // 验证通过
                    memset(mbuf, 0, 2 * NONCELEN + 2);
                    memset(hmac, 0, 32);

                    if (gV->Debug) printf("[info]>>> case2 hmac right\n");

                    node->flag = 1;

                    mystrncat(mbuf, &authMsg.header.destId, 0, 1);
                    mystrncat(mbuf, &authMsg.header.srcId, 1, 1);
                    mystrncat(mbuf, node->nonce1, 2, NONCELEN);
                    mystrncat(mbuf, node->nonce2, 2 + NONCELEN, NONCELEN);

                    my_sm3_hmac(gV->allDrone[gV->myId].hmac_key, 16, mbuf,
                                2 * NONCELEN + 2, hmac);

                    if (gV->Debug) {
                        printf("mbuf: ");
                        print_char_arr(mbuf, 34);
                        printf("id1: %d\n", authMsg.header.destId);
                        printf("id2: %d\n", authMsg.header.srcId);
                        printf("nonce1: ");
                        print_char_arr(node->nonce1, NONCELEN);
                        printf("nonce2: ");
                        print_char_arr(node->nonce2, NONCELEN);
                        printf("hmac: ");
                        print_char_arr(hmac, 32);
                    }

                    AuthenticationMsg myAuthMsg = {0};
                    MessageHeader header = {0};
                    header.srcId = authMsg.header.destId;
                    header.destId = authMsg.header.srcId;

                    generateAuthMessage(&myAuthMsg, 0x2, &header, NULL, hmac);
                    generate_session_key(gV->allDrone[gV->myId].hmac_key,
                                         node->sessionkey1, node->nonce1,
                                         node->nonce2, NONCELEN);
                    generate_session_key(gV->allDrone[gV->myId].hmac_key,
                                         node->sessionkey2, node->nonce2,
                                         node->nonce1, NONCELEN);

                    node->index = 2;

                    if (gV->Debug) {
                        printf("[info]>>>will send auth msg: \n");
                        printAuthenticationMsg(&myAuthMsg);
                    }

                    sendPaddingMsgThread(
                        gV->cfd, (void*)&myAuthMsg, sizeof(myAuthMsg), 0x1,
                        gV->allDrone[(int)(authMsg.header.srcId)].IP,
                        gV->allDrone[(int)(authMsg.header.srcId)].PORT);
                }

                else {
                    printf("[info]>>>case1 hmac is not equal!\n");
                    printf("[info]>>>compute_hmac is ");
                    print_char_arr(hmac, 32);
                    printf("[info]>>>recive_hmac is ");
                    print_char_arr(authMsg.hmac, 32);
                    deleteNode(gV->head, node);
                }

                free(mbuf);
                free(hmac);

            }

            else {
                printf("[info]>>Dont found the id\n");
            }

            if (gV->Debug)
                printf("##########CASE TWO DEBUG INFO END##########\n");
            break;

        case 2: // 查找table,验证hamc

            AuthNode* p3 = searchList(gV->head, authMsg.header.srcId);

            if (gV->Debug)
                printf("##########CASE THREE DEBUG INFO START##########\n");

            if (p3 != NULL) {
                __uint8_t* mbuf = (__uint8_t*)malloc(2 * NONCELEN + 2);
                __uint8_t* hmac = (__uint8_t*)malloc(32);
                memset(mbuf, 0, 2 * NONCELEN + 2);
                memset(hmac, 0, 32);

                mystrncat(mbuf, &authMsg.header.srcId, 0, 1);
                mystrncat(mbuf, &authMsg.header.destId, 1, 1);
                mystrncat(mbuf, p3->nonce2, 2, NONCELEN);
                mystrncat(mbuf, p3->nonce1, 2 + NONCELEN, NONCELEN);

                my_sm3_hmac(gV->allDrone[gV->myId].hmac_key, 16, mbuf,
                            2 * NONCELEN + 2, hmac);

                if (isEqual(authMsg.hmac, hmac, 32)) { // 验证通过
                    if (gV->Debug) { printf("[info]>>> case3 hmac right\n"); }

                    generate_session_key(gV->allDrone[gV->myId].hmac_key,
                                         p3->sessionkey1, p3->nonce1,
                                         p3->nonce2, NONCELEN);
                    generate_session_key(gV->allDrone[gV->myId].hmac_key,
                                         p3->sessionkey2, p3->nonce2,
                                         p3->nonce1, NONCELEN);

                    p3->flag = 1;
                    // printf("end_time: %ld\n", clock());
                    p3->index = 3;
                    p3->direct = 1;

                    printf("drone-%d auth success!\n", authMsg.header.srcId);

                    __uint8_t m[2 * NONCELEN];
                    memset(m, 0, 2 * NONCELEN);
                    AuthenticationMsg myAuthMsg = {0};
                    MessageHeader header = {0};
                    header.srcId = authMsg.header.destId;
                    header.destId = authMsg.header.srcId;

                    mystrncat(m, p3->nonce1, 0, NONCELEN);
                    mystrncat(m, p3->nonce2, NONCELEN, NONCELEN);
                    generateAuthMessage(&myAuthMsg, 0x3, &header, NULL, NULL);

                    my_sm4_cbc_encrypt(p3->sessionkey1,
                                       gV->allDrone[gV->myId].Sm4_iv, m,
                                       2 * NONCELEN, myAuthMsg.hmac, gV->Debug);
                    if (gV->Debug) {
                        printf("[info]>>>will send auth msg: \n");
                        printAuthenticationMsg(&myAuthMsg);
                    }

                    sendPaddingMsgThread(
                        gV->cfd, (void*)&myAuthMsg, sizeof(myAuthMsg), 0x1,
                        gV->allDrone[(int)(authMsg.header.srcId)].IP,
                        gV->allDrone[(int)(authMsg.header.srcId)].PORT);

                    if (gV->Debug) {
                        printf("[info]>> auth table \n");
                        printAuthtable(gV->head, 0);
                    }

                    printAuthtable(gV->head, 1);
                    printf("end_time: %ld\n", clock());
                    nonceShare(p3, 0, -1);
                } else {
                    printf("[info]>>>case3 hmac is not equal!\n");
                    printf("[info]>>>compute_hmac is ");
                    print_char_arr(hmac, 32);
                    printf("[info]>>>recive_hmac is ");
                    print_char_arr(authMsg.hmac, 32);

                    if (gV->Debug) {
                        printf("mbuf: ");
                        print_char_arr(mbuf, 34);
                        printf("id1: %d\n", authMsg.header.srcId);
                        printf("id2: %d\n", authMsg.header.destId);
                        printf("nonce1: ");
                        print_char_arr(p3->nonce1, NONCELEN);
                        printf("nonce2: ");
                        print_char_arr(p3->nonce2, NONCELEN);
                        printf("hmac: ");
                        print_char_arr(hmac, 32);
                    }
                    deleteNode(gV->head, p3);
                }
                free(mbuf);
                free(hmac);
            } else {
                printf("[info]>>Dont found the id\n");
            }
            printf("##########CASE THREE DEBUG INFO END##########\n");
            break;

        case 3:
            AuthNode* p4 = searchList(gV->head, authMsg.header.srcId);

            if (gV->Debug)
                printf("##########CASE FOUR DEBUG INFO START##########\n");

            if (p4 != NULL) {
                __uint8_t* decrypted_m = (__uint8_t*)malloc(2 * NONCELEN);
                memset(decrypted_m, 0, 2 * NONCELEN);
                __uint8_t* m = (__uint8_t*)malloc(2 * NONCELEN);
                memset(m, 0, 2 * NONCELEN);
                mystrncat(m, p4->nonce2, 0, NONCELEN);
                mystrncat(m, p4->nonce1, NONCELEN, NONCELEN);
                my_sm4_cbc_decrypt(p4->sessionkey2,
                                   gV->allDrone[gV->myId].Sm4_iv, authMsg.hmac,
                                   2 * NONCELEN, decrypted_m, gV->Debug);

                if (strncmp(m, decrypted_m, 2 * NONCELEN) == 0) { // 相等
                    p4->flag = 1;
                    // printf("end_time: %ld\n", clock());
                    p4->direct = 1;
                    p4->index = 4;

                    printf("drone-%d auth success!\n", authMsg.header.srcId);
                    printAuthtable(gV->head, 1);
                    printf("end_time: %ld\n", clock());

                    nonceShare(p4, 0, -1);
                    if (gV->Debug) {
                        printf("[info]>> auth table is \n");
                        printAuthtable(gV->head, 0);
                    }
                }

                else {
                    printf("case3 not equal!\n");
                    printf("m: ");
                    print_char_arr(m, 2 * NONCELEN);
                    printf("decrypted_m: ");
                    print_char_arr(decrypted_m, 2 * NONCELEN);
                }

                free(m);
                free(decrypted_m);
            }
            if (gV->Debug)
                printf("##########CASE FOUR DEBUG INFO END##########\n");
            break;
        }
    }
}