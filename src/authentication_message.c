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

        switch (authMsg.index) {
        case 1: // reciver
            if (gV->Debug)
                printf("##########CASE ONE DEBUG INFO START##########\n");

            __uint8_t nonce[NONCELEN];
            __uint8_t mbuf[34];
            __uint8_t hmac[32];
            memset(nonce, 0, NONCELEN);
            memset(mbuf, 0, 2 * NONCELEN + 2);
            memset(hmac, 0, 32);

            rand_bytes(nonce, NONCELEN);

            if (authMsg.header.srcId
                < authMsg.header
                      .destId) { // nonce1-header.srcId,nonce2-header.destId
                AuthNode* node =
                    insertNode(gV->head, authMsg.header.srcId, authMsg.nonce,
                               NULL, 0, 1, 0); // nonce1-srcid

                mystrncpy(node->nonce2, nonce,
                          NONCELEN); // nonce2-header.destId
                mystrncat(mbuf, &authMsg.header.srcId, 0, 1);
                mystrncat(mbuf, &authMsg.header.destId, 1, 1);
                mystrncat(mbuf, node->nonce2, 2, NONCELEN);
                mystrncat(mbuf, node->nonce1, 2 + NONCELEN, NONCELEN);
            }

            else { // header.srcId > header.destId
                AuthNode* node =
                    insertNode(gV->head, authMsg.header.srcId, NULL,
                               authMsg.nonce, 0, 1, 0); // nonce1-header.destId

                mystrncpy(node->nonce1, nonce, NONCELEN); // nonce2-srcid
                mystrncat(mbuf, &authMsg.header.srcId, 0, 1);
                mystrncat(mbuf, &authMsg.header.destId, 1, 1);
                mystrncat(mbuf, node->nonce1, 2, NONCELEN);
                mystrncat(mbuf, node->nonce2, 2 + NONCELEN, NONCELEN);
            }

            if (gV->Debug) {
                printf("[info]>>the mbuf of hmac is ");
                print_char_arr(mbuf, 2 * NONCELEN + 2);
            }

            my_sm3_hmac(hmac_key, sizeof(*hmac_key), mbuf, sizeof(*mbuf), hmac);

            AuthenticationMsg myAuthMsg = {0};
            MessageHeader header = {0};
            header.srcId = authMsg.header.destId;
            header.destId = authMsg.header.srcId;

            generateAuthMessage(&myAuthMsg, 0x2, &header, nonce, hmac);

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

        case 2: // sender
            if (gV->Debug)
                printf("##########CASE TWO DEBUG INFO START##########\n");

            AuthNode* p2 = searchList(gV->head, authMsg.header.srcId);

            if (p2 != NULL) {
                __uint8_t* mbuf = (__uint8_t*)malloc(2 * NONCELEN + 2);
                __uint8_t* hmac = (__uint8_t*)malloc(32);
                memset(mbuf, 0, 2 * NONCELEN + 2);
                memset(hmac, 0, 32);

                if (authMsg.header.srcId < authMsg.header.destId) {
                    mystrncat(mbuf, &authMsg.header.destId, 0, 1);
                    mystrncat(mbuf, &authMsg.header.srcId, 1, 1);
                    mystrncat(mbuf, authMsg.nonce, 2, NONCELEN);
                    mystrncat(mbuf, p2->nonce2, 2 + NONCELEN, NONCELEN);
                    mystrncpy(p2->nonce1, authMsg.nonce, NONCELEN);
                }

                else { // header.destId < srcid
                    mystrncat(mbuf, &authMsg.header.destId, 0, 1);
                    mystrncat(mbuf, &authMsg.header.srcId, 1, 1);
                    mystrncat(mbuf, authMsg.nonce, 2, NONCELEN);
                    mystrncat(mbuf, p2->nonce1, 2 + NONCELEN, NONCELEN);
                    mystrncpy(p2->nonce2, authMsg.nonce, NONCELEN);
                }

                my_sm3_hmac(hmac_key, sizeof(*hmac_key), mbuf, sizeof(*mbuf),
                            hmac);

                if (isEqual(authMsg.hmac, hmac, 32)) { // 验证通过
                    memset(mbuf, 0, 2 * NONCELEN + 2);
                    memset(hmac, 0, 32);

                    if (gV->Debug) printf("[info]>>> case2 hmac right\n");

                    p2->flag = 1;

                    if (authMsg.header.srcId < authMsg.header.destId) {
                        mystrncat(mbuf, &authMsg.header.destId, 0, 1);
                        mystrncat(mbuf, &authMsg.header.srcId, 1, 1);
                        mystrncat(mbuf, p2->nonce2, 2, NONCELEN);
                        mystrncat(mbuf, p2->nonce1, 2 + NONCELEN, NONCELEN);
                    }

                    else { // srcid > header.destId
                        mystrncat(mbuf, &authMsg.header.destId, 0, 1);
                        mystrncat(mbuf, &authMsg.header.srcId, 1, 1);
                        mystrncat(mbuf, p2->nonce1, 2, NONCELEN);
                        mystrncat(mbuf, p2->nonce2, 2 + NONCELEN, NONCELEN);
                    }

                    my_sm3_hmac(hmac_key, sizeof(*hmac_key), mbuf,
                                sizeof(*mbuf), hmac);
                    /*
                    if (gV->Debug){
                      printf("mbuf: ");print_char_arr(mbuf, 34);
                      printf("id1: %d\n", authMsg.header.destId);
                      printf("id2: %d\n", authMsg.srcid);
                      printf("nonce1: ");print_char_arr(p2->mynonce, NONCELEN);
                      printf("nonce2: ");print_char_arr(p2->othernonce,
                    NONCELEN); printf("hmac: ");print_char_arr(hmac, 32);
                    }
                    */
                    AuthenticationMsg myAuthMsg = {0};
                    MessageHeader header = {0};
                    header.srcId = authMsg.header.destId;
                    header.destId = authMsg.header.srcId;

                    generateAuthMessage(&myAuthMsg, 0x3, &header, NULL, hmac);
                    generate_session_key(p2->sessionkey, p2->nonce1, p2->nonce2,
                                         NONCELEN);

                    p2->index = 2;

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
                    printf("[info]>>>case2 hmac is not equal!\n");
                    printf("[info]>>>compute_hmac is ");
                    print_char_arr(hmac, 32);
                    printf("[info]>>>recive_hmac is ");
                    print_char_arr(authMsg.hmac, 32);
                    deleteNode(gV->head, p2);
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

        case 3: // reciver
            // 查找table,验证hamc
            AuthNode* p3 = searchList(gV->head, authMsg.header.srcId);

            if (gV->Debug)
                printf("##########CASE THREE DEBUG INFO START##########\n");

            if (p3 != NULL) {
                __uint8_t* mbuf = (__uint8_t*)malloc(2 * NONCELEN + 2);
                __uint8_t* hmac = (__uint8_t*)malloc(32);
                memset(mbuf, 0, 2 * NONCELEN + 2);
                memset(hmac, 0, 32);

                if (authMsg.header.srcId < authMsg.header.destId) {
                    mystrncat(mbuf, &authMsg.header.srcId, 0, 1);
                    mystrncat(mbuf, &authMsg.header.destId, 1, 1);
                    mystrncat(mbuf, p3->nonce1, 2, NONCELEN);
                    mystrncat(mbuf, p3->nonce2, 2 + NONCELEN, NONCELEN);
                }

                else {
                    mystrncat(mbuf, &authMsg.header.srcId, 0, 1);
                    mystrncat(mbuf, &authMsg.header.destId, 1, 1);
                    mystrncat(mbuf, p3->nonce2, 2, NONCELEN);
                    mystrncat(mbuf, p3->nonce1, 2 + NONCELEN, NONCELEN);
                }

                my_sm3_hmac(hmac_key, sizeof(*hmac_key), mbuf, sizeof(*mbuf),
                            hmac);

                if (isEqual(authMsg.hmac, hmac, 32)) { // 验证通过
                    if (gV->Debug) { printf("[info]>>> hmac right\n"); }

                    generate_session_key(p3->sessionkey, p3->nonce1, p3->nonce2,
                                         NONCELEN);

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
                    generateAuthMessage(&myAuthMsg, 0x4, &header, NULL, NULL);

                    my_sm4_cbc_encrypt(p3->sessionkey, Sm4_iv, m, 2 * NONCELEN,
                                       myAuthMsg.hmac, gV->Debug);
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

        case 4:
            AuthNode* p4 = searchList(gV->head, authMsg.header.srcId);

            if (gV->Debug)
                printf("##########CASE FOUR DEBUG INFO START##########\n");

            if (p4 != NULL) {
                __uint8_t* m = (__uint8_t*)malloc(2 * NONCELEN);
                memset(m, 0, 2 * NONCELEN);
                __uint8_t* mm = (__uint8_t*)malloc(2 * NONCELEN);
                memset(mm, 0, 2 * NONCELEN);
                mystrncat(mm, p4->nonce1, 0, NONCELEN);
                mystrncat(mm, p4->nonce2, NONCELEN, NONCELEN);
                my_sm4_cbc_decrypt(p4->sessionkey, Sm4_iv, authMsg.hmac,
                                   2 * NONCELEN, m, gV->Debug);

                if (strncmp(m, mm, 2 * NONCELEN) == 0) { // 相等
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
                    printf("case4 not equal!\n");
                    printf("m: ");
                    print_char_arr(m, 2 * NONCELEN);
                    printf("mm: ");
                    print_char_arr(mm, 2 * NONCELEN);
                }

                free(m);
                free(mm);
            }
            if (gV->Debug)
                printf("##########CASE FOUR DEBUG INFO END##########\n");
            break;
        }
    }
}