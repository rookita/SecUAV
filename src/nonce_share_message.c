#include "../include/nonce_share_message.h"

/**
 * @brief 生成随机数分享消息
 *
 * @param shareMsg
 * @param shareId
 * @param header
 * @param yourNonce
 * @param shareNonce
 */
void generateShareMessage(NonceShareMsg* shareMsg, char shareId,
                          MessageHeader* header, __uint8_t* yourNonce,
                          __uint8_t* shareNonce) {
    shareMsg->shareId[0] = shareId;
    shareMsg->shareNum = 1;
    shareMsg->header.srcId = header->srcId;
    shareMsg->header.destId = header->destId;
    mystrncpy(shareMsg->yourNonce, yourNonce, NONCELEN);
    mystrncpy(shareMsg->shareNonce, shareNonce, NONCELEN);
}

/**
 * @brief 向网络层发送随机数分享消息
 *
 * @param shareMsg
 * @param msgLen
 * @param DestIP
 * @param DestPort
 * @param Sm4_key
 */
void sendShareMessage(NonceShareMsg* shareMsg, size_t msgLen,
                      unsigned char* DestIP, int DestPort, __uint8_t* Sm4_key) {
    size_t clen = msgLen + 16 - msgLen % 16;
    __uint8_t ciphertext[clen];

    memset(ciphertext, 0, clen);

    my_sm4_cbc_padding_encrypt(Sm4_key, Sm4_iv, (__uint8_t*)shareMsg, msgLen,
                               ciphertext, &clen, gV->Debug);
    // printf("clen: %ld\n", clen);

    MessageHeader header = shareMsg->header;
    int headerLen = sizeof(header);

    __uint8_t msg[clen + headerLen];

    memset(msg, 0, clen + headerLen);

    addBytes(msg, (void*)ciphertext, clen, (__uint8_t*)&header, headerLen);

    sendPaddingMsgThread(gV->cfd, (void*)msg, clen + headerLen, 0x2, DestIP,
                         DestPort);
}

/**
 * @brief 打印随机数分享消息
 *
 * @param shareMsg
 */
void printNonceShareMsg(NonceShareMsg* shareMsg) {
    printf("shareId: ");
    print_char_arr(shareMsg->shareId, DRONENUM);
    printf("yourNonce: ");
    print_char_arr(shareMsg->yourNonce, NONCELEN);
    printf("nonce2: ");
    print_char_arr(shareMsg->shareNonce, DRONENUM * NONCELEN);
    printf("num: %ld\n", shareMsg->shareNum);
}

/**
 * @brief 进行随机数分享过程
 *
 * @param p
 * @param type
 * @param dont_share
 */
void nonceShare(AuthNode* p, char type, char dont_share) {
    AuthNode* node = gV->head->next;
    NonceShareMsg shareMsgToNode, shareMsgToP = {0};
    MessageHeader header = {0};

    char myId = gV->myId;
    header.srcId = myId;
    header.destId = p->id;
    shareMsgToP.header = header;

    if (type == 0) { // 是否对p分享

        int i = 0;
        if (p->id < myId) {
            mystrncpy(shareMsgToP.yourNonce, p->nonce1, NONCELEN);
        }

        else {
            mystrncpy(shareMsgToP.yourNonce, p->nonce2, NONCELEN);
        }

        while (node != NULL) {
            if (node != p && node->flag == 1 && node->id != dont_share) {
                shareMsgToP.shareId[i] = node->id;
                if (node->id < myId) {
                    mystrncat(shareMsgToP.shareNonce, node->nonce1,
                              i * NONCELEN, NONCELEN);
                } else {
                    mystrncat(shareMsgToP.shareNonce, node->nonce2,
                              i * NONCELEN, NONCELEN);
                }
                i++;
            }

            node = node->next;
        }

        shareMsgToP.shareNum = i;
        // 分享给刚认证的节点
        // printNonceShareMsg(&shareMsgToP);
        if (i != 0) {
            sendShareMessage(&shareMsgToP, sizeof(shareMsgToP),
                             gV->allDrone[p->id].IP, gV->allDrone[p->id].PORT,
                             p->sessionkey);
            printf("Send Share Msg to drone-%d\n", p->id);
        }
    }

    node = gV->head->next;
    // 给其他节点分享p

    while (node != NULL) {
        if (node != p && node->flag == 1 && node->direct == 1
            && node->id != dont_share) { // 对其他节点分享刚认证节点
            memset(&shareMsgToNode, sizeof(shareMsgToNode), 0);

            MessageHeader header = {0};
            header.srcId = myId;
            header.destId = node->id;

            if (node->id < myId && p->id < myId) {
                generateShareMessage(&shareMsgToNode, p->id, &header,
                                     node->nonce1, p->nonce1); // 发送给node
            } else if (node->id < myId && p->id > myId) {
                generateShareMessage(&shareMsgToNode, p->id, &header,
                                     node->nonce1, p->nonce2); // 发送给node
            } else if (node->id > myId && p->id < myId) {
                generateShareMessage(&shareMsgToNode, p->id, &header,
                                     node->nonce2, p->nonce1); // 发送给node
            } else if (node->id > myId && p->id > myId) {
                generateShareMessage(&shareMsgToNode, p->id, &header,
                                     node->nonce2, p->nonce2); // 发送给node
            }
            sendShareMessage(&shareMsgToNode, sizeof(shareMsgToNode),
                             gV->allDrone[node->id].IP,
                             gV->allDrone[node->id].PORT, node->sessionkey);

            printf("Send Share Msg to drone-%d\n", node->id);
        }
        // 对刚认证节点分享已认证其他节点

        node = node->next;
    }
}
/**
 * @brief 对收到的随机数分享消息进行处理
 *
 * @param msg
 */
void receiveShareMessage(void* msg) {
    NonceShareMsg shareMsg = {0};
    char myId = gV->myId;
    int shareMsgLen = sizeof(shareMsg);
    int headerLen = sizeof(MessageHeader);
    size_t clen = shareMsgLen + 16 - shareMsgLen % 16;
    __uint8_t* ciphertext = (__uint8_t*)malloc(clen);

    memset(ciphertext, 0, clen);
    __uint8_t tmp[shareMsgLen + headerLen];
    memset(ciphertext, 0, clen);
    memset(tmp, 0, shareMsgLen + headerLen);

    __uint8_t* h = (__uint8_t*)malloc(headerLen);
    memset(h, 0, headerLen);

    removeMessageType(msg, tmp, clen + headerLen);

    memmove((void*)h, tmp, headerLen);
    memmove((void*)ciphertext, tmp + headerLen, clen);
    MessageHeader* header = (MessageHeader*)h;

    if (gV->Debug) {
        printf("nonceShareMsg : ");
        print_char_arr(tmp, clen + headerLen);
        printf("ciphertext : ");
        print_char_arr(ciphertext, clen);
        printf("srcId: %d\n", header->srcId);
        printf("destId: %d\n", header->destId);
    }

    AuthNode* p = searchList(gV->head, header->srcId);
    AuthNode* pp = p;

    if (p == NULL) {
        printf("Dont find the id\n");
        return;
    }

    if (p->flag != 1) {
        printf("have not authed\n");
        return;
    }
    size_t mlen = 0;
    my_sm4_cbc_padding_decrypt(p->sessionkey, Sm4_iv, ciphertext, clen,
                               (__uint8_t*)&shareMsg, &mlen, gV->Debug);

    if (gV->Debug) {
        printf("shareMsg:\n");
        // print_char_arr((__uint8_t*)&shareMsg, clen);
        printNonceShareMsg(&shareMsg);
    }
    int i = 0;
    for (i = 0; i < shareMsg.shareNum; i++) {
        p = searchList(gV->head, shareMsg.shareId[i]);
        if (p != NULL) {
            if (p->flag == 1)

                printf("drone-%d aleardy auth!\n", shareMsg.shareId[i]);

            else {
                memset(p->nonce1, 0, NONCELEN);
                memset(p->nonce2, 0, NONCELEN);

                if (p->id < myId) {
                    mystrncpy(p->nonce1, shareMsg.shareNonce + i * NONCELEN,
                              NONCELEN); // p的nonce
                    mystrncpy(p->nonce2, shareMsg.yourNonce,
                              NONCELEN); // mynonce
                }

                else { // p->id > my_id
                    mystrncpy(p->nonce1, shareMsg.yourNonce, NONCELEN);
                    mystrncpy(p->nonce2, shareMsg.shareNonce + i * NONCELEN,
                              NONCELEN);
                }

                p->flag = 1;
                generate_session_key(p->sessionkey, p->nonce1, p->nonce2,
                                     NONCELEN);
                printf("Recive Share Msg; Authed drone-%d\n",
                       shareMsg.shareId[i]);
                printf("Share drone-%d to Others\n", p->id);
                nonceShare(p, 1, pp->id);
            }
        }

        else {
            if (shareMsg.shareId[i] < myId) {
                p = insertNode(gV->head, shareMsg.shareId[i],
                               shareMsg.shareNonce + i * NONCELEN,
                               shareMsg.yourNonce, 1, -1, 0);
            } else { // p->id > my_id
                p = insertNode(gV->head, shareMsg.shareId[i],
                               shareMsg.yourNonce,
                               shareMsg.shareNonce + i * NONCELEN, 1, -1, 0);
            }
            generate_session_key(p->sessionkey, p->nonce1, p->nonce2, NONCELEN);
            printf("Recive Share Msg; Authed drone-%d\n", shareMsg.shareId[i]);
            printf("Share drone-%d to Others\n", p->id);
            nonceShare(p, 1, pp->id);
        }
    }
    if (gV->Debug) {
        printf("Auth table\n");
        printAuthtable(gV->head, 0);
    }
    printAuthtable(gV->head, 1);
    printf("end_time: %ld\n", clock());
    free(ciphertext);
    free(h);
}