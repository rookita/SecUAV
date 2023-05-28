#include "../include/node_check_message.h"

void generateNodeCheckMsg(NodeCheckMsg* nodeCheckMsg, char index,
                          MessageHeader* header, __uint8_t* newnonce) {
    nodeCheckMsg->index = index;
    nodeCheckMsg->header.srcId = header->srcId;
    nodeCheckMsg->header.destId = header->destId;
    mystrncpy(nodeCheckMsg->newnonce, newnonce, NONCELEN);
}

void printNodeCheckMsg(NodeCheckMsg* nodeCheckMsg) {
    printf("srcId : %d\n", nodeCheckMsg->header.srcId);
    printf("destId: %d\n", nodeCheckMsg->header.destId);
    printf("newnonce: ");
    print_char_arr(nodeCheckMsg->newnonce, NONCELEN);
}
/**
 * @brief 发送节点检测消息
 *
 * @param nodeCheckMsg
 * @param msgLen 消息长度
 * @param DestIP 目标IP地址
 * @param DestPort 目标端口
 * @param Sm4_key 用于加密的密钥
 */
void sendNodeCheckMsg(NodeCheckMsg* nodeCheckMsg, int msgLen,
                      unsigned char* DestIP, int DestPort, __uint8_t* Sm4_key) {
    size_t clen = msgLen + 16 - msgLen % 16;
    __uint8_t ciphertext[clen];
    memset(ciphertext, 0, clen);

    my_sm4_cbc_padding_encrypt(Sm4_key, Sm4_iv, (__uint8_t*)nodeCheckMsg,
                               msgLen, ciphertext, &clen, gV->Debug);
    // printf("clen: %ld\n", clen);

    MessageHeader header;
    header.srcId = nodeCheckMsg->header.srcId;
    header.destId = nodeCheckMsg->header.destId;
    int headerLen = sizeof(MessageHeader);

    __uint8_t msg[clen + headerLen];
    memset(msg, 0, clen + headerLen);
    addBytes(msg, ciphertext, clen, (__uint8_t*)&header, headerLen);
    sendPaddingMsgThread(gV->cfd, (void*)msg, clen + headerLen, 0x3, DestIP,
                         DestPort);
    printf("sendNodeCheckMsg: ");
    print_char_arr(msg, clen + headerLen);
}

/**
 * @brief 对某个特点节点发送节点检测消息
 *
 * @param destId 目标节点IP地址
 */
void nodeCheckToOne(char destId) {
    AuthNode* node = gV->head->next;
    NodeCheckMsg nodeCheckMsg = {0};
    MessageHeader header;
    header.srcId = gV->myId;
    header.destId = destId;

    generateNodeCheckMsg(&nodeCheckMsg, 0x1, &header, updateif->nonce);
    while (node != NULL) {
        if (node->id == destId) {
            sendNodeCheckMsg(&nodeCheckMsg, sizeof(NodeCheckMsg),
                             gV->allDrone[destId].IP, gV->allDrone[destId].PORT,
                             node->sessionkey);
            break;
        }

        node = node->next;
    }

    if (gV->Debug) { printf("send update msg to drone-%d success\n", destId); }
}

/**
 * @brief 节点检测，向认证状态表中所有已认证的节点发送节点检测消息
 *
 * @param response
 */
void nodeCheck(Response* response) {
    cleanTable(gV->head);
    AuthNode* node = gV->head->next;
    NodeCheckMsg nodeCheckMsg = {0};
    __uint8_t nonce[NONCELEN];
    rand_bytes(nonce, NONCELEN);
    memset(updateif->nonce, 0, NONCELEN);
    mystrncpy(updateif->nonce, nonce, NONCELEN);

    MessageHeader header = {0};
    header.srcId = gV->myId;
    header.destId = node->id;

    generateNodeCheckMsg(&nodeCheckMsg, 0x1, &header,
                         nonce); // 触发节点对其他节点使用同一个随机数

    int i = 0;
    // 统计认证状态表个数
    while (node != NULL) {
        if (node->flag == 1) i++;
        node = node->next;
    }
    node = gV->head->next;

    response[0].num = i;

    i = 0;
    while (node != NULL) {
        if (node->flag == 1) { // 已认证节点
            nodeCheckMsg.header.destId = node->id;

            response[i].id = node->id; // 记录接收到的响应
            response[i].isresponsed = 0;
            i++;

            sendNodeCheckMsg(&nodeCheckMsg, sizeof(NodeCheckMsg),
                             gV->allDrone[node->id].IP,
                             gV->allDrone[node->id].PORT, node->sessionkey);

            printf("send update msg to drone-%d\n", node->id);

            if (node->id < header.srcId) { // id小的为nonce1

                memset(node->nonce2, 0, NONCELEN);
                mystrncpy(node->nonce2, nonce, NONCELEN);

            }

            else { // node->id > src_id

                memset(node->nonce1, 0, NONCELEN);
                mystrncpy(node->nonce1, nonce, NONCELEN);
            }
        }
        node = node->next;
    }
    pthread_t id;
    int ret = pthread_create(&id, NULL, listenUpdateResponse, NULL);
    if (-1 == ret) print_err("pthread_create failed", __LINE__, errno);
}
/**
 * @brief 对收到的节点检测消息进行处理
 *
 * @param msg
 */
void receiveNodeCheckMessage(void* msg) {
    NodeCheckMsg nodeCheckMsg = {0};
    int nodeCheckMsgLen = sizeof(NodeCheckMsg);
    int headerLen = sizeof(MessageHeader);
    size_t clen = nodeCheckMsgLen + 16 - nodeCheckMsgLen % 16;
    __uint8_t nonce[NONCELEN];
    __uint8_t* ciphertext = (__uint8_t*)malloc(clen);
    __uint8_t tmp[nodeCheckMsgLen + headerLen];

    memset(ciphertext, 0, clen);
    memset(tmp, 0, nodeCheckMsgLen + headerLen);
    __uint8_t* h = (__uint8_t*)malloc(headerLen);
    memset(h, 0, headerLen);
    printf("nodeCheckMsg : ");
    print_char_arr(msg, clen + headerLen + 1);
    removeMessageType(msg, tmp, clen + headerLen);

    memmove(h, tmp, headerLen);
    memmove(ciphertext, tmp + headerLen, clen);
    MessageHeader* header = (MessageHeader*)h;

    if (gV->Debug) {
        printf("\n");
        printf("nodeCheckMsg : ");
        print_char_arr(tmp, clen + headerLen);
        printf("ciphertext : ");
        print_char_arr(ciphertext, clen);
        printf("srcId: %d\n", header->srcId);
        printf("destId: %d\n", header->destId);
        printf("\n");
    }

    AuthNode* p = searchList(gV->head, header->srcId);

    if (p == NULL) {
        printf("Dont find drone-%d\n", header->srcId);
        return;
    }

    if (p->flag != 1) {
        printf("dreone-%d have not authed\n", p->id);
        return;
    }

    size_t mlen;

    my_sm4_cbc_padding_decrypt(p->sessionkey, Sm4_iv, ciphertext, clen,
                               (__uint8_t*)&nodeCheckMsg, &mlen, gV->Debug);

    if (gV->Debug) {
        printf("\n");
        printf("nodeCheckMsg:\n");
        printNodeCheckMsg(&nodeCheckMsg);
        printf("\n");
    }

    ReceiveUpdate* ru =
        receiveupdate_find(updateif->receiveupdate, header->srcId);

    if (ru == NULL) {
        printf("illegal drone-%d!\n", header->srcId);
    }

    else {
        ru->flag = 1;
    }

    if (nodeCheckMsg.index == 1) {
        p = searchList(gV->head, nodeCheckMsg.header.srcId);

        if (p == NULL) {
            printf("nodeCheck error!\n");
            return;
        }

        NodeCheckMsg responseOfNodeCheckMsg = {0};
        rand_bytes(nonce, NONCELEN);

        char myId = gV->myId;

        // response
        MessageHeader responseHeader = {0};
        responseHeader.srcId = myId;
        responseHeader.destId = header->srcId;
        generateNodeCheckMsg(&responseOfNodeCheckMsg, 0x2, &responseHeader,
                             nonce);
        sendNodeCheckMsg(
            &responseOfNodeCheckMsg, sizeof(responseOfNodeCheckMsg),
            gV->allDrone[responseOfNodeCheckMsg.header.destId].IP,
            gV->allDrone[responseOfNodeCheckMsg.header.destId].PORT,
            p->sessionkey);

        printf("send response update msg to drone-%d\n",
               responseOfNodeCheckMsg.header.destId);

        if (gV->Debug) {
            printf("\n");
            printf("responseOfNodeCheckMsg:\n");
            printNodeCheckMsg(&responseOfNodeCheckMsg);
            printf("\n");
        }

        memset(p->nonce1, 0, NONCELEN);
        memset(p->nonce2, 0, NONCELEN);
        memset(p->sessionkey, 0, NONCELEN);

        if (p->id < myId) {
            mystrncpy(p->nonce1, nodeCheckMsg.newnonce, NONCELEN);
            mystrncpy(p->nonce2, nonce, NONCELEN);
        }

        else {
            mystrncpy(p->nonce1, nonce, NONCELEN);
            mystrncpy(p->nonce2, nodeCheckMsg.newnonce, NONCELEN);
        }

        generate_session_key(p->sessionkey, p->nonce1, p->nonce2, NONCELEN);

        p->flag = 1;
        p->direct = 1;

        printf("drone-%d update success\n", responseHeader.destId);
        printf("new session key is ");
        print_char_arr(p->sessionkey, NONCELEN);

        gV->head->flag += 1;
        // printf("Auth Table:\n");
        // printAuthtable(gV->head, 0);

    }

    else if (nodeCheckMsg.index == 2) { // response
        p = searchList(gV->head, nodeCheckMsg.header.srcId);

        if (p == NULL) {
            printf("nodeCheck error!\n");
            return;
        }

        Response* response =
            response_find(updateif->response, nodeCheckMsg.header.srcId);

        if (response == NULL) {
            printf("response error!\n");
            return;
        }

        response->isresponsed = 1;
        printf("recieve update response message of drone-%d\n",
               nodeCheckMsg.header.srcId);

        if (nodeCheckMsg.header.srcId < nodeCheckMsg.header.destId) {
            memset(p->nonce1, 0, NONCELEN);
            mystrncpy(p->nonce1, nodeCheckMsg.newnonce, NONCELEN);
        }

        else {
            memset(p->nonce2, 0, NONCELEN);
            mystrncpy(p->nonce2, nodeCheckMsg.newnonce, NONCELEN);
        }

        generate_session_key(p->sessionkey, p->nonce1, p->nonce2, NONCELEN);
        p->direct = 1;
        printf("drone-%d update success\n", nodeCheckMsg.header.srcId);
        printf("new session key is ");
        print_char_arr(p->sessionkey, NONCELEN);
        // printf("Auth Table:\n");
        // printAuthtable(gV->head, 0);

        if (response_check(updateif->response)) {
            printf("recived all response. Start Sharing\n");
            printf("end1_time: %ld\n", clock());
            response_init(updateif->response, 10);
            gV->head->flag += 1;

            shareAuthTable();
        }
    }
    free(h);
}
/**
 * @brief 线程函数，监听是否回复
 *
 * @param args
 * @return void*
 */
void* listenUpdateResponse(void* args) {
    int frequency = 100000; // 5秒钟检查一次
    int times = 3;          // 3次过后直接认为该无人机丢失
    UpdateInfo* uinfo = updateif;

    int i = 0, j = 0, flag = 1;

    for (i = 0; i < times; i++) {
        sleep(frequency);
        flag = 1;

        for (j = 0; j < uinfo->response[0].num; j++) {
            if (uinfo->response[j].isresponsed != 1) {
                printf("Resend update msg to drone-%d\n",
                       uinfo->response[j].id);
                nodeCheckToOne(uinfo->response[j].id);
                flag = 0;
            }
        }

        if (flag == 1) { return NULL; }
    }

    for (j = 0; j < uinfo->response[0].num; j++) {
        if (uinfo->response[j].isresponsed != 1) {
            printf("drone-%d lost!\n", uinfo->response[j].id);
        }
    }

    return NULL;
}