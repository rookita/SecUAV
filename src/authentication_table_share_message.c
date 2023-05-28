#include "../include/authentication_table_share_message.h"
#include "../include/node_check_message.h"
#include "../include/mytime.h"

void printAuthenticationTableShareMsg(
    AuthenticationTableShareMsg* authTableShareMsg) {
    printf("num: %ld\n", authTableShareMsg->num);
    printf("id: ");
    print_char_arr(authTableShareMsg->id, authTableShareMsg->num);
    printf("nonce: ");
    print_char_arr(authTableShareMsg->nonce, authTableShareMsg->num * NONCELEN);
}

void sendAuthTableShareMsg(AuthenticationTableShareMsg* authTableShareMsg,
                           int msgLen, unsigned char* DestIP, int DestPort,
                           __uint8_t* Sm4_key) {
    int authTableShareMsgLen = sizeof(AuthenticationTableShareMsg);
    size_t clen = authTableShareMsgLen + 16 - authTableShareMsgLen % 16;
    int headerLen = sizeof(MessageHeader);
    __uint8_t ciphertext[clen];
    memset(ciphertext, 0, clen);

    my_sm4_cbc_padding_encrypt(Sm4_key, Sm4_iv, (__uint8_t*)authTableShareMsg,
                               msgLen, ciphertext, &clen, gV->Debug);
    MessageHeader header = {0};
    header.srcId = authTableShareMsg->header.srcId;
    header.destId = authTableShareMsg->header.destId;

    __uint8_t msg[clen + headerLen];
    memset(msg, 0, clen + headerLen);

    addBytes(msg, ciphertext, clen, (__uint8_t*)&header, headerLen);

    sendPaddingMsgThread(gV->cfd, (void*)msg, clen + headerLen, 0x4, DestIP,
                         DestPort);
}

void shareAuthTable() {
    AuthenticationTableShareMsg authTableShareMsg = {0};
    int i = 0;
    AuthNode* node = gV->head->next;
    char myId = gV->myId;
    MessageHeader header = {0};
    header.srcId = myId;
    while (node != NULL) {     // 构造消息
        authTableShareMsg.id[i] = node->id;
        if (node->id < myId) { // node的随机数为nonce1
            mystrncat(authTableShareMsg.nonce, node->nonce1, i * NONCELEN,
                      NONCELEN);
        }

        else {
            mystrncat(authTableShareMsg.nonce, node->nonce2, i * NONCELEN,
                      NONCELEN);
        }

        i++;
        node = node->next;
    }

    authTableShareMsg.num = i;
    node = gV->head->next;

    while (node != NULL) { // 发送消息

        header.destId = node->id;
        authTableShareMsg.header = header;
        sendAuthTableShareMsg(&authTableShareMsg, sizeof(authTableShareMsg),
                              gV->allDrone[node->id].IP,
                              gV->allDrone[node->id].PORT, node->sessionkey);
        node = node->next;
    }

    printf("Auth Table Share Success!\n");

    printf("end2_time: %ld\n", clock());

    mysetittimer(updateif->updateinterval,
                 updateif->updateinterval); // 触发节点重置密钥更新时间
}

void receiveAuthTableShareMsg(void* msg) {
    AuthenticationTableShareMsg authTableShareMsg = {0};
    int authTableShareMsgLen = sizeof(AuthenticationTableShareMsg);
    int headerLen = sizeof(MessageHeader);
    size_t clen = authTableShareMsgLen;

    __uint8_t* ciphertext = (__uint8_t*)malloc(clen);
    __uint8_t tmp[authTableShareMsgLen + sizeof(MessageHeader)];
    memset(ciphertext, 0, clen);
    memset(tmp, 0, authTableShareMsgLen + headerLen);
    __uint8_t* h = (__uint8_t*)malloc(headerLen);
    memset(h, 0, headerLen);

    removeMessageType(msg, tmp, clen + headerLen);

    memmove(h, tmp, headerLen);
    memmove(ciphertext, tmp + headerLen, clen);

    MessageHeader* header = (MessageHeader*)h;

    if (gV->Debug) {
        printf("\n");
        printf("authTableShareMsg : ");
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
        printf("have not authed\n");
        return;
    }

    size_t mlen = 0;
    my_sm4_cbc_padding_decrypt(p->sessionkey, Sm4_iv, ciphertext, clen,
                               (__uint8_t*)&authTableShareMsg, &mlen,
                               gV->Debug);

    if (gV->Debug) {
        printf("\n");
        printf("authTableShareMsg:\n");
        printAuthenticationTableShareMsg(&authTableShareMsg);
        printf("\n");
    }

    __uint8_t mynonce[NONCELEN];
    memset(mynonce, 0, NONCELEN);

    if (p->id < gV->allDrone[gV->myId].id) {
        mystrncpy(mynonce, p->nonce2, NONCELEN);

    } else {
        mystrncpy(mynonce, p->nonce1, NONCELEN);
    }

    p = NULL;
    int i = 0;
    char myId = gV->myId;
    char tmp1;

    for (i = 0; i < authTableShareMsg.num; i++) {
        tmp1 = authTableShareMsg.id[i];

        if (tmp1 != myId) { // 不处理自己的nonce
            p = searchList(gV->head, tmp1);

            if (p != NULL) { // 之前认证过
                p->flag = 1;
                p->direct = 0; // 只与发送消息者direct为1，方便后续Share

                if (tmp1 > myId) { // nonce1为我的随机数
                    memset(p->nonce2, 0, NONCELEN);
                    mystrncpy(p->nonce2, authTableShareMsg.nonce + i * NONCELEN,
                              NONCELEN);
                    memset(p->nonce1, 0, NONCELEN);
                    mystrncpy(p->nonce1, mynonce, NONCELEN);
                }

                else if (tmp1 < myId) {
                    memset(p->nonce1, 0, NONCELEN);
                    mystrncpy(p->nonce1, authTableShareMsg.nonce + i * NONCELEN,
                              NONCELEN);
                    memset(p->nonce2, 0, NONCELEN);
                    mystrncpy(p->nonce2, mynonce, NONCELEN);
                }
            } else { // 之前没认证

                if (tmp1 < myId) {
                    p = insertNode(gV->head, tmp1,
                                   authTableShareMsg.nonce + i * NONCELEN,
                                   mynonce, 1, -1, 0);
                }

                else {
                    p = insertNode(gV->head, tmp1, mynonce,
                                   authTableShareMsg.nonce + i * NONCELEN, 1,
                                   -1, 0);
                }
            }

            memset(p->sessionkey, 0, NONCELEN);
            generate_session_key(p->sessionkey, p->nonce1, p->nonce2, NONCELEN);
            printf("Update drone-%d\n", tmp1);
        }

        tmp1 = -1;
    }

    printf("Update %d drones\n", i);
    cleanTable(gV->head);
    mysetittimer(updateif->updateinterval,
                 updateif->updateinterval); // 非触发节点重置密钥更新时间
    receiveupdate_init(updateif->receiveupdate, DRONENUM);

    if (gV->Debug) {
        printf("\n");
        printf("Auth table\n");
        printAuthtable(gV->head, 0);
        printf("\n");
    }

    printAuthtable(gV->head, 1);
    printf("end_time: %ld\n", clock());
    free(h);
}

void regularUpdate(int sigum) {
    printf("update times: %d\n", gV->head->flag);

    char srcId = gV->myId;
    Response* response = updateif->response;
    AuthNode* node = gV->head->next;
    char updateId = gV->myId;

    if (gV->head->flag == 0) { // 第一次更新选择认证表中ID最小的

        while (node != NULL) {
            if (node->id <= updateId) updateId = node->id;
            node = node->next;
        }

    }

    else { // 其他情况随机指定

        node = gV->head->next;
        int sum;
        if (node != NULL && node->id < gV->myId)
            sum = node->nonce2[NONCELEN - 1];
        else if (node != NULL && node->id > gV->myId)
            sum = node->nonce1[NONCELEN - 1];
        while (node != NULL) {
            if (node->id < gV->myId)
                sum += node->nonce1[NONCELEN - 1];
            else
                sum += node->nonce2[NONCELEN - 1];
            node = node->next;
        }

        printf("sum: %d\n", sum);
        updateId = sum % DRONENUM + 1;
    }

    // sleep(1);
    printf("update id: %d\n", updateId);

    if (updateId == gV->myId) {
        printf("satrt_time: %ld\n", clock());

        node = gV->head->next;
        struct NodeCheckMsg nodeCheckMsg = {0};

        __uint8_t nonce[NONCELEN];
        rand_bytes(nonce, NONCELEN);
        MessageHeader header = {0};
        header.srcId = srcId;

        int i = 0;

        while (node != NULL) {
            if (node->flag == 1) i++;
            node = node->next;
        }

        node = gV->head->next;
        response[0].num = i;
        i = 0;

        while (node != NULL) {
            if (node->flag == 1) { // 已认证节点

                header.destId = node->id;
                nodeCheckMsg.header = header;
                generateNodeCheckMsg(&nodeCheckMsg, 0x1, &header, nonce);
                sendNodeCheckMsg(&nodeCheckMsg, sizeof(nodeCheckMsg),
                                 gV->allDrone[node->id].IP,
                                 gV->allDrone[node->id].PORT, node->sessionkey);
                printf("send nodeCheckMsg to drone-%d\n", header.destId);
                response[i].id = node->id; // 记录接收到的响应
                response[i].isresponsed = 0;
                i++;

                if (node->id < srcId) { // id小的为nonce1
                    memset(node->nonce2, 0, NONCELEN);
                    mystrncpy(node->nonce2, nonce, NONCELEN);
                }

                else { // node->id > srcId
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

    else { // 其他无人机更新

        printf("satrt_time: %ld\n", clock());

        int i = 0;
        int frequency = 5; // 5秒钟检查一次
        int times = 3;     // 3次过后直接认为该无人机丢失
        char flag = 0;
        ReceiveUpdate* ru =
            receiveupdate_find(updateif->receiveupdate, updateId);

        for (i = 0; i < times; i++) {
            sleep(frequency);
            flag = ru->flag;
            if (flag == 1) return;
        }

        if (flag == 0) { printf("drone-%d lost\n", updateId); }
    }
}