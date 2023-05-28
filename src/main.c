#include "../include/crypto.h"
#include "../include/socket.h"
#include "../include/utils.h"
#include "../include/auth_table.h"
#include "../include/drone.h"
#include "../include/message.h"
#include "../include/test.h"
#include "../include/mytime.h"
#include "../include/config.h"

GlobalVars* gV;
UpdateInfo* updateif;
int main() {
    printf("authMsgLen: %ld\n", sizeof(AuthenticationMsg));
    printf("nonceShareMsgLen: %ld\n", sizeof(NonceShareMsg));
    printf("nodeCheckLen: %ld\n", sizeof(NodeCheckMsg));
    printf("authTableShareMsgLen: %ld\n", sizeof(AuthenticationTableShareMsg));

    config_t* conf = confRead("./config");
    char Debug = atoi(confGet(conf, "debug"));
    int updateinterval = atoi(confGet(conf, "updateinterval"));
    int droneNum = atoi(confGet(conf, "dronenum"));
    char nonceLen = atoi(confGet(conf, "noncelen"));
    char sessionkeyLen = atoi(confGet(conf, "sessionkeylen"));

    Drone allDrone[DRONENUM + 1];
    droneInit(allDrone);

    Response response[DRONENUM];
    response_init(response, DRONENUM);

    char local_ip[13];
    getLocalIp(local_ip);
    char myId = findDroneByIp(allDrone, local_ip);

    if (myId == -1) {
        printf("error!\n");
        return 0;
    }

    char destId = myId + 1;
    printf("my_ip : %s, myId : %d\n", local_ip, myId);
    int cfd = mySocketInit(allDrone[myId].IP, allDrone[myId].PORT);

    AuthNode* head = initList();

    __uint8_t* mynonce = (__uint8_t*)malloc(NONCELEN);
    __uint8_t* othernonce = (__uint8_t*)malloc(NONCELEN);

    printf("updateinterval: %d\n", updateinterval);

    pthread_t id;

    GlobalVars globalVars;
    globalVars.cfd = cfd;
    globalVars.myId = myId;
    globalVars.allDrone = allDrone;
    globalVars.head = head;
    globalVars.Debug = Debug;
    gV = &globalVars;

    int ret = pthread_create(&id, NULL, receive, NULL);
    if (-1 == ret) print_err("pthread_create failed", __LINE__, errno);
    wrapperOfUpdate(updateinterval, updateinterval);

    ReceiveUpdate receiveupdate[DRONENUM];
    receiveupdate_init(receiveupdate, DRONENUM);
    UpdateInfo ui = {0};
    ui.updateinterval = updateinterval;
    ui.response = response;
    ui.receiveupdate = (ReceiveUpdate*)&receiveupdate;
    updateif = &ui;
    testWorstGroupCreate(cfd, allDrone, myId, head, droneNum);

    // testBestGroupCreate(cfd, allDrone, myId, head);
    // testCertificationTime(cfd, allDrone, myId, head);
    // testJoinTime(cfd, allDrone, myId, head, droneNum);
    // testCRTime(cfd, allDrone, myId, head, 64);
    // testOriginGroupCreateTime(cfd, allDrone, myId, head, 8);
    // testSm4Time(16,1980);while(1);
    // testHmacTime(32);while(1);

    int flag = -1;
    while (1) {
        printf("====================menu====================\n");
        printf("0:Print Auth Table\n");
        printf("1:Authenticate\t 2:Update Session Key\t 3:xxxxxx\n");
        scanf("%d", &flag);
        switch (flag) {
        case 0:

            printf("Auth Table is:\n");
            printAuthtable(head, 1);
            break;

        case 1:

            AuthNode* p = searchList(head, destId);
            if (p != NULL && p->flag == 1) {
                printf("drone-%d already authed\n", destId);
                continue;
            }
            __uint8_t* mynonce = (unsigned char*)malloc(NONCELEN);
            AuthenticationMsg authMsg = {0};
            MessageHeader header = {0};

            header.srcId = myId;
            header.destId = destId;
            rand_bytes(mynonce, NONCELEN);

            generateAuthMessage(&authMsg, 0x1, &header, mynonce, NULL);

            printf("mynonce is: ");
            print_char_arr(mynonce, NONCELEN);

            if (header.srcId < header.destId) {
                insertNode(head, allDrone[destId].id, authMsg.nonce, NULL, 0, 0,
                           0);
            }

            else {
                insertNode(head, allDrone[destId].id, NULL, authMsg.nonce, 0, 0,
                           0);
            }

            sendPaddingMsgThread(cfd, (void*)&authMsg, sizeof(authMsg), 0x1,
                                 allDrone[destId].IP, allDrone[destId].PORT);
            printf("Send authMsg to drone-%d!\n", destId);
            break;

        case 2: nodeCheck(response); break;

        default: break;
        }
    }
    return 0;
}
