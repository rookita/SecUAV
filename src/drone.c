#include "../include/drone.h"
#include "../include/utils.h"
#include <string.h>
#include <stdio.h>

__uint8_t* droneInit(Drone* alldrone, char groupSize, char isLeader,
                     char leaderID, char groupID) {
    int i = 1;
    for (i = 1; i <= DRONENUM; i++) {
        alldrone[i].id = i;
        alldrone[i].PORT = 6666;
        sprintf(alldrone[i].IP, "10.10.0.%d", i + 10);
        alldrone[i].groupID = ((i - 1) / groupSize) + 1;
        alldrone[i].leaderID = (alldrone[i].groupID - 1) * groupSize + 1;
        sprintf(alldrone[i].hashChainKey, "hashChainKey%d",
                alldrone[i].groupID);
        sprintf(alldrone[i].Sm4_iv, "0123456789abcd%d", alldrone[i].groupID);
        sprintf(alldrone[i].hmac_key, "0123456789abcd%d", alldrone[i].groupID);
        if (alldrone[i].id != alldrone[i].leaderID)
            sprintf(alldrone[i].leader_key, "0123456789abcd%d", alldrone[i].id);
        else { __uint8_t* drone_key = (__uint8_t*)malloc(groupSize * KEYLEN); }
        // printf("IP:%s\n", alldrone[i].IP);
    }
    return;
}

char findDroneByIp(Drone* alldrone, char* IP) {
    int i = 0;
    for (i = 0; i <= DRONENUM; i++) {
        if (strncmp(alldrone[i].IP, IP, 10) == 0) // 相等
            return alldrone[i].id;
    }
    return -1;
}

char findDroneById(Drone* alldrone, char id) {
    int i = 0;
    for (i = 0; i <= DRONENUM; i++) {
        if (alldrone[i].id == id) // 相等
            return 1;
    }
    return 0;
}

void printDroneInfo(Drone* drone) {
    printf("*********DRONE INFO*********\n");
    printf("id: %d\n", drone->id);
    printf("IP:%s\n", drone->IP);
    printf("groupID: %d\n", drone->groupID);
    printf("leaderID: %d\n", drone->leaderID);
    printf("hashChainKey: ");
    print_char_arr(drone->hashChainKey, 32);
    printf("hmac_key: %s\n", drone->hmac_key);
    printf("Sm4_iv: %s\n", drone->Sm4_iv);
}

char compareDroneGroup(Drone* allDrone, char id1, char id2) {
    if (allDrone[id1].groupID == allDrone[id2].groupID) {
        return 0;
    } else if (allDrone[id1].groupID < allDrone[id2].groupID) {
        return -1;
    } else {
        return 1;
    }
}