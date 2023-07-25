#ifndef _DRONE
#define _DRONE

#include "../include/crypto.h"
#include <stdlib.h>
#include <string.h>

#define DRONENUM 64
typedef struct drone {
    char id;
    __uint8_t IP[14];
    int PORT;
    char groupID;
    char leaderID;
    __uint8_t hashChainKey[32];
    __uint8_t Sm4_iv[KEYLEN];
    __uint8_t hmac_key[KEYLEN];
    __uint8_t leader_key[KEYLEN];
} Drone;

__uint8_t* droneInit(Drone* alldrone, char groupSize, char isLeader,
                     char leaderID, char groupID, char num);
char findDroneByIp(Drone* alldrone, char* IP);
char findDroneById(Drone* alldrone, char id);
void printDroneInfo(Drone* drone);
char compareDroneGroup(Drone* allDrone, char id1, char id2);
#endif