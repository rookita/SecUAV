#ifndef _DRONE
#define _DRONE

#include <stdlib.h>
#include <string.h>

#define DRONENUM 64
typedef struct drone {
    char id;
    __uint8_t IP[14];
    int PORT;
} Drone;

int droneInit(Drone* alldrone);
char findDroneByIp(Drone* alldrone, char* IP);
char findDroneById(Drone* alldrone, char id);

#endif