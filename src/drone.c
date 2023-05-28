#include "../include/drone.h"
#include <string.h>
#include <stdio.h>

int droneInit(Drone* alldrone) {
    int i = 1;
    for (i = 1; i <= DRONENUM; i++) {
        alldrone[i].id = i;
        alldrone[i].PORT = 6666;
        sprintf(alldrone[i].IP, "10.10.0.%d", i + 10);
        // printf("IP:%s\n", alldrone[i].IP);
    }
    return DRONENUM;
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
