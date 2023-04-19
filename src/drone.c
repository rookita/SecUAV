#include "../include/drone.h"
#include <string.h>

/*
"192.168.8.130", "192.168.8.187", "192.168.8.139", "192.168.8.146", "192.168.8.169", "192.168.8.109", "192.168.8.177", "192.168.8.178"
*/
void drone_init(Drone* alldrone){
    alldrone[1].id = 1;
    strncpy(alldrone[1].IP, "192.168.8.130\0", 14);
    alldrone[1].PORT = 6666;
    
    alldrone[2].id = 2;
    strncpy(alldrone[2].IP, "192.168.8.187\0", 14);
    alldrone[2].PORT = 6666;

    alldrone[3].id = 3;
    strncpy(alldrone[3].IP, "192.168.8.139\0", 14);
    alldrone[3].PORT = 6666;

    alldrone[4].id = 4;
    strncpy(alldrone[4].IP, "192.168.8.146\0", 14);
    alldrone[4].PORT = 6666;

    alldrone[5].id = 5;
    strncpy(alldrone[5].IP, "192.168.8.169\0", 14);
    alldrone[5].PORT = 6666;

    alldrone[6].id = 6;
    strncpy(alldrone[6].IP, "192.168.8.109\0", 14);
    alldrone[6].PORT = 6666;

    alldrone[7].id = 7;
    strncpy(alldrone[7].IP, "192.168.8.177\0", 14);
    alldrone[7].PORT = 6666;

    alldrone[8].id = 8;
    strncpy(alldrone[8].IP, "192.168.8.178\0", 14);
    alldrone[8].PORT = 6666;
}

char find_drone_by_ip(Drone* alldrone, char* IP){
    int i = 0;
    for (i = 0; i<20; i++){
        if (strncmp(alldrone[i].IP, IP, 13) == 0)    //相等
            return alldrone[i].id;
    }
    return -1;
}

char find_drone_by_id(Drone* alldrone, char id){
    int i = 0;
    for (i = 0; i<20; i++){
        if (alldrone[i].id == id)    //相等
            return 1;
    }
    return 0;
}

