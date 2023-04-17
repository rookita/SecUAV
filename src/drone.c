#include "../include/drone.h"
#include <string.h>

void drone_init(Drone* alldrone){
    alldrone[1].id = 1;
    strncpy(alldrone[1].IP, "192.168.8.130", 13);
    alldrone[1].PORT = 6666;
    
    alldrone[2].id = 2;
    strncpy(alldrone[2].IP, "192.168.8.187", 13);
    alldrone[2].PORT = 6666;

    alldrone[3].id = 3;
    strncpy(alldrone[3].IP, "192.168.8.139", 13);
    alldrone[3].PORT = 6666;
}

char find_drone(Drone* alldrone, char* IP){
    int i = 0;
    for (i = 0; i<10; i++){
        if (strcmp(alldrone[i].IP, IP) == 0)    //相等
            return alldrone[i].id;
    }
    return -1;
}