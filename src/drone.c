#include "../include/drone.h"


void drone_init(Drone* alldrone){
    alldrone[0].id = 1;
    strncat(alldrone[0].IP, "192.168.8.130", 20);
    alldrone[0].PORT = 6666;
    
    alldrone[1].id = 2;
    strncat(alldrone[1].IP, "192.168.8.187", 20);
    alldrone[1].PORT = 6666;

    alldrone[2].id = 3;
    strncat(alldrone[2].IP, "192.168.8.139", 20);
    alldrone[2].PORT = 6666;
}