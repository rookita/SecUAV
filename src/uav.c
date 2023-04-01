#include "../include/uav.h"

void Uav_init(Uav* uav, int id, unsigned char* IP, int PORT){
    uav->id = id;
    uav->PORT = PORT;
    strcpy(uav->IP, IP);
}