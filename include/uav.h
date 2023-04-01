#include <stdlib.h>
#include <string.h>
#include "message.h"

typedef struct uav
{
    int id;
    unsigned char IP[20];
    int PORT;
    unsigned char* r_s;    //send
    unsigned char* r_r;    //recive
    int r_s_len;
    int r_r_len;
}Uav;

void Uav_init(Uav* uav, int id, unsigned char* IP, int PORT);

