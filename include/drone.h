#ifndef _DRONE
#define _DRONE

#include <stdlib.h>
#include <string.h>

#define DRONENUM 8
typedef struct drone{
  char id;
  __uint8_t IP[14];
  int PORT;
}Drone;

int drone_init(Drone* alldrone);
char find_drone_by_ip(Drone* alldrone, char* IP);
char find_drone_by_id(Drone* alldrone, char id);

#endif