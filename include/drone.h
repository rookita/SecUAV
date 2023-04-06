#ifndef _DRONE
#define _DRONE

#include <stdlib.h>
#include <string.h>

typedef struct drone{
  char id;
  __uint8_t IP[20];
  int PORT;
}Drone;

void drone_init(Drone* alldrone);

#endif