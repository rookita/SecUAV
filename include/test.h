#ifndef __TEST
#define __TEST

#include "message.h"
#include "socket.h"
#include "utils.h"
#include <stdlib.h>

void testWorstGroupCreate(int cfd, Drone* alldrone, char MY_ID, AuthNode* head,
                          int droneNum);
void testBestGroupCreate(int cfd, Drone* alldrone, char MY_ID, AuthNode* head);
void testCertificationTime(int cfd, Drone* alldrone, char MY_ID,
                           AuthNode* head);
void testJoinTime(int cfd, Drone* alldrone, char MY_ID, AuthNode* head,
                  int droneNum);
void testSm4Time(int keyLen, int msgLen);
void testHmacTime(int keyLen, int msgLen);
void testCRTime(int cfd, Drone* alldrone, char MY_ID, AuthNode* head,
                int droneNum);
void testOriginGroupCreateTime(int cfd, Drone* alldrone, char MY_ID,
                               AuthNode* head, int droneNum);

#endif