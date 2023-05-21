#include "../include/test.h"
#include <unistd.h>
#include <time.h>

void testWorstGroupCreate(int cfd, Drone* alldrone, char MY_ID, AuthNode* head, int droneNum){    //chain
    printf("=============================START TEST!!! I am drone-%d=============================\n", MY_ID);
    char DEST_ID = MY_ID + 1;
    if (find_drone_by_id(alldrone, DEST_ID) == 0){ //无对应无人机
        return;
    }
    while(1){
      printf("start_time: %ld\n", clock());
      sleep(MY_ID);
      if (MY_ID < droneNum){
        AuthNode* p = searchList(head, DEST_ID);
        if (p == NULL){
          unsigned char nonce[NONCELEN];
          memset(nonce, 0, NONCELEN);
          rand_bytes(nonce, NONCELEN);
          AuthMsg auth_msg = {0};
          generate_auth_message(&auth_msg, 0x1, alldrone[MY_ID].id, alldrone[DEST_ID].id, nonce, NONCELEN, NULL);
          printf("mynonce is: ");
          print_char_arr(auth_msg.nonce, NONCELEN);
          if (auth_msg.srcid < auth_msg.destid){
            insertNode(head, alldrone[DEST_ID].id, auth_msg.nonce, NULL, 0, 0, 0);
          }
          else{
            insertNode(head, alldrone[DEST_ID].id, NULL, auth_msg.nonce, 0, 0,  0);
          }
          send_padding_msg_thread(cfd, (void*)&auth_msg, sizeof(auth_msg), 0x1, alldrone[DEST_ID].IP, alldrone[DEST_ID].PORT);
          printf("Send Auth msg to drone-%d!\n", DEST_ID);    
        }
        else if (p != NULL && p->flag != 1 && p->index == 0){
          unsigned char nonce[NONCELEN];
          memset(nonce, 0, NONCELEN);
          rand_bytes(nonce, NONCELEN);
          AuthMsg auth_msg = {0};
          generate_auth_message(&auth_msg, 0x1, alldrone[MY_ID].id, alldrone[DEST_ID].id, nonce, NONCELEN, NULL);
          printf("mynonce is: ");
          print_char_arr(auth_msg.nonce, NONCELEN);
          if (auth_msg.srcid < auth_msg.destid){
            memset(p->nonce1, 0, NONCELEN);
            mystrncpy(p->nonce1, auth_msg.nonce, NONCELEN);
          }
          else{
            memset(p->nonce2, 0, NONCELEN);
            mystrncpy(p->nonce2, auth_msg.nonce, NONCELEN);
          }
          send_padding_msg_thread(cfd, (void*)&auth_msg, sizeof(auth_msg), 0x1, alldrone[DEST_ID].IP, alldrone[DEST_ID].PORT);
          printf("Send Auth msg to drone-%d!\n", DEST_ID);
        }
        else{
          break;
        }
      }
    }
    printf("=============================TEST END!!! I am drone-%d=============================\n", MY_ID);
}

void testBestGroupCreate(int cfd, Drone* alldrone, char MY_ID, AuthNode* head){ //二叉树
    printf("=============================START TEST!!! I am drone-%d=============================\n", MY_ID);
    printf("start_time: %ld\n", clock());
    int count = 0, dn = DRONENUM, i, DEST_ID = 0;
    int interval = 1, start = 1, drone;
    unsigned char nonce[NONCELEN];
    AuthNode* p = NULL;
    AuthMsg auth_msg = {0};
    while(dn != 1){   //2^count == dn
      dn = dn / 2;
      count++;
    }
    printf("count: %d\n", count);
    for (i = 0; i < count; i++){
      interval = 2*interval;
      drone = start;
      printf("start: %d; interval: %d\n", start, interval);
      while(drone < DRONENUM){
        if (drone == MY_ID){
          DEST_ID = MY_ID + 1;
          break;
        }
        else if (drone > MY_ID)
          break;
        drone = drone + interval;
      }
      if (DEST_ID != 0){
        
        while(1){
          p = searchList(head, DEST_ID);
          if (p == NULL){
            memset(nonce, 0, NONCELEN);rand_bytes(nonce, NONCELEN);
            memset(&auth_msg, 0, sizeof(auth_msg));
            generate_auth_message(&auth_msg, 0x1, alldrone[MY_ID].id, alldrone[DEST_ID].id, nonce, NONCELEN, NULL);
            printf("mynonce is: ");print_char_arr(auth_msg.nonce, NONCELEN);
            if (auth_msg.srcid < auth_msg.destid){
              insertNode(head, alldrone[DEST_ID].id, auth_msg.nonce, NULL, 0, 0, 0);
            }
            else{
              insertNode(head, alldrone[DEST_ID].id, NULL, auth_msg.nonce, 0, 0,  0);
            }
            send_padding_msg_thread(cfd, (void*)&auth_msg, sizeof(auth_msg), 0x1, alldrone[DEST_ID].IP, alldrone[DEST_ID].PORT);
            printf("Send Auth msg to drone-%d!\n", DEST_ID);
          }
          else if (p->flag != 1 && p->index == 0){
            unsigned char nonce[NONCELEN];
            memset(nonce, 0, NONCELEN);
            rand_bytes(nonce, NONCELEN);
            memset(&auth_msg, 0, sizeof(auth_msg));
            generate_auth_message(&auth_msg, 0x1, alldrone[MY_ID].id, alldrone[DEST_ID].id, nonce, NONCELEN, NULL);
            printf("mynonce is: ");
            print_char_arr(auth_msg.nonce, NONCELEN);
            if (auth_msg.srcid < auth_msg.destid){
              memset(p->nonce1, 0, NONCELEN);
              mystrncpy(p->nonce1, auth_msg.nonce, NONCELEN);
            }
            else{
              memset(p->nonce2, 0, NONCELEN);
              mystrncpy(p->nonce2, auth_msg.nonce, NONCELEN);
            }
            send_padding_msg_thread(cfd, (void*)&auth_msg, sizeof(auth_msg), 0x1, alldrone[DEST_ID].IP, alldrone[DEST_ID].PORT);
            printf("Send Auth msg to drone-%d!\n", DEST_ID);
          }
          else{
            break;
          }
          sleep(10);
        }
        DEST_ID = 0;
      }
      else{ //DEST_ID == 0
        sleep(10);
      }
      start = 2*start;
  }
  printf("=============================TEST END!!! I am drone-%d=============================\n", MY_ID);
}


void testCertificationTime(int cfd, Drone* alldrone, char MY_ID, AuthNode* head){
  printf("=============================START TEST!!! I am drone-%d=============================\n", MY_ID);
  int DEST_ID = 0;
  if (MY_ID == 1){
    DEST_ID = 2;
  }
    
  sleep(5); //等待对方无人机上线
  unsigned char nonce[NONCELEN];
  memset(nonce, 0, NONCELEN);
  rand_bytes(nonce, NONCELEN);
  AuthMsg auth_msg = {0};
  generate_auth_message(&auth_msg, 0x1, alldrone[MY_ID].id, alldrone[DEST_ID].id, nonce, NONCELEN, NULL);
  insertNode(head, alldrone[DEST_ID].id, auth_msg.nonce, NULL, 0, 0, 0);  //MY_ID < DEST_ID
  printf("mynonce is: ");
  print_char_arr(auth_msg.nonce, NONCELEN);
  //printf("start_time: %ld\n", clock());
  send_padding_msg_thread(cfd, (void*)&auth_msg, sizeof(auth_msg), 0x1, alldrone[DEST_ID].IP, alldrone[DEST_ID].PORT);
  printf("Send Auth msg to drone-%d!\n", DEST_ID);
}

void testJoinTime(int cfd, Drone* alldrone, char MY_ID, AuthNode* head, int droneNum){
  printf("start_time: %ld\n", clock());
  printf("=============================START TEST!!! I am drone-%d=============================\n", MY_ID);
  char DEST_ID = MY_ID + 1;
  if (find_drone_by_id(alldrone, DEST_ID) == 0){ //无对应无人机
    return;
  }
  while(1){
    sleep(MY_ID);
    if (MY_ID == 1)
      sleep(100);
    if (MY_ID < droneNum){
      AuthNode* p = searchList(head, DEST_ID);
      if (p == NULL){
        unsigned char nonce[NONCELEN];
        memset(nonce, 0, NONCELEN);
        rand_bytes(nonce, NONCELEN);
        AuthMsg auth_msg = {0};
        generate_auth_message(&auth_msg, 0x1, alldrone[MY_ID].id, alldrone[DEST_ID].id, nonce, NONCELEN, NULL);
        printf("mynonce is: ");print_char_arr(auth_msg.nonce, NONCELEN);
        if (auth_msg.srcid < auth_msg.destid){
          insertNode(head, alldrone[DEST_ID].id, auth_msg.nonce, NULL, 0, 0, 0);
        }
        else{
          insertNode(head, alldrone[DEST_ID].id, NULL, auth_msg.nonce, 0, 0,  0);
        }
        //printf("start_time: %ld\n", clock());
        send_padding_msg_thread(cfd, (void*)&auth_msg, sizeof(auth_msg), 0x1, alldrone[DEST_ID].IP, alldrone[DEST_ID].PORT);
        printf("Send Auth msg to drone-%d!\n", DEST_ID);    
      }
      else if (p != NULL && p->flag != 1 && p->index == 0){
        unsigned char nonce[NONCELEN];
        memset(nonce, 0, NONCELEN);
        rand_bytes(nonce, NONCELEN);
        AuthMsg auth_msg = {0};
        generate_auth_message(&auth_msg, 0x1, alldrone[MY_ID].id, alldrone[DEST_ID].id, nonce, NONCELEN, NULL);
        printf("mynonce is: ");
        print_char_arr(auth_msg.nonce, NONCELEN);
        if (auth_msg.srcid < auth_msg.destid){
          memset(p->nonce1, 0, NONCELEN);
          mystrncpy(p->nonce1, auth_msg.nonce, NONCELEN);
        }
        else{
          memset(p->nonce2, 0, NONCELEN);
          mystrncpy(p->nonce2, auth_msg.nonce, NONCELEN);
        }
        send_padding_msg_thread(cfd, (void*)&auth_msg, sizeof(auth_msg), 0x1, alldrone[DEST_ID].IP, alldrone[DEST_ID].PORT);
        printf("Send Auth msg to drone-%d!\n", DEST_ID);
      }
      else{
        break;
      }
    }
  }
    printf("=============================TEST END!!! I am drone-%d=============================\n", MY_ID);
}