#include "../include/test.h"
#include <unistd.h>

void test(int cfd, Drone* alldrone, char MY_ID, AuthNode* head){
    char DEST_ID = MY_ID + 1;
    if (find_drone_by_id(alldrone, DEST_ID) == 0){ //无对应无人机
        sleep(10);
        return;
    }
    while(1){
      sleep(MY_ID);
      if (MY_ID != 4){
        AuthNode* p = searchList(head, DEST_ID);
        if (p == NULL){
          unsigned char* mynonce = (unsigned char*) malloc(NONCELEN);
          AuthMsg auth_msg = {0};
          auth_msg.index = 1;
          auth_msg.srcid = alldrone[MY_ID].id;
          auth_msg.destid = alldrone[DEST_ID].id;
          rand_bytes(auth_msg.nonce, NONCELEN);
          auth_msg.noncelen = NONCELEN;
          printf("mynonce is: ");
          print_char_arr(auth_msg.nonce, NONCELEN);
          if (auth_msg.srcid < auth_msg.destid){
            insertNode(head, alldrone[DEST_ID].id, auth_msg.nonce, NULL, 0, 0);
          }
          else{
            insertNode(head, alldrone[DEST_ID].id, NULL, auth_msg.nonce, 0, 0);
          }
          send_padding_msg_thread(cfd, (void*)&auth_msg, sizeof(auth_msg), 0x1, alldrone[DEST_ID].IP, alldrone[DEST_ID].PORT);
          printf("Send Auth msg to drone-%d!\n", DEST_ID);
          free(mynonce);    
        }
        else if (p != NULL && p->flag != 1 && p->index == 0){
          unsigned char* mynonce = (unsigned char*) malloc(NONCELEN);
          AuthMsg auth_msg = {0};
          auth_msg.index = 1;
          auth_msg.srcid = alldrone[MY_ID].id;
          auth_msg.destid = alldrone[DEST_ID].id;
          rand_bytes(auth_msg.nonce, NONCELEN);
          auth_msg.noncelen = NONCELEN;
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
          free(mynonce);    
        }
        else{
          break;
        }
      }
    }
}