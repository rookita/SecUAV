#include "../include/message.h"
#include "../include/gmssl/rand.h"
#include <string.h>

void generate_auth_message(AuthMsg* auth_msg, int index, char srcid, char destid, __uint8_t* nonce, int len, __uint8_t* hmac){
    auth_msg->index = index;
    auth_msg->srcid = srcid;
    auth_msg->destid = destid;
    auth_msg->noncelen = len;
    if (nonce != NULL)
        strncat(auth_msg->nonce, nonce, len);
    if (hmac != NULL)
        strncat(auth_msg->hmac, hmac, 32);
}

void printAuthMsg(AuthMsg* auth_msg){
    printf("index : %d\n", auth_msg->index);
    printf("srcid : %d\n", auth_msg->srcid);
    printf("destid : %d\n", auth_msg->destid);
    printf("nonce : ");print_char_arr(auth_msg->nonce, 16);
    printf("hmac : ");print_char_arr(auth_msg->hmac, 32);
}

void pre_auth_message(void*msg, AuthMsg* auth_msg, int auth_msg_len, int DEBUG){
    char* src = msg + 1;
    memmove(auth_msg, src, auth_msg_len);
    if (DEBUG){
        printf("[info]>>>origin msg is ");print_char_arr(msg, auth_msg_len+1);
    }
} 

void handle_auth_message(void* msg, struct recive_func_arg* rfa, int DEBUG){
    AuthMsg auth_msg = {0};
    pre_auth_message(msg, &auth_msg, sizeof(auth_msg), DEBUG); //预处理
    if (auth_msg.destid == rfa->alldrone[rfa->my_index].id){
      if (DEBUG){
        printf("[info]>>>recive msg \n");
        printAuthMsg(&auth_msg);
      }
      switch(auth_msg.index){
        case 1: //reciver
          if (DEBUG)
            printf("##########CASE ONE DEBUG INFO START##########\n");
          AuthNode* node = insertNode(rfa->head, auth_msg.srcid, auth_msg.nonce, NULL, 0, 0);
          __uint8_t* nonce2 = (__uint8_t*) malloc (16);
          __uint8_t* mbuf = (__uint8_t*) malloc (34);
          __uint8_t* hmac = (__uint8_t*) malloc (32);
          rand_bytes(nonce2, 16);
          strncpy(node->nonce2, nonce2, 16);
          strncat(mbuf, &auth_msg.srcid, 1);strncat(mbuf, &auth_msg.destid, 1);strncat(mbuf,node->nonce2, 16);strncat(mbuf, node->nonce1, 16);
          if (DEBUG){
            printf("[info]>>the mbuf of hmac is ");
            print_char_arr(mbuf, 32);
          }
          my_sm3_hmac(hmac_key, sizeof(*hmac_key), mbuf, sizeof(*mbuf), hmac);
          AuthMsg my_auth_msg = {0};
          generate_auth_message(&my_auth_msg, 2, auth_msg.destid, auth_msg.srcid, nonce2, 16, hmac);
          if (DEBUG){
            printf("[info]>>>recive auth request.will send msg \n");
            printAuthMsg(&my_auth_msg);
          }
          send_padding_msg(rfa->sock_fd, (void*)&my_auth_msg, sizeof(my_auth_msg), 0x1, rfa->alldrone[(int)(auth_msg.srcid) - 1].IP, rfa->alldrone[(int)(auth_msg.srcid) - 1].PORT);
          free(nonce2);free(mbuf);free(hmac);
          if (DEBUG)
            printf("##########CASE ONE DEBUG INFO END##########\n");
          break;
        case 2: //sender
          //查找table,验证并计算hmac发送给对方
          if (DEBUG)
            printf("##########CASE TWO DEBUG INFO START##########\n");
          AuthNode* p2 = searchList(rfa->head, auth_msg.srcid);
          if (p2 != NULL){
            __uint8_t* mbuf = (__uint8_t*) malloc (34);
            __uint8_t* hmac = (__uint8_t*) malloc (32);
             strncat(mbuf, &auth_msg.destid, 1);strncat(mbuf, &auth_msg.srcid, 1);strncat(mbuf, auth_msg.nonce, 16);strncat(mbuf, p2->nonce1, 16);
             my_sm3_hmac(hmac_key, sizeof(*hmac_key), mbuf, sizeof(*mbuf), hmac);
             
             if ( isEqual(auth_msg.hmac, hmac, 32) ){   //验证通过
                if (DEBUG)
                  printf("[info]>>> hmac right\n");
                strncpy(p2->nonce2, auth_msg.nonce, 16);
                memset(mbuf, 0, 34);memset(hmac, 0, 32);
                strncat(mbuf, &auth_msg.destid, 1);strncat(mbuf, &auth_msg.srcid, 1);strncat(mbuf, p2->nonce1, 16);strncat(mbuf, p2->nonce2, 16);
                my_sm3_hmac(hmac_key, sizeof(*hmac_key), mbuf, sizeof(*mbuf), hmac);
                /*
                if (DEBUG){
                  printf("mbuf: ");print_char_arr(mbuf, 34);
                  printf("id1: %d\n", auth_msg.destid);
                  printf("id2: %d\n", auth_msg.srcid);
                  printf("nonce1: ");print_char_arr(p2->mynonce, 16);
                  printf("nonce2: ");print_char_arr(p2->othernonce, 16);
                  printf("hmac: ");print_char_arr(hmac, 32);
                }
                */
                AuthMsg my_auth_msg = {0};
                generate_auth_message(&my_auth_msg, 3, auth_msg.destid, auth_msg.srcid, NULL, 16, hmac);
                p2->flag = 1;
                p2->direct = 1;
                printf("[info]>>>drone's id = %d auth success!\n\n", auth_msg.srcid);
                if (DEBUG){
                  printf("[info]>> auth table is \n");
                  printList(rfa->head);
                  printf("[info]>>>will send auth msg is \n");
                  printAuthMsg(&my_auth_msg);
                }
                send_padding_msg(rfa->sock_fd, (void*)&my_auth_msg, sizeof(my_auth_msg), 0x1, rfa->alldrone[(int)(auth_msg.srcid) - 1].IP, rfa->alldrone[(int)(auth_msg.srcid) - 1].PORT);
             }
          else {
            printf("[info]>>>case2 hmac is not equal!\n");
            printf("[info]>>>compute_hmac is ");print_char_arr(hmac, 32);
            printf("[info]>>>recive_hmac is ");print_char_arr(auth_msg.hmac, 32);
            deleteNode(rfa->head, auth_msg.srcid);
            }
          free(mbuf);free(hmac);
          }
          else{
            printf("[info]>>Dont found the id\n");
          }
          if (DEBUG)
            printf("##########CASE TWO DEBUG INFO END##########\n");
          break;
        case 3: //reciver
          //查找table,验证hamc
          AuthNode* p3 = searchList(rfa->head, auth_msg.srcid);
          if (DEBUG)
            printf("##########CASE THREE DEBUG INFO START##########\n");
          if (p3 != NULL){
              __uint8_t* mbuf = (__uint8_t*) malloc (34);
              __uint8_t* hmac = (__uint8_t*) malloc (32);
              memset(mbuf, 0, 34);memset(hmac, 0, 32);
             strncat(mbuf, &auth_msg.srcid, 1);strncat(mbuf, &auth_msg.destid, 1);strncat(mbuf,p3->nonce1, 16);strncat(mbuf, p3->nonce2, 16);
             my_sm3_hmac(hmac_key, sizeof(*hmac_key), mbuf, sizeof(*mbuf), hmac);
             if ( isEqual(auth_msg.hmac, hmac, 32) ){   //验证通过
                if (DEBUG)
                  printf("[info]>>> hmac right\n");
                p3->direct = 1;
                p3->flag = 1;
                printf("drone's id = %d auth success!\n\n", auth_msg.srcid);
                if (DEBUG){
                  printf("[info]>> auth table is \n");
                  printList(rfa->head);
                }
             }
              else {
                printf("[info]>>>case3 hmac is not equal!\n");
                printf("[info]>>>compute_hmac is ");print_char_arr(hmac, 32);
                printf("[info]>>>recive_hmac is ");print_char_arr(auth_msg.hmac, 32);
                if (DEBUG){
                  printf("mbuf: ");print_char_arr(mbuf, 34);
                  printf("id1: %d\n", auth_msg.srcid);
                  printf("id2: %d\n", auth_msg.destid);
                  printf("nonce1: ");print_char_arr(p3->nonce1, 16);
                  printf("nonce2: ");print_char_arr(p3->nonce2, 16);
                  printf("hmac: ");print_char_arr(hmac, 32);
                }
                deleteNode(rfa->head, auth_msg.srcid);
              }
              free(mbuf);free(hmac);
          }
          else{
            printf("[info]>>Dont found the id\n");
          }
          printf("##########CASE THREE DEBUG INFO END##########\n");
          break;
      }
    }
}

