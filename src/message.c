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

void send_auth_message(int cfd, AuthMsg* auth_msg, int len, unsigned char* Dest_IP, int Dest_PORT){
  send_padding_msg(cfd, (void*) auth_msg, len, 0x1, Dest_IP, Dest_PORT); 
}

void printAuthMsg(AuthMsg* auth_msg){
    printf("index : %d\n", auth_msg->index);
    printf("srcid : %d\n", auth_msg->srcid);
    printf("destid : %d\n", auth_msg->destid);
    printf("nonce : ");print_char_arr(auth_msg->nonce, 16);
    printf("hmac : ");print_char_arr(auth_msg->hmac, 32);
}

void pre_auth_message(void*msg, AuthMsg* auth_msg, int auth_msg_len, int DEBUG){
    __uint8_t* src = msg + 1;
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
          AuthNode* node = insertNode(rfa->head, auth_msg.srcid, auth_msg.nonce, NULL, 0, 0, 0);
          node->index = 2;
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
                generate_session_key(p2->sessionkey, p2->nonce1, p2->nonce2, 16);
                p2->flag = 1;
                p2->direct = 1;
                printf("[info]>>>drone's id = %d auth success!\n\n", auth_msg.srcid);
                share(rfa->sock_fd, rfa->alldrone[rfa->my_index].id, rfa->head, rfa->alldrone, p2);
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
                generate_session_key(p3->sessionkey, p3->nonce1, p3->nonce2, 16);
                p3->direct = 1;
                p3->flag = 1;
                printf("drone's id = %d auth success!\n\n", auth_msg.srcid);
                share(rfa->sock_fd, rfa->alldrone[rfa->my_index].id, rfa->head, rfa->alldrone, p3);
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

void generate_share_message(ShareMsg* share_msg, char id, __uint8_t* nonce1, __uint8_t* nonce2, size_t len){
  share_msg->id = id;
  share_msg->noncelen = len;
  strncpy(share_msg->nonce1, nonce1, len);
  strncpy(share_msg->nonce2, nonce2, len);

}

void send_share_message(int cfd, char id, ShareMsg* share_msg, int mlen, unsigned char* Dest_IP, int Dest_PORT, __uint8_t* Sm4_key){
  size_t clen = mlen%16 ? mlen+ 16 - mlen % 16: mlen;
  __uint8_t* ciphertext = (__uint8_t*) malloc (clen);
  my_sm4_cbc_padding_encrypt(Sm4_key, Sm4_iv, (__uint8_t*)share_msg, mlen, ciphertext, &clen, 1);
  __uint8_t* msg = (__uint8_t*) malloc (clen+1);
  add_byte(msg, (void*)ciphertext, clen, id);
  send_padding_msg(cfd, (void*)msg, clen, 0x2, Dest_IP, Dest_PORT);
}

void share(int cfd, char id, AuthNode* head, Drone* alldrone, AuthNode* p){
  AuthNode* node = head;
  ShareMsg share_msg = {0};
  while (node != NULL){
    if (node != p && node->flag == 1 && node->direct == 1){
      memset(&share_msg, sizeof(share_msg), 0);
      if (node->index == 1 && p->index == 1)
        generate_share_message(&share_msg, p->id, node->nonce1, p->nonce1, 16);
      else if (node->index == 1 && p->index == 2)
        generate_share_message(&share_msg, p->id, node->nonce1, p->nonce2, 16);
      else if (node->index == 2 && p->index == 1)
        generate_share_message(&share_msg, p->id, node->nonce2, p->nonce1, 16);
      else if (node->index == 2 && p->index == 2)
        generate_share_message(&share_msg, p->id, node->nonce2, p->nonce2, 16);
      send_share_message(cfd, id, &share_msg, sizeof(share_msg), alldrone[node->id - 1].IP, alldrone[node->id - 1].PORT, node->sessionkey);
    }
  }
}

void pre_share_message(void* msg, __uint8_t* ciphertext, int len, char* id, int DEBUG){
  __uint8_t* src = msg + 2;
  *id = ((char*)msg)[1];
  memmove(ciphertext, src, len);
}


void handle_share_message(void* msg, struct recive_func_arg* rfa, int DEBUG){
  ShareMsg share_msg = {0};char id;size_t clen = 48;size_t mlen;
  __uint8_t* ciphertext = (__uint8_t*)malloc(clen);
  pre_share_message(msg, ciphertext, 48, &id, DEBUG);
  AuthNode* p = searchList(rfa->head, id);
  if (p == NULL){
    printf("Dont find the id\n");
    return;
  }
  if(p->flag != 1){
    printf("have not authed\n");
    return;
  }
  my_sm4_cbc_padding_decrypt(p->sessionkey, Sm4_iv, ciphertext, clen, (__uint8_t*)&share_msg, &mlen, 1);
  if (DEBUG){
    printf("mlen : %ld\n", mlen);
  }
  p = searchList(rfa->head, share_msg.id);
  if (p != NULL){
    if (p->flag == 1)
      printf("Aleardy Auth!\n");
    else{
      p->id = share_msg.id;
      strncpy(p->nonce1, share_msg.nonce1, share_msg.noncelen);
      strncpy(p->nonce2, share_msg.nonce2, share_msg.noncelen);
      p->flag = 1;
    }
  }
}