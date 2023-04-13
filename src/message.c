#include "../include/message.h"
#include "../include/gmssl/rand.h"
#include <string.h>


void response_init(Response* response, size_t len){
  int i = 0;
  for (i = 0; i<len; i++){
    response->id = -1;
    response->isresponsed = -1;
    response->num = 0;
  }
}

Response* response_find(Response* response, char id){
  int i = 0;
  for (i = 0; i < response[0].num; i++){
    if (response[i].id == id)
      return &(response[i]);
  }
  return NULL;
}

char response_check(Response* response){
  int i = 0;
  for (i = 0; i < response[0].num; i++){
    if (response[i].isresponsed != 1)
      return 0;
  }
  return 1;
}

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
          //__uint8_t* nonce2 = (__uint8_t*) malloc (16);
          //__uint8_t* mbuf = (__uint8_t*) malloc (34);
          //__uint8_t* hmac = (__uint8_t*) malloc (32);
          __uint8_t nonce2[16];
          __uint8_t mbuf[34];
          __uint8_t hmac[32];
          memset(nonce2, 0, 16);memset(mbuf, 0, 34);memset(hmac, 0, 32);
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
          //free(nonce2);free(mbuf);free(hmac);
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
                  printAuthtable(rfa->head);
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
                  printAuthtable(rfa->head);
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

void send_share_message(int cfd, char dest_id, ShareMsg* share_msg, int mlen, unsigned char* Dest_IP, int Dest_PORT, __uint8_t* Sm4_key){
  size_t clen = 64;
  //__uint8_t* ciphertext = (__uint8_t*) malloc (clen);
  __uint8_t ciphertext[clen];
  memset(ciphertext, 0, clen);
  my_sm4_cbc_padding_encrypt(Sm4_key, Sm4_iv, (__uint8_t*)share_msg, mlen, ciphertext, &clen, 0);
  //__uint8_t* msg = (__uint8_t*) malloc (clen+1);
  __uint8_t msg[clen+1];
  memset(msg, 0 , clen+1);
  add_byte(msg, (void*)ciphertext, clen, dest_id);
  send_padding_msg(cfd, (void*)msg, clen+1, 0x2, Dest_IP, Dest_PORT);
  //free(msg);
}

void share(int cfd, char id, AuthNode* head, Drone* alldrone, AuthNode* p){
  AuthNode* node = head->next;
  ShareMsg share_msg, share_msg1 = {0};
  while (node != NULL){
    if (node != p && node->flag == 1){     //对其他节点分享刚认证节点
      memset(&share_msg, sizeof(share_msg), 0);memset(&share_msg1, sizeof(share_msg1), 0);
      if (node->index == 1 && p->index == 1){
        generate_share_message(&share_msg, p->id, node->nonce2, p->nonce2, 16); //发送给node
        generate_share_message(&share_msg1, node->id, node->nonce2, p->nonce2, 16); //发送给p
      }
      else if (node->index == 1 && p->index == 2){
        generate_share_message(&share_msg, p->id, node->nonce2, p->nonce1, 16);
        generate_share_message(&share_msg1, node->id, node->nonce2, p->nonce1, 16);
      } 
      else if (node->index == 2 && p->index == 1){
        generate_share_message(&share_msg, p->id, node->nonce1, p->nonce2, 16);
        generate_share_message(&share_msg1, node->id, node->nonce1, p->nonce2, 16);
      } 
      else if (node->index == 2 && p->index == 2){
        generate_share_message(&share_msg, p->id, node->nonce1, p->nonce1, 16);
        generate_share_message(&share_msg1, node->id, node->nonce1, p->nonce1, 16);
      } 
      send_share_message(cfd, id, &share_msg, sizeof(share_msg), alldrone[node->id - 1].IP, alldrone[node->id - 1].PORT, node->sessionkey);
      printf("Send Share Msg to drone-%d\n", node->id);
      send_share_message(cfd, id, &share_msg1, sizeof(share_msg1), alldrone[p->id - 1].IP, alldrone[p->id - 1].PORT, p->sessionkey);
      printf("Send Share Msg to drone-%d\n", p->id);
    }
    //对刚认证节点分享已认证其他节点
    node = node->next;
  }
}

void pre_share_message(void* msg, __uint8_t* ciphertext, int len, char* id, int DEBUG){
  __uint8_t* src = msg + 2;
  *id = ((char*)msg)[1];
  memmove(ciphertext, src, len);
}

void printShareMsg(ShareMsg* share_msg){
  printf("id: %d\n", share_msg->id);
  printf("nonce1: ");print_char_arr(share_msg->nonce1, 16);
  printf("nonce2: ");print_char_arr(share_msg->nonce2, 16);
}

void handle_share_message(void* msg, struct recive_func_arg* rfa, int DEBUG){
  ShareMsg share_msg = {0};char id;size_t clen = 64;size_t mlen;
  __uint8_t* ciphertext = (__uint8_t*)malloc(clen);
  memset(ciphertext, 0, clen);
  pre_share_message(msg, ciphertext, clen, &id, DEBUG);
  AuthNode* p = searchList(rfa->head, id);    
  if (p == NULL){
    printf("Dont find the id\n");
    return;
  }
  if(p->flag != 1){
    printf("have not authed\n");
    return;
  }
  my_sm4_cbc_padding_decrypt(p->sessionkey, Sm4_iv, ciphertext, clen, (__uint8_t*)&share_msg, &mlen, DEBUG);
  if (DEBUG){
    printf("Share_msg:\n");
    printShareMsg(&share_msg);
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
      generate_session_key(p->sessionkey, share_msg.nonce1, share_msg.nonce2, 16);
      printf("Recive Share Msg; Authed drone-%d\n", share_msg.id);
      if (DEBUG)
        printAuthtable(rfa->head);
    }
  }
  else{   //未认证过
    p = insertNode(rfa->head, share_msg.id, share_msg.nonce1, share_msg.nonce2, 0, 1, 1);
    generate_session_key(p->sessionkey, share_msg.nonce1, share_msg.nonce2, 16);
    printf("Recive Share Msg; Authed drone-%d\n", share_msg.id);
    if (DEBUG)
      printAuthtable(rfa->head);
  }
}

void generate_update_msg(UpdateMsg* update_msg, char src_id, char dest_id, __uint8_t* newnonce, size_t noncelen){
  update_msg->src_id = src_id;
  update_msg->dest_id = dest_id;
  strncpy(update_msg->newnonce, newnonce, noncelen);
}

void printUpdateMsg(UpdateMsg* update_msg){
  printf("src_id : %d\n", update_msg->src_id);
  printf("dest_id: %d\n", update_msg->dest_id);
  printf("newnonce: ");print_char_arr(update_msg->newnonce, update_msg->noncelen);
}

void send_update_msg(int cfd, char src_id, UpdateMsg* update_msg, int mlen, unsigned char* Dest_IP, int Dest_PORT, __uint8_t* Sm4_key){
  size_t clen = 64;
  //__uint8_t* ciphertext = (__uint8_t*) malloc (clen);
  __uint8_t ciphertext[clen];
  memset(ciphertext, 0, clen);
  my_sm4_cbc_padding_encrypt(Sm4_key, Sm4_iv, (__uint8_t*)update_msg, mlen, ciphertext, &clen, 0);
  //__uint8_t* msg = (__uint8_t*) malloc (clen+1);
  __uint8_t msg[clen+1];
  memset(msg, 0 , clen+1);
  add_byte(msg, (void*)ciphertext, clen, src_id);
  send_padding_msg(cfd, (void*)msg, clen+1, 0x3, Dest_IP, Dest_PORT);
  //free(msg);
}

void Update(int cfd, char src_id, Drone* alldrone, AuthNode* head, Response* response){
  AuthNode* node = head->next;
  UpdateMsg update_msg = {0};
  update_msg.noncelen = 16;
  __uint8_t nonce[update_msg.noncelen];
  rand_bytes(nonce, update_msg.noncelen);
  while(node != NULL){
    if (node->flag == 1){
      update_msg.src_id = src_id;
      update_msg.dest_id = node->id;
      update_msg.index = 1;
      update_msg.noncelen = 16;
      strncpy(update_msg.newnonce, nonce, update_msg.noncelen);
      //printf("Update msg:\n");printUpdateMsg(&update_msg);
      send_update_msg(cfd, src_id, &update_msg, sizeof(update_msg), alldrone[node->id - 1].IP, alldrone[node->id - 1].PORT, node->sessionkey);
      
      response[response[0].num].id = node->id;
      response[response[0].num].isresponsed = 0;
      response[0].num++;
      
      if (node->index == 1){
        memset(node->nonce1, 0, 16);
        strncpy(node->nonce1, nonce, 16);
      }
      else if (node->index == 2){
        memset(node->nonce2, 0, 16);
        strncpy(node->nonce1, node->nonce2, 16);
        memset(node->nonce1, 0, 16);
        strncpy(node->nonce1, nonce, 16);
      }
    }
    memset((void* )&update_msg, 0, sizeof(update_msg));
    node = node->next;
  }
}

void pre_update_message(void* msg, __uint8_t* ciphertext, int len, char* id, int DEBUG){
  __uint8_t* src = msg + 2;
  *id = ((char*)msg)[1];
  memmove(ciphertext, src, len);
}

void handle_update_message(void* msg, struct recive_func_arg* rfa, int DEBUG){
  UpdateMsg update_msg = {0};char id;size_t clen = 64;size_t mlen;__uint8_t nonce[16];
  __uint8_t* ciphertext = (__uint8_t*)malloc(clen);
  memset(ciphertext, 0, clen);
  pre_update_message(msg, ciphertext, clen, &id, DEBUG);
  AuthNode* p = searchList(rfa->head, id);    
  if (p == NULL){
    printf("Dont find drone-%d\n", id);
    return;
  }
  if(p->flag != 1){
    printf("have not authed\n");
    return;
  }
  my_sm4_cbc_padding_decrypt(p->sessionkey, Sm4_iv, ciphertext, clen, (__uint8_t*)&update_msg, &mlen, DEBUG);
  if (DEBUG){
    printf("Update_msg:\n");
    printUpdateMsg(&update_msg);
  }
  if (update_msg.index == 1){
    p = searchList(rfa->head, update_msg.src_id);
    if (p == NULL){
      printf("update error!\n");
      return;
    }
    UpdateMsg response_update_msg = {0};
    rand_bytes(nonce, 16);

    //response
    response_update_msg.src_id = update_msg.dest_id;
    response_update_msg.dest_id = update_msg.src_id;
    response_update_msg.index = 2;
    response_update_msg.noncelen = 16;
    strncpy(response_update_msg.newnonce, nonce, response_update_msg.noncelen);
    send_update_msg(rfa->sock_fd, update_msg.dest_id, &response_update_msg, sizeof(response_update_msg), rfa->alldrone[update_msg.src_id -1].IP, rfa->alldrone[update_msg.src_id -1].PORT, p->sessionkey);
    printf("send response update msg to drone-%d\n", update_msg.src_id);
    printf("response_msg:\n");printUpdateMsg(&response_update_msg);
    memset(p->nonce1, 0, 16);memset(p->nonce2, 0, 16);memset(p->sessionkey, 0, 16);
    strncpy(p->nonce1, update_msg.newnonce,update_msg.noncelen);
    strncpy(p->nonce2, nonce, 16);
    generate_session_key(p->sessionkey, p->nonce1, p->nonce2, 16);
    
    p->index = 1;
    p->flag = 1;
    printf("drone-%d update success\n", update_msg.src_id);
    printf("new session key is ");print_char_arr(p->sessionkey, 16);
    //printf("Auth Table:\n");
    //printAuthtable(rfa->head);
  }

  else if (update_msg.index == 2){  //response
    p = searchList(rfa->head, update_msg.src_id);
    if (p == NULL){
      printf("update error!\n");
      return;
    }
    Response* response = response_find(rfa->response, update_msg.src_id);
    if (response == NULL){
      printf("response error!\n");
      return;
    }
    response->isresponsed = 1;
    printf("recieve update response message of drone-%d\n", update_msg.src_id);
    memset(p->nonce2, 0, 16);
    strncpy(p->nonce2, update_msg.newnonce, update_msg.noncelen);
    generate_session_key(p->sessionkey, p->nonce1, p->nonce2, 16);
    printf("drone-%d update success\n", update_msg.src_id);
    printf("new session key is ");print_char_arr(p->sessionkey, 16);
    //printf("Auth Table:\n");
    //printAuthtable(rfa->head);
    if (response_check(rfa->response)){
      printf("recived all response. Start Sharing\n");
      response_init(rfa->response, 10);
      Update_After_Share(rfa->sock_fd, rfa->my_index + 1, rfa->head, rfa->alldrone);
    }
  }
}

void printUpdateShareMsg(UpdateShareMsg* update_share_msg){
  printf("id:");print_char_arr(update_share_msg->id, update_share_msg->num);
  printf("nonce:");print_char_arr(update_share_msg->nonce, update_share_msg->num*16);
}

void pre_update_share_message(void* msg, __uint8_t* ciphertext, int len, char* id, int DEBUG){
  __uint8_t* src = msg + 2;
  *id = ((char*)msg)[1];
  memmove(ciphertext, src, len);
}

void send_update_share_msg(int cfd, char src_id, UpdateShareMsg* update_share_msg, int mlen, unsigned char* Dest_IP, int Dest_PORT, __uint8_t* Sm4_key){
  size_t clen = 200;
  //__uint8_t* ciphertext = (__uint8_t*) malloc (clen);
  __uint8_t ciphertext[clen];
  memset(ciphertext, 0, clen);
  my_sm4_cbc_padding_encrypt(Sm4_key, Sm4_iv, (__uint8_t*)update_share_msg, mlen, ciphertext, &clen, 0);
  //__uint8_t* msg = (__uint8_t*) malloc (clen+1);
  __uint8_t msg[clen+1];
  memset(msg, 0 , clen+1);
  add_byte(msg, (void*)ciphertext, clen, src_id);
  send_padding_msg(cfd, (void*)msg, clen+1, 0x4, Dest_IP, Dest_PORT);
  //free(msg);
}

void Update_After_Share(int cfd, char src_id, AuthNode* head, Drone* alldrone){
  UpdateShareMsg update_share_msg = {0};
  int i = 0;
  AuthNode* node = head->next;
  while(node != NULL){
    update_share_msg.id[i] = node->id;
    if(node->index == 1){
      strncat(update_share_msg.nonce, node->nonce1, 16);
    }
    else if (node->index == 2){
      strncat(update_share_msg.nonce, node->nonce2, 16);
    }
    i++;
    node = node->next;
  }
  update_share_msg.num = i;
  node = head->next;
  while(node != NULL){
    send_update_share_msg(cfd, src_id, &update_share_msg, sizeof(update_share_msg), alldrone[node->id - 1].IP, alldrone[node->id - 1].PORT, node->sessionkey);
    node = node->next;
  }
}

void handle_update_share_msg(void* msg, struct recive_func_arg* rfa, int DEBUG){
  UpdateShareMsg update_share_msg = {0};char id;size_t clen = 200;size_t mlen;
  __uint8_t* ciphertext = (__uint8_t*)malloc(clen);
  memset(ciphertext, 0, clen);
  pre_update_share_message(msg, ciphertext, clen, &id, DEBUG);
  AuthNode* p = searchList(rfa->head, id);    
  if (p == NULL){
    printf("Dont find drone-%d\n", id);
    return;
  }
  if(p->flag != 1){
    printf("have not authed\n");
    return;
  }
  my_sm4_cbc_padding_decrypt(p->sessionkey, Sm4_iv, ciphertext, clen, (__uint8_t*)&update_share_msg, &mlen, DEBUG);
  if (DEBUG){
    printf("Update_msg:\n");
    printUpdateShareMsg(&update_share_msg);
  }
  __uint8_t mynonce[16];memset(mynonce, 0, 16);
  if (p->index == 1)
    strncpy(mynonce, p->nonce1, 16);
  else if (p->index == 2)
    strncpy(mynonce, p->nonce2, 16);
  p = NULL;
  int i = 0;char my_id = rfa->my_index + 1;char tmp;
  
  for (i = 0; i < update_share_msg.num; i++){
    tmp = update_share_msg.id[i];
    if (tmp != my_id){
      p = searchList(rfa->head, tmp);
      if (p != NULL){ //之前认证过
        p->flag = 1;
        if (p->index == 1){
          memset(p->nonce2, 0, 16);
          strncpy(p->nonce2, update_share_msg.nonce + i*16, 16);
          memset(p->nonce1, 0, 16);
          strncpy(p->nonce1, mynonce, 16);
        }
        else if (p->index == 2){
          memset(p->nonce1, 0, 16);
          strncpy(p->nonce1, update_share_msg.nonce + i*16, 16);
          memset(p->nonce2, 0, 16);
          strncpy(p->nonce2, mynonce, 16);
        }
      }
      else{ //之前没认证
        p = insertNode(rfa->head, tmp, mynonce, update_share_msg.nonce + i*16, 0, 1, 1);
      }
      memset(p->sessionkey, 0, 16);
      generate_session_key(p->sessionkey, p->nonce1, p->nonce2, 16);
      printf("Update drone-%d\n", tmp);
    }
    tmp = -1;
  }
  printf("Update %d drone\n", i);
}