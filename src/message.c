#include "../include/message.h"
#include "../include/gmssl/rand.h"
#include "../include/mytime.h"
#include <string.h>
#include <unistd.h>


//response初始化
void response_init(Response* response, size_t len){
  int i = 0;
  for (i = 0; i<len; i++){
    response[i].id = -1;
    response[i].isresponsed = -1;
    response[i].num = 0;
  }
}

//recieve_update初始化
void receiveupdate_init(ReceiveUpdate* receiveupdate, size_t len){
  int i = 0;
  for (i = 0; i<len; i++){
    receiveupdate[i].id = rfa->alldrone[i].id;
    receiveupdate[i].flag = 0;
  }
}

//寻找drone-{id}的response
Response* response_find(Response* response, char id){
  int i = 0;
  for (i = 0; i < response[0].num; i++){
    if (response[i].id == id)
      return &(response[i]);
  }
  return NULL;
}

//寻找drone-{id}的response
ReceiveUpdate* receiveupdate_find(ReceiveUpdate* receiveupdate, char id){
  int i = 0;
  for (i = 0; i < DRONENUM; i++){
    if (receiveupdate[i].id == id)
      return &(receiveupdate[i]);
  }
  return NULL;
}


//判断是否所有drone已经回复
char response_check(Response* response){
  printf("num: %d\n", response[0].num);
  int i = 0;
  for (i = 0; i < response[0].num; i++){
    if (response[i].isresponsed != 1)
      return 0;
  }
  return 1;
}

//生成认证消息
void generate_auth_message(AuthMsg* auth_msg, int index, char srcid, char destid, __uint8_t* nonce, int len, __uint8_t* hmac){
    auth_msg->index = index;
    auth_msg->srcid = srcid;
    auth_msg->destid = destid;
    auth_msg->noncelen = len;
    if (nonce != NULL)
        mystrncpy(auth_msg->nonce, nonce, len);
    if (hmac != NULL)
        mystrncpy(auth_msg->hmac, hmac, 32);
}

void send_auth_message(int cfd, AuthMsg* auth_msg, int len, unsigned char* Dest_IP, int Dest_PORT){
  send_padding_msg_thread(cfd, (void*) auth_msg, len, 0x1, Dest_IP, Dest_PORT);  //0x1表示auth_msg的类型
}

void printAuthMsg(AuthMsg* auth_msg){
    printf("index : %d\n", auth_msg->index);
    printf("srcid : %d\n", auth_msg->srcid);
    printf("destid : %d\n", auth_msg->destid);
    printf("nonce : ");print_char_arr(auth_msg->nonce, NONCELEN);
    printf("hmac : ");print_char_arr(auth_msg->hmac, 32);
}

void pre_auth_message(void*msg, AuthMsg* auth_msg, int auth_msg_len, int DEBUG){
    __uint8_t* src = msg + 1;
    memmove(auth_msg, src, auth_msg_len);
    if (DEBUG){
        printf("[info]>>>origin msg is ");print_char_arr(msg, auth_msg_len+1);
    }
} 

void handle_auth_message(void* msg, int DEBUG){
    AuthMsg auth_msg = {0};
    pre_auth_message(msg, &auth_msg, sizeof(auth_msg), DEBUG); //预处理
    if (auth_msg.destid == rfa->alldrone[rfa->my_id].id){
      if (DEBUG){
        printf("[info]>>>recive msg \n");
        printAuthMsg(&auth_msg);
      }
      switch(auth_msg.index){
        case 1: //reciver
          if (DEBUG)
            printf("##########CASE ONE DEBUG INFO START##########\n");
          __uint8_t nonce[NONCELEN];
          __uint8_t mbuf[34];
          __uint8_t hmac[32];
          if (auth_msg.srcid < auth_msg.destid){  //nonce1-srcid,nonce2-destid
            AuthNode* node = insertNode(rfa->head, auth_msg.srcid, auth_msg.nonce, NULL, 0, 1, 0);  //nonce1-srcid
            memset(nonce, 0, NONCELEN);memset(mbuf, 0, 2*NONCELEN+2);memset(hmac, 0, 32);
            rand_bytes(nonce, NONCELEN);
            mystrncpy(node->nonce2, nonce, NONCELEN);  //nonce2-destid
            mystrncat(mbuf, &auth_msg.srcid, 0, 1);mystrncat(mbuf, &auth_msg.destid, 1, 1);mystrncat(mbuf,node->nonce2, 2, NONCELEN);mystrncat(mbuf, node->nonce1, 2+NONCELEN, NONCELEN);
          }

          else{ //srcid > destid
            AuthNode* node = insertNode(rfa->head, auth_msg.srcid, NULL, auth_msg.nonce, 0, 1, 0);  //nonce1-destid
            memset(nonce, 0, NONCELEN);memset(mbuf, 0, 2*NONCELEN+2);memset(hmac, 0, 32);
            rand_bytes(nonce, NONCELEN);
            mystrncpy(node->nonce1, nonce, NONCELEN);  //nonce2-srcid
            mystrncat(mbuf, &auth_msg.srcid, 0, 1);mystrncat(mbuf, &auth_msg.destid, 1, 1);mystrncat(mbuf,node->nonce1, 2, NONCELEN);mystrncat(mbuf, node->nonce2, 2+NONCELEN, NONCELEN);
          }

          if (DEBUG){
            printf("[info]>>the mbuf of hmac is ");
            print_char_arr(mbuf, 2*NONCELEN+2);
          }

          my_sm3_hmac(hmac_key, sizeof(*hmac_key), mbuf, sizeof(*mbuf), hmac);
          AuthMsg my_auth_msg = {0};
          generate_auth_message(&my_auth_msg, 2, auth_msg.destid, auth_msg.srcid, nonce, NONCELEN, hmac);
          if (DEBUG){
            printf("[info]>>>will send msg \n");
            printAuthMsg(&my_auth_msg);
          }
          send_padding_msg_thread(rfa->sock_fd, (void*)&my_auth_msg, sizeof(my_auth_msg), 0x1, rfa->alldrone[auth_msg.srcid].IP, rfa->alldrone[auth_msg.srcid].PORT);
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
            __uint8_t* mbuf = (__uint8_t*) malloc (2*NONCELEN+2);
            __uint8_t* hmac = (__uint8_t*) malloc (32);
            memset(mbuf, 0, 2*NONCELEN+2);memset(hmac, 0, 32);
            if (auth_msg.srcid < auth_msg.destid){
              mystrncat(mbuf, &auth_msg.destid, 0, 1);mystrncat(mbuf, &auth_msg.srcid, 1, 1);mystrncat(mbuf, auth_msg.nonce, 2, NONCELEN);mystrncat(mbuf, p2->nonce2, 2+NONCELEN, NONCELEN);
              mystrncpy(p2->nonce1, auth_msg.nonce, NONCELEN);
            }
            else{ //destid < srcid
               mystrncat(mbuf, &auth_msg.destid, 0, 1);mystrncat(mbuf, &auth_msg.srcid, 1, 1);mystrncat(mbuf, auth_msg.nonce, 2, NONCELEN);mystrncat(mbuf, p2->nonce1, 2+NONCELEN, NONCELEN);
              mystrncpy(p2->nonce2, auth_msg.nonce, NONCELEN);
            }
             my_sm3_hmac(hmac_key, sizeof(*hmac_key), mbuf, sizeof(*mbuf), hmac);
             
             if ( isEqual(auth_msg.hmac, hmac, 32) ){   //验证通过
                if (DEBUG)
                  printf("[info]>>> case2 hmac right\n");
                p2->flag = 1;
                memset(mbuf, 0, 2*NONCELEN+2);memset(hmac, 0, 32);
                if (auth_msg.srcid < auth_msg.destid){
                  mystrncat(mbuf, &auth_msg.destid, 0, 1);mystrncat(mbuf, &auth_msg.srcid, 1, 1);mystrncat(mbuf, p2->nonce2, 2, NONCELEN);mystrncat(mbuf, p2->nonce1, 2+NONCELEN, NONCELEN);
                }
                else{ //srcid > destid
                  mystrncat(mbuf, &auth_msg.destid, 0, 1);mystrncat(mbuf, &auth_msg.srcid, 1, 1);mystrncat(mbuf, p2->nonce1, 2, NONCELEN);mystrncat(mbuf, p2->nonce2, 2+NONCELEN, NONCELEN);
                }
                my_sm3_hmac(hmac_key, sizeof(*hmac_key), mbuf, sizeof(*mbuf), hmac);
                /*
                if (DEBUG){
                  printf("mbuf: ");print_char_arr(mbuf, 34);
                  printf("id1: %d\n", auth_msg.destid);
                  printf("id2: %d\n", auth_msg.srcid);
                  printf("nonce1: ");print_char_arr(p2->mynonce, NONCELEN);
                  printf("nonce2: ");print_char_arr(p2->othernonce, NONCELEN);
                  printf("hmac: ");print_char_arr(hmac, 32);
                }
                */
                AuthMsg my_auth_msg = {0};
                generate_auth_message(&my_auth_msg, 3, auth_msg.destid, auth_msg.srcid, NULL, NONCELEN, hmac);                
                generate_session_key(p2->sessionkey, p2->nonce1, p2->nonce2, NONCELEN);
                p2->index = 2;
                if (DEBUG){
                  printf("[info]>>>will send auth msg: \n");
                  printAuthMsg(&my_auth_msg);
                }
                send_padding_msg_thread(rfa->sock_fd, (void*)&my_auth_msg, sizeof(my_auth_msg), 0x1, rfa->alldrone[(int)(auth_msg.srcid) ].IP, rfa->alldrone[(int)(auth_msg.srcid) ].PORT);
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
              __uint8_t* mbuf = (__uint8_t*) malloc (2*NONCELEN+2);
              __uint8_t* hmac = (__uint8_t*) malloc (32);
              memset(mbuf, 0, 2*NONCELEN+2);memset(hmac, 0, 32);
            if (auth_msg.srcid < auth_msg.destid){
              mystrncat(mbuf, &auth_msg.srcid, 0, 1);mystrncat(mbuf, &auth_msg.destid, 1, 1);mystrncat(mbuf,p3->nonce1, 2, NONCELEN);mystrncat(mbuf, p3->nonce2, 2+NONCELEN, NONCELEN);
            }
            else{
              mystrncat(mbuf, &auth_msg.srcid, 0, 1);mystrncat(mbuf, &auth_msg.destid, 1, 1);mystrncat(mbuf,p3->nonce2, 2, NONCELEN);mystrncat(mbuf, p3->nonce1, 2+NONCELEN, NONCELEN);
            }
             my_sm3_hmac(hmac_key, sizeof(*hmac_key), mbuf, sizeof(*mbuf), hmac);
             if ( isEqual(auth_msg.hmac, hmac, 32) ){   //验证通过
                if (DEBUG)
                  printf("[info]>>> hmac right\n");
                generate_session_key(p3->sessionkey, p3->nonce1, p3->nonce2, NONCELEN);
                p3->flag = 1;
                p3->index = 3;
                p3->direct = 1;
                printf("drone-%d auth success!\n", auth_msg.srcid);                
                __uint8_t m[2*NONCELEN];memset(m, 0, 2*NONCELEN);
                mystrncat(m, p3->nonce1, 0, NONCELEN);mystrncat(m, p3->nonce2, NONCELEN, NONCELEN);
                AuthMsg my_auth_msg = {0};
                generate_auth_message(&my_auth_msg, 4, auth_msg.destid, auth_msg.srcid, NULL, NONCELEN, NULL); 
                my_sm4_cbc_encrypt(p3->sessionkey, Sm4_iv, m, 2*NONCELEN, my_auth_msg.hmac, DEBUG);
                if (DEBUG){
                  printf("[info]>>>will send auth msg: \n");
                  printAuthMsg(&my_auth_msg);
                }
                send_padding_msg_thread(rfa->sock_fd, (void*)&my_auth_msg, sizeof(my_auth_msg), 0x1, rfa->alldrone[(int)(auth_msg.srcid) ].IP, rfa->alldrone[(int)(auth_msg.srcid) ].PORT);
                if (DEBUG){
                  printf("[info]>> auth table \n");
                  printAuthtable(rfa->head);
                }
                share(rfa->sock_fd, rfa->alldrone[rfa->my_id].id, rfa->head, rfa->alldrone, p3, 0, -1, DEBUG);
             }
              else {
                printf("[info]>>>case3 hmac is not equal!\n");
                printf("[info]>>>compute_hmac is ");print_char_arr(hmac, 32);
                printf("[info]>>>recive_hmac is ");print_char_arr(auth_msg.hmac, 32);
                if (DEBUG){
                  printf("mbuf: ");print_char_arr(mbuf, 34);
                  printf("id1: %d\n", auth_msg.srcid);
                  printf("id2: %d\n", auth_msg.destid);
                  printf("nonce1: ");print_char_arr(p3->nonce1, NONCELEN);
                  printf("nonce2: ");print_char_arr(p3->nonce2, NONCELEN);
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
        case 4:
          AuthNode* p4 = searchList(rfa->head, auth_msg.srcid);
          if (DEBUG)
            printf("##########CASE FOUR DEBUG INFO START##########\n");
          if (p4 != NULL){
            __uint8_t* m = (__uint8_t*)malloc(2*NONCELEN);memset(m, 0, 2*NONCELEN);
            __uint8_t* mm = (__uint8_t*)malloc(2*NONCELEN);memset(mm, 0, 2*NONCELEN);
            mystrncat(mm, p4->nonce1, 0, NONCELEN);mystrncat(mm, p4->nonce2, NONCELEN, NONCELEN);
            my_sm4_cbc_decrypt(p4->sessionkey, Sm4_iv, auth_msg.hmac, 2*NONCELEN, m, DEBUG);
            if (strncmp(m, mm, 2*NONCELEN) == 0) {//相等
              p4->flag = 1;
              p4->direct = 1;
              p4->index = 4;
              printf("drone-%d auth success!\n", auth_msg.srcid);
              share(rfa->sock_fd, rfa->alldrone[rfa->my_id].id, rfa->head, rfa->alldrone, p2, 0, -1, DEBUG);
              if (DEBUG){
                printf("[info]>> auth table is \n");
                printAuthtable(rfa->head);
              }
            }
            else{
              printf("case4 not equal!\n");
              printf("m: ");print_char_arr(m, 2*NONCELEN);
              printf("mm: ");print_char_arr(mm, 2*NONCELEN);
            }
            free(m);free(mm);
          }
          if (DEBUG)
            printf("##########CASE FOUR DEBUG INFO END##########\n");
          break;
      }
    }
}

//生成分享给已认证节点的共享消息
void generate_share_message(ShareMsg* share_msg, char id, __uint8_t* nonce1, __uint8_t* nonce2, size_t len){
  share_msg->id[0] = id;
  share_msg->num = 1;
  mystrncpy(share_msg->nonce1, nonce1, len);
  mystrncpy(share_msg->nonce2, nonce2, len);
}

void send_share_message(int cfd, char dest_id, ShareMsg* share_msg, int mlen, unsigned char* Dest_IP, int Dest_PORT, __uint8_t* Sm4_key, char DEBUG){
  //__uint8_t* ciphertext = (__uint8_t*) malloc (clen);
  __uint8_t ciphertext[mlen];
  memset(ciphertext, 0, mlen);
  my_sm4_cbc_encrypt(Sm4_key, Sm4_iv, (__uint8_t*)share_msg, mlen, ciphertext, DEBUG);
  //my_sm4_cbc_padding_encrypt(Sm4_key, Sm4_iv, (__uint8_t*)share_msg, mlen, ciphertext, &clen, 0);
  //__uint8_t* msg = (__uint8_t*) malloc (clen+1);
  __uint8_t msg[mlen+1];
  memset(msg, 0 , mlen+1);
  add_byte(msg, (void*)ciphertext, mlen, dest_id);
  send_padding_msg_thread(cfd, (void*)msg, mlen+1, 0x2, Dest_IP, Dest_PORT);
  //free(msg);
}

//发送share消息, p为刚认证的节点
void share(int cfd, char my_id, AuthNode* head, Drone* alldrone, AuthNode* p, char type, char dont_share, char DEBUG){
  AuthNode* node = head->next;
  ShareMsg share_msg_to_node, share_msg_to_p = {0};
  if (type == 0){
    int i = 0;
    if (p->id < my_id){
      mystrncpy(share_msg_to_p.nonce1, p->nonce1, NONCELEN);
    }
    else{
      mystrncpy(share_msg_to_p.nonce1, p->nonce2, NONCELEN);
    }
    while(node != NULL){
      if (node != p && node->flag == 1 && node->id != dont_share){
        share_msg_to_p.id[i] = node->id;
        if (node->id < my_id){
        mystrncat(share_msg_to_p.nonce2, node->nonce1, i*NONCELEN, NONCELEN);
        }
        else{
          mystrncat(share_msg_to_p.nonce2, node->nonce2, i*NONCELEN, NONCELEN);
        }  
        i++;
      }
      node = node->next;
    }
    share_msg_to_p.num = i;
    //分享给刚认证的节点
    //printShareMsg(&share_msg_to_p);
    if (i != 0){
      send_share_message(cfd, my_id, &share_msg_to_p, sizeof(share_msg_to_p), alldrone[p->id].IP, alldrone[p->id].PORT, p->sessionkey, DEBUG);
      printf("Send Share Msg to drone-%d\n", p->id);
    }
  }
  node = head->next;
  //给其他分享刚认证节点
  while (node != NULL){
    if (node != p && node->flag == 1 && node->direct == 1 && node->id != dont_share){     //对其他节点分享刚认证节点
      memset(&share_msg_to_node, sizeof(share_msg_to_node), 0);
      if (node->id < my_id && p->id < my_id){
        generate_share_message(&share_msg_to_node, p->id, node->nonce1, p->nonce1, NONCELEN); //发送给node
      }
      else if (node->id < my_id && p->id > my_id){
        generate_share_message(&share_msg_to_node, p->id, node->nonce1, p->nonce2, NONCELEN); //发送给node
      }
      else if (node->id > my_id && p->id < my_id){
        generate_share_message(&share_msg_to_node, p->id, node->nonce2, p->nonce1, NONCELEN); //发送给node
      }
      else if (node->id > my_id && p->id > my_id){
        generate_share_message(&share_msg_to_node, p->id, node->nonce2, p->nonce2, NONCELEN); //发送给node
      }
      send_share_message(cfd, my_id, &share_msg_to_node, sizeof(share_msg_to_node), alldrone[node->id].IP, alldrone[node->id].PORT, node->sessionkey, DEBUG);
      printf("Send Share Msg to drone-%d\n", node->id);   
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
  printf("id: ");print_char_arr(share_msg->id, DRONENUM);
  printf("nonce1: ");print_char_arr(share_msg->nonce1, NONCELEN);
  printf("nonce2: ");print_char_arr(share_msg->nonce2, DRONENUM * NONCELEN);
  printf("num: %ld\n", share_msg->num);
}

//处理share消息
void handle_share_message(void* msg, const int DEBUG){
  ShareMsg share_msg = {0};char id;size_t clen = sizeof(share_msg);size_t mlen;
  char my_id = rfa->alldrone[rfa->my_id].id;
  __uint8_t* ciphertext = (__uint8_t*)malloc(clen);
  memset(ciphertext, 0, clen);
  pre_share_message(msg, ciphertext, clen, &id, DEBUG);
  AuthNode* p = searchList(rfa->head, id);
  AuthNode* pp = p;    
  if (p == NULL){
    printf("Dont find the id\n");
    return;
  }
  if(p->flag != 1){
    printf("have not authed\n");
    return;
  }
  my_sm4_cbc_decrypt(p->sessionkey, Sm4_iv, ciphertext, clen, (__uint8_t*)&share_msg, DEBUG);
  //my_sm4_cbc_padding_decrypt(p->sessionkey, Sm4_iv, ciphertext, clen, (__uint8_t*)&share_msg, &mlen, DEBUG);
  if (DEBUG){
    printf("Share_msg:\n");
    printShareMsg(&share_msg);
  }
  int i = 0;
  for (i = 0; i < share_msg.num; i++){
    p = searchList(rfa->head, share_msg.id[i]);
    if (p != NULL){
      if (p->flag == 1)
        printf("drone-%d aleardy auth!\n", share_msg.id[i]);
      else{
        memset(p->nonce1, 0, NONCELEN);memset(p->nonce2, 0, NONCELEN);
        if (p->id < my_id){
          mystrncpy(p->nonce1, share_msg.nonce2 + i * NONCELEN, NONCELEN); //p的nonce
          mystrncpy(p->nonce2, share_msg.nonce1, NONCELEN); //mynonce
        }
        else{ //p->id > my_id
          mystrncpy(p->nonce1, share_msg.nonce1, NONCELEN);
          mystrncpy(p->nonce2, share_msg.nonce2 + i * NONCELEN, NONCELEN);
        }
        p->flag = 1;
        generate_session_key(p->sessionkey, p->nonce1, p->nonce2, NONCELEN);
        printf("Recive Share Msg; Authed drone-%d\n", share_msg.id[i]);
        printf("Share drone-%d to Others\n", p->id);
        share(rfa->sock_fd, my_id, rfa->head, rfa->alldrone, p, 1, pp->id, DEBUG);
        if (DEBUG)
          printAuthtable(rfa->head);
      }
    }
    else{
      if (share_msg.id[i] < my_id){
        p = insertNode(rfa->head, share_msg.id[i], share_msg.nonce2 + i * NONCELEN, share_msg.nonce1, 1, -1, 0);
      }
      else{ //p->id > my_id
        p = insertNode(rfa->head, share_msg.id[i], share_msg.nonce1, share_msg.nonce2 + i * NONCELEN, 1, -1, 0);
      }
      generate_session_key(p->sessionkey, p->nonce1, p->nonce2, NONCELEN);
      printf("Recive Share Msg; Authed drone-%d\n", share_msg.id[i]);
      printf("Share drone-%d to Others\n", p->id);
      share(rfa->sock_fd, my_id, rfa->head, rfa->alldrone, p, 1, pp->id, DEBUG);
      if (DEBUG)
        printAuthtable(rfa->head);
    }
  }
  free(ciphertext);
}

void generate_update_msg(UpdateMsg* update_msg, char index, char src_id, char dest_id, __uint8_t* newnonce, size_t noncelen){
  update_msg->index = index;
  update_msg->src_id = src_id;
  update_msg->dest_id = dest_id;
  update_msg->noncelen = NONCELEN;
  mystrncpy(update_msg->newnonce, newnonce, noncelen);
}

void printUpdateMsg(UpdateMsg* update_msg){
  printf("src_id : %d\n", update_msg->src_id);
  printf("dest_id: %d\n", update_msg->dest_id);
  printf("newnonce: ");print_char_arr(update_msg->newnonce, update_msg->noncelen);
}

void send_update_msg(int cfd, char src_id, UpdateMsg* update_msg, int mlen, unsigned char* Dest_IP, int Dest_PORT, __uint8_t* Sm4_key, char DEBUG){
  size_t clen = mlen;
  //__uint8_t* ciphertext = (__uint8_t*) malloc (clen);
  __uint8_t ciphertext[clen];
  memset(ciphertext, 0, clen);
  my_sm4_cbc_encrypt(Sm4_key, Sm4_iv, (__uint8_t*)update_msg, mlen, ciphertext, DEBUG);
  //my_sm4_cbc_padding_encrypt(Sm4_key, Sm4_iv, (__uint8_t*)update_msg, mlen, ciphertext, &clen, 0);
  //__uint8_t* msg = (__uint8_t*) malloc (clen+1);
  __uint8_t msg[clen+1];
  memset(msg, 0 , clen+1);
  add_byte(msg, (void*)ciphertext, clen, src_id);
  send_padding_msg_thread(cfd, (void*)msg, clen+1, 0x3, Dest_IP, Dest_PORT);
  //free(msg);
}

//对某一特定无人机发送密钥更新消息,不对response作修改
void updateToOne(char dest_id, char DEBUG){
  AuthNode* node = rfa->head->next;
  UpdateMsg update_msg = {0};
  update_msg.noncelen = NONCELEN;
  generate_update_msg(&update_msg, 0x1, rfa->my_id, node->id, updateif->nonce, NONCELEN);
  while(node != NULL){
    if (node->id == dest_id){
      send_update_msg(rfa->sock_fd, rfa->my_id, &update_msg, sizeof(update_msg), rfa->alldrone[dest_id].IP, rfa->alldrone[dest_id].PORT, node->sessionkey, DEBUG);
      break;
    }
    node = node -> next;
  }
  if (DEBUG){
    printf("send update msg to drone-%d success\n", dest_id);
  }
}

//发送心跳包，进行密钥更新
void Update(int cfd, char src_id, Drone* alldrone, AuthNode* head, Response* response, char DEBUG){
  AuthNode* node = head->next;
  UpdateMsg update_msg = {0};
  update_msg.noncelen = NONCELEN;
  __uint8_t nonce[update_msg.noncelen];
  rand_bytes(nonce, update_msg.noncelen);
  memset(updateif->nonce, 0, NONCELEN);
  mystrncpy(updateif->nonce, nonce, NONCELEN);
  generate_update_msg(&update_msg, 0x1, src_id, node->id, nonce, NONCELEN); //触发节点对其他节点使用同一个随机数
  int i = 0;
  while (node != NULL){
    if (node -> flag == 1)
      i++;
    node = node -> next;
  }
  node = head->next;
  response[0].num = i;
  i = 0;
  while(node != NULL){
    if (node->flag == 1){ //已认证节点
      update_msg.dest_id = node->id;
      //printf("Update msg:\n");printUpdateMsg(&update_msg);
      response[i].id = node->id;  //记录接收到的响应
      response[i].isresponsed = 0;
      i++;
      send_update_msg(cfd, src_id, &update_msg, sizeof(update_msg), alldrone[node->id].IP, alldrone[node->id].PORT, node->sessionkey, DEBUG);
      printf("send update msg to drone-%d\n", node->id);
      if (node->id < src_id){ //id小的为nonce1
        memset(node->nonce2, 0, NONCELEN);
        mystrncpy(node->nonce2, nonce, NONCELEN);
      }
      else {  //node->id > src_id
        memset(node->nonce1, 0, NONCELEN);
        mystrncpy(node->nonce1, nonce, NONCELEN);
      }
    }
    node = node->next;
  }
  pthread_t id;
  int ret = pthread_create(&id,NULL,listenUpdateResponse,NULL);
  if (-1 == ret) print_err("pthread_create failed", __LINE__, errno);
}

void pre_update_message(void* msg, __uint8_t* ciphertext, int len, char* id, int DEBUG){
  __uint8_t* src = msg + 2;
  *id = ((char*)msg)[1];
  memmove(ciphertext, src, len);
}

//处理密钥更新消息
void handle_update_message(void* msg, int DEBUG){
  UpdateMsg update_msg = {0};char id;size_t clen = sizeof(update_msg);size_t mlen;__uint8_t nonce[NONCELEN];
  __uint8_t* ciphertext = (__uint8_t*)malloc(clen);
  memset(ciphertext, 0, clen);
  pre_update_message(msg, ciphertext, clen, &id, DEBUG);
  AuthNode* p = searchList(rfa->head, id);    
  if (p == NULL){
    printf("Dont find drone-%d\n", id);
    return;
  }
  if(p->flag != 1){
    printf("dreone-%d have not authed\n", p->id);
    return;
  }
  my_sm4_cbc_decrypt(p->sessionkey, Sm4_iv, ciphertext, clen, (__uint8_t*)&update_msg, DEBUG);
  //my_sm4_cbc_padding_decrypt(p->sessionkey, Sm4_iv, ciphertext, clen, (__uint8_t*)&update_msg, &mlen, DEBUG);
  if (DEBUG){
    printf("Update_msg:\n");
    printUpdateMsg(&update_msg);
  }
  ReceiveUpdate* ru = receiveupdate_find(updateif->receiveupdate, id);
  if (ru == NULL){
    printf("illegal drone-%d!\n",id);
  }
  else{
    ru->flag = 1;
  }
  if (update_msg.index == 1){
    p = searchList(rfa->head, update_msg.src_id);
    if (p == NULL){
      printf("update error!\n");
      return;
    }
    UpdateMsg response_update_msg = {0};
    rand_bytes(nonce, NONCELEN);
    char my_id = update_msg.dest_id;
    //response
    generate_update_msg(&response_update_msg, 0x2, update_msg.dest_id, update_msg.src_id, nonce, NONCELEN);
    send_update_msg(rfa->sock_fd, update_msg.dest_id, &response_update_msg, sizeof(response_update_msg), rfa->alldrone[update_msg.src_id].IP, rfa->alldrone[update_msg.src_id].PORT, p->sessionkey, DEBUG);
    printf("send response update msg to drone-%d\n", update_msg.src_id);
    if (DEBUG)
      printf("response_msg:\n");printUpdateMsg(&response_update_msg);
    memset(p->nonce1, 0, NONCELEN);memset(p->nonce2, 0, NONCELEN);memset(p->sessionkey, 0, NONCELEN);
    if (p->id < my_id){
      mystrncpy(p->nonce1, update_msg.newnonce,NONCELEN);
      mystrncpy(p->nonce2, nonce, NONCELEN);
    }
    else{
      mystrncpy(p->nonce1, nonce, NONCELEN);
      mystrncpy(p->nonce2, update_msg.newnonce,NONCELEN);
    }
    generate_session_key(p->sessionkey, p->nonce1, p->nonce2, NONCELEN);
    p->flag = 1;
    p->direct = 1;
    printf("drone-%d update success\n", update_msg.src_id);
    printf("new session key is ");print_char_arr(p->sessionkey, NONCELEN);
    rfa->head->flag += 1;
    //printf("Auth Table:\n");
    //printAuthtable(rfa->head);
  }

  else if (update_msg.index == 2){  //response
    p = searchList(rfa->head, update_msg.src_id);
    if (p == NULL){
      printf("update error!\n");
      return;
    }
    Response* response = response_find(updateif->response, update_msg.src_id);
    if (response == NULL){
      printf("response error!\n");
      return;
    }
    response->isresponsed = 1;
    printf("recieve update response message of drone-%d\n", update_msg.src_id);
    if (update_msg.src_id < update_msg.dest_id){
      memset(p->nonce1, 0, NONCELEN);
      mystrncpy(p->nonce1, update_msg.newnonce, NONCELEN);
    }

    else{
      memset(p->nonce2, 0, NONCELEN);
      mystrncpy(p->nonce2, update_msg.newnonce, NONCELEN);
    }
    generate_session_key(p->sessionkey, p->nonce1, p->nonce2, NONCELEN);
    p->direct = 1;
    printf("drone-%d update success\n", update_msg.src_id);
    printf("new session key is ");print_char_arr(p->sessionkey, NONCELEN);
    //printf("Auth Table:\n");
    //printAuthtable(rfa->head);
    if (response_check(updateif->response)){
      printf("recived all response. Start Sharing\n");
      response_init(updateif->response, 10);
      rfa->head->flag += 1;
      Share_after_Update(rfa->sock_fd, rfa->my_id, rfa->head, rfa->alldrone, DEBUG);
    }
  }
}

void printUpdateShareMsg(UpdateShareMsg* update_share_msg){
  printf("num: %ld\n", update_share_msg->num);
  printf("id: ");print_char_arr(update_share_msg->id, update_share_msg->num);
  printf("nonce: ");print_char_arr(update_share_msg->nonce, update_share_msg->num*NONCELEN);
}

void pre_update_share_message(void* msg, __uint8_t* ciphertext, int len, char* id, int DEBUG){
  __uint8_t* src = msg + 2;
  *id = ((char*)msg)[1];
  memmove(ciphertext, src, len);
}

void send_update_share_msg(int cfd, char src_id, UpdateShareMsg* update_share_msg, int mlen, unsigned char* Dest_IP, int Dest_PORT, __uint8_t* Sm4_key, char DEBUG){
  size_t clen = mlen;
  //__uint8_t* ciphertext = (__uint8_t*) malloc (clen);
  __uint8_t ciphertext[clen];
  memset(ciphertext, 0, clen);
  my_sm4_cbc_encrypt(Sm4_key, Sm4_iv, (__uint8_t*)update_share_msg, mlen, ciphertext, DEBUG);
  //my_sm4_cbc_padding_encrypt(Sm4_key, Sm4_iv, (__uint8_t*)update_share_msg, mlen, ciphertext, &clen, 1);
  __uint8_t msg[clen+1];
  memset(msg, 0 , clen+1);
  add_byte(msg, (void*)ciphertext, clen, src_id);
  send_padding_msg_thread(cfd, (void*)msg, clen+1, 0x4, Dest_IP, Dest_PORT);
}

//密钥更新完成发送分享消息
void Share_after_Update(int cfd, char src_id, AuthNode* head, Drone* alldrone, char DEBUG){
  UpdateShareMsg update_share_msg = {0};
  int i = 0;
  AuthNode* node = head->next;
  while(node != NULL){  //构造消息
    update_share_msg.id[i] = node->id;
    if(node->id < src_id){  //node的随机数为nonce1
      mystrncat(update_share_msg.nonce, node->nonce1, i*NONCELEN, NONCELEN);
    }
    else{
      mystrncat(update_share_msg.nonce, node->nonce2, i*NONCELEN, NONCELEN);
    }
    i++;
    node = node->next;
  }
  update_share_msg.num = i;
  node = head->next;

  while(node != NULL){  //发送消息
    send_update_share_msg(cfd, src_id, &update_share_msg, sizeof(update_share_msg), alldrone[node->id].IP, alldrone[node->id].PORT, node->sessionkey, DEBUG);
    node = node->next;
  }
  printf("Share after update success!\n");
  mysetittimer(updateif->updateinterval, updateif->updateinterval); //触发节点重置密钥更新时间
}

//处理密钥更新后的分享消息
void handle_update_share_msg(void* msg, int DEBUG){
  UpdateShareMsg update_share_msg = {0};char id;size_t clen = sizeof(update_share_msg);
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
  my_sm4_cbc_decrypt(p->sessionkey, Sm4_iv, ciphertext, clen, (__uint8_t*)&update_share_msg, DEBUG);
  //my_sm4_cbc_padding_decrypt(p->sessionkey, Sm4_iv, ciphertext, clen, (__uint8_t*)&update_share_msg, &mlen, DEBUG);
  if (DEBUG){
    printf("Update_Share_msg:\n");
    printUpdateShareMsg(&update_share_msg);
  }
  __uint8_t mynonce[NONCELEN];memset(mynonce, 0, NONCELEN);
  if (p->id < rfa->alldrone[rfa->my_id].id){
    mystrncpy(mynonce, p->nonce2, NONCELEN);
  }
  else{
    mystrncpy(mynonce, p->nonce1, NONCELEN);
  }
  p = NULL;
  int i = 0;char my_id = rfa->my_id;char tmp;
  for (i = 0; i < update_share_msg.num; i++){
    tmp = update_share_msg.id[i];
    if (tmp != my_id){  //不处理自己的nonce
      p = searchList(rfa->head, tmp);
      if (p != NULL){ //之前认证过
        p->flag = 1;
        p->direct = 0;  //只与发送消息者direct为1，方便后续Share
        if (tmp > my_id){ //nonce1为我的随机数
          memset(p->nonce2, 0, NONCELEN);
          mystrncpy(p->nonce2, update_share_msg.nonce + i*NONCELEN, NONCELEN);
          memset(p->nonce1, 0, NONCELEN);
          mystrncpy(p->nonce1, mynonce, NONCELEN);
        }
        else if (tmp < my_id){
          memset(p->nonce1, 0, NONCELEN);
          mystrncpy(p->nonce1, update_share_msg.nonce + i*NONCELEN, NONCELEN);
          memset(p->nonce2, 0, NONCELEN);
          mystrncpy(p->nonce2, mynonce, NONCELEN);
        }
      }
      else{ //之前没认证
        if (tmp < my_id){
          p = insertNode(rfa->head, tmp, update_share_msg.nonce + i*NONCELEN, mynonce, 1, -1, 0);
        }
        else{
           p = insertNode(rfa->head, tmp, mynonce, update_share_msg.nonce + i*NONCELEN, 1, -1, 0);
        }
      }
      memset(p->sessionkey, 0, NONCELEN);
      generate_session_key(p->sessionkey, p->nonce1, p->nonce2, NONCELEN);
      printf("Update drone-%d\n", tmp);
    }
    tmp = -1;
  }
  printf("Update %d drones\n", i);
  mysetittimer(updateif->updateinterval, updateif->updateinterval); //非触发节点重置密钥更新时间
  receiveupdate_init(updateif->receiveupdate, DRONENUM);
  if (DEBUG){
    printf("Auth table\n");
    printAuthtable(rfa->head);
  }
}


//定时发送节点检测和密钥更新消息
void regularUpdate(int sigum){
  printf("update times: %d\n", rfa->head->flag);
  char src_id = rfa->my_id;
  Response* response = updateif->response;
  AuthNode* node = rfa->head->next;
  char update_id = rfa->my_id;
  if (rfa->head->flag == 0){  //第一次更新选择认证表中ID最小的
    while(node != NULL){
      if (node->id <= update_id)
        update_id = node->id;
      node = node->next;
    }
  }

  else{ //其他情况随机指定
    node = rfa->head->next;
    int sum;
    if (node != NULL && node->id < rfa->my_id)
      sum = node->nonce2[NONCELEN - 1];
    else if (node != NULL && node->id > rfa->my_id)
      sum = node->nonce1[NONCELEN - 1];
    while (node != NULL){
      if (node->id < rfa->my_id)
        sum += node->nonce1[NONCELEN - 1];
      else
        sum += node->nonce2[NONCELEN - 1];
      node = node->next;
    }
    printf("sum: %d\n",sum);
    update_id = sum % DRONENUM + 1;
  }
  //sleep(1);
  printf("update id: %d\n", update_id);
  if (update_id == rfa->my_id){
    node = rfa->head->next;
    UpdateMsg update_msg = {0};
    update_msg.noncelen = NONCELEN;
    __uint8_t nonce[update_msg.noncelen];
    rand_bytes(nonce, update_msg.noncelen);
    generate_update_msg(&update_msg, 0x1, src_id, node->id, nonce, NONCELEN); //触发节点对其他节点使用同一个随机数

    int i = 0;
    while (node != NULL){
      if (node -> flag == 1)
        i++;
      node = node -> next;
    }
    node = rfa->head->next;
    response[0].num = i;
    i = 0;
    while(node != NULL){
      if (node->flag == 1){ //已认证节点
        update_msg.dest_id = node->id;
        //printf("Update msg:\n");printUpdateMsg(&update_msg);
        send_update_msg(rfa->sock_fd, src_id, &update_msg, sizeof(update_msg), rfa->alldrone[node->id].IP, rfa->alldrone[node->id].PORT, node->sessionkey, 1);
        response[i].id = node->id;  //记录接收到的响应
        response[i].isresponsed = 0;
        i++;
        if (node->id < src_id){ //id小的为nonce1
          memset(node->nonce2, 0, NONCELEN);
          mystrncpy(node->nonce2, nonce, NONCELEN);
        }
        else {  //node->id > src_id
          memset(node->nonce1, 0, NONCELEN);
          mystrncpy(node->nonce1, nonce, NONCELEN);
        }
      }
      node = node->next;
    }
    pthread_t id;
    int ret = pthread_create(&id,NULL,listenUpdateResponse,NULL);
    if (-1 == ret) print_err("pthread_create failed", __LINE__, errno);
  }
  else{ //其他无人机更新
    int i = 0;
    int frequency = 5;  //5秒钟检查一次
    int times = 3;  //3次过后直接认为该无人机丢失
    char flag = 0;
    ReceiveUpdate* ru = receiveupdate_find(updateif->receiveupdate, update_id);
    for (i = 0; i<times; i++){
      sleep(frequency);
      flag = ru->flag;
      if (flag == 1)
        return;
    }
    if (flag == 0){
      printf("drone-%d lost\n", update_id);
    }

  }
}

void* listenUpdateResponse(void* args){
  int frequency = 5;  //5秒钟检查一次
  int times = 3;  //3次过后直接认为该无人机丢失
  UpdateInfo* uinfo = updateif;
  char DEBUG = 1;
  int i = 0, j = 0, flag = 1;
  for (i = 0; i < times; i++){
    sleep(frequency);
    flag = 1;
    for (j = 0; j < uinfo->response[0].num; j++){
      if (uinfo->response[j].isresponsed != 1){
        printf("Resend update msg to drone-%d\n", uinfo->response[j].id);
        updateToOne(uinfo->response[j].id, DEBUG);
        flag = 0;
      }
    }
    if (flag == 1){
      return NULL;
    } 
  }
  for (j = 0; j < uinfo->response[0].num; j++){
    if (uinfo->response[j].isresponsed != 1){
      printf("drone-%d lost!\n", uinfo->response[j].id);
    }
  }
  return NULL;
}