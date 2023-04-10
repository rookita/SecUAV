#ifndef _MESSAGE
#define _MESSAGE

#include <stdlib.h>
#include "socket.h"
#include "auth_table.h"
#include "crypto.h"
#include "utils.h"

//认证消息
typedef struct auth_msg {
  char index; //认证进行到第几步
  char srcid;
  char destid;
  __uint8_t nonce[16]; //随机数
  __uint8_t hmac[32];
  size_t noncelen;
}AuthMsg;

typedef struct share_msg {
  char id;
  __uint8_t nonce1[16];
  __uint8_t nonce2[16];
  size_t noncelen;
}ShareMsg;

void generate_auth_message(AuthMsg* auth_msg, int index, char srcid, char destid, __uint8_t* nonce, int len, __uint8_t* hmac);
void send_auth_message(int cfd, AuthMsg* auth_msg, int len, unsigned char* Dest_IP, int Dest_PORT);
void pre_auth_message(void*msg, AuthMsg* auth_msg, int auth_msg_len, int DEBUG);
void printAuthMsg(AuthMsg* auth_msg);
void handle_auth_message(void* msg, struct recive_func_arg* rfa, int DEBUG);

void generate_share_message(ShareMsg* share_msg, char id, __uint8_t* nonce1, __uint8_t* nonce2, size_t len);
void send_share_message(int cfd, char id, ShareMsg* share_msg, int mlen, unsigned char* Dest_IP, int Dest_PORT, __uint8_t* Sm4_key);
void pre_share_message(void* msg, __uint8_t* ciphertext, int len, char* id, int DEBUG);
void share(int cfd, char id, AuthNode* head, Drone* alldrone, AuthNode* p);
void handle_share_message(void* msg, struct recive_func_arg* rfa, int DEBUG);

#endif