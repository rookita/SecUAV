#ifndef _MESSAGE
#define _MESSAGE
#include "socket.h"
#include "auth_table.h"
#include "crypto.h"
#include "utils.h"
#include "drone.h"
#include <stdlib.h>

#define NONCELEN 16

//认证消息
typedef struct auth_msg {
  char index; //认证进行到第几步
  char srcid;
  char destid;
  __uint8_t nonce[NONCELEN]; //随机数
  __uint8_t hmac[32];
  size_t noncelen;
}AuthMsg;

//随机数分享消息
typedef struct share_msg {
  char id[DRONENUM];
  __uint8_t nonce1[NONCELEN];
  __uint8_t nonce2[NONCELEN*DRONENUM];
  size_t num;
}ShareMsg;

//密钥更新消息
typedef struct update_msg {
  char src_id;
  char dest_id;
  char index; //send or response??
  __uint8_t newnonce[NONCELEN];
  size_t noncelen;
}UpdateMsg;

//密钥更新后的密钥共享消息
typedef struct update_share_msg{
  char id[DRONENUM];
  __uint8_t nonce[NONCELEN*DRONENUM];
  size_t num; 
}UpdateShareMsg;

//记录是否收到回复
typedef struct response{
  char id;
  char isresponsed;
  char num; 
}Response;

/*
generate_xxx_message():生成消息
pre_xxx_message():对消息进行预处理，即将消息的前几个字节（表示类型或发送端id）与消息主体分离
send_xxx_message():发送消息，会调用send_padding_msg()在消息前加上类型等信息
handle_xxx_message():消息处理函数

Share():某节点新认证节点后会调用Share函数将节点信息与信任域内其他节点共享，并将其他节点信息发送给该节点
Update():密钥更新消息
Share_after_Update():触发节点进行密钥更新后的密钥共享
*/
void response_init(Response* response, size_t len);
Response* response_find(Response* response, char id);
char response_check(Response* response);

void generate_auth_message(AuthMsg* auth_msg, int index, char srcid, char destid, __uint8_t* nonce, int len, __uint8_t* hmac);
void send_auth_message(int cfd, AuthMsg* auth_msg, int len, unsigned char* Dest_IP, int Dest_PORT);
void pre_auth_message(void*msg, AuthMsg* auth_msg, int auth_msg_len, int DEBUG);
void printAuthMsg(AuthMsg* auth_msg);
void handle_auth_message(void* msg, struct recive_func_arg* rfa, int DEBUG);

void generate_share_message(ShareMsg* share_msg, char id, __uint8_t* nonce1, __uint8_t* nonce2, size_t len);
void send_share_message(int cfd, char id, ShareMsg* share_msg, int mlen, unsigned char* Dest_IP, int Dest_PORT, __uint8_t* Sm4_key);
void pre_share_message(void* msg, __uint8_t* ciphertext, int len, char* id, int DEBUG);
void printShareMsg(ShareMsg* share_msg);
void share(int cfd, char id, AuthNode* head, Drone* alldrone, AuthNode* p);
void handle_share_message(void* msg, struct recive_func_arg* rfa, int DEBUG);


void generate_update_msg(UpdateMsg* update_msg, char src_id, char dest_id, __uint8_t* newnonce, size_t noncelen);
void printUpdateMsg(UpdateMsg* update_msg);
void send_update_msg(int cfd, char dest_id, UpdateMsg* update_msg, int mlen, unsigned char* Dest_IP, int Dest_PORT, __uint8_t* Sm4_key);
void Update(int cfd, char src_id, Drone* alldrone, AuthNode* head, Response* response);
void pre_update_message(void* msg, __uint8_t* ciphertext, int len, char* id, int DEBUG);
void handle_update_message(void* msg, struct recive_func_arg* rfa, int DEBUG);

void printUpdateShareMsg(UpdateShareMsg* update_share_msg);
void pre_update_share_message(void* msg, __uint8_t* ciphertext, int len, char* id, int DEBUG);
void send_update_share_msg(int cfd, char src_id, UpdateShareMsg* update_share_msg, int mlen, unsigned char* Dest_IP, int Dest_PORT, __uint8_t* Sm4_key);
void Share_after_Update(int cfd, char src_id, AuthNode* head, Drone* alldrone);
void handle_update_share_msg(void* msg, struct recive_func_arg* rfa, int DEBUG);
#endif