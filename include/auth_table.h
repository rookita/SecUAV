#ifndef _AUTH_TABLE_
#define _AUTH_TABLE_

#include <stdio.h>
#include <stdlib.h>

// 定义链表节点结构体
typedef struct authnode {
    char id;         
    unsigned char nonce1[16];
    unsigned char nonce2[16];
    unsigned char sessionkey[16];
    char direct; //是否为直接认证
    char flag;  //是否已经认证完成
    char index; //我的随机数是nonce1还是nonce2
    struct authnode *next;
} AuthNode;

AuthNode* initList();
AuthNode* insertNode(AuthNode* head, char id, __uint8_t* mynonce, __uint8_t* othernonce, char direct, char flag, char index);
void deleteNode(AuthNode* head, char id);
AuthNode* searchList(AuthNode* head, char id);
void updateMynonce(AuthNode* node, __uint8_t* mynonce);
void updateOthernonce(AuthNode* node, __uint8_t* othernonce);
void updateFlag(AuthNode* node, char flag);
void printList(AuthNode* head);

#endif