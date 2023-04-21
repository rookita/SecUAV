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
    char flag;  //是否已经认证完成
    char index; //认证完成了几步
    char direct;    //是否直接认证
    struct authnode *next;
} AuthNode;

AuthNode* initList();
AuthNode* insertNode(AuthNode *head, char id, __uint8_t* nonce1, __uint8_t* nonce2, char flag, char index, char direct);
void deleteNode(AuthNode* head, char id);
AuthNode* searchList(AuthNode* head, char id);
void printAuthtable(AuthNode* head);

#endif