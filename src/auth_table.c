#include "../include/auth_table.h"
#include "../include/utils.h"
#include <string.h>

// 初始化链表
AuthNode *initList() {
    AuthNode *head = (AuthNode *)malloc(sizeof(AuthNode));
    head->id = -1; // 头节点不存储数据
    head->next = NULL;
    return head;
}

// 插入节点
AuthNode* insertNode(AuthNode *head, int id, __uint8_t* nonce1, __uint8_t* nonce2, char direct, char flag) {
    AuthNode *newNode = (AuthNode *)malloc(sizeof(AuthNode));
    newNode->id = id;
    if(nonce1 != NULL)
        strncpy(newNode->nonce1, nonce1, 16);
    if (nonce2 != NULL)
        strncpy(newNode->nonce2, nonce2, 16);
    newNode->direct = direct;
    newNode->flag = flag;
    newNode->next = head->next;
    head->next = newNode;
    return newNode;
}

//更新mynonce
void updateMynonce(AuthNode* node, __uint8_t* nonce1){
    strncpy(node->nonce1,nonce1, 16);
}

//更新othernonce
void updateOthernonce(AuthNode* node, __uint8_t* nonce2){
    strncpy(node->nonce2, nonce2, 16);
}

//更新flag
void updateFlag(AuthNode* node, char flag){
    node->flag = flag;
}

// 删除节点
void deleteNode(AuthNode *head, int id) {
    AuthNode *p = head->next;
    AuthNode *pre = head;
    while (p != NULL) {
        if (p->id == id) {
            pre->next = p->next;
            free(p);
            return;
        }
        pre = p;
        p = p->next;
    }
}

//查找链表
AuthNode* searchList(AuthNode* head, int id) {
    AuthNode* node = head;
    while (node != NULL) {
        if (node->id == id) {
            return node;
        }
        node = node->next;
    }
    return NULL;
}

// 打印链表
void printList(AuthNode *head) {
    AuthNode *p = head->next;
    while (p != NULL) {
        printf("id : %d\n", p->id);
        printf("nonce1: ");print_char_arr(p->nonce1, 16);
        printf("nonce2: ");print_char_arr(p->nonce2, 16);
        printf("flag : %d\n", p->flag);
        printf("direct : %d\n", p->direct);
        printf("sessionkey: ");print_char_arr(p->sessionkey, 16);
        p = p->next;
    }
    printf("\n");
}
