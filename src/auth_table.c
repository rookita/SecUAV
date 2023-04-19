#include "../include/auth_table.h"
#include "../include/utils.h"
#include "../include/message.h"
#include <string.h>

// 初始化链表
AuthNode *initList() {
    AuthNode *head = (AuthNode *)malloc(sizeof(AuthNode));
    head->id = -1; // 头节点不存储数据
    head->next = NULL;
    return head;
}

// 插入节点
AuthNode* insertNode(AuthNode *head, char id, __uint8_t* nonce1, __uint8_t* nonce2, char flag, char index) {
    AuthNode *newNode = (AuthNode *)malloc(sizeof(AuthNode));
    newNode->id = id;
    if(nonce1 != NULL)
        strncpy(newNode->nonce1, nonce1, NONCELEN);
    if (nonce2 != NULL)
        strncpy(newNode->nonce2, nonce2, NONCELEN);
    newNode->flag = flag;
    newNode->index = index;
    newNode->next = head->next;
    head->next = newNode;
    return newNode;
}


// 删除节点
void deleteNode(AuthNode *head, char id) {
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
AuthNode* searchList(AuthNode* head, char id) {
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
void printAuthtable(AuthNode *head) {
    AuthNode *p = head->next;
    printf("| %-10s | %-10s | %-32s | %-32s | %-32s |\n", "id", "Authed", "nonce1", "nonce2", "sessionkey");
    while (p != NULL) {
        printf("| %-10d ", p->id);
        printf("| %-10s |", p->flag ? "True": "Fasle");
        print_char_arr1(p->nonce1, 16);printf("  |");
        print_char_arr1(p->nonce2, 16);printf("  |");
        print_char_arr1(p->sessionkey, 16);printf("  |");
        printf("\n");     
        p = p->next;
    }
    printf("\n");
}
