#include <string.h>
#include "../include/auth_table.h"
#include "../include/utils.h"
#include "../include/message.h"

// 初始化链表
AuthNode* initList() {
    AuthNode* head = (AuthNode*)malloc(sizeof(AuthNode));
    head->id = -1;  // 头节点不存储数据
    head->flag = 0; // 头节点flag存储密钥更新次数
    head->next = NULL;
    return head;
}

// 插入节点
AuthNode* insertNode(AuthNode* head, char id, __uint8_t* nonce1,
                     __uint8_t* nonce2, char flag, char index, char direct) {
    AuthNode* newNode = (AuthNode*)malloc(sizeof(AuthNode));
    newNode->id = id;
    if (nonce1 != NULL) mystrncpy(newNode->nonce1, nonce1, NONCELEN);
    if (nonce2 != NULL) mystrncpy(newNode->nonce2, nonce2, NONCELEN);
    newNode->flag = flag;
    newNode->index = index;
    newNode->direct = direct;
    newNode->next = head->next;
    head->next = newNode;
    return newNode;
}

// 删除节点
void deleteNode(AuthNode* head, AuthNode* node) {
    AuthNode* p = head->next;
    AuthNode* pre = head;
    while (p != NULL) {
        if (p == node) {
            pre->next = p->next;
            node = p->next;
            free(p);
            return;
        }
        pre = p;
        p = p->next;
    }
}

// 清除重复项
void cleanTable(AuthNode* head) {
    AuthNode* node = head;
    AuthNode* pre = head;
    while (node != NULL) {
        if (node->flag != 1) { deleteNode(head, node); }
        node = node->next;
    }
}

// 根据ID查找认证状态表
AuthNode* searchList(AuthNode* head, char id) {
    AuthNode* node = head;
    while (node != NULL) {
        if (node->id == id) { return node; }
        node = node->next;
    }
    return NULL;
}

// 打印认证状态表
void printAuthtable(AuthNode* head, char onlyNum) {
    AuthNode* p = head->next;
    int sum = 0, num = 0;
    if (p != NULL && p->id < gV->myId)
        sum = p->nonce2[NONCELEN - 1];
    else if (p != NULL && p->id > gV->myId)
        sum = p->nonce1[NONCELEN - 1];
    if (!onlyNum)
        printf("| %-10s | %-10s | %-10s | %-32s | %-32s | %-32s |\n", "id",
               "Authed", "Direct", "nonce1", "nonce2", "sessionkey");
    while (p != NULL) {
        num += 1;
        if (p->id < gV->myId)
            sum += p->nonce1[NONCELEN - 1];
        else
            sum += p->nonce2[NONCELEN - 1];
        if (!onlyNum) {
            printf("| %-10d ", p->id);
            printf("| %-10s |", p->flag ? "True" : "Fasle");
            printf("| %-10s |", p->direct ? "True" : "Fasle");
            print_char_arr1(p->nonce1, 16);
            printf("  |");
            print_char_arr1(p->nonce2, 16);
            printf("  |");
            print_char_arr1(p->sessionkey, 16);
            printf("  |");
            printf("\n");
        }
        p = p->next;
    }
    printf("NUM: %d\n", num);
    printf("SUM: %d\n", sum);
    printf("\n");
}
