#include "../include/message.h"
#include "../include/gmssl/rand.h"
#include "../include/utils.h"
#include <string.h>

void generate_auth_message(AuthMsg* auth_msg, int index, char srcid, char destid, __uint8_t* nonce, int len, __uint8_t* hmac){
    auth_msg->index = index;
    auth_msg->srcid = srcid;
    auth_msg->destid = destid;
    auth_msg->noncelen = len;
    if (nonce != NULL)
        strncat(auth_msg->mynonce, nonce, len);
    if (hmac != NULL)
        strncat(auth_msg->hmac, hmac, 32);
}

void pre_auth_message(void*msg, AuthMsg* auth_msg, int auth_msg_len, int DEBUG){
    char* src = msg + 1;
    memmove(auth_msg, src, auth_msg_len);
    if (DEBUG){
        printf("[info]>>>origin msg is ");print_char_arr(msg, auth_msg_len+1);
    }
} 

void printAuthMsg(AuthMsg* auth_msg){
    printf("index : %d\n", auth_msg->index);
    printf("srcid : %d\n", auth_msg->srcid);
    printf("destid : %d\n", auth_msg->destid);
    printf("mynonce : ");print_char_arr(auth_msg->mynonce, 16);
    printf("hmac : ");print_char_arr(auth_msg->hmac, 32);

}