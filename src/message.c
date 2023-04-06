#include "../include/message.h"
#include "../include/gmssl/rand.h"
#include "../include/utils.h"


void generate_auth_message(AuthMsg* auth_msg, int rlen, int id, unsigned char* r){
    rand_bytes(r, rlen);
    auth_msg->noncelen = rlen;
    auth_msg->destid = id;
}

void printAuthMsg(AuthMsg* auth_msg){
    printf("index : %d\n", auth_msg->index);
    printf("srcid : %d\n", auth_msg->srcid);
    printf("destid : %d\n", auth_msg->destid);
    printf("mynonce : ");print_char_arr(auth_msg->mynonce, 16);
    printf("hmac : ");print_char_arr(auth_msg->hmac, 32);

}