#include "../include/message.h"
#include "../include/gmssl/rand.h"

void generate_auth_message(AuthMsg* auth_msg, int rlen, int id, unsigned char* r){
    rand_bytes(r, rlen);
    auth_msg->noncelen = rlen;
    auth_msg->destid = id;
}