#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void mystrncat(char *dest, const char *src, size_t n1, size_t n2) {
    size_t dest_len = n1;
    size_t i;
    for (i = 0; i < n2; i++) {
        dest[dest_len + i] = src[i];
    }
    dest[dest_len + i] = '\0';
}


int main(){
    char s1[10] = {0x1, 0x0, 0x2};
    char s2[10] = {0x1, 0x0, 0x2};
    mystrncat(s2, s1, 2, 5);
    int i = 0;
    for (i = 0; i < 10; i++){
        printf("%02x", s2[i]);
    }

}