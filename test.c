#include <string.h>
#include <stdio.h>

void mystrncpy(char *__restrict __dest, const char *__restrict __src, size_t __n){
    memset(__dest, 0, __n);
    int i;
    for (i = 0; i < __n; i++){
        __dest[i] = __src[i];
    }
}

char *strncpy1(char *dest, const char *src, size_t n) {
    char *ret = dest;
    while (n-- && (*dest++ = *src++));
    if (n > 0) {
        while (--n) *dest++ = '\0';
    }
    return ret;
}

char *strncpy2(char *dest, const char *src, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        dest[i] = src[i];
    }
    for (; i < n; i++) {
        dest[i] = '\0';
    }
    return dest;
}

int main(){
    char s[10] = {0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0};
    char s1[10];
    //mystrncpy(s1, s, 10);
    strncpy2(s1, s, 10);
    int i;
    for (i = 0; i<10; i++ ){
        printf("%02x",s1[i]);
    }
    printf("\n");
}