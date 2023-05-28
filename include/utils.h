#include <stdlib.h>
#include <stdio.h>

void print_char_arr(const unsigned char* a, size_t len);
void print_char_arr1(const unsigned char* a, size_t len);
void print_err(char* str, int line, int err_no);
void int2uint8(int num, unsigned char* arr);
int isEqual(unsigned char arr1[], unsigned char arr2[], int len);
void addBytes(__uint8_t* paddingMsg, void* originMsg, int msgLen,
              __uint8_t* bytes, int bytesLen);
int getLocalIp(char* local_ip);
void mystrncpy(char* dest, const char* src, size_t n);
void mystrncat(char* dest, const char* src, size_t n1, size_t n2);