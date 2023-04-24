#include <stdlib.h>
#include <stdio.h>

void print_char_arr(const unsigned char* a, size_t len);
void print_char_arr1(const unsigned char* a, size_t len);
void print_err(char *str, int line, int err_no);
void int2uint8(int num, unsigned char* arr);
int isEqual(unsigned char arr1[], unsigned char arr2[], int len);
void add_byte(__uint8_t* padding_msg, void* msg, int msg_len, char padding);
int get_local_ip(const char *eth_inf, char* local_ip);
void *mystrncpy(char *dest, const char *src, size_t n);
void mystrncat(char *dest, const char *src, size_t n1, size_t n2);