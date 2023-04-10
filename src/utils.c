#include <string.h>
#include "../include/utils.h"

void print_char_arr(const unsigned char* a, size_t len){
  int i = 0;
  for (i = 0; i < len; i++) {
		printf("%02X", a[i]);
	}
	printf("\n");
}

void print_err(char *str, int line, int err_no) {
  printf("%d, %s :%s\n",line,str,strerror(err_no));
}

void int2uint8(int num, unsigned char* arr){
  arr[0] = (num >> 24) & 0xFF;
  arr[1] = (num >> 16) & 0xFF;
  arr[2] = (num >> 8) & 0xFF;
  arr[3] = num & 0xFF;
}

int isEqual(unsigned char arr1[], unsigned char arr2[], int len) {
    int i;
    for (i = 0; i < len; i++) {
        if (arr1[i] != arr2[i]) {
            return 0; // 不相等，返回0
        }
    }
    return 1; // 相等，返回1
}

void add_byte(__uint8_t* padding_msg, void* msg, int msg_len, char padding){
  padding_msg[0] = padding;
  char* dest = padding_msg + 1;
  memmove((void* )dest, msg, msg_len);
}




