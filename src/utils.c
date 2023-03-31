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