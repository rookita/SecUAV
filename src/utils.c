#include "../include/utils.h"
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h> 
#include <unistd.h> 
#include <netdb.h>  
#include <net/if.h>  
#include <arpa/inet.h> 
#include <sys/ioctl.h>  
#include <sys/types.h>  
#include <sys/time.h> 
#include <ifaddrs.h>

void print_char_arr(const unsigned char* a, size_t len){
  int i = 0;
  for (i = 0; i < len; i++) {
		printf("%02X", a[i]);
	}
	printf("\n");
}

void print_char_arr1(const unsigned char* a, size_t len){
  int i = 0;
  for (i = 0; i < len; i++) {
		printf("%02X", a[i]);
	}
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


int get_local_ip(char *ip) {
    struct ifaddrs *ifAddrStruct;
    void *tmpAddrPtr=NULL;
    getifaddrs(&ifAddrStruct);
    while (ifAddrStruct != NULL) {
        if (ifAddrStruct->ifa_addr->sa_family==AF_INET) {
            tmpAddrPtr=&((struct sockaddr_in *)ifAddrStruct->ifa_addr)->sin_addr;
			if (strncmp(ifAddrStruct->ifa_name, "eth0@if", 7) == 0){
                inet_ntop(AF_INET, tmpAddrPtr, ip, INET_ADDRSTRLEN);
                //printf("%s IP Address:%s\n", ifAddrStruct->ifa_name, ip);
            }
        }
        ifAddrStruct=ifAddrStruct->ifa_next;
        }
        //free ifaddrs
        freeifaddrs(ifAddrStruct);
        return 0;
}


void mystrncpy(char *dest, const char *src, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        dest[i] = src[i];
    }
    for (; i < n; i++) {
        dest[i] = '\0';
    }
}

void mystrncat(char *dest, const char *src, size_t n1, size_t n2) {
    size_t dest_len = n1;
    size_t i;
    for (i = 0; i < n2; i++) {
        dest[dest_len + i] = src[i];
    }
    dest[dest_len + i] = '\0';
}