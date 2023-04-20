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

int get_local_ip(const char *eth_inf, char* local_ip)
{
    int sd;
    struct sockaddr_in sin;
    struct ifreq ifr;
 
    sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (-1 == sd)
    {
        printf("socket error: %s\n", strerror(errno));
        return -1;
    }
 
    strncpy(ifr.ifr_name, eth_inf, IFNAMSIZ);
    ifr.ifr_name[IFNAMSIZ - 1] = 0;
 
    // if error: No such device  
    if (ioctl(sd, SIOCGIFADDR, &ifr) < 0)
    {
        printf("ioctl error: %s\n", strerror(errno));
        close(sd);
        return -1;
    }
    
    strncpy(local_ip, inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr), 13);
    close(sd);
    return 0;
}


void *mystrncpy(char *dest, const char *src, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        dest[i] = src[i];
    }
    for (; i < n; i++) {
        dest[i] = '\0';
    }
}