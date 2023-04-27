#include <stdio.h>

#include <ifaddrs.h>

#include <netinet/in.h>

#include <string.h>

#include <arpa/inet.h>


int get_local_ip(char *ip) {

        struct ifaddrs *ifAddrStruct;

        void *tmpAddrPtr=NULL;

        getifaddrs(&ifAddrStruct);

        while (ifAddrStruct != NULL) {

                if (ifAddrStruct->ifa_addr->sa_family==AF_INET) {

                        tmpAddrPtr=&((struct sockaddr_in *)ifAddrStruct->ifa_addr)->sin_addr;

                        inet_ntop(AF_INET, tmpAddrPtr, ip, INET_ADDRSTRLEN);
						
						if (strncmp(ifAddrStruct->ifa_name, "eth0@if", 7) == 0)
                        	printf("%s IP Address:%s\n", ifAddrStruct->ifa_name, ip);

                }

                ifAddrStruct=ifAddrStruct->ifa_next;

        }

        //free ifaddrs

        freeifaddrs(ifAddrStruct);

        return 0;

}


int main()

{

        char ip[16];

        memset(ip, 0, sizeof(ip));

        get_local_ip(ip);

        return 0;

}