#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

void* func(void* args){
	char* a = (char* )args;
	char c = *a;
	while(1)
		printf("s: %c\n", c);
}

void func1(char* aa){

}

int main(){
	pthread_t id;
	char s = 'a';
	char* ps = &s;
	int ret = pthread_create(&id, NULL, func, (void*)&s);
	sleep(10);
	*ps = 'b';
	while(1);
}