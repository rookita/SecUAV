#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

void func(){
    printf("start_time: %ld\n", clock());
    sleep(20);
    printf("end_time: %ld\n", clock());
}

int main(){
    printf("%ld\n", CLOCKS_PER_SEC);
    clock_t start_time, end_time;
    double total_time;
    start_time = 4266; end_time = 56016;
    total_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    printf("程序运行时间为 %f 秒\n", total_time);
    //func();
}
