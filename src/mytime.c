#include "../include/mytime.h"

struct itimerval timer;

//更新间隔为1分钟
int value = 6000;
int interval = 6000;

//value为初始值，interval为间隔值
void mysetittimer(int value, int interval){
    timer.it_value.tv_sec = value; // 第一次触发的时间间隔
    timer.it_value.tv_usec = 0;
    timer.it_interval.tv_sec = interval; // 之后每次触发的时间间隔
    timer.it_interval.tv_usec = 0;

    if (setitimer(ITIMER_REAL, &timer, NULL) == -1) {
        perror("setitimer");
        exit(EXIT_FAILURE);
    }
}

void wrapperOfUpdate(int value, int interval){
    mysetittimer(value, interval);
    signal(SIGALRM, regularUpdate);
}

