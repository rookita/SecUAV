#include "../include/mytime.h"

//value为初始值，interval为间隔值
void wrapperOfUpdate(int value, int interval){
    struct itimerval timer;
    timer.it_value.tv_sec = value; // 第一次触发的时间间隔
    timer.it_value.tv_usec = 0;
    timer.it_interval.tv_sec = interval; // 之后每次触发的时间间隔
    timer.it_interval.tv_usec = 0;

    if (setitimer(ITIMER_REAL, &timer, NULL) == -1) {
        perror("setitimer");
        exit(EXIT_FAILURE);
    }
    signal(SIGALRM, regularUpdate);
}