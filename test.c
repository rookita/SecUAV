#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/time.h>

void timer_handler(int signum, siginfo_t *info, void *context)
{
    int *counter = (int *)info->si_value.sival_ptr;
    printf("Timer expired %d times\n", ++(*counter));
}

int main()
{
    struct sigaction sa;
    struct itimerval timer;
    int counter = 0;

    // 设置信号处理函数
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = timer_handler;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGALRM, &sa, NULL) == -1) {
        perror("sigaction");
        exit(1);
    }

    // 设置定时器
    timer.it_value.tv_sec = 1;
    timer.it_value.tv_usec = 0;
    timer.it_interval.tv_sec = 1;
    timer.it_interval.tv_usec = 0;
    if (setitimer(ITIMER_REAL, &timer, NULL) == -1) {
        perror("setitimer");
        exit(1);
    }

    // 等待定时器信号
    while (1) {
        pause();
    }

    return 0;
}
