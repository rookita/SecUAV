#ifndef __MYTIME
#define __MYTIME

#include "message.h"
#include <sys/time.h>

extern struct itimerval timer;
extern int value;
extern int interval;

void mysetittimer(int value, int interval);
void wrapperOfUpdate(int value, int interval);

#endif