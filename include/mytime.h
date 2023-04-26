#ifndef __MYTIME
#define __MYTIME

#include "message.h"
#include <sys/time.h>

extern struct itimerval timer;

void mysetittimer(int value, int interval);
void wrapperOfUpdate(int value, int interval);

#endif