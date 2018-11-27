#include "time.h"

int gettimeofday(struct timeval *t, void *timezone)
{
    struct _timeb timebuffer;
    _ftime(&timebuffer);
    t->tv_sec = timebuffer.time;
    t->tv_usec = (1000 * timebuffer.millitm);
    return 0;
}

clock_t times(struct tms *__buffer)
{
    __buffer->tms_utime = clock();
    __buffer->tms_stime = 0;
    __buffer->tms_cstime = 0;
    __buffer->tms_cutime = 0;
    return __buffer->tms_utime;
}
