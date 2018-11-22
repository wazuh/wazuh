#ifndef _TIMES_H
#define _TIMES_H

#include <sys/timeb.h>
#include <sys/types.h>
#include <winsock2.h>
#include <time.h>

#define __need_clock_t

typedef long long suseconds_t;

/* Structure describing CPU time used by a process and its children.  */
struct tms
{
    clock_t tms_utime;          /* User CPU time.  */
    clock_t tms_stime;          /* System CPU time.  */
    
    clock_t tms_cutime;         /* User CPU time of dead children.  */
    clock_t tms_cstime;         /* System CPU time of dead children.  */
};

struct timezone
{
    int tz_minuteswest; /* minutes west of Greenwich */
    int tz_dsttime; /* type of DST correction */
};

int gettimeofday(struct timeval* t,void* timezone)
{
    struct _timeb timebuffer;
    _ftime(&timebuffer);
    t->tv_sec = timebuffer.time;
    t->tv_usec = (1000 * timebuffer.millitm);
    return 0;
}

/* Store the CPU time used by this process and all its
   dead children (and their dead children) in BUFFER.
   Return the elapsed real time, or (clock_t) -1 for errors.
   All times are in CLK_TCKths of a second.  */
clock_t times (struct tms *__buffer)
{
    __buffer->tms_utime = clock();
    __buffer->tms_stime = 0;
    __buffer->tms_cstime = 0;
    __buffer->tms_cutime = 0;
    return __buffer->tms_utime;
}

#endif
