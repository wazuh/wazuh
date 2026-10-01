/** \ingroup rpmio
 * \file rpmio/rpmsw.c
 */

#include "system.h"
#include <rpm/rpmsw.h>
#include "debug.h"

static rpmtime_t rpmsw_overhead = 0;

static rpmtime_t rpmsw_cycles = 1;

static int rpmsw_initialized = 0;

rpmsw rpmswNow(rpmsw sw)
{
    if (!rpmsw_initialized)
	(void) rpmswInit();
    if (sw == NULL)
	return NULL;
    if (gettimeofday(&sw->u.tv, NULL))
    	return NULL;
    return sw;
}

/** \ingroup rpmio
 * Return difference of 2 timeval stamps in micro-seconds.
 * @param *etv		end timeval
 * @param *btv		begin timeval
 * @return		difference in milli-seconds
 */
static inline
rpmtime_t tvsub(const struct timeval * etv,
		const struct timeval * btv)
{
    time_t secs, usecs;
    if (etv == NULL  || btv == NULL) return 0;
    secs = etv->tv_sec - btv->tv_sec;
    for (usecs = etv->tv_usec - btv->tv_usec; usecs < 0; usecs += 1000000)
	secs--;
    return ((secs * 1000000) + usecs);
}

rpmtime_t rpmswDiff(rpmsw end, rpmsw begin)
{
    unsigned long long ticks = 0;

    if (end == NULL || begin == NULL)
	return 0;
    ticks = tvsub(&end->u.tv, &begin->u.tv);
    if (ticks >= rpmsw_overhead)
	ticks -= rpmsw_overhead;
    if (rpmsw_cycles > 1)
	ticks /= rpmsw_cycles;
    return ticks;
}

rpmtime_t rpmswInit(void)
{
    struct rpmsw_s begin, end;
    rpmtime_t sum_overhead = 0;
    int i;

    rpmsw_initialized = 1;

    rpmsw_overhead = 0;
    rpmsw_cycles = 0;

    /* Convergence for simultaneous cycles and overhead is overkill ... */
    for (i = 0; i < 3; i++) {
	/* Calculate timing overhead in usecs. */
	(void) rpmswNow(&begin);
	sum_overhead += rpmswDiff(rpmswNow(&end), &begin);

	rpmsw_overhead = sum_overhead/(i+1);
    }

    return rpmsw_overhead;
}

int rpmswEnter(rpmop op, ssize_t rc)
{
    if (op == NULL)
	return 0;

    op->count++;
    if (rc < 0) {
	op->bytes = 0;
	op->usecs = 0;
    }
    (void) rpmswNow(&op->begin);
    return 0;
}

rpmtime_t rpmswExit(rpmop op, ssize_t rc)
{
    struct rpmsw_s end;

    if (op == NULL)
	return 0;

    op->usecs += rpmswDiff(rpmswNow(&end), &op->begin);
    if (rc > 0)
	op->bytes += rc;
    op->begin = end;	/* structure assignment */
    return op->usecs;
}

rpmtime_t rpmswAdd(rpmop to, rpmop from)
{
    rpmtime_t usecs = 0;
    if (to != NULL && from != NULL) {
	to->count += from->count;
	to->bytes += from->bytes;
	to->usecs += from->usecs;
	usecs = to->usecs;
    }
    return usecs;
}

rpmtime_t rpmswSub(rpmop to, rpmop from)
{
    rpmtime_t usecs = 0;
    if (to != NULL && from != NULL) {
	to->count -= from->count;
	to->bytes -= from->bytes;
	to->usecs -= from->usecs;
	usecs = to->usecs;
    }
    return usecs;
}
