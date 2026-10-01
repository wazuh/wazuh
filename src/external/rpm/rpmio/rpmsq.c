/** \ingroup rpmio
 * \file rpmio/rpmsq.c
 */

#include "system.h"

#include <signal.h>
#include <sys/signal.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rpm/rpmsq.h>
#include <rpm/rpmlog.h>

#include "debug.h"

int rpmsqBlock(int op)
{
    static sigset_t oldMask;
    static int blocked = 0;
    sigset_t newMask;
    int ret = 0;

    if (op == SIG_BLOCK) {
	blocked++;
	if (blocked == 1) {
	    sigfillset(&newMask);
	    sigdelset(&newMask, SIGABRT);
	    sigdelset(&newMask, SIGBUS);
	    sigdelset(&newMask, SIGFPE);
	    sigdelset(&newMask, SIGILL);
	    sigdelset(&newMask, SIGSEGV);
	    sigdelset(&newMask, SIGTSTP);
	    ret = pthread_sigmask(SIG_BLOCK, &newMask, &oldMask);
	}
    } else if (op == SIG_UNBLOCK) {
	blocked--;
	if (blocked == 0) {
	    ret = pthread_sigmask(SIG_SETMASK, &oldMask, NULL);
	} else if (blocked < 0) {
	    blocked = 0;
	    ret = -1;
	}
    }

    return ret;
}
