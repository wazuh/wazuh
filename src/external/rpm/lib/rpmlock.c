
#include "system.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>

#include <rpm/rpmlog.h>
#include <rpm/rpmfileutil.h>

#include "rpmlock.h"

#include "debug.h"

/* Internal interface */

struct rpmlock_s {
    int fd;
    int openmode;
    char *path;
    char *descr;
    int fdrefs;
};

static rpmlock rpmlock_new(const char *lock_path, const char *descr)
{
    rpmlock lock = (rpmlock) malloc(sizeof(*lock));

    if (lock != NULL) {
	mode_t oldmask = umask(022);
	lock->fd = open(lock_path, O_RDWR|O_CREAT, 0644);
	(void) umask(oldmask);

	if (lock->fd == -1) {
	    if (errno == EACCES)
		lock->fd = open(lock_path, O_RDONLY);
	    else if (errno == EROFS) {
		/* read-only media doesn't need locks, just feed it something */
		lock->fd = dup(STDIN_FILENO);
	    }
	    if (lock->fd == -1) {
		free(lock);
		lock = NULL;
	    } else {
		lock->openmode = RPMLOCK_READ;
	    }
	} else {
	    lock->openmode = RPMLOCK_WRITE | RPMLOCK_READ;
	}
	if (lock) {
	    lock->path = xstrdup(lock_path);
	    lock->descr = xstrdup(descr);
	    lock->fdrefs = 1;
	}
    }
    return lock;
}

static void rpmlock_free(rpmlock lock)
{
    if (--lock->fdrefs == 0) {
	free(lock->path);
	free(lock->descr);
	(void) close(lock->fd);
	free(lock);
    }
}

static int rpmlock_acquire(rpmlock lock, int mode)
{
    int res = 0;

    if (!(mode & lock->openmode))
	return res;

    if (lock->fdrefs > 1) {
	res = 1;
    } else {
	struct flock info;
	int cmd;
	if (mode & RPMLOCK_WAIT)
	    cmd = F_SETLKW;
	else
	    cmd = F_SETLK;
	if (mode & RPMLOCK_READ)
	    info.l_type = F_RDLCK;
	else
	    info.l_type = F_WRLCK;
	info.l_whence = SEEK_SET;
	info.l_start = 0;
	info.l_len = 0;
	info.l_pid = 0;
	if (fcntl(lock->fd, cmd, &info) != -1)
	    res = 1;
    }

    lock->fdrefs += res;

    return res;
}

static void rpmlock_release(rpmlock lock)
{
    /* if not locked then we must not release */
    if (lock->fdrefs <= 1)
	return;

    if (--lock->fdrefs == 1) {
	struct flock info;
	info.l_type = F_UNLCK;
	info.l_whence = SEEK_SET;
	info.l_start = 0;
	info.l_len = 0;
	info.l_pid = 0;
	(void) fcntl(lock->fd, F_SETLK, &info);
     }
}


/* External interface */
rpmlock rpmlockNew(const char *lock_path, const char *descr)
{
    rpmlock lock = rpmlock_new(lock_path, descr);
    if (!lock) {
	rpmlog(RPMLOG_ERR, _("can't create %s lock on %s (%s)\n"), 
		descr, lock_path, strerror(errno));
    }
    return lock;
}

int rpmlockAcquire(rpmlock lock, int lockmode)
{
    int locked = 0; /* assume failure */
    int myerrno = errno;
    int maywait = isatty(STDIN_FILENO); /* dont wait within scriptlets */
    errno = myerrno;

    if (lock) {
	locked = rpmlock_acquire(lock, lockmode);
	if (!locked && (lock->openmode & lockmode) && maywait) {
	    rpmlog(RPMLOG_WARNING, _("waiting for %s lock on %s\n"),
		    lock->descr, lock->path);
	    locked = rpmlock_acquire(lock, (lockmode|RPMLOCK_WAIT));
	}
	if (!locked) {
	    rpmlog(RPMLOG_ERR, _("can't create %s lock on %s (%s)\n"), 
		   lock->descr, lock->path, strerror(errno));
	}
    }
    return locked;
}

void rpmlockRelease(rpmlock lock)
{
    if (lock)
	rpmlock_release(lock);
}

rpmlock rpmlockNewAcquire(const char *lock_path, const char *descr)
{
    rpmlock lock = rpmlockNew(lock_path, descr);
    if (!rpmlockAcquire(lock, RPMLOCK_WRITE))
	lock = rpmlockFree(lock);
    return lock;
}

rpmlock rpmlockFree(rpmlock lock)
{
    if (lock) {
	rpmlock_release(lock);
	rpmlock_free(lock);
    }
    return NULL;
}


