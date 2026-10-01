#include "system.h"
#include <sched.h>
#include <stdlib.h>
#include <fcntl.h>
#include <rpm/rpmstring.h>
#include <rpm/rpmlog.h>
#include "rpmchroot.h"
#include "rpmug.h"
#include "debug.h"

struct rootState_s {
    char *rootDir;
    int chrootDone;
    int cwd;
};

/* Process global chroot state */
static struct rootState_s rootState = {
   .rootDir = NULL,
   .chrootDone = 0,
   .cwd = -1,
}; 

int rpmChrootSet(const char *rootDir)
{
    int rc = 0;

    /* Setting same rootDir again is a no-op and not an error */
    if (rootDir && rootState.rootDir && rstreq(rootDir, rootState.rootDir))
	return 0;

    /* Resetting only permitted in neutral state */
    if (rootState.chrootDone != 0)
	return -1;

    rootState.rootDir = _free(rootState.rootDir);
    if (rootState.cwd >= 0) {
	close(rootState.cwd);
	rootState.cwd = -1;
    }

    if (rootDir != NULL) {
	rootState.rootDir = rstrdup(rootDir);
	rootState.cwd = open(".", O_RDONLY);
	if (rootState.cwd < 0) {
	    rpmlog(RPMLOG_ERR, _("Unable to open current directory: %m\n"));
	    rc = -1;
	}
    }

    /* Reset user and group caches */
    rpmugFree();

    return rc;
}

int rpmChrootIn(void)
{
    int rc = 0;

    if (rootState.rootDir == NULL || rstreq(rootState.rootDir, "/"))
	return 0;

    if (rootState.cwd < 0) {
	rpmlog(RPMLOG_ERR, _("%s: chroot directory not set\n"), __func__);
	return -1;
    }

    /* "refcounted" entry to chroot */
    if (rootState.chrootDone > 0) {
	rootState.chrootDone++;
    } else if (rootState.chrootDone == 0) {
	rpmlog(RPMLOG_DEBUG, "entering chroot %s\n", rootState.rootDir);
	if (chdir("/") == 0 && chroot(rootState.rootDir) == 0) {
	    rootState.chrootDone = 1;
	} else {
	    rpmlog(RPMLOG_ERR, _("Unable to change root directory: %m\n"));
	    rc = -1;
	}
    }
    return rc;
}

int rpmChrootOut(void)
{
    int rc = 0;
    if (rootState.rootDir == NULL || rstreq(rootState.rootDir, "/"))
	return 0;

    if (rootState.cwd < 0) {
	rpmlog(RPMLOG_ERR, _("%s: chroot directory not set\n"), __func__);
	return -1;
    }

    /* "refcounted" return from chroot */
    if (rootState.chrootDone > 1) {
	rootState.chrootDone--;
    } else if (rootState.chrootDone == 1) {
	rpmlog(RPMLOG_DEBUG, "exiting chroot %s\n", rootState.rootDir);
	if (chroot(".") == 0 && fchdir(rootState.cwd) == 0) {
	    rootState.chrootDone = 0;
	} else {
	    rpmlog(RPMLOG_ERR, _("Unable to restore root directory: %m\n"));
	    rc = -1;
	}
    }
    return rc;
}

int rpmChrootDone(void)
{
    return (rootState.chrootDone > 0);
}
