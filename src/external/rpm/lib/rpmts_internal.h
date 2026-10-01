#ifndef _RPMTS_INTERNAL_H
#define _RPMTS_INTERNAL_H

#include <rpm/rpmts.h>
#include <rpm/rpmstrpool.h>

#include "rpmal.h"		/* XXX availablePackage */
#include "fprint.h"
#include "rpmlock.h"
#include "rpmdb_internal.h"
#include "rpmscript.h"
#include "rpmtriggers.h"

typedef struct diskspaceInfo_s * rpmDiskSpaceInfo;

/* Transaction set elements information */
typedef struct tsMembers_s {
    rpmstrPool pool;		/*!< Global string pool */
    packageHash removedPackages;	/*!< Set of packages being removed. */
    packageHash installedPackages;	/*!< Set of installed packages */
    rpmal addedPackages;	/*!< Set of packages being installed. */

    rpmds rpmlib;		/*!< rpmlib() dependency set. */
    rpmte * order;		/*!< Packages sorted by dependencies. */
    int orderCount;		/*!< No. of transaction elements. */
    int orderAlloced;		/*!< No. of allocated transaction elements. */
    int delta;			/*!< Delta for reallocation. */
} * tsMembers;

/** \ingroup rpmts
 * The set of packages to be installed/removed atomically.
 */
struct rpmts_s {
    rpmtransFlags transFlags;	/*!< Bit(s) to control operation. */

    int (*solve) (rpmts ts, rpmds key, const void * data);
                                /*!< Search for NEVRA key. */
    const void * solveData;	/*!< Solve callback data */

    rpmCallbackFunction notify;	/*!< Callback function. */
    rpmCallbackData notifyData;	/*!< Callback private data. */
    int notifyStyle;		/*!< Callback style (header vs rpmte) */

    rpmtsChangeFunction change;	/*!< Change callback function. */
    void *changeData;		/*!< Change callback private data. */

    rpmprobFilterFlags ignoreSet;
				/*!< Bits to filter current problems. */

    rpmDiskSpaceInfo dsi;	/*!< Per filesystem disk/inode usage. */

    rpmdb rdb;			/*!< Install database handle. */
    int dbmode;			/*!< Install database open mode. */

    tsMembers members;		/*!< Transaction set member info (order etc) */

    char * rootDir;		/*!< Path to top of install tree. */
    char * lockPath;		/*!< Transaction lock path */
    rpmlock lock;		/*!< Transaction lock file */
    FD_t scriptFd;		/*!< Scriptlet stdout/stderr. */
    rpm_tid_t tid;		/*!< Transaction id. */

    rpm_color_t color;		/*!< Transaction color bits. */
    rpm_color_t prefcolor;	/*!< Preferred file color. */

    rpmVSFlags vsflags;		/*!< Signature/digest verification flags. */
    rpmVSFlags vfyflags;	/*!< Package verification flags */
    int vfylevel;		/*!< Package verification level */
    rpmKeyring keyring;		/*!< Keyring in use. */
    int keyringtype;		/*!< Keyring type */

    ARGV_t netsharedPaths;	/*!< From %{_netsharedpath} */
    ARGV_t installLangs;	/*!< From %{_install_langs} */

    struct rpmop_s ops[RPMTS_OP_MAX];

    rpmPlugins plugins;		/*!< Transaction plugins */

    int nrefs;			/*!< Reference count. */

    rpmtriggers trigs2run;   /*!< Transaction file triggers */

    int min_writes;             /*!< macro minimize_writes used */

    time_t overrideTime;	/*!< Time value used when overriding system clock. */
};

/** \ingroup rpmts
 * Return transaction global string pool handle, creating the pool if needed.
 * @param ts		transaction set
 * @return		string pool handle (weak ref)
 */
RPM_GNUC_INTERNAL
rpmstrPool rpmtsPool(rpmts ts);

RPM_GNUC_INTERNAL
tsMembers rpmtsMembers(rpmts ts);

/* Return rpmdb iterator with removals optionally pruned out */
RPM_GNUC_INTERNAL
rpmdbMatchIterator rpmtsPrunedIterator(rpmts ts, rpmDbiTagVal tag,
					      const char * key, int prune);

/* Return rpmdb iterator locked to a single rpmte */
RPM_GNUC_INTERNAL
rpmdbMatchIterator rpmtsTeIterator(rpmts ts, rpmte te, int prune);

RPM_GNUC_INTERNAL
rpmal rpmtsCreateAl(rpmts ts, rpmElementTypes types);

/* returns -1 for retry, 0 for ignore and 1 for not found */
RPM_GNUC_INTERNAL
int rpmtsSolve(rpmts ts, rpmds key);

RPM_GNUC_INTERNAL
rpmRC rpmtsSetupTransactionPlugins(rpmts ts);

RPM_GNUC_INTERNAL
rpmRC runScript(rpmts ts, rpmte te, Header h, ARGV_const_t prefixes,
		       rpmScript script, int arg1, int arg2);


RPM_GNUC_INTERNAL
int rpmtsNotifyChange(rpmts ts, int event, rpmte te, rpmte other);

RPM_GNUC_INTERNAL
rpm_time_t rpmtsGetTime(rpmts ts, time_t step);

#endif /* _RPMTS_INTERNAL_H */
