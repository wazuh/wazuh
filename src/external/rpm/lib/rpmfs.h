#ifndef _RPMFS_H
#define _RPMFS_H

#include <rpm/rpmfi.h>

/** \ingroup rpmfs
 * Transaction element file states.
 */
typedef struct rpmfs_s * rpmfs;
typedef struct sharedFileInfo_s * sharedFileInfo;
typedef char rpm_fstate_t;

/* XXX psm needs access to these */
struct sharedFileInfo_s {
    int pkgFileNum;
    int otherPkg;
    int otherFileNum;
    char rstate;
};

RPM_GNUC_INTERNAL
rpmfs rpmfsNew(rpm_count_t fc, int initState);

RPM_GNUC_INTERNAL
rpmfs rpmfsFree(rpmfs fs);

RPM_GNUC_INTERNAL
rpm_count_t rpmfsFC(rpmfs fs);

RPM_GNUC_INTERNAL
void rpmfsAddReplaced(rpmfs fs, int pkgFileNum, char rstate,
			int otherPkg, int otherFileNum);

RPM_GNUC_INTERNAL
sharedFileInfo rpmfsGetReplaced(rpmfs fs);

RPM_GNUC_INTERNAL
sharedFileInfo rpmfsNextReplaced(rpmfs fs , sharedFileInfo replaced);

RPM_GNUC_INTERNAL
void rpmfsSetState(rpmfs fs, unsigned int ix, rpmfileState state);

/* May return NULL */
RPM_GNUC_INTERNAL
rpm_fstate_t * rpmfsGetStates(rpmfs fs);

RPM_GNUC_INTERNAL
rpmFileAction rpmfsGetAction(rpmfs fs, unsigned int ix);

RPM_GNUC_INTERNAL
void rpmfsSetAction(rpmfs fs, unsigned int ix, rpmFileAction action);

RPM_GNUC_INTERNAL
void rpmfsResetActions(rpmfs fs);

#endif /* _RPMFS_H */
