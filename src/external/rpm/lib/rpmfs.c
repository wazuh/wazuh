#include <stdlib.h>
#include <string.h>

#include "system.h"
#include "rpmfs.h"
#include "debug.h"

struct rpmfs_s {
    unsigned int fc;

    rpm_fstate_t * states;
    rpmFileAction * actions;	/*!< File disposition(s). */

    sharedFileInfo replaced;	/*!< (TR_ADDED) to be replaced files in the rpmdb */
    int numReplaced;
    int allocatedReplaced;
};

rpmfs rpmfsNew(rpm_count_t fc, int initState)
{
    rpmfs fs = (rpmfs)xcalloc(1, sizeof(*fs));
    fs->fc = fc;
    fs->actions = (rpmFileAction *)xcalloc(fs->fc, sizeof(*fs->actions));
    if (initState) {
	fs->states = (rpm_fstate_t *)xmalloc(sizeof(*fs->states) * fs->fc);
	memset(fs->states, RPMFILE_STATE_NORMAL, fs->fc);
    }
    return fs;
}

rpmfs rpmfsFree(rpmfs fs)
{
    if (fs != NULL) {
	free(fs->replaced);
	free(fs->states);
	free(fs->actions);
	memset(fs, 0, sizeof(*fs)); /* trash and burn */
	free(fs);
    }
    return NULL;
}

rpm_count_t rpmfsFC(rpmfs fs)
{
    return (fs != NULL) ? fs->fc : 0;
}

void rpmfsAddReplaced(rpmfs fs, int pkgFileNum, char rstate,
			int otherPkg, int otherFileNum)
{
    if (!fs->replaced) {
	fs->replaced = (sharedFileInfo)xcalloc(3, sizeof(*fs->replaced));
	fs->allocatedReplaced = 3;
    }
    if (fs->numReplaced>=fs->allocatedReplaced) {
	fs->allocatedReplaced += (fs->allocatedReplaced>>1) + 2;
	fs->replaced = xrealloc(fs->replaced, fs->allocatedReplaced*sizeof(*fs->replaced));
    }
    fs->replaced[fs->numReplaced].pkgFileNum = pkgFileNum;
    fs->replaced[fs->numReplaced].rstate = rstate;
    fs->replaced[fs->numReplaced].otherPkg = otherPkg;
    fs->replaced[fs->numReplaced].otherFileNum = otherFileNum;

    fs->numReplaced++;
}

sharedFileInfo rpmfsGetReplaced(rpmfs fs)
{
    if (fs && fs->numReplaced)
        return fs->replaced;
    else
        return NULL;
}

sharedFileInfo rpmfsNextReplaced(rpmfs fs , sharedFileInfo replaced)
{
    if (fs && replaced) {
        replaced++;
	if (replaced - fs->replaced < fs->numReplaced)
	    return replaced;
    }
    return NULL;
}

void rpmfsSetState(rpmfs fs, unsigned int ix, rpmfileState state)
{
    assert(ix < fs->fc);
    fs->states[ix] = state;
}

rpm_fstate_t * rpmfsGetStates(rpmfs fs)
{
    return (fs != NULL) ? fs->states : NULL;
}

rpmFileAction rpmfsGetAction(rpmfs fs, unsigned int ix)
{
    rpmFileAction action;
    if (fs && fs->actions != NULL && ix < fs->fc) {
	action = fs->actions[ix];
    } else {
	action = FA_UNKNOWN;
    }
    return action;
}

void rpmfsSetAction(rpmfs fs, unsigned int ix, rpmFileAction action)
{
    if (fs->actions != NULL && ix < fs->fc) {
	fs->actions[ix] = action;
    }
}

void rpmfsResetActions(rpmfs fs)
{
    if (fs && fs->actions) {
	for (int i = 0; i < fs->fc; i++) {
	    /* --excludepaths is processed early, avoid undoing that */
	    if (fs->actions[i] != FA_SKIPNSTATE)
		fs->actions[i] = FA_UNKNOWN;
	}
    }
}
