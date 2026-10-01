#ifndef _RPMTRIGGERS_H
#define _RPMTRIGGERS_H

#include <rpm/rpmutil.h>
#include "rpmscript.h"

#define RPMTRIGGER_DEFAULT_PRIORITY 1000000

struct triggerInfo_s {
    unsigned int hdrNum;
    unsigned int tix;
    unsigned int priority;
};

typedef struct rpmtriggers_s {
    struct triggerInfo_s *triggerInfo;
    int count;
    int alloced;
} *rpmtriggers;

RPM_GNUC_INTERNAL
rpmtriggers rpmtriggersCreate(unsigned int hint);

RPM_GNUC_INTERNAL
rpmtriggers rpmtriggersFree(rpmtriggers triggers);

/*
 * Prepare post trans uninstall file triggers. After transcation uninstalled
 * files are not saved anywhere. So we need during uninstalation of every
 * package, in time when the files to uninstall are still available,
 * to determine and store triggers that should be set off after transaction.
 */
RPM_GNUC_INTERNAL
void rpmtriggersPrepPostUnTransFileTrigs(rpmts ts, rpmte te);

/* Run triggers stored in ts */
RPM_GNUC_INTERNAL
int runPostUnTransFileTrigs(rpmts ts);

/*
 * It runs file triggers in other package(s) this package/transaction sets off.
 * If tm is RPMSCRIPT_FILETRIGGERSCRIPT then it runs file triggers that are
 * fired by files in transaction entry. If tm is RPMSCRIPT_TRANSFILETRIGGERSCRIPT
 * then it runs file triggers that are fired by all files in transaction set.
 * In that case te can be NULL.
 *
 * @param ts		transaction set
 * @param te		transaction entry
 * @param sense		defines which triggers should be set off (triggerin,
 *			triggerun, triggerpostun)
 * @param tm		trigger mode, (filetrigger/transfiletrigger)
 * @param priorityClass	1 to run triggers that should be executed before
 *			standard scriptlets
 *			2 to run triggers that should be executed after
 *			standard scriptlets
 *			0 to run all triggers
 */
RPM_GNUC_INTERNAL
rpmRC runFileTriggers(rpmts ts, rpmte te, int arg2, rpmsenseFlags sense,
			rpmscriptTriggerModes tm, int priorityClass);

/* Run file triggers in this te other package(s) set off.
 * @param ts		transaction set
 * @param te		transaction entry
 * @param arg1		scriptlet argument 1 (number of instances of this pkg)
 * @param sense		defines which triggers should be set off (triggerin,
 *			triggerun, triggerpostun)
 * @param tm		trigger mode, (filetrigger/transfiletrigger)
 * @param priorityClass	1 to run triggers that should be executed before
 *			standard scriptlets
 *			2 to run triggers that should be executed after
 *			standard scriptlets
 *			0 to run all triggers
 */
RPM_GNUC_INTERNAL
rpmRC runImmedFileTriggers(rpmts ts, rpmte te, int arg1, rpmsenseFlags sense,
			    rpmscriptTriggerModes tm, int priorityClass);
#endif /* _RPMTRIGGERS_H */

