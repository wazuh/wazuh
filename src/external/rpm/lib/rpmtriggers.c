#include "system.h"

#include <rpm/rpmts.h>
#include <rpm/rpmdb.h>
#include <rpm/rpmds.h>
#include <rpm/rpmfi.h>
#include <stdlib.h>

#include "rpmtriggers.h"
#include "rpmts_internal.h"
#include "rpmdb_internal.h"
#include "rpmds_internal.h"
#include "rpmfi_internal.h"
#include "rpmte_internal.h"
#include "rpmchroot.h"

#define TRIGGER_PRIORITY_BOUND 10000

rpmtriggers rpmtriggersCreate(unsigned int hint)
{
    rpmtriggers triggers = (rpmtriggers)xmalloc(sizeof(struct rpmtriggers_s));
    triggers->count = 0;
    triggers->alloced = hint;
    triggers->triggerInfo = (struct triggerInfo_s *)xmalloc(sizeof(struct triggerInfo_s) *
				    triggers->alloced);
    return triggers;
}

rpmtriggers rpmtriggersFree(rpmtriggers triggers)
{
    _free(triggers->triggerInfo);
    _free(triggers);

    return NULL;
}

static void rpmtriggersAdd(rpmtriggers trigs, unsigned int hdrNum,
			    unsigned int tix, unsigned int priority)
{
    if (trigs->count == trigs->alloced) {
	trigs->alloced <<= 1;
	trigs->triggerInfo = xrealloc(trigs->triggerInfo,
				sizeof(struct triggerInfo_s) * trigs->alloced);
    }

    trigs->triggerInfo[trigs->count].hdrNum = hdrNum;
    trigs->triggerInfo[trigs->count].tix = tix;
    trigs->triggerInfo[trigs->count].priority = priority;
    trigs->count++;
}

static int trigCmp(const void *a, const void *b)
{
    const struct triggerInfo_s *trigA = (const struct triggerInfo_s *)a;
    const struct triggerInfo_s *trigB = (const struct triggerInfo_s *)b;

    if (trigA->priority < trigB->priority)
	return 1;

    if (trigA->priority > trigB->priority)
	return -1;

    if (trigA->hdrNum < trigB->hdrNum)
	return -1;

    if (trigA->hdrNum > trigB->hdrNum)
	return 1;

    if (trigA->tix < trigB->tix)
	return -1;

    if (trigA->tix > trigB->tix)
	return 1;

    return 0;
}

static void rpmtriggersSortAndUniq(rpmtriggers trigs)
{
    unsigned int from;
    unsigned int to = 0;
    unsigned int count = trigs->count;

    if (count > 1)
	qsort(trigs->triggerInfo, count, sizeof(struct triggerInfo_s), trigCmp);

    for (from = 0; from < count; from++) {
	if (from > 0 &&
	    !trigCmp((const void *) &trigs->triggerInfo[from - 1],
		    (const void *) &trigs->triggerInfo[from])) {

	    trigs->count--;
	    continue;
	}
	if (from != to)
	    trigs->triggerInfo[to] = trigs->triggerInfo[from];
	to++;
    }
}

static unsigned int getTrigPriority(Header h, rpmTagVal prioTag, int tix)
{
    unsigned int priority = RPMTRIGGER_DEFAULT_PRIORITY;
    struct rpmtd_s priorities;

    if (headerGet(h, prioTag, &priorities, HEADERGET_MINMEM)) {
	if (rpmtdSetIndex(&priorities, tix) >= 0)
	    priority = rpmtdGetNumber(&priorities);
    }
    return priority;
}

static void addTriggers(rpmts ts, Header trigH, rpmsenseFlags filter,
			const char *prefix)
{
    int tix = 0;
    rpmds ds;
    rpmds triggers = rpmdsNew(trigH, RPMTAG_TRANSFILETRIGGERNAME, 0);
    rpmTagVal prioTag = RPMTAG_TRANSFILETRIGGERPRIORITIES;

    while ((ds = rpmdsFilterTi(triggers, tix))) {
	while (rpmdsNext(ds) >= 0) {
	    if ((rpmdsFlags(ds) & filter) && strcmp(prefix, rpmdsN(ds)) == 0) {
		unsigned int priority = getTrigPriority(trigH, prioTag, tix);
		rpmtriggersAdd(ts->trigs2run, headerGetInstance(trigH),
				    tix, priority);
	    }
	}
	rpmdsFree(ds);
	tix++;
    }
    rpmdsFree(triggers);
}

void rpmtriggersPrepPostUnTransFileTrigs(rpmts ts, rpmte te)
{
    rpmdbIndexIterator ii;
    const void *key;
    size_t keylen;
    rpmfiles files;

    ii = rpmdbIndexIteratorInit(rpmtsGetRdb(ts), RPMDBI_TRANSFILETRIGGERNAME);
    files = rpmteFiles(te);

    /* Iterate over file triggers in rpmdb */
    while ((rpmdbIndexIteratorNext(ii, &key, &keylen)) == 0) {
	char pfx[keylen + 1];
	memcpy(pfx, key, keylen);
	pfx[keylen] = '\0';
	/* Check if file trigger matches any installed file in this te */
	rpmfi fi = rpmfilesFindPrefix(files, pfx);
	while (rpmfiNext(fi) >= 0) {
	    if (RPMFILE_IS_INSTALLED(rpmfiFState(fi))) {
		unsigned int npkg = rpmdbIndexIteratorNumPkgs(ii);
		const unsigned int *offs = rpmdbIndexIteratorPkgOffsets(ii);
		/* Save any postun triggers matching this prefix */
		for (int i = 0; i < npkg; i++) {
		    Header h = rpmdbGetHeaderAt(rpmtsGetRdb(ts), offs[i]);
		    addTriggers(ts, h, RPMSENSE_TRIGGERPOSTUN, pfx);
		    headerFree(h);
		}
		break;
	    }
	}
	rpmfiFree(fi);
    }
    rpmdbIndexIteratorFree(ii);
    rpmfilesFree(files);
}

int runPostUnTransFileTrigs(rpmts ts)
{
    int i;
    Header trigH;
    const char * trigName = NULL;
    int arg1 = 0;
    struct rpmtd_s installPrefixes;
    rpmScript script;
    rpmtriggers trigs = ts->trigs2run;
    int nerrors = 0;

    rpmtriggersSortAndUniq(trigs);
    /* Iterate over stored triggers */
    for (i = 0; i < trigs->count; i++) {
	/* Get header containing trigger script */
	trigH = rpmdbGetHeaderAt(rpmtsGetRdb(ts),
				trigs->triggerInfo[i].hdrNum);

	/* Maybe package with this trigger is already uninstalled */
	if (trigH == NULL)
	    continue;

	/* Prepare and run script */
	script = rpmScriptFromTriggerTag(trigH,
		triggertag(RPMSENSE_TRIGGERPOSTUN),
		RPMSCRIPT_TRANSFILETRIGGER, trigs->triggerInfo[i].tix);

	headerGet(trigH, RPMTAG_INSTPREFIXES, &installPrefixes,
		HEADERGET_ALLOC|HEADERGET_ARGV);

	trigName = headerGetString(trigH, RPMTAG_NAME);
	arg1 = rpmdbCountPackages(rpmtsGetRdb(ts), trigName);

	ARGV_const_t prefixes = (ARGV_const_t)installPrefixes.data;
	nerrors += runScript(ts, NULL, trigH, prefixes, script, arg1, -1);
	rpmtdFreeData(&installPrefixes);
	rpmScriptFree(script);
	headerFree(trigH);
    }

    return nerrors;
}

typedef struct matchFilesIter_s {
    rpmts ts;
    rpmds rpmdsTrigger;
    rpmfiles files;
    rpmfi fi;
    rpmfs fs;
    const char *pfx;
    const char *pkgname;
    rpmdbMatchIterator pi;
    packageHash tranPkgs;
} *matchFilesIter;

/*
 * Get files from next package from match iterator. If files are
 * available in memory then don't read them from rpmdb.
 */
static rpmfiles rpmtsNextFiles(matchFilesIter mfi)
{
    Header h;
    rpmte *tes;
    rpmte te = NULL;
    rpmfiles files = NULL;
    rpmstrPool pool = mfi->ts->members->pool;
    int ix;
    unsigned int offset;

    ix = rpmdbGetIteratorIndex(mfi->pi);
    if (ix < rpmdbGetIteratorCount(mfi->pi)) {
	offset = rpmdbGetIteratorOffsetFor(mfi->pi, ix);
	if (packageHashGetEntry(mfi->ts->members->removedPackages, offset,
				&tes, NULL, NULL)) {
	    /* Files are available in memory */
	    te = tes[0];
	    files  = rpmteFiles(te);
	}

	if (packageHashGetEntry(mfi->ts->members->installedPackages, offset,
				&tes, NULL, NULL)) {
	    /* Files are available in memory */
	    te = tes[0];
	    files  = rpmteFiles(te);
	}
    }

    if (files) {
	rpmdbSetIteratorIndex(mfi->pi, ix + 1);
	mfi->pkgname = rpmteN(te);
    } else {
	/* Files are not available in memory. Read them from rpmdb */
	h = rpmdbNextIterator(mfi->pi);
	if (h) {
	    files = rpmfilesNew(pool, h, RPMTAG_BASENAMES,
				RPMFI_FLAGS_FILETRIGGER);
	    mfi->pkgname = headerGetString(h, RPMTAG_NAME);
	}
    }

    return files;
}

static matchFilesIter matchFilesIterator(rpmds trigger, rpmfiles files, rpmte te)
{
    matchFilesIter mfi = (matchFilesIter)xcalloc(1, sizeof(*mfi));
    rpmdsInit(trigger);
    mfi->rpmdsTrigger = trigger;
    mfi->files = rpmfilesLink(files);
    mfi->fs = rpmteGetFileStates(te);
    return mfi;
}

static matchFilesIter matchDBFilesIterator(rpmds trigger, rpmts ts,
					    int inTransaction)
{
    matchFilesIter mfi = (matchFilesIter)xcalloc(1, sizeof(*mfi));
    rpmsenseFlags sense;

    rpmdsSetIx(trigger, 0);
    sense = rpmdsFlags(trigger);
    rpmdsInit(trigger);

    mfi->rpmdsTrigger = trigger;
    mfi->ts = ts;

    /* If inTransaction is set then filter out packages that aren't in transaction */
    if (inTransaction) {
	if (sense & RPMSENSE_TRIGGERIN)
	    mfi->tranPkgs = ts->members->installedPackages;
	else
	    mfi->tranPkgs = ts->members->removedPackages;
    }
    return mfi;
}

static const char *matchFilesNext(matchFilesIter mfi)
{
    const char *matchFile = NULL;
    int fx = 0;

    /* Decide if we iterate over given files (mfi->files) */
    if (!mfi->ts)
	do {
	    /* Get next file from mfi->fi */
	    matchFile = NULL;
	    while (matchFile == NULL && rpmfiNext(mfi->fi) >= 0) {
		if (!XFA_SKIPPING(rpmfsGetAction(mfi->fs, rpmfiFX(mfi->fi))))
		    matchFile = rpmfiFN(mfi->fi);
	    }
	    if (matchFile)
		break;

	    /* If we are done with current mfi->fi, create mfi->fi for next prefix */
	    fx = rpmdsNext(mfi->rpmdsTrigger);
	    mfi->pfx = rpmdsN(mfi->rpmdsTrigger);
	    rpmfiFree(mfi->fi);
	    mfi->fi = rpmfilesFindPrefix(mfi->files, mfi->pfx);

	} while (fx >= 0);
    /* or we iterate over files in rpmdb */
    else
	do {
	    matchFile = NULL;
	    while (matchFile == NULL && rpmfiNext(mfi->fi) >= 0) {
		if (RPMFILE_IS_INSTALLED(rpmfiFState(mfi->fi)))
		    matchFile = rpmfiFN(mfi->fi);
	    }
	    if (matchFile)
		break;

	    /* If we are done with current mfi->fi, create mfi->fi for next package */
	    rpmfilesFree(mfi->files);
	    rpmfiFree(mfi->fi);
	    mfi->files = rpmtsNextFiles(mfi);
	    mfi->fi = rpmfilesFindPrefix(mfi->files, mfi->pfx);
	    if (mfi->files)
		continue;

	    /* If we are done with all packages, go through packages with new prefix */
	    fx = rpmdsNext(mfi->rpmdsTrigger);
	    mfi->pfx = rpmdsN(mfi->rpmdsTrigger);
	    rpmdbFreeIterator(mfi->pi);
	    mfi->pi = rpmdbInitPrefixIterator(rpmtsGetRdb(mfi->ts),
						RPMDBI_DIRNAMES, mfi->pfx, 0);

	    rpmdbFilterIterator(mfi->pi, mfi->tranPkgs, 0);
	    /* Only walk through each header with matches once */
	    rpmdbUniqIterator(mfi->pi);

	} while (fx >= 0);


    return matchFile;
}

static int matchFilesEmpty(matchFilesIter mfi)
{
    const char *matchFile;

    /* Try to get the first file */
    matchFile = matchFilesNext(mfi);

    /* Rewind back this file */
    rpmfiInit(mfi->fi, 0);

    if (matchFile)
	/* We have at least one file so iterator is not empty */
	return 0;
    else
	/* No file in iterator */
	return 1;
}

static matchFilesIter matchFilesIteratorFree(matchFilesIter mfi)
{
    rpmfiFree(mfi->fi);
    rpmfilesFree(mfi->files);
    rpmdbFreeIterator(mfi->pi);
    free(mfi);
    return NULL;
}

/*
 * Run all file triggers in header h
 * @param searchMode	    0 match trigger prefixes against files in te
 *			    1 match trigger prefixes against files in whole ts
 *			    2 match trigger prefixes against files in whole
 *			      rpmdb
 */
static int runHandleTriggersInPkg(rpmts ts, rpmte te, Header h,
				rpmsenseFlags sense, rpmscriptTriggerModes tm,
				int searchMode, int ti, int arg1, int arg2)
{
    int nerrors = 0;
    rpmds rpmdsTriggers, rpmdsTrigger;
    rpmfiles files = NULL;
    matchFilesIter mfi = NULL;
    rpmScript script;
    struct rpmtd_s installPrefixes;
    nextfilefunc inputFunc;

    rpmdsTriggers = rpmdsNew(h, triggerDsTag(tm), 0);
    rpmdsTrigger = rpmdsFilterTi(rpmdsTriggers, ti);
    /*
     * Now rpmdsTrigger contains all dependencies belonging to one trigger
     * with trigger index tix. Have a look at the first one to check flags.
     */
    if ((rpmdsNext(rpmdsTrigger) >= 0) &&
	(rpmdsFlags(rpmdsTrigger) & sense)) {

	switch (searchMode) {
	    case 0:
		/* Create iterator over files in te that this trigger matches */
		files = rpmteFiles(te);
		mfi = matchFilesIterator(rpmdsTrigger, files, te);
		break;
	    case 1:
		/* Create iterator over files in ts that this trigger matches */
		mfi = matchDBFilesIterator(rpmdsTrigger, ts, 1);
		break;
	    case 2:
		/* Create iterator over files in whole rpmd that this trigger matches */
		mfi = matchDBFilesIterator(rpmdsTrigger, ts, 0);
		break;
	}

	/* If this trigger matches any file then run trigger script */
	if (!matchFilesEmpty(mfi)) {
	    script = rpmScriptFromTriggerTag(h, triggertag(sense), tm, ti);

	    headerGet(h, RPMTAG_INSTPREFIXES, &installPrefixes,
		    HEADERGET_ALLOC|HEADERGET_ARGV);


	    /*
	     * As input function set function to get next file from
	     * matching file iterator. As parameter for this function
	     * set matching file iterator. Input function will be called
	     * during execution of trigger script in order to get data
	     * that will be passed as stdin to trigger script. To get
	     * these data from lua script function rpm.input() can be used.
	     */
	    inputFunc = (nextfilefunc) matchFilesNext;
	    rpmScriptSetNextFileFunc(script, inputFunc, mfi);

	    /* Compute our own arg2 if asked */
	    if (arg2 < 0 && tm == RPMSCRIPT_FILETRIGGER && mfi->pkgname)
		arg2 = rpmdbCountPackages(rpmtsGetRdb(ts), mfi->pkgname);

	    ARGV_const_t prefixes = (ARGV_const_t)installPrefixes.data;
	    nerrors += runScript(ts, NULL, h, prefixes, script, arg1, arg2);
	    rpmtdFreeData(&installPrefixes);
	    rpmScriptFree(script);
	}
	rpmfilesFree(files);
	matchFilesIteratorFree(mfi);
    }
    rpmdsFree(rpmdsTrigger);
    rpmdsFree(rpmdsTriggers);

    return nerrors;
}

/* Return true if any file in package (te) starts with pfx */
static int matchFilesInPkg(rpmts ts, rpmte te, const char *pfx,
			    rpmsenseFlags sense)
{
    int rc;
    rpmfiles files = rpmteFiles(te);
    rpmfi fi = rpmfilesFindPrefix(files, pfx);

    rc = (fi != NULL);
    rpmfilesFree(files);
    rpmfiFree(fi);
    return rc;
}

/* Return number of added/removed files starting with pfx in transaction */
static int matchFilesInTran(rpmts ts, rpmte te, const char *pfx,
			    rpmsenseFlags sense)
{
    int rc = 1;
    rpmdbMatchIterator pi;

    /* Get all files from rpmdb starting with pfx */
    pi = rpmdbInitPrefixIterator(rpmtsGetRdb(ts), RPMDBI_DIRNAMES, pfx, 0);

    if (sense & RPMSENSE_TRIGGERIN)
	/* Leave in pi only files installed in ts */
	rpmdbFilterIterator(pi, ts->members->installedPackages, 0);
    else
	/* Leave in pi only files removed in ts */
	rpmdbFilterIterator(pi, ts->members->removedPackages, 0);

    rc = rpmdbGetIteratorCount(pi);
    rpmdbFreeIterator(pi);

    return rc;
}

rpmRC runFileTriggers(rpmts ts, rpmte te, int arg2, rpmsenseFlags sense,
			rpmscriptTriggerModes tm, int priorityClass)
{
    int nerrors = 0, i;
    rpmdbIndexIterator ii;
    const void *key;
    char *pfx;
    size_t keylen;
    Header trigH;
    const char * trigName = NULL;
    int arg1 = 0;
    int (*matchFunc)(rpmts, rpmte, const char*, rpmsenseFlags sense);
    rpmTagVal priorityTag;
    rpmtriggers triggers = rpmtriggersCreate(10);

    /* Decide if we match triggers against files in te or in whole ts */
    if (tm == RPMSCRIPT_FILETRIGGER) {
	matchFunc = matchFilesInPkg;
	priorityTag = RPMTAG_FILETRIGGERPRIORITIES;
    } else {
	matchFunc = matchFilesInTran;
	priorityTag = RPMTAG_TRANSFILETRIGGERPRIORITIES;
    }

    ii = rpmdbIndexIteratorInit(rpmtsGetRdb(ts), (rpmDbiTag)triggerDsTag(tm));

    /* Loop over all file triggers in rpmdb */
    while ((rpmdbIndexIteratorNext(ii, &key, &keylen)) == 0) {
	pfx = (char *)xmalloc(keylen + 1);
	memcpy(pfx, key, keylen);
	pfx[keylen] = '\0';

	/* Check if file trigger is fired by any file in ts/te */
	if (matchFunc(ts, te, pfx, sense)) {
	    for (i = 0; i < rpmdbIndexIteratorNumPkgs(ii); i++) {
		unsigned int priority = 0;
		unsigned int offset = rpmdbIndexIteratorPkgOffset(ii, i);
		unsigned int tix = rpmdbIndexIteratorTagNum(ii, i);

		/*
		 * Don't handle transaction triggers installed in current
		 * transaction to avoid executing the same script two times.
		 * These triggers are handled in runImmedFileTriggers().
		 */
		if (tm == RPMSCRIPT_TRANSFILETRIGGER &&
		    (packageHashHasEntry(ts->members->removedPackages, offset) ||
		    packageHashHasEntry(ts->members->installedPackages, offset)))
		    continue;

		/* Get priority of trigger from header */
		trigH = rpmdbGetHeaderAt(rpmtsGetRdb(ts), offset);
		priority = getTrigPriority(trigH, priorityTag, tix);
		headerFree(trigH);

		/* Store file trigger in array */
		rpmtriggersAdd(triggers, offset, tix, priority);
	    }
	}
	free(pfx);
    }
    rpmdbIndexIteratorFree(ii);

    /* Sort triggers by priority, offset, trigger index */
    rpmtriggersSortAndUniq(triggers);

    /* Handle stored triggers */
    for (i = 0; i < triggers->count; i++) {
	if (priorityClass == 1) {
	    if (triggers->triggerInfo[i].priority < TRIGGER_PRIORITY_BOUND)
		continue;
	} else if (priorityClass == 2) {
	    if (triggers->triggerInfo[i].priority >= TRIGGER_PRIORITY_BOUND)
		continue;
	}

	trigH = rpmdbGetHeaderAt(rpmtsGetRdb(ts), triggers->triggerInfo[i].hdrNum);
	trigName = headerGetString(trigH, RPMTAG_NAME);
	arg1 = rpmdbCountPackages(rpmtsGetRdb(ts), trigName);

	if (tm == RPMSCRIPT_FILETRIGGER)
	    nerrors += runHandleTriggersInPkg(ts, te, trigH, sense, tm, 0,
						triggers->triggerInfo[i].tix,
						arg1, arg2);
	else
	    nerrors += runHandleTriggersInPkg(ts, te, trigH, sense, tm, 1,
						triggers->triggerInfo[i].tix,
						arg1, arg2);
	headerFree(trigH);
    }
    rpmtriggersFree(triggers);

    return (nerrors == 0) ? RPMRC_OK : RPMRC_FAIL;
}

rpmRC runImmedFileTriggers(rpmts ts, rpmte te, int arg1, rpmsenseFlags sense,
			    rpmscriptTriggerModes tm, int priorityClass)
{
    int nerrors = 0;
    int triggersCount, i;
    Header trigH = rpmteHeader(te);
    struct rpmtd_s priorities;
    rpmTagVal priorityTag;
    rpmtriggers triggers;

    if (tm == RPMSCRIPT_FILETRIGGER) {
	priorityTag = RPMTAG_FILETRIGGERPRIORITIES;
    } else {
	priorityTag = RPMTAG_TRANSFILETRIGGERPRIORITIES;
    }
    headerGet(trigH, priorityTag, &priorities, HEADERGET_MINMEM);

    triggersCount = rpmtdCount(&priorities);
    triggers = rpmtriggersCreate(triggersCount);

    for (i = 0; i < triggersCount; i++) {
	unsigned int priority = RPMTRIGGER_DEFAULT_PRIORITY;
	if (rpmtdSetIndex(&priorities, i) >= 0)
	    priority = rpmtdGetNumber(&priorities);
	/* Offset is not important, all triggers are from the same package */
	rpmtriggersAdd(triggers, 0, i, priority);
    }

    /* Sort triggers by priority, offset, trigger index */
    rpmtriggersSortAndUniq(triggers);

    for (i = 0; i < triggersCount; i++) {
	if (priorityClass == 1) {
	    if (triggers->triggerInfo[i].priority < TRIGGER_PRIORITY_BOUND)
		continue;
	} else if (priorityClass == 2) {
	    if (triggers->triggerInfo[i].priority >= TRIGGER_PRIORITY_BOUND)
		continue;
	}

	nerrors += runHandleTriggersInPkg(ts, te, trigH, sense, tm, 2,
					    triggers->triggerInfo[i].tix,
					    arg1, -1);
    }
    rpmtriggersFree(triggers);
    headerFree(trigH);

    return (nerrors == 0) ? RPMRC_OK : RPMRC_FAIL;
}
