/** \ingroup rpmts
 * \file lib/depends.c
 */

#include "system.h"

#include <rpm/rpmlib.h>		/* rpmVersionCompare, rpmlib provides */
#include <rpm/rpmtag.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmdb.h>
#include <rpm/rpmds.h>
#include <rpm/rpmfi.h>
#include <rpm/rpmstring.h>

#include "rpmts_internal.h"
#include "rpmte_internal.h"
#include "rpmds_internal.h"
#include "rpmfi_internal.h" /* rpmfiles stuff for now */
#include "misc.h"

#include "backend/dbiset.h"

#include "debug.h"

const char * const RPMVERSION = VERSION;

const char * const rpmNAME = PACKAGE;

const char * const rpmEVR = VERSION;

const int rpmFLAGS = RPMSENSE_EQUAL;

#define HASHTYPE depCache
#define HTKEYTYPE const char *
#define HTDATATYPE int
#include "rpmhash.H"
#include "rpmhash.C"
#undef HASHTYPE
#undef HTKEYTYPE
#undef HTDATATYPE

#define HASHTYPE packageHash
#define HTKEYTYPE unsigned int
#define HTDATATYPE struct rpmte_s *
#include "rpmhash.C"
#undef HASHTYPE
#undef HTKEYTYPE
#undef HTDATATYPE

#define HASHTYPE filedepHash
#define HTKEYTYPE rpmsid
#define HTDATATYPE rpmsid
#include "rpmhash.H"
#include "rpmhash.C"
#undef HASHTYPE
#undef HTKEYTYPE
#undef HTDATATYPE

#define HASHTYPE depexistsHash
#define HTKEYTYPE rpmsid
#include "rpmhash.H"
#include "rpmhash.C"
#undef HASHTYPE
#undef HTKEYTYPE

/**
 * Check for supported payload format in header.
 * @param h		header to check
 * @return		RPMRC_OK if supported, RPMRC_FAIL otherwise
 */
static rpmRC headerCheckPayloadFormat(Header h) {
    rpmRC rc = RPMRC_OK;
    const char *payloadfmt = headerGetString(h, RPMTAG_PAYLOADFORMAT);
    /* 
     * XXX Ugh, rpm 3.x packages don't have payload format tag. Instead
     * of blindly allowing, should check somehow (HDRID existence or... ?)
     */
    if (!payloadfmt) return rc;

    if (!rstreq(payloadfmt, "cpio")) {
        char *nevra = headerGetAsString(h, RPMTAG_NEVRA);
        if (payloadfmt && rstreq(payloadfmt, "drpm")) {
            rpmlog(RPMLOG_ERR,
                     _("%s is a Delta RPM and cannot be directly installed\n"),
                     nevra);
        } else {
            rpmlog(RPMLOG_ERR, 
                     _("Unsupported payload (%s) in package %s\n"),
                     payloadfmt ? payloadfmt : "none", nevra);
        } 
        free(nevra);
	rc = RPMRC_FAIL;
    }
    return rc;
}

static void addElement(tsMembers tsmem, rpmte te, int oc)
{
    if (oc >= tsmem->orderAlloced) {
	tsmem->orderAlloced += (oc - tsmem->orderAlloced) + tsmem->delta;
	tsmem->order = xrealloc(tsmem->order,
	tsmem->orderAlloced * sizeof(*tsmem->order));
    }

    tsmem->order[oc] = te;
    if (oc == tsmem->orderCount) {
	tsmem->orderCount++;
    }
}


/**
 * Add removed package instance to ordered transaction set.
 * @param ts		transaction set
 * @param h		header
 * @param depends	installed package of pair (or RPMAL_NOMATCH on erase)
 * @return		0 on success
 */
static int removePackage(rpmts ts, Header h, rpmte depends)
{
    tsMembers tsmem = rpmtsMembers(ts);
    rpmte p, *pp;
    unsigned int dboffset = headerGetInstance(h);

    /* Can't remove what's not installed */
    if (dboffset == 0) return 1;

    /* Filter out duplicate erasures. */
    if (packageHashGetEntry(tsmem->removedPackages, dboffset, &pp, NULL, NULL)) {
	if (depends)
	    rpmteSetDependsOn(pp[0], depends);
	return 0;
    }

    p = rpmteNew(ts, h, TR_REMOVED, NULL, NULL, 0);
    if (p == NULL)
	return 1;

    packageHashAddEntry(tsmem->removedPackages, dboffset, p);
    rpmteSetDependsOn(p, depends);

    addElement(tsmem, p, tsmem->orderCount);
    rpmtsNotifyChange(ts, RPMTS_EVENT_ADD, p, depends);

    return 0;
}

/* Return rpmdb iterator with removals optionally pruned out */
rpmdbMatchIterator rpmtsPrunedIterator(rpmts ts, rpmDbiTagVal tag,
					      const char * key, int prune)
{
    rpmdbMatchIterator mi = rpmtsInitIterator(ts, tag, key, 0);
    if (prune) {
	tsMembers tsmem = rpmtsMembers(ts);
	rpmdbPruneIterator(mi, tsmem->removedPackages);
    }
    return mi;
}

rpmdbMatchIterator rpmtsTeIterator(rpmts ts, rpmte te, int prune)
{
    rpmdbMatchIterator mi = rpmtsPrunedIterator(ts, RPMDBI_NAME, rpmteN(te), prune);
    rpmdbSetIteratorRE(mi, RPMTAG_EPOCH, RPMMIRE_STRCMP, rpmteE(te));
    rpmdbSetIteratorRE(mi, RPMTAG_VERSION, RPMMIRE_STRCMP, rpmteV(te));
    rpmdbSetIteratorRE(mi, RPMTAG_RELEASE, RPMMIRE_STRCMP, rpmteR(te));
    if (rpmtsColor(ts)) {
	rpmdbSetIteratorRE(mi, RPMTAG_ARCH, RPMMIRE_STRCMP, rpmteA(te));
	rpmdbSetIteratorRE(mi, RPMTAG_OS, RPMMIRE_STRCMP, rpmteO(te));
    }
    return mi;
}

/**
 * Decides whether to skip a package upgrade/obsoletion on TE color.
 *
 * @param tscolor	color of this transaction
 * @param color 	color of this transaction element
 * @param ocolor 	header color of the upgraded/obsoleted package
 *
 * @return		non-zero if the package should be skipped
 */
static int skipColor(rpm_color_t tscolor, rpm_color_t color, rpm_color_t ocolor)
{
    return tscolor && color && ocolor && !(color & ocolor);
}

/* Add erase elements for older packages of same color (if any). */
static int addSelfErasures(rpmts ts, rpm_color_t tscolor, int op,
				rpmte p, rpm_color_t hcolor, Header h)
{
    Header oh;
    rpmdbMatchIterator mi = rpmtsInitIterator(ts, RPMDBI_NAME, rpmteN(p), 0);
    int rc = 0;

    while ((oh = rpmdbNextIterator(mi)) != NULL) {
	/* Ignore colored packages not in our rainbow. */
	if (skipColor(tscolor, hcolor, headerGetNumber(oh, RPMTAG_HEADERCOLOR)))
	    continue;

	/* On reinstall, skip packages with differing NEVRA. */
	if (op != RPMTE_UPGRADE) {
	    char * ohNEVRA = headerGetAsString(oh, RPMTAG_NEVRA);
	    if (!rstreq(rpmteNEVRA(p), ohNEVRA)) {
		free(ohNEVRA);
		continue;
	    }
	    free(ohNEVRA);
	}

	if (removePackage(ts, oh, p)) {
	    rc = 1;
	    break;
	}
    }
    rpmdbFreeIterator(mi);
    return rc;
}

/* Add erase elements for obsoleted packages of same color (if any). */
static int addObsoleteErasures(rpmts ts, rpm_color_t tscolor, rpmte p)
{
    rpmstrPool tspool = rpmtsPool(ts);
    rpmds obsoletes = rpmdsInit(rpmteDS(p, RPMTAG_OBSOLETENAME));
    Header oh;
    int rc = 0;

    while (rpmdsNext(obsoletes) >= 0 && rc == 0) {
	const char * Name;
	rpmdbMatchIterator mi = NULL;

	if ((Name = rpmdsN(obsoletes)) == NULL)
	    continue;	/* XXX can't happen */

	mi = rpmtsPrunedIterator(ts, RPMDBI_NAME, Name, 1);

	while ((oh = rpmdbNextIterator(mi)) != NULL) {
	    int match;

	    /*
	     * Rpm prior to 3.0.3 does not have versioned obsoletes.
	     * If no obsoletes version info is available, match all names.
	     */
	    match = (rpmdsEVR(obsoletes) == NULL);
	    if (!match)
		match = rpmdsMatches(tspool, oh, -1, obsoletes, 1);

	    if (match) {
		char * ohNEVRA = headerGetAsString(oh, RPMTAG_NEVRA);
		rpmlog(RPMLOG_DEBUG, "  Obsoletes: %s\t\terases %s\n",
			rpmdsDNEVR(obsoletes)+2, ohNEVRA);
		free(ohNEVRA);

		if (removePackage(ts, oh, p)) {
		    rc = 1;
		    break;
		}
	    }
	}
	rpmdbFreeIterator(mi);
    }
    return rc;
}

/*
 * Lookup obsoletions in the added set. In theory there could
 * be more than one obsoleting package, but we only care whether this
 * has been obsoleted by *something* or not.
 */
static rpmte checkObsoleted(rpmal addedPackages, rpmds thisds)
{
    rpmte p = NULL;
    rpmte *matches = NULL;

    matches = rpmalAllObsoletes(addedPackages, thisds);
    if (matches) {
	p = matches[0];
	free(matches);
    }
    return p;
}

/*
 * Filtered rpmal lookup: on colored transactions there can be more
 * than one identical NEVR but different arch, this must be allowed.
 * Only a single element needs to be considred as there can only ever
 * be one previous element to be replaced.
 */
static rpmte checkAdded(rpmal addedPackages, rpm_color_t tscolor,
			rpmte te, rpmds ds)
{
    rpmte p = NULL;
    rpmte *matches = NULL;

    matches = rpmalAllSatisfiesDepend(addedPackages, ds);
    if (matches) {
	const char * arch = rpmteA(te);
	const char * os = rpmteO(te);

	for (rpmte *m = matches; m && *m; m++) {
	    if (tscolor) {
		const char * parch = rpmteA(*m);
		const char * pos = rpmteO(*m);

		if (arch == NULL || parch == NULL || os == NULL || pos == NULL)
		    continue;
		if (!rstreq(arch, parch) || !rstreq(os, pos))
		    continue;
	    }
	    p = *m;
	    break;
  	}
	free(matches);
    }
    return p;
}

/*
 * Check for previously added versions and obsoletions.
 * Return index where to place this element, or -1 to skip.
 * XXX OBSOLETENAME is a bit of a hack, but gives us what
 * we want from rpmal: we're only interested in added package
 * names here, not their provides.
 */
static int findPos(rpmts ts, rpm_color_t tscolor, rpmte te, int upgrade)
{
    tsMembers tsmem = rpmtsMembers(ts);
    int oc = tsmem->orderCount;
    int skip = 0;
    const char * name = rpmteN(te);
    const char * evr = rpmteEVR(te);
    rpmte p;
    rpmstrPool tspool = rpmtsPool(ts);
    rpmds oldChk = rpmdsSinglePool(tspool, RPMTAG_OBSOLETENAME,
				   name, evr, (RPMSENSE_LESS));
    rpmds newChk = rpmdsSinglePool(tspool, RPMTAG_OBSOLETENAME,
				   name, evr, (RPMSENSE_GREATER));
    rpmds sameChk = rpmdsSinglePool(tspool, RPMTAG_OBSOLETENAME,
				    name, evr, (RPMSENSE_EQUAL));
    rpmds obsChk = rpmteDS(te, RPMTAG_OBSOLETENAME);

    /* If obsoleting package has already been added, skip this. */
    if ((p = checkObsoleted(tsmem->addedPackages, rpmteDS(te, RPMTAG_NAME)))) {
	skip = 1;
	goto exit;
    }

    /* If obsoleted package has already been added, replace with this. */
    rpmdsInit(obsChk);
    while (rpmdsNext(obsChk) >= 0) {
	/* XXX Obsoletes are not colored */
	if ((p = checkAdded(tsmem->addedPackages, 0, te, obsChk))) {
	    goto exit;
	}
    }

    /* If same NEVR has already been added, skip this. */
    if ((p = checkAdded(tsmem->addedPackages, tscolor, te, sameChk))) {
	skip = 1;
	goto exit;
    }

    /* On upgrades... */
    if (upgrade) {
	/* ...if newer NEVR has already been added, skip this. */
	if ((p = checkAdded(tsmem->addedPackages, tscolor, te, newChk))) {
	    skip = 1;
	    goto exit;
	}

	/* ...if older NEVR has already been added, replace with this. */
	if ((p = checkAdded(tsmem->addedPackages, tscolor, te, oldChk))) {
	    goto exit;
	}
    }

exit:
    /* If we found a previous element we've something to say */
    if (p != NULL && rpmIsVerbose()) {
	const char *msg = skip ?
		    _("package %s was already added, skipping %s\n") :
		    _("package %s was already added, replacing with %s\n");
	rpmlog(RPMLOG_WARNING, msg, rpmteNEVRA(p), rpmteNEVRA(te));
    }

    /* If replacing a previous element, find out where it is. Pooh. */
    if (!skip && p != NULL) {
	for (oc = 0; oc < tsmem->orderCount; oc++) {
	    if (p == tsmem->order[oc])
		break;
	}
    }

    rpmdsFree(oldChk);
    rpmdsFree(newChk);
    rpmdsFree(sameChk);
    return (skip) ? -1 : oc;
}

rpmal rpmtsCreateAl(rpmts ts, rpmElementTypes types)
{
    rpmal al = NULL;
    if (ts) {
	rpmte p;
	rpmtsi pi;

	al = rpmalCreate(ts, (rpmtsNElements(ts) / 4) + 1);
	pi = rpmtsiInit(ts);
	while ((p = rpmtsiNext(pi, types)))
	    rpmalAdd(al, p);
	rpmtsiFree(pi);
    }
    return al;
}

static int addPackage(rpmts ts, Header h,
		    fnpyKey key, int op, rpmRelocation * relocs)
{
    tsMembers tsmem = rpmtsMembers(ts);
    rpm_color_t tscolor = rpmtsColor(ts);
    rpmte p = NULL;
    int isSource = headerIsSource(h);
    int ec = 0;
    int oc = tsmem->orderCount;

    /* Check for supported payload format if it's a package */
    if (key && headerCheckPayloadFormat(h) != RPMRC_OK) {
	ec = 1;
	goto exit;
    }

    /* Source packages are never "upgraded" */
    if (isSource)
	op = RPMTE_INSTALL;

    /* Do lazy (readonly?) open of rpm database for upgrades. */
    if (op != RPMTE_INSTALL && rpmtsGetRdb(ts) == NULL && rpmtsGetDBMode(ts) != -1) {
	if ((ec = rpmtsOpenDB(ts, rpmtsGetDBMode(ts))) != 0)
	    goto exit;
    }

    p = rpmteNew(ts, h, TR_ADDED, key, relocs, op);
    if (p == NULL) {
	ec = 1;
	goto exit;
    }

    /* Check binary packages for redundancies in the set */
    if (!isSource) {
	oc = findPos(ts, tscolor, p, (op == RPMTE_UPGRADE));
	/* If we're replacing a previously added element, free the old one */
	if (oc >= 0 && oc < tsmem->orderCount) {
	    rpmtsNotifyChange(ts, RPMTS_EVENT_DEL, tsmem->order[oc], p);
	    rpmalDel(tsmem->addedPackages, tsmem->order[oc]);
	    tsmem->order[oc] = rpmteFree(tsmem->order[oc]);
	/* If newer NEVR was already added, we're done */
	} else if (oc < 0) {
	    p = rpmteFree(p);
	    goto exit;
	}
    }

    addElement(tsmem, p, oc);
    rpmtsNotifyChange(ts, RPMTS_EVENT_ADD, p, NULL);

    
    if (tsmem->addedPackages == NULL) {
	tsmem->addedPackages = rpmalCreate(ts, 5);
    }
    rpmalAdd(tsmem->addedPackages, p);

    /* Add erasure elements for old versions and obsoletions on upgrades */
    /* XXX TODO: If either of these fails, we'd need to undo all additions */
    if (op != RPMTE_INSTALL)
	addSelfErasures(ts, tscolor, op, p, rpmteColor(p), h);
    if (op == RPMTE_UPGRADE)
	addObsoleteErasures(ts, tscolor, p);

exit:
    return ec;
}

int rpmtsAddInstallElement(rpmts ts, Header h,
			fnpyKey key, int upgrade, rpmRelocation * relocs)
{
    int op = (upgrade == 0) ? RPMTE_INSTALL : RPMTE_UPGRADE;
    if (rpmtsSetupTransactionPlugins(ts) == RPMRC_FAIL)
	return 1;
    return addPackage(ts, h, key, op, relocs);
}

int rpmtsAddReinstallElement(rpmts ts, Header h, fnpyKey key)
{
    if (rpmtsSetupTransactionPlugins(ts) == RPMRC_FAIL)
	return 1;
    /* TODO: pull relocations from installed package */
    /* TODO: should reinstall of non-installed package fail? */
    return addPackage(ts, h, key, RPMTE_REINSTALL, NULL);
}

int rpmtsAddRestoreElement(rpmts ts, Header h)
{
    tsMembers tsmem = rpmtsMembers(ts);
    if (rpmtsSetupTransactionPlugins(ts) == RPMRC_FAIL)
	return 1;

    rpmte p = rpmteNew(ts, h, TR_RESTORED, NULL, NULL, 0);
    if (p == NULL)
	return 1;

    addElement(tsmem, p, tsmem->orderCount);
    rpmtsNotifyChange(ts, RPMTS_EVENT_ADD, p, NULL);

    return 0;
}

int rpmtsAddEraseElement(rpmts ts, Header h, int dboffset)
{
    if (rpmtsSetupTransactionPlugins(ts) == RPMRC_FAIL)
	return 1;
    return removePackage(ts, h, NULL);
}

/* Cached rpmdb provide lookup, returns 0 if satisfied, 1 otherwise */
static int rpmdbProvides(rpmts ts, depCache dcache, rpmds dep, dbiIndexSet *matches)
{
    const char * Name = rpmdsN(dep);
    const char * DNEVR = rpmdsDNEVR(dep);
    rpmTagVal deptag = rpmdsTagN(dep);
    int *cachedrc = NULL;
    rpmdbMatchIterator mi = NULL;
    Header h = NULL;
    int rc = 0;
    /* pretrans deps are provided by current packages, don't prune erasures */
    int prune = (rpmdsFlags(dep) & (RPMSENSE_PRETRANS|RPMSENSE_PREUNTRANS)) ? 0 : 1;
    unsigned int keyhash = 0;

    /* See if we already looked this up */
    if (prune && !matches) {
	keyhash = depCacheKeyHash(dcache, DNEVR);
	if (depCacheGetHEntry(dcache, DNEVR, keyhash, &cachedrc, NULL, NULL)) {
	    rc = *cachedrc;
	    rpmdsNotify(dep, "(cached)", rc);
	    return rc;
	}
    }

    if (matches)
	*matches = dbiIndexSetNew(0);
    /*
     * See if a filename dependency is a real file in some package,
     * taking file state into account: replaced, wrong colored and
     * not installed files can not satisfy a dependency.
     */
    if (deptag != RPMTAG_OBSOLETENAME && Name[0] == '/') {
	mi = rpmtsPrunedIterator(ts, RPMDBI_INSTFILENAMES, Name, prune);
	while ((h = rpmdbNextIterator(mi)) != NULL) {
	    /* Ignore self-conflicts */
	    if (deptag == RPMTAG_CONFLICTNAME) {
		unsigned int instance = headerGetInstance(h);
		if (instance && instance == rpmdsInstance(dep))
		    continue;
	    }
	    if (matches) {
		dbiIndexSetAppendOne(*matches, headerGetInstance(h), 0, 0);
		continue;
	    }
	    rpmdsNotify(dep, "(db files)", rc);
	    break;
	}
	rpmdbFreeIterator(mi);
    }

    /* Otherwise look in provides no matter what the dependency looks like */
    if (h == NULL) {
	rpmstrPool tspool = rpmtsPool(ts);
	/* Obsoletes use just name alone, everything else uses provides */
	rpmTagVal dbtag = RPMDBI_PROVIDENAME;
	int selfevr = 0;
	if (deptag == RPMTAG_OBSOLETENAME) {
	    dbtag = RPMDBI_NAME;
	    selfevr = 1;
	}

	mi = rpmtsPrunedIterator(ts, dbtag, Name, prune);
	while ((h = rpmdbNextIterator(mi)) != NULL) {
	    /* Provide-indexes can't be used with nevr-only matching */
	    int prix = (selfevr) ? -1 : rpmdbGetIteratorFileNum(mi);
	    int match = rpmdsMatches(tspool, h, prix, dep, selfevr);
	    /* Ignore self-obsoletes and self-conflicts */
	    if (match && (deptag == RPMTAG_OBSOLETENAME || deptag == RPMTAG_CONFLICTNAME)) {
		unsigned int instance = headerGetInstance(h);
		if (instance && instance == rpmdsInstance(dep))
		    match = 0;
	    }
	    if (match) {
		if (matches) {
		    dbiIndexSetAppendOne(*matches, headerGetInstance(h), 0, 0);
		    continue;
		}
		rpmdsNotify(dep, "(db provides)", rc);
		break;
	    }
	}
	rpmdbFreeIterator(mi);
    }
    rc = (h != NULL) ? 0 : 1;

    if (matches) {
	dbiIndexSetUniq(*matches, 0);
	rc = dbiIndexSetCount(*matches) ? 0 : 1;
    }

    /* Cache the relatively expensive rpmdb lookup results */
    /* Caching the oddball non-pruned case would mess up other results */
    if (prune && !matches)
	depCacheAddHEntry(dcache, xstrdup(DNEVR), keyhash, rc);
    return rc;
}

static dbiIndexSet unsatisfiedDependSet(rpmts ts, rpmds dep)
{
    dbiIndexSet set1 = NULL, set2 = NULL;
    tsMembers tsmem = rpmtsMembers(ts);
    rpmsenseFlags dsflags = rpmdsFlags(dep);

    if (dsflags & RPMSENSE_RPMLIB)
	goto exit;

    if (rpmdsIsRich(dep)) {
	rpmds ds1, ds2; 
	rpmrichOp op;
	char *emsg = 0; 

	if (rpmdsParseRichDep(dep, &ds1, &ds2, &op, &emsg) != RPMRC_OK) {
	    rpmdsNotify(dep, emsg ? emsg : "(parse error)", 1);  
	    _free(emsg);
	    goto exit;
	}
	/* only a subset of ops is supported in set mode */
	if (op != RPMRICHOP_WITH && op != RPMRICHOP_WITHOUT
            && op != RPMRICHOP_OR && op != RPMRICHOP_SINGLE) {
	    rpmdsNotify(dep, "(unsupported op in set mode)", 1);  
	    goto exit_rich;
	}

	set1 = unsatisfiedDependSet(ts, ds1);
	if (op == RPMRICHOP_SINGLE)
	    goto exit_rich;
	if (op != RPMRICHOP_OR && dbiIndexSetCount(set1) == 0)
	    goto exit_rich;
	set2 = unsatisfiedDependSet(ts, ds2);
	if (op == RPMRICHOP_WITH) {
	    dbiIndexSetFilterSet(set1, set2, 0);
	} else if (op == RPMRICHOP_WITHOUT) {
	    dbiIndexSetPruneSet(set1, set2, 0);
	} else if (op == RPMRICHOP_OR) {
	    dbiIndexSetAppendSet(set1, set2, 0);
	}
exit_rich:
	ds1 = rpmdsFree(ds1);
	ds2 = rpmdsFree(ds2);
	goto exit;
    }

    /* match database entries */
    rpmdbProvides(ts, NULL, dep, &set1);

    /* Pretrans dependencies can't be satisfied by added packages. */
    if (!(dsflags & (RPMSENSE_PRETRANS|RPMSENSE_PREUNTRANS))) {
	rpmte *matches = rpmalAllSatisfiesDepend(tsmem->addedPackages, dep);
	if (matches) {
	    for (rpmte *p = matches; *p; p++)
		dbiIndexSetAppendOne(set1, rpmalLookupTE(tsmem->addedPackages, *p), 1, 0);
	}
	_free(matches);
    }

exit:
    set2 = dbiIndexSetFree(set2);
    return set1 ? set1 : dbiIndexSetNew(0);
}

/**
 * Check dep for an unsatisfied dependency.
 * @param ts		transaction set
 * @param dcache	dependency cache
 * @param dep		dependency
 * @return		0 if satisfied, 1 if not satisfied
 */
static int unsatisfiedDepend(rpmts ts, depCache dcache, rpmds dep)
{
    tsMembers tsmem = rpmtsMembers(ts);
    int rc;
    int retrying = 0;
    int adding = (rpmdsInstance(dep) == 0);
    rpmsenseFlags dsflags = rpmdsFlags(dep);

retry:
    rc = 0;	/* assume dependency is satisfied */

    /*
     * New features in rpm packaging implicitly add versioned dependencies
     * on rpmlib provides. The dependencies look like "rpmlib(YaddaYadda)".
     * Check those dependencies now.
     */
    if (dsflags & RPMSENSE_RPMLIB) {
	if (tsmem->rpmlib == NULL)
	    rpmdsRpmlibPool(rpmtsPool(ts), &(tsmem->rpmlib), NULL);
	
	if (tsmem->rpmlib != NULL && rpmdsSearch(tsmem->rpmlib, dep) >= 0) {
	    rpmdsNotify(dep, "(rpmlib provides)", rc);
	    goto exit;
	}
	goto unsatisfied;
    }

    /* Dont look at pre-requisites of already installed packages */
    if (!adding && isTransientReq(dsflags))
	goto exit;

    /* Handle rich dependencies */
    if (rpmdsIsRich(dep)) {
	rpmds ds1, ds2; 
	rpmrichOp op;
	char *emsg = 0; 
	if (rpmdsParseRichDep(dep, &ds1, &ds2, &op, &emsg) != RPMRC_OK) {
	    rc = rpmdsTagN(dep) == RPMTAG_CONFLICTNAME ? 0 : 1;
	    if (rpmdsInstance(dep) != 0)
		rc = !rc;	/* ignore errors for installed packages */
	    rpmdsNotify(dep, emsg ? emsg : "(parse error)", rc);  
	    _free(emsg);
	    goto exit;
	}
	if (op == RPMRICHOP_WITH || op == RPMRICHOP_WITHOUT) {
	    /* switch to set mode processing */
	    dbiIndexSet set = unsatisfiedDependSet(ts, dep);
	    rc = dbiIndexSetCount(set) ? 0 : 1;
	    dbiIndexSetFree(set);
	    ds1 = rpmdsFree(ds1);
	    ds2 = rpmdsFree(ds2);
	    rpmdsNotify(dep, "(rich)", rc);
	    goto exit;
	}
	if (op == RPMRICHOP_IF || op == RPMRICHOP_UNLESS) {
	    /* A IF B -> A OR NOT(B) */
	    /* A UNLESS B -> A AND NOT(B) */
	    if (rpmdsIsRich(ds2)) {
		/* check if this has an ELSE clause */
		rpmds ds21 = NULL, ds22 = NULL;
		rpmrichOp op2;
		if (rpmdsParseRichDep(ds2, &ds21, &ds22, &op2, NULL) == RPMRC_OK && op2 == RPMRICHOP_ELSE) {
		    /* A IF B ELSE C -> (A OR NOT(B)) AND (C OR B) */
		    /* A UNLESS B ELSE C -> (A AND NOT(B)) OR (C AND B) */
		    rc = !unsatisfiedDepend(ts, dcache, ds21);	/* NOT(B) */
		    if ((rc && op == RPMRICHOP_IF) || (!rc && op == RPMRICHOP_UNLESS)) {
			rc = unsatisfiedDepend(ts, dcache, ds1);	/* A */
		    } else {
			rc = unsatisfiedDepend(ts, dcache, ds22);	/* C */
		    }
		    rpmdsFree(ds21);
		    rpmdsFree(ds22);
		    goto exitrich;
		}
		rpmdsFree(ds21);
		rpmdsFree(ds22);
	    }
	    rc = !unsatisfiedDepend(ts, dcache, ds2);	/* NOT(B) */
	    if ((rc && op == RPMRICHOP_IF) || (!rc && op == RPMRICHOP_UNLESS))
		rc = unsatisfiedDepend(ts, dcache, ds1);
	} else {
	    rc = unsatisfiedDepend(ts, dcache, ds1);
	    if ((rc && op == RPMRICHOP_OR) || (!rc && op == RPMRICHOP_AND))
		rc = unsatisfiedDepend(ts, dcache, ds2);
	}
exitrich:
	ds1 = rpmdsFree(ds1);
	ds2 = rpmdsFree(ds2);
	rpmdsNotify(dep, "(rich)", rc);
	goto exit;
    }

    /* Pretrans dependencies can't be satisfied by added packages. */
    if (!(dsflags & (RPMSENSE_PRETRANS|RPMSENSE_PREUNTRANS))) {
	rpmte *matches = rpmalAllSatisfiesDepend(tsmem->addedPackages, dep);
	int match = matches && *matches;
	_free(matches);
	if (match)
	    goto exit;
    }

    /* See if the rpmdb provides it */
    if (rpmdbProvides(ts, dcache, dep, NULL) == 0)
	goto exit;

    /* Search for an unsatisfied dependency. */
    if (adding && !retrying && !(dsflags & (RPMSENSE_PRETRANS|RPMSENSE_PREUNTRANS))) {
	int xx = rpmtsSolve(ts, dep);
	if (xx == 0)
	    goto exit;
	if (xx == -1) {
	    retrying = 1;
	    goto retry;
	}
    }

unsatisfied:
    if (dsflags & RPMSENSE_MISSINGOK) {
	/* note the result, but missingok deps are never unsatisfied */
	rpmdsNotify(dep, "(missingok)", 1);
    } else {
	/* dependency is unsatisfied */
	rc = 1;
	rpmdsNotify(dep, NULL, rc);
    }

exit:
    return rc;
}

/* Check a dependency set for problems */
static void checkDS(rpmts ts, depCache dcache, rpmte te,
		const char * pkgNEVRA, rpmds ds,
		rpm_color_t tscolor)
{
    rpm_color_t dscolor;
    /* require-problems are unsatisfied, others appear "satisfied" */
    int is_problem = (rpmdsTagN(ds) == RPMTAG_REQUIRENAME);

    ds = rpmdsInit(ds);
    while (rpmdsNext(ds) >= 0) {
	/* Ignore colored dependencies not in our rainbow. */
	dscolor = rpmdsColor(ds);
	if (tscolor && dscolor && !(tscolor & dscolor))
	    continue;

	if (unsatisfiedDepend(ts, dcache, ds) == is_problem)
	    rpmteAddDepProblem(te, pkgNEVRA, ds, NULL);
    }
}

/* Check a given dependency against installed packages */
static void checkInstDeps(rpmts ts, depCache dcache, rpmte te,
			  rpmTag depTag, const char *dep, rpmds depds, int neg)
{
    Header h;
    rpmdbMatchIterator mi;
    rpmstrPool pool = rpmtsPool(ts);
    char *ndep = NULL;
    /* require-problems are unsatisfied, others appear "satisfied" */
    int is_problem = (depTag == RPMTAG_REQUIRENAME);

    if (depds)
	dep = rpmdsN(depds);
    if (neg) {
	ndep = (char *)xmalloc(strlen(dep) + 2);
	ndep[0] = '!';
	strcpy(ndep + 1, dep);
	dep = ndep;
    }

    mi = rpmtsPrunedIterator(ts, depTag, dep, 1);
    while ((h = rpmdbNextIterator(mi)) != NULL) {
	int match = 1;
	rpmds ds;

	/* Ignore self-obsoletes and self-conflicts */
	if (depTag == RPMTAG_OBSOLETENAME || depTag == RPMTAG_CONFLICTNAME) {
	    unsigned int instance = headerGetInstance(h);
	    if (instance && instance == rpmteDBInstance(te))
		continue;
	}

	ds = rpmdsNewPool(pool, h, depTag, 0);
	rpmdsSetIx(ds, rpmdbGetIteratorFileNum(mi));

	/* Is it in our range at all? (but file deps have no range) */
	if (depds && !rpmdsIsRich(ds))
	    match = rpmdsCompare(ds, depds);

	if (match && unsatisfiedDepend(ts, dcache, ds) == is_problem) {
	    char *pkgNEVRA = headerGetAsString(h, RPMTAG_NEVRA);
	    rpmteAddDepProblem(te, pkgNEVRA, ds, NULL);
	    free(pkgNEVRA);
	}

	rpmdsFree(ds);
    }
    rpmdbFreeIterator(mi);
    free(ndep);
}

static void checkInstFileDeps(rpmts ts, depCache dcache, rpmte te,
			      rpmTag depTag, rpmfi fi, int is_not,
			      filedepHash cache, fingerPrintCache *fpcp)
{
    rpmstrPool pool = rpmtsPool(ts);
    fingerPrintCache fpc = *fpcp;
    fingerPrint * fp = NULL;
    rpmsid basename = rpmfiBNId(fi);
    rpmsid dirname;
    rpmsid *dirnames = 0;
    int ndirnames = 0;
    int i;

    filedepHashGetEntry(cache, basename, &dirnames, &ndirnames, NULL);
    if (!ndirnames)
	return;
    dirname = rpmfiDNId(fi);
    for (i = 0; i < ndirnames; i++) {
	char *fpdep = 0;
	const char *dep;
	if (dirnames[i] == dirname) {
	    dep = rpmfiFN(fi);
	} else {
	    if (!fpc)
		*fpcp = fpc = fpCacheCreate(1001, pool);
	    if (!fp)
		fpLookupId(fpc, dirname, basename, &fp);
	    if (!fpLookupEqualsId(fpc, fp, dirnames[i], basename))
		continue;
	    rstrscat(&fpdep, rpmstrPoolStr(pool, dirnames[i]),
                             rpmstrPoolStr(pool, basename), NULL);
	    dep = fpdep;
	}
	checkInstDeps(ts, dcache, te, depTag, dep, NULL, is_not);
	_free(fpdep);
    }
    _free(fp);
}

static void addFileDepToHash(rpmstrPool pool, filedepHash hash, char *key, size_t keylen)
{
    int i;
    rpmsid basename, dirname;
    if (!keylen || key[0] != '/')
	return;
    for (i = keylen - 1; key[i] != '/'; i--) 
	;
    i++;	/* include '/' in dirname */
    dirname = rpmstrPoolIdn(pool, key, i, 1);
    basename = rpmstrPoolIdn(pool, key + i, keylen - i, 1);
    filedepHashAddEntry(hash, basename, dirname);
}

static void addDepToHash(rpmstrPool pool, depexistsHash hash, char *key, size_t keylen)
{
    if (keylen)
	depexistsHashAddEntry(hash, rpmstrPoolIdn(pool, key, keylen, 1));
}

static void addIndexToDepHashes(rpmts ts, rpmDbiTag tag,
				depexistsHash dephash, filedepHash filehash,
				depexistsHash depnothash, filedepHash filenothash)
{
    rpmstrPool pool = rpmtsPool(ts);
    char *key;
    size_t keylen;
    rpmdbIndexIterator ii = rpmdbIndexKeyIteratorInit(rpmtsGetRdb(ts), tag);

    if (!ii)
	return;
    while ((rpmdbIndexIteratorNext(ii, (const void**)&key, &keylen)) == 0) {
	if (!key || !keylen)
	    continue;
	if (*key == '!' && keylen > 1) {
	    key++;
	    keylen--;
	    if (*key == '/' && filenothash)
		addFileDepToHash(pool, filenothash, key, keylen);
	    if (depnothash)
		addDepToHash(pool, depnothash, key, keylen);
	} else {
	    if (*key == '/' && filehash)
		addFileDepToHash(pool, filehash, key, keylen);
	    if (dephash)
		addDepToHash(pool, dephash, key, keylen);
	}
    }
    rpmdbIndexIteratorFree(ii);
}

static unsigned int sidHash(rpmsid sid)
{
    return sid;
}

static int sidCmp(rpmsid a, rpmsid b)
{
    return (a != b);
}


int rpmtsCheck(rpmts ts)
{
    rpm_color_t tscolor = rpmtsColor(ts);
    rpmtsi pi = NULL; rpmte p;
    int closeatexit = 0;
    int rc = 0;
    depCache dcache = NULL;
    filedepHash confilehash = NULL;	/* file conflicts of installed packages */
    filedepHash connotfilehash = NULL;	/* file conflicts of installed packages */
    depexistsHash connothash = NULL;
    filedepHash reqfilehash = NULL;	/* file requires of installed packages */
    filedepHash reqnotfilehash = NULL;	/* file requires of installed packages */
    depexistsHash reqnothash = NULL;
    fingerPrintCache fpc = NULL;
    rpmdb rdb = NULL;
    
    (void) rpmswEnter(rpmtsOp(ts, RPMTS_OP_CHECK), 0);

    /* Do lazy, readonly, open of rpm database. */
    rdb = rpmtsGetRdb(ts);
    if (rdb == NULL && rpmtsGetDBMode(ts) != -1) {
	if ((rc = rpmtsOpenDB(ts, rpmtsGetDBMode(ts))) != 0)
	    goto exit;
	rdb = rpmtsGetRdb(ts);
	closeatexit = 1;
    }

    if (rdb)
	rpmdbCtrl(rdb, RPMDB_CTRL_LOCK_RO);

    /* XXX FIXME: figure some kind of heuristic for the cache size */
    dcache = depCacheCreate(5001, rstrhash, strcmp,
				     (depCacheFreeKey)rfree, NULL);

    /* build hashes of all confilict sdependencies */
    confilehash = filedepHashCreate(257, sidHash, sidCmp, NULL, NULL);
    connothash = depexistsHashCreate(257, sidHash, sidCmp, NULL);
    connotfilehash = filedepHashCreate(257, sidHash, sidCmp, NULL, NULL);
    addIndexToDepHashes(ts, RPMDBI_CONFLICTNAME, NULL, confilehash, connothash, connotfilehash);
    if (!filedepHashNumKeys(confilehash))
	confilehash = filedepHashFree(confilehash);
    if (!depexistsHashNumKeys(connothash))
	connothash= depexistsHashFree(connothash);
    if (!filedepHashNumKeys(connotfilehash))
	connotfilehash = filedepHashFree(connotfilehash);

    /* build hashes of all requires dependencies */
    reqfilehash = filedepHashCreate(8191, sidHash, sidCmp, NULL, NULL);
    reqnothash = depexistsHashCreate(257, sidHash, sidCmp, NULL);
    reqnotfilehash = filedepHashCreate(257, sidHash, sidCmp, NULL, NULL);
    addIndexToDepHashes(ts, RPMDBI_REQUIRENAME, NULL, reqfilehash, reqnothash, reqnotfilehash);
    if (!filedepHashNumKeys(reqfilehash))
	reqfilehash = filedepHashFree(reqfilehash);
    if (!depexistsHashNumKeys(reqnothash))
	reqnothash= depexistsHashFree(reqnothash);
    if (!filedepHashNumKeys(reqnotfilehash))
	reqnotfilehash = filedepHashFree(reqnotfilehash);

    /*
     * Look at all of the added packages and make sure their dependencies
     * are satisfied.
     */
    pi = rpmtsiInit(ts);
    while ((p = rpmtsiNext(pi, TR_ADDED)) != NULL) {
	rpmds provides = rpmdsInit(rpmteDS(p, RPMTAG_PROVIDENAME));

	rpmlog(RPMLOG_DEBUG, "========== +++ %s %s/%s 0x%x\n",
		rpmteNEVR(p), rpmteA(p), rpmteO(p), rpmteColor(p));

	checkDS(ts, dcache, p, rpmteNEVRA(p), rpmteDS(p, RPMTAG_REQUIRENAME),
		tscolor);
	checkDS(ts, dcache, p, rpmteNEVRA(p), rpmteDS(p, RPMTAG_CONFLICTNAME),
		tscolor);
	checkDS(ts, dcache, p, rpmteNEVRA(p), rpmteDS(p, RPMTAG_OBSOLETENAME),
		tscolor);

	/* Skip obsoletion and provides checks for source packages (ie build) */
	if (rpmteIsSource(p))
	    continue;

	/* Check provides against conflicts in installed packages. */
	while (rpmdsNext(provides) >= 0) {
	    checkInstDeps(ts, dcache, p, RPMTAG_CONFLICTNAME, NULL, provides, 0);
	    if (reqnothash && depexistsHashHasEntry(reqnothash, rpmdsNId(provides)))
		checkInstDeps(ts, dcache, p, RPMTAG_REQUIRENAME, NULL, provides, 1);
	}

	/* Check package name (not provides!) against installed obsoletes */
	checkInstDeps(ts, dcache, p, RPMTAG_OBSOLETENAME, NULL, rpmteDS(p, RPMTAG_NAME), 0);

	/* Check filenames against installed conflicts */
        if (confilehash || reqnotfilehash) {
	    rpmfiles files = rpmteFiles(p);
	    rpmfi fi = rpmfilesIter(files, RPMFI_ITER_FWD);
	    while (rpmfiNext(fi) >= 0) {
		if (confilehash)
		    checkInstFileDeps(ts, dcache, p, RPMTAG_CONFLICTNAME, fi, 0, confilehash, &fpc);
		if (reqnotfilehash)
		    checkInstFileDeps(ts, dcache, p, RPMTAG_REQUIRENAME, fi, 1, reqnotfilehash, &fpc);
	    }
	    rpmfiFree(fi);
	    rpmfilesFree(files);
	}
    }
    rpmtsiFree(pi);

    /*
     * Look at the removed packages and make sure they aren't critical.
     */
    pi = rpmtsiInit(ts);
    while ((p = rpmtsiNext(pi, TR_REMOVED)) != NULL) {
	rpmds provides = rpmdsInit(rpmteDS(p, RPMTAG_PROVIDENAME));

	rpmlog(RPMLOG_DEBUG, "========== --- %s %s/%s 0x%x\n",
		rpmteNEVR(p), rpmteA(p), rpmteO(p), rpmteColor(p));

	/* Check provides and filenames against installed dependencies. */
	while (rpmdsNext(provides) >= 0) {
	    checkInstDeps(ts, dcache, p, RPMTAG_REQUIRENAME, NULL, provides, 0);
	    if (connothash && depexistsHashHasEntry(connothash, rpmdsNId(provides)))
		checkInstDeps(ts, dcache, p, RPMTAG_CONFLICTNAME, NULL, provides, 1);
	}

	if (reqfilehash || connotfilehash) {
	    rpmfiles files = rpmteFiles(p);
	    rpmfi fi = rpmfilesIter(files, RPMFI_ITER_FWD);
	    while (rpmfiNext(fi) >= 0) {
		if (RPMFILE_IS_INSTALLED(rpmfiFState(fi))) {
		    if (reqfilehash)
			checkInstFileDeps(ts, dcache, p, RPMTAG_REQUIRENAME, fi, 0, reqfilehash, &fpc);
		    if (connotfilehash)
			checkInstFileDeps(ts, dcache, p, RPMTAG_CONFLICTNAME, fi, 1, connotfilehash, &fpc);
		}
	    }
	    rpmfiFree(fi);
	    rpmfilesFree(files);
	}
    }
    rpmtsiFree(pi);

    if (rdb)
	rpmdbCtrl(rdb, RPMDB_CTRL_UNLOCK_RO);

exit:
    depCacheFree(dcache);
    filedepHashFree(confilehash);
    filedepHashFree(connotfilehash);
    depexistsHashFree(connothash);
    filedepHashFree(reqfilehash);
    filedepHashFree(reqnotfilehash);
    depexistsHashFree(reqnothash);
    fpCacheFree(fpc);

    (void) rpmswExit(rpmtsOp(ts, RPMTS_OP_CHECK), 0);

    if (closeatexit)
	(void) rpmtsCloseDB(ts);
    return rc;
}
