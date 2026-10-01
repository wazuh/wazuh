/**
 * \file lib/rpmps.c
 */

#include "system.h"

#include <inttypes.h>
#include <stdlib.h>

#include <rpm/rpmstring.h>
#include <rpm/rpmprob.h>

#include "debug.h"

struct rpmProblem_s {
    char * pkgNEVR;
    char * altNEVR;
    fnpyKey key;
    rpmProblemType type;
    char * str1;
    uint64_t num1;
    int nrefs;
};

static rpmProblem rpmProblemUnlink(rpmProblem prob);

rpmProblem rpmProblemCreate(rpmProblemType type,
                            const char * pkgNEVR, fnpyKey key,
                            const char * altNEVR,
                            const char * str, uint64_t number)
{
    rpmProblem p = (rpmProblem)xcalloc(1, sizeof(*p));

    p->type = type;
    p->key = key;
    p->num1 = number;

    p->pkgNEVR = (pkgNEVR ? xstrdup(pkgNEVR) : NULL);
    p->altNEVR = (altNEVR ? xstrdup(altNEVR) : NULL);
    p->str1 = (str ? xstrdup(str) : NULL);

    return rpmProblemLink(p);
}

rpmProblem rpmProblemFree(rpmProblem prob)
{
    if (prob == NULL) return NULL;

    if (prob->nrefs > 1) {
	return rpmProblemUnlink(prob);
    }
    prob->pkgNEVR = _free(prob->pkgNEVR);
    prob->altNEVR = _free(prob->altNEVR);
    prob->str1 = _free(prob->str1);
    free(prob);
    return NULL;
}

rpmProblem rpmProblemLink(rpmProblem prob)
{
    if (prob) {
	prob->nrefs++;
    }
    return prob;
}

static rpmProblem rpmProblemUnlink(rpmProblem prob)
{
    if (prob) {
	prob->nrefs--;
    }
    return NULL;
}

const char * rpmProblemGetPkgNEVR(rpmProblem p)
{
    return (p->pkgNEVR);
}

const char * rpmProblemGetAltNEVR(rpmProblem p)
{
    return (p->altNEVR);
}

fnpyKey rpmProblemGetKey(rpmProblem p)
{
    return (p->key);
}

rpmProblemType rpmProblemGetType(rpmProblem p)
{
    return (p->type);
}

const char * rpmProblemGetStr(rpmProblem p)
{
    return (p->str1);
}

rpm_loff_t rpmProblemGetDiskNeed(rpmProblem p)
{
    return (p->num1);
}

char * rpmProblemString(rpmProblem prob)
{
    const char * pkgNEVR = (prob->pkgNEVR ? prob->pkgNEVR : "?pkgNEVR?");
    const char * altNEVR = (prob->altNEVR ? prob->altNEVR : "? ?altNEVR?");
    const char * str1 = (prob->str1 ? prob->str1 : N_("different"));
    char * buf = NULL;

    switch (prob->type) {
    case RPMPROB_BADARCH:
	rasprintf(&buf, _("package %s is intended for a %s architecture"),
		pkgNEVR, str1);
	break;
    case RPMPROB_BADOS:
	rasprintf(&buf, _("package %s is intended for a %s operating system"),
		pkgNEVR, str1);
	break;
    case RPMPROB_PKG_INSTALLED:
	if (prob->num1)
	    rasprintf(&buf, _("package %s is already installed"), pkgNEVR);
	else
	    rasprintf(&buf, _("package %s is not installed"), pkgNEVR);
	break;
    case RPMPROB_BADRELOCATE:
	rasprintf(&buf, _("path %s in package %s is not relocatable"),
		str1, pkgNEVR);
	break;
    case RPMPROB_NEW_FILE_CONFLICT:
	rasprintf(&buf, 
		_("file %s conflicts between attempted installs of %s and %s"),
		str1, pkgNEVR, altNEVR);
	break;
    case RPMPROB_FILE_CONFLICT:
	rasprintf(&buf,
	    _("file %s from install of %s conflicts with file from package %s"),
		str1, pkgNEVR, altNEVR);
	break;
    case RPMPROB_OLDPACKAGE:
	rasprintf(&buf,
		_("package %s (which is newer than %s) is already installed"),
		altNEVR, pkgNEVR);
	break;
    case RPMPROB_DISKSPACE:
	rasprintf(&buf,
	    _("installing package %s needs %" PRIu64 "%cB more space on the %s filesystem"),
		pkgNEVR,
		prob->num1 > (1024*1024)
		    ? (prob->num1 + 1024 * 1024 - 1) / (1024 * 1024)
		    : (prob->num1 + 1023) / 1024,
		prob->num1 > (1024*1024) ? 'M' : 'K',
		str1);
	break;
    case RPMPROB_DISKNODES:
	rasprintf(&buf,
	    _("installing package %s needs %" PRIu64 " more inodes on the %s filesystem"),
		pkgNEVR, prob->num1, str1);
	break;
    case RPMPROB_REQUIRES:
	rasprintf(&buf, _("%s is needed by %s%s"),
		  prob->str1, (prob->num1 ? _("(installed) ") : ""), altNEVR);
	break;
    case RPMPROB_CONFLICT:
	rasprintf(&buf, _("%s conflicts with %s%s"),
		  prob->str1, (prob->num1 ? _("(installed) ") : ""), altNEVR);
	break;
    case RPMPROB_OBSOLETES:
	rasprintf(&buf, _("%s is obsoleted by %s%s"),
		  prob->str1, (prob->num1 ? _("(installed) ") : ""), altNEVR);
	break;
    case RPMPROB_VERIFY:
	rasprintf(&buf, _("package %s does not verify: %s"),
			pkgNEVR, prob->str1);
	break;
    default:
	rasprintf(&buf,
		_("unknown error %d encountered while manipulating package %s"),
		prob->type, pkgNEVR);
	break;
    }

    return buf;
}

static int cmpStr(const char *s1, const char *s2)
{
    if (s1 == s2) return 0;
    if (s1 && s2) return strcmp(s1, s2);
    return 1;
}

int rpmProblemCompare(rpmProblem ap, rpmProblem bp)
{
    if (ap == bp)
	return 0;
    if (ap == NULL || bp == NULL)
	return 1;
    if (ap->type != bp->type)
	return 1;
    if (ap->key != bp->key)
	return 1;
    if (ap->num1 != bp->num1)
	return 1;
    if (cmpStr(ap->pkgNEVR, bp->pkgNEVR))
	return 1;
    if (cmpStr(ap->altNEVR, bp->altNEVR))
	return 1;
    if (cmpStr(ap->str1, bp->str1))
	return 1;

    return 0;
}
