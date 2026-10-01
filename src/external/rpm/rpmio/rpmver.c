#include "system.h"

#include <rpm/rpmver.h>
#include <rpm/rpmstring.h>
#include <stdlib.h>

#include "debug.h"

struct rpmver_s {
    const char *e;
    const char *v;
    const char *r;
    char arena[];
};

/**
 * Split EVR into epoch, version, and release components.
 * @param evr		[epoch:]version[-release] string
 * @param[out] *ep		pointer to epoch
 * @param[out] *vp		pointer to version
 * @param[out] *rp		pointer to release
 */
static
void parseEVR(char * evr,
		const char ** ep,
		const char ** vp,
		const char ** rp)
{
    const char *epoch;
    const char *version;		/* assume only version is present */
    const char *release;
    char *s, *se;

    s = evr;
    while (*s && risdigit(*s)) s++;	/* s points to epoch terminator */
    se = strrchr(s, '-');		/* se points to version terminator */

    if (*s == ':') {
	epoch = evr;
	*s++ = '\0';
	version = s;
	if (*epoch == '\0') epoch = "0";
    } else {
	epoch = NULL;	/* XXX disable epoch compare if missing */
	version = evr;
    }
    if (se) {
	*se++ = '\0';
	release = se;
    } else {
	release = NULL;
    }

    if (ep) *ep = epoch;
    if (vp) *vp = version;
    if (rp) *rp = release;
}

int rpmverOverlap(rpmver v1, rpmsenseFlags f1, rpmver v2, rpmsenseFlags f2)
{
    int sense = 0;
    int result = 0;

    /* Compare {A,B} [epoch:]version[-release] */
    if (v1->e && *v1->e && v2->e && *v2->e)
	sense = rpmvercmp(v1->e, v2->e);
    else if (v1->e && *v1->e && atol(v1->e) > 0) {
	sense = 1;
    } else if (v2->e && *v2->e && atol(v2->e) > 0)
	sense = -1;

    if (sense == 0) {
	sense = rpmvercmp(v1->v, v2->v);
	if (sense == 0) {
	    if (v1->r && *v1->r && v2->r && *v2->r) {
		sense = rpmvercmp(v1->r, v2->r);
	    } else {
		/* always matches if the side with no release has SENSE_EQUAL */
		if ((v1->r && *v1->r && (f2 & RPMSENSE_EQUAL)) ||
		    (v2->r && *v2->r && (f1 & RPMSENSE_EQUAL))) {
		    result = 1;
		    goto exit;
		}
	    }
	}
    }

    /* Detect overlap of {A,B} range. */
    if (sense < 0 && ((f1 & RPMSENSE_GREATER) || (f2 & RPMSENSE_LESS))) {
	result = 1;
    } else if (sense > 0 && ((f1 & RPMSENSE_LESS) || (f2 & RPMSENSE_GREATER))) {
	result = 1;
    } else if (sense == 0 &&
	(((f1 & RPMSENSE_EQUAL) && (f2 & RPMSENSE_EQUAL)) ||
	 ((f1 & RPMSENSE_LESS) && (f2 & RPMSENSE_LESS)) ||
	 ((f1 & RPMSENSE_GREATER) && (f2 & RPMSENSE_GREATER)))) {
	result = 1;
    }

exit:
    return result;
}

static int compare_values(const char *str1, const char *str2)
{
    if (!str1 && !str2)
	return 0;
    else if (str1 && !str2)
	return 1;
    else if (!str1 && str2)
	return -1;
    return rpmvercmp(str1, str2);
}

int rpmverCmp(rpmver v1, rpmver v2)
{
    const char *e1 = (v1->e != NULL) ? v1->e : "0";
    const char *e2 = (v2->e != NULL) ? v2->e : "0";

    int rc = compare_values(e1, e2);
    if (!rc) {
	rc = compare_values(v1->v, v2->v);
	if (!rc)
	    rc = compare_values(v1->r, v2->r);
    }
    return rc;
}

uint32_t rpmverEVal(rpmver rv)
{
    return (rv != NULL && rv->e != NULL) ? atol(rv->e) : 0;
}

const char *rpmverE(rpmver rv)
{
    return (rv != NULL) ? rv->e : NULL;
}

const char *rpmverV(rpmver rv)
{
    return (rv != NULL) ? rv->v : NULL;
}

const char *rpmverR(rpmver rv)
{
    return (rv != NULL) ? rv->r : NULL;
}

char *rpmverEVR(rpmver rv)
{
    char *EVR = NULL;
    if (rv) {
	rstrscat(&EVR, rv->e ? rv-> e : "", rv->e ? ":" : "",
		       rv->v,
		       rv->r ? "-" : "", rv->r ? rv->r : "", NULL);
    }
    return EVR;
}

rpmver rpmverParse(const char *evr)
{
    rpmver rv = NULL;
    if (evr && *evr) {
	size_t evrlen = strlen(evr) + 1;
	rv = (rpmver)xmalloc(sizeof(*rv) + evrlen);
	memcpy(rv->arena, evr, evrlen);
	parseEVR(rv->arena, &rv->e, &rv->v, &rv->r);
    }
    return rv;
}

rpmver rpmverNew(const char *e, const char *v, const char *r)
{
    rpmver rv = NULL;

    if (v && *v) {
	size_t nb = strlen(v) + 1;
	nb += (e != NULL) ? strlen(e) + 1 : 0;
	nb += (r != NULL) ? strlen(r) + 1 : 0;
	rv = (rpmver)xmalloc(sizeof(*rv) + nb);

	rv->e = NULL;
	rv->v = NULL;
	rv->r = NULL;

	char *p = rv->arena;
	if (e) {
	    rv->e = p;
	    p = stpcpy(p, e);
	    p++;
	}

	rv->v = p;
	p = stpcpy(p, v);
	p++;

	if (r) {
	    rv->r = p;
	    p = stpcpy(p, r);
	    p++;
	}
    }
    return rv;
}

rpmver rpmverFree(rpmver rv)
{
    if (rv) {
	free(rv);
    }
    return NULL;
}
