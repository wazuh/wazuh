/** \ingroup rpmdep
 * \file lib/rpmds.c
 */
#include "system.h"

#include <rpm/rpmtypes.h>
#include <rpm/rpmlib.h>		/* rpmvercmp */
#include <rpm/rpmstring.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmstrpool.h>
#include <rpm/rpmbase64.h>

#include "rpmds_internal.h"

#include "debug.h"

/**
 * A package dependency set.
 */
struct rpmds_s {
    rpmstrPool pool;		/*!< String pool. */
    const char * Type;		/*!< Tag name. */
    char * DNEVR;		/*!< Formatted dependency string. */
    rpmsid * N;			/*!< Dependency name id's (pool) */
    rpmsid * EVR;		/*!< Dependency EVR id's (pool) */
    rpmsenseFlags * Flags;	/*!< Bit(s) identifying context/comparison. */
    rpm_color_t * Color;	/*!< Bit(s) calculated from file color(s). */
    rpmTagVal tagN;		/*!< Header tag. */
    int32_t Count;		/*!< No. of elements */
    unsigned int instance;	/*!< From rpmdb instance? */
    int i;			/*!< Element index. */
    int nrefs;			/*!< Reference count. */
    int *ti;			/*!< Trigger index. */
};

struct depinfo_s {
    rpmTagVal typeTag;
    rpmTagVal evrTag;
    rpmTagVal flagTag;
    rpmTagVal ixTag;
    const char *name;
    char abrev;
};

static const struct depinfo_s depTypes[] = {
    {	RPMTAG_PROVIDENAME,		RPMTAG_PROVIDEVERSION,
	RPMTAG_PROVIDEFLAGS,		0,
	"Provides",			'P',
    },
    {	RPMTAG_REQUIRENAME,		RPMTAG_REQUIREVERSION,
	RPMTAG_REQUIREFLAGS,		0,
	"Requires",			'R',
    },
    {	RPMTAG_CONFLICTNAME,		RPMTAG_CONFLICTVERSION,
	RPMTAG_CONFLICTFLAGS,		0,
	"Conflicts",			'C',
    },
    {	RPMTAG_OBSOLETENAME,		RPMTAG_OBSOLETEVERSION,
	RPMTAG_OBSOLETEFLAGS,		0,
	"Obsoletes",			'O',
    },
    {	RPMTAG_SUPPLEMENTNAME,		RPMTAG_SUPPLEMENTVERSION,
	RPMTAG_SUPPLEMENTFLAGS,		0,
	"Supplements",			'S',
    },
    { 	RPMTAG_ENHANCENAME,		RPMTAG_ENHANCEVERSION,
	RPMTAG_ENHANCEFLAGS,		0,
	"Enhances",			'e',
    },
    {	RPMTAG_RECOMMENDNAME,		RPMTAG_RECOMMENDVERSION,
	RPMTAG_RECOMMENDFLAGS,		0,
	"Recommends",			'r',
    },
    {	RPMTAG_SUGGESTNAME,		RPMTAG_SUGGESTVERSION,
	RPMTAG_SUGGESTFLAGS,		0,
	"Suggests",			's',
    },
    {	RPMTAG_ORDERNAME,		RPMTAG_ORDERVERSION,
	RPMTAG_ORDERFLAGS,		0,
	"Order",			'o',
    },
    {	RPMTAG_TRIGGERNAME,		RPMTAG_TRIGGERVERSION,
	RPMTAG_TRIGGERFLAGS,		RPMTAG_TRIGGERINDEX,
	"Trigger",			't',
    },
    {	RPMTAG_FILETRIGGERNAME,		RPMTAG_FILETRIGGERVERSION,
	RPMTAG_FILETRIGGERFLAGS,	RPMTAG_FILETRIGGERINDEX,
	"FileTrigger",			'f',
    },
    {	RPMTAG_TRANSFILETRIGGERNAME,	RPMTAG_TRANSFILETRIGGERVERSION,
	RPMTAG_TRANSFILETRIGGERFLAGS,	RPMTAG_TRANSFILETRIGGERINDEX,
	"TransFileTrigger",		'F',
    },
    {	RPMTAG_OLDSUGGESTSNAME,		RPMTAG_OLDSUGGESTSVERSION,
	RPMTAG_OLDSUGGESTSFLAGS,	0,
	"Oldsuggests",			'?',
    },
    {	RPMTAG_OLDENHANCESNAME,		RPMTAG_OLDENHANCESVERSION,
	RPMTAG_OLDENHANCESFLAGS,	0,
	"Oldenhances",			'?',
    },
    {	0,				0,
	0,				0,
	NULL,				0,
    }
};

static const struct depinfo_s *depinfoByTag(rpmTagVal tag)
{
    for (const struct depinfo_s *dse = depTypes; dse->name; dse++) {
	if (tag == dse->typeTag)
	    return dse;
    }
    return NULL;
}

static const struct depinfo_s *depinfoByAbrev(char abrev)
{
    for (const struct depinfo_s *dse = depTypes; dse->name; dse++) {
	if (abrev == dse->abrev)
	    return dse;
    }
    return NULL;
}
static int dsType(rpmTagVal tag, 
		  const char ** Type, rpmTagVal * tagEVR, rpmTagVal * tagF,
		  rpmTagVal * tagTi)
{
    const struct depinfo_s *di = depinfoByTag(tag);
    if (di) {
	if (Type) *Type = di->name;
	if (tagEVR) *tagEVR = di->evrTag;
	if (tagF) *tagF = di->flagTag;
	if (tagTi) *tagTi = di->ixTag;
    } 
    return (di == NULL);
}    

static char tagNToChar(rpmTagVal tagN)
{
    const struct depinfo_s *di = depinfoByTag(tagN);
    return (di != NULL) ? di->abrev : '\0';
}

rpmTagVal rpmdsDToTagN(char deptype)
{
    const struct depinfo_s *di = depinfoByAbrev(deptype);
    return (di != NULL) ? di->typeTag : RPMTAG_NOT_FOUND;
}

rpmsid rpmdsNIdIndex(rpmds ds, int i)
{
    rpmsid id = 0;
    if (ds != NULL && i >= 0 && i < ds->Count && ds->N != NULL)
	id = ds->N[i];
    return id;
}

rpmsid rpmdsEVRIdIndex(rpmds ds, int i)
{
    rpmsid id = 0;
    if (ds != NULL && i >= 0 && i < ds->Count && ds->EVR != NULL)
	id = ds->EVR[i];
    return id;
}
const char * rpmdsNIndex(rpmds ds, int i)
{
    const char * N = NULL;
    if (ds != NULL && i >= 0 && i < ds->Count && ds->N != NULL)
	N = rpmstrPoolStr(ds->pool, ds->N[i]);
    return N;
}

const char * rpmdsEVRIndex(rpmds ds, int i)
{
    const char * EVR = NULL;
    if (ds != NULL && i >= 0 && i < ds->Count && ds->EVR != NULL)
	EVR = rpmstrPoolStr(ds->pool, ds->EVR[i]);
    return EVR;
}

rpmsenseFlags rpmdsFlagsIndex(rpmds ds, int i)
{
    rpmsenseFlags Flags = 0;
    if (ds != NULL && i >= 0 && i < ds->Count && ds->Flags != NULL)
	Flags = ds->Flags[i];
    return Flags;
}

int rpmdsTiIndex(rpmds ds, int i)
{
    int ti = -1;
    if (ds != NULL && i >= 0 && i < ds->Count && ds->ti != NULL)
	ti = ds->ti[i];
    return ti;
}

rpm_color_t rpmdsColorIndex(rpmds ds, int i)
{
    rpm_color_t Color = 0;
    if (ds != NULL && i >= 0 && i < ds->Count && ds->Color != NULL)
	Color = ds->Color[i];
    return Color;
}
static rpmds rpmdsUnlink(rpmds ds)
{
    if (ds)
	ds->nrefs--;
    return NULL;
}

rpmds rpmdsLink(rpmds ds)
{
    if (ds)
	ds->nrefs++;
    return ds;
}

rpmds rpmdsFree(rpmds ds)
{
    rpmTagVal tagEVR, tagF, tagTi;

    if (ds == NULL)
	return NULL;

    if (ds->nrefs > 1)
	return rpmdsUnlink(ds);

    if (dsType(ds->tagN, NULL, &tagEVR, &tagF, &tagTi))
	return NULL;

    if (ds->Count > 0) {
	ds->N = _free(ds->N);
	ds->EVR = _free(ds->EVR);
	ds->Flags = _free(ds->Flags);
	ds->ti = _free(ds->ti);
    }

    ds->pool = rpmstrPoolFree(ds->pool);
    ds->DNEVR = _free(ds->DNEVR);
    ds->Color = _free(ds->Color);

    (void) rpmdsUnlink(ds);
    memset(ds, 0, sizeof(*ds));		/* XXX trash and burn */
    ds = _free(ds);
    return NULL;
}

static rpmds rpmdsCreate(rpmstrPool pool,
		  rpmTagVal tagN, const char * Type, int Count,
		  unsigned int instance)
{
    rpmds ds = (rpmds)xcalloc(1, sizeof(*ds));

    ds->pool = (pool != NULL) ? rpmstrPoolLink(pool) : rpmstrPoolCreate();
    ds->tagN = tagN;
    ds->Type = Type;
    ds->Count = Count;
    ds->instance = instance;
    ds->i = -1;

    return rpmdsLink(ds);
}

rpmds rpmdsNewPool(rpmstrPool pool, Header h, rpmTagVal tagN, int flags)
{
    rpmTagVal tagEVR, tagF, tagTi;
    rpmds ds = NULL;
    const char * Type;
    struct rpmtd_s names;
    if (dsType(tagN, &Type, &tagEVR, &tagF, &tagTi))
	goto exit;

    if (headerGet(h, tagN, &names, HEADERGET_MINMEM)) {
	struct rpmtd_s evr, dflags, tindices;
	rpm_count_t count = rpmtdCount(&names);

	headerGet(h, tagEVR, &evr, HEADERGET_MINMEM);
	if (evr.count && evr.count != count) {
	    rpmtdFreeData(&evr);
	    return NULL;
	}

	headerGet(h, tagF, &dflags, HEADERGET_ALLOC);
	if (dflags.count && dflags.count != count) {
	    rpmtdFreeData(&dflags);
	    return NULL;
	}

	if (tagTi != RPMTAG_NOT_FOUND) {
	    headerGet(h, tagTi, &tindices, HEADERGET_ALLOC);
	    if (tindices.count && tindices.count != count) {
		rpmtdFreeData(&tindices);
		return NULL;
	    }
	}

	ds = rpmdsCreate(pool, tagN, Type, count, headerGetInstance(h));

	ds->N = names.count ? rpmtdToPool(&names, ds->pool) : NULL;
	ds->EVR = evr.count ? rpmtdToPool(&evr, ds->pool): NULL;
	ds->Flags = (uint32_t *)dflags.data;
	if (tagTi != RPMTAG_NOT_FOUND) {
	    ds->ti = (int *)tindices.data;
	}

	/* ensure rpmlib() requires always have RPMSENSE_RPMLIB flag set */
	if (tagN == RPMTAG_REQUIRENAME && ds->Flags) {
	    for (int i = 0; i < ds->Count; i++) {
		if (!(rpmdsFlagsIndex(ds, i) & RPMSENSE_RPMLIB)) {
		    const char *N = rpmdsNIndex(ds, i);
		    if (rstreqn(N, "rpmlib(", sizeof("rpmlib(")-1))
			ds->Flags[i] |= RPMSENSE_RPMLIB;
		}
	    }
	}
	rpmtdFreeData(&names);
	rpmtdFreeData(&evr);

	/* freeze the pool to save memory, but only if private pool */
	if (ds->pool != pool)
	    rpmstrPoolFreeze(ds->pool, 0);
    }

exit:
    return ds;
}

rpmds rpmdsNew(Header h, rpmTagVal tagN, int flags)
{
    return rpmdsNewPool(NULL, h, tagN, flags);
}

char * rpmdsNewDNEVR(const char * dspfx, const rpmds ds)
{
    const char * N = rpmdsN(ds);
    const char * EVR = rpmdsEVR(ds);
    rpmsenseFlags Flags = rpmdsFlags(ds);
    char * tbuf, * t;
    size_t nb;

    nb = 0;
    if (dspfx)	nb += strlen(dspfx) + 1;
    if (N)	nb += strlen(N);
    /* XXX rpm prior to 3.0.2 did not always supply EVR and Flags. */
    if (Flags & RPMSENSE_SENSEMASK) {
	if (nb)	nb++;
	if (Flags & RPMSENSE_LESS)	nb++;
	if (Flags & RPMSENSE_GREATER) nb++;
	if (Flags & RPMSENSE_EQUAL)	nb++;
    }
    /* XXX rpm prior to 3.0.2 did not always supply EVR and Flags. */
    if (EVR && *EVR) {
	if (nb)	nb++;
	nb += strlen(EVR);
    }

    t = tbuf = (char *)xmalloc(nb + 1);
    if (dspfx) {
	t = stpcpy(t, dspfx);
	*t++ = ' ';
    }
    if (N)
	t = stpcpy(t, N);
    /* XXX rpm prior to 3.0.2 did not always supply EVR and Flags. */
    if (Flags & RPMSENSE_SENSEMASK) {
	if (t != tbuf)	*t++ = ' ';
	if (Flags & RPMSENSE_LESS)	*t++ = '<';
	if (Flags & RPMSENSE_GREATER) *t++ = '>';
	if (Flags & RPMSENSE_EQUAL)	*t++ = '=';
    }
    /* XXX rpm prior to 3.0.2 did not always supply EVR and Flags. */
    if (EVR && *EVR) {
	if (t != tbuf)	*t++ = ' ';
	t = stpcpy(t, EVR);
    }
    *t = '\0';
    return tbuf;
}

static rpmds singleDSPool(rpmstrPool pool, rpmTagVal tagN,
			  rpmsid N, rpmsid EVR, rpmsenseFlags Flags,
			  unsigned int instance, rpm_color_t Color,
			  int triggerIndex)
{
    rpmds ds = NULL;
    const char * Type;
    rpmTagVal tagTi;

    if (dsType(tagN, &Type, NULL, NULL, &tagTi))
	goto exit;

    ds = rpmdsCreate(pool, tagN, Type, 1, instance);

    ds->N = (rpmsid *)xmalloc(1 * sizeof(*ds->N));
    ds->N[0] = N;
    ds->EVR = (rpmsid *)xmalloc(1 * sizeof(*ds->EVR));
    ds->EVR[0] = EVR;
    ds->Flags = (uint32_t *)xmalloc(sizeof(*ds->Flags));
    ds->Flags[0] = Flags;
    if (tagTi != RPMTAG_NOT_FOUND) {
	ds->ti = (int *)xmalloc(sizeof(*ds->ti));
	ds->ti[0] = triggerIndex;
    }
    ds->i = 0;
    if (Color)
	rpmdsSetColor(ds, Color);

exit:
    return ds;
}

static rpmds singleDS(rpmstrPool pool, rpmTagVal tagN,
		      const char * N, const char * EVR,
		      rpmsenseFlags Flags, unsigned int instance,
		      rpm_color_t Color, int triggerIndex)
{
    rpmds ds = singleDSPool(pool, tagN, 0, 0, Flags, instance, Color,
			    triggerIndex);
    if (ds) {
	/* now that we have a pool, we can insert our N & EVR strings */
	ds->N[0] = rpmstrPoolId(ds->pool, N ? N : "", 1);
	ds->EVR[0] = rpmstrPoolId(ds->pool, EVR ? EVR : "", 1);
	/* freeze the pool to save memory, but only if private pool */
	if (ds->pool != pool)
	    rpmstrPoolFreeze(ds->pool, 0);
    }
    return ds;
}

rpmds rpmdsThisPool(rpmstrPool pool,
		    Header h, rpmTagVal tagN, rpmsenseFlags Flags)
{
    char *evr = headerGetAsString(h, RPMTAG_EVR);
    rpmds ds = singleDS(pool, tagN, headerGetString(h, RPMTAG_NAME),
			evr, Flags, headerGetInstance(h), 0, 0);
    free(evr);
    return ds;
}

rpmds rpmdsThis(Header h, rpmTagVal tagN, rpmsenseFlags Flags)
{
    return rpmdsThisPool(NULL, h, tagN, Flags);
}

rpmds rpmdsSinglePool(rpmstrPool pool,rpmTagVal tagN,
		      const char * N, const char * EVR, rpmsenseFlags Flags)
{
    return singleDS(pool, tagN, N, EVR, Flags, 0, 0, 0);
}

rpmds rpmdsSinglePoolTix(rpmstrPool pool,rpmTagVal tagN,
			    const char * N, const char * EVR,
			    rpmsenseFlags Flags, int triggerIndex)
{
    return singleDS(pool, tagN, N, EVR, Flags, 0, 0, triggerIndex);
}

rpmds rpmdsSingle(rpmTagVal tagN, const char * N, const char * EVR, rpmsenseFlags Flags)
{
    return rpmdsSinglePool(NULL, tagN, N, EVR, Flags);
}

rpmds rpmdsCurrent(rpmds ds)
{
    rpmds cds = NULL;
    int ti = -1;
    if (ds != NULL && ds->i >= 0 && ds->i < ds->Count) {
	if (ds->ti)
	    ti = ds->ti[ds->i];
	/* Using parent's pool so we can just use the same id's */
	cds = singleDSPool(ds->pool, ds->tagN, ds->N[ds->i], ds->EVR[ds->i],
			   rpmdsFlags(ds), ds->instance, rpmdsColor(ds), ti);
    }
    return cds;
}

rpmds rpmdsFilterTi(rpmds ds, int ti)
{
    int i, i2, tiCount = 0;
    rpmds fds;

    if (ds == NULL || !ds->ti || !ds->Count)
	return NULL;

    for (i = 0; i < ds->Count; i++) {
	if (ds->ti[i] == ti)
	    tiCount++;
    }

    if (!tiCount)
	return NULL;

    fds = rpmdsCreate(ds->pool, ds->tagN, ds->Type, tiCount, ds->instance);

    fds->N = (rpmsid *)xmalloc(tiCount * sizeof(*fds->N));
    fds->EVR = (rpmsid *)xmalloc(tiCount * sizeof(*fds->EVR));
    fds->Flags = (uint32_t *)xmalloc(tiCount * sizeof(*fds->Flags));
    fds->ti = (int *)xmalloc(tiCount * sizeof(*fds->ti));
    fds->i = -1;

    i2 = 0;
    for (i = 0; i < ds->Count; i++) {
	if (ds->ti[i] == ti) {
	    fds->N[i2] = ds->N[i];
	    fds->EVR[i2] = ds->EVR[i];
	    fds->Flags[i2] = ds->Flags[i];
	    fds->ti[i2] = ds->ti[i];
	    i2++;
	}
    }

    return fds;
}

int rpmdsPutToHeader(rpmds ds, Header h)
{
    rpmTagVal tagN = rpmdsTagN(ds);
    rpmTagVal tagEVR = rpmdsTagEVR(ds);
    rpmTagVal tagF = rpmdsTagF(ds);
    rpmTagVal tagTi = rpmdsTagTi(ds);
    if (!tagN)
	return -1;

    rpmds pi = rpmdsInit(ds);
    while (rpmdsNext(pi) >= 0) {
	rpmsenseFlags flags = rpmdsFlags(pi);
	uint32_t index = rpmdsTi(pi);
	headerPutString(h, tagN, rpmdsN(pi));
	headerPutString(h, tagEVR, rpmdsEVR(pi));
	headerPutUint32(h, tagF, &flags, 1);
	if (tagTi != RPMTAG_NOT_FOUND) {
	    headerPutUint32(h, tagTi, &index, 1);
	}
    }
    return 0;
}

int rpmdsCount(const rpmds ds)
{
    return (ds != NULL ? ds->Count : 0);
}

int rpmdsIx(const rpmds ds)
{
    return (ds != NULL ? ds->i : -1);
}

int rpmdsSetIx(rpmds ds, int ix)
{
    int i = -1;

    if (ds != NULL && ix >= 0 && ix < ds->Count) {
	ds->i = ix;
	ds->DNEVR = _free(ds->DNEVR);
	i = ds->i;
    }
    return i;
}

char rpmdsD(const rpmds ds)
{
    if (ds != NULL) {
	return tagNToChar(ds->tagN);
    } else {
	return '\0';
    }
}

const char * rpmdsDNEVR(const rpmds ds)
{
    const char * DNEVR = NULL;

    if (ds != NULL && ds->i >= 0 && ds->i < ds->Count) {
	if (ds->DNEVR == NULL) {
	    char t[2] = { tagNToChar(ds->tagN), '\0' };
	    ds->DNEVR = rpmdsNewDNEVR(t, ds);
	}
	DNEVR = ds->DNEVR;
    }
    return DNEVR;
}

rpmsid rpmdsNId(rpmds ds)
{
    return (ds != NULL) ? rpmdsNIdIndex(ds, ds->i) : 0;
}

rpmsid rpmdsEVRId(rpmds ds)
{
    return (ds != NULL) ? rpmdsEVRIdIndex(ds, ds->i) : 0;
}

const char * rpmdsN(const rpmds ds)
{
    return (ds != NULL) ? rpmdsNIndex(ds, ds->i) : NULL;
}

const char * rpmdsEVR(const rpmds ds)
{
    return (ds != NULL) ? rpmdsEVRIndex(ds, ds->i) : NULL;
}

rpmsenseFlags rpmdsFlags(const rpmds ds)
{
    return (ds != NULL) ? rpmdsFlagsIndex(ds, ds->i) : 0;
}

int rpmdsTi(const rpmds ds)
{
    return (ds != NULL) ? rpmdsTiIndex(ds, ds->i) : 0;
}

rpmTagVal rpmdsTagN(const rpmds ds)
{
    rpmTagVal tagN = RPMTAG_NOT_FOUND;

    if (ds != NULL)
	tagN = ds->tagN;
    return tagN;
}

rpmTagVal rpmdsTagEVR(const rpmds ds)
{
    rpmTagVal tagEVR = RPMTAG_NOT_FOUND;

    if (ds != NULL)
	dsType(ds->tagN, NULL, &tagEVR, NULL, NULL);
    return tagEVR;
}

rpmTagVal rpmdsTagF(const rpmds ds)
{
    rpmTagVal tagF = RPMTAG_NOT_FOUND;

    if (ds != NULL)
	dsType(ds->tagN, NULL, NULL, &tagF, NULL);
    return tagF;
}

rpmTagVal rpmdsTagTi(const rpmds ds)
{
    rpmTagVal tagTi = RPMTAG_NOT_FOUND;

    if (ds != NULL)
	dsType(ds->tagN, NULL, NULL, NULL, &tagTi);
    return tagTi;
}

unsigned int rpmdsInstance(rpmds ds)
{
    return (ds != NULL) ? ds->instance : 0;
}

rpm_color_t rpmdsColor(const rpmds ds)
{
    return (ds != NULL) ? rpmdsColorIndex(ds, ds->i) : 0;
}

rpm_color_t rpmdsSetColor(const rpmds ds, rpm_color_t color)
{
    rpm_color_t ocolor = 0;

    if (ds != NULL && ds->i >= 0 && ds->i < ds->Count) {
	if (ds->Color == NULL) {
	    ds->Color = (uint32_t *)xcalloc(ds->Count, sizeof(*ds->Color));
	}
	ocolor = ds->Color[ds->i];
	ds->Color[ds->i] = color;
    }
    return ocolor;
}

void rpmdsNotify(rpmds ds, const char * where, int rc)
{
    const char *DNEVR;

    if (!rpmIsDebug())
	return;
    if (!(ds != NULL && ds->i >= 0 && ds->i < ds->Count))
	return;
    if (!(ds->Type != NULL && (DNEVR = rpmdsDNEVR(ds)) != NULL))
	return;

    rpmlog(RPMLOG_DEBUG, "%9s: %-45s %-s %s\n", ds->Type,
		(rstreq(DNEVR, "cached") ? DNEVR : DNEVR+2),
		(rc ? _("NO ") : _("YES")),
		(where != NULL ? where : ""));
}

int rpmdsNext(rpmds ds)
{
    int i = -1;

    if (ds != NULL)
	i = rpmdsSetIx(ds, ds->i + 1);

    return i;
}

rpmds rpmdsInit(rpmds ds)
{
    if (ds != NULL) {
	ds->i = -1;
	ds->DNEVR = _free(ds->DNEVR);
    }
    return ds;
}

static rpmds rpmdsDup(const rpmds ods)
{
    rpmds ds = rpmdsCreate(ods->pool, ods->tagN, ods->Type,
			   ods->Count, ods->instance);
    size_t nb;
    
    ds->i = ods->i;

    nb = ds->Count * sizeof(*ds->N);
    ds->N = (rpmsid *)memcpy(xmalloc(nb), ods->N, nb);
    
    /* XXX rpm prior to 3.0.2 did not always supply EVR and Flags. */
    if (ods->EVR) {
	nb = ds->Count * sizeof(*ds->EVR);
	ds->EVR = (rpmsid *)memcpy(xmalloc(nb), ods->EVR, nb);
    }

    if (ods->Flags) {
	nb = ds->Count * sizeof(*ds->Flags);
	ds->Flags = (uint32_t *)memcpy(xmalloc(nb), ods->Flags, nb);
    }

    if (ods->ti) {
	nb = ds->Count * sizeof(*ds->ti);
	ds->ti = (int *)memcpy(xmalloc(nb), ods->ti, nb);
    }

    return ds;

}

static int doFind(rpmds ds, const rpmds ods, unsigned int *he)
{
    int comparison;
    const char *N, *ON = rpmdsN(ods);
    const char *EVR, *OEVR = rpmdsEVR(ods);
    rpmsenseFlags Flags, OFlags = rpmdsFlags(ods);
    int index, Oindex = rpmdsTi(ods);
    int rc = -1; /* assume not found */

    if (ds == NULL || ods == NULL)
	return -1;

    unsigned int l = 0;
    unsigned int u = ds->Count;
    while (l < u) {
	ds->i = (l + u) / 2;

	N = rpmdsN(ds);
	EVR = rpmdsEVR(ds);
	Flags = rpmdsFlags(ds);
	index = rpmdsTi(ds);

	comparison = strcmp(ON, N);

	/* XXX rpm prior to 3.0.2 did not always supply EVR and Flags. */
	if (comparison == 0 && OEVR && EVR)
	    comparison = strcmp(OEVR, EVR);
	if (comparison == 0)
	    comparison = OFlags - Flags;
	if (comparison == 0)
	    comparison = Oindex - index;

	if (comparison < 0)
	    u = ds->i;
	else if (comparison > 0)
	    l = ds->i + 1;
	else {
	    rc = ds->i;
	    break;
	}
    }
    if (he)
	*he = u;
    return rc;
}

int rpmdsFind(rpmds ds, const rpmds ods)
{
    return doFind(ds, ods, NULL);
}

int rpmdsMerge(rpmds * dsp, rpmds ods)
{
    rpmds ds;
    int save;
    int ocount;

    if (dsp == NULL || ods == NULL)
	return -1;

    ocount = rpmdsCount(*dsp);

    /* If not initialized yet, dup the 1st entry. */
    if (*dsp == NULL) {
	save = ods->Count;
	ods->Count = 1;
	*dsp = rpmdsDup(ods);
	ods->Count = save;
    }
    ds = *dsp;
    if (ds == NULL)
	return -1;

    /* Ensure EVR and Flags exist */
    if (ds->EVR == NULL)
	ds->EVR = (rpmsid *)xcalloc(ds->Count, sizeof(*ds->EVR));
    if (ds->Flags == NULL)
	ds->Flags = (uint32_t *)xcalloc(ds->Count, sizeof(*ds->Flags));
    if (ds->ti == NULL && ods->ti) {
	int i;
	ds->ti = (int *)xcalloc(ds->Count, sizeof(*ds->ti));
	for (i = 0; i < ds->Count; i++)
	    ds->ti[i] = -1;
    }

    /*
     * Add new entries.
     */
    save = ods->i;
    ods = rpmdsInit(ods);
    while (rpmdsNext(ods) >= 0) {
	const char *OEVR;
	unsigned int u;
	/*
	 * If this entry is already present, don't bother.
	 */
	if (doFind(ds, ods, &u) >= 0)
	    continue;

	/*
	 * Insert new entry. Ensure pool is unfrozen to allow additions.
	 */
	rpmstrPoolUnfreeze(ds->pool);
	ds->N = xrealloc(ds->N, (ds->Count+1) * sizeof(*ds->N));
	if (u < ds->Count) {
	    memmove(ds->N + u + 1, ds->N + u,
		    (ds->Count - u) * sizeof(*ds->N));
	}
	ds->N[u] = rpmstrPoolId(ds->pool, rpmdsN(ods), 1);

	ds->EVR = xrealloc(ds->EVR, (ds->Count+1) * sizeof(*ds->EVR));
	if (u < ds->Count) {
	    memmove(ds->EVR + u + 1, ds->EVR + u,
		    (ds->Count - u) * sizeof(*ds->EVR));
	}
	OEVR = rpmdsEVR(ods);
	ds->EVR[u] = rpmstrPoolId(ds->pool, OEVR ? OEVR : "", 1);

	ds->Flags = xrealloc(ds->Flags, (ds->Count+1) * sizeof(*ds->Flags));
	if (u < ds->Count) {
	    memmove(ds->Flags + u + 1, ds->Flags + u,
		    (ds->Count - u) * sizeof(*ds->Flags));
	}
	ds->Flags[u] = rpmdsFlags(ods);

	if (ds->ti || ods->ti) {
	    ds->ti = xrealloc(ds->ti, (ds->Count+1) * sizeof(*ds->ti));
	    if (u < ds->Count) {
		memmove(ds->ti + u + 1, ds->ti + u,
			(ds->Count - u) * sizeof(*ds->ti));
	    }
	    ds->ti[u] = rpmdsTi(ods);
	}

	ds->i = ds->Count;
	ds->Count++;

    }
    ods->i = save;
    return (ds->Count - ocount);
}


int rpmdsSearch(rpmds ds, rpmds ods)
{
    int comparison;
    int i, l, u;
    const char *ON = rpmdsN(ods);

    if (ds == NULL || ods == NULL)
	return -1;

    /* Binary search to find the [l,u) subset that contains N */
    i = -1;
    l = 0;
    u = ds->Count;
    while (l < u) {
	i = (l + u) / 2;

	comparison = strcmp(ON, rpmdsNIndex(ds, i));

	if (comparison < 0)
	    u = i;
	else if (comparison > 0)
	    l = i + 1;
	else {
	    /* Set l to 1st member of set that contains N. */
	    if (!rstreq(ON, rpmdsNIndex(ds, l)))
		l = i;
	    while (l > 0 && rstreq(ON, rpmdsNIndex(ds, l-1)))
		l--;
	    /* Set u to 1st member of set that does not contain N. */
	    if (u >= ds->Count || !rstreq(ON, rpmdsNIndex(ds, u)))
		u = i;
	    while (++u < ds->Count) {
		if (!rstreq(ON, rpmdsNIndex(ds, u)))
		    break;
	    }
	    break;
	}
    }

    /* Check each member of [l,u) subset for ranges overlap. */
    i = -1;
    if (l < u) {
	int oix = rpmdsIx(ods);
	while (l < u) {
	    if (rpmdsCompareIndex(ods, oix, ds, l) != 0) {
		i = l;
		break;
	    }
	    l++;
	}
    }
    return i;
}

int rpmdsCompareIndex(rpmds A, int aix, rpmds B, int bix)
{
    const char *AEVR, *BEVR;
    rpmsenseFlags AFlags, BFlags;
    int result;

    /* Different names don't overlap. */
    if (!rpmstrPoolStreq(A->pool, rpmdsNIdIndex(A, aix),
			 B->pool, rpmdsNIdIndex(B, bix))) {
	result = 0;
	goto exit;
    }

    /* XXX rpm prior to 3.0.2 did not always supply EVR and Flags. */
    if (!(A->EVR && A->Flags && B->EVR && B->Flags)) {
	result = 1;
	goto exit;
    }

    /* Same name. If either A or B is an existence test, always overlap. */
    AFlags = rpmdsFlagsIndex(A, aix);
    BFlags = rpmdsFlagsIndex(B, bix);
    if (!((AFlags & RPMSENSE_SENSEMASK) && (BFlags & RPMSENSE_SENSEMASK))) {
	result = 1;
	goto exit;
    }

    AEVR = rpmdsEVRIndex(A, aix);
    BEVR = rpmdsEVRIndex(B, bix);
    if (!(AEVR && *AEVR && BEVR && *BEVR)) {
	/* If either EVR is non-existent or empty, always overlap. */
	result = 1;
    } else {
	/* Both AEVR and BEVR exist, compare [epoch:]version[-release]. */
	rpmver av = rpmverParse(AEVR);
	rpmver bv = rpmverParse(BEVR);

	result = rpmverOverlap(av, AFlags, bv, BFlags);

	rpmverFree(av);
	rpmverFree(bv);
    }

exit:
    return result;
}

int rpmdsCompare(const rpmds A, const rpmds B)
{
    return rpmdsCompareIndex(A, A->i, B, B->i);
}

int rpmdsMatches(rpmstrPool pool, Header h, int prix,
		 rpmds req, int selfevr)
{
    rpmds provides;
    rpmTagVal tag = RPMTAG_PROVIDENAME;
    int result = 0;

    /* Get provides information from header */
    if (selfevr)
	provides = rpmdsThisPool(pool, h, tag, RPMSENSE_EQUAL);
    else
	provides = rpmdsNewPool(pool, h, tag, 0);

    /*
     * For a self-provide and indexed provide, we only need one comparison.
     * Otherwise loop through the provides until match or end.
     */
    if (prix >= 0 || selfevr) {
	if (prix >= 0)
	    rpmdsSetIx(provides, prix);
	result = rpmdsCompare(provides, req);
    } else {
	provides = rpmdsInit(provides);
	while (rpmdsNext(provides) >= 0) {
	    result = rpmdsCompare(provides, req);
	    /* If this provide matches the require, we're done. */
	    if (result)
		break;
	}
    }

    rpmdsFree(provides);
    return result;
}

int rpmdsMatchesDep (const Header h, int ix, const rpmds req, int nopromote)
{
    return rpmdsMatches(NULL, h, ix, req, 0);
}

int rpmdsAnyMatchesDep (const Header h, const rpmds req, int nopromote)
{
    return rpmdsMatches(NULL, h, -1, req, 0);
}

int rpmdsNVRMatchesDep(const Header h, const rpmds req, int nopromote)
{
    return rpmdsMatches(NULL, h, -1, req, 1);
}

/**
 */
struct rpmlibProvides_s {
    const char * featureName;
    const char * featureEVR;
    rpmsenseFlags featureFlags;
    const char * featureDescription;
};

static const struct rpmlibProvides_s rpmlibProvides[] = {
    { "rpmlib(VersionedDependencies)",	"3.0.3-1",
	(RPMSENSE_RPMLIB|RPMSENSE_EQUAL),
    N_("PreReq:, Provides:, and Obsoletes: dependencies support versions.") },
    { "rpmlib(CompressedFileNames)",	"3.0.4-1",
	(RPMSENSE_RPMLIB|RPMSENSE_EQUAL),
    N_("file name(s) stored as (dirName,baseName,dirIndex) tuple, not as path.")},
#ifdef HAVE_BZLIB_H
    { "rpmlib(PayloadIsBzip2)",		"3.0.5-1",
	(RPMSENSE_RPMLIB|RPMSENSE_EQUAL),
    N_("package payload can be compressed using bzip2.") },
#endif
#ifdef HAVE_LZMA_H
    { "rpmlib(PayloadIsXz)",		"5.2-1",
	(RPMSENSE_RPMLIB|RPMSENSE_EQUAL),
    N_("package payload can be compressed using xz.") },
    { "rpmlib(PayloadIsLzma)",		"4.4.2-1",
	(RPMSENSE_RPMLIB|RPMSENSE_EQUAL),
    N_("package payload can be compressed using lzma.") },
#endif
    { "rpmlib(PayloadFilesHavePrefix)",	"4.0-1",
	(RPMSENSE_RPMLIB|RPMSENSE_EQUAL),
    N_("package payload file(s) have \"./\" prefix.") },
    { "rpmlib(ExplicitPackageProvide)",	"4.0-1",
	(RPMSENSE_RPMLIB|RPMSENSE_EQUAL),
    N_("package name-version-release is not implicitly provided.") },
    { "rpmlib(HeaderLoadSortsTags)",    "4.0.1-1",
	(                RPMSENSE_EQUAL),
    N_("header tags are always sorted after being loaded.") },
    { "rpmlib(ScriptletInterpreterArgs)",    "4.0.3-1",
	(                RPMSENSE_EQUAL),
    N_("the scriptlet interpreter can use arguments from header.") },
    { "rpmlib(PartialHardlinkSets)",    "4.0.4-1",
	(                RPMSENSE_EQUAL),
    N_("a hardlink file set may be installed without being complete.") },
    { "rpmlib(ConcurrentAccess)",    "4.1-1",
	(                RPMSENSE_EQUAL),
    N_("package scriptlets may access the rpm database while installing.") },
    { "rpmlib(BuiltinLuaScripts)",    "4.2.2-1",
	(                RPMSENSE_EQUAL),
    N_("internal support for lua scripts.") },
    { "rpmlib(FileDigests)", 		"4.6.0-1",
	(		 RPMSENSE_EQUAL),
    N_("file digest algorithm is per package configurable") },
#ifdef WITH_CAP
    { "rpmlib(FileCaps)", 		"4.6.1-1",
	(		 RPMSENSE_EQUAL),
    N_("support for POSIX.1e file capabilities") },
#endif
    { "rpmlib(ScriptletExpansion)",    "4.9.0-1",
	(		RPMSENSE_EQUAL),
    N_("package scriptlets can be expanded at install time.") },
    { "rpmlib(TildeInVersions)",    "4.10.0-1",
	(		RPMSENSE_EQUAL),
    N_("dependency comparison supports versions with tilde.") },
    { "rpmlib(CaretInVersions)",    "4.15.0-1",
	(		RPMSENSE_EQUAL),
    N_("dependency comparison supports versions with caret.") },
    { "rpmlib(LargeFiles)", 	"4.12.0-1",
	(		RPMSENSE_EQUAL),
    N_("support files larger than 4GB") },
    { "rpmlib(RichDependencies)",    "4.12.0-1",
	(		RPMSENSE_EQUAL),
    N_("support for rich dependencies.") },
    { "rpmlib(DynamicBuildRequires)", "4.15.0-1",
	(RPMSENSE_RPMLIB|RPMSENSE_EQUAL),
    N_("support for dynamic buildrequires.") },
#ifdef HAVE_ZSTD
    { "rpmlib(PayloadIsZstd)",		"5.4.18-1",
	(RPMSENSE_RPMLIB|RPMSENSE_EQUAL),
    N_("package payload can be compressed using zstd.") },
#endif
    { NULL,				NULL, 0,	NULL }
};


int rpmdsRpmlibPool(rpmstrPool pool, rpmds * dsp, const void * tblp)
{
    const struct rpmlibProvides_s * rltblp = (const struct rpmlibProvides_s *)tblp;
    const struct rpmlibProvides_s * rlp;
    int rc = 0;

    if (rltblp == NULL)
	rltblp = rpmlibProvides;

    for (rlp = rltblp; rlp->featureName != NULL && rc >= 0; rlp++) {
	rpmds ds = rpmdsSinglePool(pool, RPMTAG_PROVIDENAME, rlp->featureName,
			rlp->featureEVR, rlp->featureFlags);
	rc = rpmdsMerge(dsp, ds);
	rpmdsFree(ds);
    }
    /* freeze the pool to save memory, but only if private pool */
    if (*dsp && (*dsp)->pool != pool)
	rpmstrPoolFreeze((*dsp)->pool, 0);
    return (rc < 0) ? -1 : 0;
}

int rpmdsRpmlib(rpmds * dsp, const void * tblp)
{
    return rpmdsRpmlibPool(NULL, dsp, tblp);
}

rpmstrPool rpmdsPool(rpmds ds)
{
    return (ds != NULL) ? ds->pool : NULL;
}

int rpmdsIsWeak(rpmds ds)
{
    int weak = 1;
    switch (rpmdsTagN(ds)) {
    case RPMTAG_REQUIRENAME:
    case RPMTAG_PROVIDENAME:
    case RPMTAG_OBSOLETENAME:
    case RPMTAG_CONFLICTNAME:
	if (!(rpmdsFlags(ds) & RPMSENSE_MISSINGOK))
	    weak = 0;
	break;
    }
    return weak;
}

int rpmdsIsReverse(rpmds ds)
{
    int reverse = 0;
    switch (rpmdsTagN(ds)) {
    case RPMTAG_SUPPLEMENTNAME:
    case RPMTAG_ENHANCENAME:
	reverse = 1;
	break;
    }
    return reverse;
}

int rpmdsIsSysuser(rpmds ds, char **sysuser)
{
    if (rpmdsTagN(ds) != RPMTAG_PROVIDENAME)
	return 0;
    if (!(rpmdsFlags(ds) & RPMSENSE_EQUAL))
	return 0;

    const char *name = rpmdsN(ds);
    if (!(rstreqn(name, "user(", 5) || rstreqn(name, "group(", 6) ||
	    rstreqn(name, "groupmember(", 12))) {
	return 0;
    }

    char *line = NULL;
    size_t llen = 0;

    if (rpmBase64Decode(rpmdsEVR(ds), (void **)&line, &llen))
	return 0;

    if (sysuser)
	*sysuser = rstrndup(line, llen);
    free(line);

    return 1;
}

rpmsenseFlags rpmSanitizeDSFlags(rpmTagVal tagN, rpmsenseFlags Flags)
{
    rpmsenseFlags extra = RPMSENSE_ANY;
    switch (tagN) {
    case RPMTAG_PROVIDENAME:
	extra = Flags & RPMSENSE_FIND_PROVIDES;
	break;
    case RPMTAG_TRIGGERNAME:
    case RPMTAG_FILETRIGGERNAME:
    case RPMTAG_TRANSFILETRIGGERNAME:
	extra = Flags & RPMSENSE_TRIGGER;
	break;
    case RPMTAG_RECOMMENDNAME:
    case RPMTAG_SUGGESTNAME:
    case RPMTAG_SUPPLEMENTNAME:
    case RPMTAG_ENHANCENAME:
    case RPMTAG_REQUIRENAME:
    case RPMTAG_ORDERNAME:
	extra = Flags & (_ALL_REQUIRES_MASK);
	break;
    case RPMTAG_CONFLICTNAME:
	extra = Flags;
	break;
    default:
	break;
    }
    return (Flags & RPMSENSE_SENSEMASK) | extra;
}

static struct ReqComp {
const char * token;
    rpmsenseFlags sense;
} const ReqComparisons[] = { 
    { "<=", RPMSENSE_LESS | RPMSENSE_EQUAL},
    { "=<", RPMSENSE_LESS | RPMSENSE_EQUAL},
    { "<",  RPMSENSE_LESS},

    { "==", RPMSENSE_EQUAL},
    { "=",  RPMSENSE_EQUAL},
    
    { ">=", RPMSENSE_GREATER | RPMSENSE_EQUAL},
    { "=>", RPMSENSE_GREATER | RPMSENSE_EQUAL},
    { ">",  RPMSENSE_GREATER},

    { NULL, 0 },
};

rpmsenseFlags rpmParseDSFlags(const char *str, size_t len)
{
    const struct ReqComp *rc;
    for (rc = ReqComparisons; rc->token != NULL; rc++)
	if (len == strlen(rc->token) && rstreqn(str, rc->token, len))
	    return rc->sense;
    return 0;
}

static struct RichOpComp {
    const char * token;
    rpmrichOp op;
} const RichOps[] = { 
    { "and",	 RPMRICHOP_AND},
    { "or",	 RPMRICHOP_OR},
    { "if",	 RPMRICHOP_IF},
    { "unless",	 RPMRICHOP_UNLESS},
    { "else",	 RPMRICHOP_ELSE},
    { "with",	 RPMRICHOP_WITH},
    { "without", RPMRICHOP_WITHOUT},
    { NULL, RPMRICHOP_NONE },
};

int rpmdsIsRich(rpmds dep)
{
    const char * n = rpmdsN(dep);
    return (n && n[0] == '(');
}

static rpmRC parseRichDepOp(const char **dstrp, rpmrichOp *opp, char **emsg)
{
    const char *p = *dstrp, *pe = p;
    const struct RichOpComp *ro;

    while (*pe && !risspace(*pe) && *pe != ')')
	pe++;
    for (ro = RichOps; ro->token != NULL; ro++)
	if (pe - p == strlen(ro->token) && rstreqn(p, ro->token, pe - p)) {
	    *opp = ro->op;
	    *dstrp = pe; 
	    return RPMRC_OK;
	}
    if (emsg)
	rasprintf(emsg, _("Unknown rich dependency op '%.*s'"), (int)(pe - p), p); 
    return RPMRC_FAIL;
}

const char *rpmrichOpStr(rpmrichOp op)
{
    if (op == RPMRICHOP_SINGLE)
	return "SINGLE";
    if (op == RPMRICHOP_AND)
	return "and";
    if (op == RPMRICHOP_OR)
	return "or";
    if (op == RPMRICHOP_IF)
	return "if";
    if (op == RPMRICHOP_UNLESS)
	return "unless";
    if (op == RPMRICHOP_ELSE)
	return "else";
    if (op == RPMRICHOP_WITH)
	return "with";
    if (op == RPMRICHOP_WITHOUT)
	return "without";
    return NULL;
}


#define SKIPWHITE(_x)   {while (*(_x) && (risspace(*_x) || *(_x) == ',')) (_x)++;}
#define SKIPNONWHITEX(_x){int bl = 0; while (*(_x) &&!(risspace(*_x) || *(_x) == ',' || (*(_x) == ')' && bl-- <= 0))) if (*(_x)++ == '(') bl++;}

static rpmRC parseSimpleDep(const char **dstrp, char **emsg, rpmrichParseFunction cb, void *cbdata)
{
    const char *p = *dstrp;
    const char *n, *e = 0;
    int nl, el = 0;
    rpmsenseFlags sense = 0;

    n = p;
    SKIPNONWHITEX(p);
    nl = p - n;
    if (nl == 0) {
        if (emsg)
          rasprintf(emsg, _("Name required"));
        return RPMRC_FAIL;
    }   
    SKIPWHITE(p);
    if (*p) {
        const char *pe = p;

        SKIPNONWHITEX(pe);
	sense = rpmParseDSFlags(p, pe - p);
        if (sense) {
            p = pe; 
            SKIPWHITE(p);
            e = p;
            SKIPNONWHITEX(p);
            el = p - e;
        }
    }   
    if (e && el == 0) {
        if (emsg)
          rasprintf(emsg, _("Version required"));
        return RPMRC_FAIL;
    }
    if (cb && cb(cbdata, RPMRICH_PARSE_SIMPLE, n, nl, e, el, sense, RPMRICHOP_SINGLE, emsg) != RPMRC_OK)
	return RPMRC_FAIL;
    *dstrp = p;
    return RPMRC_OK;
}

#define RICHPARSE_CHECK		(1 << 0)
#define RICHPARSE_NO_WITH	(1 << 1)
#define RICHPARSE_NO_AND	(1 << 2)
#define RICHPARSE_NO_OR		(1 << 3)

static rpmRC rpmrichParseCheck(rpmrichOp op, int check, char **emsg)
{
    if ((op == RPMRICHOP_WITH || op == RPMRICHOP_WITHOUT) && (check & RICHPARSE_NO_WITH) != 0) {
	if (emsg)
	    rasprintf(emsg, _("Illegal ops in with/without"));
	return RPMRC_FAIL;
    }
    if ((check & RICHPARSE_CHECK) == 0)
	return RPMRC_OK;
    if ((op == RPMRICHOP_AND || op == RPMRICHOP_IF) && (check & RICHPARSE_NO_AND) != 0) {
	if (emsg)
	    rasprintf(emsg, _("Illegal context for 'unless', please use 'or' instead"));
	return RPMRC_FAIL;
    }
    if ((op == RPMRICHOP_OR || op == RPMRICHOP_UNLESS) && (check & RICHPARSE_NO_OR) != 0) {
	if (emsg)
	    rasprintf(emsg, _("Illegal context for 'if', please use 'and' instead"));
	return RPMRC_FAIL;
    }
    return RPMRC_OK;
}

static rpmRC rpmrichParseInternal(const char **dstrp, char **emsg, rpmrichParseFunction cb, void *cbdata, int *checkp)
{
    const char *p = *dstrp, *pe;
    rpmrichOp op = RPMRICHOP_SINGLE, firstop = RPMRICHOP_SINGLE, chainop = RPMRICHOP_NONE;
    int check = checkp ? *checkp : 0;

    if (cb && cb(cbdata, RPMRICH_PARSE_ENTER, p, 0, 0, 0, 0, op, emsg) != RPMRC_OK)
        return RPMRC_FAIL;
    if (*p++ != '(') {
        if (emsg)
          rasprintf(emsg, _("Rich dependency does not start with '('"));
        return RPMRC_FAIL;
    }
    for (;;) {
        SKIPWHITE(p);
        if (*p == ')') {
            if (emsg) {
                if (chainop)
                    rasprintf(emsg, _("Missing argument to rich dependency op"));
                else
                    rasprintf(emsg, _("Empty rich dependency"));
            }
            return RPMRC_FAIL;
        }
	if (*p == '(') {
	    int subcheck = check & RICHPARSE_CHECK;
	    if (rpmrichParseInternal(&p, emsg, cb, cbdata, &subcheck) != RPMRC_OK)
		return RPMRC_FAIL;
	    if (op == RPMRICHOP_IF || op == RPMRICHOP_UNLESS)
		subcheck &= ~(RICHPARSE_NO_AND | RICHPARSE_NO_OR);
	    check |= subcheck;
	} else {
            if (parseSimpleDep(&p, emsg, cb, cbdata) != RPMRC_OK)
                return RPMRC_FAIL;
        }
        SKIPWHITE(p);
        if (!*p) {
            if (emsg)
                rasprintf(emsg, _("Unterminated rich dependency: %s"), *dstrp);
            return RPMRC_FAIL;
        }
        if (*p == ')')
            break;
        pe = p;
        if (parseRichDepOp(&pe, &op, emsg) != RPMRC_OK)
            return RPMRC_FAIL;
	if (firstop == RPMRICHOP_SINGLE)
	    firstop = op;

	if (op == RPMRICHOP_ELSE && (chainop == RPMRICHOP_IF || chainop == RPMRICHOP_UNLESS))
	    chainop = RPMRICHOP_NONE;
        if (chainop && op != chainop) {
            if (emsg)
                rasprintf(emsg, _("Cannot chain different ops"));
            return RPMRC_FAIL;
        }
        if (chainop && op != RPMRICHOP_AND && op != RPMRICHOP_OR && op != RPMRICHOP_WITH) {
            if (emsg)
                rasprintf(emsg, _("Can only chain and/or/with ops"));
            return RPMRC_FAIL;
	}
        if (cb && cb(cbdata, RPMRICH_PARSE_OP, p, pe - p, 0, 0, 0, op, emsg) != RPMRC_OK)
            return RPMRC_FAIL;
        chainop = op;
        p = pe;
    }

    /* check for illegal combinations */
    if (rpmrichParseCheck(firstop, check, emsg) != RPMRC_OK)
	return RPMRC_FAIL;

    /* update check data */
    if (firstop == RPMRICHOP_IF)
	check |= RICHPARSE_NO_OR;
    if (firstop == RPMRICHOP_UNLESS)
	check |= RICHPARSE_NO_AND;
    if (op == RPMRICHOP_AND || op == RPMRICHOP_OR)
	check &= ~(RICHPARSE_NO_AND | RICHPARSE_NO_OR);
    if (op != RPMRICHOP_SINGLE && op != RPMRICHOP_WITH && op != RPMRICHOP_WITHOUT && op != RPMRICHOP_OR)
	check |= RICHPARSE_NO_WITH;

    p++;
    if (cb && cb(cbdata, RPMRICH_PARSE_LEAVE, *dstrp, p - *dstrp , 0, 0, 0, op, emsg) != RPMRC_OK)
        return RPMRC_FAIL;
    *dstrp = p;
    if (checkp)
	*checkp |= check;
    return RPMRC_OK;
}

rpmRC rpmrichParse(const char **dstrp, char **emsg, rpmrichParseFunction cb, void *cbdata)
{
    return rpmrichParseInternal(dstrp, emsg, cb, cbdata, NULL);
}

rpmRC rpmrichParseForTag(const char **dstrp, char **emsg, rpmrichParseFunction cb, void *cbdata, rpmTagVal tagN)
{
    int check = RICHPARSE_CHECK;
    if (rpmrichParseInternal(dstrp, emsg, cb, cbdata, &check) != RPMRC_OK)
	return RPMRC_FAIL;
    switch (tagN) {
    case RPMTAG_CONFLICTNAME:
    case RPMTAG_SUPPLEMENTNAME:
    case RPMTAG_ENHANCENAME:
	if (rpmrichParseCheck(RPMRICHOP_OR, check, emsg) != RPMRC_OK)
	    return RPMRC_FAIL;
	break;
    default:
	if (rpmrichParseCheck(RPMRICHOP_AND, check, emsg) != RPMRC_OK)
	    return RPMRC_FAIL;
	break;
    }
    return RPMRC_OK;
}

struct rpmdsParseRichDepData {
    rpmds dep;
    rpmsenseFlags depflags;

    rpmds leftds;
    rpmds rightds;
    rpmrichOp op;

    int depth;
    const char *rightstart;
    int dochain;
};

static rpmRC rpmdsParseRichDepCB(void *cbdata, rpmrichParseType type,
		const char *n, int nl, const char *e, int el, rpmsenseFlags sense,
		rpmrichOp op, char **emsg) {
    struct rpmdsParseRichDepData *data = (struct rpmdsParseRichDepData *)cbdata;
    rpmds ds = 0;

    if (type == RPMRICH_PARSE_ENTER)
	data->depth++;
    else if (type == RPMRICH_PARSE_LEAVE) {
	if (--data->depth == 0 && data->dochain && data->rightstart) {
	    /* chain op hack, construct a sub-ds from the right side of the chain */
	    char *right = (char *)xmalloc(n + nl - data->rightstart + 2);
	    right[0] = '(';
	    strncpy(right + 1, data->rightstart, n + nl - data->rightstart);
	    right[n + nl - data->rightstart + 1] = 0;
	    data->rightds = rpmdsFree(data->rightds);
	    ds = singleDS(data->dep->pool, data->dep->tagN, 0, 0, data->depflags, 0, 0, 0);
	    ds->N[0] = rpmstrPoolId(ds->pool, right, 1);
	    ds->EVR[0] = rpmstrPoolId(ds->pool, "", 1);
	    data->rightds = ds;
	    free(right);
	}
    }
    if (data->depth != 1)
	return RPMRC_OK;	/* we're only interested in top-level parsing */
    if ((type == RPMRICH_PARSE_SIMPLE || type == RPMRICH_PARSE_LEAVE) && !data->dochain) {
	if (type == RPMRICH_PARSE_SIMPLE && data->dep->tagN == RPMTAG_REQUIRENAME && nl > 7 &&
			 rstreqn(n, "rpmlib(", sizeof("rpmlib(")-1))
	    sense |= RPMSENSE_RPMLIB;
	ds = singleDS(data->dep->pool, data->dep->tagN, 0, 0, sense | data->depflags, 0, 0, 0);
	ds->N[0] = rpmstrPoolIdn(ds->pool, n, nl, 1);
	ds->EVR[0] = rpmstrPoolIdn(ds->pool, e ? e : "", el, 1);
	if (!data->leftds)
	    data->leftds = ds;
	else {
	    data->rightds = ds;
	    data->rightstart = n;
	}
    }
    if (type == RPMRICH_PARSE_OP) {
	if (data->op != RPMRICHOP_SINGLE)
	    data->dochain = 1;	/* this is a chained op */
	else
	    data->op = op;
    }
    return RPMRC_OK;
}


rpmRC rpmdsParseRichDep(rpmds dep, rpmds *leftds, rpmds *rightds, rpmrichOp *op, char **emsg)
{
    rpmRC rc;
    struct rpmdsParseRichDepData data;
    const char *depstr = rpmdsN(dep);
    memset(&data, 0, sizeof(data));
    data.dep = dep;
    data.op = RPMRICHOP_SINGLE;
    data.depflags = rpmdsFlags(dep) & ~(RPMSENSE_SENSEMASK | RPMSENSE_MISSINGOK);
    rc = rpmrichParse(&depstr, emsg, rpmdsParseRichDepCB, &data);
    if (rc == RPMRC_OK && *depstr) {
	if (emsg)
	    rasprintf(emsg, _("Junk after rich dependency"));
	rc = RPMRC_FAIL;
    }
    if (rc != RPMRC_OK) {
	rpmdsFree(data.leftds);
	rpmdsFree(data.rightds);
    } else {
	*leftds = data.leftds;
	*rightds = data.rightds;
	*op = data.op;
    }
    return rc;
}

