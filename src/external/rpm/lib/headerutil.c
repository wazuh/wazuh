/** \ingroup rpmdb
 * \file lib/headerutil.c
 */

#include "system.h"

#include <rpm/rpmtypes.h>
#include <rpm/rpmlib.h>
#include <rpm/header.h>
#include <rpm/rpmstring.h>
#include <rpm/rpmds.h>

#include "debug.h"

int headerIsSource(Header h)
{
    /* Positive identification of a source package */
    if (headerIsEntry(h, RPMTAG_SOURCEPACKAGE))
	return 1;
    /* Positive identification of a binary package */
    if (headerIsEntry(h, RPMTAG_SOURCERPM))
	return 0;
    /* Dunno, guess so (as per traditional behavior) */
    return 1;
}

Header headerCopy(Header h)
{
    Header nh = headerNew();
    HeaderIterator hi;
    struct rpmtd_s td;
   
    hi = headerInitIterator(h);
    while (headerNext(hi, &td)) {
	if (rpmtdCount(&td) > 0) {
	    (void) headerPut(nh, &td, HEADERPUT_DEFAULT);
	}
	rpmtdFreeData(&td);
    }
    headerFreeIterator(hi);

    return nh;
}

void headerCopyTags(Header headerFrom, Header headerTo, 
		    const rpmTagVal * tagstocopy)
{
    const rpmTagVal * p;
    struct rpmtd_s td;

    if (headerFrom == headerTo)
	return;

    for (p = tagstocopy; *p != 0; p++) {
	if (headerIsEntry(headerTo, *p))
	    continue;
	if (!headerGet(headerFrom, *p, &td, (HEADERGET_MINMEM|HEADERGET_RAW)))
	    continue;
	(void) headerPut(headerTo, &td, HEADERPUT_DEFAULT);
	rpmtdFreeData(&td);
    }
}

char * headerGetAsString(Header h, rpmTagVal tag)
{
    char *res = NULL;
    struct rpmtd_s td;

    if (headerGet(h, tag, &td, HEADERGET_EXT)) {
	if (rpmtdCount(&td) == 1) {
	    res = rpmtdFormat(&td, RPMTD_FORMAT_STRING, NULL);
	}
	rpmtdFreeData(&td);
    }
    return res;
}

const char * headerGetString(Header h, rpmTagVal tag)
{
    const char *res = NULL;
    struct rpmtd_s td;

    if (headerGet(h, tag, &td, HEADERGET_MINMEM)) {
	if (rpmtdCount(&td) == 1) {
	    res = rpmtdGetString(&td);
	}
	rpmtdFreeData(&td);
    }
    return res;
}

uint64_t headerGetNumber(Header h, rpmTagVal tag)
{
    uint64_t res = 0;
    struct rpmtd_s td;

    if (headerGet(h, tag, &td, HEADERGET_EXT)) {
	if (rpmtdCount(&td) == 1) {
	    res = rpmtdGetNumber(&td);
	}
	rpmtdFreeData(&td);
    }
    return res;
}

/*
 * Sanity check data types against tag table before putting. Assume
 * append on all array-types.
 */
static int headerPutType(Header h, rpmTagVal tag, rpmTagType reqtype,
			rpm_constdata_t data, rpm_count_t size)
{
    struct rpmtd_s td;
    rpmTagType type = rpmTagGetTagType(tag);
    rpmTagReturnType retype = rpmTagGetReturnType(tag);
    headerPutFlags flags = HEADERPUT_APPEND; 
    int valid = 1;

    /* Basic sanity checks: type must match and there must be data to put */
    if (type != reqtype 
	|| size < 1 || data == NULL || h == NULL) {
	valid = 0;
    }

    /*
     * Non-array types can't be appended to. Binary types use size
     * for data length, for other non-array types size must be 1.
     */
    if (retype != RPM_ARRAY_RETURN_TYPE) {
	flags = HEADERPUT_DEFAULT;
	if (type != RPM_BIN_TYPE && size != 1) {
	    valid = 0;
	}
    }

    if (valid) {
	rpmtdReset(&td);
	td.tag = tag;
	td.type = type;
	td.data = (void *) data;
	td.count = size;

	valid = headerPut(h, &td, flags);
    }

    return valid;
}
	
int headerPutString(Header h, rpmTagVal tag, const char *val)
{
    rpmTagType type = rpmTagGetTagType(tag);
    const void *sptr = NULL;

    /* string arrays expect char **, arrange that */
    if (type == RPM_STRING_ARRAY_TYPE || type == RPM_I18NSTRING_TYPE) {
	sptr = &val;
    } else if (type == RPM_STRING_TYPE) {
	sptr = val;
    } else {
	return 0;
    }

    return headerPutType(h, tag, type, sptr, 1);
}

int headerPutStringArray(Header h, rpmTagVal tag, const char **array, rpm_count_t size)
{
    return headerPutType(h, tag, RPM_STRING_ARRAY_TYPE, array, size);
}

int headerPutChar(Header h, rpmTagVal tag, const char *val, rpm_count_t size)
{
    return headerPutType(h, tag, RPM_CHAR_TYPE, val, size);
}

int headerPutUint8(Header h, rpmTagVal tag, const uint8_t *val, rpm_count_t size)
{
    return headerPutType(h, tag, RPM_INT8_TYPE, val, size);
}

int headerPutUint16(Header h, rpmTagVal tag, const uint16_t *val, rpm_count_t size)
{
    return headerPutType(h, tag, RPM_INT16_TYPE, val, size);
}

int headerPutUint32(Header h, rpmTagVal tag, const uint32_t *val, rpm_count_t size)
{
    return headerPutType(h, tag, RPM_INT32_TYPE, val, size);
}

int headerPutUint64(Header h, rpmTagVal tag, const uint64_t *val, rpm_count_t size)
{
    return headerPutType(h, tag, RPM_INT64_TYPE, val, size);
}

int headerPutBin(Header h, rpmTagVal tag, const uint8_t *val, rpm_count_t size)
{
    return headerPutType(h, tag, RPM_BIN_TYPE, val, size);
}

static int dncmp(const void * a, const void * b)
{
    const char *const * first = (const char *const *)a;
    const char *const * second = (const char *const *)b;
    return strcmp(*first, *second);
}

static void compressFilelist(Header h)
{
    struct rpmtd_s fileNames;
    char ** dirNames;
    const char ** baseNames;
    uint32_t * dirIndexes;
    rpm_count_t count, realCount = 0;
    int i;
    int dirIndex = -1;

    /*
     * This assumes the file list is already sorted, and begins with a
     * single '/'. That assumption isn't critical, but it makes things go
     * a bit faster.
     */

    if (headerIsEntry(h, RPMTAG_DIRNAMES)) {
	headerDel(h, RPMTAG_OLDFILENAMES);
	return;		/* Already converted. */
    }

    if (!headerGet(h, RPMTAG_OLDFILENAMES, &fileNames, HEADERGET_MINMEM)) 
	return;
    count = rpmtdCount(&fileNames);
    if (count < 1) 
	return;

    dirNames = (char **)xmalloc(sizeof(*dirNames) * count);	/* worst case */
    baseNames = (const char **)xmalloc(sizeof(*dirNames) * count);
    dirIndexes = (uint32_t *)xmalloc(sizeof(*dirIndexes) * count);

    /* HACK. Source RPM, so just do things differently */
    {	const char *fn = rpmtdGetString(&fileNames);
	if (fn && *fn != '/') {
	    dirIndex = 0;
	    dirNames[dirIndex] = xstrdup("");
	    while ((i = rpmtdNext(&fileNames)) >= 0) {
		dirIndexes[i] = dirIndex;
		baseNames[i] = rpmtdGetString(&fileNames);
		realCount++;
	    }
	    goto exit;
	}
    }

    /* 
     * XXX EVIL HACK, FIXME:
     * This modifies (and then restores) a const string from rpmtd
     * through basename retrieved from strrchr() which silently 
     * casts away const on return.
     */
    while ((i = rpmtdNext(&fileNames)) >= 0) {
	char ** needle;
	char savechar;
	char * baseName;
	size_t len;
	char *filename = (char *) rpmtdGetString(&fileNames); /* HACK HACK */

	if (filename == NULL)	/* XXX can't happen */
	    continue;
	baseName = strrchr(filename, '/');
	if (baseName == NULL) {
	    baseName = filename;
	} else {
	    baseName += 1;
	}
	len = baseName - filename;
	needle = dirNames;
	savechar = *baseName;
	*baseName = '\0';
	if (dirIndex < 0 ||
	    (needle = (char **)bsearch(&filename, dirNames, dirIndex + 1, sizeof(dirNames[0]), dncmp)) == NULL) {
	    char *s = (char *)xmalloc(len + 1);
	    rstrlcpy(s, filename, len + 1);
	    dirIndexes[realCount] = ++dirIndex;
	    dirNames[dirIndex] = s;
	} else
	    dirIndexes[realCount] = needle - dirNames;

	*baseName = savechar;
	baseNames[realCount] = baseName;
	realCount++;
    }

exit:
    if (count > 0) {
	headerPutUint32(h, RPMTAG_DIRINDEXES, dirIndexes, realCount);
	headerPutStringArray(h, RPMTAG_BASENAMES, baseNames, realCount);
	headerPutStringArray(h, RPMTAG_DIRNAMES, 
			     (const char **) dirNames, dirIndex + 1);
    }

    rpmtdFreeData(&fileNames);
    for (i = 0; i <= dirIndex; i++) {
	free(dirNames[i]);
    }
    free(dirNames);
    free(baseNames);
    free(dirIndexes);

    headerDel(h, RPMTAG_OLDFILENAMES);
}

static void expandFilelist(Header h)
{
    struct rpmtd_s filenames;

    if (!headerIsEntry(h, RPMTAG_OLDFILENAMES)) {
	(void) headerGet(h, RPMTAG_FILENAMES, &filenames, HEADERGET_EXT);
	if (rpmtdCount(&filenames) < 1)
	    return;
	rpmtdSetTag(&filenames, RPMTAG_OLDFILENAMES);
	headerPut(h, &filenames, HEADERPUT_DEFAULT);
	rpmtdFreeData(&filenames);
    }

    (void) headerDel(h, RPMTAG_DIRNAMES);
    (void) headerDel(h, RPMTAG_BASENAMES);
    (void) headerDel(h, RPMTAG_DIRINDEXES);
}

/*
 * Up to rpm 3.0.4, packages implicitly provided their own name-version-release.
 * Retrofit an explicit "Provides: name = epoch:version-release.
 */
static void providePackageNVR(Header h)
{
    const char *name = headerGetString(h, RPMTAG_NAME);
    char *pEVR = headerGetAsString(h, RPMTAG_EVR);
    rpmsenseFlags pFlags = RPMSENSE_EQUAL;
    int bingo = 1;
    struct rpmtd_s pnames;
    rpmds hds, nvrds;

    /* Generate provides for this package name-version-release. */
    if (!(name && pEVR)) {
	free(pEVR);
	return;
    }

    /*
     * Rpm prior to 3.0.3 does not have versioned provides.
     * If no provides at all are available, we can just add.
     */
    if (!headerGet(h, RPMTAG_PROVIDENAME, &pnames, HEADERGET_MINMEM)) {
	goto exit;
    }

    /*
     * Otherwise, fill in entries on legacy packages.
     */
    if (!headerIsEntry(h, RPMTAG_PROVIDEVERSION)) {
	while (rpmtdNext(&pnames) >= 0) {
	    rpmsenseFlags fdummy = RPMSENSE_ANY;

	    headerPutString(h, RPMTAG_PROVIDEVERSION, "");
	    headerPutUint32(h, RPMTAG_PROVIDEFLAGS, &fdummy, 1);
	}
	goto exit;
    }

    /* see if we already have this provide */
    hds = rpmdsNew(h, RPMTAG_PROVIDENAME, 0);
    nvrds = rpmdsSingle(RPMTAG_PROVIDENAME, name, pEVR, pFlags);
    if (rpmdsFind(hds, nvrds) >= 0) {
	bingo = 0;
    }
    rpmdsFree(hds);
    rpmdsFree(nvrds);
    

exit:
    if (bingo) {
	headerPutString(h, RPMTAG_PROVIDENAME, name);
	headerPutString(h, RPMTAG_PROVIDEVERSION, pEVR);
	headerPutUint32(h, RPMTAG_PROVIDEFLAGS, &pFlags, 1);
    }
    rpmtdFreeData(&pnames);
    free(pEVR);
}

static void legacyRetrofit(Header h)
{
    /*
     * The file list was moved to a more compressed format which not
     * only saves memory (nice), but gives fingerprinting a nice, fat
     * speed boost (very nice). Go ahead and convert old headers to
     * the new style (this is a noop for new headers).
     */
     compressFilelist(h);

    /* Retrofit "Provide: name = EVR" for binary packages. */
    if (!headerIsSource(h)) {
	providePackageNVR(h);
    }
}

int headerConvert(Header h, int op)
{
    int rc = 1;

    if (h == NULL)
	return 0;

    switch (op) {
    case HEADERCONV_EXPANDFILELIST:
	expandFilelist(h);
	break;
    case HEADERCONV_COMPRESSFILELIST:
	compressFilelist(h);
	break;
    case HEADERCONV_RETROFIT_V3:
	legacyRetrofit(h);
	break;
    default:
	rc = 0;
	break;
    }
    return rc;
};

int rpmVersionCompare(Header first, Header second)
{
    /* Missing epoch becomes zero here, which is what we want */
    uint32_t epochOne = headerGetNumber(first, RPMTAG_EPOCH);
    uint32_t epochTwo = headerGetNumber(second, RPMTAG_EPOCH);
    int rc;

    if (epochOne < epochTwo)
	return -1;
    else if (epochOne > epochTwo)
	return 1;

    rc = rpmvercmp(headerGetString(first, RPMTAG_VERSION),
		   headerGetString(second, RPMTAG_VERSION));
    if (rc)
	return rc;

    return rpmvercmp(headerGetString(first, RPMTAG_RELEASE),
		     headerGetString(second, RPMTAG_RELEASE));
}
