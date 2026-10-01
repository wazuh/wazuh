#include "system.h"

#include <rpm/rpmtypes.h>
#include <rpm/header.h>
#include <rpm/rpmfi.h>
#include <rpm/rpmfileutil.h>
#include <rpm/rpmmacro.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmstring.h>

#include "rpmfs.h"
#include "misc.h"

#include "debug.h"

/**
 * Identify a file type.
 * @param ft		file type
 * @return		string to identify a file type
 */
static
const char * ftstring (rpmFileTypes ft)
{
    switch (ft) {
    case XDIR:	return "directory";
    case CDEV:	return "char dev";
    case BDEV:	return "block dev";
    case LINK:	return "link";
    case SOCK:	return "sock";
    case PIPE:	return "fifo/pipe";
    case REG:	return "file";
    default:	return "unknown file type";
    }
}

static char **duparray(char ** src, int size)
{
    char **dest = (char **)xmalloc((size+1) * sizeof(*dest));
    for (int i = 0; i < size; i++) {
	dest[i] = xstrdup(src[i]);
    }
    free(src);
    return dest;
}

static int addPrefixes(Header h, rpmRelocation *relocations, int numRelocations)
{
    struct rpmtd_s validRelocs;
    const char *validprefix;
    const char ** actualRelocations;
    int numActual = 0;

    headerGet(h, RPMTAG_PREFIXES, &validRelocs, HEADERGET_MINMEM);
    /*
     * If no relocations are specified (usually the case), then return the
     * original header. If there are prefixes, however, then INSTPREFIXES
     * should be added for RPM_INSTALL_PREFIX environ variables in scriptlets, 
     * but, since relocateFileList() can be called more than once for 
     * the same header, don't bother if already present.
     */
    if (relocations == NULL || numRelocations == 0) {
	if (rpmtdCount(&validRelocs) > 0) {
	    if (!headerIsEntry(h, RPMTAG_INSTPREFIXES)) {
		rpmtdSetTag(&validRelocs, RPMTAG_INSTPREFIXES);
		headerPut(h, &validRelocs, HEADERPUT_DEFAULT);
	    }
	    rpmtdFreeData(&validRelocs);
	}
	return 0;
    }

    actualRelocations = (const char **)xmalloc(rpmtdCount(&validRelocs) * sizeof(*actualRelocations));
    rpmtdInit(&validRelocs);
    while ((validprefix = rpmtdNextString(&validRelocs))) {
	int j;
	for (j = 0; j < numRelocations; j++) {
	    if (relocations[j].oldPath == NULL || /* XXX can't happen */
		!rstreq(validprefix, relocations[j].oldPath))
		continue;
	    /* On install, a relocate to NULL means skip the path. */
	    if (relocations[j].newPath) {
		actualRelocations[numActual] = relocations[j].newPath;
		numActual++;
	    }
	    break;
	}
	if (j == numRelocations) {
	    actualRelocations[numActual] = validprefix;
	    numActual++;
	}
    }
    rpmtdFreeData(&validRelocs);

    if (numActual) {
	headerPutStringArray(h, RPMTAG_INSTPREFIXES, actualRelocations, numActual);
    }
    free(actualRelocations);
    /* When any relocations are present there'll be more work to do */
    return 1;
}

static void saveOrig(Header h)
{
	struct rpmtd_s td;
	headerGet(h, RPMTAG_BASENAMES, &td, HEADERGET_MINMEM);
	rpmtdSetTag(&td, RPMTAG_ORIGBASENAMES);
	headerPut(h, &td, HEADERPUT_DEFAULT);
	rpmtdFreeData(&td);

	headerGet(h, RPMTAG_DIRNAMES, &td, HEADERGET_MINMEM);
	rpmtdSetTag(&td, RPMTAG_ORIGDIRNAMES);
	headerPut(h, &td, HEADERPUT_DEFAULT);
	rpmtdFreeData(&td);

	headerGet(h, RPMTAG_DIRINDEXES, &td, HEADERGET_MINMEM);
	rpmtdSetTag(&td, RPMTAG_ORIGDIRINDEXES);
	headerPut(h, &td, HEADERPUT_DEFAULT);
	rpmtdFreeData(&td);
}

void rpmRelocateFileList(rpmRelocation *relocations, int numRelocations, 
			 rpmfs fs, Header h)
{
    char ** baseNames;
    char ** dirNames;
    uint32_t * dirIndexes;
    rpm_count_t fileCount, dirCount, dirCountOrig;
    int nrelocated = 0;
    int fileAlloced = 0;
    char * fn = NULL;
    int haveRelocatedBase = 0;
    size_t maxlen = 0;
    int i, j;
    struct rpmtd_s bnames, dnames, dindexes, fmodes;

    if (!addPrefixes(h, relocations, numRelocations))
	return;

    if (rpmIsDebug()) {
	rpmlog(RPMLOG_DEBUG, "========== relocations\n");
	for (i = 0; i < numRelocations; i++) {
	    if (relocations[i].oldPath == NULL) continue; /* XXX can't happen */
	    if (relocations[i].newPath == NULL)
		rpmlog(RPMLOG_DEBUG, "%5d exclude  %s\n",
			i, relocations[i].oldPath);
	    else
		rpmlog(RPMLOG_DEBUG, "%5d relocate %s -> %s\n",
			i, relocations[i].oldPath, relocations[i].newPath);
	}
    }

    for (i = 0; i < numRelocations; i++) {
	if (relocations[i].newPath == NULL) continue;
	size_t len = strlen(relocations[i].newPath);
	if (len > maxlen) maxlen = len;
    }

    headerGet(h, RPMTAG_BASENAMES, &bnames, HEADERGET_MINMEM);
    headerGet(h, RPMTAG_DIRINDEXES, &dindexes, HEADERGET_ALLOC);
    headerGet(h, RPMTAG_DIRNAMES, &dnames, HEADERGET_MINMEM);
    headerGet(h, RPMTAG_FILEMODES, &fmodes, HEADERGET_MINMEM);
    /* TODO XXX ugh.. use rpmtd iterators & friends instead */
    baseNames = (char **)bnames.data;
    dirIndexes = (uint32_t *)dindexes.data;
    fileCount = rpmtdCount(&bnames);
    dirCount = dirCountOrig = rpmtdCount(&dnames);
    /* XXX TODO: use rpmtdDup() instead */
    dirNames = duparray((char **)dnames.data, dirCount);
    dnames.data = dirNames;
    dnames.flags |= RPMTD_PTR_ALLOCED;

    /*
     * For all relocations, we go through sorted file/relocation lists 
     * backwards so that /usr/local relocations take precedence over /usr 
     * ones.
     */

    /* Relocate individual paths. */

    for (i = fileCount - 1; i >= 0; i--) {
	rpmFileTypes ft;
	int fnlen;

	size_t baselen = strlen(baseNames[i]);
	size_t len = maxlen +
		strlen(dirNames[dirIndexes[i]]) + baselen + 1;
	if (len >= fileAlloced) {
	    fileAlloced = len * 2;
	    fn = xrealloc(fn, fileAlloced);
	}

assert(fn != NULL);		/* XXX can't happen */
	*fn = '\0';
	fnlen = stpcpy( stpcpy(fn, dirNames[dirIndexes[i]]), baseNames[i]) - fn;

	/*
	 * See if this file path needs relocating.
	 */
	/*
	 * XXX FIXME: Would a bsearch of the (already sorted) 
	 * relocation list be a good idea?
	 */
	for (j = numRelocations - 1; j >= 0; j--) {
	    if (relocations[j].oldPath == NULL) /* XXX can't happen */
		continue;
	    len = !rstreq(relocations[j].oldPath, "/")
		? strlen(relocations[j].oldPath)
		: 0;

	    if (fnlen < len)
		continue;
	    /*
	     * Only subdirectories or complete file paths may be relocated. We
	     * don't check for '\0' as our directory names all end in '/'.
	     */
	    if (!(fn[len] == '/' || fnlen == len))
		continue;

	    if (!rstreqn(relocations[j].oldPath, fn, len))
		continue;
	    break;
	}
	if (j < 0) continue;

	rpmtdSetIndex(&fmodes, i);
	ft = rpmfiWhatis(rpmtdGetNumber(&fmodes));

	/* On install, a relocate to NULL means skip the path. */
	if (relocations[j].newPath == NULL) {
	    if (ft == XDIR) {
		/* Start with the parent, looking for directory to exclude. */
		for (j = dirIndexes[i]; j < dirCount; j++) {
		    len = strlen(dirNames[j]) - 1;
		    while (len > 0 && dirNames[j][len-1] == '/') len--;
		    if (fnlen != len)
			continue;
		    if (!rstreqn(fn, dirNames[j], fnlen))
			continue;
		    break;
		}
	    }
	    rpmfsSetAction(fs, i, FA_SKIPNSTATE);
	    rpmlog(RPMLOG_DEBUG, "excluding %s %s\n",
		   ftstring(ft), fn);
	    continue;
	}

	/* Relocation on '/' and full paths only, please. */
	if (baselen && fnlen != len)
	    continue;

	rpmlog(RPMLOG_DEBUG, "relocating %s to %s\n",
	       fn, relocations[j].newPath);
	nrelocated++;

	strcpy(fn, relocations[j].newPath);
	{   char * te = strrchr(fn, '/');
	    if (te) {
		if (te > fn) te++;	/* root is special */
		fnlen = te - fn;
	    } else
		te = fn + strlen(fn);
	    if (!rstreq(baseNames[i], te)) { /* basename changed too? */
		if (!haveRelocatedBase) {
		    /* XXX TODO: use rpmtdDup() instead */
		    bnames.data = baseNames = duparray(baseNames, fileCount);
		    bnames.flags |= RPMTD_PTR_ALLOCED;
		    haveRelocatedBase = 1;
		}
		free(baseNames[i]);
		baseNames[i] = xstrdup(te);
	    }
	    *te = '\0';			/* terminate new directory name */
	}

	/* Does this directory already exist in the directory list? */
	for (j = 0; j < dirCount; j++) {
	    if (fnlen != strlen(dirNames[j]))
		continue;
	    if (!rstreqn(fn, dirNames[j], fnlen))
		continue;
	    break;
	}
	
	if (j < dirCount) {
	    dirIndexes[i] = j;
	    continue;
	}

	/* Creating new paths is a pita */
	dnames.data = xrealloc(dnames.data,
			       sizeof(*dirNames) * (dirCount + 1));
	dirNames = (char **)dnames.data;

	dirNames[dirCount] = xstrdup(fn);
	dirIndexes[i] = dirCount;
	dirCount++;
	dnames.count++;
    }

    /* Finish off by relocating directories. */
    for (i = dirCountOrig - 1; i >= 0; i--) {
	for (j = numRelocations - 1; j >= 0; j--) {

	    if (relocations[j].oldPath == NULL) /* XXX can't happen */
		continue;
	    size_t len = !rstreq(relocations[j].oldPath, "/")
		? strlen(relocations[j].oldPath)
		: 0;

	    if (len && !rstreqn(relocations[j].oldPath, dirNames[i], len))
		continue;

	    /*
	     * Only subdirectories or complete file paths may be relocated. We
	     * don't check for '\0' as our directory names all end in '/'.
	     */
	    if (dirNames[i][len] != '/')
		continue;

	    if (relocations[j].newPath) { /* Relocate the path */
		char *t = NULL;
		rstrscat(&t, relocations[j].newPath, (dirNames[i] + len), NULL);
		/* Unfortunately rpmCleanPath strips the trailing slash.. */
		(void) rpmCleanPath(t);
		rstrcat(&t, "/");

		rpmlog(RPMLOG_DEBUG,
		       "relocating directory %s to %s\n", dirNames[i], t);
		free(dirNames[i]);
		dirNames[i] = t;
		nrelocated++;
	    }
	}
    }

    /* Save original filenames in header and replace (relocated) filenames. */
    if (nrelocated) {
	saveOrig(h);
	headerMod(h, &bnames);
	headerMod(h, &dnames);
	headerMod(h, &dindexes);
    }

    rpmtdFreeData(&bnames);
    rpmtdFreeData(&dnames);
    rpmtdFreeData(&dindexes);
    rpmtdFreeData(&fmodes);
    free(fn);
}

/**
 * Macros to be defined from per-header tag values.
 * @todo Should other macros be added from header when installing a package?
 */
static struct tagMacro {
    const char *macroname; 	/*!< Macro name to define. */
    rpmTagVal tag;		/*!< Header tag to use for value. */
} const tagMacros[] = {
    { "name",		RPMTAG_NAME },
    { "version",	RPMTAG_VERSION },
    { "release",	RPMTAG_RELEASE },
    { "epoch",		RPMTAG_EPOCH },
    { NULL, 0 }
};

/**
 * Define or undefine per-header macros.
 * @param h		header
 * @param define	define/undefine?
 * @return		0 always
 */
static void rpmInstallLoadMacros(Header h, int define)
{
    const struct tagMacro * tagm;

    for (tagm = tagMacros; tagm->macroname != NULL; tagm++) {
	struct rpmtd_s td;
	char *body;
	if (!headerGet(h, tagm->tag, &td, HEADERGET_DEFAULT))
	    continue;

	/*
	 * Undefine doesn't need the actual data for anything, but
	 * this way ensures we only undefine what was defined earlier.
	 */
	if (define) {
	    body = rpmtdFormat(&td, RPMTD_FORMAT_STRING, NULL);
	    rpmPushMacro(NULL, tagm->macroname, NULL, body, -1);
	    free(body);
	} else {
	    rpmPopMacro(NULL, tagm->macroname);
	}
	rpmtdFreeData(&td);
    }
}

int headerFindSpec(Header h)
{
    struct rpmtd_s filenames;
    int specix = -1;

    if (headerGet(h, RPMTAG_BASENAMES, &filenames, HEADERGET_MINMEM)) {
	struct rpmtd_s td;
	const char *str;
	
	/* Try to find spec by file flags */
	if (headerGet(h, RPMTAG_FILEFLAGS, &td, HEADERGET_MINMEM)) {
	    rpmfileAttrs *flags;
	    while (specix < 0 && (flags = rpmtdNextUint32(&td))) {
		if (*flags & RPMFILE_SPECFILE)
		    specix = rpmtdGetIndex(&td);
	    }
	    rpmtdFreeData(&td);
	}
	/* Still no spec? Look by filename. */
	while (specix < 0 && (str = rpmtdNextString(&filenames))) {
	    if (rpmFileHasSuffix(str, ".spec")) 
		specix = rpmtdGetIndex(&filenames);
	}
	rpmtdFreeData(&filenames);
    }
    return specix;
}

/*
 * Source rpms only contain basenames, on install the full paths are
 * constructed with %{_specdir} and %{_sourcedir} macros. Because
 * of that regular relocation wont work, we need to do it the hard
 * way. Return spec file index on success, -1 on errors.
 */
int rpmRelocateSrpmFileList(Header h, const char *rootDir)
{
    int specix = headerFindSpec(h);

    if (specix >= 0) {
	const char *bn;
	struct rpmtd_s filenames;
	/* save original file names */
	saveOrig(h);

	headerDel(h, RPMTAG_BASENAMES);
	headerDel(h, RPMTAG_DIRNAMES);
	headerDel(h, RPMTAG_DIRINDEXES);

	/* Macros need to be added before trying to create directories */
	rpmInstallLoadMacros(h, 1);

	/* ALLOC is needed as we modify the header */
	headerGet(h, RPMTAG_ORIGBASENAMES, &filenames, HEADERGET_ALLOC);
	for (int i = 0; (bn = rpmtdNextString(&filenames)); i++) {
	    int spec = (i == specix);
	    char *fn = rpmGenPath(rootDir,
				  spec ? "%{_specdir}" : "%{_sourcedir}", bn);
	    headerPutString(h, RPMTAG_OLDFILENAMES, fn);
	    free(fn);
	}
	rpmtdFreeData(&filenames);
	headerConvert(h, HEADERCONV_COMPRESSFILELIST);
	rpmInstallLoadMacros(h, 0);
    }

    return specix;
}

/* stupid bubble sort, but it's probably faster here */
static void sortRelocs(rpmRelocation *relocations, int numRelocations)
{
    for (int i = 0; i < numRelocations; i++) {
	int madeSwap = 0;
	for (int j = 1; j < numRelocations; j++) {
	    rpmRelocation tmpReloc;
	    if (relocations[j - 1].oldPath == NULL || /* XXX can't happen */
		relocations[j    ].oldPath == NULL || /* XXX can't happen */
		strcmp(relocations[j - 1].oldPath, relocations[j].oldPath) <= 0)
		continue;
	    tmpReloc = relocations[j - 1];
	    relocations[j - 1] = relocations[j];
	    relocations[j] = tmpReloc;
	    madeSwap = 1;
	}
	if (!madeSwap) break;
    }
}

static char * stripTrailingChar(char * s, char c)
{
    char * t;
    for (t = s + strlen(s) - 1; *t == c && t >= s; t--)
	*t = '\0';
    return s;
}

void rpmRelocationBuild(Header h, rpmRelocation *rawrelocs,
		int *rnrelocs, rpmRelocation **rrelocs, uint8_t **rbadrelocs)
{
    int i;
    struct rpmtd_s validRelocs;
    rpmRelocation * relocs = NULL;
    uint8_t *badrelocs = NULL;
    int nrelocs = 0;

    for (rpmRelocation *r = rawrelocs; r->oldPath || r->newPath; r++)
	nrelocs++;

    headerGet(h, RPMTAG_PREFIXES, &validRelocs, HEADERGET_MINMEM);
    relocs = (rpmRelocation *)xmalloc(sizeof(*relocs) * (nrelocs+1));

    /* Build sorted relocation list from raw relocations. */
    for (i = 0; i < nrelocs; i++) {
	char * t;

	/*
	 * Default relocations (oldPath == NULL) are handled in the UI,
	 * not rpmlib.
	 */
	if (rawrelocs[i].oldPath == NULL) continue; /* XXX can't happen */

	/* FIXME: Trailing /'s will confuse us greatly. Internal ones will 
	   too, but those are more trouble to fix up. :-( */
	t = xstrdup(rawrelocs[i].oldPath);
	relocs[i].oldPath = (t[0] == '/' && t[1] == '\0')
	    ? t
	    : stripTrailingChar(t, '/');

	/* An old path w/o a new path is valid, and indicates exclusion */
	if (rawrelocs[i].newPath) {
	    int valid = 0;
	    const char *validprefix;

	    t = xstrdup(rawrelocs[i].newPath);
	    relocs[i].newPath = (t[0] == '/' && t[1] == '\0')
		? t
		: stripTrailingChar(t, '/');

	   	/* FIX:  relocations[i].oldPath == NULL */
	    /* Verify that the relocation's old path is in the header. */
	    rpmtdInit(&validRelocs);
	    while ((validprefix = rpmtdNextString(&validRelocs))) {
		if (rstreq(validprefix, relocs[i].oldPath)) {
		    valid = 1;
		    break;
		}
	    }

	    if (!valid) {
		if (badrelocs == NULL)
		    badrelocs = (uint8_t *)xcalloc(nrelocs, sizeof(*badrelocs));
		badrelocs[i] = 1;
	    }
	} else {
	    relocs[i].newPath = NULL;
	}
    }
    relocs[i].oldPath = NULL;
    relocs[i].newPath = NULL;
    sortRelocs(relocs, nrelocs);
    
    rpmtdFreeData(&validRelocs);

    *rrelocs = relocs;
    *rnrelocs = nrelocs;
    *rbadrelocs = badrelocs;
}

