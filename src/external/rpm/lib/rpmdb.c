/** \ingroup rpmdb dbi
 * \file lib/rpmdb.c
 */

#include "system.h"

#include <sys/file.h>
#include <utime.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>

#ifndef	DYING	/* XXX already in "system.h" */
#include <fnmatch.h>
#endif

#include <regex.h>

#include <rpm/rpmtypes.h>
#include <rpm/rpmurl.h>
#include <rpm/rpmcrypto.h>
#include <rpm/rpmmacro.h>
#include <rpm/rpmsq.h>
#include <rpm/rpmstring.h>
#include <rpm/rpmfileutil.h>
#include <rpm/rpmds.h>			/* XXX isInstallPreReq macro only */
#include <rpm/rpmlog.h>
#include <rpm/rpmdb.h>
#include <rpm/rpmts.h>
#include <rpm/argv.h>

#include "rpmchroot.h"
#include "rpmdb_internal.h"
#include "fprint.h"
#include "header_internal.h"	/* XXX for headerSetInstance() */
#include "backend/dbi.h"
#include "backend/dbiset.h"
#include "misc.h"
#include "debug.h"

#define HASHTYPE dbChk
#define HTKEYTYPE unsigned int
#define HTDATATYPE rpmRC
#include "rpmhash.H"
#include "rpmhash.C"
#undef HASHTYPE
#undef HTKEYTYPE
#undef HTDATATYPE

static rpmdb rpmdbUnlink(rpmdb db);

static int buildIndexes(rpmdb db)
{
    int rc = 0;
    Header h;
    rpmdbMatchIterator mi;

    rc += rpmdbOpenAll(db);

    /* If the main db was just created, this is expected - dont whine */
    if (!(dbiFlags(db->db_pkgs) & DBI_CREATED)) {
	rpmlog(RPMLOG_WARNING,
	       _("Generating %d missing index(es), please wait...\n"),
	       db->db_buildindex);
    }

    /* Don't call us again */
    db->db_buildindex = 0;

    dbSetFSync(db, 0);

    dbCtrl(db, DB_CTRL_LOCK_RW);

    mi = rpmdbInitIterator(db, RPMDBI_PACKAGES, NULL, 0);
    while ((h = rpmdbNextIterator(mi))) {
	unsigned int hdrNum = headerGetInstance(h);
	/* Build all secondary indexes which were created on open */
	for (int dbix = 0; dbix < db->db_ndbi; dbix++) {
	    dbiIndex dbi = db->db_indexes[dbix];
	    if (dbi && (dbiFlags(dbi) & DBI_CREATED)) {
		rc += idxdbPut(dbi, db->db_tags[dbix], hdrNum, h);
	    }
	}
    }
    rpmdbFreeIterator(mi);

    dbCtrl(db, DB_CTRL_INDEXSYNC);
    dbCtrl(db, DB_CTRL_UNLOCK_RW);

    dbSetFSync(db, !db->cfg.db_no_fsync);
    return rc;
}

static int uintCmp(unsigned int a, unsigned int b)
{
    return (a != b);
}

static unsigned int uintId(unsigned int a)
{
    return a;
}

/** \ingroup dbi
 * Return (newly allocated) integer of the epoch.
 * @param s		version string optionally containing epoch number
 * @param[out] version	only the version part of s
 * @return		epoch integer within the [0; UINT32_MAX] interval,
 *                      or -1 for no epoch
 */
static int64_t splitEpoch(const char *s, const char **version)
{
    int64_t e;
    char *end;
    int saveerrno = errno;

    *version = s;
    e = strtol(s, &end, 10);
    if (*end == ':' && e >= 0 && e <= UINT32_MAX) {
	*version = end + 1;
    } else {
	e = -1;
    }

    errno = saveerrno;
    return e;
}

static int pkgdbOpen(rpmdb db, int flags, dbiIndex *dbip)
{
    int rc = 0;
    dbiIndex dbi = NULL;

    if (db == NULL)
	return -1;

    /* Is this it already open ? */
    if ((dbi = db->db_pkgs) != NULL)
	goto exit;

    rc = dbiOpen(db, RPMDBI_PACKAGES, &dbi, flags);

    if (rc == 0) {
	int verifyonly = (flags & RPMDB_FLAG_VERIFYONLY);

	db->db_pkgs = dbi;
	/* Allocate header checking cache .. based on some random number */
	if (!verifyonly && (db->db_checked == NULL)) {
	    db->db_checked = dbChkCreate(567, uintId, uintCmp, NULL, NULL);
	}
	/* If primary got created, we can safely run without fsync */
	if ((!verifyonly && (dbiFlags(dbi) & DBI_CREATED)) || db->cfg.db_no_fsync) {
	    rpmlog(RPMLOG_DEBUG, "disabling fsync on database\n");
	    db->cfg.db_no_fsync = 1;
	    dbSetFSync(db, 0);
	}
    } else {
	rpmlog(RPMLOG_ERR, _("cannot open %s index using %s - %s (%d)\n"),
		   rpmTagGetName(RPMDBI_PACKAGES), db->db_descr,
		   (rc > 0 ? strerror(rc) : ""), rc);
    }

exit:
    if (rc == 0 && dbip)
	*dbip = dbi;

    return rc;
}

static int indexOpen(rpmdb db, rpmDbiTagVal rpmtag, int flags, dbiIndex *dbip)
{
    int dbix, rc = 0;
    dbiIndex dbi = NULL;

    if (db == NULL)
	return -1;

    for (dbix = 0; dbix < db->db_ndbi; dbix++) {
	if (rpmtag == db->db_tags[dbix])
	    break;
    }
    if (dbix >= db->db_ndbi)
	return -1;

    /* Is this index already open ? */
    if ((dbi = db->db_indexes[dbix]) != NULL)
	goto exit;

    rc = dbiOpen(db, rpmtag, &dbi, flags);

    if (rc == 0) {
	int verifyonly = (flags & RPMDB_FLAG_VERIFYONLY);
	int rebuild = (db->db_flags & RPMDB_FLAG_REBUILD);

	db->db_indexes[dbix] = dbi;
	if (!rebuild && !verifyonly && (dbiFlags(dbi) & DBI_CREATED)) {
	    rpmlog(RPMLOG_DEBUG, "index %s needs creating\n", dbiName(dbi));
	    db->db_buildindex++;
	    if (db->db_buildindex == 1) {
		buildIndexes(db);
	    }
	}
    } else {
	rpmlog(RPMLOG_ERR, _("cannot open %s index using %s - %s (%d)\n"),
		   rpmTagGetName(rpmtag), db->db_descr,
		   (rc > 0 ? strerror(rc) : ""), rc);
    }

exit:
    if (rc == 0 && dbip)
	*dbip = dbi;
    return rc;
}

static rpmRC indexGet(dbiIndex dbi, const char *keyp, size_t keylen,
		       dbiIndexSet *set)
{
    rpmRC rc = RPMRC_FAIL; /* assume failure */
    if (dbi != NULL) {
	dbiCursor dbc = dbiCursorInit(dbi, DBC_READ);

	if (keyp) {
	    if (keylen == 0)
		keylen = strlen(keyp);
	    rc = idxdbGet(dbi, dbc, keyp, keylen, set, DBC_NORMAL_SEARCH);
	} else {
	    do {
		rc = idxdbGet(dbi, dbc, NULL, 0, set, DBC_NORMAL_SEARCH);
	    } while (rc == RPMRC_OK);

	    /* If we got some results, not found is not an error */
	    if (rc == RPMRC_NOTFOUND && set != NULL)
		rc = RPMRC_OK;
	}

	dbiCursorFree(dbi, dbc);
    }
    return rc;
}

static rpmRC indexPrefixGet(dbiIndex dbi, const char *pfx, size_t plen,
			    dbiIndexSet *set)
{
    rpmRC rc = RPMRC_FAIL; /* assume failure */

    if (dbi != NULL && pfx) {
	dbiCursor dbc = dbiCursorInit(dbi, DBC_READ);

	if (plen == 0)
	    plen = strlen(pfx);
	rc = idxdbGet(dbi, dbc, pfx, plen, set, DBC_PREFIX_SEARCH);

	dbiCursorFree(dbi, dbc);
    }
    return rc;
}


typedef struct miRE_s {
    rpmTagVal		tag;		/*!< header tag */
    rpmMireMode		mode;		/*!< pattern match mode */
    char *		pattern;	/*!< pattern string */
    int			notmatch;	/*!< like "grep -v" */
    regex_t *		preg;		/*!< regex compiled pattern buffer */
    int			cflags;		/*!< regcomp(3) flags */
    int			eflags;		/*!< regexec(3) flags */
    int			fnflags;	/*!< fnmatch(3) flags */
} * miRE;

struct rpmdbMatchIterator_s {
    rpmdbMatchIterator	mi_next;
    rpmdb		mi_db;
    rpmDbiTagVal	mi_rpmtag;
    dbiIndexSet		mi_set;
    dbiCursor		mi_dbc;
    int			mi_setx;
    Header		mi_h;
    int			mi_sorted;
    int			mi_cflags;
    int			mi_modified;
    unsigned int	mi_prevoffset;	/* header instance (native endian) */
    unsigned int	mi_offset;	/* header instance (native endian) */
    unsigned int	mi_filenum;	/* tag element (native endian) */
    int			mi_nre;
    miRE		mi_re;
    rpmts		mi_ts;
    rpmRC (*mi_hdrchk) (rpmts ts, const void * uh, size_t uc, char ** msg);

};

struct rpmdbIndexIterator_s {
    rpmdbIndexIterator	ii_next;
    rpmdb		ii_db;
    dbiIndex		ii_dbi;
    rpmDbiTag		ii_rpmtag;
    dbiCursor		ii_dbc;
    dbiIndexSet		ii_set;
    unsigned int	*ii_hdrNums;
    int			ii_skipdata;
};

rpmop rpmdbOp(rpmdb rpmdb, rpmdbOpX opx)
{
    rpmop op = NULL;
    switch (opx) {
    case RPMDB_OP_DBGET:
	op = &rpmdb->db_getops;
	break;
    case RPMDB_OP_DBPUT:
	op = &rpmdb->db_putops;
	break;
    case RPMDB_OP_DBDEL:
	op = &rpmdb->db_delops;
	break;
    default:
	break;
    }
    return op;
}

const char *rpmdbHome(rpmdb db)
{
    const char *dbdir = NULL;
    if (db) {
	dbdir = rpmChrootDone() ? db->db_home : db->db_fullpath;
    }
    return dbdir;
}

static int doOpen(rpmdb db, int justPkgs)
{
    int rc = pkgdbOpen(db, db->db_flags, NULL);
    if (!justPkgs) {
	for (int dbix = 0; rc == 0 && dbix < db->db_ndbi; dbix++) {
	    rc += indexOpen(db, db->db_tags[dbix], db->db_flags, NULL);
	}
    }
    return rc;
}

int rpmdbOpenAll(rpmdb db)
{
    if (db == NULL) return -2;

    return doOpen(db, 0);
}

static int dbiForeach(dbiIndex *dbis, int ndbi,
		  int (*func) (dbiIndex, unsigned int), int del)
{
    int xx, rc = 0;
    for (int dbix = ndbi; --dbix >= 0; ) {
	if (dbis[dbix] == NULL)
	    continue;
	xx = func(dbis[dbix], 0);
	if (xx && rc == 0) rc = xx;
	if (del)
	    dbis[dbix] = NULL;
    }
    return rc;
}

int rpmdbClose(rpmdb db)
{
    int rc = 0;

    if (db == NULL)
	goto exit;

    (void) rpmdbUnlink(db);

    if (db->nrefs > 0)
	goto exit;

    /* Always re-enable fsync on close of rw-database */
    if ((db->db_mode & O_ACCMODE) != O_RDONLY)
	dbSetFSync(db, 1);

    if (db->db_pkgs)
	rc = dbiClose(db->db_pkgs, 0);
    rc += dbiForeach(db->db_indexes, db->db_ndbi, dbiClose, 1);

    db->db_root = _free(db->db_root);
    db->db_home = _free(db->db_home);
    db->db_fullpath = _free(db->db_fullpath);
    db->db_checked = dbChkFree(db->db_checked);
    db->db_indexes = _free(db->db_indexes);

    db = _free(db);

exit:
    return rc;
}

static rpmdb newRpmdb(const char * root, const char * home,
		      int mode, int perms, int flags)
{
    rpmdb db = NULL;
    char * db_home = rpmGetPath((home && *home) ? home : "%{_dbpath}", NULL);

    static rpmDbiTag const dbiTags[] = {
	RPMDBI_NAME,
	RPMDBI_BASENAMES,
	RPMDBI_GROUP,
	RPMDBI_REQUIRENAME,
	RPMDBI_PROVIDENAME,
	RPMDBI_CONFLICTNAME,
	RPMDBI_OBSOLETENAME,
	RPMDBI_TRIGGERNAME,
	RPMDBI_DIRNAMES,
	RPMDBI_INSTALLTID,
	RPMDBI_SIGMD5,
	RPMDBI_SHA1HEADER,
	RPMDBI_FILETRIGGERNAME,
	RPMDBI_TRANSFILETRIGGERNAME,
	RPMDBI_RECOMMENDNAME,
	RPMDBI_SUGGESTNAME,
	RPMDBI_SUPPLEMENTNAME,
	RPMDBI_ENHANCENAME,
    };

    if (!(db_home && db_home[0] != '%')) {
	rpmlog(RPMLOG_ERR, _("no dbpath has been set\n"));
	free(db_home);
	return NULL;
    }

    db = (rpmdb)xcalloc(sizeof(*db), 1);

    if (!(perms & 0600)) perms = 0644;	/* XXX sanity */

    db->db_mode = (mode >= 0) ? mode : 0;
    db->db_perms = (perms >= 0) ? perms : 0644;
    db->db_flags = (flags >= 0) ? flags : 0;

    db->db_home = db_home;
    db->db_root = rpmGetPath((root && *root) ? root : "/", NULL);
    db->db_fullpath = rpmGenPath(db->db_root, db->db_home, NULL);
    db->db_tags = dbiTags;
    db->db_ndbi = sizeof(dbiTags) / sizeof(rpmDbiTag);
    db->db_indexes = (dbiIndex *)xcalloc(db->db_ndbi, sizeof(*db->db_indexes));
    db->nrefs = 0;
    return rpmdbLink(db);
}

static int openDatabase(const char * prefix,
		const char * dbpath, rpmdb *dbp,
		int mode, int perms, int flags)
{
    rpmdb db;
    int rc;
    int justCheck = flags & RPMDB_FLAG_JUSTCHECK;

    if (dbp)
	*dbp = NULL;
    if ((mode & O_ACCMODE) == O_WRONLY) 
	return 1;

    db = newRpmdb(prefix, dbpath, mode, perms, flags);
    if (db == NULL)
	return 1;

    /* Try to ensure db home exists, error out if we can't even create */
    rc = rpmioMkpath(rpmdbHome(db), 0755, getuid(), getgid());
    if (rc == 0) {
	/* Open just bare minimum when rebuilding a potentially damaged db */
	int justPkgs = (db->db_flags & RPMDB_FLAG_REBUILD) &&
		       ((db->db_mode & O_ACCMODE) == O_RDONLY);
	rc = doOpen(db, justPkgs);

	if (!db->db_descr)
	    db->db_descr = "unknown db";
    }

    if (rc || justCheck || dbp == NULL)
	rpmdbClose(db);
    else {
        *dbp = db;
    }

    return rc;
}

static rpmdb rpmdbUnlink(rpmdb db)
{
    if (db)
	db->nrefs--;
    return NULL;
}

rpmdb rpmdbLink(rpmdb db)
{
    if (db)
	db->nrefs++;
    return db;
}

int rpmdbOpen (const char * prefix, rpmdb *dbp, int mode, int perms)
{
    return openDatabase(prefix, NULL, dbp, mode, perms, 0);
}

int rpmdbInit (const char * prefix, int perms)
{
    rpmdb db = NULL;
    int rc;

    rc = openDatabase(prefix, NULL, &db, (O_CREAT | O_RDWR), perms, 0);
    if (db != NULL) {
	int xx = rpmdbClose(db);
	if (xx && rc == 0) rc = xx;
	db = NULL;
    }
    return rc;
}

int rpmdbVerify(const char * prefix)
{
    rpmdb db = NULL;
    int rc = 0;

    rc = openDatabase(prefix, NULL, &db, O_RDONLY, 0644, RPMDB_FLAG_VERIFYONLY);

    if (db != NULL) {
	int xx;
	
	if (db->db_pkgs)
	    rc += dbiVerify(db->db_pkgs, 0);
	rc += dbiForeach(db->db_indexes, db->db_ndbi, dbiVerify, 0);

	xx = rpmdbClose(db);
	if (xx && rc == 0) rc = xx;
	db = NULL;
    }
    return rc;
}

Header rpmdbGetHeaderAt(rpmdb db, unsigned int offset)
{   
    rpmdbMatchIterator mi = rpmdbInitIterator(db, RPMDBI_PACKAGES,
					      &offset, sizeof(offset));
    Header h = headerLink(rpmdbNextIterator(mi));
    rpmdbFreeIterator(mi);
    return h;
}

/**
 * Find file matches in database.
 * @param db		rpm database
 * @param dbi		index database handle (always RPMDBI_BASENAMES)
 * @param filespec
 * @param usestate	take file state into account?
 * @param[out] matches
 * @return 		RPMRC_OK on match, RPMRC_NOMATCH or RPMRC_FAIL
 */
static rpmRC rpmdbFindByFile(rpmdb db, dbiIndex dbi, const char *filespec,
			   int usestate, dbiIndexSet * matches)
{
    char * dirName = NULL;
    const char * baseName;
    fingerPrintCache fpc = NULL;
    fingerPrint * fp1 = NULL;
    dbiIndexSet allMatches = NULL;
    unsigned int i;
    rpmRC rc = RPMRC_FAIL; /* assume error */

    *matches = NULL;
    if (filespec == NULL) return rc; /* nothing alloced yet */

    if ((baseName = strrchr(filespec, '/')) != NULL) {
	size_t len = baseName - filespec + 1;
	dirName = rstrndup(filespec, len);
	baseName++;
    } else {
	dirName = xstrdup("");
	baseName = filespec;
    }
    if (baseName == NULL)
	goto exit;

    rc = indexGet(dbi, baseName, 0, &allMatches);

    if (rc || allMatches == NULL) goto exit;

    *matches = dbiIndexSetNew(0);
    fpc = fpCacheCreate(allMatches->count, NULL);
    fpLookup(fpc, dirName, baseName, &fp1);

    i = 0;
    while (i < allMatches->count) {
	struct rpmtd_s bn, dn, di, fs;
	const char ** baseNames, ** dirNames;
	const uint32_t * dirIndexes;
	unsigned int offset = dbiIndexRecordOffset(allMatches, i);
	unsigned int prevoff;
	Header h = rpmdbGetHeaderAt(db, offset);

	if (h == NULL) {
	    i++;
	    continue;
	}

	headerGet(h, RPMTAG_BASENAMES, &bn, HEADERGET_MINMEM);
	headerGet(h, RPMTAG_DIRNAMES, &dn, HEADERGET_MINMEM);
	headerGet(h, RPMTAG_DIRINDEXES, &di, HEADERGET_MINMEM);
	baseNames = (const char **)bn.data;
	dirNames = (const char **)dn.data;
	dirIndexes = (const uint32_t *)di.data;
	if (usestate)
	    headerGet(h, RPMTAG_FILESTATES, &fs, HEADERGET_MINMEM);

	do {
	    unsigned int num = dbiIndexRecordFileNumber(allMatches, i);
	    int skip = 0;

	    if (usestate) {
		rpmtdSetIndex(&fs, num);
		if (!RPMFILE_IS_INSTALLED(rpmtdGetNumber(&fs))) {
		    skip = 1;
		}
	    }

	    if (!skip) {
		const char *dirName = dirNames[dirIndexes[num]];
		if (fpLookupEquals(fpc, fp1, dirName, baseNames[num])) {
		    dbiIndexSetAppendOne(*matches, dbiIndexRecordOffset(allMatches, i),
					 dbiIndexRecordFileNumber(allMatches, i), 0);
		}
	    }

	    prevoff = offset;
	    i++;
	    if (i < allMatches->count)
		offset = dbiIndexRecordOffset(allMatches, i);
	} while (i < allMatches->count && offset == prevoff);

	rpmtdFreeData(&bn);
	rpmtdFreeData(&dn);
	rpmtdFreeData(&di);
	if (usestate)
	    rpmtdFreeData(&fs);
	headerFree(h);
    }

    free(fp1);
    fpCacheFree(fpc);

    if ((*matches)->count == 0) {
	*matches = dbiIndexSetFree(*matches);
	rc = RPMRC_NOTFOUND;
    } else {
	rc = RPMRC_OK;
    }

exit:
    dbiIndexSetFree(allMatches);
    free(dirName);
    return rc;
}

int rpmdbCountPackages(rpmdb db, const char * name)
{
    int count = -1;
    dbiIndex dbi = NULL;

    if (name != NULL && indexOpen(db, RPMDBI_NAME, 0, &dbi) == 0) {
	dbiIndexSet matches = NULL;

	rpmRC rc = indexGet(dbi, name, strlen(name), &matches);

	if (rc == RPMRC_OK) {
	    count = dbiIndexSetCount(matches);
	} else {
	    count = (rc == RPMRC_NOTFOUND) ? 0 : -1;
	}
	dbiIndexSetFree(matches);
    }

    return count;
}

/**
 * Attempt partial matches on name[-version[-release]][.arch] strings.
 * @param db		rpmdb handle
 * @param dbi		index database
 * @param name		package name
 * @param epoch 	package epoch (-1 for any epoch)
 * @param version	package version (can be a pattern)
 * @param release	package release (can be a pattern)
 * @param arch		package arch (can be a pattern)
 * @param[out] matches	set of header instances that match
 * @return 		RPMRC_OK on match, RPMRC_NOMATCH or RPMRC_FAIL
 */
static rpmRC dbiFindMatches(rpmdb db, dbiIndex dbi,
		const char * name,
		int64_t epoch,
		const char * version,
		const char * release,
		const char * arch,
		dbiIndexSet * matches)
{
    unsigned int gotMatches = 0;
    rpmRC rc;
    unsigned int i;

    rc = indexGet(dbi, name, strlen(name), matches);

    /* No matches on the name, anything else wont match either */
    if (rc != RPMRC_OK)
	goto exit;
    
    /* If we got matches on name and nothing else was specified, we're done */
    if (epoch < 0 && version == NULL && release == NULL && arch == NULL)
	goto exit;

    /* Make sure the version and release match. */
    for (i = 0; i < dbiIndexSetCount(*matches); i++) {
	unsigned int recoff = dbiIndexRecordOffset(*matches, i);
	rpmdbMatchIterator mi;
	Header h;

	if (recoff == 0)
	    continue;

	mi = rpmdbInitIterator(db, RPMDBI_PACKAGES, &recoff, sizeof(recoff));

	/* Set iterator selectors for version/release if available. */
	if (version &&
	    rpmdbSetIteratorRE(mi, RPMTAG_VERSION, RPMMIRE_DEFAULT, version))
	{
	    rc = RPMRC_FAIL;
	    goto exit;
	}
	if (release &&
	    rpmdbSetIteratorRE(mi, RPMTAG_RELEASE, RPMMIRE_DEFAULT, release))
	{
	    rc = RPMRC_FAIL;
	    goto exit;
	}
	if (arch &&
	    rpmdbSetIteratorRE(mi, RPMTAG_ARCH, RPMMIRE_DEFAULT, arch))
	{
	    rc = RPMRC_FAIL;
	    goto exit;
	}

	h = rpmdbNextIterator(mi);

	if (epoch >= 0 && h) {
	    struct rpmtd_s td;
	    headerGet(h, RPMTAG_EPOCH, &td, HEADERGET_MINMEM);
	    if (epoch != rpmtdGetNumber(&td))
		h = NULL;
	    rpmtdFreeData(&td);
	}
	if (h)
	    (*matches)->recs[gotMatches++] = (*matches)->recs[i];
	else
	    (*matches)->recs[i].hdrNum = 0;
	rpmdbFreeIterator(mi);
    }

    if (gotMatches) {
	(*matches)->count = gotMatches;
	rc = RPMRC_OK;
    } else
	rc = RPMRC_NOTFOUND;

exit:
/* FIX: double indirection */
    if (rc && matches && *matches)
	*matches = dbiIndexSetFree(*matches);
    return rc;
}

/**
 * Lookup by name, name-version, and finally by name-version-release.
 * Both version and release can be patterns.
 * @todo Name must be an exact match, as name is a db key.
 * @param db		rpmdb handle
 * @param dbi		index database handle (always RPMDBI_NAME)
 * @param arg		name[-[epoch:]version[-release]] string
 * @param arglen	length of arg
 * @param arch		possible arch string (or NULL)
 * @param[out] matches	set of header instances that match
 * @return 		RPMRC_OK on match, RPMRC_NOMATCH or RPMRC_FAIL
 */
static rpmRC dbiFindByLabelArch(rpmdb db, dbiIndex dbi,
			    const char * arg, size_t arglen, const char *arch,
			    dbiIndexSet * matches)
{
    char localarg[arglen+1];
    int64_t epoch;
    const char * version;
    const char * release;
    char * s;
    char c;
    int brackets;
    rpmRC rc;

    if (arglen == 0) return RPMRC_NOTFOUND;

    strncpy(localarg, arg, arglen);
    localarg[arglen] = '\0';

    /* did they give us just a name? */
    rc = dbiFindMatches(db, dbi, localarg, -1, NULL, NULL, arch, matches);
    if (rc != RPMRC_NOTFOUND)
	goto exit;

    /* FIX: double indirection */
    *matches = dbiIndexSetFree(*matches);

    /* maybe a name-[epoch:]version ? */
    s = localarg + arglen;

    c = '\0';
    brackets = 0;
    for (s -= 1; s > localarg; s--) {
	switch (*s) {
	case '[':
	    brackets = 1;
	    break;
	case ']':
	    if (c != '[') brackets = 0;
	    break;
	}
	if (!brackets && c && *s == '-')
	    break;
	c = *s;
    }

   	/* FIX: *matches may be NULL. */
    if (s == localarg) {
	rc = RPMRC_NOTFOUND;
	goto exit;
    }

    *s = '\0';

    epoch = splitEpoch(s + 1, &version);
    rc = dbiFindMatches(db, dbi, localarg, epoch, version, NULL, arch, matches);
    if (rc != RPMRC_NOTFOUND) goto exit;

    /* FIX: double indirection */
    *matches = dbiIndexSetFree(*matches);

    /* how about name-[epoch:]version-release? */

    release = s + 1;

    c = '\0';
    brackets = 0;
    for (; s > localarg; s--) {
	switch (*s) {
	case '[':
	    brackets = 1;
	    break;
	case ']':
	    if (c != '[') brackets = 0;
	    break;
	}
	if (!brackets && c && *s == '-')
	    break;
	c = *s;
    }

    if (s == localarg) {
	rc = RPMRC_NOTFOUND;
	goto exit;
    }

    *s = '\0';
   	/* FIX: *matches may be NULL. */
    epoch = splitEpoch(s + 1, &version);
    rc = dbiFindMatches(db, dbi, localarg, epoch, version, release, arch, matches);
exit:
    return rc;
}

static rpmRC dbiFindByLabel(rpmdb db, dbiIndex dbi, const char * label,
			    dbiIndexSet * matches)
{
    const char *arch = NULL;
    /* First, try with label as it is */
    rpmRC rc = dbiFindByLabelArch(db, dbi, label, strlen(label), NULL, matches);

    /* If not found, retry with possible .arch specifier if there is one */
    if (rc == RPMRC_NOTFOUND && (arch = strrchr(label, '.')))
	rc = dbiFindByLabelArch(db, dbi, label, arch-label, arch+1, matches);

    return rc;
}

/**
 * Rewrite a header into packages (if necessary) and free the header.
 *   Note: this is called from a markReplacedFiles iteration, and *must*
 *   preserve the "join key" (i.e. offset) for the header.
 * @param mi		database iterator
 * @param dbi		index database handle
 * @return 		0 on success
 */
static int miFreeHeader(rpmdbMatchIterator mi, dbiIndex dbi)
{
    int rc = 0;

    if (mi == NULL || mi->mi_h == NULL)
	return 0;

    if (dbi && mi->mi_dbc && mi->mi_modified && mi->mi_prevoffset) {
	rpmRC rpmrc = RPMRC_NOTFOUND;
	unsigned int hdrLen = 0;
	uint8_t *hdrBlob = (uint8_t *)headerExport(mi->mi_h, &hdrLen);

	/* Check header digest/signature on blob export (if requested). */
	if (mi->mi_hdrchk && mi->mi_ts) {
	    char * msg = NULL;
	    int lvl;

	    rpmrc = (*mi->mi_hdrchk) (mi->mi_ts, hdrBlob, hdrLen, &msg);
	    lvl = (rpmrc == RPMRC_FAIL ? RPMLOG_ERR : RPMLOG_DEBUG);
	    rpmlog(lvl, "%s h#%8u %s",
		(rpmrc == RPMRC_FAIL ? _("miFreeHeader: skipping") : "write"),
			mi->mi_prevoffset, (msg ? msg : "\n"));
	    msg = _free(msg);
	}

	if (hdrBlob != NULL && rpmrc != RPMRC_FAIL) {
	    rpmsqBlock(SIG_BLOCK);
	    dbCtrl(mi->mi_db, DB_CTRL_LOCK_RW);
	    rc = pkgdbPut(dbi, mi->mi_dbc, &mi->mi_prevoffset,
			  hdrBlob, hdrLen);
	    dbCtrl(mi->mi_db, DB_CTRL_INDEXSYNC);
	    dbCtrl(mi->mi_db, DB_CTRL_UNLOCK_RW);
	    rpmsqBlock(SIG_UNBLOCK);

	    if (rc) {
		rpmlog(RPMLOG_ERR,
			_("error(%d) storing record #%d into %s\n"),
			rc, mi->mi_prevoffset, dbiName(dbi));
	    }
	}
	free(hdrBlob);
    }

    mi->mi_h = headerFree(mi->mi_h);

    return rc;
}

rpmdbMatchIterator rpmdbFreeIterator(rpmdbMatchIterator mi)
{
    dbiIndex dbi = NULL;
    int i;

    if (mi == NULL)
	return NULL;

    pkgdbOpen(mi->mi_db, 0, &dbi);

    miFreeHeader(mi, dbi);

    mi->mi_dbc = dbiCursorFree(dbi, mi->mi_dbc);

    if (mi->mi_re != NULL)
    for (i = 0; i < mi->mi_nre; i++) {
	miRE mire = mi->mi_re + i;
	mire->pattern = _free(mire->pattern);
	if (mire->preg != NULL) {
	    regfree(mire->preg);
	    mire->preg = _free(mire->preg);
	}
    }
    mi->mi_re = _free(mi->mi_re);

    mi->mi_set = dbiIndexSetFree(mi->mi_set);
    rpmdbClose(mi->mi_db);
    mi->mi_ts = rpmtsFree(mi->mi_ts);

    mi = _free(mi);

    return NULL;
}

unsigned int rpmdbGetIteratorOffset(rpmdbMatchIterator mi)
{
    return (mi ? mi->mi_offset : 0);
}

unsigned int rpmdbGetIteratorFileNum(rpmdbMatchIterator mi)
{
    return (mi ? mi->mi_filenum : 0);
}

int rpmdbGetIteratorCount(rpmdbMatchIterator mi)
{
    return (mi && mi->mi_set ?  mi->mi_set->count : 0);
}

int rpmdbGetIteratorIndex(rpmdbMatchIterator mi)
{
    return (mi ? mi->mi_setx : 0);
}

void rpmdbSetIteratorIndex(rpmdbMatchIterator mi, unsigned int ix)
{
    if (mi)
	mi->mi_setx = ix;
}

unsigned int rpmdbGetIteratorOffsetFor(rpmdbMatchIterator mi, unsigned int ix)
{
    if (mi && mi->mi_set && ix < mi->mi_set->count)
	return mi->mi_set->recs[ix].hdrNum;
    return 0;
}

/**
 * Return pattern match.
 * @param mire		match iterator regex
 * @param val		value to match
 * @return		0 if pattern matches, >0 on nomatch, <0 on error
 */
static int miregexec(miRE mire, const char * val)
{
    int rc = 0;

    switch (mire->mode) {
    case RPMMIRE_STRCMP:
	rc = (!rstreq(mire->pattern, val));
	break;
    case RPMMIRE_DEFAULT:
    case RPMMIRE_REGEX:
	rc = regexec(mire->preg, val, 0, NULL, mire->eflags);
	if (rc && rc != REG_NOMATCH) {
	    char msg[256];
	    (void) regerror(rc, mire->preg, msg, sizeof(msg)-1);
	    msg[sizeof(msg)-1] = '\0';
	    rpmlog(RPMLOG_ERR, _("%s: regexec failed: %s\n"),
			mire->pattern, msg);
	    rc = -1;
	}
	break;
    case RPMMIRE_GLOB:
	rc = fnmatch(mire->pattern, val, mire->fnflags);
	if (rc && rc != FNM_NOMATCH)
	    rc = -1;
	break;
    default:
	rc = -1;
	break;
    }

    return rc;
}

/**
 * Compare iterator selectors by rpm tag (qsort/bsearch).
 * @param a		1st iterator selector
 * @param b		2nd iterator selector
 * @return		result of comparison
 */
static int mireCmp(const void * a, const void * b)
{
    const miRE mireA = (const miRE) a;
    const miRE mireB = (const miRE) b;
    return (mireA->tag - mireB->tag);
}

/**
 * Copy pattern, escaping for appropriate mode.
 * @param tag		rpm tag
 * @param[out] modep	type of pattern match
 * @param pattern	pattern to duplicate
 * @return		duplicated pattern
 */
static char * mireDup(rpmTagVal tag, rpmMireMode *modep,
			const char * pattern)
{
    const char * s;
    char * pat;
    char * t;
    int brackets;
    size_t nb;
    int c;

    switch (*modep) {
    default:
    case RPMMIRE_DEFAULT:
	if (tag == RPMTAG_DIRNAMES || tag == RPMTAG_BASENAMES) {
	    *modep = RPMMIRE_GLOB;
	    pat = xstrdup(pattern);
	    break;
	}

	nb = strlen(pattern) + sizeof("^$");

	/* Find no. of bytes needed for pattern. */
	/* periods, plusses and carets are escaped, splats become '.*' */
	c = '\0';
	brackets = 0;
	for (s = pattern; *s != '\0'; s++) {
	    switch (*s) {
	    case '.':
	    case '+':
	    case '*':
	    case '^':
		if (!brackets) nb++;
		break;
	    case '\\':
		s++;
		break;
	    case '[':
		brackets = 1;
		break;
	    case ']':
		if (c != '[') brackets = 0;
		break;
	    }
	    c = *s;
	}

	pat = t = (char *)xmalloc(nb);

	if (pattern[0] != '^') *t++ = '^';

	/* Copy pattern, escaping periods, plusses and carets, and prefixing splats with period. */
	c = '\0';
	brackets = 0;
	for (s = pattern; *s != '\0'; s++, t++) {
	    switch (*s) {
	    case '.':
	    case '+':
	    case '^':
		if (!brackets) *t++ = '\\';
		break;
	    case '*':
		if (!brackets) *t++ = '.';
		break;
	    case '\\':
		*t++ = *s++;
		break;
	    case '[':
		brackets = 1;
		break;
	    case ']':
		if (c != '[') brackets = 0;
		break;
	    }
	    c = *t = *s;
	}

	if (s > pattern && s[-1] != '$') *t++ = '$';
	*t = '\0';
	*modep = RPMMIRE_REGEX;
	break;
    case RPMMIRE_STRCMP:
    case RPMMIRE_REGEX:
    case RPMMIRE_GLOB:
	pat = xstrdup(pattern);
	break;
    }

    return pat;
}

int rpmdbSetIteratorRE(rpmdbMatchIterator mi, rpmTagVal tag,
		rpmMireMode mode, const char * pattern)
{
    miRE mire = NULL;
    char * allpat = NULL;
    int notmatch = 0;
    regex_t * preg = NULL;
    int cflags = 0;
    int eflags = 0;
    int fnflags = 0;
    int rc = 0;

    /* Handle missing epoch, see mireSkip() */
    if (tag == RPMTAG_EPOCH && pattern == NULL)
	pattern = "0";

    if (mi == NULL || pattern == NULL)
	return rc;

    /* Leading '!' inverts pattern match sense, like "grep -v". */
    if (*pattern == '!') {
	notmatch = 1;
	pattern++;
    }

    allpat = mireDup(tag, &mode, pattern);

    switch (mode) {
    case RPMMIRE_DEFAULT:
    case RPMMIRE_STRCMP:
	break;
    case RPMMIRE_REGEX:
	preg = (regex_t *)xcalloc(1, sizeof(*preg));
	cflags = (REG_EXTENDED | REG_NOSUB);
	rc = regcomp(preg, allpat, cflags);
	if (rc) {
	    char msg[256];
	    (void) regerror(rc, preg, msg, sizeof(msg)-1);
	    msg[sizeof(msg)-1] = '\0';
	    rpmlog(RPMLOG_ERR, _("%s: regcomp failed: %s\n"), allpat, msg);
	}
	break;
    case RPMMIRE_GLOB:
	fnflags = FNM_PATHNAME | FNM_PERIOD;
	break;
    default:
	rc = -1;
	break;
    }

    if (rc) {
	/* FIX: mire has kept values */
	allpat = _free(allpat);
	if (preg) {
	    regfree(preg);
	    preg = _free(preg);
	}
	return rc;
    }

    mi->mi_re = xrealloc(mi->mi_re, (mi->mi_nre + 1) * sizeof(*mi->mi_re));
    mire = mi->mi_re + mi->mi_nre;
    mi->mi_nre++;
    
    mire->tag = tag;
    mire->mode = mode;
    mire->pattern = allpat;
    mire->notmatch = notmatch;
    mire->preg = preg;
    mire->cflags = cflags;
    mire->eflags = eflags;
    mire->fnflags = fnflags;

    if (mi->mi_nre > 1)
	qsort(mi->mi_re, mi->mi_nre, sizeof(*mi->mi_re), mireCmp);

    return rc;
}

/**
 * Return iterator selector match.
 * @param mi		rpm database iterator
 * @return		1 if header should be skipped
 */
static int mireSkip (const rpmdbMatchIterator mi)
{
    miRE mire;
    uint32_t zero = 0;
    int ntags = 0;
    int nmatches = 0;
    int rc;

    if (mi->mi_h == NULL)	/* XXX can't happen */
	return 0;

    /*
     * Apply tag tests, implicitly "||" for multiple patterns/values of a
     * single tag, implicitly "&&" between multiple tag patterns.
     */
    if ((mire = mi->mi_re) != NULL)
    for (int i = 0; i < mi->mi_nre; i++, mire++) {
	int anymatch;
	struct rpmtd_s td;

	if (!headerGet(mi->mi_h, mire->tag, &td, HEADERGET_MINMEM)) {
	    if (mire->tag != RPMTAG_EPOCH) {
		ntags++;
		continue;
	    }
	    /* "is package already installed" checks rely on this behavior */
	    td.count = 1;
	    td.type = RPM_INT32_TYPE;
	    td.data = &zero;
	}

	anymatch = 0;		/* no matches yet */
	while (1) {
	    rpmtdInit(&td);
	    while (rpmtdNext(&td) >= 0) {
	    	char *str = rpmtdFormat(&td, RPMTD_FORMAT_STRING, NULL);
		if (str) {
		    rc = miregexec(mire, str);
		    if ((!rc && !mire->notmatch) || (rc && mire->notmatch))
			anymatch++;
		    free(str);
		}
	    }
	    if ((i+1) < mi->mi_nre && mire[0].tag == mire[1].tag) {
		i++;
		mire++;
		continue;
	    }
	    break;
	}
	rpmtdFreeData(&td);

	ntags++;
	if (anymatch)
	    nmatches++;
    }

    return (ntags == nmatches ? 0 : 1);
}

int rpmdbSetIteratorRewrite(rpmdbMatchIterator mi, int rewrite)
{
    int rc;
    if (mi == NULL)
	return 0;
    rc = (mi->mi_cflags & DBC_WRITE) ? 1 : 0;
    if (rewrite)
	mi->mi_cflags |= DBC_WRITE;
    else
	mi->mi_cflags &= ~DBC_WRITE;
    return rc;
}

int rpmdbSetIteratorModified(rpmdbMatchIterator mi, int modified)
{
    int rc;
    if (mi == NULL)
	return 0;
    rc = mi->mi_modified;
    mi->mi_modified = modified;
    return rc;
}

int rpmdbSetHdrChk(rpmdbMatchIterator mi, rpmts ts,
	rpmRC (*hdrchk) (rpmts ts, const void *uh, size_t uc, char ** msg))
{
    int rc = 0;
    if (mi == NULL)
	return 0;
    mi->mi_ts = rpmtsLink(ts);
    mi->mi_hdrchk = hdrchk;
    return rc;
}

static rpmRC miVerifyHeader(rpmdbMatchIterator mi, const void *uh, size_t uhlen)
{
    rpmRC rpmrc = RPMRC_NOTFOUND;

    if (!(mi->mi_hdrchk && mi->mi_ts))
	return rpmrc;

    /* Don't bother re-checking a previously read header. */
    if (mi->mi_db->db_checked) {
	rpmRC *res;
	if (dbChkGetEntry(mi->mi_db->db_checked, mi->mi_offset,
			  &res, NULL, NULL)) {
	    rpmrc = res[0];
	}
    }

    /* If blob is unchecked, check blob import consistency now. */
    if (rpmrc != RPMRC_OK) {
	char * msg = NULL;
	int lvl;

	rpmrc = (*mi->mi_hdrchk) (mi->mi_ts, uh, uhlen, &msg);
	lvl = (rpmrc == RPMRC_FAIL ? RPMLOG_ERR : RPMLOG_DEBUG);
	rpmlog(lvl, "%s h#%8u %s\n",
	    (rpmrc == RPMRC_FAIL ? _("rpmdbNextIterator: skipping") : " read"),
		    mi->mi_offset, (msg ? msg : ""));
	msg = _free(msg);

	/* Mark header checked. */
	if (mi->mi_db && mi->mi_db->db_checked) {
	    dbChkAddEntry(mi->mi_db->db_checked, mi->mi_offset, rpmrc);
	}
    }
    return rpmrc;
}

/* FIX: mi->mi_key.data may be NULL */
Header rpmdbNextIterator(rpmdbMatchIterator mi)
{
    dbiIndex dbi = NULL;
    unsigned char * uh;
    unsigned int uhlen;
    int rc;
    headerImportFlags importFlags = HEADERIMPORT_FAST;

    if (mi == NULL)
	return NULL;

    if (pkgdbOpen(mi->mi_db, 0, &dbi))
	return NULL;

#if defined(_USE_COPY_LOAD)
    importFlags |= HEADERIMPORT_COPY;
#endif
    /*
     * Cursors are per-iterator, not per-dbi, so get a cursor for the
     * iterator on 1st call. If the iteration is to rewrite headers,
     * then the cursor needs to marked with DBC_WRITE as well.
     */
    if (mi->mi_dbc == NULL)
	mi->mi_dbc = dbiCursorInit(dbi, mi->mi_cflags);

top:
    uh = NULL;
    uhlen = 0;

    do {
	if (mi->mi_set) {
	    if (!(mi->mi_setx < mi->mi_set->count))
		return NULL;
	    mi->mi_offset = dbiIndexRecordOffset(mi->mi_set, mi->mi_setx);
	    mi->mi_filenum = dbiIndexRecordFileNumber(mi->mi_set, mi->mi_setx);
	} else {
	    rc = pkgdbGet(dbi, mi->mi_dbc, 0, &uh, &uhlen);
	    if (rc == 0)
		mi->mi_offset = pkgdbKey(dbi, mi->mi_dbc);

	    /* Terminate on error or end of keys */
	    if (rc || (mi->mi_setx && mi->mi_offset == 0))
		return NULL;
	}
	mi->mi_setx++;
    } while (mi->mi_offset == 0);

    /* If next header is identical, return it now. */
    if (mi->mi_prevoffset && mi->mi_offset == mi->mi_prevoffset)
	return mi->mi_h;

    /* Retrieve next header blob for index iterator. */
    if (uh == NULL) {
	rc = pkgdbGet(dbi, mi->mi_dbc, mi->mi_offset, &uh, &uhlen);
	if (rc)
	    return NULL;
    }

    /* Rewrite current header (if necessary) and unlink. */
    miFreeHeader(mi, dbi);

    /* Is this the end of the iteration? */
    if (uh == NULL)
	return NULL;

    /* Verify header if enabled, skip damaged and inconsistent headers */
    if (miVerifyHeader(mi, uh, uhlen) == RPMRC_FAIL) {
	goto top;
    }

    /* Did the header blob load correctly? */
    mi->mi_h = headerImport(uh, uhlen, importFlags);
    if (mi->mi_h == NULL || !headerIsEntry(mi->mi_h, RPMTAG_NAME)) {
	rpmlog(RPMLOG_ERR,
		_("rpmdb: damaged header #%u retrieved -- skipping.\n"),
		mi->mi_offset);
	goto top;
    }

    /*
     * Skip this header if iterator selector (if any) doesn't match.
     */
    if (mireSkip(mi)) {
	goto top;
    }
    headerSetInstance(mi->mi_h, mi->mi_offset);

    mi->mi_prevoffset = mi->mi_offset;
    mi->mi_modified = 0;

    return mi->mi_h;
}

/** \ingroup rpmdb
 * sort the iterator by (recnum, filenum)
 * Return database iterator.
 * @param mi		rpm database iterator
 */
void rpmdbSortIterator(rpmdbMatchIterator mi)
{
    if (mi && mi->mi_set) {
	dbiIndexSetSort(mi->mi_set);
	mi->mi_sorted = 1;
    }
}

void rpmdbUniqIterator(rpmdbMatchIterator mi)
{
    if (mi && mi->mi_set) {
	dbiIndexSetUniq(mi->mi_set, mi->mi_sorted);
    }
}

int rpmdbExtendIterator(rpmdbMatchIterator mi,
			const char* keyp, size_t keylen)
{
    dbiIndex dbi = NULL;
    dbiIndexSet set = NULL;
    int rc = 1; /* assume failure */

    if (mi == NULL || keyp == NULL)
	return rc;

    rc = indexOpen(mi->mi_db, mi->mi_rpmtag, 0, &dbi);

    if (rc == 0 && indexGet(dbi, keyp, keylen, &set) == RPMRC_OK) {
	if (mi->mi_set == NULL) {
	    mi->mi_set = set;
	} else {
	    dbiIndexSetAppendSet(mi->mi_set, set, 0);
	    dbiIndexSetFree(set);
	}
	mi->mi_sorted = 0;
	rc = 0;
    }

    return rc;
}

int rpmdbFilterIterator(rpmdbMatchIterator mi, packageHash hdrNums, int neg)
{
    if (mi == NULL || hdrNums == NULL)
	return 1;

    if (!mi->mi_set)
	return 0;

    if (packageHashNumKeys(hdrNums) == 0) {
	if (!neg)
	    mi->mi_set->count = 0;
	return 0;
    }

    unsigned int from;
    unsigned int to = 0;
    unsigned int num = mi->mi_set->count;
    int cond;

    assert(mi->mi_set->count > 0);

    for (from = 0; from < num; from++) {
	cond = !packageHashHasEntry(hdrNums, mi->mi_set->recs[from].hdrNum);
	cond = neg ? !cond : cond;
	if (cond) {
	    mi->mi_set->count--;
	    continue;
	}
	if (from != to)
	    mi->mi_set->recs[to] = mi->mi_set->recs[from]; /* structure assignment */
	to++;
    }
    return 0;
}

int rpmdbPruneIterator(rpmdbMatchIterator mi, packageHash hdrNums)
{
    if (packageHashNumKeys(hdrNums) <= 0)
	return 1;

    return rpmdbFilterIterator(mi, hdrNums, 1);
}


int rpmdbAppendIterator(rpmdbMatchIterator mi,
			const unsigned int * hdrNums, unsigned int nHdrNums)
{
    if (mi == NULL || hdrNums == NULL || nHdrNums == 0)
	return 1;

    if (mi->mi_set == NULL)
	mi->mi_set = dbiIndexSetNew(nHdrNums);

    for (unsigned int i = 0; i < nHdrNums; i++)
	dbiIndexSetAppendOne(mi->mi_set, hdrNums[i], 0, 0);
    mi->mi_sorted = 0;
    return 0;
}

rpmdbMatchIterator rpmdbNewIterator(rpmdb db, rpmDbiTagVal dbitag)
{
    rpmdbMatchIterator mi = NULL;

    if (dbitag == RPMDBI_PACKAGES) {
	if (pkgdbOpen(db, 0, NULL))
	    return NULL;
    } else {
	if (indexOpen(db, dbitag, 0, NULL))
	    return NULL;
    }

    mi = (rpmdbMatchIterator)xcalloc(1, sizeof(*mi));
    mi->mi_set = NULL;
    mi->mi_db = rpmdbLink(db);
    mi->mi_rpmtag = dbitag;

    mi->mi_dbc = NULL;
    mi->mi_setx = 0;
    mi->mi_h = NULL;
    mi->mi_sorted = 0;
    mi->mi_cflags = 0;
    mi->mi_modified = 0;
    mi->mi_prevoffset = 0;
    mi->mi_offset = 0;
    mi->mi_filenum = 0;
    mi->mi_nre = 0;
    mi->mi_re = NULL;

    mi->mi_ts = NULL;
    mi->mi_hdrchk = NULL;

    return mi;
};

static rpmdbMatchIterator pkgdbIterInit(rpmdb db,
				    const unsigned int * keyp, size_t keylen)
{
    rpmdbMatchIterator mi = NULL;
    rpmDbiTagVal dbtag = RPMDBI_PACKAGES;
    dbiIndex pkgs = NULL;

    /* Require a sane keylen if one is specified */
    if (keyp && keylen != sizeof(*keyp))
	return NULL;

    if (pkgdbOpen(db, 0, &pkgs) == 0) {
	mi = rpmdbNewIterator(db, dbtag);
	if (keyp)
	    rpmdbAppendIterator(mi, keyp, 1);
    }
    return mi;
}

static rpmdbMatchIterator indexIterInit(rpmdb db, rpmDbiTagVal rpmtag,
				        const char *keyp, size_t keylen)
{
    rpmdbMatchIterator mi = NULL;
    rpmDbiTagVal dbtag = rpmtag;
    dbiIndex dbi = NULL;
    dbiIndexSet set = NULL;

    /* Fixup the physical index for our pseudo indexes */
    if (rpmtag == RPMDBI_LABEL) {
	dbtag = RPMDBI_NAME;
    } else if (rpmtag == RPMDBI_INSTFILENAMES) {
	dbtag = RPMDBI_BASENAMES;
    }

    if (indexOpen(db, dbtag, 0, &dbi) == 0) {
	int rc = 0;

        if (keyp) {
            if (rpmtag == RPMDBI_LABEL) {
                rc = dbiFindByLabel(db, dbi, keyp, &set);
            } else if (rpmtag == RPMDBI_BASENAMES) {
                rc = rpmdbFindByFile(db, dbi, keyp, 0, &set);
            } else if (rpmtag == RPMDBI_INSTFILENAMES) {
                rc = rpmdbFindByFile(db, dbi, keyp, 1, &set);
            } else {
		rc = indexGet(dbi, keyp, keylen, &set);
	    }
	} else {
            /* get all entries from index */
	    rc = indexGet(dbi, NULL, 0, &set);
        }

	if (rc)	{	/* error/not found */
	    set = dbiIndexSetFree(set);
	} else {
	    mi = rpmdbNewIterator(db, dbtag);
	    mi->mi_set = set;

	    if (keyp) {
		rpmdbSortIterator(mi);
	    }
	}
    }
    
    return mi;
}

rpmdbMatchIterator rpmdbInitIterator(rpmdb db, rpmDbiTagVal rpmtag,
		const void * keyp, size_t keylen)
{
    rpmdbMatchIterator mi = NULL;

    if (db != NULL) {
	if (rpmtag == RPMDBI_PACKAGES)
	    mi = pkgdbIterInit(db, (unsigned int *)keyp, keylen);
	else
	    mi = indexIterInit(db, rpmtag, (const char *)keyp, keylen);
    }

    return mi;
}

rpmdbMatchIterator rpmdbInitPrefixIterator(rpmdb db, rpmDbiTagVal rpmtag,
					    const char* pfx, size_t plen)
{
    rpmdbMatchIterator mi = NULL;
    dbiIndexSet set = NULL;
    dbiIndex dbi = NULL;
    rpmDbiTagVal dbtag = rpmtag;

    if (!pfx)
	return NULL;

    if (db != NULL && rpmtag != RPMDBI_PACKAGES) {

	if (indexOpen(db, dbtag, 0, &dbi) == 0) {
	    int rc = 0;

	    rc = indexPrefixGet(dbi, pfx, plen, &set);

	    if (rc)	{
		set = dbiIndexSetFree(set);
	    } else {
		mi = rpmdbNewIterator(db, dbtag);
		mi->mi_set = set;
		rpmdbSortIterator(mi);
	    }
	}

    }

    return mi;
}

/*
 * Convert current tag data to db key
 * @param tagdata	Tag data container
 * @param[out] keylen	Length of key
 * @return 		Pointer to key value or NULL to signal skip 
 */
static const void * td2key(rpmtd tagdata, unsigned int *keylen) 
{
    const void * data = NULL;
    unsigned int size = 0;
    const char *str = NULL;

    switch (rpmtdType(tagdata)) {
    case RPM_CHAR_TYPE:
    case RPM_INT8_TYPE:
	size = sizeof(uint8_t);
	data = rpmtdGetChar(tagdata);
	break;
    case RPM_INT16_TYPE:
	size = sizeof(uint16_t);
	data = rpmtdGetUint16(tagdata);
	break;
    case RPM_INT32_TYPE:
	size = sizeof(uint32_t);
	data = rpmtdGetUint32(tagdata);
	break;
    case RPM_INT64_TYPE:
	size = sizeof(uint64_t);
	data = rpmtdGetUint64(tagdata);
	break;
    case RPM_BIN_TYPE:
	size = tagdata->count;
	data = tagdata->data;
	break;
    case RPM_STRING_TYPE:
    case RPM_I18NSTRING_TYPE:
    case RPM_STRING_ARRAY_TYPE:
	str = rpmtdGetString(tagdata);
	if (str) {
	    size = strlen(str);
	    data = str;
	}
	break;
    default:
	break;
    }

    if (data && keylen)
	*keylen = size;

    return data;
}
/*
 * rpmdbIndexIterator
 */

rpmdbIndexIterator rpmdbIndexIteratorInit(rpmdb db, rpmDbiTag rpmtag)
{
    rpmdbIndexIterator ii;
    dbiIndex dbi = NULL;

    if (db == NULL)
	return NULL;

    if (indexOpen(db, rpmtag, 0, &dbi))
	return NULL;

    ii = (rpmdbIndexIterator)xcalloc(1, sizeof(*ii));
    ii->ii_db = rpmdbLink(db);
    ii->ii_rpmtag = rpmtag;
    ii->ii_dbi = dbi;
    ii->ii_set = NULL;

    return ii;
}

rpmdbIndexIterator rpmdbIndexKeyIteratorInit(rpmdb db, rpmDbiTag rpmtag)
{
    rpmdbIndexIterator ki = rpmdbIndexIteratorInit(db, rpmtag);
    ki->ii_skipdata = 1;
    return ki;
}

int rpmdbIndexIteratorNext(rpmdbIndexIterator ii, const void ** key, size_t * keylen)
{
    int rc;
    unsigned int iikeylen = 0; /* argh, size_t vs uint pointer... */

    if (ii == NULL)
	return -1;

    if (ii->ii_dbc == NULL)
	ii->ii_dbc = dbiCursorInit(ii->ii_dbi, DBC_READ);

    /* free old data */
    ii->ii_set = dbiIndexSetFree(ii->ii_set);

    rc = idxdbGet(ii->ii_dbi, ii->ii_dbc, NULL, 0,
		ii->ii_skipdata ? NULL : &ii->ii_set, DBC_NORMAL_SEARCH);

    *key = idxdbKey(ii->ii_dbi, ii->ii_dbc, &iikeylen);
    *keylen = iikeylen;

    return (rc == RPMRC_OK) ? 0 : -1;
}

int rpmdbIndexIteratorNextTd(rpmdbIndexIterator ii, rpmtd keytd)
{
    size_t keylen = 0;
    const void * keyp = NULL;

    int rc = rpmdbIndexIteratorNext(ii, &keyp, &keylen);

    if (rc == 0) {
	rpmTagVal tag = ii->ii_rpmtag;
	rpmTagClass tagclass = rpmTagGetClass(tag);

	/* Set the common values, overridden below as necessary */
	keytd->type = rpmTagGetTagType(tag);
	keytd->tag = tag;
	keytd->flags = RPMTD_ALLOCED;
	keytd->count = 1;

	switch (tagclass) {
	case RPM_STRING_CLASS: {
	    /*
	     * XXX: We never return arrays here, so everything is a
	     * "simple" string. However this can disagree with the
	     * type of the index tag, eg requires are string arrays.
	     */
	    char *key = (char *)memcpy(xmalloc(keylen + 1), keyp, keylen);
	    key[keylen] = '\0';
	    keytd->data = key;
	    keytd->type = RPM_STRING_TYPE;
	    } break;
	case RPM_BINARY_CLASS:
	    /* Binary types abuse count for data length */
	    keytd->count = keylen;
	    /* fallthrough */
	case RPM_NUMERIC_CLASS:
	    keytd->data = (char *)memcpy(xmalloc(keylen), keyp, keylen);
	    break;
	default:
	    rpmtdReset(keytd);
	    rc = -1;
	    break;
	}
    }
    
    return rc;
}

unsigned int rpmdbIndexIteratorNumPkgs(rpmdbIndexIterator ii)
{
    return (ii && ii->ii_set) ? dbiIndexSetCount(ii->ii_set) : 0;
}

unsigned int rpmdbIndexIteratorPkgOffset(rpmdbIndexIterator ii, unsigned int nr)
{
    if (!ii || !ii->ii_set)
        return 0;
    if (dbiIndexSetCount(ii->ii_set) <= nr)
        return 0;
    return dbiIndexRecordOffset(ii->ii_set, nr);
}

const unsigned int *rpmdbIndexIteratorPkgOffsets(rpmdbIndexIterator ii)
{
    int i;

    if (!ii || !ii->ii_set)
	return NULL;

    if (ii->ii_hdrNums)
	ii->ii_hdrNums = _free(ii->ii_hdrNums);

    ii->ii_hdrNums = (unsigned int *)xmalloc(sizeof(*ii->ii_hdrNums) * ii->ii_set->count);
    for (i = 0; i < ii->ii_set->count; i++) {
	ii->ii_hdrNums[i] = ii->ii_set->recs[i].hdrNum;
    }

    return ii->ii_hdrNums;
}

unsigned int rpmdbIndexIteratorTagNum(rpmdbIndexIterator ii, unsigned int nr)
{
    if (!ii || !ii->ii_set)
        return 0;
    if (dbiIndexSetCount(ii->ii_set) <= nr)
        return 0;
    return dbiIndexRecordFileNumber(ii->ii_set, nr);
}

rpmdbIndexIterator rpmdbIndexIteratorFree(rpmdbIndexIterator ii)
{
    if (ii == NULL)
        return NULL;

    ii->ii_dbc = dbiCursorFree(ii->ii_dbi, ii->ii_dbc);
    ii->ii_dbi = NULL;
    rpmdbClose(ii->ii_db);
    ii->ii_set = dbiIndexSetFree(ii->ii_set);

    if (ii->ii_hdrNums)
	ii->ii_hdrNums = _free(ii->ii_hdrNums);

    ii = _free(ii);
    return NULL;
}

static void logAddRemove(const char *dbiname, int removing, rpmtd tagdata)
{
    rpm_count_t c = rpmtdCount(tagdata);
    if (c == 1 && rpmtdType(tagdata) == RPM_STRING_TYPE) {
	rpmlog(RPMLOG_DEBUG, "%s \"%s\" %s %s index.\n",
		removing ? "removing" : "adding", rpmtdGetString(tagdata), 
		removing ? "from" : "to", dbiname);
    } else if (c > 0) {
	rpmlog(RPMLOG_DEBUG, "%s %d entries %s %s index.\n",
		removing ? "removing" : "adding", c, 
		removing ? "from" : "to", dbiname);
    }
}

int rpmdbRemove(rpmdb db, unsigned int hdrNum)
{
    dbiIndex dbi = NULL;
    dbiCursor dbc = NULL;
    Header h;
    int ret = 0;

    if (db == NULL)
	return 0;

    h = rpmdbGetHeaderAt(db, hdrNum);

    if (h == NULL) {
	rpmlog(RPMLOG_ERR, _("%s: cannot read header at 0x%x\n"),
	      "rpmdbRemove", hdrNum);
	return 1;
    } else {
	char *nevra = headerGetAsString(h, RPMTAG_NEVRA);
	rpmlog(RPMLOG_DEBUG, "  --- h#%8u %s\n", hdrNum, nevra);
	free(nevra);
    }

    if (pkgdbOpen(db, 0, &dbi))
	return 1;

    rpmsqBlock(SIG_BLOCK);
    dbCtrl(db, DB_CTRL_LOCK_RW);

    /* Remove header from primary index */
    dbc = dbiCursorInit(dbi, DBC_WRITE);
    ret = pkgdbDel(dbi, dbc, hdrNum);
    dbiCursorFree(dbi, dbc);

    /* Remove associated data from secondary indexes */
    if (ret == 0) {
	for (int dbix = 0; dbix < db->db_ndbi; dbix++) {
	    rpmDbiTag rpmtag = db->db_tags[dbix];

	    if (indexOpen(db, rpmtag, 0, &dbi))
		continue;

	    ret += idxdbDel(dbi, rpmtag, hdrNum, h);
	}
    }

    dbCtrl(db, DB_CTRL_INDEXSYNC);
    dbCtrl(db, DB_CTRL_UNLOCK_RW);
    rpmsqBlock(SIG_UNBLOCK);

    headerFree(h);

    /* XXX return ret; */
    return 0;
}

struct updateRichDepData {
    ARGV_t argv;
    int nargv;
    int neg;
    int level;
    int *nargv_level;
};

static rpmRC updateRichDepCB(void *cbdata, rpmrichParseType type,
		const char *n, int nl, const char *e, int el, rpmsenseFlags sense,
		rpmrichOp op, char **emsg) {
    struct updateRichDepData *data = (struct updateRichDepData *)cbdata;
    if (type == RPMRICH_PARSE_ENTER) {
	data->level++;
	data->nargv_level = xrealloc(data->nargv_level, data->level * (sizeof(int)));
	data->nargv_level[data->level - 1] = data->nargv;
    }
    if (type == RPMRICH_PARSE_LEAVE) {
	data->level--;
    }
    if (type == RPMRICH_PARSE_SIMPLE && nl && !(nl > 7 && !strncmp(n, "rpmlib(", 7))) {
	char *name = (char *)xmalloc(nl + 2);
	*name = data->neg ? '!' : ' ';
	strncpy(name + 1, n, nl);
	name[1 + nl] = 0;
	argvAdd(&data->argv, name);
	data->nargv++;
	_free(name);
    }
    if (type == RPMRICH_PARSE_OP && (op == RPMRICHOP_IF || op == RPMRICHOP_UNLESS)) {
	/* save nargv in case of ELSE */
	data->nargv_level[data->level - 1] = data->nargv;
	data->neg ^= 1;
    }
    if (type == RPMRICH_PARSE_OP && op == RPMRICHOP_ELSE) {
	int i, nargv = data->nargv;
	/* copy and invert condition block */
	for (i = data->nargv_level[data->level - 1]; i < nargv; i++) {
	    char *name = data->argv[i];
	    *name ^= ' ' ^ '!';
	    argvAdd(&data->argv, name);
	    *name ^= ' ' ^ '!';
	    data->nargv++;
	}
	data->neg ^= 1;
    }
    if (type == RPMRICH_PARSE_LEAVE && (op == RPMRICHOP_IF || op == RPMRICHOP_UNLESS)) {
	data->neg ^= 1;
    }
    return RPMRC_OK;
}

static int updateRichDep(dbiIndex dbi, dbiCursor dbc, const char *str,
                           struct dbiIndexItem_s *rec,
                           idxfunc idxupdate)
{
    int n, i, rc = 0;
    struct updateRichDepData data;

    data.argv = argvNew();
    data.neg = 0;
    data.nargv = 0;
    data.level = 0;
    data.nargv_level = (int *)xcalloc(1, sizeof(int));
    if (rpmrichParse(&str, NULL, updateRichDepCB, &data) == RPMRC_OK) {
	n = argvCount(data.argv);
	if (n) {
	    argvSort(data.argv, NULL);
	    for (i = 0; i < n; i++) {
		char *name = data.argv[i];
		if (i && !strcmp(data.argv[i - 1], name))
		    continue;       /* ignore dups */
		if (*name == ' ')
		    name++;
		rc += idxupdate(dbi, dbc, name, strlen(name), rec);
	    }
	}
    }
    _free(data.nargv_level);
    argvFree(data.argv);
    return rc;
}

rpmRC tag2index(dbiIndex dbi, rpmTagVal rpmtag,
		       unsigned int hdrNum, Header h,
		       idxfunc idxupdate)
{
    int i, rc = 0;
    struct rpmtd_s tagdata, reqflags, trig_index;
    dbiCursor dbc = NULL;

    switch (rpmtag) {
    case RPMTAG_REQUIRENAME:
	headerGet(h, RPMTAG_REQUIREFLAGS, &reqflags, HEADERGET_MINMEM);
	break;
    case RPMTAG_FILETRIGGERNAME:
	headerGet(h, RPMTAG_FILETRIGGERINDEX, &trig_index, HEADERGET_MINMEM);
	break;
    case RPMTAG_TRANSFILETRIGGERNAME:
	headerGet(h, RPMTAG_TRANSFILETRIGGERINDEX, &trig_index, HEADERGET_MINMEM);
	break;
    }
    headerGet(h, rpmtag, &tagdata, HEADERGET_MINMEM);

    if (rpmtdCount(&tagdata) == 0) {
	if (rpmtag != RPMTAG_GROUP)
	    goto exit;

	/* XXX preserve legacy behavior */
	tagdata.type = RPM_STRING_TYPE;
	tagdata.data = (const char **) "Unknown";
	tagdata.count = 1;
    }

    dbc = dbiCursorInit(dbi, DBC_WRITE);

    logAddRemove(dbiName(dbi), 0, &tagdata);
    while ((i = rpmtdNext(&tagdata)) >= 0) {
	const void * key = NULL;
	unsigned int keylen = 0;
	int j;
	struct dbiIndexItem_s rec;

	switch (rpmtag) {
	/* Include trigger index in db index for triggers */
	case RPMTAG_FILETRIGGERNAME:
	case RPMTAG_TRANSFILETRIGGERNAME:
	    rec.hdrNum = hdrNum;
	    rec.tagNum = *rpmtdNextUint32(&trig_index);
	    break;

	/* Include the tagNum in the others indices (only files use though) */
	default:
	    rec.hdrNum = hdrNum;
	    rec.tagNum = i;
	    break;
	}

	switch (rpmtag) {
	case RPMTAG_REQUIRENAME: {
	    /* Filter out install prerequisites. */
	    rpm_flag_t *rflag = rpmtdNextUint32(&reqflags);
	    if (rflag && isTransientReq(*rflag))
		continue;
	    break;
	    }
	case RPMTAG_TRIGGERNAME:
	    if (i > 0) {	/* don't add duplicates */
		const char **tnames = (const char **)tagdata.data;
		const char *str = rpmtdGetString(&tagdata);
		for (j = 0; j < i; j++) {
		    if (rstreq(str, tnames[j]))
			break;
		}
		if (j < i)
		    continue;
	    }
	    break;
	default:
	    break;
	}

	if ((key = td2key(&tagdata, &keylen)) == NULL)
	    continue;

	rc += idxupdate(dbi, dbc, (const char *)key, keylen, &rec);

	if (*(char *)key == '(') {
	    switch (rpmtag) {
	    case RPMTAG_REQUIRENAME:
	    case RPMTAG_CONFLICTNAME:
	    case RPMTAG_SUGGESTNAME:
	    case RPMTAG_SUPPLEMENTNAME:
	    case RPMTAG_RECOMMENDNAME:
	    case RPMTAG_ENHANCENAME:
		if (rpmtdType(&tagdata) == RPM_STRING_ARRAY_TYPE) {
		    rc += updateRichDep(dbi, dbc, rpmtdGetString(&tagdata),
			&rec, idxupdate);
		}
	    default:
		break;
	    }
	}
    }

    dbiCursorFree(dbi, dbc);

exit:
    rpmtdFreeData(&tagdata);
    return (rc == 0) ? RPMRC_OK : RPMRC_FAIL;
}

int rpmdbAdd(rpmdb db, Header h)
{
    dbiIndex dbi = NULL;
    dbiCursor dbc = NULL;
    unsigned int hdrNum = 0;
    unsigned int hdrLen = 0;
    uint8_t *hdrBlob = NULL;
    int ret = 0;

    if (db == NULL)
	return 0;

    hdrBlob = (uint8_t *)headerExport(h, &hdrLen);
    if (hdrBlob == NULL || hdrLen == 0) {
	ret = -1;
	goto exit;
    }

    ret = pkgdbOpen(db, 0, &dbi);
    if (ret)
	goto exit;
	
    rpmsqBlock(SIG_BLOCK);
    dbCtrl(db, DB_CTRL_LOCK_RW);

    /* Add header to primary index */
    dbc = dbiCursorInit(dbi, DBC_WRITE);
    ret = pkgdbPut(dbi, dbc, &hdrNum, hdrBlob, hdrLen);
    dbiCursorFree(dbi, dbc);

    /* Add associated data to secondary indexes */
    if (ret == 0) {	
	for (int dbix = 0; dbix < db->db_ndbi; dbix++) {
	    rpmDbiTag rpmtag = db->db_tags[dbix];

	    if (indexOpen(db, rpmtag, 0, &dbi))
		continue;

	    ret += idxdbPut(dbi, rpmtag, hdrNum, h);
	}
    }

    dbCtrl(db, DB_CTRL_INDEXSYNC);
    dbCtrl(db, DB_CTRL_UNLOCK_RW);
    rpmsqBlock(SIG_UNBLOCK);

    /* If everything ok, mark header as installed now */
    if (ret == 0) {
	headerSetInstance(h, hdrNum);
	/* Purge our verification cache on added public keys */
	if (db->db_checked && headerIsEntry(h, RPMTAG_PUBKEYS)) {
	    dbChkEmpty(db->db_checked);
	}
    }

exit:
    free(hdrBlob);

    return ret;
}

static int rpmdbRemoveFiles(char * pattern)
{
    int rc = 0;
    ARGV_t paths = NULL, p;

    if (rpmGlob(pattern, NULL, &paths) == 0) {
	for (p = paths; *p; p++) {
	    rc += unlink(*p);
	}
	argvFree(paths);
    }
    return rc;
}

static int rpmdbRemoveDatabase(const char *dbpath)
{
    int rc = 0; 
    char *pattern;

    pattern = rpmGetPath(dbpath, "/*", NULL);
    rc += rpmdbRemoveFiles(pattern);
    free(pattern);
    pattern = rpmGetPath(dbpath, "/.??*", NULL);
    rc += rpmdbRemoveFiles(pattern);
    free(pattern);
    
    rc += rmdir(dbpath);
    return rc;
}

static int rpmdbMoveDatabase(const char * prefix, const char * srcdbpath,
			     const char * dbpath, const char * tmppath)
{
    int rc = -1;
    int xx;
    char *src = rpmGetPath(prefix, "/", srcdbpath, NULL);
    char *old = rpmGetPath(prefix, "/", tmppath, NULL);
    char *dest = rpmGetPath(prefix, "/", dbpath, NULL);

    char * oldkeys = rpmGetPath(old, "/", "pubkeys", NULL);
    char * destkeys = rpmGetPath(dest, "/", "pubkeys", NULL);

    xx = rename(dest, old);
    if (xx) {
	goto exit;
    }
    xx = rename(src, dest);
    if (xx) {
	rpmlog(RPMLOG_ERR, _("could not move new database in place\n"));
	xx = rename(old, dest);
	if (xx) {
	    rpmlog(RPMLOG_ERR, _("could also not restore old database from %s\n"),
		   old);
	    rpmlog(RPMLOG_ERR, _("replace files in %s with files from %s "
				 "to recover\n"), dest, old);
	}
	goto exit;
    }

    if (access(oldkeys, F_OK ) != -1) {
	xx = rename(oldkeys, destkeys);
	if (xx) {
	    rpmlog(RPMLOG_ERR, _("Could not get public keys from %s\n"), oldkeys);
	    goto exit;
	}
    }

    xx = rpmdbRemoveDatabase(old);
    if (xx) {
	rpmlog(RPMLOG_ERR, _("could not delete old database at %s\n"), old);
    }

    rc = 0;

 exit:
    _free(src);
    _free(old);
    _free(dest);
    _free(oldkeys);
    _free(destkeys);
    return rc;
}

static int rpmdbSetPermissions(char * src, char * dest)
{
    struct dirent *dp;
    DIR *dfd;

    struct stat st;
    int xx, rc = -1;
    char * filepath;
    
    if (stat(dest, &st) < 0)
	    goto exit;
    if (stat(src, &st) < 0)
	    goto exit;

    if ((dfd = opendir(dest)) == NULL) {
	goto exit;
    }

    rc = 0;
    while ((dp = readdir(dfd)) != NULL) {
	if (!strcmp(dp->d_name, "..")) {
	    continue;
	}
	filepath = rpmGetPath(dest, "/", dp->d_name, NULL);
	xx = chown(filepath, st.st_uid, st.st_gid);
	rc += xx;
	if (!strcmp(dp->d_name, ".")) {
	    xx = chmod(filepath, (st.st_mode & 07777));
	} else {
	    xx = chmod(filepath, (st.st_mode & 07666));
	}
	rc += xx;
	_free(filepath);
    }
    closedir(dfd);

 exit:
    return rc;
}

int rpmdbRebuild(const char * prefix, rpmts ts,
		rpmRC (*hdrchk) (rpmts ts, const void *uh, size_t uc, char ** msg),
		int rebuildflags)
{
    rpmdb olddb;
    char * dbpath = NULL;
    char * rootdbpath = NULL;
    char * tmppath = NULL;
    rpmdb newdb;
    char * newdbpath = NULL;
    char * newrootdbpath = NULL;
    int nocleanup = 1;
    int failed = 0;
    int rc = 0;

    dbpath = rpmGetPath("%{?_dbpath}", NULL);
    if (rstreq(dbpath, "")) {
	rpmlog(RPMLOG_ERR, _("no dbpath has been set"));
	rc = 1;
	goto exit;
    }
    rootdbpath = rpmGetPath(prefix, dbpath, NULL);

    newdbpath = rpmGetPath("%{?_dbpath_rebuild}", NULL);
    if (rstreq(newdbpath, "") || rstreq(newdbpath, dbpath)) {
	newdbpath = _free(newdbpath);
	rasprintf(&newdbpath, "%srebuilddb.%d", dbpath, (int) getpid());
	nocleanup = 0;
    }
    newrootdbpath = rpmGetPath(prefix, newdbpath, NULL);

    rpmlog(RPMLOG_DEBUG, "rebuilding database %s into %s\n",
	rootdbpath, newrootdbpath);

    if (mkdir(newrootdbpath, 0755)) {
	rpmlog(RPMLOG_ERR, _("failed to create directory %s: %s\n"),
	      newrootdbpath, strerror(errno));
	rc = 1;
	goto exit;
    }

    if (openDatabase(prefix, dbpath, &olddb,
		     O_RDONLY, 0644, RPMDB_FLAG_REBUILD |
		     (rebuildflags & RPMDB_REBUILD_FLAG_SALVAGE ?
		         RPMDB_FLAG_SALVAGE : 0))) {
	rc = 1;
	goto exit;
    }
    if (openDatabase(prefix, newdbpath, &newdb,
		     (O_RDWR | O_CREAT), 0644, RPMDB_FLAG_REBUILD)) {
	rc = 1;
	goto exit;
    }

    {	Header h = NULL;
	rpmdbMatchIterator mi;

	mi = rpmdbInitIterator(olddb, RPMDBI_PACKAGES, NULL, 0);
	if (ts && hdrchk)
	    (void) rpmdbSetHdrChk(mi, ts, hdrchk);

	while ((h = rpmdbNextIterator(mi)) != NULL) {

	    /* let's sanity check this record a bit, otherwise just skip it */
	    if (!(headerIsEntry(h, RPMTAG_NAME) &&
		headerIsEntry(h, RPMTAG_VERSION) &&
		headerIsEntry(h, RPMTAG_RELEASE)))
	    {
		rpmlog(RPMLOG_ERR,
			_("header #%u in the database is bad -- skipping.\n"),
			rpmdbGetIteratorOffset(mi));
		continue;
	    }

	    /* Deleted entries are eliminated in legacy headers by copy. */
	    if (headerIsEntry(h, RPMTAG_HEADERIMAGE)) {
		Header nh = headerReload(headerCopy(h), RPMTAG_HEADERIMAGE);
		rc = rpmdbAdd(newdb, nh);
		headerFree(nh);
	    } else {
		rc = rpmdbAdd(newdb, h);
	    }

	    if (rc) {
		rpmlog(RPMLOG_ERR, _("cannot add record originally at %u\n"),
		       rpmdbGetIteratorOffset(mi));
		failed = 1;
		break;
	    }
	}

	rpmdbFreeIterator(mi);

    }

    rpmdbClose(olddb);
    dbCtrl(newdb, DB_CTRL_INDEXSYNC);
    rpmdbClose(newdb);

    if (failed) {
	rpmlog(RPMLOG_WARNING, 
		_("failed to rebuild database: original database "
		"remains in place\n"));

	rpmdbRemoveDatabase(newrootdbpath);
	rc = 1;
	goto exit;
    } else {
	rpmdbSetPermissions(dbpath, newdbpath);
    }

    if (!nocleanup) {
	rasprintf(&tmppath, "%sold.%d", dbpath, (int) getpid());
	if (rpmdbMoveDatabase(prefix, newdbpath, dbpath, tmppath)) {
	    rpmlog(RPMLOG_ERR, _("failed to replace old database with new "
			"database!\n"));
	    rpmlog(RPMLOG_ERR, _("replace files in %s with files from %s "
			"to recover\n"), dbpath, newdbpath);
	    rc = 1;
	    goto exit;
	}
    }
    rc = 0;

exit:
    free(newdbpath);
    free(dbpath);
    free(tmppath);
    free(newrootdbpath);
    free(rootdbpath);

    return rc;
}

int rpmdbCtrl(rpmdb db, rpmdbCtrlOp ctrl)
{
    dbCtrlOp dbctrl = DB_CTRL_NONE;
    switch (ctrl) {
    case RPMDB_CTRL_LOCK_RO:
	dbctrl = DB_CTRL_LOCK_RO;
	break;
    case RPMDB_CTRL_UNLOCK_RO:
	dbctrl = DB_CTRL_UNLOCK_RO;
	break;
    case RPMDB_CTRL_LOCK_RW:
	dbctrl = DB_CTRL_LOCK_RW;
	break;
    case RPMDB_CTRL_UNLOCK_RW:
	dbctrl = DB_CTRL_UNLOCK_RW;
	break;
    case RPMDB_CTRL_INDEXSYNC:
	dbctrl = DB_CTRL_INDEXSYNC;
	break;
    }
    return dbctrl ? dbCtrl(db, dbctrl) : 1;
}

char *rpmdbCookie(rpmdb db)
{
    void *cookie = NULL;
    rpmdbIndexIterator ii = rpmdbIndexIteratorInit(db, RPMDBI_NAME);

    if (ii) {
	DIGEST_CTX ctx = rpmDigestInit(RPM_HASH_SHA256, RPMDIGEST_NONE);
	const void *key = 0;
	size_t keylen = 0;
	while ((rpmdbIndexIteratorNext(ii, &key, &keylen)) == 0) {
	    const unsigned int *offsets = rpmdbIndexIteratorPkgOffsets(ii);
	    unsigned int npkgs = rpmdbIndexIteratorNumPkgs(ii);
	    rpmDigestUpdate(ctx, key, keylen);
	    rpmDigestUpdate(ctx, offsets, sizeof(*offsets) * npkgs);
	}
	rpmDigestFinal(ctx, &cookie, NULL, 1);
    }
    rpmdbIndexIteratorFree(ii);
    return (char *)cookie;
}

int rpmdbFStat(rpmdb db, struct stat *statbuf)
{
    int rc = -1;
    if (db) {
	const char *dbfile = db->db_ops->path;
	if (dbfile) {
	    char *path = rpmGenPath(rpmdbHome(db), dbfile, NULL);
	    rc = stat(path, statbuf);
	    free(path);
	}
    }
    return rc;
}

int rpmdbStat(const char *prefix, struct stat *statbuf)
{
    rpmdb db = NULL;
    int flags = RPMDB_FLAG_VERIFYONLY;
    int rc = -1;

    if (openDatabase(prefix, NULL, &db, O_RDONLY, 0644, flags) == 0) {
	rc = rpmdbFStat(db, statbuf);
	rpmdbClose(db);
    }
    return rc;
}
