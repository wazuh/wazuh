/** \ingroup rpmdb
 * \file lib/dbi.c
 */

#include "system.h"

#include <stdlib.h>
#include <fcntl.h>
#include <rpm/rpmstring.h>
#include <rpm/rpmmacro.h>
#include <rpm/rpmlog.h>
#include <rpm/header.h>
#include "rpmdb_internal.h"
#include "debug.h"

const struct rpmdbOps_s *backends[] = {
#if defined(ENABLE_SQLITE)
    &sqlite_dbops,
#endif
#ifdef ENABLE_NDB
    &ndb_dbops,
#endif
#if defined(ENABLE_BDB_RO)
    &bdbro_dbops,
#endif
    &dummydb_dbops,
    NULL
};

dbiIndex dbiFree(dbiIndex dbi)
{
    if (dbi) {
	free(dbi);
    }
    return NULL;
}

dbiIndex dbiNew(rpmdb rdb, rpmDbiTagVal rpmtag)
{
    dbiIndex dbi = (dbiIndex)xcalloc(1, sizeof(*dbi));
    /* FIX: figger lib/dbi refcounts */
    dbi->dbi_rpmdb = rdb;
    dbi->dbi_file = rpmTagGetName(rpmtag);
    dbi->dbi_type = (rpmtag == RPMDBI_PACKAGES) ? DBI_PRIMARY : DBI_SECONDARY;
    return dbi;
}

void dbShowRC(FILE* fp)
{
    const struct rpmdbOps_s **ops;
    char *db_backend = rpmExpand("%{?_db_backend}", NULL);
    fprintf(fp, "\nBACKEND:\n");
    if (db_backend) {
	fprintf(fp, "default backend       : %s\n", db_backend);
	free(db_backend);
    }
    fprintf(fp, "available backends    :");
    for (ops = backends; ops && *ops; ops++) {
	fputc(' ', fp);
	fputs((*ops)->name, fp);
    }
    fprintf(fp, "\n");
}

/* Test whether there's a database for this backend, return true/false */
static int tryBackend(const char *dbhome, const struct rpmdbOps_s *be)
{
    int rc = 0;
    if (be && be->path) {
	char *path = rstrscat(NULL, dbhome, "/", be->path, NULL);
	rc = (access(path, F_OK) == 0);
	free(path);
    }
    return rc;
}

static void
dbDetectBackend(rpmdb rdb)
{
    const char *dbhome = rpmdbHome(rdb);
    char *db_backend = rpmExpand("%{?_db_backend}", NULL);
    const struct rpmdbOps_s **ops;
    const struct rpmdbOps_s *cfg = NULL;
    const struct rpmdbOps_s *ondisk = NULL;

    /* Find configured backend */
    for (ops = backends; ops && *ops; ops++) {
	if (rstreq(db_backend, (*ops)->name)) {
	    cfg = *ops;
	    break;
	}
    }

    if (!cfg && ((rdb->db_mode & O_ACCMODE) != O_RDONLY || (rdb->db_flags & RPMDB_FLAG_REBUILD) != 0)) {
	rpmlog(RPMLOG_WARNING, _("invalid %%_db_backend: %s\n"), db_backend);
	goto exit;
    }

    /* If configured database doesn't exist, try autodetection */
    if (!tryBackend(dbhome, cfg)) {
	for (ops = backends; ops && *ops; ops++) {
	    if (tryBackend(dbhome, *ops)) {
		ondisk = *ops;
		break;
	    }
	}

	/* On-disk database differs from configuration */
	if (ondisk && ondisk != cfg) {
	    if (*db_backend) {
		if (rdb->db_flags & RPMDB_FLAG_REBUILD) {
		    rpmlog(RPMLOG_WARNING,
			    _("Converting database from %s to %s backend\n"),
			    ondisk->name, db_backend);
		} else {
		    rpmlog(RPMLOG_WARNING,
			_("Found %s %s database while attempting %s backend: "
			"using %s backend.\n"),
			ondisk->name, ondisk->path, db_backend, ondisk->name);
		}
	    } else {
		rpmlog(RPMLOG_DEBUG, "Found %s %s database: using %s backend.\n",
		    ondisk->name, ondisk->path, ondisk->name);
	    }
	    rdb->db_ops = ondisk;
	}
    }

    /* Newly created database, use configured backend */
    if (rdb->db_ops == NULL && cfg)
	rdb->db_ops = cfg;

exit:
    /* If all else fails... */
    if (rdb->db_ops == NULL) {
	rdb->db_ops = &dummydb_dbops;
	rpmlog(RPMLOG_WARNING, "using dummy database, installs not possible\n");
    }

    rdb->db_descr = rdb->db_ops->name;

    if (db_backend)
	free(db_backend);
}

const char * dbiName(dbiIndex dbi)
{
    return dbi->dbi_file;
}

int dbiFlags(dbiIndex dbi)
{
    return dbi->dbi_flags;
}

void dbSetFSync(rpmdb rdb, int enable)
{
    if (!rdb->db_ops)
	dbDetectBackend(rdb);
    rdb->db_ops->setFSync(rdb, enable);
}

int dbCtrl(rpmdb rdb, dbCtrlOp ctrl)
{
    if (!rdb->db_ops)
	dbDetectBackend(rdb);
    return rdb->db_ops->ctrl(rdb, ctrl);
}

int dbiOpen(rpmdb rdb, rpmDbiTagVal rpmtag, dbiIndex * dbip, int flags)
{
    if (!rdb->db_ops)
	dbDetectBackend(rdb);
    return rdb->db_ops->open(rdb, rpmtag, dbip, flags);
}

int dbiClose(dbiIndex dbi, unsigned int flags)
{
    return dbi ? dbi->dbi_rpmdb->db_ops->close(dbi, flags) : 0;
}

int dbiVerify(dbiIndex dbi, unsigned int flags)
{
    return dbi->dbi_rpmdb->db_ops->verify(dbi, flags);
}

dbiCursor dbiCursorInit(dbiIndex dbi, unsigned int flags)
{
    return dbi->dbi_rpmdb->db_ops->cursorInit(dbi, flags);
}

dbiCursor dbiCursorFree(dbiIndex dbi, dbiCursor dbc)
{
    return dbi->dbi_rpmdb->db_ops->cursorFree(dbi, dbc);
}

rpmRC pkgdbPut(dbiIndex dbi, dbiCursor dbc, unsigned int *hdrNum, unsigned char *hdrBlob, unsigned int hdrLen)
{
    return dbi->dbi_rpmdb->db_ops->pkgdbPut(dbi, dbc, hdrNum, hdrBlob, hdrLen);
}

rpmRC pkgdbDel(dbiIndex dbi, dbiCursor dbc,  unsigned int hdrNum)
{
    return dbi->dbi_rpmdb->db_ops->pkgdbDel(dbi, dbc, hdrNum);
}

rpmRC pkgdbGet(dbiIndex dbi, dbiCursor dbc, unsigned int hdrNum, unsigned char **hdrBlob, unsigned int *hdrLen)
{
    return dbi->dbi_rpmdb->db_ops->pkgdbGet(dbi, dbc, hdrNum, hdrBlob, hdrLen);
}

unsigned int pkgdbKey(dbiIndex dbi, dbiCursor dbc)
{
    return dbi->dbi_rpmdb->db_ops->pkgdbKey(dbi, dbc);
}

rpmRC idxdbGet(dbiIndex dbi, dbiCursor dbc, const char *keyp, size_t keylen, dbiIndexSet *set, int curFlags)
{
    return dbi->dbi_rpmdb->db_ops->idxdbGet(dbi, dbc, keyp, keylen, set, curFlags);
}

rpmRC idxdbPut(dbiIndex dbi, rpmTagVal rpmtag, unsigned int hdrNum, Header h)
{
    return dbi->dbi_rpmdb->db_ops->idxdbPut(dbi, rpmtag, hdrNum, h);
}

rpmRC idxdbDel(dbiIndex dbi, rpmTagVal rpmtag, unsigned int hdrNum, Header h)
{
    return dbi->dbi_rpmdb->db_ops->idxdbDel(dbi, rpmtag, hdrNum, h);
}

const void * idxdbKey(dbiIndex dbi, dbiCursor dbc, unsigned int *keylen)
{
    return dbi->dbi_rpmdb->db_ops->idxdbKey(dbi, dbc, keylen);
}

