#include "system.h"

#include <sqlite3.h>
#include <fcntl.h>
#include <inttypes.h>

#include <rpm/rpmlog.h>
#include <rpm/rpmfileutil.h>
#include <rpm/rpmmacro.h>
#include <rpm/rpmstring.h>
#include "rpmdb_internal.h"

#include "debug.h"

static const int sleep_ms = 50;

struct dbiCursor_s {
    sqlite3 *sdb;
    sqlite3_stmt *stmt;
    const char *fmt;
    int flags;
    rpmTagVal tag;
    int ctype;
    struct dbiCursor_s *subc;

    const void *key;
    unsigned int keylen;
};

static int sqlexec(sqlite3 *sdb, const char *fmt, ...);

static void rpm_match3(sqlite3_context *sctx, int argc, sqlite3_value **argv)
{
    int match = 0;
    if (argc == 3) {
	int b1len = sqlite3_value_bytes(argv[0]);
	int b2len = sqlite3_value_bytes(argv[1]);
	int n = sqlite3_value_int(argv[2]);
	if (b1len >= n && b2len >= n) {
	    const void *b1 = sqlite3_value_blob(argv[0]);
	    const void *b2 = sqlite3_value_blob(argv[1]);
	    match = (memcmp(b1, b2, n) == 0);
	}
    }
    sqlite3_result_int(sctx, match);
}

static int dbiCursorReset(dbiCursor dbc)
{
    if (dbc->stmt) {
	sqlite3_reset(dbc->stmt);
	sqlite3_clear_bindings(dbc->stmt);
    }
    return 0;
}

static rpmRC dbiCursorResult(dbiCursor dbc)
{
    int rc = sqlite3_errcode(dbc->sdb);
    int err = (rc != SQLITE_OK && rc != SQLITE_DONE && rc != SQLITE_ROW);
    if (err) {
	rpmlog(RPMLOG_ERR, "%s: %d: %s\n", sqlite3_sql(dbc->stmt),
		sqlite3_errcode(dbc->sdb), sqlite3_errmsg(dbc->sdb));
    }
    return err ? RPMRC_FAIL : RPMRC_OK;
}

static rpmRC dbiCursorPrep(dbiCursor dbc, const char *fmt, ...)
{
    if (dbc->stmt == NULL) {
	char *cmd = NULL;
	va_list ap;

	va_start(ap, fmt); 
	cmd = sqlite3_vmprintf(fmt, ap);
	va_end(ap);

	sqlite3_prepare_v2(dbc->sdb, cmd, -1, &dbc->stmt, NULL);
	sqlite3_free(cmd);
    } else {
	dbiCursorReset(dbc);
    }

    return dbiCursorResult(dbc);
}

static rpmRC dbiCursorBindPkg(dbiCursor dbc, unsigned int hnum,
				void *blob, unsigned int bloblen)
{
    int rc = 0;

    if (hnum)
	rc = sqlite3_bind_int(dbc->stmt, 1, hnum);
    else
	rc = sqlite3_bind_null(dbc->stmt, 1);

    if (blob) {
	if (!rc)
	    rc = sqlite3_bind_blob(dbc->stmt, 2, blob, bloblen, NULL);
    }
    return dbiCursorResult(dbc);
}

static rpmRC dbiCursorBindIdx(dbiCursor dbc, const char *key, int keylen,
				dbiIndexItem rec)
{
    int rc;
    if (dbc->ctype == SQLITE_TEXT) {
	rc = sqlite3_bind_text(dbc->stmt, 1, key, keylen, NULL);
    } else {
	rc = sqlite3_bind_blob(dbc->stmt, 1, key, keylen, NULL);
    }

    if (rec) {
	if (!rc)
	    rc = sqlite3_bind_int(dbc->stmt, 2, rec->hdrNum);
	if (!rc)
	    rc = sqlite3_bind_int(dbc->stmt, 3, rec->tagNum);
    }

    return dbiCursorResult(dbc);
}

static int sqlite_init(rpmdb rdb, const char * dbhome)
{
    int rc = 0;
    char *dbfile = NULL;

    if (rdb->db_dbenv == NULL) {
	dbfile = rpmGenPath(dbhome, rdb->db_ops->path, NULL);
	sqlite3 *sdb = NULL;
	int xx = SQLITE_CANTOPEN, flags = 0;
	int retry_open = 1;
	if ((rdb->db_mode & O_ACCMODE) == O_RDONLY)
	    flags |= SQLITE_OPEN_READONLY;
	else
	    flags |= (SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);

	while (retry_open--) {
	    xx = sqlite3_open_v2(dbfile, &sdb, flags, NULL);
	    /* Attempt to create if missing, discarding OPEN_READONLY (!) */
	    if (xx == SQLITE_CANTOPEN && (flags & SQLITE_OPEN_READONLY)) {
		/* Sqlite allocates resources even on failure to open (!) */
		sqlite3_close(sdb);
		flags &= ~SQLITE_OPEN_READONLY;
		flags |= (SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
		retry_open++;
	    }
	}

	if (xx != SQLITE_OK) {
	    rpmlog(RPMLOG_ERR, _("Unable to open sqlite database %s: %s\n"),
		    dbfile, sqlite3_errstr(xx));
	    rc = 1;
	    goto exit;
	}

	sqlite3_create_function(sdb, "match", 3,
				(SQLITE_UTF8|SQLITE_DETERMINISTIC),
				NULL, rpm_match3, NULL, NULL);

	/*
	 * Set an extremely high timeout because we must avoid
	 * the "database is locked" errors at every cost
	 */
	sqlite3_busy_timeout(sdb, 10000);

	sqlexec(sdb, "PRAGMA secure_delete = OFF");

	if (sqlite3_db_readonly(sdb, NULL) == 0) {
	    if (sqlexec(sdb, "PRAGMA journal_mode = WAL") == 0) {
		int one = 1;
		/* Annoying but necessary to support non-privileged readers */
		sqlite3_file_control(sdb, NULL, SQLITE_FCNTL_PERSIST_WAL, &one);
		/* Sqlite default threshold is way too low for rpmdb */
		sqlexec(sdb, "PRAGMA wal_autocheckpoint = 10000");
	    }
	}

	rdb->db_dbenv = sdb;
    }
    rdb->db_opens++;

exit:
    free(dbfile);
    return rc;
}

static int64_t sqlite_free_space_kb(sqlite3 * db)
{
    int64_t result = 0;
    sqlite3_stmt *s = NULL;
    const char *cmd = "SELECT (freelist_count*page_size) as FreeSizeEstimate"
	" FROM pragma_freelist_count, pragma_page_size";
    if (sqlite3_prepare_v2(db, cmd, -1, &s, NULL) == SQLITE_OK) {
	while (sqlite3_step(s) == SQLITE_ROW) {
	    result = sqlite3_column_int64(s, 0);
	}
	sqlite3_finalize(s);
    }
    return result / 1024;
}

static int sqlite_fini(rpmdb rdb)
{
    int rc = 0;
    if (rdb) {
	sqlite3 *sdb = (sqlite3 *)rdb->db_dbenv;
	if (rdb->db_opens > 1) {
	    rdb->db_opens--;
	} else {
	    if (sqlite3_db_readonly(sdb, NULL) == 0) {

		sqlexec(sdb, "PRAGMA optimize");
		sqlexec(sdb, "PRAGMA wal_checkpoint = TRUNCATE");

		int max_size = rpmExpandNumeric("%{?_sqlite_vacuum_kb}");
		if (max_size <= 0)
		    max_size = 20*1024;
		int64_t free_space = sqlite_free_space_kb(sdb);

		if (free_space > max_size) {
		    sqlexec(sdb, "VACUUM");
		    rpmlog(RPMLOG_DEBUG, "rpmdb sqlite backend VACUUM maxfree:"
			   " %ikB, free: %" PRIu64 "kB -> %" PRIu64 "kB\n",
			   max_size, free_space, sqlite_free_space_kb(sdb));
		}
	    }
	    rdb->db_dbenv = NULL;
	    int xx = sqlite3_close(sdb);
	    rc = (xx != SQLITE_OK);
	}
    }

    return rc;
}

static int sqlexec(sqlite3 *sdb, const char *fmt, ...)
{
    int rc = 0;
    char *cmd = NULL;
    char *err = NULL;
    va_list ap;

    va_start(ap, fmt);
    cmd = sqlite3_vmprintf(fmt, ap);
    va_end(ap);

    /* sqlite3_exec() doesn't seeem to honor sqlite3_busy_timeout() */
    while ((rc = sqlite3_exec(sdb, cmd, NULL, NULL, &err)) == SQLITE_BUSY) {
	usleep(sleep_ms);
    }

    if (rc)
	rpmlog(RPMLOG_ERR, "sqlite failure: %s: %s\n", cmd, err);
    else
	rpmlog(RPMLOG_DEBUG, "%s: %d\n", cmd, rc);

    sqlite3_free(cmd);
    sqlite3_free(err);

    return rc ? RPMRC_FAIL : RPMRC_OK;
}

static int dbiExists(dbiIndex dbi)
{
    const char *col = (dbi->dbi_type == DBI_PRIMARY) ? "hnum" : "key";
    const char *tbl = dbi->dbi_file;
    int rc = sqlite3_table_column_metadata((sqlite3 *)dbi->dbi_db, NULL, tbl, col,
					   NULL, NULL, NULL, NULL, NULL);
    return (rc == 0);
}

static int init_table(dbiIndex dbi, rpmTagVal tag)
{
    int rc = 0;

    if (dbiExists(dbi))
	return 0;

    if (dbi->dbi_type == DBI_PRIMARY) {
	rc = sqlexec((sqlite3 *)dbi->dbi_db,
			"CREATE TABLE IF NOT EXISTS '%q' ("
			    "hnum INTEGER PRIMARY KEY AUTOINCREMENT,"
			    "blob BLOB NOT NULL"
			")",
			dbi->dbi_file);
    } else {
	const char *keytype = (rpmTagGetClass(tag) == RPM_STRING_CLASS) ?
				"TEXT" : "BLOB";
	rc = sqlexec((sqlite3 *)dbi->dbi_db,
			"CREATE TABLE IF NOT EXISTS '%q' ("
			    "key '%q' NOT NULL, "
			    "hnum INTEGER NOT NULL, "
			    "idx INTEGER NOT NULL, "
			    "FOREIGN KEY (hnum) REFERENCES 'Packages'(hnum)"
			")",
			dbi->dbi_file, keytype);
    }
    if (!rc)
	dbi->dbi_flags |= DBI_CREATED;

    return rc;
}

static int create_index(sqlite3 *sdb, const char *table, const char *col)
{
    return sqlexec(sdb,
		"CREATE INDEX IF NOT EXISTS '%s_%s_idx' ON '%q'(%s ASC)",
		table, col, table, col);
}

static int init_index(dbiIndex dbi, rpmTagVal tag)
{
    int rc = 0;

    /* Can't create on readonly database, but things will still work */
    if (sqlite3_db_readonly((sqlite3 *)dbi->dbi_db, NULL) == 1)
	return 0;

    if (dbi->dbi_type == DBI_SECONDARY) {
	int string = (rpmTagGetClass(tag) == RPM_STRING_CLASS);
	int array = (rpmTagGetReturnType(tag) == RPM_ARRAY_RETURN_TYPE);
	if (!rc && string)
	    rc = create_index((sqlite3 *)dbi->dbi_db, dbi->dbi_file, "key");
	if (!rc && array)
	    rc = create_index((sqlite3 *)dbi->dbi_db, dbi->dbi_file, "hnum");
    }
    return rc;
}

static int sqlite_Open(rpmdb rdb, rpmDbiTagVal rpmtag, dbiIndex * dbip, int flags)
{
    int rc = sqlite_init(rdb, rpmdbHome(rdb));

    if (!rc) {
	dbiIndex dbi = dbiNew(rdb, rpmtag);
	dbi->dbi_db = rdb->db_dbenv;

	rc = init_table(dbi, rpmtag);

	if (!rc && !(rdb->db_flags & RPMDB_FLAG_REBUILD))
	    rc = init_index(dbi, rpmtag);

	if (!rc && dbip)
	    *dbip = dbi;
	else
	    dbiFree(dbi);
    }

    return rc;
}

static int sqlite_Close(dbiIndex dbi, unsigned int flags)
{
    rpmdb rdb = dbi->dbi_rpmdb;
    int rc = 0;
    if (rdb->db_flags & RPMDB_FLAG_REBUILD)
	rc = init_index(dbi, rpmTagGetValue(dbi->dbi_file));
    sqlite_fini(dbi->dbi_rpmdb);
    dbiFree(dbi);
    return rc;
}

static int sqlite_Verify(dbiIndex dbi, unsigned int flags)
{
    int errors = -1;
    int key_errors = -1;
    sqlite3_stmt *s = NULL;
    const char *cmd = "PRAGMA integrity_check";

    if (dbi->dbi_type == DBI_SECONDARY)
	return RPMRC_OK;

    if (sqlite3_prepare_v2((sqlite3 *)dbi->dbi_db, cmd, -1, &s, NULL) == SQLITE_OK) {
	errors = 0;
	while (sqlite3_step(s) == SQLITE_ROW) {
	    const char *txt = (const char *)sqlite3_column_text(s, 0);
	    if (!rstreq(txt, "ok")) {
		errors++;
		rpmlog(RPMLOG_ERR, "verify: %s\n", txt);
	    }
	}
	sqlite3_finalize(s);
    } else {
	rpmlog(RPMLOG_ERR, "%s: %s\n", cmd, sqlite3_errmsg((sqlite3 *)dbi->dbi_db));
    }

    /* No point checking higher-level errors if low-level errors exist */
    if (errors)
	goto exit;

    cmd = "PRAGMA foreign_key_check";
    if (sqlite3_prepare_v2((sqlite3 *)dbi->dbi_db, cmd, -1, &s, NULL) == SQLITE_OK) {
	key_errors = 0;
	while (sqlite3_step(s) == SQLITE_ROW) {
	    key_errors++;
	    rpmlog(RPMLOG_ERR, "verify key: %s[%lld]\n",
				sqlite3_column_text(s, 0),
				sqlite3_column_int64(s, 1));
	}
	sqlite3_finalize(s);
    } else {
	rpmlog(RPMLOG_ERR, "%s: %s\n", cmd, sqlite3_errmsg((sqlite3 *)dbi->dbi_db));
    }

exit:

    return (errors == 0 && key_errors == 0) ? RPMRC_OK : RPMRC_FAIL;
}

static void sqlite_SetFSync(rpmdb rdb, int enable)
{
    sqlexec((sqlite3 *)rdb->db_dbenv,
	    "PRAGMA synchronous = %s", enable ? "FULL" : "OFF");
}

static int sqlite_Ctrl(rpmdb rdb, dbCtrlOp ctrl)
{
    int rc = 0;

    switch (ctrl) {
    case DB_CTRL_LOCK_RW:
	rc = sqlexec((sqlite3 *)rdb->db_dbenv, "SAVEPOINT 'rwlock'");
	break;
    case DB_CTRL_UNLOCK_RW:
	rc = sqlexec((sqlite3 *)rdb->db_dbenv, "RELEASE 'rwlock'");
	break;
    default:
	break;
    }

    return rc;
}

static dbiCursor sqlite_CursorInit(dbiIndex dbi, unsigned int flags)
{
    dbiCursor dbc = (dbiCursor)xcalloc(1, sizeof(*dbc));
    dbc->sdb = (sqlite3 *)dbi->dbi_db;
    dbc->flags = flags;
    dbc->tag = rpmTagGetValue(dbi->dbi_file);
    if (rpmTagGetClass(dbc->tag) == RPM_STRING_CLASS) {
	dbc->ctype = SQLITE_TEXT;
    } else {
	dbc->ctype = SQLITE_BLOB;
    }
    if (dbc->flags & DBC_WRITE)
	sqlexec(dbc->sdb, "SAVEPOINT '%s'", dbi->dbi_file);
    return dbc;
}

static dbiCursor sqlite_CursorFree(dbiIndex dbi, dbiCursor dbc)
{
    if (dbc) {
	sqlite3_finalize(dbc->stmt);
	if (dbc->subc)
	    dbiCursorFree(dbi, dbc->subc);
	if (dbc->flags & DBC_WRITE)
	    sqlexec(dbc->sdb, "RELEASE '%s'", dbi->dbi_file);
	free(dbc);
    }
    return NULL;
}

static rpmRC sqlite_pkgdbPut(dbiIndex dbi, dbiCursor dbc,  unsigned int *hdrNum, unsigned char *hdrBlob, unsigned int hdrLen)
{
    rpmRC rc = RPMRC_OK;
    dbiCursor dbwc = NULL;

    /* Avoid trashing existing query cursor on header rewrite */
    if (hdrNum && *hdrNum) {
	dbwc = dbiCursorInit(dbi, DBC_WRITE);
	dbc = dbwc;
    }

    if (!rc) {
	rc = dbiCursorPrep(dbc, "INSERT OR REPLACE INTO '%q' VALUES(?, ?)",
			    dbi->dbi_file);
    }

    if (!rc)
	rc = dbiCursorBindPkg(dbc, *hdrNum, hdrBlob, hdrLen);

    if (!rc) {
	int sqrc = 0;
	while ((sqrc = sqlite3_step(dbc->stmt)) == SQLITE_ROW) {};

	/* XXX rowid is a 64bit integer and could overflow hdrnum */
	if (sqrc == SQLITE_DONE && *hdrNum == 0)
	    *hdrNum = sqlite3_last_insert_rowid(dbc->sdb);
    }

    rc = dbiCursorResult(dbc);

    if (dbwc)
	dbiCursorFree(dbi, dbwc);

    return rc;
}

static rpmRC sqlite_pkgdbDel(dbiIndex dbi, dbiCursor dbc,  unsigned int hdrNum)
{
    rpmRC rc = dbiCursorPrep(dbc, "DELETE FROM '%q' WHERE hnum=?;",
			    dbi->dbi_file);

    if (!rc)
	rc = dbiCursorBindPkg(dbc, hdrNum, NULL, 0);

    if (!rc)
	while (sqlite3_step(dbc->stmt) == SQLITE_ROW) {};

    return dbiCursorResult(dbc);
}

static rpmRC sqlite_stepPkg(dbiCursor dbc, unsigned char **hdrBlob, unsigned int *hdrLen)
{
    int rc = sqlite3_step(dbc->stmt);

    if (rc == SQLITE_ROW) {
	if (hdrLen)
	    *hdrLen = sqlite3_column_bytes(dbc->stmt, 1);
	if (hdrBlob)
	    *hdrBlob = (unsigned char *) sqlite3_column_blob(dbc->stmt, 1);
    }

    return (rc == SQLITE_DONE) ? RPMRC_NOTFOUND : dbiCursorResult(dbc);
}

static rpmRC sqlite_pkgdbByKey(dbiIndex dbi, dbiCursor dbc, unsigned int hdrNum, unsigned char **hdrBlob, unsigned int *hdrLen)
{
    rpmRC rc = dbiCursorPrep(dbc, "SELECT hnum, blob FROM '%q' WHERE hnum=?",
				dbi->dbi_file);

    if (!rc)
	rc = dbiCursorBindPkg(dbc, hdrNum, NULL, 0);

    if (!rc)
	rc = sqlite_stepPkg(dbc, hdrBlob, hdrLen);

    return dbiCursorResult(dbc);
}

static rpmRC sqlite_pkgdbIter(dbiIndex dbi, dbiCursor dbc,
				unsigned char **hdrBlob, unsigned int *hdrLen)
{
    rpmRC rc = RPMRC_OK;
    if (dbc->stmt == NULL) {
	rc = dbiCursorPrep(dbc, "SELECT hnum, blob FROM '%q'", dbi->dbi_file);
    }

    if (!rc)
	rc = sqlite_stepPkg(dbc, hdrBlob, hdrLen);

    return rc;
}

static rpmRC sqlite_pkgdbGet(dbiIndex dbi, dbiCursor dbc, unsigned int hdrNum, unsigned char **hdrBlob, unsigned int *hdrLen)
{
    rpmRC rc;

    if (hdrNum) {
	rc = sqlite_pkgdbByKey(dbi, dbc, hdrNum, hdrBlob, hdrLen);
    } else {
	rc = sqlite_pkgdbIter(dbi, dbc, hdrBlob, hdrLen);
    }

    return rc;
}

static unsigned int sqlite_pkgdbKey(dbiIndex dbi, dbiCursor dbc)
{
    return sqlite3_column_int(dbc->stmt, 0);
}

static rpmRC sqlite_idxdbByKey(dbiIndex dbi, dbiCursor dbc,
			    const char *keyp, size_t keylen, int searchType,
			    dbiIndexSet *set)
{
    rpmRC rc = RPMRC_NOTFOUND;

    if (searchType == DBC_PREFIX_SEARCH) {
	rc = dbiCursorPrep(dbc, "SELECT hnum, idx FROM '%q' "
				"WHERE MATCH(key,'%q',%d) "
				"ORDER BY key",
				dbi->dbi_file, keyp, keylen);
    } else {
	rc = dbiCursorPrep(dbc, "SELECT hnum, idx FROM '%q' WHERE key=?",
			dbi->dbi_file);
	if (!rc)
	    rc = dbiCursorBindIdx(dbc, keyp, keylen, NULL);
    }


    if (!rc) {
	int sqrc;
	while ((sqrc = sqlite3_step(dbc->stmt)) == SQLITE_ROW) {
	    unsigned int hnum = sqlite3_column_int(dbc->stmt, 0);
	    unsigned int tnum = sqlite3_column_int(dbc->stmt, 1);

	    if (*set == NULL)
		*set = dbiIndexSetNew(5);
	    dbiIndexSetAppendOne(*set, hnum, tnum, 0);
	}

	if (sqrc == SQLITE_DONE) {
	    rc = (*set) ? RPMRC_OK : RPMRC_NOTFOUND;
	} else {
	    rc = dbiCursorResult(dbc);
	}
    }

    return rc;
}

static rpmRC sqlite_idxdbIter(dbiIndex dbi, dbiCursor dbc, dbiIndexSet *set)
{
    rpmRC rc = RPMRC_OK;

    if (dbc->stmt == NULL) {
	rc = dbiCursorPrep(dbc, "SELECT DISTINCT key FROM '%q' ORDER BY key",
				dbi->dbi_file);
	if (set)
	    dbc->subc = dbiCursorInit(dbi, 0);
    }

    if (!rc) {
	int sqrc = sqlite3_step(dbc->stmt);

	if (sqrc == SQLITE_ROW) {
	    if (dbc->ctype == SQLITE_TEXT) {
		dbc->key = sqlite3_column_text(dbc->stmt, 0);
	    } else {
		dbc->key = sqlite3_column_blob(dbc->stmt, 0);
	    }
	    dbc->keylen = sqlite3_column_bytes(dbc->stmt, 0);
	    if (dbc->subc) {
		rc = sqlite_idxdbByKey(dbi, dbc->subc,
					(const char *)dbc->key, dbc->keylen,
					DBC_NORMAL_SEARCH, set);
	    } else {
		rc = RPMRC_OK;
	    }
	} else if (sqrc == SQLITE_DONE) {
	    rc = RPMRC_NOTFOUND;
	} else {
	    rc = dbiCursorResult(dbc);
	}
    }

    return rc;
}

static rpmRC sqlite_idxdbGet(dbiIndex dbi, dbiCursor dbc, const char *keyp, size_t keylen, dbiIndexSet *set, int searchType)
{
    rpmRC rc;
    if (keyp) {
	rc = sqlite_idxdbByKey(dbi, dbc, keyp, keylen, searchType, set);
    } else {
	rc = sqlite_idxdbIter(dbi, dbc, set);
    }

    return rc;
}

static rpmRC sqlite_idxdbPutOne(dbiIndex dbi, dbiCursor dbc, const char *keyp, size_t keylen, dbiIndexItem rec)
{
    rpmRC rc = dbiCursorPrep(dbc, "INSERT INTO '%q' VALUES(?, ?, ?)",
			dbi->dbi_file);

    if (!rc)
	rc = dbiCursorBindIdx(dbc, keyp, keylen, rec);

    if (!rc)
	while (sqlite3_step(dbc->stmt) == SQLITE_ROW) {};

    return dbiCursorResult(dbc);
}

static rpmRC sqlite_idxdbPut(dbiIndex dbi, rpmTagVal rpmtag, unsigned int hdrNum, Header h)
{
    return tag2index(dbi, rpmtag, hdrNum, h, sqlite_idxdbPutOne);
}

static rpmRC sqlite_idxdbDel(dbiIndex dbi, rpmTagVal rpmtag, unsigned int hdrNum, Header h)
{
    dbiCursor dbc = dbiCursorInit(dbi, DBC_WRITE);
    rpmRC rc = dbiCursorPrep(dbc, "DELETE FROM '%q' WHERE hnum=?", dbi->dbi_file);

    if (!rc)
	rc = dbiCursorBindPkg(dbc, hdrNum, NULL, 0);

    if (!rc)
	while (sqlite3_step(dbc->stmt) == SQLITE_ROW) {};

    rc = dbiCursorResult(dbc);
    dbiCursorFree(dbi, dbc);
    return rc;
}

static const void * sqlite_idxdbKey(dbiIndex dbi, dbiCursor dbc, unsigned int *keylen)
{
    const void *key = NULL;
    if (dbc) {
	key = dbc->key;
	if (key && keylen)
	    *keylen = dbc->keylen;
    }
    return key;
}



struct rpmdbOps_s sqlite_dbops = {
    .name	= "sqlite",
    .path	= "rpmdb.sqlite",

    .open	= sqlite_Open,
    .close	= sqlite_Close,
    .verify	= sqlite_Verify,
    .setFSync	= sqlite_SetFSync,
    .ctrl	= sqlite_Ctrl,

    .cursorInit	= sqlite_CursorInit,
    .cursorFree	= sqlite_CursorFree,

    .pkgdbGet	= sqlite_pkgdbGet,
    .pkgdbPut	= sqlite_pkgdbPut,
    .pkgdbDel	= sqlite_pkgdbDel,
    .pkgdbKey	= sqlite_pkgdbKey,

    .idxdbGet	= sqlite_idxdbGet,
    .idxdbPut	= sqlite_idxdbPut,
    .idxdbDel	= sqlite_idxdbDel,
    .idxdbKey	= sqlite_idxdbKey
};

