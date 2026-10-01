#include "system.h"

#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>

#include "rpmdb_internal.h"
#include <rpm/rpmstring.h>
#include <rpm/rpmlog.h>

#include "backend/ndb/rpmpkg.h"
#include "backend/ndb/rpmxdb.h"
#include "backend/ndb/rpmidx.h"

#include "debug.h"

struct dbiCursor_s {
    dbiIndex dbi; 
    const void *key;
    unsigned int keylen;
    unsigned int hdrNum;
    int flags;

    unsigned int *list;
    unsigned int nlist;
    unsigned int ilist;
    unsigned char *listdata;
};

struct ndbEnv_s {
    rpmpkgdb pkgdb;
    rpmxdb xdb;
    int refs;
    int dofsync;

    unsigned int hdrNum;
    void *data;
    unsigned int datalen;
};

static void closeEnv(rpmdb rdb)
{
    struct ndbEnv_s *ndbenv = (struct ndbEnv_s *)rdb->db_dbenv;
    if (--ndbenv->refs == 0) {
	if (ndbenv->xdb) {
	    rpmxdbClose(ndbenv->xdb);
	    rpmlog(RPMLOG_DEBUG, "closed   db index       %s/Index.db\n", rpmdbHome(rdb));
	}
	if (ndbenv->pkgdb) {
	    rpmpkgClose(ndbenv->pkgdb);
	    rpmlog(RPMLOG_DEBUG, "closed   db index       %s/Packages.db\n", rpmdbHome(rdb));
	}
	if (ndbenv->data)
	    free(ndbenv->data);
	free(ndbenv);
	rdb->db_dbenv = 0;
    }
}

static struct ndbEnv_s *openEnv(rpmdb rdb)
{
    struct ndbEnv_s *ndbenv = (struct ndbEnv_s *)rdb->db_dbenv;
    if (!ndbenv) {
	rdb->db_dbenv = ndbenv = (struct ndbEnv_s *)xcalloc(1, sizeof(struct ndbEnv_s));
	ndbenv->dofsync = 1;
    }
    ndbenv->refs++;
    return ndbenv;
}

static int ndb_Close(dbiIndex dbi, unsigned int flags)
{
    rpmdb rdb = dbi->dbi_rpmdb;
    if (dbi->dbi_type != DBI_PRIMARY && dbi->dbi_db) {
	rpmidxClose((rpmidxdb)dbi->dbi_db);
	rpmlog(RPMLOG_DEBUG, "closed   db index       %s\n", dbi->dbi_file);
    }
    if (rdb->db_dbenv)
	closeEnv(rdb);
    dbiFree(dbi);
    return 0;
}

static void ndb_CheckIndexSync(rpmpkgdb pkgdb, rpmxdb xdb)
{
    unsigned int generation, xdb_generation;
    if (!pkgdb || !xdb)
        return;
    if (rpmpkgLock(pkgdb, 0))
        return;
    if (rpmpkgGeneration(pkgdb, &generation)) {
        rpmpkgUnlock(pkgdb, 0);
        return;
    }
    if (!rpmxdbGetUserGeneration(xdb, &xdb_generation) && generation == xdb_generation) {
        rpmpkgUnlock(pkgdb, 0);
        return;
    }
    rpmpkgUnlock(pkgdb, 0);
    /* index corrupt or with different generation */
    if (rpmxdbIsRdonly(xdb)) {
	rpmlog(RPMLOG_WARNING, _("Detected outdated index databases\n"));
    } else {
	rpmlog(RPMLOG_WARNING, _("Rebuilding outdated index databases\n"));
	rpmxdbDelAllBlobs(xdb);
    }
}

static int ndb_Open(rpmdb rdb, rpmDbiTagVal rpmtag, dbiIndex * dbip, int flags)
{
    const char *dbhome = rpmdbHome(rdb);
    struct ndbEnv_s *ndbenv;
    dbiIndex dbi;
    int rc, oflags, ioflags;

    if (dbip)
	*dbip = NULL;

    if ((dbi = dbiNew(rdb, rpmtag)) == NULL)
	return 1;

    ndbenv = openEnv(rdb);

    oflags = O_RDWR;
    if ((rdb->db_mode & O_ACCMODE) == O_RDONLY)
	oflags = O_RDONLY;
    
    if (dbi->dbi_type == DBI_PRIMARY) {
	rpmpkgdb pkgdb = 0;
	char *path = rstrscat(NULL, dbhome, "/", rdb->db_ops->path, NULL);
	rpmlog(RPMLOG_DEBUG, "opening  db index       %s mode=0x%x\n", path, rdb->db_mode);
	if ((rdb->db_flags & RPMDB_FLAG_SALVAGE) == 0)
	    rc = rpmpkgOpen(&pkgdb, path, oflags, rdb->db_perms);
	else
	    rc = rpmpkgSalvage(&pkgdb, path);
 	if (rc && errno == ENOENT && (rdb->db_flags & RPMDB_FLAG_SALVAGE) == 0) {
	    oflags = O_RDWR|O_CREAT;
	    dbi->dbi_flags |= DBI_CREATED;
	    rc = rpmpkgOpen(&pkgdb, path, oflags, rdb->db_perms);
	}
	if (rc) {
	    perror("rpmpkgOpen");
	    free(path);
	    ndb_Close(dbi, 0);
	    return 1;
	}
	free(path);
	dbi->dbi_db = ndbenv->pkgdb = pkgdb;
	rpmpkgSetFsync(pkgdb, ndbenv->dofsync);
    } else {
	unsigned int id;
	rpmidxdb idxdb = 0;
	if (!ndbenv->pkgdb) {
	    ndb_Close(dbi, 0);
	    return 1;	/* please open primary first */
	}
	if (!ndbenv->xdb) {
	    char *path = rstrscat(NULL, dbhome, "/Index.db", NULL);
	    int created = 0;
	    rpmlog(RPMLOG_DEBUG, "opening  db index       %s mode=0x%x\n", path, rdb->db_mode);

	    /* Open indexes readwrite if possible */
	    ioflags = O_RDWR;
	    rc = rpmxdbOpen(&ndbenv->xdb, (rpmpkgdb)rdb->db_pkgs->dbi_db, path, ioflags, rdb->db_perms);
	    if (rc && (errno == EACCES || errno == EROFS)) {
		/* If it is not asked for rw explicitly, try to open ro */
		if (!(oflags & O_RDWR)) {
		    ioflags = O_RDONLY;
		    rc = rpmxdbOpen(&ndbenv->xdb, (rpmpkgdb)rdb->db_pkgs->dbi_db, path, ioflags, rdb->db_perms);
		}
	    } else if (rc && errno == ENOENT) {
		ioflags = O_CREAT|O_RDWR;
		rc = rpmxdbOpen(&ndbenv->xdb, (rpmpkgdb)rdb->db_pkgs->dbi_db, path, ioflags, rdb->db_perms);
		created = 1;
	    }
	    if (rc) {
		perror("rpmxdbOpen");
		free(path);
		ndb_Close(dbi, 0);
		return 1;
	    }
	    free(path);
	    rpmxdbSetFsync(ndbenv->xdb, ndbenv->dofsync);
	    if (!created)
		ndb_CheckIndexSync(ndbenv->pkgdb, ndbenv->xdb);
	}
	if (rpmxdbLookupBlob(ndbenv->xdb, &id, rpmtag, 0, 0) == RPMRC_NOTFOUND) {
	    oflags = O_RDWR|O_CREAT;
	    dbi->dbi_flags |= DBI_CREATED;
	}
	rpmlog(RPMLOG_DEBUG, "opening  db index       %s tag=%d\n", dbiName(dbi), rpmtag);
	if (rpmidxOpenXdb(&idxdb, (rpmpkgdb)rdb->db_pkgs->dbi_db, ndbenv->xdb, rpmtag, oflags)) {
	    perror("rpmidxOpenXdb");
	    ndb_Close(dbi, 0);
	    return 1;
	}
	dbi->dbi_db = idxdb;
    }

    if ((oflags & (O_RDWR | O_RDONLY)) == O_RDONLY)
	dbi->dbi_flags |= DBI_RDONLY;

    if (dbip != NULL)
	*dbip = dbi;
    else
	ndb_Close(dbi, 0);
    return 0;
}

static int ndb_Verify(dbiIndex dbi, unsigned int flags)
{
    int rc;
    if (dbi->dbi_type == DBI_PRIMARY) {
	rc = rpmpkgVerify((rpmpkgdb)dbi->dbi_db);
    } else {
	rc = 0;		/* cannot verify the index databases */
    }
    return rc;
}

static void ndb_SetFSync(rpmdb rdb, int enable)
{
    struct ndbEnv_s *ndbenv = (struct ndbEnv_s *)rdb->db_dbenv;
    if (ndbenv) {
	ndbenv->dofsync = enable;
	if (ndbenv->pkgdb)
	    rpmpkgSetFsync(ndbenv->pkgdb, enable);
	if (ndbenv->xdb)
	    rpmxdbSetFsync(ndbenv->xdb, enable);
    }
}

static int indexSync(rpmpkgdb pkgdb, rpmxdb xdb)
{
    unsigned int generation;
    int rc;
    if (!pkgdb || !xdb)
        return 1;
    if (rpmpkgLock(pkgdb, 1))
        return 1;
    if (rpmpkgGeneration(pkgdb, &generation)) {
        rpmpkgUnlock(pkgdb, 1);
        return 1;
    }
    rc = rpmxdbSetUserGeneration(xdb, generation);
    rpmpkgUnlock(pkgdb, 1);
    return rc;
}

static int ndb_Ctrl(rpmdb rdb, dbCtrlOp ctrl)
{
    struct ndbEnv_s *ndbenv = (struct ndbEnv_s *)rdb->db_dbenv;

    switch (ctrl) {
    case DB_CTRL_LOCK_RO:
	if (!rdb->db_pkgs)
	    return 1;
	return rpmpkgLock((rpmpkgdb)rdb->db_pkgs->dbi_db, 0);
    case DB_CTRL_LOCK_RW:
	if (!rdb->db_pkgs)
	    return 1;
	return rpmpkgLock((rpmpkgdb)rdb->db_pkgs->dbi_db, 1);
    case DB_CTRL_UNLOCK_RO:
	if (!rdb->db_pkgs)
	    return 1;
	return rpmpkgUnlock((rpmpkgdb)rdb->db_pkgs->dbi_db, 0);
    case DB_CTRL_UNLOCK_RW:
	if (!rdb->db_pkgs)
	    return 1;
	return rpmpkgUnlock((rpmpkgdb)rdb->db_pkgs->dbi_db, 1);
    case DB_CTRL_INDEXSYNC:
	if (!ndbenv)
	    return 1;
	return indexSync(ndbenv->pkgdb, ndbenv->xdb);
    default:
	break;
    }
    return 0;
}

static dbiCursor ndb_CursorInit(dbiIndex dbi, unsigned int flags)
{
    dbiCursor dbc = (dbiCursor)xcalloc(1, sizeof(*dbc));
    dbc->dbi = dbi;
    dbc->flags = flags;
    return dbc;
}

static dbiCursor ndb_CursorFree(dbiIndex dbi, dbiCursor dbc)
{
    if (dbc) {
	if (dbc->list)
	    free(dbc->list);
	if (dbc->listdata)
	    free(dbc->listdata);
	free(dbc);
    }
    return NULL;
}


static void setdata(dbiCursor dbc,  unsigned int hdrNum, unsigned char *hdrBlob, unsigned int hdrLen)
{
    struct ndbEnv_s *ndbenv = (struct ndbEnv_s *)dbc->dbi->dbi_rpmdb->db_dbenv;
    if (ndbenv->data)
	free(ndbenv->data);
    ndbenv->hdrNum  = hdrNum;
    ndbenv->data    = hdrBlob;
    ndbenv->datalen = hdrLen;
}

static rpmRC ndb_pkgdbPut(dbiIndex dbi, dbiCursor dbc,  unsigned int *hdrNum, unsigned char *hdrBlob, unsigned int hdrLen)
{
    struct ndbEnv_s *ndbenv = (struct ndbEnv_s *)dbc->dbi->dbi_rpmdb->db_dbenv;
    unsigned int hnum = *hdrNum;
    rpmRC rc = RPMRC_OK;

    if (hnum == 0) {
	rc = rpmpkgNextPkgIdx((rpmpkgdb)dbc->dbi->dbi_db, &hnum);
	if (!rc && ndbenv->hdrNum == hnum)
	    setdata(dbc, hnum, 0, 0);
    }

    if (!rc)
	rc = rpmpkgPut((rpmpkgdb)dbc->dbi->dbi_db, hnum, hdrBlob, hdrLen);

    if (!rc) {
	dbc->hdrNum = hnum;
	if (ndbenv->hdrNum == hnum)
	    setdata(dbc, hnum, 0, 0);
	*hdrNum = hnum;
    }
    return rc;
}

static rpmRC ndb_pkgdbDel(dbiIndex dbi, dbiCursor dbc,  unsigned int hdrNum)
{
    struct ndbEnv_s *ndbenv = (struct ndbEnv_s *)dbc->dbi->dbi_rpmdb->db_dbenv;
    dbc->hdrNum = 0;
    if (ndbenv->hdrNum == hdrNum)
	setdata(dbc, 0, 0, 0);
    return rpmpkgDel((rpmpkgdb)dbc->dbi->dbi_db, hdrNum);
}

/* iterate over all packages */
static rpmRC ndb_pkgdbIter(dbiIndex dbi, dbiCursor dbc, unsigned char **hdrBlob, unsigned int *hdrLen)
{
    rpmRC rc;
    unsigned int hdrNum;

    if (!dbc->list) {
	rc = rpmpkgList((rpmpkgdb)dbc->dbi->dbi_db, &dbc->list, &dbc->nlist);
	if (rc)
	    return rc;
	dbc->ilist = 0;
    }
    for (;;) {
	if (dbc->ilist >= dbc->nlist) {
	    rc = RPMRC_NOTFOUND;
	    break;
	}
	*hdrBlob = 0;
	hdrNum = dbc->list[dbc->ilist];
	rc = rpmpkgGet((rpmpkgdb)dbc->dbi->dbi_db, hdrNum, hdrBlob, hdrLen);
	if (rc && rc != RPMRC_NOTFOUND)
	    break;
	dbc->ilist++;
	if (!rc) {
	    dbc->hdrNum = hdrNum;
	    setdata(dbc, hdrNum, *hdrBlob, *hdrLen);
	    break;
	}
    }
    return rc;
}

static rpmRC ndb_pkgdbGet(dbiIndex dbi, dbiCursor dbc, unsigned int hdrNum, unsigned char **hdrBlob, unsigned int *hdrLen)
{
    rpmRC rc;
    struct ndbEnv_s *ndbenv = (struct ndbEnv_s *)dbc->dbi->dbi_rpmdb->db_dbenv;

    if (!hdrNum)
	return ndb_pkgdbIter(dbi, dbc, hdrBlob, hdrLen);
    if (hdrNum == ndbenv->hdrNum && ndbenv->data) {
	*hdrBlob = (unsigned char *)ndbenv->data;
	*hdrLen = ndbenv->datalen;
	return RPMRC_OK;
    }
    rc = rpmpkgGet((rpmpkgdb)dbc->dbi->dbi_db, hdrNum, hdrBlob, hdrLen);
    if (!rc) {
	dbc->hdrNum = hdrNum;
	setdata(dbc, hdrNum, *hdrBlob, *hdrLen);
    }
    return rc;
}

static unsigned int ndb_pkgdbKey(dbiIndex dbi, dbiCursor dbc)
{
    return dbc->hdrNum;
}


static void addtoset(dbiIndexSet *set, unsigned int *pkglist, unsigned int pkglistn)
{
    unsigned int i, j;
    dbiIndexSet newset = dbiIndexSetNew(pkglistn / 2);
    for (i = j = 0; i < pkglistn; i += 2) {
	newset->recs[j].hdrNum = pkglist[i];
	newset->recs[j].tagNum = pkglist[i + 1];
	j++;
    }
    newset->count = j;
    if (pkglist)
	free(pkglist);
    if (*set) {
	dbiIndexSetAppendSet(*set, newset, 0);
	dbiIndexSetFree(newset);
    } else
	*set = newset;
}

/* Iterate over all index entries */
static rpmRC ndb_idxdbIter(dbiIndex dbi, dbiCursor dbc, dbiIndexSet *set)
{
    rpmRC rc;
    if (!dbc->list) {
	/* setup iteration list on first call */
	rc = rpmidxList((rpmidxdb)dbc->dbi->dbi_db, &dbc->list, &dbc->nlist, &dbc->listdata);
	if (rc)
	    return rc;
	dbc->ilist = 0;
    }
    for (;;) {
	unsigned char *k;
	unsigned int kl;
	unsigned int *pkglist, pkglistn;
	if (dbc->ilist >= dbc->nlist) {
	    rc = RPMRC_NOTFOUND;
	    break;
	}
	k = dbc->listdata + dbc->list[dbc->ilist];
	kl = dbc->list[dbc->ilist + 1];

	if (set == NULL) {
	    dbc->ilist += 2;
	    dbc->key = k;
	    dbc->keylen = kl;
	    rc = RPMRC_OK;
	    break;
	}

	pkglist = 0;
	pkglistn = 0;
	rc = rpmidxGet((rpmidxdb)dbc->dbi->dbi_db, k, kl, &pkglist, &pkglistn);
	if (rc && rc != RPMRC_NOTFOUND)
	    break;
	dbc->ilist += 2;
	if (!rc && pkglistn) {
	    addtoset(set, pkglist, pkglistn);
	    dbc->key = k;
	    dbc->keylen = kl;
	    break;
	}
	if (pkglist)
	    free(pkglist);
    }
    return rc;
}

static rpmRC ndb_idxdbGet(dbiIndex dbi, dbiCursor dbc, const char *keyp, size_t keylen, dbiIndexSet *set, int searchType)
{
    rpmRC rc;
    unsigned int *pkglist = 0, pkglistn = 0;

    if (!keyp)
	return ndb_idxdbIter(dbi, dbc, set);

    if (searchType == DBC_PREFIX_SEARCH) {
	unsigned int *list = 0, nlist = 0, i = 0;
	unsigned char *listdata = 0;
	rpmRC rrc = RPMRC_NOTFOUND;
	rc = rpmidxList((rpmidxdb)dbc->dbi->dbi_db, &list, &nlist, &listdata);
	if (rc)
	    return rc;
	for (i = 0; i < nlist && !rc; i += 2) {
	    unsigned char *k = listdata + list[i];
	    unsigned int kl = list[i + 1];
	    if (kl < keylen || memcmp(k, keyp, keylen) != 0)
		continue;
	    rc = ndb_idxdbGet(dbi, dbc, (char *)k, kl, set, DBC_NORMAL_SEARCH);
	    if (rc == RPMRC_NOTFOUND)
		rc = RPMRC_OK;
	    else
		rrc = rc;
	}
	if (list)
	    free(list);
	if (listdata)
	    free(listdata);
	return rc ? rc : rrc;
    }

    rc = rpmidxGet((rpmidxdb)dbc->dbi->dbi_db, (const unsigned char *)keyp, keylen, &pkglist, &pkglistn);
    if (!rc)
	addtoset(set, pkglist, pkglistn);
    return rc;
}

static rpmRC ndb_idxdbPutOne(dbiIndex dbi, dbiCursor dbc, const char *keyp, size_t keylen, dbiIndexItem rec)
{
    return rpmidxPut((rpmidxdb)dbc->dbi->dbi_db, (const unsigned char *)keyp, keylen, rec->hdrNum, rec->tagNum);
}

static rpmRC ndb_idxdbPut(dbiIndex dbi, rpmTagVal rpmtag, unsigned int hdrNum, Header h)
{
    return tag2index(dbi, rpmtag, hdrNum, h, ndb_idxdbPutOne);
}

static rpmRC ndb_idxdbDelOne(dbiIndex dbi, dbiCursor dbc, const char *keyp, size_t keylen, dbiIndexItem rec)
{
    return rpmidxDel((rpmidxdb)dbc->dbi->dbi_db, (const unsigned char *)keyp, keylen, rec->hdrNum, rec->tagNum);
}

static rpmRC ndb_idxdbDel(dbiIndex dbi, rpmTagVal rpmtag, unsigned int hdrNum, Header h)
{
    return tag2index(dbi, rpmtag, hdrNum, h, ndb_idxdbDelOne);
}

static const void * ndb_idxdbKey(dbiIndex dbi, dbiCursor dbc, unsigned int *keylen)
{
    if (dbc->key && keylen)
	*keylen = dbc->keylen;
    return dbc->key;
}



struct rpmdbOps_s ndb_dbops = {
    .name	= "ndb",
    .path	= "Packages.db",

    .open	= ndb_Open,
    .close	= ndb_Close,
    .verify	= ndb_Verify,
    .setFSync	= ndb_SetFSync,
    .ctrl	= ndb_Ctrl,

    .cursorInit	= ndb_CursorInit,
    .cursorFree	= ndb_CursorFree,

    .pkgdbGet	= ndb_pkgdbGet,
    .pkgdbPut	= ndb_pkgdbPut,
    .pkgdbDel	= ndb_pkgdbDel,
    .pkgdbKey	= ndb_pkgdbKey,

    .idxdbGet	= ndb_idxdbGet,
    .idxdbPut	= ndb_idxdbPut,
    .idxdbDel	= ndb_idxdbDel,
    .idxdbKey	= ndb_idxdbKey
};

