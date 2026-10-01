#include "system.h"

#include "rpmdb_internal.h"

#include "debug.h"

static int dummydb_Close(dbiIndex dbi, unsigned int flags)
{
    dbiFree(dbi);
    return 0;
}

static int dummydb_Open(rpmdb rdb, rpmDbiTagVal rpmtag, dbiIndex * dbip, int flags)
{
    dbiIndex dbi = dbiNew(rdb, rpmtag);
    if (dbip)
	*dbip = dbi;
    else
	dbiFree(dbi);
    return 0;
}

static int dummydb_Verify(dbiIndex dbi, unsigned int flags)
{
    return 0;
}

static void dummydb_SetFSync(rpmdb rdb, int enable)
{
}

static int dummydb_Ctrl(rpmdb rdb, dbCtrlOp ctrl)
{
    return 0;
}

static dbiCursor dummydb_CursorInit(dbiIndex dbi, unsigned int flags)
{
    return NULL;
}

static dbiCursor dummydb_CursorFree(dbiIndex dbi, dbiCursor dbc)
{
    return NULL;
}


static rpmRC dummydb_pkgdbPut(dbiIndex dbi, dbiCursor dbc,  unsigned int *hdrNum, unsigned char *hdrBlob, unsigned int hdrLen)
{
    return RPMRC_FAIL;
}

static rpmRC dummydb_pkgdbDel(dbiIndex dbi, dbiCursor dbc,  unsigned int hdrNum)
{
    return RPMRC_FAIL;
}

static rpmRC dummydb_pkgdbGet(dbiIndex dbi, dbiCursor dbc, unsigned int hdrNum, unsigned char **hdrBlob, unsigned int *hdrLen)
{
    return RPMRC_FAIL;
}

static unsigned int dummydb_pkgdbKey(dbiIndex dbi, dbiCursor dbc)
{
    return 0;
}

static rpmRC dummydb_idxdbGet(dbiIndex dbi, dbiCursor dbc, const char *keyp, size_t keylen, dbiIndexSet *set, int searchType)
{
    return RPMRC_FAIL;
}

static rpmRC dummydb_idxdbPut(dbiIndex dbi, rpmTagVal rpmtag, unsigned int hdrNum, Header h)
{
    return RPMRC_FAIL;
}

static rpmRC dummydb_idxdbDel(dbiIndex dbi, rpmTagVal rpmtag, unsigned int hdrNum, Header h)
{
    return RPMRC_FAIL;
}

static const void * dummydb_idxdbKey(dbiIndex dbi, dbiCursor dbc, unsigned int *keylen)
{
    return NULL;
}



struct rpmdbOps_s dummydb_dbops = {
    .name	= "dummy",
    .path	= NULL,

    .open	= dummydb_Open,
    .close	= dummydb_Close,
    .verify	= dummydb_Verify,
    .setFSync	= dummydb_SetFSync,
    .ctrl	= dummydb_Ctrl,

    .cursorInit	= dummydb_CursorInit,
    .cursorFree	= dummydb_CursorFree,

    .pkgdbGet	= dummydb_pkgdbGet,
    .pkgdbPut	= dummydb_pkgdbPut,
    .pkgdbDel	= dummydb_pkgdbDel,
    .pkgdbKey	= dummydb_pkgdbKey,

    .idxdbGet	= dummydb_idxdbGet,
    .idxdbPut	= dummydb_idxdbPut,
    .idxdbDel	= dummydb_idxdbDel,
    .idxdbKey	= dummydb_idxdbKey
};

