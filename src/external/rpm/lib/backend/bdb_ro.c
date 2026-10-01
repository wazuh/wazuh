#include "system.h"

#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "rpmdb_internal.h"
#include <rpm/rpmstring.h>
#include <rpm/rpmlog.h>

#define BDB_HASH 0
#define BDB_BTREE 1

struct dbiCursor_s;

struct bdb_kv {
    unsigned char *kv;
    unsigned int len;
};

struct bdb_db {
    int fd;			/* file descriptor of database */
    int type;			/* BDB_HASH / BDB_BTREE */
    unsigned int pagesize;
    unsigned int lastpage;
    int swapped;		/* different endianess? */
    /* btree */
    unsigned int root;		/* root page of the b-tree */
    /* hash */
    unsigned int maxbucket;
    unsigned int highmask;
    unsigned int lowmask;
    unsigned int spares[32];	/* spare pages for each splitpoint */
};

struct bdb_cur {
    struct bdb_db *db;

    struct bdb_kv key;		/* key and value from the db entry */
    struct bdb_kv val;

    unsigned char *page;	/* the page we're looking at */

    unsigned char *ovpage;
    struct bdb_kv keyov;	/* space to store oversized keys/values */
    struct bdb_kv valov;

    int state;			/* 1: onpage, -1: error */
    int idx;			/* entry index */
    int numidx;			/* number of entries on the page */
    int islookup;		/* we're doing a lookup operation */

    /* hash */
    unsigned int bucket;	/* current bucket */
};


static void swap16(unsigned char *p)
{
    int a = p[0];
    p[0] = p[1];
    p[1] = a;
}

static void swap32(unsigned char *p)
{
    int a = p[0];
    p[0] = p[3];
    p[3] = a;
    a = p[1];
    p[1] = p[2];
    p[2] = a;
}

static void swap32_2(unsigned char *p)
{
    swap32(p);
    swap32(p + 4);
}

static void bdb_swapmetapage(struct bdb_db *db, unsigned char *page)
{
    int i, maxi = db->type == BDB_HASH ? 224 : 92;
    for (i = 8; i < maxi; i += 4)
        swap32((unsigned char *)(page + i));
    swap32((unsigned char *)(page + 24));
}

static void bdb_swappage(struct bdb_db *db, unsigned char *page)
{
    unsigned int pagesize = db->pagesize;
    int type, i, nent, off;
    swap32(page + 8);		/* page number */
    swap32_2(page + 12);	/* prev/next page */
    swap16(page + 20);		/* nitems */
    swap16(page + 22);		/* highfree */

    type = page[25];
    if (type != 2 && type != 13 && type != 3 && type != 5)
	return;
    nent = *(uint16_t *)(page + 20);
    if (nent > (pagesize - 26) / 2)
	nent = (pagesize - 26) / 2;
    for (i = 0; i < nent; i++) {
	int minoff = 26 + nent * 2;
	swap16(page + 26 + i * 2);		/* offset */
	off = *(uint16_t *)(page + 26 + i * 2);
	if (off < minoff || off >= pagesize)
	    continue;
	if (type == 2 || type == 13) {		/* hash */
	    if (page[off] == 3 && off + 12 <= pagesize)
	        swap32_2(page + off + 4);	/* page no/length */
	} else if (type == 3) {			/* btree internal */
	    if (off + 12 > pagesize)
	        continue;
	    swap16(page + off);			/* length */
	    swap32_2(page + off + 4);		/* page no/num recs */
	    if (page[off + 2] == 3 && off + 24 <= pagesize)
		swap32_2(page + off + 16);	/* with overflow page/length */
	} else if (type == 5) {			/* btree leaf */
	    if (off + 3 <= pagesize && page[off + 2] == 1)
		swap16(page + off);		/* length */
	    else if (off + 12 <= pagesize && page[off + 2] == 3)
		swap32_2(page + off + 4);	/* overflow page/length */
	}
    }
}

static int bdb_getpage(struct bdb_db *db, unsigned char *page, unsigned int pageno)
{
    if (!pageno || pageno > db->lastpage)
	return -1;
    if (pread(db->fd, page, db->pagesize, (off_t)pageno * db->pagesize) != db->pagesize) {
	rpmlog(RPMLOG_ERR, "pread: %s\n", strerror(errno));
	return -1;
    }
    if (db->swapped)
	bdb_swappage(db, page);
    if (pageno != *(uint32_t *)(page + 8))
	return -1;
    return 0;
}

static void bdb_close(struct bdb_db *db)
{
    if (db->fd >= 0)
	close(db->fd);
    free(db);
}

static struct bdb_db *bdb_open(const char *name)
{
    uint32_t meta[512 / 4];
    int i, fd;
    struct bdb_db *db;

    fd = open(name, O_RDONLY);
    if (fd == -1) {
	return NULL;
    }
    db = (struct bdb_db *)xcalloc(1, sizeof(*db));
    db->fd = fd;
    if (pread(fd, meta, 512, 0) != 512) {
	rpmlog(RPMLOG_ERR, "%s: pread: %s\n", name, strerror(errno));
	bdb_close(db);
	return NULL;
    }
    if (meta[3] == 0x00061561 || meta[3] == 0x61150600) {
	db->type = BDB_HASH;
	db->swapped = meta[3] == 0x61150600;
    } else if (meta[3] == 0x00053162 || meta[3] == 0x62310500) {
	db->type = BDB_BTREE;
	db->swapped = meta[3] == 0x62310500;
    } else {
	rpmlog(RPMLOG_ERR, "%s: not a berkeley db hash/btree database\n", name);
	bdb_close(db);
	return NULL;
    }
    if (db->swapped)
        bdb_swapmetapage(db, (unsigned char *)meta);
    db->pagesize = meta[5];
    db->lastpage = meta[8];
    if (db->type == BDB_HASH) {
	if (meta[4] < 8 || meta[4] > 10) {
	    rpmlog(RPMLOG_ERR, "%s: unsupported hash version %d\n", name, meta[4]);
	    bdb_close(db);
	    return NULL;
	}
	db->maxbucket = meta[18];
	db->highmask = meta[19];
	db->lowmask = meta[20];
	for (i = 0; i < 32; i++)
	    db->spares[i] = meta[24 + i];
    }
    if (db->type == BDB_BTREE) {
	if (meta[4] < 9 || meta[4] > 10) {
	    rpmlog(RPMLOG_ERR, "%s: unsupported btree version %d\n", name, meta[4]);
	    bdb_close(db);
	    return NULL;
	}
	db->root = meta[22];
    }
    return db;
}


/****** overflow handling ******/

static int ovfl_get(struct bdb_cur *cur, struct bdb_kv *kv, struct bdb_kv *ov, uint32_t *pagenolen)
{
    unsigned int pageno = pagenolen[0];
    unsigned int len = pagenolen[1];
    unsigned int plen;
    unsigned char *p;

    if (len == 0)
	return -1;
    if (len > ov->len) {
	if (ov->kv)
	    ov->kv = xrealloc(ov->kv, len);
	else
	    ov->kv = (unsigned char *)xmalloc(len);
	ov->len = len;
    }
    if (!cur->ovpage)
	cur->ovpage = (unsigned char *)xmalloc(cur->db->pagesize);
    p = ov->kv;
    while (len > 0) {
	if (bdb_getpage(cur->db, cur->ovpage, pageno))
	    return -1;
	if (cur->ovpage[25] != 7)
	    return -1;
	plen = *(uint16_t *)(cur->ovpage + 22);
	if (plen + 26 > cur->db->pagesize || plen > len)
	    return -1;
	memcpy(p, cur->ovpage + 26, plen);
	p += plen;
	len -= plen;
	pageno = *(uint32_t *)(cur->ovpage + 16);
    }
    if (kv) {
	kv->kv = ov->kv;
	kv->len = pagenolen[1];
    }
    return 0;
}


/****** hash implementation ******/

static int hash_bucket_to_page(struct bdb_db *db, unsigned int bucket)
{
    unsigned int b;
    int i = 0;
    for (b = bucket; b; b >>= 1)
	i++;
    return bucket + db->spares[i];
}

static int hash_lookup(struct bdb_cur *cur, const unsigned char *key, unsigned int keyl)
{
    uint32_t bucket;
    unsigned int pg, i;
    cur->state = -1;
    for (bucket = 0, i = 0; i < keyl; i++)
	bucket = (bucket * 16777619) ^ key[i];
    bucket &= cur->db->highmask;
    if (bucket > cur->db->maxbucket)
	bucket &= cur->db->lowmask;
    cur->bucket = bucket;
    pg = hash_bucket_to_page(cur->db, bucket);
    if (bdb_getpage(cur->db, cur->page, pg))
	return -1;
    if (cur->page[25] != 8 && cur->page[25] != 13 && cur->page[25] != 2)
	return -1;
    cur->idx = (unsigned int)-2;
    cur->numidx = *(uint16_t *)(cur->page + 20);
    cur->state = 1;
    return 0;
}

static int hash_getkv(struct bdb_cur *cur, struct bdb_kv *kv, struct bdb_kv *ov, int off, int len)
{
    if (len <= 0 || off + len > cur->db->pagesize)
	return -1;
    if (cur->page[off] == 1) {
	kv->kv = cur->page + off + 1;
	kv->len = len - 1;
    } else if (cur->page[off] == 3) {
	uint32_t ovlpage[2];
	if (len != 12)
	    return -1;
	memcpy(ovlpage, cur->page + off + 4, 8);	/* off is unaligned */
	if (ovfl_get(cur, kv, ov, ovlpage))
	    return -1;
    } else {
	return -1;
    }
    return 0;
}

static int hash_next(struct bdb_cur *cur)
{
    int pagesize = cur->db->pagesize;
    int koff, klen, voff, vlen;
    if (!cur->state && hash_lookup(cur, 0, 0))
	return -1;
    cur->idx += 2;
    for (;;) {
	if (cur->idx + 1 >= cur->numidx) {
	    unsigned int pg;
	    cur->idx = cur->numidx = 0;
	    pg = *(uint32_t *)(cur->page + 16);
	    if (!pg) {
		if (cur->islookup || cur->bucket >= cur->db->maxbucket)
		    return 1;
		pg = hash_bucket_to_page(cur->db, ++cur->bucket);
	    }
	    if (bdb_getpage(cur->db, cur->page, pg))
		return -1;
	    if (cur->page[25] != 8 && cur->page[25] != 13 && cur->page[25] != 2)
		return -1;
	    cur->numidx = *(uint16_t *)(cur->page + 20);
	    continue;
	}
	koff = *(uint16_t *)(cur->page + 26 + 2 * cur->idx);
	voff = *(uint16_t *)(cur->page + 28 + 2 * cur->idx);
	if (koff >= pagesize || voff >= pagesize)
	    return -1;
	if (cur->idx == 0)
	    klen = pagesize - koff;
	else
	    klen = *(uint16_t *)(cur->page + 24 + 2 * cur->idx) - koff;
	vlen = koff - voff;
	if (hash_getkv(cur, &cur->key, &cur->keyov, koff, klen))
	    return -1;
	if (!cur->islookup && hash_getkv(cur, &cur->val, &cur->valov, voff, vlen))
	    return -1;
	return 0;
    }
}

static int hash_getval(struct bdb_cur *cur)
{
    int koff, voff;
    if (cur->state != 1 || cur->idx + 1 >= cur->numidx)
	return -1;
    koff = *(uint16_t *)(cur->page + 26 + 2 * cur->idx);
    voff = *(uint16_t *)(cur->page + 28 + 2 * cur->idx);
    return hash_getkv(cur, &cur->val, &cur->valov, voff, koff - voff);
}


/****** btree implementation ******/

static int btree_lookup(struct bdb_cur *cur, const unsigned char *key, unsigned int keylen)
{
    int pagesize = cur->db->pagesize;
    int off, lastoff, idx, numidx;
    unsigned int pg;
    unsigned char *ekey;
    unsigned int ekeylen;
    int cmp;

    cur->state = -1;
    pg = cur->db->root;
    for (;;) {
	if (bdb_getpage(cur->db, cur->page, pg))
	    return -1;
	if (cur->page[25] == 5)
	    break;		/* found leaf page */
	if (cur->page[25] != 3)
	    return -1;
	numidx = *(uint16_t *)(cur->page + 20);
	if (!numidx)
	    return -1;
	for (lastoff = 0, idx = 0; idx < numidx; idx++, lastoff = off) {
	    off = *(uint16_t *)(cur->page + 26 + 2 * idx);
	    if ((off & 3) != 0 || off + 3 > pagesize)
		return -1;
	    ekeylen = *(uint16_t *)(cur->page + off);
	    if (off + 12 + ekeylen > pagesize)
		return -1;
	    if (!keylen) {
		lastoff = off;
		break;
	    }
	    if (idx == 0)
		continue;
	    ekey = cur->page + off + 12;
	    if ((cur->page[off + 2] & 0x7f) == 3) {
		if (ekeylen != 12)
		    return -1;
		if (ovfl_get(cur, 0, &cur->keyov, (uint32_t *)(ekey + 4)))
		    return -1;
		ekeylen = *(uint32_t *)(ekey + 8);
		ekey = cur->keyov.kv;
	    } else if ((cur->page[off + 2] & 0x7f) != 1) {
	      return -1;
	    }
	    cmp = memcmp(ekey, key, keylen < ekeylen ? keylen : ekeylen);
	    if (cmp > 0 || (cmp == 0 && ekeylen > keylen))
		break;
	}
	pg = *(uint32_t *)(cur->page + lastoff + 4);
    }
    cur->idx = (unsigned int)-2;
    cur->numidx = *(uint16_t *)(cur->page + 20);
    cur->state = 1;
    return 0;
}

static int btree_getkv(struct bdb_cur *cur, struct bdb_kv *kv, struct bdb_kv *ov, int off)
{
    if ((off & 3) != 0)
	return -1;
    if (cur->page[off + 2] == 1) {
	int len = *(uint16_t *)(cur->page + off);
	if (off + 3 + len > cur->db->pagesize)
	    return -1;
	kv->kv = cur->page + off + 3;
	kv->len = len;
    } else if (cur->page[off + 2] == 3) {
	if (off + 12 > cur->db->pagesize)
	    return -1;
	if (ovfl_get(cur, kv, ov, (uint32_t *)(cur->page + off + 4)))
	    return -1;
    } else {
	return -1;
    }
    return 0;
}

static int btree_next(struct bdb_cur *cur)
{
    int pagesize = cur->db->pagesize;
    int koff, voff;
    if (!cur->state && btree_lookup(cur, 0, 0))
	return -1;
    cur->idx += 2;
    for (;;) {
	if (cur->idx + 1 >= cur->numidx) {
	    unsigned int pg;
	    cur->idx = cur->numidx = 0;
	    pg = *(uint32_t *)(cur->page + 16);
	    if (cur->islookup || !pg)
	      return 1;
	    if (bdb_getpage(cur->db, cur->page, pg))
		return -1;
	    if (cur->page[25] != 5)
		return -1;
	    cur->numidx = *(uint16_t *)(cur->page + 20);
	    continue;
	}
	koff = *(uint16_t *)(cur->page + 26 + 2 * cur->idx);
	voff = *(uint16_t *)(cur->page + 28 + 2 * cur->idx);
	if (koff + 3 > pagesize || voff + 3 > pagesize)
	    return -1;
	if ((cur->page[koff + 2] & 0x80) != 0 || (cur->page[voff + 2] & 0x80) != 0)
	    continue;	/* ignore deleted */
	if (btree_getkv(cur, &cur->key, &cur->keyov, koff))
	    return -1;
	if (!cur->islookup && btree_getkv(cur, &cur->val, &cur->valov, voff))
	    return -1;
	return 0;
    }
}

static int btree_getval(struct bdb_cur *cur)
{
    int voff;
    if (cur->state != 1 || cur->idx + 1 >= cur->numidx)
	return -1;
    voff = *(uint16_t *)(cur->page + 28 + 2 * cur->idx);
    return btree_getkv(cur, &cur->val, &cur->valov, voff);
}


/****** cursor functions ******/

static struct bdb_cur *cur_open(struct bdb_db *db)
{
    struct bdb_cur *cur = (struct bdb_cur *)xcalloc(1, sizeof(*cur));
    cur->db = db;
    cur->page = (unsigned char *)xmalloc(db->pagesize);
    return cur;
}

static void cur_close(struct bdb_cur *cur)
{
    if (cur->page)
	free(cur->page);
    if (cur->ovpage)
	free(cur->ovpage);
    if (cur->keyov.kv)
	free(cur->keyov.kv);
    if (cur->valov.kv)
	free(cur->valov.kv);
    free(cur);
}

static int cur_next(struct bdb_cur *cur)
{
    if (cur->state < 0)
	return -1;
    if (cur->db->type == BDB_HASH)
	return hash_next(cur);
    if (cur->db->type == BDB_BTREE)
	return btree_next(cur);
    return -1;
}

static int cur_getval(struct bdb_cur *cur)
{
    if (cur->state < 0)
	return -1;
    if (cur->db->type == BDB_HASH)
	return hash_getval(cur);
    if (cur->db->type == BDB_BTREE)
	return btree_getval(cur);
    return -1;
}

static int cur_lookup(struct bdb_cur *cur, const unsigned char *key, unsigned int keyl)
{
    int r = -1;
    if (cur->db->type == BDB_HASH)
	r = hash_lookup(cur, key, keyl);
    if (cur->db->type == BDB_BTREE)
	r = btree_lookup(cur, key, keyl);
    if (r != 0)
	return r;
    cur->islookup = 1;
    while ((r = cur_next(cur)) == 0)
	if (keyl == cur->key.len && !memcmp(key, cur->key.kv, keyl))
	    break;
    cur->islookup = 0;
    if (r == 0)
	r = cur_getval(cur);
    return r;
}

static int cur_lookup_ge(struct bdb_cur *cur, const unsigned char *key, unsigned int keyl)
{
    int r = -1;
    if (cur->db->type == BDB_BTREE)
	r = btree_lookup(cur, key, keyl);
    if (r != 0)
	return r;
    cur->islookup = 1;
    while ((r = cur_next(cur)) == 0) {
	unsigned int ekeyl = cur->key.len;
	int cmp = memcmp(cur->key.kv, key, keyl < ekeyl ? keyl : ekeyl);
	if (cmp > 0 || (cmp == 0 && ekeyl >= keyl))
	    break;
    }
    cur->islookup = 0;
    if (r == 0)
	r = cur_getval(cur);
    else if (r == 1)
	r = cur_next(cur);
    return r;
}

/****** glue code ******/

static unsigned int getui32(unsigned char *x, int swapped)
{
    union _dbswap bs;
    memcpy(bs.uc, x, 4);
    if (swapped)
      _DBSWAP(bs);
    return bs.ui;
}

static void setui32(unsigned char *x, uint32_t v, int swapped)
{
    union _dbswap bs;
    bs.ui = v;
    if (swapped)
      _DBSWAP(bs);
    memcpy(x, bs.uc, 4);
}

static void log_error(dbiIndex dbi)
{
    rpmlog(RPMLOG_ERR, "bdb_ro error reading %s database\n", dbi->dbi_file);
}

static int bdbro_Open(rpmdb rdb, rpmDbiTagVal rpmtag, dbiIndex * dbip, int flags)
{
    const char *dbhome = rpmdbHome(rdb);
    dbiIndex dbi = NULL;
    char *path;

    if (dbip)
	*dbip = NULL;
    if ((rdb->db_mode & O_ACCMODE) != O_RDONLY)
	return EPERM;
    if ((dbi = dbiNew(rdb, rpmtag)) == NULL)
	return 1;
    path = rstrscat(NULL, dbhome, "/", dbi->dbi_file, NULL);
    rpmlog(RPMLOG_DEBUG, "opening  db index       %s\n", path);
    dbi->dbi_db = bdb_open(path);
    if (!dbi->dbi_db) {
	int lvl = (dbi->dbi_type == DBI_PRIMARY) ? RPMLOG_ERR : RPMLOG_WARNING;
	rpmlog(lvl, "could not open %s: %s\n", path, strerror(errno));
	if (dbi->dbi_type == DBI_PRIMARY) {
	    free(path);
	    dbiFree(dbi);
	    return 1;
	}
    }
    free(path);
    dbi->dbi_flags |= DBI_RDONLY;
    if (dbip)
	*dbip = dbi;
    else
	(void) dbiClose(dbi, 0);
    return 0;
}

static int bdbro_Close(dbiIndex dbi, unsigned int flags)
{
    if (dbi->dbi_db)
	bdb_close((struct bdb_db *)dbi->dbi_db);
    dbiFree(dbi);
    return 0;
}

static int bdbro_Verify(dbiIndex dbi, unsigned int flags)
{
    return 0;
}

static void bdbro_SetFSync(rpmdb rdb, int enable)
{
}

static int bdbro_Ctrl(rpmdb rdb, dbCtrlOp ctrl)
{
    return 0;
}

static dbiCursor bdbro_CursorInit(dbiIndex dbi, unsigned int flags)
{
    /* Secondary indexes may be missing */
    return (dbi && dbi->dbi_db) ? (dbiCursor)cur_open((struct bdb_db *)dbi->dbi_db) : NULL;
}

static dbiCursor bdbro_CursorFree(dbiIndex dbi, dbiCursor dbc)
{
    if (dbc)
	cur_close((struct bdb_cur *)dbc);
    return NULL;
}

static void appenddbt(dbiCursor dbc, unsigned char *val, unsigned int vallen, dbiIndexSet *setp)
{
    struct bdb_cur *cur = (struct bdb_cur *)dbc;
    dbiIndexSet set;
    unsigned int i;

    set = dbiIndexSetNew(vallen / (2 * sizeof(uint32_t)));
    set->count = vallen / (2 * sizeof(uint32_t));

    for (i = 0; i < set->count; i++, val += 8) {
	set->recs[i].hdrNum = getui32(val, cur->db->swapped);
	set->recs[i].tagNum = getui32(val + 4, cur->db->swapped);
    }
    if (*setp == NULL) {
	*setp = set;
    } else {
	dbiIndexSetAppendSet(*setp, set, 0);
	dbiIndexSetFree(set);
    }
}

static rpmRC bdbro_idxdbPut(dbiIndex dbi, rpmTagVal rpmtag, unsigned int hdrNum, Header h)
{
    return RPMRC_FAIL;
}

static rpmRC bdbro_idxdbDel(dbiIndex dbi, rpmTagVal rpmtag, unsigned int hdrNum, Header h)
{
    return RPMRC_FAIL;
}

static rpmRC bdbro_idxdbGet(dbiIndex dbi, dbiCursor dbc, const char *keyp, size_t keylen,
                          dbiIndexSet *set, int searchType)
{
    struct bdb_cur *cur = (struct bdb_cur *)dbc;
    int r;

    if (!cur)
	return RPMRC_FAIL;
    if (searchType == DBC_PREFIX_SEARCH) {
	rpmRC rc = RPMRC_NOTFOUND;
	if (!keyp)
	    return RPMRC_FAIL;
	r = cur_lookup_ge(cur, (const unsigned char *)keyp, keylen);
	for (; r == 0; r = cur_next(cur)) {
	    if (cur->key.len < keylen || memcmp(cur->key.kv, keyp, keylen) != 0)
		break;
	    if (set)
		appenddbt(dbc, cur->val.kv, cur->val.len, set);
	    rc = RPMRC_OK;
	}
	if (r == -1)
	    log_error(dbi);
	cur->key.kv = 0;
	return r == -1 ? RPMRC_FAIL : rc;
    }
    if (keyp) {
	if (keylen == 0) {
	    keyp = "";
	    keylen = 1;
	}
	r = cur_lookup(cur, (const unsigned char *)keyp, keylen);
    } else {
	r = cur_next(cur);
    }
    if (r == 0) {
	if (set)
	    appenddbt(dbc, cur->val.kv, cur->val.len, set);
	return RPMRC_OK;
    }
    if (r == -1)
	log_error(dbi);
    cur->key.kv = 0;
    return r == 1 ? RPMRC_NOTFOUND : RPMRC_FAIL;
}

static const void *bdbro_idxdbKey(dbiIndex dbi, dbiCursor dbc, unsigned int *keylen)
{
    struct bdb_cur *cur = (struct bdb_cur *)dbc;
    if (!cur || !cur->key.kv)
	return 0;
    if (keylen)
	*keylen = cur->key.len;
    return cur->key.kv;
}

static rpmRC bdbro_pkgdbPut(dbiIndex dbi, dbiCursor dbc,  unsigned int *hdrNum,
	unsigned char *hdrBlob, unsigned int hdrLen)
{
    return RPMRC_FAIL;
}

static rpmRC bdbro_pkgdbDel(dbiIndex dbi, dbiCursor dbc, unsigned int hdrNum)
{
    return RPMRC_FAIL;
}

static rpmRC bdbro_pkgdbGet(dbiIndex dbi, dbiCursor dbc, unsigned int hdrNum,
	unsigned char **hdrBlob, unsigned int *hdrLen)
{
    struct bdb_cur *cur = (struct bdb_cur *)dbc;
    int r;
    if (hdrNum) {
	unsigned char hdrkey[4];
        setui32(hdrkey, hdrNum, cur->db->swapped);
	r = cur_lookup(cur, hdrkey, 4);
    } else {
	r = cur_next(cur);
    }
    if (r == 0) {
	if (hdrBlob)
	    *hdrBlob = cur->val.kv;
	if (hdrLen)
	    *hdrLen = cur->val.len;
	return RPMRC_OK;
    }
    if (r == -1)
	log_error(dbi);
    cur->key.kv = 0;
    return r == 1 ? RPMRC_NOTFOUND : RPMRC_FAIL;
}

static unsigned int bdbro_pkgdbKey(dbiIndex dbi, dbiCursor dbc)
{
    struct bdb_cur *cur = (struct bdb_cur *)dbc;
    if (!cur || !cur->key.kv || cur->key.len != 4)
        return 0;
    return getui32(cur->key.kv, cur->db->swapped);
}

struct rpmdbOps_s bdbro_dbops = {
    .name       = "bdb_ro",
    .path       = "Packages",

    .open       = bdbro_Open,
    .close      = bdbro_Close,
    .verify     = bdbro_Verify,
    .setFSync   = bdbro_SetFSync,
    .ctrl       = bdbro_Ctrl,

    .cursorInit = bdbro_CursorInit,
    .cursorFree = bdbro_CursorFree,

    .pkgdbGet   = bdbro_pkgdbGet,
    .pkgdbPut   = bdbro_pkgdbPut,
    .pkgdbDel   = bdbro_pkgdbDel,
    .pkgdbKey   = bdbro_pkgdbKey,

    .idxdbGet   = bdbro_idxdbGet,
    .idxdbPut   = bdbro_idxdbPut,
    .idxdbDel   = bdbro_idxdbDel,
    .idxdbKey   = bdbro_idxdbKey
};

