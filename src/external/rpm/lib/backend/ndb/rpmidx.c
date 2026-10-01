#include "system.h"

#include <rpm/rpmlog.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <errno.h>

#ifdef __APPLE__
#include <machine/endian.h>
#include <libkern/OSByteOrder.h>
#define htole32(x) OSSwapHostToLittleInt32(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)
#else
#include <endian.h>
#endif /* __APPLE__ */

#include "rpmidx.h"
#include "rpmxdb.h"

/* Index database
 *
 *
 * Layout:
 *    Header
 *    Slots
 *    Keys
 *
 * Each slot contains 12 bytes, they are split into a 8 byte
 * and a 4 byte part:
 *    4 bytes   key offset + extra tag bits
 *    4 bytes   data
 *    4 bytes   data overflow
 * The slot space first contains all 8 byte parts followed by all of
 * the 4 byte overflow parts. This is done because most of the time we
 * do not need the latter.
 *
 * If a new (key, pkgidx, datidx) tupel is added, the key is hashed with
 * the popular murmur hash. The lower bits of the hash determine the start
 * slot, parts of the higher bits are used as extra key equality check.
 * The (pkgidx, datidx) pair is encoded in a (data, dataovl) pair, so that
 * most of the time dataovl is zero.
 * 
 * The code then checks the current entry at the start slot. If the key
 * does not match, it advances to the next slot. If it matches, it also
 * checks the data part for a match but it remembers the key offset.
 * If the code found a (key, data, dataovl) match, nothing needs to be done.
 *
 * Otherwise, the code arrived at an empty slot. It then adds the key
 * to the key space if it did not find a matching key, and then puts
 * the encoded (key, data, dataovl) pair into the slot.
 *
 * Deleting a (key, data) pair is done by replacing the slot with a
 * (-1, -1, 0) dummy entry.
 *
 */


typedef struct rpmidxdb_s {
    rpmpkgdb pkgdb;		/* main database */

    int flags;
    int mode;

    int rdonly;

    /* xdb support */
    rpmxdb xdb;
    unsigned int xdbtag;
    unsigned int xdbid;

    unsigned char *head_mapped;
    unsigned char *slot_mapped;
    unsigned char *key_mapped;
    unsigned int key_size;
    unsigned int file_size;

    unsigned int generation;
    unsigned int nslots;
    unsigned int usedslots;
    unsigned int dummyslots;

    unsigned int keyend;
    unsigned int keyexcess;

    unsigned int hmask;
    unsigned int xmask;

    unsigned int pagesize;
} * rpmidxdb;

static inline unsigned int le2h(unsigned char *p) 
{
    return p[0] | p[1] << 8 | p[2] << 16 | p[3] << 24;
}

static inline void h2le(unsigned int x, unsigned char *p) 
{
    p[0] = x;
    p[1] = x >> 8; 
    p[2] = x >> 16;
    p[3] = x >> 24;
}

/* aligned versions */
static inline unsigned int le2ha(unsigned char *p) 
{
    unsigned int x = *(unsigned int *)p;
    return le32toh(x);
}

static inline void h2lea(unsigned int x, unsigned char *p) 
{
    *(unsigned int *)p = htole32(x);
}

/*** Header management ***/

#define IDXDB_MAGIC     ('R' | 'p' << 8 | 'm' << 16 | 'I' << 24)
#define IDXDB_VERSION	0

#define IDXDB_OFFSET_MAGIC	0
#define IDXDB_OFFSET_VERSION	4
#define IDXDB_OFFSET_GENERATION	8
#define IDXDB_OFFSET_NSLOTS	12
#define IDXDB_OFFSET_USEDSLOTS	16
#define IDXDB_OFFSET_DUMMYSLOTS	20
#define IDXDB_OFFSET_XMASK	24
#define IDXDB_OFFSET_KEYEND	28
#define IDXDB_OFFSET_KEYEXCESS	32
#define IDXDB_OFFSET_OBSOLETE	36

#define IDXDB_SLOT_OFFSET	64
#define IDXDB_KEY_CHUNKSIZE	4096

/* XDB subids */

#define IDXDB_XDB_SUBTAG		0
#define IDXDB_XDB_SUBTAG_REBUILD	1

static void set_mapped(rpmidxdb idxdb, unsigned char *addr, unsigned int size)
{
    if (addr) {
	idxdb->head_mapped = addr;
	idxdb->slot_mapped = addr + IDXDB_SLOT_OFFSET; 
	idxdb->key_mapped = addr + IDXDB_SLOT_OFFSET + idxdb->nslots * 12;
	idxdb->key_size = size - (IDXDB_SLOT_OFFSET + idxdb->nslots * 12);
	idxdb->file_size = size;
    } else {
	idxdb->head_mapped = idxdb->slot_mapped = idxdb->key_mapped = 0;
	idxdb->file_size = idxdb->key_size = 0;
    }
}

/* XDB callbacks */
static void mapcb(rpmxdb xdb, void *data, void *newaddr, size_t newsize) {
    set_mapped((rpmidxdb)data, newaddr, (unsigned int)newsize);
}

static int rpmidxMap(rpmidxdb idxdb)
{
    if (rpmxdbMapBlob(idxdb->xdb, idxdb->xdbid, idxdb->rdonly ? O_RDONLY : O_RDWR, mapcb, idxdb))
	return RPMRC_FAIL;
    if (idxdb->file_size < 4096) {
	rpmxdbUnmapBlob(idxdb->xdb, idxdb->xdbid);
	return RPMRC_FAIL;
    }
    return RPMRC_OK;
}

static void rpmidxUnmap(rpmidxdb idxdb)
{
    if (!idxdb->head_mapped)
	return;
    rpmxdbUnmapBlob(idxdb->xdb, idxdb->xdbid);
}

static int rpmidxReadHeader(rpmidxdb idxdb)
{
    unsigned int version;

    if (idxdb->head_mapped) {
	if (le2ha(idxdb->head_mapped + IDXDB_OFFSET_GENERATION) == idxdb->generation)
	    return RPMRC_OK;
	rpmidxUnmap(idxdb);
    }
    idxdb->nslots = 0;
    if (rpmidxMap(idxdb))
	return RPMRC_FAIL;

    if (le2ha(idxdb->head_mapped + IDXDB_OFFSET_MAGIC) != IDXDB_MAGIC) {
	rpmidxUnmap(idxdb);
	return RPMRC_FAIL;
    }
    version = le2ha(idxdb->head_mapped + IDXDB_OFFSET_VERSION);
    if (version != IDXDB_VERSION) {
	rpmlog(RPMLOG_ERR, _("rpmidx: Version mismatch. Expected version: %u. "
	    "Found version: %u\n"), IDXDB_VERSION, version);
	rpmidxUnmap(idxdb);
	return RPMRC_FAIL;
    }
    idxdb->generation = le2ha(idxdb->head_mapped + IDXDB_OFFSET_GENERATION);
    idxdb->nslots     = le2ha(idxdb->head_mapped + IDXDB_OFFSET_NSLOTS);
    idxdb->usedslots  = le2ha(idxdb->head_mapped + IDXDB_OFFSET_USEDSLOTS);
    idxdb->dummyslots = le2ha(idxdb->head_mapped + IDXDB_OFFSET_DUMMYSLOTS);
    idxdb->xmask      = le2ha(idxdb->head_mapped + IDXDB_OFFSET_XMASK);
    idxdb->keyend     = le2ha(idxdb->head_mapped + IDXDB_OFFSET_KEYEND);
    idxdb->keyexcess  = le2ha(idxdb->head_mapped + IDXDB_OFFSET_KEYEXCESS);

    /* make sure data is sane */
    if (idxdb->nslots < 256 || (idxdb->nslots & (idxdb->nslots - 1)) != 0 ||
	    idxdb->usedslots > idxdb->nslots || idxdb->dummyslots > idxdb->nslots ||
	    idxdb->nslots >= (0xffffffffU - IDXDB_SLOT_OFFSET) / 12) {
	rpmidxUnmap(idxdb);	/* too small, somthing is wrong */
	return RPMRC_FAIL;
    }

    idxdb->hmask = idxdb->nslots - 1;

    /* now that we know nslots we can split between slots and keys */
    if (idxdb->file_size <= IDXDB_SLOT_OFFSET + idxdb->nslots * 12) {
	rpmidxUnmap(idxdb);	/* too small, somthing is wrong */
	return RPMRC_FAIL;
    }
    idxdb->key_mapped = idxdb->slot_mapped + idxdb->nslots * 12;
    idxdb->key_size = idxdb->file_size - (IDXDB_SLOT_OFFSET + idxdb->nslots * 12);
    return RPMRC_OK;
}

static int rpmidxWriteHeader(rpmidxdb idxdb)
{
    if (!idxdb->head_mapped)
	return RPMRC_FAIL;
    h2lea(IDXDB_MAGIC,       idxdb->head_mapped + IDXDB_OFFSET_MAGIC);
    h2lea(IDXDB_VERSION,     idxdb->head_mapped + IDXDB_OFFSET_VERSION);
    h2lea(idxdb->generation, idxdb->head_mapped + IDXDB_OFFSET_GENERATION);
    h2lea(idxdb->nslots,     idxdb->head_mapped + IDXDB_OFFSET_NSLOTS);
    h2lea(idxdb->usedslots,  idxdb->head_mapped + IDXDB_OFFSET_USEDSLOTS);
    h2lea(idxdb->dummyslots, idxdb->head_mapped + IDXDB_OFFSET_DUMMYSLOTS);
    h2lea(idxdb->xmask,      idxdb->head_mapped + IDXDB_OFFSET_XMASK);
    h2lea(idxdb->keyend,     idxdb->head_mapped + IDXDB_OFFSET_KEYEND);
    h2lea(idxdb->keyexcess,  idxdb->head_mapped + IDXDB_OFFSET_KEYEXCESS);
    return RPMRC_OK;
}

static inline void updateUsedslots(rpmidxdb idxdb)
{
    h2lea(idxdb->usedslots, idxdb->head_mapped + IDXDB_OFFSET_USEDSLOTS);
}

static inline void updateDummyslots(rpmidxdb idxdb)
{
    h2lea(idxdb->dummyslots, idxdb->head_mapped + IDXDB_OFFSET_DUMMYSLOTS);
}

static inline void updateKeyend(rpmidxdb idxdb)
{
    h2lea(idxdb->keyend, idxdb->head_mapped + IDXDB_OFFSET_KEYEND);
}

static inline void updateKeyexcess(rpmidxdb idxdb)
{
    h2lea(idxdb->keyexcess, idxdb->head_mapped + IDXDB_OFFSET_KEYEXCESS);
}

static inline void bumpGeneration(rpmidxdb idxdb)
{
    idxdb->generation++;
    h2lea(idxdb->generation, idxdb->head_mapped + IDXDB_OFFSET_GENERATION);
}

/*** Key management ***/

#define MURMUR_M 0x5bd1e995

static unsigned int murmurhash(const unsigned char *s, unsigned int l)
{
    unsigned int h =  l * MURMUR_M;

    while (l >= 4) {
	h += s[0] | s[1] << 8 | s[2] << 16 | s[3] << 24;
	h *= MURMUR_M;
	h ^= h >> 16;
	s += 4;
	l -= 4;
    }
    switch (l) {
	case 3:
	    h += s[2] << 16; 
	case 2:
	    h += s[1] << 8;
	case 1:
	    h += s[0];
	    h *= MURMUR_M;
	    h ^= h >> 16;
	default:
	    break;
    }
    h *= MURMUR_M;
    h ^= h >> 10; 
    h *= MURMUR_M;
    h ^= h >> 17; 
    return h;
}

static inline unsigned int decodekeyl(unsigned char *p, unsigned int *hl)
{
    if (*p != 255) {
	*hl = 1;
	return *p;
    } else if (p[1] != 255 || p[2] != 255) {
	*hl = 3;
	return p[1] | p[2] << 8;
    } else {
	*hl = 7;
	return p[3] | p[4] << 8 | p[5] << 16 | p[6] << 24;
    }
}

static inline void encodekeyl(unsigned char *p, unsigned int keyl)
{
    if (keyl && keyl < 255) {
	p[0] = keyl;
    } else if (keyl < 65535) {
	p[0] = 255;
	p[1] = keyl;
	p[2] = keyl >> 8;
    } else {
	p[0] = 255;
	p[1] = 255;
	p[2] = 255;
	p[3] = keyl;
	p[4] = keyl >> 8;
	p[5] = keyl >> 16;
	p[6] = keyl >> 24;
    }
}

static inline unsigned int keylsize(unsigned int keyl)
{
    return keyl && keyl < 255 ? 1 : keyl < 65535 ? 3 : 7;
}

static inline int equalkey(rpmidxdb idxdb, unsigned int off, const unsigned char *key, unsigned int keyl)
{
    unsigned char *p;
    if (off + keyl + 1 > idxdb->keyend)
	return 0;
    p = idxdb->key_mapped + off;
    if (keyl && keyl < 255) {
	if (*p != keyl)
	    return 0;
	p += 1;
    } else if (keyl < 65535) {
	if (p[0] != 255 || (p[1] | p[2] << 8) != keyl)
	    return 0;
	p += 3;
    } else {
	if (p[0] != 255 || p[1] != 255 || p[2] != 255 || (p[3] | p[4] << 8 | p[5] << 16 | p[6] << 24) != keyl)
	    return 0;
	p += 7;
    }
    if (keyl && memcmp(key, p, keyl))
	return 0;
    return 1;
}

static int addkeypage(rpmidxdb idxdb) {
    unsigned int addsize = idxdb->pagesize > IDXDB_KEY_CHUNKSIZE ? idxdb->pagesize : IDXDB_KEY_CHUNKSIZE;

    if (addsize > 0xffffffffU - idxdb->file_size)
	return RPMRC_FAIL;
    if (rpmxdbResizeBlob(idxdb->xdb, idxdb->xdbid, idxdb->file_size + addsize))
	return RPMRC_FAIL;
    return RPMRC_OK;
}

static int addnewkey(rpmidxdb idxdb, const unsigned char *key, unsigned int keyl, unsigned int *keyoffp)
{
    int hl = keylsize(keyl);
    while (idxdb->key_size - idxdb->keyend < hl + keyl) {
	if (addkeypage(idxdb))
	    return RPMRC_FAIL;
    }
    encodekeyl(idxdb->key_mapped + idxdb->keyend, keyl);
    if (keyl)
	memcpy(idxdb->key_mapped + idxdb->keyend + hl, key, keyl);
    *keyoffp = idxdb->keyend;
    idxdb->keyend += hl + keyl;
    updateKeyend(idxdb);
    return RPMRC_OK;
}


/*** Data encoding/decoding ***/

/* Encode a (pkgidx, datidx) tuple into a (data, ovldata) tuple in a way
 * that most of the time ovldata will be zero. */
static inline unsigned int encodedata(rpmidxdb idxdb, unsigned int pkgidx, unsigned int datidx, unsigned int *ovldatap)
{
    if (pkgidx < 0x100000 && datidx < 0x400) {
	*ovldatap = 0;
	return pkgidx | datidx << 20;
    } else if (pkgidx < 0x1000000 && datidx < 0x40) {
	*ovldatap = 0;
	return pkgidx | datidx << 24 | 0x40000000;
    } else {
	*ovldatap = pkgidx;
	return datidx | 0x80000000;
    }
}

/* Decode (data, ovldata) back into (pkgidx, datidx) */
static inline unsigned int decodedata(rpmidxdb idxdb, unsigned int data, unsigned int ovldata, unsigned int *datidxp)
{
    if (data & 0x80000000) {
	*datidxp = data ^ 0x80000000;
	return ovldata;
    } else if (data & 0x40000000) {
	*datidxp = (data ^ 0x40000000) >> 24;
	return data & 0xffffff;
    } else {
	*datidxp = data >> 20;
	return data & 0xfffff;
    }
}


/*** Rebuild helpers ***/

/* copy a single data entry into the new database */
static inline void copyentry(rpmidxdb idxdb, unsigned int keyh, unsigned int newkeyoff, unsigned int data, unsigned int ovldata)
{
    unsigned int h, hh = 7;
    unsigned char *ent;
    unsigned int hmask = idxdb->hmask;
    unsigned int x;
    
    /* find an empty slot */
    for (h = keyh & hmask;; h = (h + hh++) & hmask) {
	ent = idxdb->slot_mapped + 8 * h;
	x = le2ha(ent);
	if (x == 0)
	    break;
    }
    /* write data */
    h2lea(newkeyoff, ent);
    h2lea(data, ent + 4);
    if (ovldata)
	h2lea(ovldata, idxdb->slot_mapped + idxdb->nslots * 8 + 4 * h);
    idxdb->usedslots++;
}

/* copy all entries belonging to a single key from the old database into the new database */
static inline void copykeyentries(const unsigned char *key, unsigned int keyl, rpmidxdb idxdb, unsigned int oldkeyoff, rpmidxdb nidxdb, unsigned int newkeyoff, unsigned char *done)
{
    unsigned int h, hh;
    unsigned int keyh = murmurhash(key, keyl);
    unsigned int hmask = idxdb->hmask;

    oldkeyoff |= keyh & idxdb->xmask;
    newkeyoff |= keyh & nidxdb->xmask;
    for (h = keyh & hmask, hh = 7; ; h = (h + hh++) & hmask) {
	unsigned char *ent = idxdb->slot_mapped + 8 * h;
	unsigned int data, ovldata;
	unsigned int x = le2ha(ent);
	if (x == 0)
	    break;
	if (x != oldkeyoff)
	    continue;
	data = le2ha(ent + 4);
	ovldata = (data & 0x80000000) ? le2ha(idxdb->slot_mapped + idxdb->nslots * 8 + 4 * h) : 0;
	copyentry(nidxdb, keyh, newkeyoff, data, ovldata);
	done[h >> 3] |= 1 << (h & 7);
    }
}

static int rpmidxRebuildInternal(rpmidxdb idxdb)
{
    struct rpmidxdb_s nidxdb_s, *nidxdb;
    unsigned int i, nslots;
    unsigned int keyend, keyoff, xmask;
    unsigned char *done;
    unsigned char *ent;
    unsigned int file_size, key_size, xfile_size;

    nidxdb = &nidxdb_s;
    memset(nidxdb, 0, sizeof(*nidxdb));
    nidxdb->pagesize = rpmxdbPagesize(idxdb->xdb);

    /* calculate nslots the hard way, don't trust usedslots */
    nslots = 0;
    for (i = 0, ent = idxdb->slot_mapped; i < idxdb->nslots; i++, ent += 8) {
	unsigned int x = le2ha(ent);
	if (x != 0 && x != -1)
	    nslots++;
    }
    if (nslots < 256)
	nslots = 256;
    while (nslots & (nslots - 1))
	nslots = nslots & (nslots - 1);
    nslots *= 4;
    if (nslots < 256 || nslots >= (0xffffffffU - IDXDB_SLOT_OFFSET) / 12)
	return RPMRC_FAIL;

    nidxdb->nslots = nslots;
    nidxdb->hmask = nslots - 1;

    /* calculate the new key space size */
    key_size = idxdb->keyend;
    if (key_size < IDXDB_KEY_CHUNKSIZE)
	key_size = IDXDB_KEY_CHUNKSIZE;
    if (key_size >= 0xffffffffU - (IDXDB_SLOT_OFFSET + nslots * 12))
	return RPMRC_FAIL;

    file_size = IDXDB_SLOT_OFFSET + nslots * 12 + key_size;

    /* round file size to multiple of the page size */
    if (file_size & (nidxdb->pagesize - 1)) {
	unsigned int add = nidxdb->pagesize - (file_size & (nidxdb->pagesize - 1));
	if (add > 0xffffffffU - file_size)
	    return RPMRC_FAIL;
	file_size += add;
	key_size += add;
    }

    /* calculate xmask, leave at least 8192 bytes headroom for key space */
    for (xmask = 0x00010000; xmask && xmask < key_size + 8192; xmask <<= 1)
      ;
    xmask = xmask ? ~(xmask - 1) : 0;
    nidxdb->xmask = xmask;

    /* create new database */
    nidxdb->xdb = idxdb->xdb;
    nidxdb->xdbtag = idxdb->xdbtag;
    if (rpmxdbLookupBlob(nidxdb->xdb, &nidxdb->xdbid, idxdb->xdbtag, IDXDB_XDB_SUBTAG_REBUILD, O_CREAT|O_TRUNC)) {
	return RPMRC_FAIL;
    }
    if (rpmxdbResizeBlob(nidxdb->xdb, nidxdb->xdbid, file_size)) {
	return RPMRC_FAIL;
    }
    if (rpmidxMap(nidxdb)) {
	return RPMRC_FAIL;
    }

    /* copy all entries */
    done = xcalloc(idxdb->nslots / 8 + 1, 1);
    keyend = 1;
    for (i = 0, ent = idxdb->slot_mapped; i < idxdb->nslots; i++, ent += 8) {
	unsigned int x = le2ha(ent);
	unsigned char *key;
	unsigned int keyl, hl;

	if (x == 0 || x == -1)
	    continue;
	if (done[i >> 3] & (1 << (i & 7))) {
	    continue;	/* we already did that one */
	}
	x &= ~idxdb->xmask;
	key = idxdb->key_mapped + x;
	keyl = decodekeyl(key, &hl);
	keyoff = keyend;
	keyend += hl + keyl;
	memcpy(nidxdb->key_mapped + keyoff, key, hl + keyl);
	copykeyentries(key + hl, keyl, idxdb, x, nidxdb, keyoff, done);
    }
    free(done);
    nidxdb->keyend = keyend;
    nidxdb->generation = idxdb->generation + 1;
    rpmidxWriteHeader(nidxdb);
    rpmidxUnmap(nidxdb);

    /* shrink if we have allocated excessive key space */
    xfile_size = file_size - key_size + keyend + IDXDB_KEY_CHUNKSIZE;
    xfile_size = (xfile_size + nidxdb->pagesize - 1) & ~(nidxdb->pagesize - 1);
    if (xfile_size < file_size)
	rpmxdbResizeBlob(nidxdb->xdb, nidxdb->xdbid, xfile_size);

    /* now switch over to new database */
    rpmidxUnmap(idxdb);
    if (rpmxdbRenameBlob(nidxdb->xdb, &nidxdb->xdbid, idxdb->xdbtag, IDXDB_XDB_SUBTAG))
	return RPMRC_FAIL;
    idxdb->xdbid = nidxdb->xdbid;
    if (rpmidxReadHeader(idxdb))
	return RPMRC_FAIL;
    return RPMRC_OK;
}

/* check if we need to rebuild the index. We need to do this if
 * - there are too many used slot, so hashing is inefficient
 * - there is too much key excess (i.e. holes in the keys)
 * - our keys grew so much that they need more bits
 */
static int rpmidxCheck(rpmidxdb idxdb)
{
    if (idxdb->usedslots > idxdb->nslots / 2 ||
	(idxdb->keyexcess > 4096 && idxdb->keyexcess * 4 > idxdb->keyend) ||
	idxdb->keyend >= ~idxdb->xmask) {
	if (rpmidxRebuildInternal(idxdb))
	    return RPMRC_FAIL;
    }
    return RPMRC_OK;
}

static int rpmidxPutInternal(rpmidxdb idxdb, const unsigned char *key, unsigned int keyl, unsigned int pkgidx, unsigned int datidx)
{
    unsigned int keyh = murmurhash(key, keyl);
    unsigned int keyoff = 0;
    unsigned int freeh = -1;
    unsigned int x, h, hh = 7;
    unsigned int hmask;
    unsigned int xmask;
    unsigned char *ent;
    unsigned int data, ovldata;

    if (datidx >= 0x80000000)
	return RPMRC_FAIL;
    if (keyl >= 0x80000000)
	return RPMRC_FAIL;
    if (rpmidxCheck(idxdb))
	return RPMRC_FAIL;
    data = encodedata(idxdb, pkgidx, datidx, &ovldata);
    hmask = idxdb->hmask;
    xmask = idxdb->xmask;
    for (h = keyh & hmask; ; h = (h + hh++) & hmask) {
	ent = idxdb->slot_mapped + 8 * h;
	x = le2ha(ent);
	if (x == 0)		/* reached an empty slot */
	    break;
	if (x == -1) {
	    freeh = h;		/* found a dummy slot, remember the position */
	    continue;
	}
	if (!keyoff) {
	    if (((x ^ keyh) & xmask) != 0)
		continue;
	    if (!equalkey(idxdb, x & ~xmask, key, keyl))
		continue;
	    keyoff = x;
	}
	if (keyoff != x)
	    continue;
	/* string matches, check data/ovldata */
	if (le2ha(ent + 4) == data) {
	    if (!ovldata || le2ha(idxdb->slot_mapped + idxdb->nslots * 8 + 4 * h) == ovldata)
		return RPMRC_OK;	/* already in database */
	}
	/* continue searching */
    }
    if (!keyoff) {
	/* we did not find this key. add it */
	if (addnewkey(idxdb, key, keyl, &keyoff))
	    return RPMRC_FAIL;
	keyoff |= keyh & xmask;		/* tag it with the extra bits */
	/* re-calculate ent, addnewkey may have changed the mapping! */
	ent = idxdb->slot_mapped + 8 * h;
    }
    if (freeh == -1) {
	/* did not find a dummy slot, so use the current empty slot */
	idxdb->usedslots++;
	updateUsedslots(idxdb);
    } else {
	/* re-use dummy slot */
	h = freeh;
	ent = idxdb->slot_mapped + 8 * h;
	if (idxdb->dummyslots) {
	    idxdb->dummyslots--;
	    updateDummyslots(idxdb);
	}
    }
    h2lea(keyoff, ent);
    h2lea(data, ent + 4);
    if (ovldata)
	h2lea(ovldata, idxdb->slot_mapped + idxdb->nslots * 8 + 4 * h);
    bumpGeneration(idxdb);
    return RPMRC_OK;
}

static int rpmidxDelInternal(rpmidxdb idxdb, const unsigned char *key, unsigned int keyl, unsigned int pkgidx, unsigned int datidx)
{
    unsigned int keyoff = 0;
    unsigned int keyh = murmurhash(key, keyl);
    unsigned int hmask;
    unsigned int xmask;
    unsigned int x, h, hh = 7;
    int otherusers = 0;
    unsigned int data, ovldata;

    if (datidx >= 0x80000000)
	return RPMRC_FAIL;
    if (keyl >= 0x80000000)
	return RPMRC_FAIL;
    if (rpmidxCheck(idxdb))
	return RPMRC_FAIL;
    data = encodedata(idxdb, pkgidx, datidx, &ovldata);
    hmask = idxdb->hmask;
    xmask = idxdb->xmask;
    for (h = keyh & hmask; ; h = (h + hh++) & hmask) {
	unsigned char *ent = idxdb->slot_mapped + 8 * h;
	x = le2ha(ent);
	if (x == 0)
	    break;
	if (x == -1)
	    continue;
	if (!keyoff) {
	    if (((x ^ keyh) & xmask) != 0)
		continue;
	    if (!equalkey(idxdb, x & ~xmask, key, keyl))
		continue;
	    keyoff = x;
	}
	if (keyoff != x)
	    continue;
	/* key matches, check data/ovldata */
	if (le2ha(ent + 4) != data) {
	    otherusers = 1;
	    continue;
	}
	if (ovldata && le2ha(idxdb->slot_mapped + idxdb->nslots * 8 + 4 * h) != ovldata) {
	    otherusers = 1;
	    continue;
	}
	/* found a match. convert entry to a dummy slot */
	h2lea(-1, ent);
	h2lea(-1, ent + 4);
	if (ovldata)
	    h2lea(0, idxdb->slot_mapped + idxdb->nslots * 8 + 4 * h);
	idxdb->dummyslots++;
	updateDummyslots(idxdb);
	/* continue searching (so that we find other users of the key...) */
    }
    if (keyoff && !otherusers) {
	/* key is no longer in use. free it */
	int hl = keylsize(keyl);
	memset(idxdb->key_mapped + (keyoff & ~xmask), 0, hl + keyl);
	idxdb->keyexcess += hl + keyl;
	updateKeyexcess(idxdb);
    }
    if (keyoff)
	bumpGeneration(idxdb);
    return RPMRC_OK;
}

static int rpmidxGetInternal(rpmidxdb idxdb, const unsigned char *key, unsigned int keyl, unsigned int **pkgidxlistp, unsigned int *pkgidxnump)
{
    unsigned int keyoff = 0;
    unsigned int keyh = murmurhash(key, keyl);
    unsigned int hmask = idxdb->hmask;
    unsigned int xmask = idxdb->xmask;
    unsigned int x, h, hh = 7;
    unsigned int data, ovldata, datidx;
    unsigned int nhits = 0;
    unsigned int *hits = 0;
    for (h = keyh & hmask; ; h = (h + hh++) & hmask) {
	unsigned char *ent = idxdb->slot_mapped + 8 * h;
	x = le2ha(ent);
	if (x == 0)
	    break;
	if (x == -1)
	    continue;
	if (!keyoff) {
	    if (((x ^ keyh) & xmask) != 0)
		continue;
	    if (!equalkey(idxdb, x & ~xmask, key, keyl))
		continue;
	    keyoff = x;
	}
	if (keyoff != x)
	    continue;
	if ((nhits & 15) == 0) {
	    if (!hits) {
		hits = xmalloc(16 * sizeof(unsigned int));
	    } else {
		hits = xrealloc(hits, (nhits + 16) * sizeof(unsigned int));
	    }
	}
	data = le2ha(ent + 4);
	ovldata = (data & 0x80000000) ? le2ha(idxdb->slot_mapped + idxdb->nslots * 8 + 4 * h) : 0;
	hits[nhits++] = decodedata(idxdb, data, ovldata, &datidx);
	hits[nhits++] = datidx;
    }
    *pkgidxlistp = hits;
    *pkgidxnump = nhits;
    return nhits ? RPMRC_OK : RPMRC_NOTFOUND;
}

static int rpmidxListSort_cmp(const void *a, const void *b)
{
    return ((unsigned int *)a)[1] - ((unsigned int *)b)[1];
}

/* sort in hash offset order, so that we get sequential acceess */
static void rpmidxListSort(rpmidxdb idxdb, unsigned int *keylist, unsigned int nkeylist, unsigned char *data)
{
    unsigned int i, *arr;
    if (nkeylist < 2 * 2)
	return;
    arr = xmalloc(nkeylist * sizeof(unsigned int));
    for (i = 0; i < nkeylist; i += 2) {
	arr[i] = i;
	arr[i + 1] = murmurhash(data + keylist[i], keylist[i + 1]) & idxdb->hmask;
    }
    qsort(arr, nkeylist / 2, 2 * sizeof(unsigned int), rpmidxListSort_cmp);
    for (i = 0; i < nkeylist; i += 2) {
	unsigned int ai = arr[i];
	arr[i] = keylist[ai];
	arr[i + 1] = keylist[ai + 1];
    }
    memcpy(keylist, arr, nkeylist * sizeof(unsigned int));
    free(arr);
}

static int rpmidxListInternal(rpmidxdb idxdb, unsigned int **keylistp, unsigned int *nkeylistp, unsigned char **datap)
{
    unsigned int *keylist = 0;
    unsigned int nkeylist = 0;
    unsigned char *data, *terminate, *key, *keyendp;

    data = xmalloc(idxdb->keyend + 1);	/* +1 so we can terminate the last key */
    memcpy(data, idxdb->key_mapped, idxdb->keyend);
    keylist = xmalloc(16 * sizeof(*keylist));
    terminate = 0;
    for (key = data + 1, keyendp = data + idxdb->keyend; key < keyendp; ) {
	unsigned int hl, keyl;
	if (!*key) {
	    key++;
	    continue;
	}
	if ((nkeylist & 15) == 0) {
	    unsigned int *kl = xrealloc(keylist, (nkeylist + 16) * sizeof(*keylist));
	    keylist = kl;
	}
	keyl = decodekeyl(key, &hl);
	keylist[nkeylist++] = key + hl - data;
	keylist[nkeylist++] = keyl;
	key += hl + keyl;
	if (terminate)
	  *terminate = 0;
	terminate = key;
    }
    if (terminate)
      *terminate = 0;
    rpmidxListSort(idxdb, keylist, nkeylist, data);
    *keylistp = keylist;
    *nkeylistp = nkeylist;
    *datap = data;
    return RPMRC_OK;
}


static int rpmidxInitInternal(rpmidxdb idxdb)
{
    unsigned int id;
    int rc = rpmxdbLookupBlob(idxdb->xdb, &id, idxdb->xdbtag, IDXDB_XDB_SUBTAG, 0);
    if (rc == RPMRC_OK && id) {
	idxdb->xdbid = id;
	return RPMRC_OK;	/* somebody else was faster */
    }
    if (rc && rc != RPMRC_NOTFOUND)
	return rc;
    return rpmidxRebuildInternal(idxdb);
}

static int rpmidxLock(rpmidxdb idxdb, int excl)
{
    if (excl && idxdb->rdonly)
	return RPMRC_FAIL;
    return rpmxdbLock(idxdb->xdb, excl);
}

static int rpmidxUnlock(rpmidxdb idxdb, int excl)
{
    return rpmxdbUnlock(idxdb->xdb, excl);
}

static int rpmidxLockReadHeader(rpmidxdb idxdb, int excl)
{
    if (rpmidxLock(idxdb, excl))
	return RPMRC_FAIL;
    if (rpmidxReadHeader(idxdb)) {
	rpmidxUnlock(idxdb, excl);
	return RPMRC_FAIL;
    }
    return RPMRC_OK;
}

static int rpmidxInit(rpmidxdb idxdb)
{
    int rc;
    if (rpmidxLock(idxdb, 1))
	return RPMRC_FAIL;
    rc = rpmidxInitInternal(idxdb);
    rpmidxUnlock(idxdb, 1);
    return rc;
}

int rpmidxOpen(rpmidxdb *idxdbp, rpmpkgdb pkgdb, const char *filename, int flags, int mode)
{
    return RPMRC_FAIL;
}

int rpmidxOpenXdb(rpmidxdb *idxdbp, rpmpkgdb pkgdb, rpmxdb xdb, unsigned int xdbtag, int flags)
{
    rpmidxdb idxdb;
    unsigned int id;
    *idxdbp = 0;
    int rc;
    
    if (rpmxdbIsRdonly(xdb) && (flags & (O_RDONLY|O_RDWR)) != O_RDONLY) {
	errno = EACCES;
	return RPMRC_FAIL;
    }
    if (rpmxdbLock(xdb, 0))
	return RPMRC_FAIL;
    rc = rpmxdbLookupBlob(xdb, &id, xdbtag, IDXDB_XDB_SUBTAG, 0);
    if (rc == RPMRC_NOTFOUND)
	id = 0;
    else if (rc) {
	rpmxdbUnlock(xdb, 0);
	return RPMRC_FAIL;
    }
    idxdb = xcalloc(1, sizeof(*idxdb));
    idxdb->xdb = xdb;
    idxdb->xdbtag = xdbtag;
    idxdb->xdbid = id;
    idxdb->pkgdb = pkgdb;
    idxdb->pagesize = rpmxdbPagesize(xdb);
    idxdb->rdonly = (flags & (O_RDONLY|O_RDWR)) == O_RDONLY ? 1 : 0;
    if (!id) {
	if (rpmidxInit(idxdb)) {
	    free(idxdb);
	    rpmxdbUnlock(xdb, 0);
	    return RPMRC_FAIL;
	}
    }
    *idxdbp = idxdb;
    rpmxdbUnlock(xdb, 0);
    return RPMRC_OK;
}

int rpmidxDelXdb(rpmpkgdb pkgdb, rpmxdb xdb, unsigned int xdbtag)
{
    unsigned int id;
    int rc;
    if (rpmxdbLock(xdb, 1))
	return RPMRC_FAIL;
    rc = rpmxdbLookupBlob(xdb, &id, xdbtag, IDXDB_XDB_SUBTAG, 0);
    if (rc == RPMRC_NOTFOUND)
	id = 0;
    else if (rc) {
	rpmxdbUnlock(xdb, 1);
	return rc;
    }
    if (id && rpmxdbDelBlob(xdb, id)) {
	rpmxdbUnlock(xdb, 1);
	return RPMRC_FAIL;
    }
    rpmxdbUnlock(xdb, 1);
    return RPMRC_OK;
}

void rpmidxClose(rpmidxdb idxdb)
{
    rpmidxUnmap(idxdb);
    free(idxdb);
}

rpmRC rpmidxPut(rpmidxdb idxdb, const unsigned char *key, unsigned int keyl, unsigned int pkgidx, unsigned int datidx)
{
    int rc;
    if (!pkgidx || datidx >= 0x80000000) {
	return RPMRC_FAIL;
    }
    if (rpmidxLockReadHeader(idxdb, 1))
	return RPMRC_FAIL;
    rc = rpmidxPutInternal(idxdb, key, keyl, pkgidx, datidx);
    rpmidxUnlock(idxdb, 1);
    return rc;
}

rpmRC rpmidxDel(rpmidxdb idxdb, const unsigned char *key, unsigned int keyl, unsigned int pkgidx, unsigned int datidx)
{
    int rc;
    if (!pkgidx || datidx >= 0x80000000) {
	return RPMRC_FAIL;
    }
    if (rpmidxLockReadHeader(idxdb, 1))
	return RPMRC_FAIL;
    rc = rpmidxDelInternal(idxdb, key, keyl, pkgidx, datidx);
    rpmidxUnlock(idxdb, 1);
    return rc;
}

rpmRC rpmidxGet(rpmidxdb idxdb, const unsigned char *key, unsigned int keyl, unsigned int **pkgidxlistp, unsigned int *pkgidxnump)
{
    int rc;
    *pkgidxlistp = 0;
    *pkgidxnump = 0;
    if (rpmidxLockReadHeader(idxdb, 0))
	return RPMRC_FAIL;
    rc = rpmidxGetInternal(idxdb, key, keyl, pkgidxlistp, pkgidxnump);
    rpmidxUnlock(idxdb, 0);
    return rc;
}

rpmRC rpmidxList(rpmidxdb idxdb, unsigned int **keylistp, unsigned int *nkeylistp, unsigned char **datap)
{
    int rc;
    *keylistp = 0;
    *nkeylistp = 0;
    if (rpmidxLockReadHeader(idxdb, 0))
	return RPMRC_FAIL;
    rc = rpmidxListInternal(idxdb, keylistp, nkeylistp, datap);
    rpmidxUnlock(idxdb, 0);
    return rc;
}

int rpmidxStats(rpmidxdb idxdb)
{
    if (rpmidxLockReadHeader(idxdb, 0))
	return RPMRC_FAIL;
    printf("--- IndexDB Stats\n");
    printf("Xdb tag: %d, id: %d\n", idxdb->xdbtag, idxdb->xdbid);
    printf("Generation: %u\n", idxdb->generation);
    printf("Slots: %u\n", idxdb->nslots);
    printf("Used slots: %u\n", idxdb->usedslots);
    printf("Dummy slots: %u\n", idxdb->dummyslots);
    printf("Key data size: %u, left %u\n", idxdb->keyend, idxdb->key_size - idxdb->keyend);
    printf("Key excess: %u\n", idxdb->keyexcess);
    printf("XMask: 0x%08x\n", idxdb->xmask);
    rpmidxUnlock(idxdb, 0);
    return RPMRC_OK;
}
