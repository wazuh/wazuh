/** \ingroup rpmdep
 * \file lib/rpmfi.c
 * Routines to handle file info tag sets.
 */

#include "system.h"

#include <rpm/rpmlog.h>
#include <rpm/rpmts.h>
#include <rpm/rpmfileutil.h>	/* XXX rpmDoDigest */
#include <rpm/rpmstring.h>
#include <rpm/rpmmacro.h>	/* XXX rpmCleanPath */
#include <rpm/rpmds.h>
#include <rpm/rpmbase64.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>

#include "rpmfi_internal.h"
#include "rpmte_internal.h"	/* relocations */
#include "cpio.h"	/* XXX CPIO_FOO */
#include "fsm.h"	/* rpmpsm stuff for now */
#include "rpmug.h"
#include "rpmio_internal.h"       /* fdInit/FiniDigest */

#include "debug.h"

struct hardlinks_s {
    int nlink;
    int files[];
};

typedef struct hardlinks_s * hardlinks_t;

#define HASHTYPE nlinkHash
#define HTKEYTYPE int
#define HTDATATYPE struct hardlinks_s *
#include "rpmhash.H"
#include "rpmhash.C"
#undef HASHTYPE
#undef HTKEYTYPE
#undef HTDATATYPE

typedef int (*iterfunc)(rpmfi fi);

struct rpmfi_s {
    int i;			/*!< Current file index. */
    int j;			/*!< Current directory index. */
    iterfunc next;		/*!< Iterator function. */
    char * fn;			/*!< File name buffer. */
    char * ofn;			/*!< Original file name buffer. */

    int intervalStart;		/*!< Start of iterating interval. */
    int intervalEnd;		/*!< End of iterating interval. */

    rpmfiChdirCb onChdir;	/*!< Callback for directory changes */
    void *onChdirData;		/*!< Caller private callback data */

    rpmfiles files;		/*!< File info set */
    rpmcpio_t archive;		/*!< Archive with payload */
    uint8_t * found;	/*!< Bit field of files found in the archive */
    int nrefs;			/*!< Reference count */
};

struct rpmfn_s {
    rpm_count_t dc;		/*!< No. of directories. */
    rpm_count_t fc;		/*!< No. of files. */

    rpmsid * bnid;		/*!< Index to base name(s) (pool) */
    rpmsid * dnid;		/*!< Index to directory name(s) (pool) */
    uint32_t * dil;		/*!< Directory indice(s) (from header) */
};

typedef struct rpmfn_s * rpmfn;

/**
 * A package filename set.
 */
struct rpmfiles_s {
    Header h;			/*!< Header for file info set (or NULL) */
    rpmstrPool pool;		/*!< String pool of this file info set */

    struct rpmfn_s fndata;	/*!< File name data */
    struct rpmfn_s *ofndata;	/*!< Original file name data */

    rpmsid * flinks;		/*!< Index to file link(s) (pool) */

    rpm_flag_t * fflags;	/*!< File flag(s) (from header) */
    rpm_off_t * fsizes;		/*!< File size(s) (from header) */
    rpm_loff_t * lfsizes;	/*!< File size(s) (from header) */
    rpm_time_t * fmtimes;	/*!< File modification time(s) (from header) */
    rpm_mode_t * fmodes;	/*!< File mode(s) (from header) */
    rpm_rdev_t * frdevs;	/*!< File rdev(s) (from header) */
    rpm_ino_t * finodes;	/*!< File inodes(s) (from header) */

    rpmsid * fuser;		/*!< Index to file owner(s) (misc pool) */
    rpmsid * fgroup;		/*!< Index to file group(s) (misc pool) */
    rpmsid * flangs;		/*!< Index to file lang(s) (misc pool) */

    char * fstates;		/*!< File state(s) (from header) */

    rpm_color_t * fcolors;	/*!< File color bits (header) */
    char ** fcaps;		/*!< File capability strings (header) */

    char ** cdict;		/*!< File class dictionary (header) */
    rpm_count_t ncdict;		/*!< No. of class entries. */
    uint32_t * fcdictx;		/*!< File class dictionary index (header) */

    uint32_t * ddict;		/*!< File depends dictionary (header) */
    rpm_count_t nddict;		/*!< No. of depends entries. */
    uint32_t * fddictx;		/*!< File depends dictionary start (header) */
    uint32_t * fddictn;		/*!< File depends dictionary count (header) */
    rpm_flag_t * vflags;	/*!< File verify flag(s) (from header) */

    rpmfiFlags fiflags;		/*!< file info set control flags */

    struct fingerPrint_s * fps;	/*!< File fingerprint(s). */

    int digestalgo;		/*!< File digest algorithm */
    uint32_t *signatureoffs;	/*!< File signature offsets */
    int veritysiglength;	/*!< Verity signature length */
    uint16_t verityalgo;	/*!< Verity algorithm */
    unsigned char * digests;	/*!< File digests in binary. */
    unsigned char * signatures; /*!< File signatures in binary. */
    unsigned char * veritysigs; /*!< Verity signatures in binary. */

    struct nlinkHash_s * nlinks;/*!< Files connected by hardlinks */
    rpm_loff_t * replacedSizes;	/*!< (TR_ADDED) */
    int magic;
    int nrefs;		/*!< Reference count. */
};

static int indexSane(rpmtd xd, rpmtd yd, rpmtd zd);
static int cmpPoolFn(rpmstrPool pool, rpmfn files, int ix, const char * fn);

static rpmfiles rpmfilesUnlink(rpmfiles fi)
{
    if (fi)
	fi->nrefs--;
    return NULL;
}

rpmfiles rpmfilesLink(rpmfiles fi)
{
    if (fi)
	fi->nrefs++;
    return fi;
}

static rpmfi rpmfiUnlink(rpmfi fi)
{
    if (fi)
	fi->nrefs--;
    return NULL;
}

rpmfi rpmfiLink(rpmfi fi)
{
    if (fi)
	fi->nrefs++;
    return fi;
}

/*
 * Collect and validate file path data from header.
 * Return the number of files found (could be none) or -1 on error.
 */
static int rpmfnInit(rpmfn fndata, rpmTagVal bntag, Header h, rpmstrPool pool)
{
    struct rpmtd_s bn, dn, dx;
    rpmTagVal dntag, ditag;
    int rc = 0;

    if (bntag == RPMTAG_BASENAMES) {
	dntag = RPMTAG_DIRNAMES;
	ditag = RPMTAG_DIRINDEXES;
    } else if (bntag == RPMTAG_ORIGBASENAMES) {
	dntag = RPMTAG_ORIGDIRNAMES;
	ditag = RPMTAG_ORIGDIRINDEXES;
    } else {
	return -1;
    }

    /* Grab and validate file triplet data (if there is any) */
    if (headerGet(h, bntag, &bn, HEADERGET_MINMEM)) {
	headerGet(h, dntag, &dn, HEADERGET_MINMEM);
	headerGet(h, ditag, &dx, HEADERGET_ALLOC);

	if (indexSane(&bn, &dn, &dx)) {
	    /* Init the file triplet data */
	    fndata->fc = rpmtdCount(&bn);
	    fndata->dc = rpmtdCount(&dn);
	    fndata->bnid = rpmtdToPool(&bn, pool);
	    fndata->dnid = rpmtdToPool(&dn, pool);
	    /* Steal index data from the td (pooh...) */
	    fndata->dil = (uint32_t *)dx.data;
	    dx.data = NULL;
	    rc = fndata->fc;
	} else {
	    memset(fndata, 0, sizeof(*fndata));
	    rc = -1;
	}
	rpmtdFreeData(&bn);
	rpmtdFreeData(&dn);
	rpmtdFreeData(&dx);
    }

    return rc;
}

static void rpmfnClear(rpmfn fndata)
{
    if (fndata) {
	free(fndata->bnid);
	free(fndata->dnid);
	free(fndata->dil);
	memset(fndata, 0, sizeof(*fndata));
    }
}

static rpm_count_t rpmfnFC(rpmfn fndata)
{
    return (fndata != NULL) ? fndata->fc :0;
}

static rpm_count_t rpmfnDC(rpmfn fndata)
{
    return (fndata != NULL) ? fndata->dc : 0;
}

static int rpmfnDI(rpmfn fndata, int ix)
{
    int j = -1;
    if (ix >= 0 && ix < rpmfnFC(fndata)) {
	if (fndata->dil != NULL)
	    j = fndata->dil[ix];
    }
    return j;
}

static rpmsid rpmfnBNId(rpmfn fndata, int ix)
{
    rpmsid id = 0;
    if (ix >= 0 && ix < rpmfnFC(fndata)) {
	if (fndata->bnid != NULL)
	    id = fndata->bnid[ix];
    }
    return id;
}

static rpmsid rpmfnDNId(rpmfn fndata, int ix)
{
    rpmsid id = 0;
    if (ix >= 0 && ix < rpmfnDC(fndata)) {
	if (fndata->dnid != NULL)
	    id = fndata->dnid[ix];
    }
    return id;
}

static const char * rpmfnBN(rpmstrPool pool, rpmfn fndata, int ix)
{
    return rpmstrPoolStr(pool, rpmfnBNId(fndata, ix));
}

static const char * rpmfnDN(rpmstrPool pool, rpmfn fndata, int ix)
{
    return rpmstrPoolStr(pool, rpmfnDNId(fndata, ix));
}

static char * rpmfnFN(rpmstrPool pool, rpmfn fndata, int ix)
{
    char *fn = NULL;
    if (ix >= 0 && ix < rpmfnFC(fndata)) {
	fn = rstrscat(NULL, rpmfnDN(pool, fndata, rpmfnDI(fndata, ix)),
			    rpmfnBN(pool, fndata, ix), NULL);
    }
    return fn;
}

rpm_count_t rpmfilesFC(rpmfiles fi)
{
    return (fi != NULL ? rpmfnFC(&fi->fndata) : 0);
}

rpm_count_t rpmfilesDC(rpmfiles fi)
{
    return (fi != NULL ? rpmfnDC(&fi->fndata) : 0);
}

int rpmfilesDigestAlgo(rpmfiles fi)
{
    return (fi != NULL) ? fi->digestalgo : 0;
}

rpm_count_t rpmfiFC(rpmfi fi)
{
    return (fi != NULL ? rpmfilesFC(fi->files) : 0);
}

rpm_count_t rpmfiDC(rpmfi fi)
{
    return (fi != NULL ? rpmfilesDC(fi->files) : 0);
}

int rpmfiSetOnChdir(rpmfi fi, rpmfiChdirCb cb, void *data)
{
    int rc = -1;
    if (fi != NULL) {
	fi->onChdir = cb;
	fi->onChdirData = data;
	rc = 0;
    }
    return rc;
}

int rpmfiFX(rpmfi fi)
{
    return (fi != NULL ? fi->i : -1);
}

int rpmfiSetFX(rpmfi fi, int fx)
{
    int i = -1;

    if (fi != NULL && fx >= 0 && fx < rpmfilesFC(fi->files)) {
	int dx = fi->j;
	fi->i = fx;
	fi->j = rpmfilesDI(fi->files, fi->i);
	i = fi->i;

	if (fi->j != dx && fi->onChdir) {
	    int chrc = fi->onChdir(fi, fi->onChdirData);
	    if (chrc < 0)
		i = chrc;
	}
    }
    return i;
}

int rpmfiDX(rpmfi fi)
{
    return (fi != NULL ? fi->j : -1);
}

int rpmfilesDI(rpmfiles fi, int ix)
{
    return (fi != NULL) ? rpmfnDI(&fi->fndata, ix) : -1;
}

int rpmfilesODI(rpmfiles fi, int ix)
{
    return (fi != NULL) ? rpmfnDI(fi->ofndata, ix) : -1;
}

rpmsid rpmfilesBNId(rpmfiles fi, int ix)
{
    return (fi != NULL) ? rpmfnBNId(&fi->fndata, ix) : 0;
}

rpmsid rpmfilesOBNId(rpmfiles fi, int ix)
{
    return (fi != NULL) ? rpmfnBNId(fi->ofndata, ix) : 0;
}

rpmsid rpmfilesDNId(rpmfiles fi, int jx)
{
    return (fi != NULL) ? rpmfnDNId(&fi->fndata, jx) : 0;
}

rpmsid rpmfilesODNId(rpmfiles fi, int jx)
{
    return (fi != NULL) ? rpmfnDNId(fi->ofndata, jx) : 0;
}

const char * rpmfilesBN(rpmfiles fi, int ix)
{
    return (fi != NULL) ? rpmfnBN(fi->pool, &fi->fndata, ix) : NULL;
}

const char * rpmfilesOBN(rpmfiles fi, int ix)
{
    return (fi != NULL) ? rpmstrPoolStr(fi->pool, rpmfilesOBNId(fi, ix)) : NULL;
}

const char * rpmfilesDN(rpmfiles fi, int jx)
{
    return (fi != NULL) ? rpmfnDN(fi->pool, &fi->fndata, jx) : NULL;
}

const char * rpmfilesODN(rpmfiles fi, int jx)
{
    return (fi != NULL) ? rpmstrPoolStr(fi->pool, rpmfilesODNId(fi, jx)) : NULL;
}

char * rpmfilesFN(rpmfiles fi, int ix)
{
    return (fi != NULL) ? rpmfnFN(fi->pool, &fi->fndata, ix) : NULL;
}

char * rpmfilesOFN(rpmfiles fi, int ix)
{
    return (fi != NULL) ? rpmfnFN(fi->pool, fi->ofndata, ix) : NULL;
}

/* Fn is expected to be relative path, convert directory to relative too */
static int cmpPoolFn(rpmstrPool pool, rpmfn files, int ix, const char * fn)
{
    rpmsid dnid = rpmfnDNId(files, rpmfnDI(files, ix));
    const char *dn = rpmstrPoolStr(pool, dnid);
    const char *reldn = (dn[0] == '/') ? dn + 1 : dn;
    size_t l = strlen(reldn);
    int cmp = strncmp(reldn, fn, l);
    if (cmp == 0)
	cmp = strcmp(rpmfnBN(pool, files, ix), fn + l);
    return cmp;
}

static int rpmfnFindFN(rpmstrPool pool, rpmfn files, const char * fn)
{
    int fc = rpmfnFC(files);

    /*
     * Skip payload prefix, turn absolute paths into relative. This
     * allows handling binary rpm payloads with and without ./ prefix and
     * srpm payloads which only contain basenames.
     */
    if (fn[0] == '.' && fn[1] == '/')
	fn += 2;
    if (fn[0] == '/')
	fn += 1;

    /* try binary search */

    int lo = 0;
    int hi = fc;
    int mid, cmp;

    while (hi > lo) {
	mid = (hi + lo) / 2 ;
	cmp = cmpPoolFn(pool, files, mid, fn);
	if (cmp < 0) {
	    lo = mid+1;
	} else if (cmp > 0) {
	    hi = mid;
	} else {
	    return mid;
	}
    }

    /* not found: try linear search */
    for (int i=0; i < fc; i++) {
	if (cmpPoolFn(pool, files, i, fn) == 0)
	    return i;
    }
    return -1;
}

int rpmfilesFindFN(rpmfiles files, const char * fn)
{
    return (files && fn) ? rpmfnFindFN(files->pool, &files->fndata, fn) : -1;
}

int rpmfilesFindOFN(rpmfiles files, const char * fn)
{
    return (files && fn) ? rpmfnFindFN(files->pool, files->ofndata, fn) : -1;
}

int rpmfiFindFN(rpmfi fi, const char * fn)
{
    int ix = -1;

    if (fi != NULL) {
	ix = rpmfilesFindFN(fi->files, fn);
    }
    return ix;
}

int rpmfiFindOFN(rpmfi fi, const char * fn)
{
    int ix = -1;

    if (fi != NULL) {
	ix = rpmfilesFindOFN(fi->files, fn);
    }
    return ix;
}

/*
 * Dirnames are not sorted when separated from basenames, we need to assemble
 * the whole path for search (binary or otherwise) purposes.
 */
static int cmpPfx(rpmfiles files, int ix, const char *pfx, size_t plen)
{
    char *fn = rpmfilesFN(files, ix);
    int rc = strncmp(pfx, fn, plen);
    free(fn);
    return rc;
}

rpmfileAttrs rpmfilesFFlags(rpmfiles fi, int ix)
{
    rpmfileAttrs FFlags = 0;

    if (fi != NULL && ix >= 0 && ix < rpmfilesFC(fi)) {
	if (fi->fflags != NULL)
	    FFlags = fi->fflags[ix];
    }
    return FFlags;
}

rpmVerifyAttrs rpmfilesVFlags(rpmfiles fi, int ix)
{
    rpmVerifyAttrs VFlags = 0;

    if (fi != NULL && ix >= 0 && ix < rpmfilesFC(fi)) {
	if (fi->vflags != NULL)
	    VFlags = fi->vflags[ix];
    }
    return VFlags;
}

rpm_mode_t rpmfilesFMode(rpmfiles fi, int ix)
{
    rpm_mode_t fmode = 0;

    if (fi != NULL && ix >= 0 && ix < rpmfilesFC(fi)) {
	if (fi->fmodes != NULL)
	    fmode = fi->fmodes[ix];
    }
    return fmode;
}

rpmfileState rpmfilesFState(rpmfiles fi, int ix)
{
    rpmfileState fstate = RPMFILE_STATE_MISSING;

    if (fi != NULL && ix >= 0 && ix < rpmfilesFC(fi)) {
	if (fi->fstates != NULL)
	    fstate = (rpmfileState)fi->fstates[ix];
    }
    return fstate;
}

int rpmfiDigestAlgo(rpmfi fi)
{
    return fi ? rpmfilesDigestAlgo(fi->files) : 0;
}

const unsigned char * rpmfilesFDigest(rpmfiles fi, int ix, int *algo, size_t *len)
{
    const unsigned char *digest = NULL;

    if (fi != NULL && ix >= 0 && ix < rpmfilesFC(fi)) {
    	size_t diglen = rpmDigestLength(fi->digestalgo);
	if (fi->digests != NULL)
	    digest = fi->digests + (diglen * ix);
	if (len) 
	    *len = diglen;
	if (algo) 
	    *algo = fi->digestalgo;
    }
    return digest;
}

char * rpmfiFDigestHex(rpmfi fi, int *algo)
{
    size_t diglen = 0;
    char *fdigest = NULL;
    const unsigned char *digest = rpmfiFDigest(fi, algo, &diglen);
    if (digest) {
	fdigest = rpmhex(digest, diglen);
    }
    return fdigest;
}

const unsigned char * rpmfilesFSignature(rpmfiles fi, int ix, size_t *len)
{
    const unsigned char *signature = NULL;

    if (fi != NULL && ix >= 0 && ix < rpmfilesFC(fi)) {
	size_t slen = 0;
	if (fi->signatures != NULL && fi->signatureoffs != NULL) {
	    uint32_t off = fi->signatureoffs[ix];
	    slen = fi->signatureoffs[ix+1] - off;
	    if (slen > 0)
		signature = fi->signatures + off;
	}
	if (len)
	    *len = slen;
    }
    return signature;
}

const unsigned char * rpmfilesVSignature(rpmfiles fi, int ix, size_t *len,
					 uint16_t *algo)
{
    const unsigned char *vsignature = NULL;

    if (fi != NULL && ix >= 0 && ix < rpmfilesFC(fi)) {
	if (fi->veritysigs != NULL)
	    vsignature = fi->veritysigs + (fi->veritysiglength * ix);
	if (len)
	    *len = fi->veritysiglength;
	if (algo)
	    *algo = fi->verityalgo;
    }
    return vsignature;
}

const char * rpmfilesFLink(rpmfiles fi, int ix)
{
    const char * flink = NULL;

    if (fi != NULL && ix >= 0 && ix < rpmfilesFC(fi)) {
	if (fi->flinks != NULL)
	    flink = rpmstrPoolStr(fi->pool, fi->flinks[ix]);
    }
    return flink;
}

rpm_loff_t rpmfilesFSize(rpmfiles fi, int ix)
{
    rpm_loff_t fsize = 0;

    if (fi != NULL && ix >= 0 && ix < rpmfilesFC(fi)) {
	if (fi->fsizes != NULL)
	    fsize = fi->fsizes[ix];
	else if (fi->lfsizes != NULL)
	    fsize = fi->lfsizes[ix];
    }
    return fsize;
}

rpm_rdev_t rpmfilesFRdev(rpmfiles fi, int ix)
{
    rpm_rdev_t frdev = 0;

    if (fi != NULL && ix >= 0 && ix < rpmfilesFC(fi)) {
	if (fi->frdevs != NULL)
	    frdev = fi->frdevs[ix];
    }
    return frdev;
}

rpm_ino_t rpmfilesFInode(rpmfiles fi, int ix)
{
    rpm_ino_t finode = 0;

    if (fi != NULL && ix >= 0 && ix < rpmfilesFC(fi)) {
	if (fi->finodes != NULL)
	    finode = fi->finodes[ix];
    }
    return finode;
}

rpm_color_t rpmfilesColor(rpmfiles files)
{
    rpm_color_t color = 0;

    if (files != NULL && files->fcolors != NULL) {
	int fc = rpmfilesFC(files);
	for (int i = 0; i < fc; i++)
	    color |= files->fcolors[i];
	/* XXX ignore all but lsnibble for now. */
	color &= 0xf;
    }
    return color;
}

rpm_color_t rpmfiColor(rpmfi fi)
{
    return (fi != NULL) ? rpmfilesColor(fi->files) : 0;
}

rpm_color_t rpmfilesFColor(rpmfiles fi, int ix)
{
    rpm_color_t fcolor = 0;

    if (fi != NULL && ix >= 0 && ix < rpmfilesFC(fi)) {
	if (fi->fcolors != NULL)
	    /* XXX ignore all but lsnibble for now. */
	    fcolor = (fi->fcolors[ix] & 0x0f);
    }
    return fcolor;
}

const char * rpmfilesFClass(rpmfiles fi, int ix)
{
    const char * fclass = NULL;
    int cdictx;

    if (fi != NULL && fi->fcdictx != NULL && ix >= 0 && ix < rpmfilesFC(fi)) {
	cdictx = fi->fcdictx[ix];
	if (fi->cdict != NULL && cdictx >= 0 && cdictx < fi->ncdict)
	    fclass = fi->cdict[cdictx];
    }
    return fclass;
}

uint32_t rpmfilesFDepends(rpmfiles fi, int ix, const uint32_t ** fddictp)
{
    int fddictx = -1;
    int fddictn = 0;
    const uint32_t * fddict = NULL;

    if (fi != NULL && ix >= 0 && ix < rpmfilesFC(fi)) {
	if (fi->fddictn != NULL)
	    fddictn = fi->fddictn[ix];
	if (fddictn > 0 && fi->fddictx != NULL)
	    fddictx = fi->fddictx[ix];
	if (fi->ddict != NULL && fddictx >= 0 && (fddictx+fddictn) <= fi->nddict)
	    fddict = fi->ddict + fddictx;
    }
    if (fddictp)
	*fddictp = fddict;
    return fddictn;
}

uint32_t rpmfilesFLinks(rpmfiles fi, int ix, const int ** files)
{
    uint32_t nlink = 0;

    if (fi != NULL && ix >= 0 && ix < rpmfilesFC(fi)) {
	nlink = 1;
	if (fi->nlinks) {
	    struct hardlinks_s ** hardlinks = NULL;
	    nlinkHashGetEntry(fi->nlinks, ix, &hardlinks, NULL, NULL);
	    if (hardlinks) {
		nlink = hardlinks[0]->nlink;
		if (files) {
		    *files = hardlinks[0]->files;
		}
	    } else if (files){
		*files = NULL;
	    }
	}
    }
    return nlink;
}

uint32_t rpmfiFLinks(rpmfi fi, const int ** files)
{
    return rpmfilesFLinks(fi ? fi->files : NULL, fi ? fi->i : -1, files);
}

uint32_t rpmfilesFNlink(rpmfiles fi, int ix)
{
    return rpmfilesFLinks(fi, ix, NULL);
}

rpm_time_t rpmfilesFMtime(rpmfiles fi, int ix)
{
    rpm_time_t fmtime = 0;

    if (fi != NULL && ix >= 0 && ix < rpmfilesFC(fi)) {
	if (fi->fmtimes != NULL)
	    fmtime = fi->fmtimes[ix];
    }
    return fmtime;
}

const char * rpmfilesFUser(rpmfiles fi, int ix)
{
    const char * fuser = NULL;

    if (fi != NULL && ix >= 0 && ix < rpmfilesFC(fi)) {
	if (fi->fuser != NULL)
	    fuser = rpmstrPoolStr(fi->pool, fi->fuser[ix]);
    }
    return fuser;
}

const char * rpmfilesFGroup(rpmfiles fi, int ix)
{
    const char * fgroup = NULL;

    if (fi != NULL && ix >= 0 && ix < rpmfilesFC(fi)) {
	if (fi->fgroup != NULL)
	    fgroup = rpmstrPoolStr(fi->pool, fi->fgroup[ix]);
    }
    return fgroup;
}

const char * rpmfilesFCaps(rpmfiles fi, int ix)
{
    const char *fcaps = NULL;
    if (fi != NULL && ix >= 0 && ix < rpmfilesFC(fi)) {
	fcaps = fi->fcaps ? fi->fcaps[ix] : "";
    }
    return fcaps;
}

const char * rpmfilesFLangs(rpmfiles fi, int ix)
{
    const char *flangs = NULL;
    if (fi != NULL && fi->flangs != NULL && ix >= 0 && ix < rpmfilesFC(fi)) {
	flangs = rpmstrPoolStr(fi->pool, fi->flangs[ix]);
    }
    return flangs;
}

int rpmfilesStat(rpmfiles fi, int ix, int flags, struct stat *sb)
{
    int rc = -1;
    if (fi && sb) {
	/* XXX FIXME define proper flags with sane semantics... */
	int warn = flags & 0x1;
	const char *user = rpmfilesFUser(fi, ix);
	const char *group = rpmfilesFGroup(fi, ix);

	memset(sb, 0, sizeof(*sb));
	sb->st_nlink = rpmfilesFLinks(fi, ix, NULL);
	sb->st_ino = rpmfilesFInode(fi, ix);
	sb->st_rdev = rpmfilesFRdev(fi, ix);
	sb->st_mode = rpmfilesFMode(fi, ix);
	sb->st_mtime = rpmfilesFMtime(fi, ix);

	/* Only regular files and symlinks have a size */
	if (S_ISREG(sb->st_mode) || S_ISLNK(sb->st_mode))
	    sb->st_size = rpmfilesFSize(fi, ix);

	if (user && rpmugUid(user, &sb->st_uid)) {
	    if (warn)
		rpmlog(RPMLOG_WARNING,
			_("user %s does not exist - using %s\n"), user, UID_0_USER);
	    sb->st_mode &= ~S_ISUID;	  /* turn off suid bit */
	}

	if (group && rpmugGid(group, &sb->st_gid)) {
	    if (warn)
		rpmlog(RPMLOG_WARNING,
			_("group %s does not exist - using %s\n"), group, GID_0_GROUP);
	    sb->st_mode &= ~S_ISGID;	/* turn off sgid bit */
	}

	rc = 0;
    }
    return rc;
}

struct fingerPrint_s *rpmfilesFps(rpmfiles fi)
{
    return (fi != NULL) ? fi->fps : NULL;
}

static int iterFwd(rpmfi fi)
{
    return fi->i + 1;
}

static int iterBack(rpmfi fi)
{
    return fi->i - 1;
}

static int iterInterval(rpmfi fi)
{
    if (fi->i == -1)
	return fi->intervalStart;
    else if (fi->i + 1 < fi->intervalEnd)
	return fi->i + 1;
    else
	return RPMERR_ITER_END;
}

int rpmfiNext(rpmfi fi)
{
    int next = -1;
    if (fi != NULL) {
	do {
	    next = fi->next(fi);
	} while (next == RPMERR_ITER_SKIP);

	if (next >= 0)
	    next = rpmfiSetFX(fi, next);
    }
    return next;
}

rpmfi rpmfiInit(rpmfi fi, int fx)
{
    if (fi != NULL) {
	if (fx >= 0 && fx < rpmfilesFC(fi->files)) {
	    fi->i = fx - 1;
	    fi->j = -1;
	}
    }

    return fi;
}

rpmFileTypes rpmfiWhatis(rpm_mode_t mode)
{
    if (S_ISDIR(mode))	return XDIR;
    if (S_ISCHR(mode))	return CDEV;
    if (S_ISBLK(mode))	return BDEV;
    if (S_ISLNK(mode))	return LINK;
    if (S_ISSOCK(mode))	return SOCK;
    if (S_ISFIFO(mode))	return PIPE;
    return REG;
}

int rpmfilesCompare(rpmfiles afi, int aix, rpmfiles bfi, int bix)
{
    mode_t amode = rpmfilesFMode(afi, aix);
    mode_t bmode = rpmfilesFMode(bfi, bix);
    rpmFileTypes awhat = rpmfiWhatis(amode);

    if ((rpmfilesFFlags(afi, aix) & RPMFILE_GHOST) ||
	(rpmfilesFFlags(bfi, bix) & RPMFILE_GHOST)) return 0;

    /* Mode difference is a conflict, except for symlinks */
    if (!(awhat == LINK && rpmfiWhatis(bmode) == LINK) && amode != bmode)
	return 1;

    if (awhat == LINK || awhat == REG) {
	if (rpmfilesFSize(afi, aix) != rpmfilesFSize(bfi, bix))
	    return 1;
    }

    if (!rstreq(rpmfilesFUser(afi, aix), rpmfilesFUser(bfi, bix)))
	return 1;
    if (!rstreq(rpmfilesFGroup(afi, aix), rpmfilesFGroup(bfi, bix)))
	return 1;

    if (awhat == LINK) {
	const char * alink = rpmfilesFLink(afi, aix);
	const char * blink = rpmfilesFLink(bfi, bix);
	if (alink == blink) return 0;
	if (alink == NULL) return 1;
	if (blink == NULL) return -1;
	return strcmp(alink, blink);
    } else if (awhat == REG) {
	size_t adiglen, bdiglen;
	int aalgo, balgo;
	const unsigned char * adigest, * bdigest;
	adigest = rpmfilesFDigest(afi, aix, &aalgo, &adiglen);
	bdigest = rpmfilesFDigest(bfi, bix, &balgo, &bdiglen);
	if (adigest == bdigest) return 0;
	if (adigest == NULL) return 1;
	if (bdigest == NULL) return -1;
	/* can't meaningfully compare different hash types */
	if (aalgo != balgo || adiglen != bdiglen) return -1;
	return memcmp(adigest, bdigest, adiglen);
    } else if (awhat == CDEV || awhat == BDEV) {
	if (rpmfilesFRdev(afi, aix) != rpmfilesFRdev(bfi, bix))
	    return 1;
    }

    return 0;
}

int rpmfileContentsEqual(rpmfiles ofi, int oix, rpmfiles nfi, int nix)
{
    char * fn = rpmfilesFN(nfi, nix);
    rpmFileTypes diskWhat, newWhat, oldWhat;
    struct stat sb;
    int equal = 0;

    if (fn == NULL || (lstat(fn, &sb))) {
	goto exit; /* The file doesn't exist on the disk */
    }

    if (rpmfilesFSize(nfi, nix) != sb.st_size) {
	goto exit;
    }

    diskWhat = rpmfiWhatis((rpm_mode_t)sb.st_mode);
    newWhat = rpmfiWhatis(rpmfilesFMode(nfi, nix));
    oldWhat = rpmfiWhatis(rpmfilesFMode(ofi, oix));
    if ((diskWhat != newWhat) || (diskWhat != oldWhat)) {
	goto exit;
    }

    if (diskWhat == REG) {
	int oalgo, nalgo;
	size_t odiglen, ndiglen;
	const unsigned char * odigest, * ndigest;
	char buffer[1024];

	odigest = rpmfilesFDigest(ofi, oix, &oalgo, &odiglen);
	ndigest = rpmfilesFDigest(nfi, nix, &nalgo, &ndiglen);
	/* See if the file in old pkg is identical to the one in new pkg */
	if ((oalgo != nalgo) || (odiglen != ndiglen) || (!ndigest) ||
	    (memcmp(odigest, ndigest, ndiglen) != 0)) {
	    goto exit;
	}

	if (rpmDoDigest(nalgo, fn, 0, (unsigned char *)buffer) != 0) {
	     goto exit;		/* assume file has been removed */
	}

	/* See if the file on disk is identical to the one in new pkg */
	if (memcmp(ndigest, buffer, ndiglen) == 0) {
	    equal = 1;
	    goto exit;
	}
    }  else if (diskWhat == LINK) {
	const char * nFLink;
	char buffer[1024];
	ssize_t link_len;

	nFLink = rpmfilesFLink(nfi, nix);
	link_len = readlink(fn, buffer, sizeof(buffer) - 1);
	if (link_len == -1) {
	    goto exit;		/* assume file has been removed */
	}
	buffer[link_len] = '\0';
	/* See if the link on disk is identical to the one in new pkg */
	if (nFLink && rstreq(nFLink, buffer)) {
	    equal = 1;
	    goto exit;
	}
    }

exit:
    free(fn);
    return equal;
}


rpmFileAction rpmfilesDecideFate(rpmfiles ofi, int oix,
				   rpmfiles nfi, int nix,
				   int skipMissing)
{
    char * fn = rpmfilesFN(nfi, nix);
    rpmfileAttrs newFlags = rpmfilesFFlags(nfi, nix);
    char buffer[1024];
    rpmFileTypes dbWhat, newWhat, diskWhat;
    struct stat sb;
    rpmFileAction save = (newFlags & RPMFILE_NOREPLACE) ? FA_ALTNAME : FA_SAVE;
    rpmFileAction action = FA_CREATE; /* assume we can create */

    /* If the new file is a ghost, leave whatever might be on disk alone. */
    if (newFlags & RPMFILE_GHOST) {
	action = FA_SKIP;
	goto exit;
    }

    if (lstat(fn, &sb)) {
	/*
	 * The file doesn't exist on the disk. Create it unless the new
	 * package has marked it as missingok, or allfiles is requested.
	 */
	if (skipMissing && (newFlags & RPMFILE_MISSINGOK)) {
	    rpmlog(RPMLOG_DEBUG, "%s skipped due to missingok flag\n",
			fn);
	    action = FA_SKIP;
	    goto exit;
	} else {
	    goto exit;
	}
    }

    diskWhat = rpmfiWhatis((rpm_mode_t)sb.st_mode);
    dbWhat = rpmfiWhatis(rpmfilesFMode(ofi, oix));
    newWhat = rpmfiWhatis(rpmfilesFMode(nfi, nix));

    /*
     * This order matters - we'd prefer to TOUCH the file if at all
     * possible in case something else (like the timestamp) has changed.
     * Only regular files and symlinks might need a backup, everything
     * else falls through here with FA_CREATE.
     */
    if (dbWhat == REG) {
	int oalgo, nalgo;
	size_t odiglen, ndiglen;
	const unsigned char * odigest, * ndigest;

	/* See if the file on disk is identical to the one in new pkg */
	ndigest = rpmfilesFDigest(nfi, nix, &nalgo, &ndiglen);
	if (diskWhat == REG && newWhat == REG) {
	    if (rpmDoDigest(nalgo, fn, 0, (unsigned char *)buffer))
		goto exit;		/* assume file has been removed */
	    if (ndigest && memcmp(ndigest, buffer, ndiglen) == 0) {
		action = FA_TOUCH;
	        goto exit;		/* unmodified config file, touch it. */
	    }
	}

	/* See if the file on disk is identical to the one in old pkg */
	odigest = rpmfilesFDigest(ofi, oix, &oalgo, &odiglen);
	if (diskWhat == REG) {
	    /* hash algo changed or digest was not computed, recalculate it */
	    if ((oalgo != nalgo) || (newWhat != REG)) {
		if (rpmDoDigest(oalgo, fn, 0, (unsigned char *)buffer))
		    goto exit;	/* assume file has been removed */
		}
	    if (odigest && memcmp(odigest, buffer, odiglen) == 0)
	        goto exit;	/* unmodified config file, replace. */
	}

	/* if new file is no longer config, backup it and replace it */
	if (!(newFlags & RPMFILE_CONFIG)) {
	    action = FA_SAVE;
	    goto exit;
	}

	/* If file can be determined identical in old and new pkg, let it be */
	if (newWhat == REG && oalgo == nalgo && odiglen == ndiglen) {
	    if (odigest && ndigest && memcmp(odigest, ndigest, odiglen) == 0) {
		action = FA_SKIP; /* identical file, dont bother */
		goto exit;
	    }
	}
	
	/* ...but otherwise a backup will be needed */
	action = save;
    } else if (dbWhat == LINK) {
	const char * oFLink, * nFLink;

	if (diskWhat == LINK) {
	    /* Read link from the disk */
	    ssize_t link_len = readlink(fn, buffer, sizeof(buffer) - 1);
	    if (link_len == -1)
		goto exit;		/* assume file has been removed */
	    buffer[link_len] = '\0';
	}

	/* See if the link on disk is identical to the one in new pkg */
	nFLink = rpmfilesFLink(nfi, nix);
	if (diskWhat == LINK && newWhat == LINK) {
	    if (nFLink && rstreq(nFLink, buffer)) {
		action = FA_TOUCH;
		goto exit;		/* unmodified config file, touch it. */
	    }
	}

	/* See if the link on disk is identical to the one in old pkg */
	oFLink = rpmfilesFLink(ofi, oix);
	if (diskWhat == LINK) {
	    if (oFLink && rstreq(oFLink, buffer))
		goto exit;		/* unmodified config file, replace. */
	}

	/* if new file is no longer config, backup it and replace it */
	if (!(newFlags & RPMFILE_CONFIG)) {
	    action = FA_SAVE;
	    goto exit;
	}

	/* If link is identical in old and new pkg, let it be */
	if (newWhat == LINK && oFLink && nFLink && rstreq(oFLink, nFLink)) {
	    action = FA_SKIP;		/* identical file, don't bother. */
	    goto exit;
	}

	/* ...but otherwise a backup will be needed */
	action = save;
    }

exit:
    free(fn);
    return action;
}

int rpmfilesConfigConflict(rpmfiles fi, int ix)
{
    char * fn = NULL;
    rpmfileAttrs flags = rpmfilesFFlags(fi, ix);
    char buffer[1024];
    rpmFileTypes newWhat, diskWhat;
    struct stat sb;
    int rc = 0;

    /* Non-configs are not config conflicts. */
    if (!(flags & RPMFILE_CONFIG))
	return 0;

    /* Only links and regular files can be %config */
    newWhat = rpmfiWhatis(rpmfilesFMode(fi, ix));
    if (newWhat != LINK && newWhat != REG)
	return 0;

    /* If it's not on disk, there's nothing to be saved */
    fn = rpmfilesFN(fi, ix);
    if (lstat(fn, &sb))
	goto exit;

    /*
     * Preserve legacy behavior: an existing %ghost %config is considered
     * "modified" but unlike regular %config, its never removed and
     * never backed up. Whether this actually makes sense is a whole
     * another question, but this is very long-standing behavior that
     * people might be depending on. The resulting FA_ALTNAME etc action
     * is special-cased in FSM to avoid actually creating backups on ghosts.
     */
    if (flags & RPMFILE_GHOST) {
	rc = 1;
	goto exit;
    }

    /* Files of different types obviously are not identical */
    diskWhat = rpmfiWhatis((rpm_mode_t)sb.st_mode);
    if (diskWhat != newWhat) {
	rc = 1;
	goto exit;
    }

    /* Files of different sizes obviously are not identical */
    if (rpmfilesFSize(fi, ix) != sb.st_size) {
	rc = 1;
	goto exit;
    }
    
    memset(buffer, 0, sizeof(buffer));
    if (newWhat == REG) {
	int algo;
	size_t diglen;
	const unsigned char *ndigest = rpmfilesFDigest(fi,ix, &algo, &diglen);
	if (rpmDoDigest(algo, fn, 0, (unsigned char *)buffer))
	    goto exit;	/* assume file has been removed */
	if (ndigest && memcmp(ndigest, buffer, diglen) == 0)
	    goto exit;	/* unmodified config file */
    } else /* newWhat == LINK */ {
	const char * nFLink;
	ssize_t link_len = readlink(fn, buffer, sizeof(buffer) - 1);
	if (link_len == -1)
	    goto exit;	/* assume file has been removed */
	buffer[link_len] = '\0';
	nFLink = rpmfilesFLink(fi, ix);
	if (nFLink && rstreq(nFLink, buffer))
	    goto exit;	/* unmodified config file */
    }

    rc = 1;

exit:
    free(fn);
    return rc;
}

rpmfiles rpmfilesFree(rpmfiles fi)
{
    if (fi == NULL) return NULL;

    if (fi->nrefs > 1)
	return rpmfilesUnlink(fi);

    if (rpmfilesFC(fi) > 0) {
	if (fi->ofndata != &fi->fndata) {
	    rpmfnClear(fi->ofndata);
	    free(fi->ofndata);
	}
	rpmfnClear(&fi->fndata);

	fi->flinks = _free(fi->flinks);
	fi->flangs = _free(fi->flangs);
	fi->digests = _free(fi->digests);
	fi->signatures = _free(fi->signatures);
	fi->signatureoffs = _free(fi->signatureoffs);
	fi->veritysigs = _free(fi->veritysigs);
	fi->fcaps = _free(fi->fcaps);

	fi->cdict = _free(fi->cdict);

	fi->fuser = _free(fi->fuser);
	fi->fgroup = _free(fi->fgroup);

	fi->fstates = _free(fi->fstates);
	fi->fps = _free(fi->fps);

	/* these point to header memory if KEEPHEADER is used, dont free */
	if (!(fi->fiflags & RPMFI_KEEPHEADER) && fi->h == NULL) {
	    fi->fmtimes = _free(fi->fmtimes);
	    fi->fmodes = _free(fi->fmodes);
	    fi->fflags = _free(fi->fflags);
	    fi->vflags = _free(fi->vflags);
	    fi->fsizes = _free(fi->fsizes);
	    fi->lfsizes = _free(fi->lfsizes);
	    fi->frdevs = _free(fi->frdevs);
	    fi->finodes = _free(fi->finodes);

	    fi->fcolors = _free(fi->fcolors);
	    fi->fcdictx = _free(fi->fcdictx);
	    fi->ddict = _free(fi->ddict);
	    fi->fddictx = _free(fi->fddictx);
	    fi->fddictn = _free(fi->fddictn);

	}
    }

    fi->replacedSizes = _free(fi->replacedSizes);

    fi->h = headerFree(fi->h);
    fi->pool = rpmstrPoolFree(fi->pool);

    fi->nlinks = nlinkHashFree(fi->nlinks);

    (void) rpmfilesUnlink(fi);
    memset(fi, 0, sizeof(*fi));		/* XXX trash and burn */
    fi = _free(fi);

    return NULL;
}

rpmfi rpmfiFree(rpmfi fi)
{
    if (fi == NULL) return NULL;

    if (fi->nrefs > 1)
	return rpmfiUnlink(fi);

    fi->files = rpmfilesFree(fi->files);
    fi->fn = _free(fi->fn);
    fi->ofn = _free(fi->ofn);
    fi->found = _free(fi->found);
    fi->archive = rpmcpioFree(fi->archive);

    free(fi);
    return NULL;
}

static rpmsid * tag2pool(rpmstrPool pool, Header h, rpmTag tag, rpm_count_t size)
{
    rpmsid *sids = NULL;
    struct rpmtd_s td;
    if (headerGet(h, tag, &td, HEADERGET_MINMEM)) {
	if (rpmtdCount(&td) == size) { /* ensure right size */
	    sids = rpmtdToPool(&td, pool);
	}
	rpmtdFreeData(&td);
    }
    return sids;
}

/* validate a indexed tag data triplet (such as file bn/dn/dx) */
static int indexSane(rpmtd xd, rpmtd yd, rpmtd zd)
{
    int sane = 0;
    uint32_t xc = rpmtdCount(xd);
    uint32_t yc = rpmtdCount(yd);
    uint32_t zc = rpmtdCount(zd);

    /* check that the amount of data in each is sane */
    /* normally yc <= xc but larger values are not fatal (RhBug:1001553) */
    if (xc > 0 && yc > 0 && zc == xc) {
	uint32_t * i, nvalid = 0;
	/* ...and that the indexes are within bounds */
	while ((i = rpmtdNextUint32(zd))) {
	    if (*i >= yc)
		break;
	    nvalid++;
	}
	/* unless the loop runs to finish, the data is broken */
	sane = (nvalid == zc);
    }
    return sane;
}

/* Get file data from header */
/* Requires totalfc to be set and label err: to goto on error */
#define _hgfi(_h, _tag, _td, _flags, _data) \
    if (headerGet((_h), (_tag), (_td), (_flags))) { \
	if (rpmtdCount(_td) != totalfc) { \
	    rpmlog(RPMLOG_ERR, _("Wrong number of entries for tag %s: %u found but %u expected.\n"), rpmTagGetName(_tag), rpmtdCount(_td), totalfc); \
	    goto err; \
	} \
	if (rpmTagGetTagType(_tag) != RPM_STRING_ARRAY_TYPE && rpmTagGetTagType(_tag) != RPM_I18NSTRING_TYPE && \
	    (_td)->size < totalfc * sizeof(*(_data))) {		\
	    rpmlog(RPMLOG_ERR, _("Malformed data for tag %s: %u bytes found but %" PRIu64 " expected.\n"), rpmTagGetName(_tag), (_td)->size, (uint64_t)totalfc * sizeof(*(_data))); \
	    goto err;				\
	} \
	_data = (typeof((_data)))((_td)->data); \
    }
/* Get file data from header without checking number of entries */
#define _hgfinc(_h, _tag, _td, _flags, _data) \
    if (headerGet((_h), (_tag), (_td), (_flags))) {\
	_data = (typeof((_data)))((_td)->data);	   \
    }

/*** Hard link handling ***/

struct fileid_s {
    rpm_dev_t id_dev;
    rpm_ino_t id_ino;
};

#define HASHTYPE fileidHash
#define HTKEYTYPE struct fileid_s
#define HTDATATYPE int
#include "rpmhash.H"
#include "rpmhash.C"
#undef HASHTYPE
#undef HTKEYTYPE
#undef HTDATATYPE

static unsigned int fidHashFunc(struct fileid_s a)
{
    return  a.id_ino + (a.id_dev<<16) + (a.id_dev>>16);
}

static int fidCmp(struct fileid_s a, struct fileid_s b)
{
    return  !((a.id_dev == b.id_dev) && (a.id_ino == b.id_ino));
}

static unsigned int intHash(int a)
{
    return a < 0 ? UINT_MAX-a : a;
}

static int intCmp(int a, int b)
{
    return a != b;
}

static struct hardlinks_s * freeNLinks(struct hardlinks_s * nlinks)
{
    nlinks->nlink--;
    if (!nlinks->nlink) {
	nlinks = _free(nlinks);
    }
    return nlinks;
}

static void rpmfilesBuildNLink(rpmfiles fi, Header h)
{
    struct fileid_s f_id;
    fileidHash files;
    rpm_dev_t * fdevs = NULL;
    struct rpmtd_s td;
    int fc = 0;
    int totalfc = rpmfilesFC(fi);

    if (!fi->finodes)
	return;

    _hgfi(h, RPMTAG_FILEDEVICES, &td, HEADERGET_ALLOC, fdevs);
    if (!fdevs)
	return;

    files = fileidHashCreate(totalfc, fidHashFunc, fidCmp, NULL, NULL);
    for (int i=0; i < totalfc; i++) {
	if (!S_ISREG(rpmfilesFMode(fi, i)) ||
		(rpmfilesFFlags(fi, i) & RPMFILE_GHOST) ||
		fi->finodes[i] <= 0) {
	    continue;
	}
	fc++;
	f_id.id_dev = fdevs[i];
	f_id.id_ino = fi->finodes[i];
	fileidHashAddEntry(files, f_id, i);
    }
    if (fileidHashNumKeys(files) != fc) {
	/* Hard links */
	fi->nlinks = nlinkHashCreate(2*(totalfc - fileidHashNumKeys(files)),
		intHash, intCmp, NULL, freeNLinks);
	for (int i=0; i < totalfc; i++) {
	    int fcnt;
	    int * data;
	    if (!S_ISREG(rpmfilesFMode(fi, i)) ||
		    (rpmfilesFFlags(fi, i) & RPMFILE_GHOST)) {
		continue;
	    }
	    f_id.id_dev = fdevs[i];
	    f_id.id_ino = fi->finodes[i];
	    fileidHashGetEntry(files, f_id, &data, &fcnt, NULL);
	    if (fcnt > 1 && !nlinkHashHasEntry(fi->nlinks, i)) {
		struct hardlinks_s * hlinks;
		hlinks = (struct hardlinks_s *)xmalloc(sizeof(*hlinks) +
			fcnt*sizeof(hlinks->files[0]));
		hlinks->nlink = fcnt;
		for (int j=0; j<fcnt; j++) {
		    hlinks->files[j] = data[j];
		    nlinkHashAddEntry(fi->nlinks, data[j], hlinks);
		}
	    }
	}
    }
    _free(fdevs);
    files = fileidHashFree(files);
err:
    return;
}

/*
 * Convert a tag of variable len hex strings to binary presentation,
 * accessed via offsets to a contiguous binary blob. Empty values
 * are represented by identical consequtive offsets. The offsets array
 * always has one extra element to allow calculating the size of the
 * last element.
 */
static uint8_t *hex2binv(Header h, rpmTagVal tag, rpm_count_t num,
			uint32_t **offsetp)
{
    struct rpmtd_s td;
    uint8_t *bin = NULL;
    uint32_t *offs = NULL;

    if (headerGet(h, tag, &td, HEADERGET_MINMEM) && rpmtdCount(&td) == num) {
	const char *s;
	int i = 0;
	uint8_t *t = bin = (uint8_t *)xmalloc(((rpmtdSize(&td) / 2) + 1));
	offs = (uint32_t *)xmalloc((num + 1) * sizeof(*offs));

	while ((s = rpmtdNextString(&td))) {
	    uint32_t slen = strlen(s);
	    uint32_t len = slen / 2;
	    if (slen % 2) {
		bin = _free(bin);
		offs = _free(offs);
		goto exit;
	    }
	    offs[i] = t - bin;
	    for (int j = 0; j < len; j++, t++, s += 2)
		*t = (rnibble(s[0]) << 4) | rnibble(s[1]);
	    i++;
	}
	offs[i] = t - bin;
	*offsetp = offs;
    }

exit:
    rpmtdFreeData(&td);
    return bin;
}

/* Convert a tag of hex strings to binary presentation */
static uint8_t *hex2bin(Header h, rpmTagVal tag, rpm_count_t num, size_t len)
{
    struct rpmtd_s td;
    uint8_t *bin = NULL;

    if (headerGet(h, tag, &td, HEADERGET_MINMEM) && rpmtdCount(&td) == num) {
	uint8_t *t = bin = (uint8_t *)xmalloc(num * len);
	const char *s;

	while ((s = rpmtdNextString(&td))) {
	    if (*s == '\0') {
		memset(t, 0, len);
		t += len;
		continue;
	    }
	    if (strlen(s) != len * 2) {
		bin = _free(bin);
		break;
	    }
	    for (int j = 0; j < len; j++, t++, s += 2)
		*t = (rnibble(s[0]) << 4) | rnibble(s[1]);
	}
    }
    rpmtdFreeData(&td);

    return bin;
}

/*
 * Convert a tag of base64 strings to binary presentation.
 * This handles variable length strings by finding the longest string
 * before building the output array. Dummy strings in the tag should be
 * added as '\0'
 */
static uint8_t *base2bin(Header h, rpmTagVal tag, rpm_count_t num, int *len)
{
    struct rpmtd_s td;
    uint8_t *bin = NULL, *t = NULL;
    size_t maxlen = 0;
    int status, i= 0;
    uint8_t **arr = (uint8_t **)xmalloc(num * sizeof(void *));
    size_t *lengths = (size_t *)xcalloc(num, sizeof(size_t));
    const char *s;

    if (!headerGet(h, tag, &td, HEADERGET_MINMEM) || rpmtdCount(&td) != num)
	goto out;

    while ((s = rpmtdNextString(&td))) {
	/* Insert a dummy entry for empty strings */
	if (*s == '\0') {
	    arr[i++] = NULL;
	    continue;
	}
	status = rpmBase64Decode(s, (void**)&arr[i], &lengths[i]);
	if (lengths[i] > maxlen)
	    maxlen = lengths[i];
	if (status) {
	    rpmlog(RPMLOG_DEBUG, _("%s: base64 decode failed, len %zu\n"),
		   __func__, lengths[i]);
	    goto out;
	}
	i++;
    }

    if (maxlen) {
	rpmlog(RPMLOG_DEBUG, _("%s: base64 decode success, len %zu\n"),
	       __func__, maxlen);

	t = bin = (uint8_t *)xcalloc(num, maxlen);

	for (i = 0; i < num; i++) {
	    if (arr[i]) {
		memcpy(t, arr[i], lengths[i]);
		free(arr[i]);
	    }
	    t += maxlen;
	}
	*len = maxlen;
    }
 out:
    free(arr);
    free(lengths);
    rpmtdFreeData(&td);

    return bin;
}

static int rpmfilesPopulate(rpmfiles fi, Header h, rpmfiFlags flags)
{
    headerGetFlags scareFlags = (flags & RPMFI_KEEPHEADER) ? 
				HEADERGET_MINMEM : HEADERGET_ALLOC;
    headerGetFlags defFlags = HEADERGET_ALLOC;
    struct rpmtd_s digalgo, td;
    rpm_count_t totalfc = rpmfilesFC(fi);

    /* XXX TODO: all these should be sanity checked, ugh... */
    if (!(flags & RPMFI_NOFILEMODES))
	_hgfi(h, RPMTAG_FILEMODES, &td, scareFlags, fi->fmodes);
    if (!(flags & RPMFI_NOFILEFLAGS))
	_hgfi(h, RPMTAG_FILEFLAGS, &td, scareFlags, fi->fflags);
    if (!(flags & RPMFI_NOFILEVERIFYFLAGS))
	_hgfi(h, RPMTAG_FILEVERIFYFLAGS, &td, scareFlags, fi->vflags);
    if (!(flags & RPMFI_NOFILESIZES)) {
	_hgfi(h, RPMTAG_FILESIZES, &td, scareFlags, fi->fsizes);
	_hgfi(h, RPMTAG_LONGFILESIZES, &td, scareFlags, fi->lfsizes);
    }
    if (!(flags & RPMFI_NOFILECOLORS))
	_hgfi(h, RPMTAG_FILECOLORS, &td, scareFlags, fi->fcolors);

    if (!(flags & RPMFI_NOFILECLASS)) {
	_hgfinc(h, RPMTAG_CLASSDICT, &td, scareFlags, fi->cdict);
	fi->ncdict = rpmtdCount(&td);
	_hgfi(h, RPMTAG_FILECLASS, &td, scareFlags, fi->fcdictx);
    }
    if (!(flags & RPMFI_NOFILEDEPS)) {
	_hgfinc(h, RPMTAG_DEPENDSDICT, &td, scareFlags, fi->ddict);
	fi->nddict = rpmtdCount(&td);
	_hgfinc(h, RPMTAG_FILEDEPENDSX, &td, scareFlags, fi->fddictx);
	_hgfinc(h, RPMTAG_FILEDEPENDSN, &td, scareFlags, fi->fddictn);
    }

    if (!(flags & RPMFI_NOFILESTATES))
	_hgfi(h, RPMTAG_FILESTATES, &td, defFlags, fi->fstates);

    if (!(flags & RPMFI_NOFILECAPS))
	_hgfi(h, RPMTAG_FILECAPS, &td, defFlags, fi->fcaps);

    if (!(flags & RPMFI_NOFILELINKTOS))
	fi->flinks = tag2pool(fi->pool, h, RPMTAG_FILELINKTOS, totalfc);
    /* FILELANGS are only interesting when installing */
    if ((headerGetInstance(h) == 0) && !(flags & RPMFI_NOFILELANGS))
	fi->flangs = tag2pool(fi->pool, h, RPMTAG_FILELANGS, totalfc);

    /* See if the package has non-md5 file digests */
    fi->digestalgo = RPM_HASH_MD5;
    if (headerGet(h, RPMTAG_FILEDIGESTALGO, &digalgo, HEADERGET_MINMEM)) {
	uint32_t *algo = rpmtdGetUint32(&digalgo);
	/* Hmm, what to do with unknown digest algorithms? */
	if (algo && rpmDigestLength(*algo) != 0) {
	    fi->digestalgo = *algo;
	}
    }

    fi->digests = NULL;
    /* grab hex digests from header and store in binary format */
    if (!(flags & RPMFI_NOFILEDIGESTS)) {
	size_t diglen = rpmDigestLength(fi->digestalgo);
	fi->digests = hex2bin(h, RPMTAG_FILEDIGESTS, totalfc, diglen);
    }

    fi->signatures = NULL;
    /* grab hex signatures from header and store in binary format */
    if (!(flags & RPMFI_NOFILESIGNATURES)) {
	fi->signatures = hex2binv(h, RPMTAG_FILESIGNATURES,
				 totalfc, &fi->signatureoffs);
    }

    fi->veritysigs = NULL;
    if (!(flags & RPMFI_NOVERITYSIGNATURES)) {
	fi->verityalgo = headerGetNumber(h, RPMTAG_VERITYSIGNATUREALGO);
	fi->veritysigs = base2bin(h, RPMTAG_VERITYSIGNATURES,
				  totalfc, &fi->veritysiglength);
    }

    /* XXX TR_REMOVED doesn;t need fmtimes, frdevs, finodes */
    if (!(flags & RPMFI_NOFILEMTIMES))
	_hgfi(h, RPMTAG_FILEMTIMES, &td, scareFlags, fi->fmtimes);
    if (!(flags & RPMFI_NOFILERDEVS))
	_hgfi(h, RPMTAG_FILERDEVS, &td, scareFlags, fi->frdevs);
    if (!(flags & RPMFI_NOFILEINODES)) {
	_hgfi(h, RPMTAG_FILEINODES, &td, scareFlags, fi->finodes);
	rpmfilesBuildNLink(fi, h);
    }
    if (!(flags & RPMFI_NOFILEUSER)) {
	fi->fuser = tag2pool(fi->pool, h, RPMTAG_FILEUSERNAME, totalfc);
	if (!fi->fuser) goto err;
    }
    if (!(flags & RPMFI_NOFILEGROUP)) {
	fi->fgroup = tag2pool(fi->pool, h, RPMTAG_FILEGROUPNAME, totalfc);
	if (!fi->fgroup) goto err;
    }
    /* TODO: validate and return a real error */
    return 0;
 err:
    return -1;
}

rpmfiles rpmfilesNew(rpmstrPool pool, Header h, rpmTagVal tagN, rpmfiFlags flags)
{
    rpmfiles fi = (rpmfiles)xcalloc(1, sizeof(*fi));
    int fc;

    fi->magic = RPMFIMAGIC;
    fi->fiflags = flags;
    /* private or shared pool? */
    fi->pool = (pool != NULL) ? rpmstrPoolLink(pool) : rpmstrPoolCreate();

    /*
     * Grab and validate file triplet data. Headers with no files simply
     * fall through here and an empty file set is returned.
     */
    fc = rpmfnInit(&fi->fndata, RPMTAG_BASENAMES, h, fi->pool);

    /* Broken data, bail out */
    if (fc < 0)
	goto err;

    /* populate the rest of the stuff if we have files */
    if (fc > 0) {
	if (headerIsEntry(h, RPMTAG_ORIGBASENAMES)) {
	    /* For relocated packages, grab the original paths too */
	    int ofc;
	    fi->ofndata = (rpmfn)xmalloc(sizeof(*fi->ofndata));
	    ofc = rpmfnInit(fi->ofndata, RPMTAG_ORIGBASENAMES, h, fi->pool);
	    
	    if (ofc != 0 && ofc != fc)
		goto err;
	} else {
	    /* In the normal case, orig is the same as actual path data */
	    fi->ofndata = &fi->fndata;
	}
	    
	if (rpmfilesPopulate(fi, h, flags))
	    goto err;
    }

    /* freeze the pool to save memory, but only if private pool */
    if (fi->pool != pool)
	rpmstrPoolFreeze(fi->pool, 0);

    fi->h = (fi->fiflags & RPMFI_KEEPHEADER) ? headerLink(h) : NULL;

    return rpmfilesLink(fi);

err:
    rpmfilesFree(fi);
    return NULL;
}

static int iterWriteArchiveNext(rpmfi fi);
static int iterReadArchiveNext(rpmfi fi);
static int iterReadArchiveNextContentFirst(rpmfi fi);
static int iterReadArchiveNextOmitHardlinks(rpmfi fi);

static int (*nextfuncs[])(rpmfi fi) = {
    iterFwd,
    iterBack,
    iterWriteArchiveNext,
    iterReadArchiveNext,
    iterReadArchiveNextContentFirst,
    iterReadArchiveNextOmitHardlinks,
    iterInterval,
};


static rpmfi initIter(rpmfiles files, int itype, int link)
{
    rpmfi fi = NULL;

    if (files && itype>=0 && itype<=RPMFILEITERMAX) {
	fi = (rpmfi)xcalloc(1, sizeof(*fi));
	fi->i = -1;
	fi->j = -1;
	fi->files = link ? rpmfilesLink(files) : files;
	fi->next = nextfuncs[itype];
	if (itype == RPMFI_ITER_BACK) {
	    fi->i = rpmfilesFC(fi->files);
	} else if (itype >=RPMFI_ITER_READ_ARCHIVE
	    && itype <= RPMFI_ITER_READ_ARCHIVE_OMIT_HARDLINKS) {

	    fi->found = (uint8_t *)xcalloc(1, (rpmfiFC(fi)>>3) + 1);
	}
	rpmfiLink(fi);
    }
    return fi;
}

rpmfi rpmfilesIter(rpmfiles files, int itype)
{
    /* standalone iterators need to bump our refcount */
    return initIter(files, itype, 1);
}

rpmfi rpmfilesFindPrefix(rpmfiles fi, const char *pfx)
{
    int l, u, c, comparison;
    rpmfi iterator = NULL;

    if (!fi || !pfx)
	return NULL;

    size_t plen = strlen(pfx);
    l = 0;
    u = rpmfilesFC(fi);
    while (l < u) {
	c = (l + u) / 2;

	comparison = cmpPfx(fi, c, pfx, plen);

	if (comparison < 0)
	    u = c;
	else if (comparison > 0)
	    l = c + 1;
	else {
	    if (cmpPfx(fi, l, pfx, plen))
		l = c;
	    while (l > 0 && !cmpPfx(fi, l - 1, pfx, plen))
		l--;
	    if ( u >= rpmfilesFC(fi) || cmpPfx(fi, u, pfx, plen))
		u = c;
	    while (++u < rpmfilesFC(fi)) {
		if (cmpPfx(fi, u, pfx, plen))
		    break;
	    }
	    break;
	}

    }

    if (l < u) {
	iterator = initIter(fi, RPMFI_ITER_INTERVAL, 1);
	iterator->intervalStart = l;
	iterator->intervalEnd = u;
    }

    return iterator;
}

rpmfi rpmfiNewPool(rpmstrPool pool, Header h, rpmTagVal tagN, rpmfiFlags flags)
{
    rpmfiles files = rpmfilesNew(pool, h, tagN, flags);
    /* we already own rpmfiles, avoid extra refcount on it */
    return initIter(files, RPMFI_ITER_FWD, 0);
}

rpmfi rpmfiNew(const rpmts ts, Header h, rpmTagVal tagN, rpmfiFlags flags)
{
    return rpmfiNewPool(NULL, h, tagN, flags);
}

void rpmfilesSetFReplacedSize(rpmfiles fi, int ix, rpm_loff_t newsize)
{
    if (fi != NULL && ix >= 0 && ix < rpmfilesFC(fi)) {
	/* Switch over to 64 bit variant */
	int fc = rpmfilesFC(fi);
	if (fi->replacedSizes == NULL)
	    fi->replacedSizes = (rpm_loff_t *)xcalloc(fc, sizeof(*fi->replacedSizes));
	fi->replacedSizes[ix] = newsize;
    }
}

rpm_loff_t rpmfilesFReplacedSize(rpmfiles fi, int ix)
{
    rpm_loff_t rsize = 0;
    if (fi != NULL && ix >= 0 && ix < rpmfilesFC(fi)) {
	if (fi->replacedSizes) {
	    rsize = fi->replacedSizes[ix];
	}
    }
    return rsize;
}

void rpmfilesFpLookup(rpmfiles fi, fingerPrintCache fpc)
{
    /* This can get called twice (eg yum), scratch former results and redo */
    if (rpmfilesFC(fi) > 0) {
	rpmfn fn = &fi->fndata;
	if (fi->fps)
	    free(fi->fps);
	fi->fps = fpLookupList(fpc, fi->pool,
			       fn->dnid, fn->bnid, fn->dil, fn->fc);
    }
}

/* 
 * Generate iterator accessors function wrappers, these do nothing but
 * call the corresponding rpmfiFooIndex(fi, fi->[ij])
 */

#define RPMFI_ITERFUNC(TYPE, NAME, IXV) \
    TYPE rpmfi ## NAME(rpmfi fi) { return rpmfiles ## NAME(fi ? fi->files : NULL, fi ? fi->IXV : -1); }

RPMFI_ITERFUNC(rpmsid, BNId, i)
RPMFI_ITERFUNC(rpmsid, DNId, j)
RPMFI_ITERFUNC(const char *, BN, i)
RPMFI_ITERFUNC(const char *, DN, j)
RPMFI_ITERFUNC(const char *, OBN, i)
RPMFI_ITERFUNC(const char *, ODN, j)
RPMFI_ITERFUNC(const char *, FLink, i)
RPMFI_ITERFUNC(const char *, FUser, i)
RPMFI_ITERFUNC(const char *, FGroup, i)
RPMFI_ITERFUNC(const char *, FCaps, i)
RPMFI_ITERFUNC(const char *, FLangs, i)
RPMFI_ITERFUNC(const char *, FClass, i)
RPMFI_ITERFUNC(rpmfileState, FState, i)
RPMFI_ITERFUNC(rpmfileAttrs, FFlags, i)
RPMFI_ITERFUNC(rpmVerifyAttrs, VFlags, i)
RPMFI_ITERFUNC(rpm_mode_t, FMode, i)
RPMFI_ITERFUNC(rpm_rdev_t, FRdev, i)
RPMFI_ITERFUNC(rpm_time_t, FMtime, i)
RPMFI_ITERFUNC(rpm_ino_t, FInode, i)
RPMFI_ITERFUNC(rpm_loff_t, FSize, i)
RPMFI_ITERFUNC(rpm_color_t, FColor, i)
RPMFI_ITERFUNC(uint32_t, FNlink, i)

const char * rpmfiFN(rpmfi fi)
{
    const char *fn = ""; /* preserve behavior on errors */
    if (fi != NULL) {
	free(fi->fn);
	fi->fn = rpmfilesFN(fi->files, fi->i);
	if (fi->fn != NULL)
	    fn = fi->fn;
    }
    return fn;
}

const char * rpmfiOFN(rpmfi fi)
{
    const char *fn = ""; /* preserve behavior on errors */
    if (fi != NULL) {
	free(fi->ofn);
	fi->ofn = rpmfilesOFN(fi->files, fi->i);
	if (fi->ofn != NULL)
	    fn = fi->ofn;
    }
    return fn;
}

const unsigned char * rpmfiFDigest(rpmfi fi, int *algo, size_t *len)
{
    return rpmfilesFDigest(fi ? fi->files : NULL, fi ? fi->i : -1, algo, len);
}

const unsigned char * rpmfiFSignature(rpmfi fi, size_t *len)
{
    return rpmfilesFSignature(fi ? fi->files : NULL, fi ? fi->i : -1, len);
}

const unsigned char * rpmfiVSignature(rpmfi fi, size_t *len, uint16_t *algo)
{
    return rpmfilesVSignature(fi ? fi->files : NULL, fi ? fi->i : -1, len, algo);
}

uint32_t rpmfiFDepends(rpmfi fi, const uint32_t ** fddictp)
{
    return rpmfilesFDepends(fi ? fi->files : NULL,  fi ? fi->i : -1, fddictp);
}

int rpmfiStat(rpmfi fi, int flags, struct stat *sb)
{
    int rc = -1;
    if (fi != NULL) {
	rc = rpmfilesStat(fi->files, fi->i, flags, sb);
	/* In archives, hardlinked files are empty except for the last one */
	if (rc == 0 && fi->archive && sb->st_nlink > 1) {
	    const int *links = NULL;
	    if (rpmfiFLinks(fi, &links) && links[sb->st_nlink-1] != fi->i)
		sb->st_size = 0;
	}
    }
    return rc;
}

int rpmfiCompare(const rpmfi afi, const rpmfi bfi)
{
    return rpmfilesCompare(afi ? afi->files : NULL, afi ? afi->i : -1,
			   bfi ? bfi->files : NULL, bfi ? bfi->i : -1);
}

rpmVerifyAttrs rpmfiVerify(rpmfi fi, rpmVerifyAttrs omitMask)
{
    return rpmfilesVerify(fi->files, fi->i, omitMask);
}

rpmstrPool rpmfilesPool(rpmfiles fi)
{
    return (fi != NULL) ? fi->pool : NULL;
}

rpmfiles rpmfiFiles(rpmfi fi)
{
    return (fi != NULL) ? fi->files : NULL;
}

/******************************************************/
/*** Archive handling *********************************/
/******************************************************/

rpmfi rpmfiNewArchiveReader(FD_t fd, rpmfiles files, int itype)
{
    rpmcpio_t archive = rpmcpioOpen(fd, O_RDONLY);
    rpmfi fi = NULL;
    if (archive && itype >= RPMFI_ITER_READ_ARCHIVE) {
	fi = rpmfilesIter(files, itype);
    }
    if (fi) {
	fi->archive = archive;
    } else {
	rpmcpioFree(archive);
    }
    return fi;
}

rpmfi rpmfiNewArchiveWriter(FD_t fd, rpmfiles files)
{
    rpmcpio_t archive = rpmcpioOpen(fd, O_WRONLY);
    rpmfi fi = NULL;
    if (archive) {
	fi = rpmfilesIter(files, RPMFI_ITER_WRITE_ARCHIVE);
    }
    if (fi) {
	fi->archive = archive;
    } else {
	rpmcpioFree(archive);
    }
    return fi;
}

int rpmfiArchiveClose(rpmfi fi)
{
    if (fi == NULL)
	return -1;
    int rc = rpmcpioClose(fi->archive);
    return rc;
}

rpm_loff_t rpmfiArchiveTell(rpmfi fi)
{
    if (fi == NULL || fi->archive == NULL)
	return 0;
    return (rpm_loff_t) rpmcpioTell(fi->archive);
}

static int rpmfiArchiveWriteHeader(rpmfi fi)
{
    int rc;
    struct stat st;

    if (rpmfiStat(fi, 0, &st))
	return -1;

    rpmfiles files = fi->files;

    if (files->lfsizes) {
	return rpmcpioStrippedHeaderWrite(fi->archive, rpmfiFX(fi), st.st_size);
    } else {
	const char * dn = rpmfiDN(fi);
	char * path = rstrscat(NULL, (dn[0] == '/' && !rpmExpandNumeric("%{_noPayloadPrefix}")) ? "." : "",
			       dn, rpmfiBN(fi), NULL);
	rc = rpmcpioHeaderWrite(fi->archive, path, &st);
	free(path);
    }

    return rc;
}

static int iterWriteArchiveNextFile(rpmfi fi)
{
    rpmfiles files = rpmfiFiles(fi);
    int fx = rpmfiFX(fi);
    int fc = rpmfiFC(fi);
    const int * hardlinks;
    int numHardlinks = 0;

    /* already processing hard linked files */
    if (rpmfiFNlink(fi) > 1) {
	/* search next hard linked file */
	fi->i = -1;
	for (int i=fx+1; i<fc; i++) {
	    /* no ghosts */
	    if (rpmfilesFFlags(files, i) & RPMFILE_GHOST)
		continue;
	    numHardlinks = rpmfilesFLinks(files, i, &hardlinks);
	    if (numHardlinks > 1 && hardlinks[0] == i) {
		rpmfiSetFX(fi, i);
		break;
	    }
	}
    } else {
	fi->i = -1;
	/* search next non hardlinked file */
	for (int i=fx+1; i<fc; i++) {
	    /* no ghosts */
	    if (rpmfilesFFlags(files, i) & RPMFILE_GHOST)
		continue;
	    if (rpmfilesFNlink(files, i) < 2) {
		rpmfiSetFX(fi, i);
		break;
	    }
	}
	if (rpmfiFX(fi) == -1) {
	    /* continue with first hard linked file */
	    for (int i=0; i<fc; i++) {
		/* no ghosts */
		if (rpmfilesFFlags(files, i) & RPMFILE_GHOST)
		    continue;
		numHardlinks = rpmfilesFLinks(files, i, &hardlinks);
		if (numHardlinks > 1) {
		    rpmfiSetFX(fi, i);
		    break;
		}
	    }
	}
    }
    if (rpmfiFX(fi) == -1)
	return -1;

    /* write header(s) */
    if (numHardlinks>1) {
	for (int i=0; i<numHardlinks; i++) {
	    rpmfiSetFX(fi, hardlinks[i]);
	    int rc = rpmfiArchiveWriteHeader(fi);
	    if (rc) {
		return rc;
	    }
	}
	rpmfiSetFX(fi, hardlinks[0]);
    } else {
	int rc = rpmfiArchiveWriteHeader(fi);
	if (rc) {
	    return rc;
	}
    }
    return rpmfiFX(fi);
}

static int iterWriteArchiveNext(rpmfi fi)
{
    int fx;
    /* loop over the files we can handle ourself */
    do {
	fx = iterWriteArchiveNextFile(fi);
	if (S_ISLNK(rpmfiFMode(fi))) {
	    /* write symlink target */
	    const char *lnk = rpmfiFLink(fi);
	    size_t len = strlen(lnk);
	    if (rpmfiArchiveWrite(fi, lnk, len) != len) {
		return RPMERR_WRITE_FAILED;
	    }
	} else if (S_ISREG(rpmfiFMode(fi)) && rpmfiFSize(fi)) {
	    /* this file actually needs some content */
	    return fx;
	}
	/* go on for special files, directories and empty files */
    } while (fx >= 0);
    return fx;
}

size_t rpmfiArchiveWrite(rpmfi fi, const void * buf, size_t size)
{
    if (fi == NULL || fi->archive == NULL)
	return -1;
    return rpmcpioWrite(fi->archive, buf, size);
}

int rpmfiArchiveWriteFile(rpmfi fi, FD_t fd)
{
    rpm_loff_t left;
    int rc = 0;
    size_t len;
    char buf[BUFSIZ*4];

    if (fi == NULL || fi->archive == NULL || fd == NULL)
	return -1;

    left = rpmfiFSize(fi);

    while (left) {
	len = (left > sizeof(buf) ? sizeof(buf) : left);
	if (Fread(buf, sizeof(*buf), len, fd) != len || Ferror(fd)) {
	    rc = RPMERR_READ_FAILED;
	    break;
	}

	if (rpmcpioWrite(fi->archive, buf, len) != len) {
	    rc = RPMERR_WRITE_FAILED;
	    break;
	}
	left -= len;
    }
    return rc;
}

static void rpmfiSetFound(rpmfi fi, int ix)
{
    fi->found[ix >> 3] |= (1 << (ix % 8));
}

static int rpmfiFound(rpmfi fi, int ix)
{
    return fi->found[ix >> 3] & (1 << (ix % 8));
}

static int iterReadArchiveNext(rpmfi fi)
{
    int rc;
    int fx = -1;
    int fc = rpmfilesFC(fi->files);
    char * path = NULL;

    if (fi->archive == NULL)
	return -1;

    /* Read next payload header. */
    rc = rpmcpioHeaderRead(fi->archive, &path, &fx);

    /* if archive ended, check if we found all files */
    if (rc == RPMERR_ITER_END) {
	for (int i=0; i<fc; i++) {
	    if (!rpmfiFound(fi, i) &&
			!(rpmfilesFFlags(fi->files, i) & RPMFILE_GHOST)) {
                rc = RPMERR_MISSING_FILE;
		break;
            }
	}
    }
    if (rc) {
	return rc;
    }

    if (path) {
	/* Regular cpio archive, identify mapping index. */
	fx = rpmfilesFindOFN(fi->files, path);
	free(path);
    }

    if (fx >= 0 && fx < fc) {
	rpm_loff_t fsize = 0;
	rpm_mode_t mode = rpmfilesFMode(fi->files, fx);

	/* %ghost in payload, should not be there but rpm < 4.11 sometimes did this */
	if (rpmfilesFFlags(fi->files, fx) & RPMFILE_GHOST)
	    return RPMERR_ITER_SKIP;

	if (S_ISREG(mode)) {
	    const int * links;
	    uint32_t numlinks = rpmfilesFLinks(fi->files, fx, &links);
	    if (!(numlinks > 1 && links[numlinks-1] != fx))
		fsize = rpmfilesFSize(fi->files, fx);
	} else if (S_ISLNK(mode)) {
	    /* Skip over symlink target data in payload */
	    rpm_loff_t lsize = rpmfilesFSize(fi->files, fx);
	    char *buf = (char *)xmalloc(lsize + 1);
	    if (rpmcpioRead(fi->archive, buf, lsize) != lsize)
		rc = RPMERR_READ_FAILED;
	    /* XXX should we validate the payload matches? */
	    free(buf);
	}
	rpmcpioSetExpectedFileSize(fi->archive, fsize);
	rpmfiSetFound(fi, fx);
    } else {
	/* Mapping error */
	rc = RPMERR_UNMAPPED_FILE;
    }
    return (rc != 0) ? rc : fx;
}


static int iterReadArchiveNextOmitHardlinks(rpmfi fi)
{
    int fx;
    const int * links;
    int nlink;
    do {
	fx = iterReadArchiveNext(fi);
	nlink = rpmfilesFLinks(fi->files, fx, &links);
    } while (fx>=0 && nlink>1 && links[nlink-1]!=fx);
    return fx;
}

static int iterReadArchiveNextContentFirst(rpmfi fi)
{
    int fx = rpmfiFX(fi);
    const int * links;
    int nlink;
    /* decide what to do on the basis of the last entry */
    nlink = rpmfilesFLinks(fi->files, fx, &links);
    if (nlink > 1) {
	/* currently reading through hard links */
	if (fx == links[nlink-1]) {
	    /* arrived back at last entry, read on */
	    fx = iterReadArchiveNext(fi);    
	} else {
	    /* next hard link */
	    /* scales poorly but shouldn't matter */
	    for (int i=0; i<nlink; i++) {
		if (links[i] == fx) {
		    fx = links[i+1];
		    return fx;
		}
	    }
	    /* should never happen */
	    return -1;
	}
    } else {
	fx = iterReadArchiveNext(fi);
    }

    /* look at the new entry */
    nlink = rpmfilesFLinks(fi->files, fx, &links);
    /* arrived at new set of hardlinks? */
    if (nlink > 1) {
	/* read over all entries to the last one (containing the content) */
	do {
	    fx = iterReadArchiveNext(fi);
	} while (fx >=0 && fx != links[nlink-1]);
	/* rewind to the first entry */
	if (fx >= 0) {
	    fx = links[0];
	}
    }
    return fx;
}

int rpmfiArchiveHasContent(rpmfi fi)
{
    int res = 0;
    if (fi && S_ISREG(rpmfiFMode(fi))) {
	const int * links;
	int nlink = rpmfiFLinks(fi, &links);
	if (nlink > 1) {
	    if (fi->next == iterReadArchiveNext ||
		fi->next == iterReadArchiveNextOmitHardlinks) {
		res = rpmfiFX(fi) == links[nlink-1];
	    } else if (fi->next == iterReadArchiveNextContentFirst) {
		res = rpmfiFX(fi) == links[0];
	    }
	} else {
	    res = 1;
	}
    }
    return res;
}

ssize_t rpmfiArchiveRead(rpmfi fi, void * buf, size_t size)
{
    if (fi == NULL || fi->archive == NULL)
	return -1;
    return rpmcpioRead(fi->archive, buf, size);
}

int rpmfiArchiveReadToFilePsm(rpmfi fi, FD_t fd, int nodigest, rpmpsm psm)
{
    if (fi == NULL || fi->archive == NULL || fd == NULL)
	return -1;

    rpm_loff_t left = rpmfiFSize(fi);
    const unsigned char * fidigest = NULL;
    int digestalgo = 0;
    int rc = 0;
    char buf[BUFSIZ*4];

    if (!nodigest) {
	digestalgo = rpmfiDigestAlgo(fi);
	fidigest = rpmfilesFDigest(fi->files, rpmfiFX(fi), NULL, NULL);
	fdInitDigest(fd, digestalgo, 0);
    }

    while (left) {
	size_t len;
	len = (left > sizeof(buf) ? sizeof(buf) : left);
	if (rpmcpioRead(fi->archive, buf, len) != len) {
	    rc = RPMERR_READ_FAILED;
	    goto exit;
	}
	if ((Fwrite(buf, sizeof(*buf), len, fd) != len) || Ferror(fd)) {
	    rc = RPMERR_WRITE_FAILED;
	    goto exit;
	}

	rpmpsmNotify(psm, RPMCALLBACK_INST_PROGRESS, rpmfiArchiveTell(fi));
	left -= len;
    }

    if (!nodigest) {
	void * digest = NULL;

	(void) Fflush(fd);
	fdFiniDigest(fd, digestalgo, &digest, NULL, 0);

	if (digest != NULL && fidigest != NULL) {
	    size_t diglen = rpmDigestLength(digestalgo);
	    if (memcmp(digest, fidigest, diglen)) {
		rc = RPMERR_DIGEST_MISMATCH;

		/* ...but in old packages, empty files have zeros for digest */
		if (rpmfiFSize(fi) == 0 && digestalgo == RPM_HASH_MD5) {
		    uint8_t zeros[diglen];
		    memset(&zeros, 0, diglen);
		    if (memcmp(zeros, fidigest, diglen) == 0)
			rc = 0;
		}
	    }
	} else {
	    rc = RPMERR_DIGEST_MISMATCH;
	}
	free(digest);
    }

exit:
    return rc;
}

int rpmfiArchiveReadToFile(rpmfi fi, FD_t fd, int nodigest)
{
    return rpmfiArchiveReadToFilePsm(fi, fd, nodigest, NULL);
}

char * rpmfileStrerror(int rc)
{
    char *msg = NULL;
    const char *s = NULL;
    const char *prefix = "cpio";
    int myerrno = errno;

    switch (rc) {
    default:
	break;
    case RPMERR_BAD_MAGIC:	s = _("Bad magic");		break;
    case RPMERR_BAD_HEADER:	s = _("Bad/unreadable  header");break;

    case RPMERR_OPEN_FAILED:	s = "open";	break;
    case RPMERR_CHMOD_FAILED:	s = "chmod";	break;
    case RPMERR_CHOWN_FAILED:	s = "chown";	break;
    case RPMERR_WRITE_FAILED:	s = "write";	break;
    case RPMERR_UTIME_FAILED:	s = "utime";	break;
    case RPMERR_UNLINK_FAILED:	s = "unlink";	break;
    case RPMERR_RENAME_FAILED:	s = "rename";	break;
    case RPMERR_SYMLINK_FAILED: s = "symlink";	break;
    case RPMERR_STAT_FAILED:	s = "stat";	break;
    case RPMERR_LSTAT_FAILED:	s = "lstat";	break;
    case RPMERR_MKDIR_FAILED:	s = "mkdir";	break;
    case RPMERR_RMDIR_FAILED:	s = "rmdir";	break;
    case RPMERR_MKNOD_FAILED:	s = "mknod";	break;
    case RPMERR_MKFIFO_FAILED:	s = "mkfifo";	break;
    case RPMERR_LINK_FAILED:	s = "link";	break;
    case RPMERR_READLINK_FAILED: s = "readlink";	break;
    case RPMERR_READ_FAILED:	s = "read";	break;
    case RPMERR_COPY_FAILED:	s = "copy";	break;
    case RPMERR_LSETFCON_FAILED: s = "lsetfilecon";	break;
    case RPMERR_SETCAP_FAILED: s = "cap_set_file";	break;

    case RPMERR_HDR_SIZE:	s = _("Header size too big");	break;
    case RPMERR_FILE_SIZE:	s = _("File too large for archive");	break;
    case RPMERR_UNKNOWN_FILETYPE: s = _("Unknown file type");	break;
    case RPMERR_MISSING_FILE: s = _("Missing file(s)"); break;
    case RPMERR_DIGEST_MISMATCH: s = _("Digest mismatch");	break;
    case RPMERR_INTERNAL:	s = _("Internal error");	break;
    case RPMERR_UNMAPPED_FILE:	s = _("Archive file not in header"); break;
    case RPMERR_INVALID_SYMLINK: s = _("Unsafe symlink");	break;
    case RPMERR_ENOTDIR:	s = strerror(ENOTDIR);	break;
    case RPMERR_ENOENT:	s = strerror(ENOENT); break;
    case RPMERR_ENOTEMPTY:	s = strerror(ENOTEMPTY); break;
    case RPMERR_EXIST_AS_DIR:
	s = _("File from package already exists as a directory in system");
	break;
    }

    if (s != NULL) {
	rasprintf(&msg, "%s: %s", prefix, s);
	if ((rc <= RPMERR_CHECK_ERRNO) && myerrno) {
	    rstrscat(&msg, _(" failed - "), strerror(myerrno), NULL);
	}
    } else {
	rasprintf(&msg, _("%s: (error 0x%x)"), prefix, rc);
    }

    return msg;
}
