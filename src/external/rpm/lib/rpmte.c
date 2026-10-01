/** \ingroup rpmdep
 * \file lib/rpmte.c
 * Routine(s) to handle an "rpmte"  transaction element.
 */
#include "system.h"

#include <rpm/rpmtypes.h>
#include <rpm/rpmlib.h>		/* RPM_MACHTABLE_* */
#include <rpm/rpmmacro.h>
#include <rpm/rpmds.h>
#include <rpm/rpmfi.h>
#include <rpm/rpmstring.h>
#include <rpm/rpmts.h>
#include <rpm/rpmdb.h>
#include <rpm/rpmlog.h>

#include "misc.h"
#include "rpmplugins.h"
#include "rpmte_internal.h"
/* strpool-related interfaces */
#include "rpmfi_internal.h"
#include "rpmds_internal.h"
#include "rpmts_internal.h"

#include "debug.h"

/** \ingroup rpmte
 * A single package instance to be installed/removed atomically.
 */
struct rpmte_s {
    rpmElementType type;	/*!< Package disposition (installed/removed). */
    void *userdata;		/*!< Application private user data. */

    Header h;			/*!< Package header. */
    char * NEVR;		/*!< Package name-version-release. */
    char * NEVRA;		/*!< Package name-version-release.arch. */
    char * name;		/*!< Name: */
    char * epoch;
    char * version;		/*!< Version: */
    char * release;		/*!< Release: */
    char * arch;		/*!< Architecture hint. */
    char * os;			/*!< Operating system hint. */
    int isSource;		/*!< (TR_ADDED) source rpm? */

    rpmte depends;              /*!< Package updated by this package (ERASE te) */
    rpmte parent;		/*!< Parent transaction element. */
    unsigned int db_instance;	/*!< Database instance (of removed pkgs) */
    tsortInfo tsi;		/*!< Dependency ordering chains. */

    rpmds thisds;		/*!< This package's provided NEVR. */
    rpmds provides;		/*!< Provides: dependencies. */
    rpmds requires;		/*!< Requires: dependencies. */
    rpmds conflicts;		/*!< Conflicts: dependencies. */
    rpmds obsoletes;		/*!< Obsoletes: dependencies. */
    rpmds order;		/*!< Order: dependencies. */
    rpmds recommends;		/*!< Recommends: dependencies. */
    rpmds suggests;		/*!< Suggests: dependencies. */
    rpmds supplements;		/*!< Supplements: dependencies. */
    rpmds enhances;		/*!< Enhances: dependencies. */
    rpmfiles files;		/*!< File information. */
    rpmps probs;		/*!< Problems (relocations) */
    rpmts ts;			/*!< Parent transaction */

    rpm_color_t color;		/*!< Color bit(s) from package dependencies. */
    rpm_loff_t pkgFileSize;	/*!< No. of bytes in package file (approx). */
    unsigned int headerSize;	/*!< No. of bytes in package header */

    fnpyKey key;		/*!< (TR_ADDED) Retrieval key. */
    rpmRelocation * relocs;	/*!< (TR_ADDED) Payload file relocations. */
    int nrelocs;		/*!< (TR_ADDED) No. of relocations. */
    uint8_t *badrelocs;		/*!< (TR_ADDED) Bad relocations (or NULL) */
    FD_t fd;			/*!< (TR_ADDED) Payload file descriptor. */
    int verified;		/*!< (TR_ADDED) Verification status */
    int addop;			/*!< (TR_ADDED) RPMTE_INSTALL/UPDATE/REINSTALL */

#define RPMTE_HAVE_PRETRANS	(1 << 0)
#define RPMTE_HAVE_POSTTRANS	(1 << 1)
#define RPMTE_HAVE_PREUNTRANS	(1 << 2)
#define RPMTE_HAVE_POSTUNTRANS	(1 << 3)
    int transscripts;		/*!< pre/posttrans script existence */
    int failed;			/*!< (parent) install/erase failed */

    rpmfs fs;
};

/* forward declarations */
static void rpmteColorDS(rpmte te, rpmTag tag);
static int rpmteClose(rpmte te, int reset_fi);

void rpmteCleanDS(rpmte te)
{
    te->thisds = rpmdsFree(te->thisds);
    te->provides = rpmdsFree(te->provides);
    te->requires = rpmdsFree(te->requires);
    te->conflicts = rpmdsFree(te->conflicts);
    te->obsoletes = rpmdsFree(te->obsoletes);
    te->recommends = rpmdsFree(te->recommends);
    te->suggests = rpmdsFree(te->suggests);
    te->supplements = rpmdsFree(te->supplements);
    te->enhances = rpmdsFree(te->enhances);
    te->order = rpmdsFree(te->order);
}

static rpmfiles getFiles(rpmte p, Header h)
{
    rpmfiFlags fiflags = RPMFI_NOHEADER;
    switch (p->type) {
    case TR_ADDED:
    case TR_RESTORED:
	fiflags |= RPMFI_FLAGS_INSTALL;
	break;
    case TR_REMOVED:
    case TR_RPMDB:
	fiflags |= RPMFI_FLAGS_ERASE;
	break;
    }

    /* relocate stuff in header if necessary */
    if (rpmteType(p) == TR_ADDED && rpmfsFC(p->fs) > 0) {
	if (!headerIsEntry(h, RPMTAG_ORIGBASENAMES)) {
	    if (rpmteIsSource(p)) {
		/* Unlike binary packages, source relocation can fail */
		if (rpmRelocateSrpmFileList(h, rpmtsRootDir(p->ts)) < 0) {
		    return NULL;
		}
	    } else {
		rpmRelocateFileList(p->relocs, p->nrelocs, p->fs, h);
	    }
	}
    }
    return rpmfilesNew(rpmtsPool(p->ts), h, RPMTAG_BASENAMES, fiflags);
}

/**
 * Initialize transaction element data from header.
 * @param p		transaction element
 * @param h		header
 * @param key		(TR_ADDED) package retrieval key (e.g. file name)
 * @param relocs	(TR_ADDED) package file relocations
 */
static int addTE(rpmte p, Header h, fnpyKey key, rpmRelocation * relocs)
{
    rpmstrPool tspool = rpmtsPool(p->ts);
    struct rpmtd_s bnames;
    int rc = 1; /* assume failure */

    p->name = headerGetAsString(h, RPMTAG_NAME);
    p->version = headerGetAsString(h, RPMTAG_VERSION);
    p->release = headerGetAsString(h, RPMTAG_RELEASE);

    /* name, version and release are required in all packages */
    if (p->name == NULL || p->version == NULL || p->release == NULL)
	goto exit;

    p->epoch = headerGetAsString(h, RPMTAG_EPOCH);

    p->arch = headerGetAsString(h, RPMTAG_ARCH);
    p->os = headerGetAsString(h, RPMTAG_OS);

    if ((p->arch == NULL || p->os == NULL) &&
	(p->type != TR_REMOVED || !rstreq(p->name, "gpg-pubkey")))
	    goto exit;

    if (p->type != TR_REMOVED && rstreq(p->name, "gpg-pubkey")) {
	rpmlog(RPMLOG_ERR, _("public keys can not be installed as gpg-pubkey packages; use rpmkeys --import <keyfile> for that\n"));
	goto exit;
    }

    p->isSource = headerIsSource(h);
    
    p->NEVR = headerGetAsString(h, RPMTAG_NEVR);
    p->NEVRA = headerGetAsString(h, RPMTAG_NEVRA);

    p->nrelocs = 0;
    p->relocs = NULL;
    p->badrelocs = NULL;
    if (relocs != NULL)
	rpmRelocationBuild(h, relocs, &p->nrelocs, &p->relocs, &p->badrelocs);

    p->db_instance = headerGetInstance(h);
    p->key = key;
    p->fd = NULL;

    p->pkgFileSize = 0;
    p->headerSize = headerSizeof(h, HEADER_MAGIC_NO);

    p->thisds = rpmdsThisPool(tspool, h, RPMTAG_PROVIDENAME, RPMSENSE_EQUAL);
    p->provides = rpmdsNewPool(tspool, h, RPMTAG_PROVIDENAME, 0);
    p->requires = rpmdsNewPool(tspool, h, RPMTAG_REQUIRENAME, 0);
    p->conflicts = rpmdsNewPool(tspool, h, RPMTAG_CONFLICTNAME, 0);
    p->obsoletes = rpmdsNewPool(tspool, h, RPMTAG_OBSOLETENAME, 0);
    p->order = rpmdsNewPool(tspool, h, RPMTAG_ORDERNAME, 0);
    p->recommends = rpmdsNewPool(tspool, h, RPMTAG_RECOMMENDNAME, 0);
    p->suggests = rpmdsNewPool(tspool, h, RPMTAG_SUGGESTNAME, 0);
    p->supplements = rpmdsNewPool(tspool, h, RPMTAG_SUPPLEMENTNAME, 0);
    p->enhances = rpmdsNewPool(tspool, h, RPMTAG_ENHANCENAME, 0);

    /* Relocation needs to know file count before rpmfiNew() */
    headerGet(h, RPMTAG_BASENAMES, &bnames, HEADERGET_MINMEM);
    p->fs = rpmfsNew(rpmtdCount(&bnames),
		    (p->type == TR_ADDED || p->type == TR_RESTORED));
    rpmtdFreeData(&bnames);

    p->files = getFiles(p, h);

    /* Packages with no files return an empty file info set, NULL is an error */
    if (p->files == NULL)
	goto exit;

    /* See if we have pre/posttrans scripts. */
    p->transscripts |= (headerIsEntry(h, RPMTAG_PRETRANS) ||
			 headerIsEntry(h, RPMTAG_PRETRANSPROG)) ?
			RPMTE_HAVE_PRETRANS : 0;
    p->transscripts |= (headerIsEntry(h, RPMTAG_POSTTRANS) ||
			 headerIsEntry(h, RPMTAG_POSTTRANSPROG)) ?
			RPMTE_HAVE_POSTTRANS : 0;
    p->transscripts |= (headerIsEntry(h, RPMTAG_PREUNTRANS) ||
			 headerIsEntry(h, RPMTAG_PREUNTRANSPROG)) ?
			RPMTE_HAVE_PREUNTRANS : 0;
    p->transscripts |= (headerIsEntry(h, RPMTAG_POSTUNTRANS) ||
			 headerIsEntry(h, RPMTAG_POSTUNTRANSPROG)) ?
			RPMTE_HAVE_POSTUNTRANS : 0;

    rpmteColorDS(p, RPMTAG_PROVIDENAME);
    rpmteColorDS(p, RPMTAG_REQUIRENAME);

    if (p->type == TR_ADDED)
	p->pkgFileSize = headerGetNumber(h, RPMTAG_LONGSIGSIZE) + 96 + 256;

    rc = 0;

exit:
    return rc;
}

rpmte rpmteFree(rpmte te)
{
    if (te != NULL) {
	if (te->relocs) {
	    for (int i = 0; i < te->nrelocs; i++) {
		free(te->relocs[i].oldPath);
		free(te->relocs[i].newPath);
	    }
	    free(te->relocs);
	    free(te->badrelocs);
	}

	free(te->os);
	free(te->arch);
	free(te->epoch);
	free(te->name);
	free(te->version);
	free(te->release);
	free(te->NEVR);
	free(te->NEVRA);

	fdFree(te->fd);
	rpmfilesFree(te->files);
	headerFree(te->h);
	rpmfsFree(te->fs);
	rpmpsFree(te->probs);
	rpmteCleanDS(te);

	memset(te, 0, sizeof(*te));	/* XXX trash and burn */
	free(te);
    }
    return NULL;
}

rpmte rpmteNew(rpmts ts, Header h, rpmElementType type, fnpyKey key,
	       rpmRelocation * relocs, int addop)
{
    rpmte p = (rpmte)xcalloc(1, sizeof(*p));
    p->ts = ts;
    p->type = type;
    p->addop = addop;
    p->verified = RPMSIG_UNVERIFIED_TYPE;

    if (addTE(p, h, key, relocs)) {
	rpmteFree(p);
	return NULL;
    }

    return p;
}

unsigned int rpmteDBInstance(rpmte te) 
{
    return (te != NULL ? te->db_instance : 0);
}

void rpmteSetDBInstance(rpmte te, unsigned int instance) 
{
    if (te != NULL) 
	te->db_instance = instance;
}

Header rpmteHeader(rpmte te)
{
    return (te != NULL && te->h != NULL ? headerLink(te->h) : NULL);
}

Header rpmteSetHeader(rpmte te, Header h)
{
    if (te != NULL)  {
	te->h = headerFree(te->h);
	if (h != NULL)
	    te->h = headerLink(h);
    }
    return NULL;
}

rpmElementType rpmteType(rpmte te)
{
    return te->type;
}

const char * rpmteN(rpmte te)
{
    return (te != NULL ? te->name : NULL);
}

const char * rpmteE(rpmte te)
{
    return (te != NULL ? te->epoch : NULL);
}

const char * rpmteV(rpmte te)
{
    return (te != NULL ? te->version : NULL);
}

const char * rpmteR(rpmte te)
{
    return (te != NULL ? te->release : NULL);
}

const char * rpmteA(rpmte te)
{
    return (te != NULL ? te->arch : NULL);
}

const char * rpmteO(rpmte te)
{
    return (te != NULL ? te->os : NULL);
}

int rpmteIsSource(rpmte te)
{
    return (te != NULL ? te->isSource : 0);
}

rpm_color_t rpmteColor(rpmte te)
{
    return (te != NULL ? te->color : 0);
}

rpm_color_t rpmteSetColor(rpmte te, rpm_color_t color)
{
    rpm_color_t ocolor = 0;
    if (te != NULL) {
	ocolor = te->color;
	te->color = color;
    }
    return ocolor;
}

rpm_loff_t rpmtePkgFileSize(rpmte te)
{
    return (te != NULL ? te->pkgFileSize : 0);
}

unsigned int rpmteHeaderSize(rpmte te)
{
    return (te != NULL ? te->headerSize : 0);
}

rpmte rpmteParent(rpmte te)
{
    return (te != NULL ? te->parent : NULL);
}

rpmte rpmteSetParent(rpmte te, rpmte pte)
{
    rpmte opte = NULL;
    if (te != NULL) {
	opte = te->parent;
	te->parent = pte;
    }
    return opte;
}

tsortInfo rpmteTSI(rpmte te)
{
    return te->tsi;
}

void rpmteSetTSI(rpmte te, tsortInfo tsi)
{
    te->tsi = tsi;
}

void rpmteSetDependsOn(rpmte te, rpmte depends)
{
    te->depends = depends;
}

rpmte rpmteDependsOn(rpmte te)
{
    return te->depends;
}

int rpmteDBOffset(rpmte te)
{
    return rpmteDBInstance(te);
}

const char * rpmteEVR(rpmte te)
{
    return (te != NULL ? te->NEVR + strlen(te->name) + 1 : NULL);
}

const char * rpmteNEVR(rpmte te)
{
    return (te != NULL ? te->NEVR : NULL);
}

const char * rpmteNEVRA(rpmte te)
{
    return (te != NULL ? te->NEVRA : NULL);
}

FD_t rpmteSetFd(rpmte te, FD_t fd)
{
    if (te != NULL)  {
	if (te->fd != NULL)
	    te->fd = fdFree(te->fd);
	if (fd != NULL)
	    te->fd = fdLink(fd);
    }
    return NULL;
}

fnpyKey rpmteKey(rpmte te)
{
    return (te != NULL ? te->key : NULL);
}

void rpmteSetUserdata(rpmte te, void *data)
{
    if (te)
	te->userdata = data;
}

void *rpmteUserdata(rpmte te)
{
    return (te != NULL ? te->userdata : NULL);
}

rpmds rpmteDS(rpmte te, rpmTagVal tag)
{
    if (te == NULL)
	return NULL;

    switch (tag) {
    case RPMTAG_NAME:		return te->thisds;
    case RPMTAG_PROVIDENAME:	return te->provides;
    case RPMTAG_REQUIRENAME:	return te->requires;
    case RPMTAG_CONFLICTNAME:	return te->conflicts;
    case RPMTAG_OBSOLETENAME:	return te->obsoletes;
    case RPMTAG_ORDERNAME:	return te->order;
    case RPMTAG_RECOMMENDNAME:	return te->recommends;
    case RPMTAG_SUGGESTNAME:	return te->suggests;
    case RPMTAG_SUPPLEMENTNAME:	return te->supplements;
    case RPMTAG_ENHANCENAME:	return te->enhances;
    default:			break;
    }
    return NULL;
}

void rpmteCleanFiles(rpmte te)
{
    if (te != NULL)  {
	te->files = rpmfilesFree(te->files);
    }
}

rpmfiles rpmteFiles(rpmte te)
{
    return (te != NULL) ? rpmfilesLink(te->files) : NULL;
}

static void rpmteColorDS(rpmte te, rpmTag tag)
{
    rpmfi fi;
    rpmds ds = rpmteDS(te, tag);
    char deptype = rpmdsD(ds);
    char mydt;
    const uint32_t * ddict;
    rpm_color_t * colors;
    rpm_color_t val;
    int Count;
    unsigned ix;
    int ndx, i;

    if (!(te && deptype && (Count = rpmdsCount(ds)) > 0 && rpmfilesFC(te->files) > 0))
	return;

    colors = (rpm_color_t *)xcalloc(Count, sizeof(*colors));

    /* Calculate dependency color. */
    fi = rpmfilesIter(te->files, RPMFI_ITER_FWD);
    while (rpmfiNext(fi) >= 0) {
	val = rpmfiFColor(fi);
	ddict = NULL;
	ndx = rpmfiFDepends(fi, &ddict);
	if (ddict != NULL)
	while (ndx-- > 0) {
	    ix = *ddict++;
	    mydt = ((ix >> 24) & 0xff);
	    if (mydt != deptype)
		continue;
	    ix &= 0x00ffffff;
assert (ix < Count);
	    colors[ix] |= val;
	}
    }

    /* Set color values in dependency set. */
    ds = rpmdsInit(ds);
    while ((i = rpmdsNext(ds)) >= 0) {
	val = colors[i];
	te->color |= val;
	(void) rpmdsSetColor(ds, val);
    }
    free(colors);
    rpmfiFree(fi);
}

static Header rpmteDBHeader(rpmte te)
{
    Header h = NULL;
    rpmdbMatchIterator mi;

    mi = rpmtsInitIterator(te->ts, RPMDBI_PACKAGES,
			   &te->db_instance, sizeof(te->db_instance));
    /* iterator returns weak refs, grab hold of header */
    if ((h = rpmdbNextIterator(mi)))
	h = headerLink(h);
    rpmdbFreeIterator(mi);
    return h;
}

static Header rpmteFDHeader(rpmte te)
{
    Header h = NULL;
    te->fd = (FD_t)rpmtsNotify(te->ts, te, RPMCALLBACK_INST_OPEN_FILE, 0, 0);
    if (te->fd != NULL) {
	rpmVSFlags ovsflags;
	rpmRC pkgrc;

	ovsflags = rpmtsSetVSFlags(te->ts,
				   rpmtsVSFlags(te->ts) | RPMVSF_NEEDPAYLOAD);
	pkgrc = rpmReadPackageFile(te->ts, te->fd, rpmteNEVRA(te), &h);
	rpmtsSetVSFlags(te->ts, ovsflags);
	switch (pkgrc) {
	default:
	    rpmteClose(te, 1);
	    break;
	case RPMRC_NOTTRUSTED:
	case RPMRC_NOKEY:
	case RPMRC_OK:
	    break;
	}
    }
    return h;
}

static int rpmteOpen(rpmte te, int reload_fi)
{
    int rc = 0; /* assume failure */
    Header h = NULL;
    if (te == NULL || te->ts == NULL || rpmteFailed(te))
	goto exit;

    switch (rpmteType(te)) {
    case TR_ADDED:
	h = rpmteDBInstance(te) ? rpmteDBHeader(te) : rpmteFDHeader(te);
	break;
    case TR_REMOVED:
	if (te->h) {
	    h = headerLink(te->h);
	    break;
	}
    case TR_RPMDB:
    case TR_RESTORED:
	h = rpmteDBHeader(te);
    	break;
    }

    if (h != NULL) {
	if (reload_fi) {
	    /* This can fail if we get a different, bad header from callback */
	    te->files = getFiles(te, h);
	    rc = (te->files != NULL);
	} else {
	    rc = 1;
	}
	
	rpmteSetHeader(te, h);
	headerFree(h);
    }

exit:
    return rc;
}

static int rpmteClose(rpmte te, int reset_fi)
{
    int keephdr = 0;
    if (te == NULL || te->ts == NULL)
	return 0;

    switch (te->type) {
    case TR_ADDED:
	if (te->fd) {
	    rpmtsNotify(te->ts, te, RPMCALLBACK_INST_CLOSE_FILE, 0, 0);
	    te->fd = NULL;
	}
	break;
    case TR_REMOVED:
	if (te->transscripts & RPMTE_HAVE_POSTUNTRANS)
	    keephdr = 1;
    case TR_RPMDB:
    case TR_RESTORED:
	/* eventually we'll want notifications for erase open too */
	break;
    }
    if (!keephdr)
	rpmteSetHeader(te, NULL);
    if (reset_fi) {
	rpmteCleanFiles(te);
    }
    return 1;
}

FD_t rpmtePayload(rpmte te)
{
    FD_t payload = NULL;
    if (te->fd && te->h) {
	const char *compr = headerGetString(te->h, RPMTAG_PAYLOADCOMPRESSOR);
	char *ioflags = rstrscat(NULL, "r.", compr ? compr : "gzip", NULL);
	payload = Fdopen(fdDup(Fileno(te->fd)), ioflags);
	free(ioflags);
    }
    return payload;
}

static int rpmteMarkFailed(rpmte te)
{
    te->failed++;

    /* No need to do this more than once, avoid recursion loops */
    if (te->failed == 1) {
	rpmtsi pi = rpmtsiInit(te->ts);
	rpmte p;

	/* XXX we can do a much better here than this... */
	while ((p = rpmtsiNext(pi, TR_REMOVED))) {
	    if (rpmteDependsOn(p) == te) {
		rpmteMarkFailed(p);
	    }
	}
	rpmtsiFree(pi);
    }
    return te->failed;
}

int rpmteFailed(rpmte te)
{
    return (te != NULL) ? te->failed : -1;
}

int rpmteHaveTransScript(rpmte te, rpmTagVal tag)
{
    /* We only filter pre/post transaction scripts */
    int rc = 1;
    if (tag == RPMTAG_PRETRANS) {
	rc = (te->transscripts & RPMTE_HAVE_PRETRANS);
    } else if (tag == RPMTAG_POSTTRANS) {
	rc = (te->transscripts & RPMTE_HAVE_POSTTRANS);
    } else if (tag == RPMTAG_PREUNTRANS) {
	rc = (te->transscripts & RPMTE_HAVE_PREUNTRANS);
    } else if (tag == RPMTAG_POSTUNTRANS) {
	rc = (te->transscripts & RPMTE_HAVE_POSTUNTRANS);
    }
    return rc;
}

rpmps rpmteProblems(rpmte te)
{
    return (te != NULL) ? rpmpsLink(te->probs) : NULL;
}

void rpmteCleanProblems(rpmte te)
{
    if (te != NULL && te->probs != NULL) {
	te->probs = rpmpsFree(te->probs);
    }
}

static void appendProblem(rpmte te, rpmProblemType type,
		fnpyKey key, const char * altNEVR,
		const char * str, uint64_t number)
{
    rpmProblem o;
    rpmProblem p = rpmProblemCreate(type, te->NEVRA, key, altNEVR, str, number);
    rpmpsi psi = rpmpsInitIterator(te->probs);

    /* Only add new, unique problems to the set */
    while ((o = rpmpsiNext(psi))) {
	if (rpmProblemCompare(p, o) == 0)
	    break;
    }
    rpmpsFreeIterator(psi);

    if (o == NULL) {
	if (te->probs == NULL)
	    te->probs = rpmpsCreate();
	rpmpsAppendProblem(te->probs, p);
	rpmteMarkFailed(te);
    }
    rpmProblemFree(p);
}

void rpmteAddProblem(rpmte te, rpmProblemType type,
		     const char *altNEVR, const char *str, uint64_t number)
{
    if (te != NULL) {
	appendProblem(te, type, rpmteKey(te), altNEVR, str, number);
    }
}

void rpmteAddDepProblem(rpmte te, const char * altNEVR, rpmds ds,
		        fnpyKey * suggestedKeys)
{
    if (te != NULL) {
	const char * DNEVR = rpmdsDNEVR(ds);
	rpmProblemType type;
	fnpyKey key = (suggestedKeys ? suggestedKeys[0] : NULL);

	switch ((unsigned)DNEVR[0]) {
	case 'O':	type = RPMPROB_OBSOLETES;	break;
	case 'C':	type = RPMPROB_CONFLICT;	break;
	default:
	case 'R':	type = RPMPROB_REQUIRES;	break;
	}

	appendProblem(te, type, key, altNEVR, DNEVR+2, rpmdsInstance(ds));
    }
}

void rpmteAddRelocProblems(rpmte te)
{
    if (te && te->badrelocs) {
	for (int i = 0; i < te->nrelocs; i++) {
	    if (te->badrelocs[i]) {
		rpmteAddProblem(te, RPMPROB_BADRELOCATE, NULL,
				te->relocs[i].oldPath, 0);
	    }
	}
    }
}

const char * rpmteTypeString(rpmte te)
{
    switch (rpmteType(te)) {
    case TR_ADDED:	return _("install");
    case TR_REMOVED:	return _("erase");
    case TR_RPMDB:	return _("rpmdb");
    case TR_RESTORED:	return _("restored");
    default:		return "???";
    }
}

rpmfs rpmteGetFileStates(rpmte te)
{
    return te->fs;
}

void rpmteSetVerified(rpmte te, int verified)
{
    te->verified = verified;
}

int rpmteVerified(rpmte te)
{
    return (te != NULL) ? te->verified : 0;
}

int rpmteAddOp(rpmte te)
{
    return te->addop;
}

int rpmteProcess(rpmte te, pkgGoal goal, int num)
{
    /* Only install/erase resets pkg file info */
    int scriptstage = (goal != PKG_INSTALL && goal != PKG_ERASE && goal != PKG_RESTORE);
    int test = (rpmtsFlags(te->ts) & RPMTRANS_FLAG_TEST);
    int reset_fi = (scriptstage == 0 && test == 0);
    int failed = 1;

    /* Dont bother opening for elements without pre/posttrans scripts */
    if (!rpmteHaveTransScript(te, goal))
	return 0;

    if (rpmteOpen(te, reset_fi)) {
	if (!scriptstage) {
	    rpmtsNotify(te->ts, te, RPMCALLBACK_ELEM_PROGRESS, num,
			rpmtsMembers(te->ts)->orderCount);
	}

	failed = rpmpsmRun(te->ts, te, goal);
	rpmteClose(te, reset_fi);
    }
    
    if (failed) {
	failed = rpmteMarkFailed(te);
    }

    return failed;
}
