/** \ingroup rpmdep
 * \file lib/rpmts.c
 * Routine(s) to handle a "rpmts" transaction sets.
 */
#include "system.h"

#include <inttypes.h>
#include <libgen.h>
#include <fcntl.h>
#include <errno.h>

#include <rpm/rpmtypes.h>
#include <rpm/rpmlib.h>			/* rpmReadPackage etc */
#include <rpm/rpmmacro.h>
#include <rpm/rpmfileutil.h>		/* rpmtsOpenDB() needs rpmGetPath */
#include <rpm/rpmstring.h>
#include <rpm/rpmkeyring.h>
#include <rpm/rpmbase64.h>

#include <rpm/rpmdb.h>
#include <rpm/rpmds.h>
#include <rpm/rpmfi.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmsq.h>
#include <rpm/rpmte.h>

#include "rpmpgpval.h"
#include "rpmal.h"
#include "rpmchroot.h"
#include "rpmplugins.h"
#include "rpmts_internal.h"
#include "rpmte_internal.h"
#include "misc.h"
#include "rpmtriggers.h"

#include "debug.h"

enum {
    KEYRING_RPMDB 	= 1,
    KEYRING_FS		= 2,
};

/**
 * Iterator across transaction elements, forward on install, backward on erase.
 */
struct rpmtsi_s {
    rpmts ts;		/*!< transaction set. */
    int oc;		/*!< iterator index. */
};

struct rpmtxn_s {
    rpmlock lock;	/* transaction lock */
    rpmtxnFlags flags;	/* transaction flags */
    rpmts ts;		/* parent transaction set reference */
};

static void loadKeyring(rpmts ts);

int _rpmts_stats = 0;

static rpmts rpmtsUnlink(rpmts ts)
{
    if (ts)
	ts->nrefs--;
    return NULL;
}

rpmts rpmtsLink(rpmts ts)
{
    if (ts)
	ts->nrefs++;
    return ts;
}

int rpmtsCloseDB(rpmts ts)
{
    int rc = 0;

    if (ts->rdb != NULL) {
	(void) rpmswAdd(rpmtsOp(ts, RPMTS_OP_DBGET), 
			rpmdbOp(ts->rdb, RPMDB_OP_DBGET));
	(void) rpmswAdd(rpmtsOp(ts, RPMTS_OP_DBPUT),
			rpmdbOp(ts->rdb, RPMDB_OP_DBPUT));
	(void) rpmswAdd(rpmtsOp(ts, RPMTS_OP_DBDEL),
			rpmdbOp(ts->rdb, RPMDB_OP_DBDEL));
	rc = rpmdbClose(ts->rdb);
	ts->rdb = NULL;
    }
    return rc;
}

int rpmtsOpenDB(rpmts ts, int dbmode)
{
    int rc = 0;

    if (ts->rdb != NULL && ts->dbmode == dbmode)
	return 0;

    (void) rpmtsCloseDB(ts);

    /* XXX there's a potential db lock race here. */

    ts->dbmode = dbmode;
    rc = rpmdbOpen(ts->rootDir, &ts->rdb, ts->dbmode, 0644);
    if (rc) {
	char * dn = rpmGetPath(ts->rootDir, "%{_dbpath}", NULL);
	rpmlog(RPMLOG_ERR, _("cannot open Packages database in %s\n"), dn);
	free(dn);
    }
    return rc;
}

int rpmtsInitDB(rpmts ts, int perms)
{
    rpmtxn txn = rpmtxnBegin(ts, RPMTXN_WRITE);
    int rc = -1;
    if (txn)
	    rc = rpmdbInit(ts->rootDir, perms);
    rpmtxnEnd(txn);
    return rc;
}

int rpmtsGetDBMode(rpmts ts)
{
    assert(ts != NULL);
    return (ts->dbmode);
}

int rpmtsSetDBMode(rpmts ts, int dbmode)
{
    int rc = 1;
    /* mode setting only permitted on non-open db */
    if (ts != NULL && rpmtsGetRdb(ts) == NULL) {
    	ts->dbmode = dbmode;
	rc = 0;
    }
    return rc;
}


int rpmtsRebuildDB(rpmts ts)
{
    int rc = -1;
    rpmtxn txn = NULL;
    int rebuildflags = 0;

    /* Cannot do this on a populated transaction set */
    if (rpmtsNElements(ts) > 0)
	return -1;

    if (rpmExpandNumeric("%{?_rebuilddb_salvage}"))
	rebuildflags |= RPMDB_REBUILD_FLAG_SALVAGE;

    txn = rpmtxnBegin(ts, RPMTXN_WRITE);
    if (txn) {
	if (!(ts->vsflags & RPMVSF_NOHDRCHK))
	    rc = rpmdbRebuild(ts->rootDir, ts, headerCheck, rebuildflags);
	else
	    rc = rpmdbRebuild(ts->rootDir, NULL, NULL, rebuildflags);
	rpmtxnEnd(txn);
    }
    return rc;
}

int rpmtsVerifyDB(rpmts ts)
{
    int rc = -1;
    rpmtxn txn = rpmtxnBegin(ts, RPMTXN_READ);
    if (txn) {
	rc = rpmdbVerify(ts->rootDir);
	rpmtxnEnd(txn);
    }
    return rc;
}

/* keyp might no be defined. */
rpmdbMatchIterator rpmtsInitIterator(const rpmts ts, rpmDbiTagVal rpmtag,
			const void * keyp, size_t keylen)
{
    rpmdbMatchIterator mi = NULL;
    char *tmp = NULL;

    if (ts == NULL)
	return NULL;

    if (ts->rdb == NULL && rpmtsOpenDB(ts, ts->dbmode))
	return NULL;

    if (ts->keyring == NULL)
	loadKeyring(ts);

    /* Parse out "N(EVR)" tokens from a label key if present */
    const char *s = (const char *)keyp;
    if (rpmtag == RPMDBI_LABEL && keyp != NULL && strchr(s, '(')) {
	const char *se;
	char *t;
	size_t slen = strlen(s);
	int level = 0;
	int c;

	tmp = (char *)xmalloc(slen+1);
	keyp = t = tmp;
	while ((c = *s++) != '\0') {
	    switch (c) {
	    default:
		*t++ = c;
		break;
	    case '(':
		/* XXX Fail if nested parens. */
		if (level++ != 0) {
		    rpmlog(RPMLOG_ERR, _("extra '(' in package label: %s\n"), (const char*)keyp);
		    goto exit;
		}
		/* Parse explicit epoch. */
		for (se = s; *se && risdigit(*se); se++)
		    {};
		if (*se == ':') {
		    /* XXX skip explicit epoch's (for now) */
		    *t++ = '-';
		    s = se + 1;
		} else {
		    /* No Epoch: found. Convert '(' to '-' and chug. */
		    *t++ = '-';
		}
		break;
	    case ')':
		/* XXX Fail if nested parens. */
		if (--level != 0) {
		    rpmlog(RPMLOG_ERR, _("missing '(' in package label: %s\n"), (const char*)keyp);
		    goto exit;
		}
		/* Don't copy trailing ')' */
		break;
	    }
	}
	if (level) {
	    rpmlog(RPMLOG_ERR, _("missing ')' in package label: %s\n"), (const char*)keyp);
	    goto exit;
	}
	*t = '\0';
    }

    mi = rpmdbInitIterator(ts->rdb, rpmtag, keyp, keylen);

    /* Verify header signature/digest during retrieve (if not disabled). */
    if (mi && !(ts->vsflags & RPMVSF_NOHDRCHK))
	(void) rpmdbSetHdrChk(mi, ts, headerCheck);

exit:
    free(tmp);

    return mi;
}

rpmKeyring rpmtsGetKeyring(rpmts ts, int autoload)
{
    rpmKeyring keyring = NULL;
    if (ts) {
	if (ts->keyring == NULL && autoload) {
	    loadKeyring(ts);
	}
	keyring = rpmKeyringLink(ts->keyring);
    }
    return keyring;
}

int rpmtsSetKeyring(rpmts ts, rpmKeyring keyring)
{
    if (ts == NULL)
	return -1;

    rpmKeyringFree(ts->keyring);
    ts->keyring = rpmKeyringLink(keyring);
    return 0;
}

static int loadKeyringFromFiles(rpmts ts)
{
    ARGV_t files = NULL;
    /* XXX TODO: deal with chroot path issues */
    char *pkpath = rpmGetPath(ts->rootDir, "%{_keyringpath}/*.key", NULL);
    int nkeys = 0;

    rpmlog(RPMLOG_DEBUG, "loading keyring from pubkeys in %s\n", pkpath);
    if (rpmGlob(pkpath, NULL, &files)) {
	rpmlog(RPMLOG_DEBUG, "couldn't find any keys in %s\n", pkpath);
	goto exit;
    }

    for (char **f = files; *f; f++) {
	int subkeysCount, i;
	rpmPubkey *subkeys;
	rpmPubkey key = rpmPubkeyRead(*f);

	if (!key) {
	    rpmlog(RPMLOG_ERR, _("%s: reading of public key failed.\n"), *f);
	    continue;
	}
	if (rpmKeyringAddKey(ts->keyring, key) == 0) {
	    nkeys++;
	    rpmlog(RPMLOG_DEBUG, "added key %s to keyring\n", *f);
	}
	subkeys = rpmGetSubkeys(key, &subkeysCount);
	rpmPubkeyFree(key);

	for (i = 0; i < subkeysCount; i++) {
	    rpmPubkey subkey = subkeys[i];

	    if (rpmKeyringAddKey(ts->keyring, subkey) == 0) {
		rpmlog(RPMLOG_DEBUG,
		    "added subkey %d of main key %s to keyring\n",
		    i, *f);

		nkeys++;
	    }
	    rpmPubkeyFree(subkey);
	}
	free(subkeys);
    }
exit:
    free(pkpath);
    argvFree(files);
    return nkeys;
}

static int loadKeyringFromDB(rpmts ts)
{
    Header h;
    rpmdbMatchIterator mi;
    int nkeys = 0;

    rpmlog(RPMLOG_DEBUG, "loading keyring from rpmdb\n");
    mi = rpmtsInitIterator(ts, RPMDBI_NAME, "gpg-pubkey", 0);
    while ((h = rpmdbNextIterator(mi)) != NULL) {
	struct rpmtd_s pubkeys;
	const char *key;

	/* don't allow normal packages named gpg-pubkey */
	if (headerIsEntry(h, RPMTAG_ARCH) || headerIsEntry(h, RPMTAG_OS) ||
	    !headerGet(h, RPMTAG_PUBKEYS, &pubkeys, HEADERGET_MINMEM))
	{
	    char *nevr = headerGetAsString(h, RPMTAG_NEVR);
	    rpmlog(RPMLOG_WARNING, _("%s is not a valid public key\n"), nevr);
	    free(nevr);
	    continue;
	}

	while ((key = rpmtdNextString(&pubkeys))) {
	    uint8_t *pkt;
	    size_t pktlen;

	    if (rpmBase64Decode(key, (void **) &pkt, &pktlen) == 0) {
		rpmPubkey key = rpmPubkeyNew(pkt, pktlen);
		int subkeysCount, i;
		rpmPubkey *subkeys = rpmGetSubkeys(key, &subkeysCount);

		if (rpmKeyringAddKey(ts->keyring, key) == 0) {
		    char *nvr = headerGetAsString(h, RPMTAG_NVR);
		    rpmlog(RPMLOG_DEBUG, "added key %s to keyring\n", nvr);
		    free(nvr);
		    nkeys++;
		}
		rpmPubkeyFree(key);

		for (i = 0; i < subkeysCount; i++) {
		    rpmPubkey subkey = subkeys[i];

		    if (rpmKeyringAddKey(ts->keyring, subkey) == 0) {
			char *nvr = headerGetAsString(h, RPMTAG_NVR);
			rpmlog(RPMLOG_DEBUG,
			    "added subkey %d of main key %s to keyring\n",
			    i, nvr);

			free(nvr);
			nkeys++;
		    }
		    rpmPubkeyFree(subkey);
		}
		free(subkeys);
		free(pkt);
	    }
	}
	rpmtdFreeData(&pubkeys);
    }
    rpmdbFreeIterator(mi);

    return nkeys;
}

static int getKeyringType(void)
{
    int kt = KEYRING_RPMDB;
    char *krtype = rpmExpand("%{?_keyring}", NULL);

    if (rstreq(krtype, "fs")) {
	kt = KEYRING_FS;
    } else if (*krtype && !rstreq(krtype, "rpmdb")) {
	/* Fall back to using rpmdb if unknown, for now at least */
	rpmlog(RPMLOG_WARNING,
		_("unknown keyring type: %s, using rpmdb\n"), krtype);
    }
    free(krtype);

    return kt;
}

static void loadKeyring(rpmts ts)
{
    /* Never load the keyring if signature checking is disabled */
    if ((rpmtsVSFlags(ts) & RPMVSF_MASK_NOSIGNATURES) !=
	RPMVSF_MASK_NOSIGNATURES) {
	ts->keyring = rpmKeyringNew();
	if (!ts->keyringtype)
	    ts->keyringtype = getKeyringType();
	if (ts->keyringtype == KEYRING_FS) {
	    loadKeyringFromFiles(ts);
	} else {
	    loadKeyringFromDB(ts);
	}
    }
}

static void addGpgProvide(Header h, const char *n, const char *v)
{
    rpmsenseFlags pflags = (RPMSENSE_KEYRING|RPMSENSE_EQUAL);
    char * nsn = rstrscat(NULL, "gpg(", n, ")", NULL);

    headerPutString(h, RPMTAG_PROVIDENAME, nsn);
    headerPutString(h, RPMTAG_PROVIDEVERSION, v);
    headerPutUint32(h, RPMTAG_PROVIDEFLAGS, &pflags, 1);

    free(nsn);
}

struct pgpdata_s {
    char *signid;
    char *timestr;
    char *verid;
    const char *userid;
    const char *shortid;
    uint32_t time;
};

static void initPgpData(pgpDigParams pubp, struct pgpdata_s *pd)
{
    memset(pd, 0, sizeof(*pd));
    pd->signid = rpmhex(pgpDigParamsSignID(pubp), PGP_KEYID_LEN);
    pd->shortid = pd->signid + 8;
    pd->userid = pgpDigParamsUserID(pubp);
    if (! pd->userid) {
        pd->userid = "none";
    }
    pd->time = pgpDigParamsCreationTime(pubp);

    rasprintf(&pd->timestr, "%x", pd->time);
    rasprintf(&pd->verid, "%d:%s-%s", pgpDigParamsVersion(pubp), pd->signid, pd->timestr);
}

static void finiPgpData(struct pgpdata_s *pd)
{
    free(pd->timestr);
    free(pd->verid);
    free(pd->signid);
    memset(pd, 0, sizeof(*pd));
}

static Header makeImmutable(Header h)
{
    h = headerReload(h, RPMTAG_HEADERIMMUTABLE);
    if (h != NULL) {
	char *sha1 = NULL;
	char *sha256 = NULL;
	unsigned int blen = 0;
	void *blob = headerExport(h, &blen);

	/* XXX FIXME: bah, this code is repeated in way too many places */
	rpmDigestBundle bundle = rpmDigestBundleNew();
	rpmDigestBundleAdd(bundle, RPM_HASH_SHA1, RPMDIGEST_NONE);
	rpmDigestBundleAdd(bundle, RPM_HASH_SHA256, RPMDIGEST_NONE);

	rpmDigestBundleUpdate(bundle, rpm_header_magic, sizeof(rpm_header_magic));
	rpmDigestBundleUpdate(bundle, blob, blen);

	rpmDigestBundleFinal(bundle, RPM_HASH_SHA1, (void **)&sha1, NULL, 1);
	rpmDigestBundleFinal(bundle, RPM_HASH_SHA256, (void **)&sha256, NULL, 1);

	if (sha1 && sha256) {
	    headerPutString(h, RPMTAG_SHA1HEADER, sha1);
	    headerPutString(h, RPMTAG_SHA256HEADER, sha256);
	} else {
	    h = headerFree(h);
	}
	free(sha1);
	free(sha256);
	free(blob);
	rpmDigestBundleFree(bundle);
    }
    return h;
}

/* Build pubkey header. */
static int makePubkeyHeader(rpmts ts, rpmPubkey key, rpmPubkey *subkeys,
			    int subkeysCount, Header * hdrp)
{
    Header h = headerNew();
    const char * afmt = "%{pubkeys:armor}";
    const char * group = "Public Keys";
    const char * license = "pubkey";
    const char * buildhost = "localhost";
    uint32_t zero = 0;
    struct pgpdata_s kd;
    char * d = NULL;
    char * enc = NULL;
    char * s = NULL;
    int rc = -1;
    int i;

    memset(&kd, 0, sizeof(kd));

    if ((enc = rpmPubkeyBase64(key)) == NULL)
	goto exit;

    /* Build header elements. */
    initPgpData(rpmPubkeyPgpDigParams(key), &kd);

    rasprintf(&s, "%s public key", kd.userid);
    headerPutString(h, RPMTAG_PUBKEYS, enc);

    if ((d = headerFormat(h, afmt, NULL)) == NULL)
	goto exit;

    headerPutString(h, RPMTAG_NAME, "gpg-pubkey");
    headerPutString(h, RPMTAG_VERSION, kd.shortid);
    headerPutString(h, RPMTAG_RELEASE, kd.timestr);
    headerPutString(h, RPMTAG_DESCRIPTION, d);
    headerPutString(h, RPMTAG_GROUP, group);
    headerPutString(h, RPMTAG_LICENSE, license);
    headerPutString(h, RPMTAG_SUMMARY, s);
    headerPutString(h, RPMTAG_PACKAGER, kd.userid);
    headerPutUint32(h, RPMTAG_SIZE, &zero, 1);
    headerPutString(h, RPMTAG_RPMVERSION, RPMVERSION);
    headerPutString(h, RPMTAG_BUILDHOST, buildhost);
    headerPutUint32(h, RPMTAG_BUILDTIME, &kd.time, 1);
    headerPutString(h, RPMTAG_SOURCERPM, "(none)");

    addGpgProvide(h, kd.userid, kd.verid);
    addGpgProvide(h, kd.shortid, kd.verid);
    addGpgProvide(h, kd.signid, kd.verid);

    for (i = 0; i < subkeysCount; i++) {
	struct pgpdata_s skd;
	initPgpData(rpmPubkeyPgpDigParams(subkeys[i]), &skd);
	addGpgProvide(h, skd.shortid, skd.verid);
	addGpgProvide(h, skd.signid, skd.verid);
	finiPgpData(&skd);
    }

    /* Reload it into immutable region and stomp standard digests on it */
    h = makeImmutable(h);
    if (h != NULL) {
	*hdrp = headerLink(h);
	rc = 0;
    }

exit:
    headerFree(h);
    finiPgpData(&kd);
    free(enc);
    free(d);
    free(s);

    return rc;
}

rpmRC rpmtsImportHeader(rpmtxn txn, Header h, rpmFlags flags)
{
    rpmRC rc = RPMRC_FAIL;

    if (txn && h && rpmtsOpenDB(txn->ts, (O_RDWR|O_CREAT)) == 0) {
	if (rpmdbAdd(rpmtsGetRdb(txn->ts), h) == 0) {
	    rc = RPMRC_OK;
	}
    }
    return rc;
}

static rpmRC rpmtsImportFSKey(rpmtxn txn, Header h, rpmFlags flags)
{
    rpmRC rc = RPMRC_FAIL;
    char *keyfmt = headerFormat(h, "%{nvr}.key", NULL);
    char *keyval = headerGetAsString(h, RPMTAG_DESCRIPTION);
    char *path = rpmGenPath(rpmtsRootDir(txn->ts), "%{_keyringpath}/", keyfmt);

    FD_t fd = Fopen(path, "wx");
    if (fd) {
	size_t keylen = strlen(keyval);
	if (Fwrite(keyval, 1, keylen, fd) == keylen)
	    rc = RPMRC_OK;
	Fclose(fd);
    }

    if (rc) {
	rpmlog(RPMLOG_ERR, _("failed to import key: %s: %s\n"),
		path, strerror(errno));
    }

    free(path);
    free(keyval);
    free(keyfmt);
    return rc;
}

rpmRC rpmtsImportPubkey(const rpmts ts, const unsigned char * pkt, size_t pktlen)
{
    Header h = NULL;
    rpmRC rc = RPMRC_FAIL;		/* assume failure */
    char *lints = NULL;
    rpmPubkey pubkey = NULL;
    rpmPubkey *subkeys = NULL;
    int subkeysCount = 0;
    rpmVSFlags oflags = rpmtsVSFlags(ts);
    rpmKeyring keyring = NULL;
    rpmtxn txn = rpmtxnBegin(ts, RPMTXN_WRITE);
    int krc, i;

    if (txn == NULL)
	return rc;

    if (pgpPubKeyLint(pkt, pktlen, &lints) != RPMRC_OK) {
	if (lints) {
            rpmlog(RPMLOG_ERR, "%s\n", lints);
	    free(lints);
	}
	goto exit;
    }
    if (lints) {
	/* XXX Hack to ease testing between different backends */
	if (rpmIsNormal())
	    rpmlog(RPMLOG_WARNING, "%s\n", lints);
        free(lints);
    }

    /* XXX keyring wont load if sigcheck disabled, force it temporarily */
    rpmtsSetVSFlags(ts, (oflags & ~RPMVSF_MASK_NOSIGNATURES));
    keyring = rpmtsGetKeyring(ts, 1);
    rpmtsSetVSFlags(ts, oflags);

    if ((pubkey = rpmPubkeyNew(pkt, pktlen)) == NULL)
	goto exit;

    if ((subkeys = rpmGetSubkeys(pubkey, &subkeysCount)) == NULL)
	goto exit;

    krc = rpmKeyringAddKey(keyring, pubkey);
    if (krc < 0)
	goto exit;
    for (i = 0; i < subkeysCount; i++)
	rpmKeyringAddKey(keyring, subkeys[i]);

    /* If we dont already have the key, make a persistent record of it */
    if (krc == 0) {
	rpm_tid_t tid = rpmtsGetTid(ts);

	if (makePubkeyHeader(ts, pubkey, subkeys, subkeysCount, &h) != 0)
	    goto exit;

	headerPutUint32(h, RPMTAG_INSTALLTIME, &tid, 1);
	headerPutUint32(h, RPMTAG_INSTALLTID, &tid, 1);

	/* Add header to database. */
	rc = RPMRC_OK;
	if (!(rpmtsFlags(ts) & RPMTRANS_FLAG_TEST)) {
	    if (ts->keyringtype == KEYRING_FS)
		rc = rpmtsImportFSKey(txn, h, 0);
	    else
		rc = rpmtsImportHeader(txn, h, 0);
	}
    } else {
	rc = RPMRC_OK;		/* already have key */
    }

exit:
    /* Clean up. */
    headerFree(h);
    rpmPubkeyFree(pubkey);
    for (i = 0; i < subkeysCount; i++)
	rpmPubkeyFree(subkeys[i]);
    free(subkeys);

    rpmKeyringFree(keyring);
    rpmtxnEnd(txn);
    return rc;
}

int rpmtsSetSolveCallback(rpmts ts,
		int (*solve) (rpmts ts, rpmds key, const void * data),
		const void * solveData)
{
    int rc = 0;

    if (ts) {
	ts->solve = solve;
	ts->solveData = solveData;
    }
    return rc;
}

int rpmtsSolve(rpmts ts, rpmds key)
{
    int rc = 1; /* assume not found */
    if (ts && ts->solve) {
	rc = (*ts->solve)(ts, key, ts->solveData);
    }
    return rc;
}

rpmps rpmtsProblems(rpmts ts)
{
    rpmps ps = rpmpsCreate();
    rpmtsi pi = rpmtsiInit(ts);
    rpmte p;

    while ((p = rpmtsiNext(pi, 0)) != NULL) {
	rpmps teprobs = rpmteProblems(p);
	rpmpsMerge(ps, teprobs);
	rpmpsFree(teprobs);
    }
    rpmtsiFree(pi);

    /* Return NULL on no problems instead of an empty set */
    if (rpmpsNumProblems(ps) == 0) {
	ps = rpmpsFree(ps);
    }

    return ps;
}

void rpmtsCleanProblems(rpmts ts)
{
    rpmte p;
    rpmtsi pi = rpmtsiInit(ts);
    while ((p = rpmtsiNext(pi, 0)) != NULL)
	rpmteCleanProblems(p);
    rpmtsiFree(pi);
}

void rpmtsClean(rpmts ts)
{
    rpmtsi pi; rpmte p;
    tsMembers tsmem = rpmtsMembers(ts);

    if (ts == NULL)
	return;

    /* Clean up after dependency checks. */
    pi = rpmtsiInit(ts);
    while ((p = rpmtsiNext(pi, 0)) != NULL)
	rpmteCleanDS(p);
    rpmtsiFree(pi);

    tsmem->addedPackages = rpmalFree(tsmem->addedPackages);
    tsmem->rpmlib = rpmdsFree(tsmem->rpmlib);

    rpmtsCleanProblems(ts);
}

/* hash comparison function */
static int uintCmp(unsigned int a, unsigned int b)
{
    return (a != b);
}

/* "hash"function*/ 
static unsigned int uintId(unsigned int a)
{
    return a;
}

void rpmtsEmpty(rpmts ts)
{
    tsMembers tsmem = rpmtsMembers(ts);
    if (ts == NULL)
	return;

    rpmtsClean(ts);

    for (int oc = 0; oc < tsmem->orderCount; oc++) {
	rpmtsNotifyChange(ts, RPMTS_EVENT_DEL, tsmem->order[oc], NULL);
	tsmem->order[oc] = rpmteFree(tsmem->order[oc]);
    }

    tsmem->orderCount = 0;
    /* The pool cannot be emptied, there might be references to its contents */
    tsmem->pool = rpmstrPoolFree(tsmem->pool);
    packageHashEmpty(tsmem->removedPackages);
    return;
}

static void rpmtsPrintStat(const char * name, struct rpmop_s * op)
{
    static const unsigned int scale = (1000 * 1000);
    if (op != NULL && op->count > 0)
	fprintf(stderr, "   %s %6d %6lu.%06lu MB %6lu.%06lu secs\n",
		name, op->count,
		(unsigned long)op->bytes/scale, (unsigned long)op->bytes%scale,
		op->usecs/scale, op->usecs%scale);
}

static void rpmtsPrintStats(rpmts ts)
{
    (void) rpmswExit(rpmtsOp(ts, RPMTS_OP_TOTAL), 0);

    rpmtsPrintStat("total:       ", rpmtsOp(ts, RPMTS_OP_TOTAL));
    rpmtsPrintStat("check:       ", rpmtsOp(ts, RPMTS_OP_CHECK));
    rpmtsPrintStat("order:       ", rpmtsOp(ts, RPMTS_OP_ORDER));
    rpmtsPrintStat("verify:      ", rpmtsOp(ts, RPMTS_OP_VERIFY));
    rpmtsPrintStat("fingerprint: ", rpmtsOp(ts, RPMTS_OP_FINGERPRINT));
    rpmtsPrintStat("install:     ", rpmtsOp(ts, RPMTS_OP_INSTALL));
    rpmtsPrintStat("erase:       ", rpmtsOp(ts, RPMTS_OP_ERASE));
    rpmtsPrintStat("scriptlets:  ", rpmtsOp(ts, RPMTS_OP_SCRIPTLETS));
    rpmtsPrintStat("compress:    ", rpmtsOp(ts, RPMTS_OP_COMPRESS));
    rpmtsPrintStat("uncompress:  ", rpmtsOp(ts, RPMTS_OP_UNCOMPRESS));
    rpmtsPrintStat("digest:      ", rpmtsOp(ts, RPMTS_OP_DIGEST));
    rpmtsPrintStat("signature:   ", rpmtsOp(ts, RPMTS_OP_SIGNATURE));
    rpmtsPrintStat("dbadd:       ", rpmtsOp(ts, RPMTS_OP_DBADD));
    rpmtsPrintStat("dbremove:    ", rpmtsOp(ts, RPMTS_OP_DBREMOVE));
    rpmtsPrintStat("dbget:       ", rpmtsOp(ts, RPMTS_OP_DBGET));
    rpmtsPrintStat("dbput:       ", rpmtsOp(ts, RPMTS_OP_DBPUT));
    rpmtsPrintStat("dbdel:       ", rpmtsOp(ts, RPMTS_OP_DBDEL));
}

rpmts rpmtsFree(rpmts ts)
{
    tsMembers tsmem = rpmtsMembers(ts);
    if (ts == NULL)
	return NULL;

    if (ts->nrefs > 1)
	return rpmtsUnlink(ts);

    /* Don't issue element change callbacks when freeing */
    rpmtsSetChangeCallback(ts, NULL, NULL);
    rpmtsEmpty(ts);

    (void) rpmtsCloseDB(ts);

    tsmem->removedPackages = packageHashFree(tsmem->removedPackages);
    tsmem->installedPackages = packageHashFree(tsmem->installedPackages);
    tsmem->order = _free(tsmem->order);
    ts->members = _free(ts->members);

    ts->dsi = _free(ts->dsi);

    if (ts->scriptFd != NULL) {
	ts->scriptFd = fdFree(ts->scriptFd);
	ts->scriptFd = NULL;
    }
    ts->rootDir = _free(ts->rootDir);
    ts->lockPath = _free(ts->lockPath);
    ts->lock = rpmlockFree(ts->lock);

    ts->keyring = rpmKeyringFree(ts->keyring);
    ts->netsharedPaths = argvFree(ts->netsharedPaths);
    ts->installLangs = argvFree(ts->installLangs);

    ts->plugins = rpmpluginsFree(ts->plugins);

    rpmtriggersFree(ts->trigs2run);

    if (_rpmts_stats)
	rpmtsPrintStats(ts);

    (void) rpmtsUnlink(ts);

    ts = _free(ts);

    return NULL;
}

rpmVSFlags rpmtsVSFlags(rpmts ts)
{
    rpmVSFlags vsflags = 0;
    if (ts != NULL)
	vsflags = ts->vsflags;
    return vsflags;
}

rpmVSFlags rpmtsSetVSFlags(rpmts ts, rpmVSFlags vsflags)
{
    rpmVSFlags ovsflags = 0;
    if (ts != NULL) {
	ovsflags = ts->vsflags;
	ts->vsflags = vsflags;
    }
    return ovsflags;
}

rpmVSFlags rpmtsVfyFlags(rpmts ts)
{
    rpmVSFlags vfyflags = 0;
    if (ts != NULL)
	vfyflags = ts->vfyflags;
    return vfyflags;
}

rpmVSFlags rpmtsSetVfyFlags(rpmts ts, rpmVSFlags vfyflags)
{
    rpmVSFlags ovfyflags = 0;
    if (ts != NULL) {
	ovfyflags = ts->vfyflags;
	ts->vfyflags = vfyflags;
    }
    return ovfyflags;
}

int rpmtsVfyLevel(rpmts ts)
{
    int vfylevel = 0;
    if (ts != NULL)
	vfylevel = ts->vfylevel;
    return vfylevel;
}

int rpmtsSetVfyLevel(rpmts ts, int vfylevel)
{
    int ovfylevel = 0;
    if (ts != NULL) {
	ovfylevel = ts->vfylevel;
	ts->vfylevel = vfylevel;
    }
    return ovfylevel;
}

const char * rpmtsRootDir(rpmts ts)
{
    return ts ? ts->rootDir : NULL;
}

int rpmtsSetRootDir(rpmts ts, const char * rootDir)
{
    if (ts == NULL || (rootDir && rootDir[0] != '/')) {
	return -1;
    }

    ts->rootDir = _free(ts->rootDir);
    /* Ensure clean path with a trailing slash */
    ts->rootDir = rootDir ? rpmGetPath(rootDir, NULL) : xstrdup("/");
    if (!rstreq(ts->rootDir, "/")) {
	rstrcat(&ts->rootDir, "/");
    }
    return 0;
}

FD_t rpmtsScriptFd(rpmts ts)
{
    FD_t scriptFd = NULL;
    if (ts != NULL) {
	scriptFd = ts->scriptFd;
    }
    return scriptFd;
}

void rpmtsSetScriptFd(rpmts ts, FD_t scriptFd)
{

    if (ts != NULL) {
	if (ts->scriptFd != NULL) {
	    ts->scriptFd = fdFree(ts->scriptFd);
	    ts->scriptFd = NULL;
	}
	if (scriptFd != NULL)
	    ts->scriptFd = fdLink(scriptFd);
    }
}

rpm_tid_t rpmtsGetTid(rpmts ts)
{
    rpm_tid_t tid = (rpm_tid_t)-1;  /* XXX -1 is time(2) error return. */
    if (ts != NULL) {
	tid = ts->tid;
    }
    return tid;
}

rpm_tid_t rpmtsSetTid(rpmts ts, rpm_tid_t tid)
{
    rpm_tid_t otid = (rpm_tid_t)-1; /* XXX -1 is time(2) error return. */
    if (ts != NULL) {
	otid = ts->tid;
	ts->tid = tid;
    }
    return otid;
}

rpmdb rpmtsGetRdb(rpmts ts)
{
    rpmdb rdb = NULL;
    if (ts != NULL) {
	rdb = ts->rdb;
    }
    return rdb;
}

void * rpmtsNotify(rpmts ts, rpmte te,
		rpmCallbackType what, rpm_loff_t amount, rpm_loff_t total)
{
    void * ptr = NULL;
    if (ts && ts->notify) {
	void *arg = NULL;
	Header h = NULL;
	fnpyKey cbkey = NULL;
	if (te) {
	    if (ts->notifyStyle == 0) {
		h = rpmteHeader(te);
		arg = h;
	    } else {
		arg = te;
	    }
	    cbkey = rpmteKey(te);
	}
	ptr = ts->notify(arg, what, amount, total, cbkey, ts->notifyData);

	if (h) {
	    headerFree(h); /* undo rpmteHeader() ref */
	}
    }
    return ptr;
}

int rpmtsNotifyChange(rpmts ts, int event, rpmte te, rpmte other)
{
    int rc = 0;
    if (ts && ts->change) {
	rc = ts->change(event, te, other, ts->changeData);
    }
    return rc;
}

int rpmtsNElements(rpmts ts)
{
    int nelements = 0;
    tsMembers tsmem = rpmtsMembers(ts);
    if (tsmem != NULL && tsmem->order != NULL) {
	nelements = tsmem->orderCount;
    }
    return nelements;
}

rpmte rpmtsElement(rpmts ts, int ix)
{
    rpmte te = NULL;
    tsMembers tsmem = rpmtsMembers(ts);
    if (tsmem != NULL && tsmem->order != NULL) {
	if (ix >= 0 && ix < tsmem->orderCount)
	    te = tsmem->order[ix];
    }
    return te;
}

rpmprobFilterFlags rpmtsFilterFlags(rpmts ts)
{
    return (ts != NULL ? ts->ignoreSet : 0);
}

rpmtransFlags rpmtsFlags(rpmts ts)
{
    return (ts != NULL ? ts->transFlags : 0);
}

rpmtransFlags rpmtsSetFlags(rpmts ts, rpmtransFlags transFlags)
{
    rpmtransFlags otransFlags = 0;
    if (ts != NULL) {
	otransFlags = ts->transFlags;
	ts->transFlags = transFlags;
    }
    return otransFlags;
}

rpm_color_t rpmtsColor(rpmts ts)
{
    return (ts != NULL ? ts->color : 0);
}

rpm_color_t rpmtsSetColor(rpmts ts, rpm_color_t color)
{
    rpm_color_t ocolor = 0;
    if (ts != NULL) {
	ocolor = ts->color;
	ts->color = color;
    }
    return ocolor;
}

rpm_color_t rpmtsPrefColor(rpmts ts)
{
    return (ts != NULL ? ts->prefcolor : 0);
}

rpm_color_t rpmtsSetPrefColor(rpmts ts, rpm_color_t color)
{
    rpm_color_t ocolor = 0;
    if (ts != NULL) {
	ocolor = ts->prefcolor;
	ts->prefcolor = color;
    }
    return ocolor;
}

rpmop rpmtsOp(rpmts ts, rpmtsOpX opx)
{
    rpmop op = NULL;

    if (ts != NULL && opx >= 0 && opx < RPMTS_OP_MAX)
	op = ts->ops + opx;
    return op;
}

rpmPlugins rpmtsPlugins(rpmts ts)
{
    rpmPlugins plugins = NULL;

    if (ts != NULL) {
	if (ts->plugins == NULL)
	    ts->plugins = rpmpluginsNew(ts);
	plugins = ts->plugins;
    }
    return plugins;
}

int rpmtsSetNotifyCallback(rpmts ts,
		rpmCallbackFunction notify, rpmCallbackData notifyData)
{
    if (ts != NULL) {
	ts->notify = notify;
	ts->notifyData = notifyData;
    }
    return 0;
}

int rpmtsSetNotifyStyle(rpmts ts, int style)
{
    if (ts != NULL)
	ts->notifyStyle = style;
    return 0;
}

int rpmtsGetNotifyStyle(rpmts ts)
{
    int style = 0;
    if (ts != NULL)
	style = ts->notifyStyle;
    return style;
}

int rpmtsSetChangeCallback(rpmts ts, rpmtsChangeFunction change, void *data)
{
    if (ts != NULL) {
	ts->change = change;
	ts->changeData = data;
    }
    return 0;
}

tsMembers rpmtsMembers(rpmts ts)
{
    return (ts != NULL) ? ts->members : NULL;
}

rpmstrPool rpmtsPool(rpmts ts)
{
    tsMembers tsmem = rpmtsMembers(ts);
    rpmstrPool tspool = NULL;

    if (tsmem) {
	if (tsmem->pool == NULL)
	    tsmem->pool = rpmstrPoolCreate();
	tspool = tsmem->pool;
    }
    return tspool;
}

static int vfylevel_init(void)
{
    int vfylevel = -1;
    char *val = rpmExpand("%{?_pkgverify_level}", NULL);

    if (rstreq(val, "all"))
	vfylevel = RPMSIG_SIGNATURE_TYPE|RPMSIG_DIGEST_TYPE;
    else if (rstreq(val, "signature"))
	vfylevel = RPMSIG_SIGNATURE_TYPE;
    else if (rstreq(val, "digest"))
	vfylevel = RPMSIG_DIGEST_TYPE;
    else if (rstreq(val, "none"))
	vfylevel = 0;
    else if (!rstreq(val, ""))
	rpmlog(RPMLOG_WARNING, _("invalid package verify level %s\n"), val);

    free(val);
    return vfylevel;
}

rpmts rpmtsCreate(void)
{
    rpmts ts = (rpmts)xcalloc(1, sizeof(*ts));
    tsMembers tsmem;
    char *source_date_epoch = NULL;

    memset(&ts->ops, 0, sizeof(ts->ops));
    (void) rpmswEnter(rpmtsOp(ts, RPMTS_OP_TOTAL), -1);
    ts->dsi = NULL;

    ts->solve = NULL;
    ts->solveData = NULL;

    ts->rdb = NULL;
    ts->dbmode = O_RDONLY;

    source_date_epoch = getenv("SOURCE_DATE_EPOCH");
    if (source_date_epoch != NULL) {
	ts->overrideTime = (time_t)strtol(source_date_epoch, NULL, 10);
    } else {
	ts->overrideTime = (time_t)-1;
    }

    ts->scriptFd = NULL;
    ts->tid = (rpm_tid_t) rpmtsGetTime(ts, 0);

    ts->color = rpmExpandNumeric("%{?_transaction_color}");
    ts->prefcolor = rpmExpandNumeric("%{?_prefer_color}")?:2;

    ts->netsharedPaths = NULL;
    ts->installLangs = NULL;
    {	char *tmp = rpmExpand("%{_netsharedpath}", NULL);
	if (tmp && *tmp != '%') {
	    argvSplit(&ts->netsharedPaths, tmp, ":");
	}
	free(tmp);

	tmp = rpmExpand("%{_install_langs}", NULL);
	if (tmp && *tmp != '%') {
	    ARGV_t langs = NULL;
	    argvSplit(&langs, tmp, ":");	
	    /* If we'll be installing all languages anyway, don't bother */
	    for (ARGV_t l = langs; *l; l++) {
		if (rstreq(*l, "all")) {
		    langs = argvFree(langs);
		    break;
		}
	    }
	    ts->installLangs = langs;
	}
	free(tmp);
    }

    tsmem = (tsMembers)xcalloc(1, sizeof(*ts->members));
    tsmem->pool = NULL;
    tsmem->delta = 5;
    tsmem->addedPackages = NULL;
    tsmem->removedPackages = packageHashCreate(128, uintId, uintCmp, NULL, NULL);
    tsmem->installedPackages = packageHashCreate(128, uintId, uintCmp, NULL, NULL);
    tsmem->orderAlloced = 0;
    tsmem->orderCount = 0;
    tsmem->order = NULL;
    ts->members = tsmem;

    ts->rootDir = NULL;
    ts->keyring = NULL;
    ts->keyringtype = 0;
    ts->vfyflags = rpmExpandNumeric("%{?_pkgverify_flags}");
    ts->vfylevel = vfylevel_init();

    ts->nrefs = 0;

    ts->plugins = NULL;

    ts->trigs2run = rpmtriggersCreate(10);

    ts->min_writes = (rpmExpandNumeric("%{?_minimize_writes}") > 0);

    return rpmtsLink(ts);
}

rpm_time_t rpmtsGetTime(rpmts ts, time_t step)
{
    time_t tstime;

    if (ts->overrideTime == (time_t)-1) {
	tstime = time(NULL);
    } else {
	tstime = ts->overrideTime;
	ts->overrideTime += step;
    }

    return (rpm_time_t)tstime;
}

rpmtsi rpmtsiFree(rpmtsi tsi)
{
    /* XXX watchout: a funky recursion segfaults here iff nrefs is wrong. */
    if (tsi) {
	tsi->ts = rpmtsFree(tsi->ts);
	_free(tsi);
    }
    return NULL;
}

rpmtsi rpmtsiInit(rpmts ts)
{
    rpmtsi tsi = NULL;

    tsi = (rpmtsi)xcalloc(1, sizeof(*tsi));
    tsi->ts = rpmtsLink(ts);
    tsi->oc = 0;
    return tsi;
}

/**
 * Return next transaction element.
 * @param tsi		transaction element iterator
 * @return		transaction element, NULL on termination
 */
static
rpmte rpmtsiNextElement(rpmtsi tsi)
{
    rpmte te = NULL;
    int oc = -1;

    if (tsi == NULL || tsi->ts == NULL || rpmtsNElements(tsi->ts) <= 0)
	return te;

    if (tsi->oc < rpmtsNElements(tsi->ts))	oc = tsi->oc++;
    if (oc != -1)
	te = rpmtsElement(tsi->ts, oc);
    return te;
}

rpmte rpmtsiNext(rpmtsi tsi, rpmElementTypes types)
{
    rpmte te;

    while ((te = rpmtsiNextElement(tsi)) != NULL) {
	if (types == 0 || (rpmteType(te) & types) != 0)
	    break;
    }
    return te;
}

#define RPMLOCK_PATH LOCALSTATEDIR "/rpm/.rpm.lock"
rpmtxn rpmtxnBegin(rpmts ts, rpmtxnFlags flags)
{
    static const char * const rpmlock_path_default = "%{?_rpmlock_path}";
    rpmtxn txn = NULL;

    if (ts == NULL)
	return NULL;

    if (ts->lockPath == NULL) {
	const char *rootDir = rpmtsRootDir(ts);
	char *t;

	if (!rootDir || rpmChrootDone())
	    rootDir = "/";

	t = rpmGenPath(rootDir, rpmlock_path_default, NULL);
	if (t == NULL || *t == '\0' || *t == '%') {
	    free(t);
	    t = xstrdup(RPMLOCK_PATH);
	}
	ts->lockPath = xstrdup(t);
	(void) rpmioMkpath(dirname(t), 0755, getuid(), getgid());
	free(t);
    }

    if (ts->lock == NULL)
	ts->lock = rpmlockNew(ts->lockPath, _("transaction"));

    int lockmode = (flags & RPMTXN_WRITE) ? RPMLOCK_WRITE : RPMLOCK_READ;
    if (rpmlockAcquire(ts->lock, lockmode)) {
	txn = (rpmtxn)xcalloc(1, sizeof(*txn));
	txn->lock = ts->lock;
	txn->flags = flags;
	txn->ts = rpmtsLink(ts);
	if (txn->flags & RPMTXN_WRITE)
	    rpmsqBlock(SIG_BLOCK);
    }
    
    return txn;
}

rpmtxn rpmtxnEnd(rpmtxn txn)
{
    if (txn) {
	rpmlockRelease(txn->lock);
	if (txn->flags & RPMTXN_WRITE)
	    rpmsqBlock(SIG_UNBLOCK);
	rpmtsFree(txn->ts);
	free(txn);
    }
    return NULL;
}
