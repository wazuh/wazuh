/** \ingroup header
 * \file lib/package.c
 */

#include "system.h"

#include <netinet/in.h>
#include <pthread.h>

#include <rpm/rpmlib.h>			/* XXX RPMSIGTAG, other sig stuff */
#include <rpm/rpmts.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmstring.h>
#include <rpm/rpmkeyring.h>

#include "rpmlead.h"
#include "rpmio_internal.h"	/* fd digest bits */
#include "header_internal.h"	/* XXX headerCheck */
#include "rpmvs.h"

#include "debug.h"

typedef struct pkgdata_s *pkgdatap;

typedef void (*hdrvsmsg)(struct rpmsinfo_s *sinfo, pkgdatap pkgdata, const char *msg);

struct pkgdata_s {
    hdrvsmsg msgfunc;
    const char *fn;
    char *msg;
    rpmRC rc;
};

static struct taglate_s {
    rpmTagVal stag;
    rpmTagVal xtag;
    rpm_count_t count;
    int quirk;
} const xlateTags[] = {
    { RPMSIGTAG_SIZE, RPMTAG_SIGSIZE, 1, 0 },
    { RPMSIGTAG_PGP, RPMTAG_SIGPGP, 0, 0 },
    { RPMSIGTAG_MD5, RPMTAG_SIGMD5, 16, 0 },
    { RPMSIGTAG_GPG, RPMTAG_SIGGPG, 0, 0 },
    /* { RPMSIGTAG_PGP5, RPMTAG_SIGPGP5, 0, 0 }, */ /* long obsolete, dont use */
    { RPMSIGTAG_PAYLOADSIZE, RPMTAG_ARCHIVESIZE, 1, 1 },
    { RPMSIGTAG_FILESIGNATURES, RPMTAG_FILESIGNATURES, 0, 1 },
    { RPMSIGTAG_FILESIGNATURELENGTH, RPMTAG_FILESIGNATURELENGTH, 1, 1 },
    { RPMSIGTAG_VERITYSIGNATURES, RPMTAG_VERITYSIGNATURES, 0, 0 },
    { RPMSIGTAG_VERITYSIGNATUREALGO, RPMTAG_VERITYSIGNATUREALGO, 1, 0 },
    { RPMSIGTAG_SHA1, RPMTAG_SHA1HEADER, 1, 0 },
    { RPMSIGTAG_SHA256, RPMTAG_SHA256HEADER, 1, 0 },
    { RPMSIGTAG_DSA, RPMTAG_DSAHEADER, 0, 0 },
    { RPMSIGTAG_RSA, RPMTAG_RSAHEADER, 0, 0 },
    { RPMSIGTAG_LONGSIZE, RPMTAG_LONGSIGSIZE, 1, 0 },
    { RPMSIGTAG_LONGARCHIVESIZE, RPMTAG_LONGARCHIVESIZE, 1, 0 },
    { 0 }
};

/** \ingroup header
 * Translate and merge legacy signature tags into header.
 * @param h		header (dest)
 * @param sigh		signature header (src)
 * @return		failing tag number, 0 on success
 */
static
rpmTagVal headerMergeLegacySigs(Header h, Header sigh, char **msg)
{
    const struct taglate_s *xl;
    struct rpmtd_s td;

    for (xl = xlateTags; xl->stag; xl++) {
	/* There mustn't be one in the main header */
	if (headerIsEntry(h, xl->xtag)) {
	    /* Some tags may exist in either header, but never both */
	    if (xl->quirk && !headerIsEntry(sigh, xl->stag))
		continue;
	    goto exit;
	}
    }

    rpmtdReset(&td);
    for (xl = xlateTags; xl->stag; xl++) {
	if (headerGet(sigh, xl->stag, &td, HEADERGET_RAW|HEADERGET_MINMEM)) {
	    /* Translate legacy tags */
	    if (xl->stag != xl->xtag)
		td.tag = xl->xtag;
	    /* Ensure type and tag size match expectations */
	    if (td.type != rpmTagGetTagType(td.tag))
		break;
	    if (td.count < 1 || td.count > 16*1024*1024)
		break;
	    if (xl->count && td.count != xl->count)
		break;
	    if (!headerPut(h, &td, HEADERPUT_DEFAULT))
		break;
	    rpmtdFreeData(&td);
	}
    }
    rpmtdFreeData(&td);

exit:
    if (xl->stag) {
	rasprintf(msg, "invalid signature tag %s (%d)",
			rpmTagGetName(xl->xtag), xl->xtag);
    }

    return xl->stag;
}

/**
 * Remember current key id.
 * XXX: This s*** needs to die. Hook it into keyring or sumthin...
 * @param keyid		signature keyid
 * @return		0 if new keyid, otherwise 1
 */
static int stashKeyid(unsigned int keyid)
{
    static pthread_mutex_t keyid_lock = PTHREAD_MUTEX_INITIALIZER;
    static const unsigned int nkeyids_max = 256;
    static unsigned int nkeyids = 0;
    static unsigned int nextkeyid  = 0;
    static unsigned int * keyids;

    int i;
    int seen = 0;

    if (keyid == 0)
	return 0;

    /* Just pretend we didn't see the keyid if we fail to lock */
    if (pthread_mutex_lock(&keyid_lock))
	return 0;

    if (keyids != NULL)
    for (i = 0; i < nkeyids; i++) {
	if (keyid == keyids[i]) {
	    seen = 1;
	    goto exit;
        }
    }

    if (nkeyids < nkeyids_max) {
	nkeyids++;
	keyids = xrealloc(keyids, nkeyids * sizeof(*keyids));
    }
    if (keyids)		/* XXX can't happen */
	keyids[nextkeyid] = keyid;
    nextkeyid++;
    nextkeyid %= nkeyids_max;

exit:
    pthread_mutex_unlock(&keyid_lock);
    return seen;
}

static int handleHdrVS(struct rpmsinfo_s *sinfo, void *cbdata)
{
    struct pkgdata_s *pkgdata = (struct pkgdata_s *)cbdata;

    if (pkgdata->msgfunc) {
	char *vsmsg = rpmsinfoMsg(sinfo);
	pkgdata->msgfunc(sinfo, pkgdata, vsmsg);
	free(vsmsg);
    }

    /* Remember actual return code, but don't override a previous failure */
    if (sinfo->rc && pkgdata->rc != RPMRC_FAIL)
	pkgdata->rc = sinfo->rc;

    /* Preserve traditional behavior for now: only failure prevents read */
    if (sinfo->rc != RPMRC_FAIL)
	sinfo->rc = RPMRC_OK;

    return 1;
}


static void appendhdrmsg(struct rpmsinfo_s *sinfo, struct pkgdata_s *pkgdata,
			const char *msg)
{
    pkgdata->msg = rstrscat(&pkgdata->msg, "\n", msg, NULL);
}

rpmRC headerCheck(rpmts ts, const void * uh, size_t uc, char ** msg)
{
    rpmRC rc = RPMRC_FAIL;
    rpmVSFlags vsflags = rpmtsVSFlags(ts) | RPMVSF_NEEDPAYLOAD;
    rpmKeyring keyring = rpmtsGetKeyring(ts, 1);
    struct hdrblob_s blob;
    struct pkgdata_s pkgdata = {
	.msgfunc = appendhdrmsg,
	.fn = NULL,
	.msg = NULL,
	.rc = RPMRC_OK,
    };

    if (hdrblobInit(uh, uc, 0, 0, &blob, msg) == RPMRC_OK) {
	struct rpmvs_s *vs = rpmvsCreate(0, vsflags, keyring);
	rpmDigestBundle bundle = rpmDigestBundleNew();

	rpmswEnter(rpmtsOp(ts, RPMTS_OP_DIGEST), 0);

	rpmvsInit(vs, &blob, bundle);
	rpmvsInitRange(vs, RPMSIG_HEADER);
	hdrblobDigestUpdate(bundle, &blob);
	rpmvsFiniRange(vs, RPMSIG_HEADER);

	rpmvsVerify(vs, RPMSIG_VERIFIABLE_TYPE, handleHdrVS, &pkgdata);

	rpmswExit(rpmtsOp(ts, RPMTS_OP_DIGEST), uc);

	rc = pkgdata.rc;

	if (rc == RPMRC_OK && pkgdata.msg == NULL)
	    pkgdata.msg = xstrdup("Header sanity check: OK");

	if (msg)
	    *msg = pkgdata.msg;
	else
	    free(pkgdata.msg);

	rpmDigestBundleFree(bundle);
	rpmvsFree(vs);
    }

    rpmKeyringFree(keyring);

    return rc;
}

rpmRC rpmReadHeader(rpmts ts, FD_t fd, Header *hdrp, char ** msg)
{
    char *buf = NULL;
    struct hdrblob_s blob;
    Header h = NULL;
    rpmRC rc = RPMRC_FAIL;		/* assume failure */

    if (hdrp)
	*hdrp = NULL;
    if (msg)
	*msg = NULL;

    if (hdrblobRead(fd, 1, 1, RPMTAG_HEADERIMMUTABLE, &blob, &buf) != RPMRC_OK)
	goto exit;

    /* OK, blob looks sane, load the header. */
    rc = hdrblobImport(&blob, 0, &h, &buf);
    
exit:
    if (hdrp && h && rc == RPMRC_OK)
	*hdrp = headerLink(h);
    headerFree(h);

    if (msg != NULL && *msg == NULL && buf != NULL) {
	*msg = buf;
    } else {
	free(buf);
    }

    return rc;
}

static
void applyRetrofits(Header h)
{
    int v3 = 0;
    /*
     * Make sure that either RPMTAG_SOURCERPM or RPMTAG_SOURCEPACKAGE
     * is set. Use a simple heuristic to find the type if both are unset.
     */
    if (!headerIsEntry(h, RPMTAG_SOURCERPM) && !headerIsEntry(h, RPMTAG_SOURCEPACKAGE)) {
	/* the heuristic needs the compressed file list */
	if (headerIsEntry(h, RPMTAG_OLDFILENAMES))
	    headerConvert(h, HEADERCONV_COMPRESSFILELIST);
	if (headerIsSourceHeuristic(h)) {
	    /* Retrofit RPMTAG_SOURCEPACKAGE to srpms for compatibility */
	    uint32_t one = 1;
	    headerPutUint32(h, RPMTAG_SOURCEPACKAGE, &one, 1);
	} else {
	    /*
	     * Make sure binary rpms have RPMTAG_SOURCERPM set as that's
	     * what we use for differentiating binary vs source elsewhere.
	     */
	    headerPutString(h, RPMTAG_SOURCERPM, "(none)");
	}
    }

    /*
     * Convert legacy headers on the fly. Not having immutable region
     * equals a truly ancient package, do full retrofit. OTOH newer
     * packages might have been built with --nodirtokens, test and handle
     * the non-compressed filelist case separately.
     */
    if (!headerIsEntry(h, RPMTAG_HEADERIMMUTABLE)) {
	v3 = 1;
	headerConvert(h, HEADERCONV_RETROFIT_V3);
    } else if (headerIsEntry(h, RPMTAG_OLDFILENAMES)) {
	headerConvert(h, HEADERCONV_COMPRESSFILELIST);
	v3 = 1;
    }
    if (v3) {
	char *s = headerGetAsString(h, RPMTAG_NEVRA);
	rpmlog(RPMLOG_WARNING, _("RPM v3 packages are deprecated: %s\n"), s);
	free(s);
    }
}

static void loghdrmsg(struct rpmsinfo_s *sinfo, struct pkgdata_s *pkgdata,
			const char *msg)
{
    int lvl = RPMLOG_DEBUG;
    switch (sinfo->rc) {
    case RPMRC_OK:		/* Signature is OK. */
	break;
    case RPMRC_NOTTRUSTED:	/* Signature is OK, but key is not trusted. */
    case RPMRC_NOKEY:		/* Public key is unavailable. */
	/* XXX Print NOKEY/NOTTRUSTED warning only once. */
	if (stashKeyid(sinfo->keyid) == 0)
	    lvl = RPMLOG_WARNING;
	break;
    case RPMRC_NOTFOUND:	/* Signature/digest not present. */
	lvl = RPMLOG_WARNING;
	break;
    default:
    case RPMRC_FAIL:		/* Signature does not verify. */
	lvl = RPMLOG_ERR;
	break;
    }

    rpmlog(lvl, "%s: %s\n", pkgdata->fn, msg);
}

rpmRC rpmReadPackageFile(rpmts ts, FD_t fd, const char * fn, Header * hdrp)
{
    char *msg = NULL;
    Header h = NULL;
    Header sigh = NULL;
    hdrblob blob = NULL;
    hdrblob sigblob = NULL;
    rpmVSFlags vsflags = rpmtsVSFlags(ts) | RPMVSF_NEEDPAYLOAD;
    rpmKeyring keyring = rpmtsGetKeyring(ts, 1);
    struct rpmvs_s *vs = rpmvsCreate(0, vsflags, keyring);
    struct pkgdata_s pkgdata = {
	.msgfunc = loghdrmsg,
	.fn = fn ? fn : Fdescr(fd),
	.msg = NULL,
	.rc = RPMRC_OK,
    };

    /* XXX: lots of 3rd party software relies on the behavior */
    if (hdrp)
	*hdrp = NULL;

    rpmRC rc = rpmpkgRead(vs, fd, &sigblob, &blob, &msg);
    if (rc)
	goto exit;

    /* Actually all verify discovered signatures and digests */
    rc = RPMRC_FAIL;
    if (!rpmvsVerify(vs, RPMSIG_VERIFIABLE_TYPE, handleHdrVS, &pkgdata)) {
	/* Finally import the headers and do whatever required retrofits etc */
	if (hdrp) {
	    if (hdrblobImport(sigblob, 0, &sigh, &msg))
		goto exit;
	    if (hdrblobImport(blob, 0, &h, &msg))
		goto exit;

	    /* Append (and remap) signature tags to the metadata. */
	    if (headerMergeLegacySigs(h, sigh, &msg))
		goto exit;
	    applyRetrofits(h);

	    /* Bump reference count for return. */
	    *hdrp = headerLink(h);
	}
	rc = RPMRC_OK;
    }

    /* If there was a "substatus" (NOKEY in practise), return that instead */
    if (rc == RPMRC_OK && pkgdata.rc)
	rc = pkgdata.rc;

exit:
    if (rc && msg)
	rpmlog(RPMLOG_ERR, "%s: %s\n", Fdescr(fd), msg);
    hdrblobFree(sigblob);
    hdrblobFree(blob);
    headerFree(sigh);
    headerFree(h);
    rpmKeyringFree(keyring);
    rpmvsFree(vs);
    free(msg);

    return rc;
}



