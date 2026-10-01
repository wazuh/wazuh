/** \ingroup rpmcli
 * \file lib/rpmchecksig.c
 * Verify the signature of a package.
 */

#include "system.h"

#include <ctype.h>

#include <rpm/rpmlib.h>			/* RPMSIGTAG & related */
#include <rpm/rpmpgp.h>
#include <rpm/rpmcli.h>
#include <rpm/rpmfileutil.h>	/* rpmMkTemp() */
#include <rpm/rpmsq.h>
#include <rpm/rpmts.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmstring.h>
#include <rpm/rpmkeyring.h>

#include "rpmio_internal.h" 	/* fdSetBundle() */
#include "rpmlead.h"
#include "header_internal.h"
#include "rpmvs.h"

#include "debug.h"

static int doImport(rpmts ts, const char *fn, char *buf, ssize_t blen)
{
    char const * const pgpmark = "-----BEGIN PGP ";
    size_t marklen = strlen(pgpmark);
    int res = 0;
    int keyno = 1;
    char *start = strstr(buf, pgpmark);

    do {
	uint8_t *pkt = NULL;
	uint8_t *pkti = NULL;
	size_t pktlen = 0;
	size_t certlen;
	
	/* Read pgp packet. */
	if (pgpParsePkts(start, &pkt, &pktlen) == PGPARMOR_PUBKEY) {
	    pkti = pkt;

	    /* Iterate over certificates in pkt */
	    while (pktlen > 0) {
		if (pgpPubKeyCertLen(pkti, pktlen, &certlen)) {
		    rpmlog(RPMLOG_ERR, _("%s: key %d import failed.\n"), fn,
			    keyno);
		    res++;
		    break;
		}

		/* Import pubkey certificate. */
		if (rpmtsImportPubkey(ts, pkti, certlen) != RPMRC_OK) {
		    rpmlog(RPMLOG_ERR, _("%s: key %d import failed.\n"), fn,
			    keyno);
		    res++;
		}
		pkti += certlen;
		pktlen -= certlen;
	    }
	} else {
	    rpmlog(RPMLOG_ERR, _("%s: key %d not an armored public key.\n"),
		   fn, keyno);
	    res++;
	}
	
	/* See if there are more keys in the buffer */
	if (start && start + marklen < buf + blen) {
	    start = strstr(start + marklen, pgpmark);
	} else {
	    start = NULL;
	}

	keyno++;
	free(pkt);
    } while (start != NULL);

    return res;
}

int rpmcliImportPubkeys(rpmts ts, ARGV_const_t argv)
{
    int res = 0;
    for (ARGV_const_t arg = argv; arg && *arg; arg++) {
	const char *fn = *arg;
	uint8_t *buf = NULL;
	ssize_t blen = 0;
	char *t = NULL;
	int iorc;

	/* Read the file and try to import all contained keys */
	iorc = rpmioSlurp(fn, &buf, &blen);
	if (iorc || buf == NULL || blen < 64) {
	    rpmlog(RPMLOG_ERR, _("%s: import read failed(%d).\n"), fn, iorc);
	    res++;
	} else {
	    res += doImport(ts, fn, (char *)buf, blen);
	}
	
	free(t);
	free(buf);
    }
    return res;
}

static int readFile(FD_t fd, char **msg)
{
    unsigned char buf[4*BUFSIZ];
    ssize_t count;

    /* Read the payload from the package. */
    while ((count = Fread(buf, sizeof(buf[0]), sizeof(buf), fd)) > 0) {}
    if (count < 0)
	rasprintf(msg, _("Fread failed: %s"), Fstrerror(fd));

    return (count != 0);
}

struct vfydata_s {
    int seen;
    int bad;
    int verbose;
};

static int vfyCb(struct rpmsinfo_s *sinfo, void *cbdata)
{
    struct vfydata_s *vd = (struct vfydata_s *)cbdata;
    vd->seen |= sinfo->type;
    if (sinfo->rc != RPMRC_OK)
	vd->bad |= sinfo->type;
    if (vd->verbose) {
	char *vsmsg = rpmsinfoMsg(sinfo);
	rpmlog(RPMLOG_NOTICE, "    %s\n", vsmsg);
	free(vsmsg);
    }
    return 1;
}

rpmRC rpmpkgRead(struct rpmvs_s *vs, FD_t fd,
		hdrblob *sigblobp, hdrblob *blobp, char **emsg)
{

    char * msg = NULL;
    rpmRC xx, rc = RPMRC_FAIL; /* assume failure */
    hdrblob sigblob = hdrblobCreate();
    hdrblob blob = hdrblobCreate();
    rpmDigestBundle bundle = fdGetBundle(fd, 1); /* freed with fd */

    if ((xx = rpmLeadRead(fd, &msg)) != RPMRC_OK) {
	/* Avoid message spew on manifests */
	if (xx == RPMRC_NOTFOUND)
	    msg = _free(msg);
	rc = xx;
	goto exit;
    }

    /* Read the signature header. Might not be in a contiguous region. */
    if (hdrblobRead(fd, 1, 0, RPMTAG_HEADERSIGNATURES, sigblob, &msg))
	goto exit;

    rpmvsInit(vs, sigblob, bundle);

    /* Initialize digests ranging over the header */
    rpmvsInitRange(vs, RPMSIG_HEADER);

    /* Read the header from the package. */
    if (hdrblobRead(fd, 1, 1, RPMTAG_HEADERIMMUTABLE, blob, &msg))
	goto exit;

    /* Finalize header range */
    rpmvsFiniRange(vs, RPMSIG_HEADER);

    /* Fish interesting tags from the main header. This is a bit hacky... */
    rpmvsAppendTag(vs, blob, RPMTAG_PAYLOADDIGEST);
    rpmvsAppendTag(vs, blob, RPMTAG_PAYLOADDIGESTALT);

    /* If needed and not explicitly disabled, read the payload as well. */
    if (rpmvsRange(vs) & RPMSIG_PAYLOAD) {
	/* Initialize digests ranging over the payload only */
	rpmvsInitRange(vs, RPMSIG_PAYLOAD);

	if (readFile(fd, &msg))
	    goto exit;

	/* Finalize payload range */
	rpmvsFiniRange(vs, RPMSIG_PAYLOAD);
	rpmvsFiniRange(vs, RPMSIG_HEADER|RPMSIG_PAYLOAD);
    }

    if (sigblobp && blobp) {
	*sigblobp = sigblob;
	*blobp = blob;
	sigblob = NULL;
	blob = NULL;
    }
    rc = RPMRC_OK;

exit:
    if (emsg)
	*emsg = msg;
    else
	free(msg);
    hdrblobFree(sigblob);
    hdrblobFree(blob);
    return rc;
}

static int rpmpkgVerifySigs(rpmKeyring keyring, int vfylevel, rpmVSFlags flags,
			   FD_t fd, const char *fn)
{
    char *msg = NULL;
    struct vfydata_s vd = { .seen = 0,
			    .bad = 0,
			    .verbose = rpmIsVerbose(),
    };
    int rc;
    struct rpmvs_s *vs = rpmvsCreate(vfylevel, flags, keyring);

    rpmlog(RPMLOG_NOTICE, "%s:%s", fn, vd.verbose ? "\n" : "");

    rc = rpmpkgRead(vs, fd, NULL, NULL, &msg);

    if (rc)
	goto exit;

    rc = rpmvsVerify(vs, RPMSIG_VERIFIABLE_TYPE, vfyCb, &vd);

    if (!vd.verbose) {
	if (vd.seen & RPMSIG_DIGEST_TYPE) {
	    rpmlog(RPMLOG_NOTICE, " %s", (vd.bad & RPMSIG_DIGEST_TYPE) ?
					_("DIGESTS") : _("digests"));
	}
	if (vd.seen & RPMSIG_SIGNATURE_TYPE) {
	    rpmlog(RPMLOG_NOTICE, " %s", (vd.bad & RPMSIG_SIGNATURE_TYPE) ?
					_("SIGNATURES") : _("signatures"));
	}
	rpmlog(RPMLOG_NOTICE, " %s\n", rc ? _("NOT OK") : _("OK"));
    }

exit:
    if (rc && msg)
	rpmlog(RPMLOG_ERR, "%s: %s\n", Fdescr(fd), msg);
    rpmvsFree(vs);
    free(msg);
    return rc;
}

/* Wrapper around rpmkVerifySigs to preserve API */
int rpmVerifySignatures(QVA_t qva, rpmts ts, FD_t fd, const char * fn)
{
    int rc = 1; /* assume failure */
    if (ts && qva && fd && fn) {
	rpmKeyring keyring = rpmtsGetKeyring(ts, 1);
	rpmVSFlags vsflags = rpmtsVfyFlags(ts);
	int vfylevel = rpmtsVfyLevel(ts);
	rc = rpmpkgVerifySigs(keyring, vfylevel, vsflags, fd, fn);
    	rpmKeyringFree(keyring);
    }
    return rc;
}

int rpmcliVerifySignatures(rpmts ts, ARGV_const_t argv)
{
    const char * arg;
    int res = 0;
    rpmKeyring keyring = rpmtsGetKeyring(ts, 1);
    rpmVSFlags vsflags = rpmtsVfyFlags(ts);
    int vfylevel = rpmtsVfyLevel(ts);

    vsflags |= rpmcliVSFlags;
    if (rpmcliVfyLevelMask) {
	vfylevel &= ~rpmcliVfyLevelMask;
	rpmtsSetVfyLevel(ts, vfylevel);
    }

    while ((arg = *argv++) != NULL) {
	FD_t fd = Fopen(arg, "r.ufdio");
	if (fd == NULL || Ferror(fd)) {
	    rpmlog(RPMLOG_ERR, _("%s: open failed: %s\n"), 
		     arg, Fstrerror(fd));
	    res++;
	} else if (rpmpkgVerifySigs(keyring, vfylevel, vsflags, fd, arg)) {
	    res++;
	}

	Fclose(fd);
    }
    rpmKeyringFree(keyring);
    return res;
}
