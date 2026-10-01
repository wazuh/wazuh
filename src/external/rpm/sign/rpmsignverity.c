/**
 * Copyright (C) 2020 Facebook
 *
 * Author: Jes Sorensen <jsorensen@fb.com>
 */

#include "system.h"

#include <inttypes.h>

#include <rpm/rpmlib.h>		/* RPMSIGTAG & related */
#include <rpm/rpmlog.h>		/* rpmlog */
#include <rpm/rpmfi.h>
#include <rpm/rpmcrypto.h>		/* rpmDigestLength */
#include <rpm/header.h>		/* HEADERGET_MINMEM */
#include <rpm/rpmtypes.h>	/* rpmRC */
#include <rpm/rpmbase64.h>
#include "header_internal.h"
#include <libfsverity.h>
#include "rpmio_internal.h"
#include "rpmvs.h"

#include "rpmsignverity.h"

#define MAX_SIGNATURE_LENGTH 1024

static int rpmVerityRead(void *opaque, void *buf, size_t size)
{
	int retval;
	rpmfi fi = (rpmfi)opaque;

	retval = rpmfiArchiveRead(fi, buf, size);

	if (retval > 0)
		retval = 0;
	return retval;
}

static char *rpmVeritySignFile(rpmfi fi, size_t *sig_size, char *key,
			       char *keypass, char *cert, uint16_t algo)
{
    struct libfsverity_merkle_tree_params params;
    struct libfsverity_signature_params sig_params;
    struct libfsverity_digest *digest = NULL;
    rpm_loff_t file_size;
    char *digest_hex, *digest_base64, *sig_base64 = NULL, *sig_hex = NULL;
    uint8_t *sig = NULL;
    int status;

    if (S_ISLNK(rpmfiFMode(fi)))
	file_size = 0;
    else
	file_size = rpmfiFSize(fi);

    memset(&params, 0, sizeof(struct libfsverity_merkle_tree_params));
    params.version = 1;
    params.hash_algorithm = algo;
    params.block_size = RPM_FSVERITY_BLKSZ;
    params.salt_size = 0 /* salt_size */;
    params.salt = NULL /* salt */;
    params.file_size = file_size;
    status = libfsverity_compute_digest(fi, rpmVerityRead, &params, &digest);
    if (status) {
	rpmlog(RPMLOG_DEBUG, _("failed to compute digest\n"));
	goto out;
    }

    digest_hex = rpmhex(digest->digest, digest->digest_size);
    digest_base64 = rpmBase64Encode(digest->digest, digest->digest_size, -1);
    rpmlog(RPMLOG_DEBUG, _("file(size %" PRIu64 "): %s: digest(%i): %s, idx %i\n"),
	   file_size, rpmfiFN(fi), digest->digest_size, digest_hex,
	   rpmfiFX(fi));
    rpmlog(RPMLOG_DEBUG, _("file(size %" PRIu64 "): %s: digest sz (%u): base64 sz (%zu), %s, idx %i\n"),
	   file_size, rpmfiFN(fi), digest->digest_size, strlen(digest_base64),
	   digest_base64, rpmfiFX(fi));

    free(digest_hex);

    memset(&sig_params, 0, sizeof(struct libfsverity_signature_params));
    sig_params.keyfile = key;
    sig_params.certfile = cert;
    if (libfsverity_sign_digest(digest, &sig_params, &sig, sig_size)) {
	rpmlog(RPMLOG_DEBUG, _("failed to sign digest\n"));
	goto out;
    }

    sig_hex = rpmhex(sig, *sig_size);
    sig_base64 = rpmBase64Encode(sig, *sig_size, -1);
    rpmlog(RPMLOG_DEBUG, _("%s: sig_size(%zu), base64_size(%zu), idx %i: signature:\n%s\n"),
	   rpmfiFN(fi), *sig_size, strlen(sig_base64), rpmfiFX(fi), sig_hex);
 out:
    free(sig_hex);

    free(digest);
    free(sig);
    return sig_base64;
}

rpmRC rpmSignVerity(FD_t fd, Header sigh, Header h, char *key,
		    char *keypass, char *cert, uint16_t algo)
{
    rpmRC rc;
    FD_t gzdi;
    rpmfiles files = NULL;
    rpmfi fi = NULL;
    rpmfi hfi = rpmfiNew(NULL, h, RPMTAG_BASENAMES, RPMFI_FLAGS_QUERY);
    rpmts ts = rpmtsCreate();
    struct rpmtd_s td;
    off_t offset = Ftell(fd);
    const char *compr;
    char *rpmio_flags = NULL;
    char *sig_hex;
    char **signatures = NULL;
    size_t sig_size;
    int nr_files, idx;
    uint32_t algo32;

    Fseek(fd, 0, SEEK_SET);
    rpmtsSetVSFlags(ts, RPMVSF_MASK_NODIGESTS | RPMVSF_MASK_NOSIGNATURES |
		    RPMVSF_NOHDRCHK);

    rc = rpmReadPackageFile(ts, fd, "fsverity", &h);
    if (rc != RPMRC_OK) {
	rpmlog(RPMLOG_DEBUG, _("%s: rpmReadPackageFile returned %i\n"),
	       __func__, rc);
	goto out;
    }

    rpmlog(RPMLOG_DEBUG, _("key: %s\n"), key);
    rpmlog(RPMLOG_DEBUG, _("cert: %s\n"), cert);

    compr = headerGetString(h, RPMTAG_PAYLOADCOMPRESSOR);
    rpmio_flags = rstrscat(NULL, "r.", compr ? compr : "gzip", NULL);

    gzdi = Fdopen(fdDup(Fileno(fd)), rpmio_flags);
    free(rpmio_flags);
    if (!gzdi)
	rpmlog(RPMLOG_DEBUG, _("Fdopen() failed\n"));

    files = rpmfilesNew(NULL, h, RPMTAG_BASENAMES, RPMFI_FLAGS_QUERY);
    fi = rpmfiNewArchiveReader(gzdi, files,
			       RPMFI_ITER_READ_ARCHIVE_OMIT_HARDLINKS);

    /*
     * Should this be sigh from the cloned fd or the sigh we received?
     */
    headerDel(sigh, RPMSIGTAG_VERITYSIGNATURES);
    headerDel(sigh, RPMSIGTAG_VERITYSIGNATUREALGO);

    /*
     * The payload doesn't include special files, like ghost files, and
     * we cannot rely on the file order in the payload to match that of
     * the header. Instead we allocate an array of pointers and populate
     * it as we go along. Then walk the header fi and account for the
     * special files. Last we walk the array and populate the header.
     */
    nr_files = rpmfiFC(hfi);
    signatures = (char **)xcalloc(nr_files, sizeof(char *));

    if (!algo)
	    algo = FS_VERITY_HASH_ALG_SHA256;

    rpmlog(RPMLOG_DEBUG, _("file count - header: %i, payload %i\n"),
	   nr_files, rpmfiFC(fi));

    while (rpmfiNext(fi) >= 0) {
	idx = rpmfiFX(fi);

	signatures[idx] = rpmVeritySignFile(fi, &sig_size, key, keypass, cert,
					    algo);
    }

    while (rpmfiNext(hfi) >= 0) {
	idx = rpmfiFX(hfi);
	if (signatures[idx])
	    continue;
	signatures[idx] = rpmVeritySignFile(hfi, &sig_size, key, keypass, cert,
					    algo);
    }

    rpmtdReset(&td);
    td.tag = RPMSIGTAG_VERITYSIGNATURES;
    td.type = RPM_STRING_ARRAY_TYPE;
    td.count = 1;
    for (idx = 0; idx < nr_files; idx++) {
	sig_hex = signatures[idx];
	td.data = &sig_hex;
	if (!headerPut(sigh, &td, HEADERPUT_APPEND)) {
	    rpmlog(RPMLOG_ERR, _("headerPutString failed\n"));
	    rc = RPMRC_FAIL;
	    goto out;
	}
	rpmlog(RPMLOG_DEBUG, _("signature: %s\n"), signatures[idx]);
	rpmlog(RPMLOG_DEBUG, _("digest signed, len: %zu\n"), sig_size);
	free(signatures[idx]);
	signatures[idx] = NULL;
    }

    if (sig_size == 0) {
	rpmlog(RPMLOG_ERR, _("Zero length fsverity signature\n"));
	rc = RPMRC_FAIL;
	goto out;
    }

    rpmtdReset(&td);

    /* RPM doesn't like new 16 bit types, so use a 32 bit tag */
    algo32 = algo;
    rpmtdReset(&td);
    td.tag = RPMSIGTAG_VERITYSIGNATUREALGO;
    td.type = RPM_INT32_TYPE;
    td.data = &algo32;
    td.count = 1;
    headerPut(sigh, &td, HEADERPUT_DEFAULT);

    rpmlog(RPMLOG_DEBUG, _("sigh size: %i\n"), headerSizeof(sigh, 0));

    rc = RPMRC_OK;
 out:
    signatures = _free(signatures);
    Fseek(fd, offset, SEEK_SET);

    rpmfilesFree(files);
    rpmfiFree(fi);
    rpmfiFree(hfi);
    rpmtsFree(ts);
    return rc;
}
