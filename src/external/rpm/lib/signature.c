/** \ingroup signature
 * \file lib/signature.c
 */

#include "system.h"

#include <inttypes.h>
#include <netinet/in.h>

#include <rpm/rpmtypes.h>
#include <rpm/rpmstring.h>
#include <rpm/rpmfileutil.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmmacro.h>

#include "rpmlead.h"
#include "header_internal.h"
#include "signature.h"

#include "debug.h"

/**
 * Print package size (debug purposes only)
 * @param fd			package file handle
 * @param sigh			signature header
 */
static void printSize(FD_t fd, Header sigh)
{
    struct stat st;
    int fdno = Fileno(fd);
    size_t siglen = headerSizeof(sigh, HEADER_MAGIC_YES);
    size_t pad = (8 - (siglen % 8)) % 8; /* 8-byte pad */
    struct rpmtd_s sizetag;
    rpm_loff_t datalen = 0;

    /* Print package component sizes. */
    if (headerGet(sigh, RPMSIGTAG_LONGSIZE, &sizetag, HEADERGET_DEFAULT)) {
	rpm_loff_t *tsize = rpmtdGetUint64(&sizetag);
	datalen = (tsize) ? *tsize : 0;
    } else if (headerGet(sigh, RPMSIGTAG_SIZE, &sizetag, HEADERGET_DEFAULT)) {
	rpm_off_t *tsize = rpmtdGetUint32(&sizetag);
	datalen = (tsize) ? *tsize : 0;
    }
    rpmtdFreeData(&sizetag);

    rpmlog(RPMLOG_DEBUG,
		"Expected size: %12" PRIu64 \
		" = lead(%d)+sigs(%zd)+pad(%zd)+data(%" PRIu64 ")\n",
		RPMLEAD_SIZE+siglen+pad+datalen,
		RPMLEAD_SIZE, siglen, pad, datalen);

    if (fstat(fdno, &st) == 0) {
	rpmlog(RPMLOG_DEBUG,
		"  Actual size: %12" PRIu64 "\n", (rpm_loff_t) st.st_size);
    }
}

rpmRC rpmReadSignature(FD_t fd, Header * sighp, char ** msg)
{
    char *buf = NULL;
    struct hdrblob_s blob;
    Header sigh = NULL;
    rpmRC rc = RPMRC_FAIL;		/* assume failure */

    if (sighp)
	*sighp = NULL;

    if (hdrblobRead(fd, 1, 0, RPMTAG_HEADERSIGNATURES, &blob, &buf) != RPMRC_OK)
	goto exit;
    
    /* OK, blob looks sane, load the header. */
    if (hdrblobImport(&blob, 0, &sigh, &buf) != RPMRC_OK)
	goto exit;

    printSize(fd, sigh);
    rc = RPMRC_OK;

exit:
    if (sighp && sigh && rc == RPMRC_OK)
	*sighp = headerLink(sigh);
    headerFree(sigh);

    if (msg != NULL) {
	*msg = buf;
    } else {
	free(buf);
    }

    return rc;
}

int rpmWriteSignature(FD_t fd, Header sigh)
{
    static const uint8_t zeros[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
    int sigSize, pad;
    int rc;

    rc = headerWrite(fd, sigh, HEADER_MAGIC_YES);
    if (rc)
	return rc;

    sigSize = headerSizeof(sigh, HEADER_MAGIC_YES);
    pad = (8 - (sigSize % 8)) % 8;
    if (pad) {
	if (Fwrite(zeros, sizeof(zeros[0]), pad, fd) != pad)
	    rc = 1;
    }
    rpmlog(RPMLOG_DEBUG, "Signature: size(%d)+pad(%d)\n", sigSize, pad);
    return rc;
}

rpmRC rpmGenerateSignature(char *SHA256, char *SHA1, uint8_t *MD5,
			rpm_loff_t size, rpm_loff_t payloadSize, FD_t fd)
{
    Header sig = headerNew();
    struct rpmtd_s td;
    rpmRC rc = RPMRC_OK;
    uint8_t *reservedSpace;
    int spaceSize = 32; /* always reserve a bit of space */
    int gpgSize = rpmExpandNumeric("%{__gpg_reserved_space}");
    rpm_off_t size32 = size;
    rpm_off_t payloadSize32 = payloadSize;

    /* Prepare signature */
    if (SHA256) {
	rpmtdReset(&td);
	td.tag = RPMSIGTAG_SHA256;
	td.count = 1;
	td.type = RPM_STRING_TYPE;
	td.data = SHA256;
	headerPut(sig, &td, HEADERPUT_DEFAULT);
    }

    if (SHA1) {
	rpmtdReset(&td);
	td.tag = RPMSIGTAG_SHA1;
	td.count = 1;
	td.type = RPM_STRING_TYPE;
	td.data = SHA1;
	headerPut(sig, &td, HEADERPUT_DEFAULT);
    }

    if (MD5) {
	rpmtdReset(&td);
	td.tag = RPMSIGTAG_MD5;
	td.count = 16;
	td.type = RPM_BIN_TYPE;
	td.data = MD5;
	headerPut(sig, &td, HEADERPUT_DEFAULT);
    }

    rpmtdReset(&td);
    td.count = 1;
    td.type = RPM_INT32_TYPE;

    td.tag = RPMSIGTAG_PAYLOADSIZE;
    td.data = &payloadSize32;
    headerPut(sig, &td, HEADERPUT_DEFAULT);

    td.tag = RPMSIGTAG_SIZE;
    td.data = &size32;
    headerPut(sig, &td, HEADERPUT_DEFAULT);

    if (size >= UINT32_MAX || payloadSize >= UINT32_MAX) {
	/*
	 * Put the 64bit size variants into the header, but
	 * modify spaceSize so that the resulting header has
	 * the same size. Note that this only works if all tags
	 * with a lower number than RPMSIGTAG_RESERVEDSPACE are
	 * already added and no tag with a higher number is
	 * added yet.
	 */
	rpm_loff_t p = payloadSize;
	rpm_loff_t s = size;
	int newsigSize, oldsigSize;

	oldsigSize = headerSizeof(sig, HEADER_MAGIC_YES);

	headerDel(sig, RPMSIGTAG_PAYLOADSIZE);
	headerDel(sig, RPMSIGTAG_SIZE);

	td.type = RPM_INT64_TYPE;

	td.tag = RPMSIGTAG_LONGARCHIVESIZE;
	td.data = &p;
	headerPut(sig, &td, HEADERPUT_DEFAULT);

	td.tag = RPMSIGTAG_LONGSIZE;
	td.data = &s;
	headerPut(sig, &td, HEADERPUT_DEFAULT);

	newsigSize = headerSizeof(sig, HEADER_MAGIC_YES);
	spaceSize -= newsigSize - oldsigSize;
    }

    if (gpgSize > 0)
	spaceSize += gpgSize;

    if (spaceSize > 0) {
	reservedSpace = (uint8_t *)xcalloc(spaceSize, sizeof(char));
	rpmtdReset(&td);
	td.tag = RPMSIGTAG_RESERVEDSPACE;
	td.count = spaceSize;
	td.type = RPM_BIN_TYPE;
	td.data = reservedSpace;
	headerPut(sig, &td, HEADERPUT_DEFAULT);
	free(reservedSpace);
    }

    /* Reallocate the signature into one contiguous region. */
    sig = headerReload(sig, RPMTAG_HEADERSIGNATURES);
    if (sig == NULL) { /* XXX can't happen */
	rpmlog(RPMLOG_ERR, _("Unable to reload signature header.\n"));
	rc = RPMRC_FAIL;
	goto exit;
    }

    /* Write the signature section into the package. */
    if (rpmWriteSignature(fd, sig)) {
	rc = RPMRC_FAIL;
	goto exit;
    }

exit:
    headerFree(sig);
    return rc;
}


