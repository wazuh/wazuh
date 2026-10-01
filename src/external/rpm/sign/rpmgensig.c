/** \ingroup rpmcli
 * \file lib/rpmchecksig.c
 * Verify the signature of a package.
 */

#include "system.h"

#include <errno.h>
#include <sys/wait.h>
#include <popt.h>
#include <fcntl.h>
#ifdef WITH_FSVERITY
#include <libfsverity.h>
#include "rpmsignverity.h"
#endif
#ifdef WITH_IMAEVM
#include "rpmsignfiles.h"
#endif

#include <rpm/rpmlib.h>			/* RPMSIGTAG & related */
#include <rpm/rpmmacro.h>
#include <rpm/rpmpgp.h>
#include <rpm/rpmsign.h>
#include <rpm/rpmfileutil.h>	/* rpmMkTemp() */
#include <rpm/rpmlog.h>
#include <rpm/rpmstring.h>
#include "rpmio_internal.h"

#include "rpmlead.h"
#include "signature.h"
#include "rpmvs.h"

#include "debug.h"

typedef struct sigTarget_s {
    FD_t fd;
    const char *fileName;
    off_t start;
    rpm_loff_t size;
} *sigTarget;

static int closeFile(FD_t *fdp)
{
    if (fdp == NULL || *fdp == NULL)
	return 1;

    /* close and reset *fdp to NULL */
    (void) Fclose(*fdp);
    *fdp = NULL;
    return 0;
}

/**
 */
static int manageFile(FD_t *fdp, const char *fn, int flags)
{
    FD_t fd;
    const char *fmode;

    if (fdp == NULL || fn == NULL)	/* programmer error */
	return 1;

    /* open a file and set *fdp */
    if (*fdp == NULL && fn != NULL) {
	switch (flags & O_ACCMODE) {
	    case O_WRONLY:
		fmode = "w.ufdio";
		break;
	    case O_RDONLY:
		fmode = "r.ufdio";
		break;
	    default:
	    case O_RDWR:
		fmode = "r+.ufdio";
		break;
	}
	fd = Fopen(fn, fmode);
	if (fd == NULL || Ferror(fd)) {
	    rpmlog(RPMLOG_ERR, _("%s: open failed: %s\n"), fn,
		Fstrerror(fd));
	    return 1;
	}
	*fdp = fd;
	return 0;
    }

    /* no operation */
    if (*fdp != NULL && fn != NULL)
	return 0;

    /* XXX never reached */
    return 1;
}

/**
 * Copy header+payload, calculating digest(s) on the fly.
 * @param sfdp source file
 * @param sfnp source path
 * @param tfdp destination file
 * @param tfnp destination path
 */
static int copyFile(FD_t *sfdp, const char *sfnp,
		FD_t *tfdp, const char *tfnp)
{
    unsigned char buf[BUFSIZ];
    ssize_t count;
    int rc = 1;

    while ((count = Fread(buf, sizeof(buf[0]), sizeof(buf), *sfdp)) > 0)
    {
	if (Fwrite(buf, sizeof(buf[0]), count, *tfdp) != count) {
	    rpmlog(RPMLOG_ERR, _("%s: Fwrite failed: %s\n"), tfnp,
		Fstrerror(*tfdp));
	    goto exit;
	}
    }
    if (count < 0) {
	rpmlog(RPMLOG_ERR, _("%s: Fread failed: %s\n"), sfnp, Fstrerror(*sfdp));
	goto exit;
    }
    if (Fflush(*tfdp) != 0) {
	rpmlog(RPMLOG_ERR, _("%s: Fflush failed: %s\n"), tfnp,
	    Fstrerror(*tfdp));
    }

    rc = 0;

exit:
    return rc;
}

/*
 * Validate generated signature and insert to header if it looks sane.
 * RPM doesn't support everything GPG does. Basic tests to see if the
 * generated signature is something we can use.
 * Return generated signature tag data on success, NULL on failure.
 */
static rpmtd makeSigTag(Header sigh, int ishdr, uint8_t *pkt, size_t pktlen)
{
    pgpDigParams sigp = NULL;
    rpmTagVal sigtag;
    rpmtd sigtd = NULL;
    unsigned int hash_algo;
    unsigned int pubkey_algo;
    int ver;

    if (pgpPrtParams(pkt, pktlen, PGPTAG_SIGNATURE, &sigp)) {
	rpmlog(RPMLOG_ERR, _("Unsupported OpenPGP signature\n"));
	goto exit;
    }

    hash_algo = pgpDigParamsAlgo(sigp, PGPVAL_HASHALGO);
    if (rpmDigestLength(hash_algo) == 0) {
	rpmlog(RPMLOG_ERR, _("Unsupported OpenPGP hash algorithm %u\n"), hash_algo);
	goto exit;
    }

    pubkey_algo = pgpDigParamsAlgo(sigp, PGPVAL_PUBKEYALGO);
    switch (pubkey_algo) {
    case PGPPUBKEYALGO_DSA:
    case PGPPUBKEYALGO_ECDSA:
    case PGPPUBKEYALGO_EDDSA:
	sigtag = ishdr ? RPMSIGTAG_DSA : RPMSIGTAG_GPG;
	break;
    case PGPPUBKEYALGO_RSA:
	sigtag = ishdr ? RPMSIGTAG_RSA : RPMSIGTAG_PGP;
	break;
    default:
	rpmlog(RPMLOG_ERR, _("Unsupported OpenPGP pubkey algorithm %u\n"),
		pubkey_algo);
	goto exit;
	break;
    }

    ver = pgpDigParamsVersion(sigp);
    if (ver < 4) {
	rpmlog(RPMLOG_WARNING, _("Deprecated OpenPGP signature version %d\n"),
		ver);
    }

    /* Looks sane, create the tag data */
    sigtd = rpmtdNew();
    sigtd->count = pktlen;
    sigtd->data = memcpy(xmalloc(pktlen), pkt, pktlen);;
    sigtd->type = RPM_BIN_TYPE;
    sigtd->tag = sigtag;
    sigtd->flags |= RPMTD_ALLOCED;

exit:
    pgpDigParamsFree(sigp);
    return sigtd;
}

static char ** signCmd(const char *sigfile)
{
    int argc = 0;
    char **argv = NULL;

    rpmPushMacro(NULL, "__plaintext_filename", NULL, "-", -1);
    rpmPushMacro(NULL, "__signature_filename", NULL, sigfile, -1);

    char *cmd = rpmExpand("%{?__gpg_sign_cmd}", NULL);

    rpmPopMacro(NULL, "__plaintext_filename");
    rpmPopMacro(NULL, "__signature_filename");

    if (poptParseArgvString(cmd, &argc, (const char ***)&argv) < 0 || argc < 2) {
	rpmlog(RPMLOG_ERR, _("Invalid sign command: %s\n"), cmd);
	argv = _free(argv);
    }

    free(cmd);

    return argv;
}

static int runGPG(sigTarget sigt, const char *sigfile)
{
    int pid = 0, status;
    int pipefd[2];
    FILE *fpipe = NULL;
    unsigned char buf[BUFSIZ];
    ssize_t count;
    ssize_t wantCount;
    rpm_loff_t size;
    int rc = 1; /* assume failure */
    char **argv = NULL;

    if ((argv = signCmd(sigfile)) == NULL)
	goto exit_nowait;

    if (pipe(pipefd) < 0) {
        rpmlog(RPMLOG_ERR, _("Could not create pipe for signing: %m\n"));
        goto exit_nowait;
    }

    if (!(pid = fork())) {
	/* GnuPG needs extra setup, try to see if that's what we're running */
	char *out = rpmExpand("%(", argv[0], " --version 2> /dev/null)", NULL);
	int using_gpg = (strstr(out, "GnuPG") != NULL);
	if (using_gpg) {
	    const char *tty = ttyname(STDIN_FILENO);
	    const char *gpg_path = NULL;

	    if (!getenv("GPG_TTY") && (!tty || setenv("GPG_TTY", tty, 0)))
		rpmlog(RPMLOG_WARNING, _("Could not set GPG_TTY to stdin: %m\n"));

	    gpg_path = rpmExpand("%{?_gpg_path}", NULL);
	    if (gpg_path && *gpg_path != '\0')
		(void) setenv("GNUPGHOME", gpg_path, 1);
	}
	free(out);

	dup2(pipefd[0], STDIN_FILENO);
	close(pipefd[1]);

	rc = execve(argv[0], argv+1, environ);

	rpmlog(RPMLOG_ERR, _("Could not exec %s: %s\n"), argv[0],
		strerror(errno));
	_exit(EXIT_FAILURE);
    }

    close(pipefd[0]);
    fpipe = fdopen(pipefd[1], "w");
    if (!fpipe) {
	rpmlog(RPMLOG_ERR, _("Could not open pipe for writing: %m\n"));
	goto exit;
    }

    if (Fseek(sigt->fd, sigt->start, SEEK_SET) < 0) {
	rpmlog(RPMLOG_ERR, _("Could not seek in file %s: %s\n"),
		sigt->fileName, Fstrerror(sigt->fd));
	goto exit;
    }

    size = sigt->size;
    wantCount = size < sizeof(buf) ? size : sizeof(buf);
    while ((count = Fread(buf, sizeof(buf[0]), wantCount, sigt->fd)) > 0) {
	fwrite(buf, sizeof(buf[0]), count, fpipe);
	if (ferror(fpipe)) {
	    rpmlog(RPMLOG_ERR, _("Could not write to pipe\n"));
	    goto exit;
	}
	size -= count;
	wantCount = size < sizeof(buf) ? size : sizeof(buf);
    }
    if (count < 0) {
	rpmlog(RPMLOG_ERR, _("Could not read from file %s: %s\n"),
		sigt->fileName, Fstrerror(sigt->fd));
	goto exit;
    }

exit:

    if (fpipe)
	fclose(fpipe);
    if (pipefd[1])
	close(pipefd[1]);

    pid_t reaped;
    do {
        reaped = waitpid(pid, &status, 0);
    } while (reaped == -1 && errno == EINTR);

    if (reaped == -1) {
	rpmlog(RPMLOG_ERR, _("%s waitpid failed (%s)\n"), argv[0],
		strerror(errno));
    } else if (!WIFEXITED(status) || WEXITSTATUS(status)) {
	rpmlog(RPMLOG_ERR, _("%s exec failed (%d)\n"), argv[0],
		WEXITSTATUS(status));
    } else {
	rc = 0;
    }

exit_nowait:
    free(argv);

    return rc;
}

/**
 * Generate GPG signature(s) for a header+payload file.
 * @param sigh		signature header
 * @param ishdr		header-only signature?
 * @param sigt		signature target
 * @param passPhrase	private key pass phrase
 * @return		generated sigtag on success, 0 on failure
 */
static rpmtd makeGPGSignature(Header sigh, int ishdr, sigTarget sigt)
{
    char * sigfile = rstrscat(NULL, sigt->fileName, ".sig", NULL);
    struct stat st;
    uint8_t * pkt = NULL;
    size_t pktlen = 0;
    rpmtd sigtd = NULL;

    if (runGPG(sigt, sigfile))
	goto exit;

    if (stat(sigfile, &st)) {
	/* External command failed to write signature */
	rpmlog(RPMLOG_ERR, _("failed to write signature\n"));
	goto exit;
    }

    pktlen = st.st_size;
    rpmlog(RPMLOG_DEBUG, "OpenPGP sig size: %zd\n", pktlen);
    pkt = (uint8_t *)xmalloc(pktlen);

    {	FD_t fd;

	int rc = 0;
	fd = Fopen(sigfile, "r.ufdio");
	if (fd != NULL && !Ferror(fd)) {
	    rc = Fread(pkt, sizeof(*pkt), pktlen, fd);
	    (void) Fclose(fd);
	}
	if (rc != pktlen) {
	    rpmlog(RPMLOG_ERR, _("unable to read the signature\n"));
	    goto exit;
	}
    }

    rpmlog(RPMLOG_DEBUG, "Got %zd bytes of OpenPGP sig\n", pktlen);

    /* Parse the signature, change signature tag as appropriate. */
    sigtd = makeSigTag(sigh, ishdr, pkt, pktlen);
exit:
    (void) unlink(sigfile);
    free(sigfile);
    free(pkt);

    return sigtd;
}

static void deleteSigs(Header sigh)
{
    headerDel(sigh, RPMSIGTAG_GPG);
    headerDel(sigh, RPMSIGTAG_PGP);
    headerDel(sigh, RPMSIGTAG_DSA);
    headerDel(sigh, RPMSIGTAG_RSA);
    headerDel(sigh, RPMSIGTAG_PGP5);
}

static void deleteFileSigs(Header sigh)
{
    headerDel(sigh, RPMSIGTAG_FILESIGNATURELENGTH);
    headerDel(sigh, RPMSIGTAG_FILESIGNATURES);
    headerDel(sigh, RPMSIGTAG_VERITYSIGNATURES);
    headerDel(sigh, RPMSIGTAG_VERITYSIGNATUREALGO);
}

static int haveSignature(rpmtd sigtd, Header h)
{
    pgpDigParams sig1 = NULL;
    pgpDigParams sig2 = NULL;
    struct rpmtd_s oldtd;
    int rc = 0; /* assume no */

    if (!headerGet(h, rpmtdTag(sigtd), &oldtd, HEADERGET_DEFAULT))
	return rc;

    pgpPrtParams((uint8_t *)sigtd->data, sigtd->count, PGPTAG_SIGNATURE, &sig1);
    while (rpmtdNext(&oldtd) >= 0 && rc == 0) {
	pgpPrtParams((uint8_t *)oldtd.data, oldtd.count, PGPTAG_SIGNATURE, &sig2);
	if (pgpDigParamsCmp(sig1, sig2) == 0)
	    rc = 1;
	sig2 = pgpDigParamsFree(sig2);
    }
    pgpDigParamsFree(sig1);
    rpmtdFreeData(&oldtd);

    return rc;
}

static int replaceSignature(Header sigh, sigTarget sigt_v3, sigTarget sigt_v4)
{
    int rc = -1;
    rpmtd sigtd = NULL;
    
    /* Make the cheaper v4 signature first */
    if ((sigtd = makeGPGSignature(sigh, 1, sigt_v4)) == NULL)
	goto exit;

    /* See if we already have a signature by the same key and parameters */
    if (haveSignature(sigtd, sigh)) {
	rc = 1;
	goto exit;
    }
    /* Nuke all signature tags */
    deleteSigs(sigh);

    if (headerPut(sigh, sigtd, HEADERPUT_DEFAULT) == 0)
	goto exit;

    if (sigt_v3) {
	rpmtdFree(sigtd);

	/* Assume the same signature test holds for v3 signature too */
	if ((sigtd = makeGPGSignature(sigh, 0, sigt_v3)) == NULL)
	    goto exit;

	if (headerPut(sigh, sigtd, HEADERPUT_DEFAULT) == 0)
	    goto exit;
    }

    rc = 0;
exit:
    rpmtdFree(sigtd);
    return rc;
}

static void unloadImmutableRegion(Header *hdrp, rpmTagVal tag)
{
    struct rpmtd_s td;
    Header oh = NULL;

    if (headerGet(*hdrp, tag, &td, HEADERGET_DEFAULT)) {
	oh = headerImport(td.data, td.count, HEADERIMPORT_COPY);
	rpmtdFreeData(&td);
    } else {
	/* XXX should we warn if the immutable region is corrupt/missing? */
	oh = headerLink(*hdrp);
    }

    if (oh) {
	/* Perform a copy to eliminate crud from buggy signing tools etc */
	Header nh = headerCopy(oh);
	headerFree(*hdrp);
	*hdrp = headerLink(nh);
	headerFree(nh);
	headerFree(oh);
    }
}

static rpmRC includeFileSignatures(Header *sigp, Header *hdrp)
{
#ifdef WITH_IMAEVM
    rpmRC rc;
    char *key = rpmExpand("%{?_file_signing_key}", NULL);
    char *keypass = rpmExpand("%{?_file_signing_key_password}", NULL);

    if (rstreq(keypass, "")) {
	free(keypass);
	keypass = NULL;
    }

    rc = rpmSignFiles(*sigp, *hdrp, key, keypass);

    free(keypass);
    free(key);
    return rc;
#else
    rpmlog(RPMLOG_ERR, _("file signing support not built in\n"));
    return RPMRC_FAIL;
#endif
}

static rpmRC includeVeritySignatures(FD_t fd, Header *sigp, Header *hdrp)
{
#ifdef WITH_FSVERITY
    rpmRC rc = RPMRC_OK;
    char *key = rpmExpand("%{?_file_signing_key}", NULL);
    char *keypass = rpmExpand("%{?_file_signing_key_password}", NULL);
    char *cert = rpmExpand("%{?_file_signing_cert}", NULL);
    char *algorithm = rpmExpand("%{?_verity_algorithm}", NULL);
    uint16_t algo = 0;

    if (rstreq(keypass, "")) {
	free(keypass);
	keypass = NULL;
    }

    if (algorithm && strlen(algorithm) > 0) {
	    algo = libfsverity_find_hash_alg_by_name(algorithm);
	    rpmlog(RPMLOG_DEBUG, _("Searching for algorithm %s got %i\n"),
		   algorithm, algo);
	    if (!algo) {
		    rpmlog(RPMLOG_ERR, _("Unsupported fsverity algorithm %s\n"),
			   algorithm);
		    rc = RPMRC_FAIL;
		    goto out;
	    }
    }
    if (key && cert) {
	    rc = rpmSignVerity(fd, *sigp, *hdrp, key, keypass, cert, algo);
    } else {
	rpmlog(RPMLOG_ERR, _("fsverity signatures requires a key and a cert\n"));
	rc = RPMRC_FAIL;
    }

 out:
    free(keypass);
    free(key);
    free(cert);
    return rc;
#else
    rpmlog(RPMLOG_ERR, _("fsverity signing support not built in\n"));
    return RPMRC_FAIL;
#endif
}

static int msgCb(struct rpmsinfo_s *sinfo, void *cbdata)
{
    char **msg = (char **)cbdata;
    if (sinfo->rc && *msg == NULL)
	*msg = rpmsinfoMsg(sinfo);
    return (sinfo->rc != RPMRC_FAIL);
}

/* Require valid digests on entire package for signing. */
static rpmRC checkPkg(FD_t fd, char **msg)
{
    rpmRC rc;
    struct rpmvs_s *vs = rpmvsCreate(RPMSIG_DIGEST_TYPE, 0, NULL);
    off_t offset = Ftell(fd);

    Fseek(fd, 0, SEEK_SET);
    rc = rpmpkgRead(vs, fd, NULL, NULL, msg);
    if (!rc) {
	rc = rpmvsVerify(vs, RPMSIG_DIGEST_TYPE, msgCb, msg) ?
			RPMRC_FAIL : RPMRC_OK;
    }
    Fseek(fd, offset, SEEK_SET);
    Fseek(fd, offset, SEEK_SET);

    rpmvsFree(vs);
    return rc;
}

/** \ingroup rpmcli
 * Create/modify elements in signature header.
 * @param rpm		path to package
 * @param deleting	adding or deleting signature?
 * @param flags
 * @return		0 on success, -1 on error
 */
static int rpmSign(const char *rpm, int deleting, int flags)
{
    FD_t fd = NULL;
    FD_t ofd = NULL;
    char *trpm = NULL;
    Header sigh = NULL;
    Header h = NULL;
    char *msg = NULL;
    int res = -1; /* assume failure */
    rpmRC rc;
    struct rpmtd_s utd;
    off_t headerStart;
    off_t sigStart;
    struct sigTarget_s sigt_v3;
    struct sigTarget_s sigt_v4;
    unsigned int origSigSize;
    int insSig = 0;

    fprintf(stdout, "%s:\n", rpm);

    if (manageFile(&fd, rpm, O_RDWR))
	goto exit;

    /* Ensure package is intact before attempting to sign */
    if ((rc = checkPkg(fd, &msg))) {
	rpmlog(RPMLOG_ERR, "not signing corrupt package %s: %s\n", rpm, msg);
	goto exit;
    }

    if ((rc = rpmLeadRead(fd, &msg)) != RPMRC_OK) {
	rpmlog(RPMLOG_ERR, "%s: %s\n", rpm, msg);
	goto exit;
    }

    sigStart = Ftell(fd);
    rc = rpmReadSignature(fd, &sigh, &msg);
    if (rc != RPMRC_OK) {
	rpmlog(RPMLOG_ERR, _("%s: rpmReadSignature failed: %s"), rpm,
		    (msg && *msg ? msg : "\n"));
	goto exit;
    }

    headerStart = Ftell(fd);
    if (rpmReadHeader(NULL, fd, &h, &msg) != RPMRC_OK) {
	rpmlog(RPMLOG_ERR, _("%s: headerRead failed: %s\n"), rpm, msg);
	goto exit;
    }

    if (!headerIsEntry(h, RPMTAG_HEADERIMMUTABLE)) {
	rpmlog(RPMLOG_ERR, _("Cannot sign RPM v3 packages\n"));
	goto exit;
    }

    /* Always add V3 signatures if no payload digest present */
    if (!(headerIsEntry(h, RPMTAG_PAYLOADDIGEST) ||
	  headerIsEntry(h, RPMTAG_PAYLOADDIGESTALT))) {
	flags |= RPMSIGN_FLAG_RPMV3;
    }

    if (headerIsSource(h)) {
	rpmlog(RPMLOG_DEBUG,
	    _("File signatures not applicable to src.rpm: %s\n"), rpm);
	flags &= ~(RPMSIGN_FLAG_IMA | RPMSIGN_FLAG_FSVERITY);
    }

    origSigSize = headerSizeof(sigh, HEADER_MAGIC_YES);
    unloadImmutableRegion(&sigh, RPMTAG_HEADERSIGNATURES);

    if (flags & RPMSIGN_FLAG_IMA) {
	if (includeFileSignatures(&sigh, &h))
	    goto exit;
    }

    if (flags & RPMSIGN_FLAG_FSVERITY) {
	if (includeVeritySignatures(fd, &sigh, &h))
	    goto exit;
    }

    if (deleting == 2) {	/* Nuke IMA + fsverity file signature tags. */
	deleteFileSigs(sigh);
    } else if (deleting) {	/* Nuke all the signature tags. */
	deleteSigs(sigh);
    } else {
	/* Signature target containing header + payload */
	int v3 = (flags & RPMSIGN_FLAG_RPMV3);
	sigt_v3.fd = fd;
	sigt_v3.start = headerStart;
	sigt_v3.fileName = rpm;
	sigt_v3.size = fdSize(fd) - headerStart;

	/* Signature target containing only header */
	sigt_v4 = sigt_v3;
	sigt_v4.size = headerSizeof(h, HEADER_MAGIC_YES);

	res = replaceSignature(sigh, v3 ? &sigt_v3 : NULL, &sigt_v4);
	if (res != 0) {
	    if (res == 1) {
		rpmlog(RPMLOG_WARNING,
		   _("%s already contains identical signature, skipping\n"),
		   rpm);
		/* Identical signature is not an error */
		res = 0;
	    }
	    goto exit;
	}
	res = -1;
    }

    /* Adjust reserved size for added/removed signatures */
    if (headerGet(sigh, RPMSIGTAG_RESERVEDSPACE, &utd, HEADERGET_MINMEM)) {
	unsigned newSize = headerSizeof(sigh, HEADER_MAGIC_YES);
	int diff = newSize - origSigSize;

	/* diff can be zero if nothing was added or removed */
	if (diff) {
	    utd.count -= diff;
	    if (utd.count > 0 && newSize + utd.count <= origSigSize) {
		uint8_t *zeros = (uint8_t *)xcalloc(utd.count, sizeof(*zeros));
		utd.data = zeros;
		headerMod(sigh, &utd);
		insSig = 1;
		free(zeros);
	    }
	}
    }

    /* Reallocate the signature into one contiguous region. */
    sigh = headerReload(sigh, RPMTAG_HEADERSIGNATURES);
    if (sigh == NULL)	/* XXX can't happen */
	goto exit;

    if (Fseek(fd, insSig ? sigStart : 0, SEEK_SET) < 0) {
	rpmlog(RPMLOG_ERR, _("Could not seek in file %s: %s\n"),
		rpm, Fstrerror(fd));
	goto exit;
    }

    if (insSig) {
	/* Insert new signature into original rpm */
	if (rpmWriteSignature(fd, sigh)) {
	    rpmlog(RPMLOG_ERR, _("%s: rpmWriteSignature failed: %s\n"), rpm,
		Fstrerror(fd));
	    goto exit;
	}
	res = 0;
    } else {
	char lbuf[RPMLEAD_SIZE];
	/* Replace orignal rpm with new rpm containing new signature */
	rasprintf(&trpm, "%s.XXXXXX", rpm);
	ofd = rpmMkTemp(trpm);
	if (ofd == NULL || Ferror(ofd)) {
	    rpmlog(RPMLOG_ERR, _("rpmMkTemp failed\n"));
	    goto exit;
	}

	/* Copy lead from original */
	if (!(Fread(lbuf, 1, RPMLEAD_SIZE, fd) == RPMLEAD_SIZE &&
	      Fwrite(lbuf, 1, RPMLEAD_SIZE, ofd) == RPMLEAD_SIZE))
	{
	    rpmlog(RPMLOG_ERR, _("%s: failed to copy rpm lead: %s\n"),
				trpm, Fstrerror(ofd));
	    goto exit;
	}

	if (rpmWriteSignature(ofd, sigh)) {
	    rpmlog(RPMLOG_ERR, _("%s: rpmWriteSignature failed: %s\n"), trpm,
		Fstrerror(ofd));
	    goto exit;
	}

	if (Fseek(fd, headerStart, SEEK_SET) < 0) {
	    rpmlog(RPMLOG_ERR, _("Could not seek in file %s: %s\n"),
		    rpm, Fstrerror(fd));
	    goto exit;
	}
	/* Append the header and archive from the temp file */
	if (copyFile(&fd, rpm, &ofd, trpm) == 0) {
	    struct stat st;

	    /* File must be closed before deletion due to different file locking in some file systems*/
	    if (fd) (void) closeFile(&fd);
	    if (ofd) (void) closeFile(&ofd);

	    /* Move final target into place, restore file permissions. */
	    if (stat(rpm, &st) == 0 && unlink(rpm) == 0 &&
			rename(trpm, rpm) == 0 && chmod(rpm, st.st_mode) == 0) {
		res = 0;
	    } else {
		rpmlog(RPMLOG_ERR, _("replacing %s failed: %s\n"),
		       rpm, strerror(errno));
	    }
	}
    }

exit:
    if (fd)	(void) closeFile(&fd);
    if (ofd)	(void) closeFile(&ofd);

    headerFree(sigh);
    headerFree(h);
    free(msg);

    /* Clean up intermediate target */
    if (trpm) {
	(void) unlink(trpm);
	free(trpm);
    }

    return res;
}

int rpmPkgSign(const char *path, const struct rpmSignArgs * args)
{
    int rc;

    if (args) {
	if (args->hashalgo) {
	    char *algo = NULL;
	    rasprintf(&algo, "%d", args->hashalgo);
	    rpmPushMacro(NULL, "_gpg_digest_algo", NULL, algo, RMIL_GLOBAL);
	    free(algo);
	}
	if (args->keyid) {
	    rpmPushMacro(NULL, "_gpg_name", NULL, args->keyid, RMIL_GLOBAL);
	}
    }

    rc = rpmSign(path, 0, args ? args->signflags : 0);

    if (args) {
	if (args->hashalgo) {
	    rpmPopMacro(NULL, "_gpg_digest_algo");
	}
	if (args->keyid) {
	    rpmPopMacro(NULL, "_gpg_name");
	}
    }

    return rc;
}

int rpmPkgDelSign(const char *path, const struct rpmSignArgs * args)
{
    return rpmSign(path, 1, 0);
}

int rpmPkgDelFileSign(const char *path, const struct rpmSignArgs * args)
{
    return rpmSign(path, 2, 0);
}
