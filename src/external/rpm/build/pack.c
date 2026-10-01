/** \ingroup rpmbuild
 * \file build/pack.c
 *  Assemble components of an RPM package.
 */

#include "system.h"

#include <errno.h>
#include <stdlib.h>
#include <sys/wait.h>

#include <rpm/rpmlib.h>			/* RPMSIGTAG*, rpmReadPackageFile */
#include <rpm/rpmfileutil.h>
#include <rpm/rpmlog.h>

#include "rpmio_internal.h"	/* fdInitDigest, fdFiniDigest */
#include "fsm.h"
#include "signature.h"
#include "rpmlead.h"
#include "rpmbuild_internal.h"
#include "rpmbuild_misc.h"

#include "debug.h"

static int rpmPackageFilesArchive(rpmfiles fi, int isSrc,
				  FD_t cfd, ARGV_t dpaths,
				  rpm_loff_t * archiveSize, char ** failedFile)
{
    int rc = 0;
    rpmfi archive = rpmfiNewArchiveWriter(cfd, fi);

    while (!rc && (rc = rpmfiNext(archive)) >= 0) {
        /* Copy file into archive. */
	FD_t rfd = NULL;
	const char *path = dpaths[rpmfiFX(archive)];

	rfd = Fopen(path, "r.ufdio");
	if (Ferror(rfd)) {
	    rc = RPMERR_OPEN_FAILED;
	} else {
	    rc = rpmfiArchiveWriteFile(archive, rfd);
	}

	if (rc && failedFile)
	    *failedFile = xstrdup(path);
	if (rfd) {
	    /* preserve any prior errno across close */
	    int myerrno = errno;
	    Fclose(rfd);
	    errno = myerrno;
	}
    }

    if (rc == RPMERR_ITER_END)
	rc = 0;

    /* Finish the payload stream */
    if (!rc)
	rc = rpmfiArchiveClose(archive);

    if (archiveSize)
	*archiveSize = (rc == 0) ? rpmfiArchiveTell(archive) : 0;

    rpmfiFree(archive);

    return rc;
}
/**
 * @todo Create transaction set *much* earlier.
 */
static rpmRC cpio_doio(FD_t fdo, Package pkg, const char * fmodeMacro,
			int pld_algo,
			rpm_loff_t *archiveSize, char ** pldig)
{
    char *failedFile = NULL;
    FD_t cfd;
    int fsmrc;

    (void) Fflush(fdo);
    cfd = Fdopen(fdDup(Fileno(fdo)), fmodeMacro);
    if (cfd == NULL)
	return RPMRC_FAIL;

    /* Calculate alternative (uncompressed) payload digest while writing */
    fdInitDigestID(cfd, pld_algo, RPMTAG_PAYLOADDIGESTALT, 0);
    fsmrc = rpmPackageFilesArchive(pkg->cpioList, headerIsSource(pkg->header),
				   cfd, pkg->dpaths,
				   archiveSize, &failedFile);
    fdFiniDigest(cfd, RPMTAG_PAYLOADDIGESTALT, (void **)pldig, NULL, 1);

    if (fsmrc) {
	char *emsg = rpmfileStrerror(fsmrc);
	if (failedFile)
	    rpmlog(RPMLOG_ERR, _("create archive failed on file %s: %s\n"),
		   failedFile, emsg);
	else
	    rpmlog(RPMLOG_ERR, _("create archive failed: %s\n"), emsg);
	free(emsg);
    }

    free(failedFile);
    Fclose(cfd);

    return (fsmrc == 0) ? RPMRC_OK : RPMRC_FAIL;
}

static rpmRC addFileToTag(rpmSpec spec, const char * file,
			  Header h, rpmTagVal tag, int append)
{
    StringBuf sb = NULL;
    rpmRC rc = RPMRC_FAIL; /* assume failure */
    int flags = ALLOW_EMPTY;

    /* no script file is not an error */
    if (file == NULL)
	return RPMRC_OK;

    sb = newStringBuf();
    #pragma omp critical
    {
    if (append) {
	const char *s = headerGetString(h, tag);
	if (s) {
	    appendLineStringBuf(sb, s);
	    headerDel(h, tag);
	}
    }

    if (readManifest(spec, file, rpmTagGetName(tag), flags, NULL, &sb) >= 0) {
	headerPutString(h, tag, getStringBuf(sb));
	rc = RPMRC_OK;
    }

    } /* omp critical */
    freeStringBuf(sb);

    return rc;
}

static rpmRC processScriptFiles(rpmSpec spec, Package pkg)
{
    struct TriggerFileEntry *p;
    int addflags = 0;
    rpmRC rc = RPMRC_FAIL;
    Header h = pkg->header;
    struct TriggerFileEntry *tfa[] = {pkg->triggerFiles,
				      pkg->fileTriggerFiles,
				      pkg->transFileTriggerFiles};

    rpmTagVal progTags[] = {RPMTAG_TRIGGERSCRIPTPROG,
			    RPMTAG_FILETRIGGERSCRIPTPROG,
			    RPMTAG_TRANSFILETRIGGERSCRIPTPROG};

    rpmTagVal flagTags[] = {RPMTAG_TRIGGERSCRIPTFLAGS,
			    RPMTAG_FILETRIGGERSCRIPTFLAGS,
			    RPMTAG_TRANSFILETRIGGERSCRIPTFLAGS};

    rpmTagVal scriptTags[] = {RPMTAG_TRIGGERSCRIPTS,
			      RPMTAG_FILETRIGGERSCRIPTS,
			      RPMTAG_TRANSFILETRIGGERSCRIPTS};
    rpmTagVal priorityTags[] = {0,
				RPMTAG_FILETRIGGERPRIORITIES,
				RPMTAG_TRANSFILETRIGGERPRIORITIES};
    int i;
    
    if (addFileToTag(spec, pkg->preInFile, h, RPMTAG_PREIN, 1) ||
	addFileToTag(spec, pkg->preUnFile, h, RPMTAG_PREUN, 1) ||
	addFileToTag(spec, pkg->preTransFile, h, RPMTAG_PRETRANS, 1) ||
	addFileToTag(spec, pkg->postInFile, h, RPMTAG_POSTIN, 1) ||
	addFileToTag(spec, pkg->postUnFile, h, RPMTAG_POSTUN, 1) ||
	addFileToTag(spec, pkg->postTransFile, h, RPMTAG_POSTTRANS, 1) ||
	addFileToTag(spec, pkg->preunTransFile, h, RPMTAG_PREUNTRANS, 1) ||
	addFileToTag(spec, pkg->postunTransFile, h, RPMTAG_POSTUNTRANS, 1) ||
	addFileToTag(spec, pkg->verifyFile, h, RPMTAG_VERIFYSCRIPT, 1))
    {
	goto exit;
    }


    for (i = 0; i < sizeof(tfa)/sizeof(tfa[0]); i++) {
	addflags = 0;
	/* if any trigger has flags, we need to add flags entry for all of them */
	for (p = tfa[i]; p != NULL; p = p->next) {
	    if (p->flags) {
		addflags = 1;
		break;
	    }
	}

	for (p = tfa[i]; p != NULL; p = p->next) {
	    headerPutString(h, progTags[i], p->prog);

	    if (priorityTags[i]) {
		headerPutUint32(h, priorityTags[i], &p->priority, 1);
	    }

	    if (addflags) {
		headerPutUint32(h, flagTags[i], &p->flags, 1);
	    }

	    if (p->script) {
		headerPutString(h, scriptTags[i], p->script);
	    } else if (p->fileName) {
		if (addFileToTag(spec, p->fileName, h, scriptTags[i], 0)) {
		    goto exit;
		}
	    } else {
		/* This is dumb.  When the header supports NULL string */
		/* this will go away.                                  */
		headerPutString(h, scriptTags[i], "");
	    }
	}
    }
    rc = RPMRC_OK;

exit:
    return rc;
}

struct charInDepData {
    char c;
    int present;
};

static rpmRC charInDepCb(void *cbdata, rpmrichParseType type,
		const char *n, int nl, const char *e, int el, rpmsenseFlags sense,
		rpmrichOp op, char **emsg) {
    struct charInDepData *data = (struct charInDepData *)cbdata;
    if (e && data && memchr(e, data->c, el))
	data->present = 1;

    return RPMRC_OK;
}

static int haveCharInDep(Package pkg, char c)
{
    struct charInDepData data = {c, 0};
    for (int i = 0; i < PACKAGE_NUM_DEPS; i++) {
	rpmds ds = rpmdsInit(pkg->dependencies[i]);
	while (rpmdsNext(ds) >= 0) {
	    if (rpmdsIsRich(ds)) {
		const char *depstr = rpmdsN(ds);
		rpmrichParse(&depstr, NULL, charInDepCb, &data);
	    } else {
		const char *evr = rpmdsEVR(ds);
		if (strchr(evr, c))
		    data.present = 1;
	    }
	    if (data.present)
		return 1;
	}
    }
    return 0;
}

static int haveRichDep(Package pkg)
{
    for (int i = 0; i < PACKAGE_NUM_DEPS; i++) {
	rpmds ds = rpmdsInit(pkg->dependencies[i]);
	rpmTagVal tagN = rpmdsTagN(ds);
	if (tagN != RPMTAG_REQUIRENAME &&
	    tagN != RPMTAG_RECOMMENDNAME &&
	    tagN != RPMTAG_SUGGESTNAME &&
	    tagN != RPMTAG_SUPPLEMENTNAME &&
	    tagN != RPMTAG_ENHANCENAME &&
	    tagN != RPMTAG_CONFLICTNAME)
	    continue;
	while (rpmdsNext(ds) >= 0) {
	    if (rpmdsIsRich(ds))
		return 1;
	}
    }
    return 0;
}

static char *getIOFlags(Package pkg)
{
    char *rpmio_flags;
    const char *s;

    /* Save payload information */
    if (headerIsSource(pkg->header))
	rpmio_flags = rpmExpand("%{?_source_payload}", NULL);
    else 
	rpmio_flags = rpmExpand("%{?_binary_payload}", NULL);

    /* If not configured or bogus, fall back to gz */
    if (rpmio_flags[0] != 'w') {
	free(rpmio_flags);
	rpmio_flags = xstrdup("w9.gzdio");
    }
    s = strchr(rpmio_flags, '.');
    if (s) {
	char *buf = NULL;
	const char *compr = NULL;
	headerPutString(pkg->header, RPMTAG_PAYLOADFORMAT, "cpio");

	if (rstreq(s+1, "ufdio")) {
	    compr = NULL;
	} else if (rstreq(s+1, "gzdio")) {
	    compr = "gzip";
#ifdef HAVE_BZLIB_H
	} else if (rstreq(s+1, "bzdio")) {
	    compr = "bzip2";
	    /* Add prereq on rpm version that understands bzip2 payloads */
	    (void) rpmlibNeedsFeature(pkg, "PayloadIsBzip2", "3.0.5-1");
#endif
#ifdef HAVE_LZMA_H
	} else if (rstreq(s+1, "xzdio")) {
	    compr = "xz";
	    (void) rpmlibNeedsFeature(pkg, "PayloadIsXz", "5.2-1");
	} else if (rstreq(s+1, "lzdio")) {
	    compr = "lzma";
	    (void) rpmlibNeedsFeature(pkg, "PayloadIsLzma", "4.4.6-1");
#endif
#ifdef HAVE_ZSTD
	} else if (rstreq(s+1, "zstdio")) {
	    compr = "zstd";
	    /* Add prereq on rpm version that understands zstd payloads */
	    (void) rpmlibNeedsFeature(pkg, "PayloadIsZstd", "5.4.18-1");
#endif
	} else {
	    rpmlog(RPMLOG_ERR, _("Unknown payload compression: %s\n"),
		   rpmio_flags);
	    rpmio_flags = _free(rpmio_flags);
	    goto exit;
	}

	if (compr)
	    headerPutString(pkg->header, RPMTAG_PAYLOADCOMPRESSOR, compr);
	buf = xstrdup(rpmio_flags);
	buf[s - rpmio_flags] = '\0';
	headerPutString(pkg->header, RPMTAG_PAYLOADFLAGS, buf+1);
	free(buf);
    }
exit:
    return rpmio_flags;
}

static void finalizeDeps(Package pkg)
{
    /* check if the package has a dependency with a '~' */
    if (haveCharInDep(pkg, '~'))
	(void) rpmlibNeedsFeature(pkg, "TildeInVersions", "4.10.0-1");

    /* check if the package has a dependency with a '^' */
    if (haveCharInDep(pkg, '^'))
	(void) rpmlibNeedsFeature(pkg, "CaretInVersions", "4.15.0-1");

    /* check if the package has a rich dependency */
    if (haveRichDep(pkg))
	(void) rpmlibNeedsFeature(pkg, "RichDependencies", "4.12.0-1");

    /* All dependencies added finally, write them into the header */
    for (int i = 0; i < PACKAGE_NUM_DEPS; i++) {
	/* Nuke any previously added dependencies from the header */
	headerDel(pkg->header, rpmdsTagN(pkg->dependencies[i]));
	headerDel(pkg->header, rpmdsTagEVR(pkg->dependencies[i]));
	headerDel(pkg->header, rpmdsTagF(pkg->dependencies[i]));
	headerDel(pkg->header, rpmdsTagTi(pkg->dependencies[i]));
	/* ...and add again, now with automatic dependencies included */
	rpmdsPutToHeader(pkg->dependencies[i], pkg->header);
    }
}

static void *nullDigest(int algo, int ascii)
{
    void *d = NULL;
    DIGEST_CTX ctx = rpmDigestInit(algo, 0);
    rpmDigestFinal(ctx, &d, NULL, ascii);
    return d;
}

static rpmRC fdJump(FD_t fd, off_t offset)
{
    if (Fseek(fd, offset, SEEK_SET) < 0) {
	rpmlog(RPMLOG_ERR, _("Could not seek in file %s: %s\n"),
		Fdescr(fd), Fstrerror(fd));
	return RPMRC_FAIL;
    }
    return RPMRC_OK;
}

static rpmRC fdConsume(FD_t fd, off_t start, off_t nbytes)
{
    size_t bufsiz = 32*BUFSIZ;
    unsigned char buf[bufsiz];
    off_t left = nbytes;
    ssize_t nb;

    if (start && fdJump(fd, start))
	return RPMRC_FAIL;

    while (left > 0) {
	nb = Fread(buf, 1, (left < bufsiz) ? left : bufsiz, fd);
	if (nb > 0)
	    left -= nb;
	else
	    break;
    };

    if (left) {
	rpmlog(RPMLOG_ERR, _("Failed to read %jd bytes in file %s: %s\n"),
	       (intmax_t) nbytes, Fdescr(fd), Fstrerror(fd));
    }

    return (left == 0) ? RPMRC_OK : RPMRC_FAIL;
}

static rpmRC writeHdr(FD_t fd, Header pkgh)
{
    /* Reallocate the header into one contiguous region for writing. */
    Header h = headerReload(headerCopy(pkgh), RPMTAG_HEADERIMMUTABLE);
    rpmRC rc = RPMRC_FAIL;

    if (h == NULL) {
	rpmlog(RPMLOG_ERR,_("Unable to create immutable header region\n"));
	goto exit;
    }

    if (headerWrite(fd, h, HEADER_MAGIC_YES)) {
	rpmlog(RPMLOG_ERR, _("Unable to write header to %s: %s\n"),
		Fdescr(fd), Fstrerror(fd));
	goto exit;
    }
    (void) Fflush(fd);
    rc = RPMRC_OK;

exit:
    headerFree(h);
    return rc;
}

/*
 * This is more than just a little insane:
 * In order to write the signature, we need to know the size and
 * the size and digests of the header and payload, which are located
 * after the signature on disk. We also need a digest of the compressed
 * payload for the main header, and of course the payload is after the
 * header on disk. So we need to create placeholders for both the
 * signature and main header that exactly match the final sizes, calculate
 * the payload digest, then generate and write the real main header to
 * be able to FINALLY calculate the digests we need for the signature
 * header. In other words, we need to write things in the exact opposite
 * order to how the RPM format is laid on disk.
 */
static rpmRC writeRPM(Package pkg, unsigned char ** pkgidp,
		      const char *fileName, char **cookie,
		      rpm_time_t buildTime, const char* buildHost)
{
    FD_t fd = NULL;
    char * rpmio_flags = NULL;
    char * SHA1 = NULL;
    char * SHA256 = NULL;
    uint8_t * MD5 = NULL;
    char * pld = NULL;
    char * upld = NULL;
    uint32_t pld_algo = RPM_HASH_SHA256; /* TODO: macro configuration */
    rpmRC rc = RPMRC_FAIL; /* assume failure */
    rpm_loff_t archiveSize = 0;
    off_t sigStart, hdrStart, payloadStart, payloadEnd;

    if (pkgidp)
	*pkgidp = NULL;

    rpmio_flags = getIOFlags(pkg);
    if (!rpmio_flags)
	goto exit;

    finalizeDeps(pkg);

    /* Create and add the cookie */
    if (cookie) {
	free(*cookie);
	rasprintf(cookie, "%s %d", buildHost, buildTime);
	headerPutString(pkg->header, RPMTAG_COOKIE, *cookie);
    }

    /* Create a dummy payload digests to get the header size right */
    pld = (char *)nullDigest(pld_algo, 1);
    headerPutUint32(pkg->header, RPMTAG_PAYLOADDIGESTALGO, &pld_algo, 1);
    headerPutString(pkg->header, RPMTAG_PAYLOADDIGEST, pld);
    headerPutString(pkg->header, RPMTAG_PAYLOADDIGESTALT, pld);
    pld = _free(pld);
    
    /* Check for UTF-8 encoding of string tags, add encoding tag if all good */
    if (checkForEncoding(pkg->header, 1))
	goto exit;

    /* Open the output file */
    fd = Fopen(fileName, "w+.ufdio");
    if (fd == NULL || Ferror(fd)) {
	rpmlog(RPMLOG_ERR, _("Could not open %s: %s\n"),
		fileName, Fstrerror(fd));
	goto exit;
    }

    /* Write the lead section into the package. */
    if (rpmLeadWrite(fd, pkg->header)) {
	rpmlog(RPMLOG_ERR, _("Unable to write package: %s\n"), Fstrerror(fd));
	goto exit;
    }

    /* Save the position of signature section */
    sigStart = Ftell(fd);

    /* Generate and write a placeholder signature header */
    SHA1 = (char *)nullDigest(RPM_HASH_SHA1, 1);
    SHA256 = (char *)nullDigest(RPM_HASH_SHA256, 1);
    MD5 = (uint8_t *)nullDigest(RPM_HASH_MD5, 0);
    if (rpmGenerateSignature(SHA256, SHA1, MD5, 0, 0, fd))
	goto exit;
    SHA1 = _free(SHA1);
    SHA256 = _free(SHA256);
    MD5 = _free(MD5);

    /* Write a placeholder header. */
    hdrStart = Ftell(fd);
    if (writeHdr(fd, pkg->header))
	goto exit;

    /* Write payload section (cpio archive) */
    payloadStart = Ftell(fd);
    if (cpio_doio(fd, pkg, rpmio_flags, pld_algo, &archiveSize, &upld))
	goto exit;
    payloadEnd = Ftell(fd);

    /* Re-read payload to calculate compressed digest */
    fdInitDigestID(fd, pld_algo, RPMTAG_PAYLOADDIGEST, 0);
    if (fdConsume(fd, payloadStart, payloadEnd - payloadStart))
	goto exit;
    fdFiniDigest(fd, RPMTAG_PAYLOADDIGEST, (void **)&pld, NULL, 1);

    /* Insert the payload digests in main header */
    headerDel(pkg->header, RPMTAG_PAYLOADDIGEST);
    headerPutString(pkg->header, RPMTAG_PAYLOADDIGEST, pld);
    headerDel(pkg->header, RPMTAG_PAYLOADDIGESTALT);
    headerPutString(pkg->header, RPMTAG_PAYLOADDIGESTALT, upld);
    pld = _free(pld);

    /* Write the final header */
    if (fdJump(fd, hdrStart))
	goto exit;
    if (writeHdr(fd, pkg->header))
	goto exit;

    /* Calculate digests: SHA on header, legacy MD5 on header + payload */
    fdInitDigestID(fd, RPM_HASH_MD5, RPMTAG_SIGMD5, 0);
    fdInitDigestID(fd, RPM_HASH_SHA1, RPMTAG_SHA1HEADER, 0);
    fdInitDigestID(fd, RPM_HASH_SHA256, RPMTAG_SHA256HEADER, 0);
    if (fdConsume(fd, hdrStart, payloadStart - hdrStart))
	goto exit;
    fdFiniDigest(fd, RPMTAG_SHA1HEADER, (void **)&SHA1, NULL, 1);
    fdFiniDigest(fd, RPMTAG_SHA256HEADER, (void **)&SHA256, NULL, 1);

    if (fdConsume(fd, 0, payloadEnd - payloadStart))
	goto exit;
    fdFiniDigest(fd, RPMTAG_SIGMD5, (void **)&MD5, NULL, 0);

    if (fdJump(fd, sigStart))
	goto exit;

    /* Generate the signature. Now with right values */
    if (rpmGenerateSignature(SHA256, SHA1, MD5, payloadEnd - hdrStart, archiveSize, fd))
	goto exit;

    rc = RPMRC_OK;

exit:
    free(rpmio_flags);
    free(SHA1);
    free(SHA256);
    free(upld);

    /* XXX Fish the pkgid out of the signature header. */
    if (pkgidp != NULL) {
	if (MD5 != NULL) {
	    *pkgidp = MD5;
	}
    } else {
	free(MD5);
    }

    Fclose(fd);

    if (rc == RPMRC_OK)
	rpmlog(RPMLOG_NOTICE, _("Wrote: %s\n"), fileName);
    else
	(void) unlink(fileName);

    return rc;
}

static const rpmTagVal copyTags[] = {
    RPMTAG_CHANGELOGTIME,
    RPMTAG_CHANGELOGNAME,
    RPMTAG_CHANGELOGTEXT,
    0
};

static rpmRC checkPackages(char *pkgcheck)
{
    int fail = rpmExpandNumeric("%{?_nonzero_exit_pkgcheck_terminate_build}");
    int xx;
    
    rpmlog(RPMLOG_NOTICE, _("Executing \"%s\":\n"), pkgcheck);
    xx = system(pkgcheck);
    if (WEXITSTATUS(xx) == -1 || WEXITSTATUS(xx) == 127) {
	rpmlog(RPMLOG_ERR, _("Execution of \"%s\" failed.\n"), pkgcheck);
	if (fail) return RPMRC_NOTFOUND;
    }
    if (WEXITSTATUS(xx) != 0) {
	rpmlog(RPMLOG_ERR, _("Package check \"%s\" failed.\n"), pkgcheck);
	if (fail) return RPMRC_FAIL;
    }
    
    return RPMRC_OK;
}

static rpmRC checkPackageSet(Package pkgs)
{
    char *pkglist = NULL;
    char *pkgcheck_set = NULL;
    rpmRC rc = RPMRC_OK;

    for (Package pkg = pkgs; pkg != NULL; pkg = pkg->next) {
	if (pkg->filename)
	    rstrscat(&pkglist, pkg->filename, " ", NULL);
    }

    pkgcheck_set = rpmExpand("%{?_build_pkgcheck_set} ", pkglist,  NULL);

    /* run only if _build_pkgcheck_set is defined */
    if (pkgcheck_set[0] != ' ')
	rc = checkPackages(pkgcheck_set);

    free(pkgcheck_set);
    free(pkglist);
    return rc;
}

/* watchout, argument is modified */
static rpmRC ensureDir(char *binRpm)
{
    rpmRC rc = RPMRC_OK;
    char *binDir = strchr(binRpm, '/');
    char *dn = NULL;
    if (binDir) {
	struct stat st;
	*binDir = '\0';
	dn = rpmGetPath("%{_rpmdir}/", binRpm, NULL);
	if (stat(dn, &st) < 0) {
	    switch (errno) {
	    case ENOENT:
		if (mkdir(dn, 0755) == 0 || errno == EEXIST)
		    break;
	    default:
		rpmlog(RPMLOG_ERR,_("cannot create %s: %s\n"),
			dn, strerror(errno));
		rc = RPMRC_FAIL;
		break;
	    }
	}
    }
    free(dn);
    return rc;
}

static rpmRC getPkgFilename(Header h, char **filename)
{
    const char *errorString;
    char *binFormat = rpmGetPath("%{_rpmfilename}", NULL);
    char *binRpm = headerFormat(h, binFormat, &errorString);
    rpmRC rc = RPMRC_FAIL;

    if (binRpm == NULL) {
	rpmlog(RPMLOG_ERR, _("Could not generate output "
	     "filename for package %s: %s\n"),
	     headerGetString(h, RPMTAG_NAME), errorString);
    } else {
	*filename = rpmGetPath("%{_rpmdir}/", binRpm, NULL);
	rc = ensureDir(binRpm);
    }
    free(binFormat);
    free(binRpm);
    return rc;
}

static rpmRC packageBinary(rpmSpec spec, Package pkg, const char *cookie, int cheating, char** filename)
{
    rpmRC rc = RPMRC_OK;

    if (pkg->fileList == NULL)
	return rc;

    if ((rc = processScriptFiles(spec, pkg)))
	return rc;

    if (cookie) {
	headerPutString(pkg->header, RPMTAG_COOKIE, cookie);
    }

    /* Copy changelog from src rpm */
    #pragma omp critical
    headerCopyTags(spec->sourcePackage->header, pkg->header, copyTags);

    headerPutString(pkg->header, RPMTAG_RPMVERSION, VERSION);
    headerPutString(pkg->header, RPMTAG_BUILDHOST, spec->buildHost);
    headerPutUint32(pkg->header, RPMTAG_BUILDTIME, &(spec->buildTime), 1);

    if (spec->sourcePkgId != NULL) {
	headerPutBin(pkg->header, RPMTAG_SOURCEPKGID, spec->sourcePkgId,16);
    }

    if (cheating) {
	(void) rpmlibNeedsFeature(pkg, "ShortCircuited", "4.9.0-1");
    }

    if ((rc = getPkgFilename(pkg->header, filename)))
	return rc;

    rc = writeRPM(pkg, NULL, *filename, NULL, spec->buildTime, spec->buildHost);
    if (rc == RPMRC_OK) {
	/* Do check each written package if enabled */
	char *pkgcheck = rpmExpand("%{?_build_pkgcheck} ", *filename, NULL);
	if (pkgcheck[0] != ' ') {
	    rc = checkPackages(pkgcheck);
	}
	free(pkgcheck);
    }
    return rc;
}

static int compareBinaries(const void *p1, const void *p2) {
    Package pkg1 = *(Package *)p1;
    Package pkg2 = *(Package *)p2;
    uint64_t size1 = headerGetNumber(pkg1->header, RPMTAG_LONGSIZE);
    uint64_t size2 = headerGetNumber(pkg2->header, RPMTAG_LONGSIZE);
    if (size1 > size2)
        return -1;
    if (size1 < size2)
        return 1;
    return 0;
}

/*
 * Run binary creation in parallel, with task priority based on package size
 * (largest first) to help achieve an optimal load distribution.
 */
rpmRC packageBinaries(rpmSpec spec, const char *cookie, int cheating)
{
    rpmRC rc = RPMRC_OK;
    Package pkg;
    Package *tasks;
    int npkgs = 0;

    for (pkg = spec->packages; pkg != NULL; pkg = pkg->next)
        npkgs++;
    tasks = (Package *)xcalloc(npkgs, sizeof(Package));

    pkg = spec->packages;
    for (int i = 0; i < npkgs; i++) {
        tasks[i] = pkg;
        pkg = pkg->next;
    }
    qsort(tasks, npkgs, sizeof(Package), compareBinaries);

    #pragma omp parallel
    #pragma omp single
    for (int i = 0; i < npkgs; i++) {
	Package pkg = tasks[i];
	#pragma omp task untied priority(i)
	{
	pkg->rc = packageBinary(spec, pkg, cookie, cheating, &pkg->filename);
	rpmlog(RPMLOG_DEBUG,
		_("Finished binary package job, result %d, filename %s\n"),
		pkg->rc, pkg->filename);
	if (pkg->rc) {
	    #pragma omp critical
	    rc = pkg->rc;
	}
	} /* omp task */
	if (rc)
	    break;
    }

    /* Now check the package set if enabled */
    if (rc == RPMRC_OK)
	rc = checkPackageSet(spec->packages);

    free(tasks);

    return rc;
}

rpmRC packageSources(rpmSpec spec, char **cookie)
{
    Package sourcePkg = spec->sourcePackage;
    rpmRC rc;

    /* Add some cruft */
    headerPutString(sourcePkg->header, RPMTAG_RPMVERSION, VERSION);
    headerPutString(sourcePkg->header, RPMTAG_BUILDHOST, spec->buildHost);
    headerPutUint32(sourcePkg->header, RPMTAG_BUILDTIME, &(spec->buildTime), 1);

    /* Include spec in parsed and expanded form */
    headerPutString(sourcePkg->header, RPMTAG_SPEC,
		    rpmSpecGetSection(spec, RPMBUILD_NONE));

    if (rpmSpecGetSection(spec, RPMBUILD_BUILDREQUIRES)) {
	(void) rpmlibNeedsFeature(sourcePkg, "DynamicBuildRequires", "4.15.0-1");
    }

    /* XXX this should be %_srpmdir */
    {	sourcePkg->filename = rpmGetPath("%{_srcrpmdir}/", spec->sourceRpmName,NULL);
	char *pkgcheck = rpmExpand("%{?_build_pkgcheck_srpm} ", sourcePkg->filename, NULL);

	spec->sourcePkgId = NULL;
	rc = writeRPM(sourcePkg, &spec->sourcePkgId, sourcePkg->filename, cookie, spec->buildTime, spec->buildHost);

	/* Do check SRPM package if enabled */
	if (rc == RPMRC_OK && pkgcheck[0] != ' ') {
	    rc = checkPackages(pkgcheck);
	}

	free(pkgcheck);
    }
    return rc;
}
