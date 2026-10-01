/** \ingroup rpmcli
 * \file lib/verify.c
 * Verify installed payload files from package metadata.
 */

#include "system.h"

#include <errno.h>
#include <fcntl.h>
#ifdef WITH_CAP
#include <sys/capability.h>
#endif
#ifdef WITH_ACL
#include <acl/libacl.h>
#endif

#include <rpm/rpmcli.h>
#include <rpm/header.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmfi.h>
#include <rpm/rpmts.h>
#include <rpm/rpmdb.h>
#include <rpm/rpmfileutil.h>
#include <rpm/rpmstring.h>

#include "misc.h"
#include "rpmchroot.h"
#include "rpmte_internal.h"	/* rpmteProcess() */
#include "rpmug.h"

#include "debug.h"

#define S_ISDEV(m) (S_ISBLK((m)) || S_ISCHR((m)))

rpmVerifyAttrs rpmfilesVerify(rpmfiles fi, int ix, rpmVerifyAttrs omitMask)
{
    rpmfileAttrs fileAttrs = rpmfilesFFlags(fi, ix);
    rpmVerifyAttrs flags = rpmfilesVFlags(fi, ix);
    char * fn = rpmfilesFN(fi, ix);
    struct stat sb, fsb;
    rpmVerifyAttrs vfy = RPMVERIFY_NONE;

    /*
     * Check to see if the file was installed - if not pretend all is OK.
     */
    switch (rpmfilesFState(fi, ix)) {
    case RPMFILE_STATE_NETSHARED:
    case RPMFILE_STATE_NOTINSTALLED:
	goto exit;
	break;
    case RPMFILE_STATE_REPLACED:
	/* For replaced files we can only verify if it exists at all */
	flags = RPMVERIFY_LSTATFAIL;
	break;
    case RPMFILE_STATE_WRONGCOLOR:
	/*
	 * Files with wrong color are supposed to share some attributes
	 * with the actually installed file - verify what we can.
	 */
	flags &= ~(RPMVERIFY_FILEDIGEST | RPMVERIFY_FILESIZE |
		   RPMVERIFY_MTIME | RPMVERIFY_RDEV);
	break;
    case RPMFILE_STATE_NORMAL:
    /* File from a non-installed package, try to verify nevertheless */
    case RPMFILE_STATE_MISSING:
	break;
    }

    if (fn == NULL || lstat(fn, &sb) != 0 || rpmfilesStat(fi, ix, 0, &fsb)) {
	vfy |= RPMVERIFY_LSTATFAIL;
	goto exit;
    }

    /* If we expected a directory but got a symlink to one, follow the link */
    if (S_ISDIR(fsb.st_mode) && S_ISLNK(sb.st_mode)) {
	struct stat dsb;
	/* ...if it actually points to a directory  */
	if (stat(fn, &dsb) == 0 && S_ISDIR(dsb.st_mode)) {
	    /* ...and is by a legit user, to match fsmVerify() behavior */
	    if (sb.st_uid == 0 || sb.st_uid == dsb.st_uid)
		sb = dsb; /* struct assignment */
	}
    }

    /* Links have no mode, other types have no linkto */
    if (S_ISLNK(sb.st_mode))
	flags &= ~(RPMVERIFY_MODE);
    else
	flags &= ~(RPMVERIFY_LINKTO);

    /* Not all attributes of non-regular files can be verified */
    if (!S_ISREG(sb.st_mode))
	flags &= ~(RPMVERIFY_FILEDIGEST | RPMVERIFY_FILESIZE |
		   RPMVERIFY_MTIME | RPMVERIFY_CAPS);

    /* Content checks of %ghost files are meaningless. */
    if (fileAttrs & RPMFILE_GHOST)
	flags &= ~(RPMVERIFY_FILEDIGEST | RPMVERIFY_FILESIZE |
		   RPMVERIFY_MTIME | RPMVERIFY_LINKTO);

    /* Don't verify any features in omitMask. */
    flags &= ~(omitMask | RPMVERIFY_FAILURES);


    if (flags & RPMVERIFY_FILEDIGEST) {
	const unsigned char *digest; 
	int algo;
	size_t diglen;

	if ((digest = rpmfilesFDigest(fi, ix, &algo, &diglen))) {
	    unsigned char fdigest[diglen];

	    if (rpmDoDigest(algo, fn, 0, fdigest)) {
		vfy |= (RPMVERIFY_READFAIL|RPMVERIFY_FILEDIGEST);
	    } else {
		if (memcmp(fdigest, digest, diglen))
		    vfy |= RPMVERIFY_FILEDIGEST;
	    }
	} else {
	    vfy |= RPMVERIFY_FILEDIGEST;
	} 
    } 

    if (flags & RPMVERIFY_LINKTO) {
	char linkto[1024+1];
	int size = 0;

	if ((size = readlink(fn, linkto, sizeof(linkto)-1)) == -1)
	    vfy |= (RPMVERIFY_READLINKFAIL|RPMVERIFY_LINKTO);
	else {
	    const char * flink = rpmfilesFLink(fi, ix);
	    linkto[size] = '\0';
	    if (flink == NULL || !rstreq(linkto, flink))
		vfy |= RPMVERIFY_LINKTO;
	}
    } 

    if ((flags & RPMVERIFY_FILESIZE) && (sb.st_size != fsb.st_size))
	vfy |= RPMVERIFY_FILESIZE;

    if (flags & RPMVERIFY_MODE) {
	mode_t metamode = fsb.st_mode;
	mode_t filemode = sb.st_mode;

	/*
	 * Comparing the type of %ghost files is meaningless, but perms are OK.
	 */
	if (fileAttrs & RPMFILE_GHOST) {
	    metamode &= ~S_IFMT;
	    filemode &= ~S_IFMT;
	}

	if (metamode != filemode)
	    vfy |= RPMVERIFY_MODE;

#ifdef WITH_ACL
	/*
	 * For now, any non-default acl's on a file is a difference as rpm
	 * cannot have set them.
	 */
	acl_t facl = acl_get_file(fn, ACL_TYPE_ACCESS);
	if (facl) {
	    if (acl_equiv_mode(facl, NULL) == 1) {
		vfy |= RPMVERIFY_MODE;
	    }
	    acl_free(facl);
	}
#endif 
    }

    if (flags & RPMVERIFY_RDEV) {
	if (S_ISCHR(fsb.st_mode) != S_ISCHR(sb.st_mode)
	 || S_ISBLK(fsb.st_mode) != S_ISBLK(sb.st_mode))
	{
	    vfy |= RPMVERIFY_RDEV;
	} else if (S_ISDEV(fsb.st_mode) && S_ISDEV(sb.st_mode)) {
	    rpm_rdev_t st_rdev = (sb.st_rdev & 0xffff);
	    rpm_rdev_t frdev = (fsb.st_rdev & 0xffff);
	    if (st_rdev != frdev)
		vfy |= RPMVERIFY_RDEV;
	} 
    }

#ifdef WITH_CAP
    if (flags & RPMVERIFY_CAPS) {
	cap_t cap = NULL;
	cap_t fcap = cap_get_file(fn);
	const char *captext = rpmfilesFCaps(fi, ix);

	/* captext "" means no capability */
	if (captext && captext[0])
	    cap = cap_from_text(captext);

	if ((fcap || cap) && (cap_compare(cap, fcap) != 0))
	    vfy |= RPMVERIFY_CAPS;

	cap_free(fcap);
	cap_free(cap);
    }
#endif

    if ((flags & RPMVERIFY_MTIME) && (sb.st_mtime != fsb.st_mtime))
	vfy |= RPMVERIFY_MTIME;

    if ((flags & RPMVERIFY_USER) && (sb.st_uid != fsb.st_uid))
	vfy |= RPMVERIFY_USER;

    if ((flags & RPMVERIFY_GROUP) && (sb.st_gid != fsb.st_gid))
	vfy |= RPMVERIFY_GROUP;

exit:
    free(fn);
    return vfy;
}

/**
 * Return exit code from running verify script from header.
 * @param ts		transaction set
 * @param h		header
 * @return              0 on success
 */
static int rpmVerifyScript(rpmts ts, Header h)
{
    int rc = 0;

    if (headerIsEntry(h, RPMTAG_VERIFYSCRIPT)) {
	/* fake up a transaction element */
	rpmte p = rpmteNew(ts, h, TR_RPMDB, NULL, NULL, 0);

	if (p != NULL) {
	    rpmteSetHeader(p, h);

	    rc = (rpmpsmRun(ts, p, PKG_VERIFY) != RPMRC_OK);

	    /* clean up our fake transaction bits */
	    rpmteFree(p);
	} else {
	    rc = RPMRC_FAIL;
	}
    }

    return rc;
}

#define unknown "?"
#define	_verify(_RPMVERIFY_F, _C, _pad)	\
	((verifyResult & _RPMVERIFY_F) ? _C : _pad)
#define	_verifylink(_RPMVERIFY_F, _C, _pad)	\
	((verifyResult & RPMVERIFY_READLINKFAIL) ? unknown : \
	 (verifyResult & _RPMVERIFY_F) ? _C : _pad)
#define	_verifyfile(_RPMVERIFY_F, _C, _pad)	\
	((verifyResult & RPMVERIFY_READFAIL) ? unknown : \
	 (verifyResult & _RPMVERIFY_F) ? _C : _pad)
char * rpmVerifyString(uint32_t verifyResult, const char *pad)
{
    char *fmt = NULL;
    rasprintf(&fmt, "%s%s%s%s%s%s%s%s%s",
		_verify(RPMVERIFY_FILESIZE, "S", pad),
		_verify(RPMVERIFY_MODE, "M", pad),
		_verifyfile(RPMVERIFY_FILEDIGEST, "5", pad),
		_verify(RPMVERIFY_RDEV, "D", pad),
		_verifylink(RPMVERIFY_LINKTO, "L", pad),
		_verify(RPMVERIFY_USER, "U", pad),
		_verify(RPMVERIFY_GROUP, "G", pad),
		_verify(RPMVERIFY_MTIME, "T", pad),
		_verify(RPMVERIFY_CAPS, "P", pad));
		
    return fmt;
}
#undef _verifyfile
#undef _verifylink
#undef _verify
#undef aok
#undef unknown

char * rpmFFlagsString(uint32_t fflags)
{
    char *fmt, *p;
    fmt = p = (char *)xmalloc(10);
    if ((fflags & RPMFILE_DOC))
        *p++ = 'd';
    if ((fflags & RPMFILE_CONFIG))
        *p++ = 'c';
    if ((fflags & RPMFILE_SPECFILE))
        *p++ = 's';
    if ((fflags & RPMFILE_MISSINGOK))
        *p++ = 'm';
    if ((fflags & RPMFILE_NOREPLACE))
        *p++ = 'n';
    if ((fflags & RPMFILE_GHOST))
        *p++ = 'g';
    if ((fflags & RPMFILE_LICENSE))
        *p++ = 'l';
    if ((fflags & RPMFILE_README))
        *p++ = 'r';
    if ((fflags & RPMFILE_ARTIFACT))
        *p++ = 'a';
    *p++= '\0';
    return fmt;
}

static const char * stateStr(rpmfileState fstate)
{
    switch (fstate) {
    case RPMFILE_STATE_NORMAL:
	return NULL;
    case RPMFILE_STATE_NOTINSTALLED:
	return rpmIsVerbose() ? _("not installed") : NULL;
    case RPMFILE_STATE_NETSHARED:
	return rpmIsVerbose() ? _("net shared") : NULL;
    case RPMFILE_STATE_WRONGCOLOR:
	return rpmIsVerbose() ? _("wrong color") : NULL;
    case RPMFILE_STATE_REPLACED:
	return _("replaced");
    case RPMFILE_STATE_MISSING:
	return _("no state");
    }
    return _("unknown state");
}

/**
 * Check file info from header against what's actually installed.
 * @param ts		transaction set
 * @param h		header to verify
 * @param omitMask	bits to disable verify checks
 * @param incAttr	skip files without these attrs (eg %ghost)
 * @param skipAttr	skip files with these attrs (eg %ghost)
 * @return		0 no problems, 1 problems found
 */
static int verifyHeader(rpmts ts, Header h, rpmVerifyAttrs omitMask,
			rpmfileAttrs incAttrs, rpmfileAttrs skipAttrs)
{
    rpmVerifyAttrs verifyResult = 0;
    rpmVerifyAttrs verifyAll = 0; /* assume no problems */
    rpmfi fi = rpmfiNew(ts, h, RPMTAG_BASENAMES, RPMFI_FLAGS_VERIFY);

    if (fi == NULL)
	return 1;

    rpmfiInit(fi, 0);
    while (rpmfiNext(fi) >= 0) {
	rpmfileAttrs fileAttrs = rpmfiFFlags(fi);
	char *buf = NULL, *attrFormat;
	const char *fstate = NULL;
	char ac;

	/* If filtering by inclusion, skip non-matching (eg --configfiles) */
	if (incAttrs && !(incAttrs & fileAttrs))
	    continue;

	/* Skip on attributes (eg from --noghost) */
	if (skipAttrs & fileAttrs)
	    continue;

	verifyResult = rpmfiVerify(fi, omitMask);

	/* Filter out timestamp differences of shared files */
	if (verifyResult & RPMVERIFY_MTIME) {
	    rpmdbMatchIterator mi;
	    mi = rpmtsInitIterator(ts, RPMDBI_BASENAMES, rpmfiFN(fi), 0);
	    if (rpmdbGetIteratorCount(mi) > 1) 
		verifyResult &= ~RPMVERIFY_MTIME;
	    rpmdbFreeIterator(mi);
	}

	/* State is only meaningful for installed packages */
	if (headerGetInstance(h))
	    fstate = stateStr(rpmfiFState(fi));

	attrFormat = rpmFFlagsString(fileAttrs);
	ac = rstreq(attrFormat, "") ? ' ' : attrFormat[0];
	if (verifyResult & RPMVERIFY_LSTATFAIL) {
	    if (!(fileAttrs & (RPMFILE_MISSINGOK|RPMFILE_GHOST)) || rpmIsVerbose()) {
		rasprintf(&buf, _("missing   %c %s"), ac, rpmfiFN(fi));
		if ((verifyResult & RPMVERIFY_LSTATFAIL) != 0 &&
		    errno != ENOENT) {
		    char *app;
		    rasprintf(&app, " (%s)", strerror(errno));
		    rstrcat(&buf, app);
		    free(app);
		}
	    }
	} else if (verifyResult || fstate || rpmIsVerbose()) {
	    char *verifyFormat = rpmVerifyString(verifyResult, ".");
	    rasprintf(&buf, "%s  %c %s", verifyFormat, ac, rpmfiFN(fi));
	    free(verifyFormat);
	}
	free(attrFormat);

	if (buf) {
	    if (fstate)
		buf = rstrscat(&buf, " (", fstate, ")", NULL);
	    rpmlog(RPMLOG_NOTICE, "%s\n", buf);
	    buf = _free(buf);
	}

	/* Filter out missing %ghost/%missingok errors from final result */
	if (fileAttrs & (RPMFILE_MISSINGOK|RPMFILE_GHOST))
	    verifyResult &= ~RPMVERIFY_LSTATFAIL;

	verifyAll |= verifyResult;
    }
    rpmfiFree(fi);
	
    return (verifyAll != 0) ? 1 : 0;
}

/**
 * Check installed package dependencies for problems.
 * @param ts		transaction set
 * @param h		header
 * @return		number of problems found (0 for no problems)
 */
static int verifyDependencies(rpmts ts, Header h)
{
    rpmps ps;
    rpmte te;
    int rc;

    rpmtsEmpty(ts);
    (void) rpmtsAddInstallElement(ts, h, NULL, 0, NULL);

    (void) rpmtsCheck(ts);
    te = rpmtsElement(ts, 0);
    ps = rpmteProblems(te);
    rc = rpmpsNumProblems(ps);

    if (rc > 0) {
	rpmlog(RPMLOG_NOTICE, _("Unsatisfied dependencies for %s:\n"),
	       rpmteNEVRA(te));
	rpmpsi psi = rpmpsInitIterator(ps);
	rpmProblem p;

	while ((p = rpmpsiNext(psi)) != NULL) {
	    char * ps = rpmProblemString(p);
	    rpmlog(RPMLOG_NOTICE, "\t%s\n", ps);
	    free(ps);
	}
	rpmpsFreeIterator(psi);
    }
    rpmpsFree(ps);
    rpmtsEmpty(ts);

    return rc;
}

int showVerifyPackage(QVA_t qva, rpmts ts, Header h)
{
    int ec = 0;
    int rc;

    if (qva->qva_flags & VERIFY_DEPS) {
	if ((rc = verifyDependencies(ts, h)) != 0)
	    ec = rc;
    }
    if (qva->qva_flags & VERIFY_FILES) {
	if ((rc = verifyHeader(ts, h, qva->qva_ofvattr,
				qva->qva_incattr, qva->qva_excattr)) != 0)
	    ec = rc;
    }
    if (qva->qva_flags & VERIFY_SCRIPT) {
	if ((rc = rpmVerifyScript(ts, h)) != 0)
	    ec = rc;
    }

    return ec;
}

int rpmcliVerify(rpmts ts, QVA_t qva, char * const * argv)
{
    rpmVSFlags vsflags, ovsflags;
    int ec = 0;
    FD_t scriptFd = fdDup(STDOUT_FILENO);

    /* 
     * Open the DB + indices explicitly before possible chroot for
     * consistency with how transactions operate.
     */
    rpmtsOpenDB(ts, O_RDONLY);
    rpmdbOpenAll(rpmtsGetRdb(ts));
    if (rpmChrootSet(rpmtsRootDir(ts)) || rpmChrootIn()) {
	ec = 1;
	goto exit;
    }

    if (qva->qva_showPackage == NULL)
        qva->qva_showPackage = showVerifyPackage;

    vsflags = rpmExpandNumeric("%{?_vsflags_verify}");
    vsflags |= rpmcliVSFlags;
    vsflags &= ~RPMVSF_NEEDPAYLOAD;

    rpmtsSetScriptFd(ts, scriptFd);
    ovsflags = rpmtsSetVSFlags(ts, vsflags);
    ec = rpmcliArgIter(ts, qva, argv);
    rpmtsSetVSFlags(ts, ovsflags);
    rpmtsSetScriptFd(ts, NULL);

    if (qva->qva_showPackage == showVerifyPackage)
        qva->qva_showPackage = NULL;

    rpmtsEmpty(ts);

    if (rpmChrootOut() || rpmChrootSet(NULL))
	ec = 1;

exit:
    Fclose(scriptFd);

    return ec;
}
