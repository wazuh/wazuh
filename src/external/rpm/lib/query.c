/** \ingroup rpmcli
 * \file lib/query.c
 * Display tag values from package metadata.
 */

#include "system.h"

#include <errno.h>
#include <inttypes.h>
#include <ctype.h>

#include <rpm/rpmcli.h>
#include <rpm/header.h>
#include <rpm/rpmdb.h>
#include <rpm/rpmfi.h>
#include <rpm/rpmts.h>
#include <rpm/rpmsq.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmfileutil.h>	/* rpmCleanPath */
#include <rpm/rpmstring.h>

#include "rpmgi.h"
#include "manifest.h"

#include "debug.h"


/**
 */
static void printFileInfo(const char * name,
			  rpm_loff_t size, unsigned short mode,
			  unsigned int mtime,
			  unsigned short rdev, unsigned int nlink,
			  const char * owner, const char * group,
			  const char * linkto, time_t now)
{
    char sizefield[21];
    char ownerfield[8+1], groupfield[8+1];
    char timefield[100];
    time_t when = mtime;  /* important if sizeof(uint32_t) ! sizeof(time_t) */
    struct tm * tm, _tm;
    char * perms = rpmPermsString(mode);
    char *link = NULL;

    rstrlcpy(ownerfield, owner, sizeof(ownerfield));
    rstrlcpy(groupfield, group, sizeof(groupfield));

    /* this is normally right */
    snprintf(sizefield, sizeof(sizefield), "%20" PRIu64, size);

    /* this knows too much about dev_t */

    if (S_ISLNK(mode)) {
	rasprintf(&link, "%s -> %s", name, linkto);
    } else if (S_ISCHR(mode)) {
	perms[0] = 'c';
	snprintf(sizefield, sizeof(sizefield), "%3u, %3u", ((unsigned)(rdev >> 8) & 0xff),
			((unsigned)rdev & 0xff));
    } else if (S_ISBLK(mode)) {
	perms[0] = 'b';
	snprintf(sizefield, sizeof(sizefield), "%3u, %3u", ((unsigned)(rdev >> 8) & 0xff),
			((unsigned)rdev & 0xff));
    }

    /* Convert file mtime to display format */
    tm = localtime_r(&when, &_tm);
    timefield[0] = '\0';
    if (tm != NULL)
    {	const char *fmt;
	if (now > when + 6L * 30L * 24L * 60L * 60L ||	/* Old. */
	    now < when - 60L * 60L)			/* In the future.  */
	{
	/* The file is fairly old or in the future.
	 * POSIX says the cutoff is 6 months old;
	 * approximate this by 6*30 days.
	 * Allow a 1 hour slop factor for what is considered "the future",
	 * to allow for NFS server/client clock disagreement.
	 * Show the year instead of the time of day.
	 */        
	    fmt = "%b %e  %Y";
	} else {
	    fmt = "%b %e %H:%M";
	}
	(void)strftime(timefield, sizeof(timefield) - 1, fmt, tm);
    }

    rpmlog(RPMLOG_NOTICE, "%s %4d %-8s %-8s %10s %s %s\n", perms,
	(int)nlink, ownerfield, groupfield, sizefield, timefield, 
	link ? link : name);
    free(perms);
    free(link);
}

int showQueryPackage(QVA_t qva, rpmts ts, Header h)
{
    rpmfi fi = NULL;
    rpmfiFlags fiflags =  (RPMFI_NOHEADER | RPMFI_FLAGS_QUERY);
    int rc = 0;		/* XXX FIXME: need real return code */
    time_t now = 0;

    if (qva->qva_queryFormat != NULL) {
	const char *errstr;
	char *str = headerFormat(h, qva->qva_queryFormat, &errstr);

	if ( str != NULL ) {
	    rpmlog(RPMLOG_NOTICE, "%s", str);
	    free(str);
	} else {
	    rpmlog(RPMLOG_ERR, _("incorrect format: %s\n"), errstr);
	}
    }

    /* Inclusion flags traditionally imply list mode */
    if (qva->qva_incattr)
	qva->qva_flags |= QUERY_FOR_LIST;

    if (!(qva->qva_flags & QUERY_FOR_LIST))
	goto exit;

    if (!(qva->qva_flags & QUERY_FOR_DUMPFILES))
	fiflags |= RPMFI_NOFILEDIGESTS;

    fi = rpmfiNew(ts, h, RPMTAG_BASENAMES, fiflags);
    if (rpmfiFC(fi) <= 0) {
	rpmlog(RPMLOG_NOTICE, _("(contains no files)\n"));
	goto exit;
    }

    fi = rpmfiInit(fi, 0);
    while (rpmfiNext(fi) >= 0) {
	rpmfileAttrs fflags = rpmfiFFlags(fi);
	rpm_mode_t fmode = rpmfiFMode(fi);
	rpm_rdev_t frdev = rpmfiFRdev(fi);
	rpm_time_t fmtime = rpmfiFMtime(fi);
	rpmfileState fstate = rpmfiFState(fi);
	rpm_loff_t fsize = rpmfiFSize(fi);
	const char *fn = rpmfiFN(fi);
	const char *fuser = rpmfiFUser(fi);
	const char *fgroup = rpmfiFGroup(fi);
	const char *flink = rpmfiFLink(fi);
	char *buf = NULL;

	/* If filtering by inclusion, skip non-matching (eg --configfiles) */
	if (qva->qva_incattr && !(fflags & qva->qva_incattr))
	    continue;

	/* Skip on attributes (eg from --noghost) */
	if (fflags & qva->qva_excattr)
	    continue;

	if (qva->qva_flags & QUERY_FOR_STATE) {
	    switch (fstate) {
	    case RPMFILE_STATE_NORMAL:
		rstrcat(&buf, _("normal        "));
		break;
	    case RPMFILE_STATE_REPLACED:
		rstrcat(&buf, _("replaced      "));
		break;
	    case RPMFILE_STATE_NOTINSTALLED:
		rstrcat(&buf, _("not installed "));
		break;
	    case RPMFILE_STATE_NETSHARED:
		rstrcat(&buf, _("net shared    "));
		break;
	    case RPMFILE_STATE_WRONGCOLOR:
		rstrcat(&buf, _("wrong color   "));
		break;
	    case RPMFILE_STATE_MISSING:
		rstrcat(&buf, _("(no state)    "));
		break;
	    default:
		rasprintf(&buf, _("(unknown %3d) "), fstate);
		break;
	    }
	}

	if (qva->qva_flags & QUERY_FOR_DUMPFILES) {
	    char *add, *fdigest;
	    fdigest = rpmfiFDigestHex(fi, NULL);
	    rasprintf(&add, "%s %" PRIu64 " %d %s 0%o ", 
		      fn, fsize, fmtime, fdigest ? fdigest : "", fmode);
	    rstrcat(&buf, add);
	    free(add);
	    free(fdigest);

	    if (fuser && fgroup) {
		rasprintf(&add, "%s %s", fuser, fgroup);
		rstrcat(&buf, add);
		free(add);
	    } else {
		rpmlog(RPMLOG_ERR,
			_("package has not file owner/group lists\n"));
	    }

	    rasprintf(&add, " %s %s %u %s",
				 fflags & RPMFILE_CONFIG ? "1" : "0",
				 fflags & RPMFILE_DOC ? "1" : "0",
				 frdev,
				 (flink && *flink ? flink : "X"));
	    rpmlog(RPMLOG_NOTICE, "%s%s\n", buf, add);
	    free(add);
	} else
	if (!rpmIsVerbose()) {
	    rpmlog(RPMLOG_NOTICE, "%s%s\n", buf ? buf : "", fn);
	}
	else {
	    uint32_t fnlink = rpmfiFNlink(fi);

	    /* XXX Adjust directory link count and size for display output. */
	    if (S_ISDIR(fmode)) {
		fnlink++;
		fsize = 0;
	    }

	    if (fuser && fgroup) {
		/* On first call, grab snapshot of now */
		if (now == 0)
		    now = time(NULL);
		if (buf) {
		    rpmlog(RPMLOG_NOTICE, "%s", buf);
		}
		printFileInfo(fn, fsize, fmode, fmtime, frdev, fnlink,
					fuser, fgroup, flink, now);
	    } else {
		rpmlog(RPMLOG_ERR,
			_("package has neither file owner or id lists\n"));
	    }
	}
	free(buf);
    }

    rc = 0;

exit:
    rpmfiFree(fi);
    return rc;
}

void rpmDisplayQueryTags(FILE * fp)
{
    static const char * const tagTypeNames[] = {
	"", "char", "int8", "int16", "int32", "int64",
	"string", "blob", "argv", "i18nstring"
    };
    const char *tname, *sname;
    rpmtd names = rpmtdNew();
    (void) rpmTagGetNames(names, 1);

    while ((tname = rpmtdNextString(names))) {
	sname = tname + strlen("RPMTAG_");
	if (rpmIsVerbose()) {
	    rpmTagVal tag = rpmTagGetValue(sname);
	    rpmTagType type = rpmTagGetTagType(tag);
	    fprintf(fp, "%-20s %6d", sname, tag);
	    if (type >= RPM_MIN_TYPE && type <= RPM_MAX_TYPE)
		fprintf(fp, " %s", tagTypeNames[type]);
	} else {
	    fprintf(fp, "%s", sname);
	}
	fprintf(fp, "\n");
    }
    rpmtdFree(names);
}

static int rpmgiShowMatches(QVA_t qva, rpmts ts, rpmgi gi)
{
    int ec = 0;
    Header h;

    while ((h = rpmgiNext(gi)) != NULL) {
	int rc;

	if ((rc = qva->qva_showPackage(qva, ts, h)) != 0)
	    ec = rc;
	headerFree(h);
    }
    return ec + rpmgiNumErrors(gi);
}

static int rpmcliShowMatches(QVA_t qva, rpmts ts, rpmdbMatchIterator mi)
{
    Header h;
    int ec = 0;

    if (mi == NULL)
	return 1;

    while ((h = rpmdbNextIterator(mi)) != NULL) {
	int rc;
	if ((rc = qva->qva_showPackage(qva, ts, h)) != 0)
	    ec = rc;
    }
    return ec;
}

static rpmdbMatchIterator matchesIterator(rpmts ts, rpmDbiTag dbi,
					const void *arg, size_t arglen)
{
    unsigned int matches = 0;
    rpmdbMatchIterator mi = rpmtsInitIterator(ts, dbi, arg, arglen);
    while (rpmdbNextIterator(mi) != NULL)
	matches++;
    mi = rpmdbFreeIterator(mi);
    if (matches)
	mi = rpmtsInitIterator(ts, dbi, arg, arglen);
    return mi;
}

static rpmdbMatchIterator initQueryIterator(QVA_t qva, rpmts ts, const char * arg)
{
    const char * s;
    int i;
    rpmdbMatchIterator mi = NULL;

    if (qva->qva_showPackage == NULL)
	goto exit;

    switch (qva->qva_source) {
    case RPMQV_GROUP:
	mi = rpmtsInitIterator(ts, RPMDBI_GROUP, arg, 0);
	if (mi == NULL) {
	    rpmlog(RPMLOG_NOTICE,
		_("group %s does not contain any packages\n"), arg);
	}
	break;

    case RPMQV_TRIGGEREDBY:
	mi = rpmtsInitIterator(ts, RPMDBI_TRIGGERNAME, arg, 0);
	if (mi == NULL) {
	    rpmlog(RPMLOG_NOTICE, _("no package triggers %s\n"), arg);
	}
	break;

    case RPMQV_PKGID:
    {	unsigned char MD5[16];
	unsigned char * t;

	for (i = 0, s = arg; *s && isxdigit(*s); s++, i++)
	    {};
	if (i != 32) {
	    rpmlog(RPMLOG_ERR, _("malformed %s: %s\n"), "pkgid", arg);
	    goto exit;
	}

	MD5[0] = '\0';
        for (i = 0, t = MD5, s = arg; i < 16; i++, t++, s += 2)
            *t = (rnibble(s[0]) << 4) | rnibble(s[1]);
	
	mi = rpmtsInitIterator(ts, RPMDBI_SIGMD5, MD5, sizeof(MD5));
	if (mi == NULL) {
	    rpmlog(RPMLOG_NOTICE, _("no package matches %s: %s\n"),
			"pkgid", arg);
	}
    }	break;

    case RPMQV_HDRID:
	for (i = 0, s = arg; *s && isxdigit(*s); s++, i++)
	    {};
	if (i != 40) {
	    rpmlog(RPMLOG_ERR, _("malformed %s: %s\n"), "hdrid", arg);
	    goto exit;
	}

	mi = rpmtsInitIterator(ts, RPMDBI_SHA1HEADER, arg, 0);
	if (mi == NULL) {
	    rpmlog(RPMLOG_NOTICE, _("no package matches %s: %s\n"),
			"hdrid", arg);
	}
	break;

    case RPMQV_TID:
    {	char * end = NULL;
	rpm_tid_t iid = strtoul(arg, &end, 0);

	if ((*end) || (end == arg) || (iid == UINT_MAX)) {
	    rpmlog(RPMLOG_ERR, _("malformed %s: %s\n"), "tid", arg);
	    goto exit;
	}
	mi = rpmtsInitIterator(ts, RPMDBI_INSTALLTID, &iid, sizeof(iid));
	if (mi == NULL) {
	    rpmlog(RPMLOG_NOTICE, _("no package matches %s: %s\n"),
			"tid", arg);
	}
    }	break;

    case RPMQV_WHATCONFLICTS:
	mi = rpmtsInitIterator(ts, RPMDBI_CONFLICTNAME, arg, 0);
	if (mi == NULL) {
	    rpmlog(RPMLOG_NOTICE, _("no package conflicts %s\n"), arg);
	}
	break;

    case RPMQV_WHATOBSOLETES:
	mi = rpmtsInitIterator(ts, RPMDBI_OBSOLETENAME, arg, 0);
	if (mi == NULL) {
	    rpmlog(RPMLOG_NOTICE, _("no package obsoletes %s\n"), arg);
	}
	break;

    case RPMQV_WHATREQUIRES:
	mi = rpmtsInitIterator(ts, RPMDBI_REQUIRENAME, arg, 0);
	if (mi == NULL) {
	    rpmlog(RPMLOG_NOTICE, _("no package requires %s\n"), arg);
	}
	break;

    case RPMQV_WHATRECOMMENDS:
	mi = rpmtsInitIterator(ts, RPMDBI_RECOMMENDNAME, arg, 0);
	if (mi == NULL) {
	    rpmlog(RPMLOG_NOTICE, _("no package recommends %s\n"), arg);
	}
	break;

    case RPMQV_WHATSUGGESTS:
	mi = rpmtsInitIterator(ts, RPMDBI_SUGGESTNAME, arg, 0);
	if (mi == NULL) {
	    rpmlog(RPMLOG_NOTICE, _("no package suggests %s\n"), arg);
	}
	break;

    case RPMQV_WHATSUPPLEMENTS:
	mi = rpmtsInitIterator(ts, RPMDBI_SUPPLEMENTNAME, arg, 0);
	if (mi == NULL) {
	    rpmlog(RPMLOG_NOTICE, _("no package supplements %s\n"), arg);
	}
	break;

    case RPMQV_WHATENHANCES:
	mi = rpmtsInitIterator(ts, RPMDBI_ENHANCENAME, arg, 0);
	if (mi == NULL) {
	    rpmlog(RPMLOG_NOTICE, _("no package enhances %s\n"), arg);
	}
	break;

    case RPMQV_WHATPROVIDES:
	if (arg[0] != '/' && arg[0] != '.') {
	    mi = rpmtsInitIterator(ts, RPMDBI_PROVIDENAME, arg, 0);
	    if (mi == NULL) {
		rpmlog(RPMLOG_NOTICE, _("no package provides %s\n"), arg);
	    }
	    break;
	}
	/* fallthrough on absolute and relative paths */
    case RPMQV_PATH:
    case RPMQV_PATH_ALL:
    {   char * fn;

	for (s = arg; *s != '\0'; s++)
	    if (!(*s == '.' || *s == '/'))
		break;

	if (*s == '\0') {
	    fn = realpath(arg, NULL);
	    if (!fn)
		fn = xstrdup(arg);
	} else if (*arg != '/') {
	    char *curDir = rpmGetCwd();
	    fn = (char *) rpmGetPath(curDir, "/", arg, NULL);
	    free(curDir);
	} else
	    fn = xstrdup(arg);
	(void) rpmCleanPath(fn);

	rpmDbiTagVal tag = RPMDBI_INSTFILENAMES;
	if (qva->qva_source == RPMQV_PATH_ALL)
	    tag = RPMDBI_BASENAMES;
	mi = rpmtsInitIterator(ts, tag, fn, 0);
	if (mi == NULL)
	    mi = rpmtsInitIterator(ts, RPMDBI_PROVIDENAME, fn, 0);

	if (mi == NULL) {
	    struct stat sb;
	    char * full_fn = rpmGetPath(rpmtsRootDir(ts), fn, NULL);
	    if (lstat(full_fn, &sb) != 0)
		rpmlog(RPMLOG_ERR, _("file %s: %s\n"), fn, strerror(errno));
	    else
		rpmlog(RPMLOG_NOTICE,
			_("file %s is not owned by any package\n"), fn);
	    free(full_fn);
	}

	free(fn);
    }	break;

    case RPMQV_DBOFFSET:
    {	char * end = NULL;
	unsigned int recOffset = strtoul(arg, &end, 0);

	if ((*end) || (end == arg) || (recOffset == UINT_MAX)) {
	    rpmlog(RPMLOG_ERR, _("invalid package number: %s\n"), arg);
	    goto exit;
	}
	rpmlog(RPMLOG_DEBUG, "package record number: %u\n", recOffset);
	/* RPMDBI_PACKAGES */
	mi = matchesIterator(ts, RPMDBI_PACKAGES, &recOffset, sizeof(recOffset));
	if (mi == NULL) {
	    rpmlog(RPMLOG_ERR, _("record %u could not be read\n"), recOffset);
	}
    }	break;

    case RPMQV_PACKAGE:
    {
	mi = matchesIterator(ts, RPMDBI_LABEL, arg, 0);

	if (mi == NULL && !rpmFileHasSuffix(arg, ".rpm"))
	    rpmlog(RPMLOG_NOTICE, _("package %s is not installed\n"), arg);
	break;
    }
    default:
	break;
    }

exit:
    return mi;
}

/*
 * Initialize db iterator with optional filters.  By default patterns
 * applied to package name, others can be specified with <tagname>=<pattern>
 */
static rpmdbMatchIterator initFilterIterator(rpmts ts, ARGV_const_t argv)
{
    rpmdbMatchIterator mi = rpmtsInitIterator(ts, RPMDBI_PACKAGES, NULL, 0);

    for (ARGV_const_t arg = argv; arg && *arg != NULL; arg++) {
	rpmTagVal tag = RPMTAG_NAME;
	char a[strlen(*arg)+1], *ae;
	const char *pat = a;

	strcpy(a, *arg);

	/* Parse for "tag=pattern" args. */
	if ((ae = strchr(a, '=')) != NULL) {
	    *ae++ = '\0';
	    tag = rpmTagGetValue(a);
	    if (tag == RPMTAG_NOT_FOUND) {
		rpmlog(RPMLOG_ERR, _("unknown tag: \"%s\"\n"), a);
		mi = rpmdbFreeIterator(mi);
		break;
	    }
	    pat = ae;
	}

	rpmdbSetIteratorRE(mi, tag, RPMMIRE_DEFAULT, pat);
    }

    return mi;
}

int rpmcliArgIter(rpmts ts, QVA_t qva, ARGV_const_t argv)
{
    int ec = 0;

    switch (qva->qva_source) {
    case RPMQV_ALL: {
	rpmdbMatchIterator mi = initFilterIterator(ts, argv);
	ec = rpmcliShowMatches(qva, ts, mi);
	rpmdbFreeIterator(mi);
	break;
    }
    case RPMQV_RPM: {
	rpmgi gi = rpmgiNew(ts, giFlags, argv);
	ec = rpmgiShowMatches(qva, ts, gi);
	rpmgiFree(gi);
	break;
    }
    case RPMQV_SPECRPMS:
    case RPMQV_SPECBUILTRPMS:
    case RPMQV_SPECSRPM: {
	char *target = rpmExpand("%{_target}", NULL);
	for (ARGV_const_t arg = argv; arg && *arg; arg++) {
	    ec += ((qva->qva_specQuery != NULL)
		    ? qva->qva_specQuery(ts, qva, *arg) : 1);
	    rpmFreeMacros(NULL);
	    rpmReadConfigFiles(rpmcliRcfile, target);
	}
	free(target);
	break;
    }
    default:
	for (ARGV_const_t arg = argv; arg && *arg; arg++) {
	    int ecLocal;
	    rpmdbMatchIterator mi = initQueryIterator(qva, ts, *arg);
	    ecLocal = rpmcliShowMatches(qva, ts, mi);
	    if (mi == NULL && qva->qva_source == RPMQV_PACKAGE) {
		if (rpmFileHasSuffix(*arg, ".rpm")) {
		    char * const argFirst[2] = { arg[0], NULL };
		    rpmgi gi = rpmgiNew(ts, giFlags, argFirst);
		    ecLocal = rpmgiShowMatches(qva, ts, gi);
		    rpmgiFree(gi);
		}
	    }
	    ec += ecLocal;
	    rpmdbFreeIterator(mi);
	}
	break;
    }

    return ec;
}

int rpmcliQuery(rpmts ts, QVA_t qva, char * const * argv)
{
    rpmVSFlags vsflags, ovsflags;
    int ec = 0;

    if (qva->qva_showPackage == NULL)
	qva->qva_showPackage = showQueryPackage;

    /* If --queryformat unspecified, then set default now. */
    if (!(qva->qva_flags & _QUERY_FOR_BITS) && !(qva->qva_incattr) &&
					    qva->qva_queryFormat == NULL) {
	char * fmt = rpmExpand("%{?_query_all_fmt}\n", NULL);
	if (fmt == NULL || strlen(fmt) <= 1) {
	    free(fmt);
	    fmt = xstrdup("%{nvra}\n");
	}
	qva->qva_queryFormat = fmt;
    }

    vsflags = rpmExpandNumeric("%{?_vsflags_query}");
    vsflags |= rpmcliVSFlags;

    ovsflags = rpmtsSetVSFlags(ts, vsflags);
    ec = rpmcliArgIter(ts, qva, argv);
    rpmtsSetVSFlags(ts, ovsflags);

    if (qva->qva_showPackage == showQueryPackage)
	qva->qva_showPackage = NULL;

    return ec;
}
