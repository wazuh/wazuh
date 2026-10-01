/** \ingroup rpmbuild
 * \file build/build.c
 *  Top-level build dispatcher.
 */

#include "system.h"

#include <errno.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <time.h>
#ifdef ENABLE_OPENMP
#include <omp.h>
#endif

#include <rpm/rpmlog.h>
#include <rpm/rpmfileutil.h>
#include "rpmbuild_internal.h"
#include "rpmbuild_misc.h"

#include "debug.h"

static rpm_time_t getBuildTime(void)
{
    rpm_time_t buildTime = 0;
    char *btMacro;
    char *srcdate;
    time_t epoch;
    char *endptr;
    char *timestr = NULL;

    btMacro = rpmExpand("%{?_buildtime}", NULL);
    if (*btMacro) {
        errno = 0;
        epoch = strtol(btMacro, &endptr, 10);
        if (btMacro == endptr || *endptr || errno != 0)
            rpmlog(RPMLOG_ERR, _("unable to parse _buildtime macro\n"));
	else
            buildTime = (uint32_t) epoch;
    } else if ((srcdate = getenv("SOURCE_DATE_EPOCH")) != NULL &&
	    rpmExpandNumeric("%{?use_source_date_epoch_as_buildtime}")) {
        errno = 0;
        epoch = strtol(srcdate, &endptr, 10);
        if (srcdate == endptr || *endptr || errno != 0)
            rpmlog(RPMLOG_ERR, _("unable to parse SOURCE_DATE_EPOCH\n"));
        else
            buildTime = (uint32_t) epoch;
    } else
        buildTime = (uint32_t) time(NULL);
    free(btMacro);

    rasprintf(&timestr, "%u", buildTime);
    setenv("RPM_BUILD_TIME", timestr, 1);
    free(timestr);

    return buildTime;
}

static char * buildHost(void)
{
    char* hostname;
    char *bhMacro;

    bhMacro = rpmExpand("%{?_buildhost}", NULL);
    if (strcmp(bhMacro, "") != 0) {
        rasprintf(&hostname, "%s", bhMacro);
    } else {
	hostname = (char *)rcalloc(NI_MAXHOST + 1, sizeof(*hostname));
	if (gethostname(hostname, NI_MAXHOST) == 0) {
	    struct addrinfo *ai, hints;
	    memset(&hints, 0, sizeof(hints));
	    hints.ai_flags = AI_CANONNAME;

	    if (getaddrinfo(hostname, NULL, &hints, &ai) == 0) {
		strcpy(hostname, ai->ai_canonname);
		freeaddrinfo(ai);
	    } else {
		rpmlog(RPMLOG_WARNING,
                    _("Could not canonicalize hostname: %s\n"), hostname);
	    }
	}
    }
    free(bhMacro);
    return(hostname);
}

/**
 */
static int doRmSource(rpmSpec spec)
{
    struct Source *p;
    Package pkg;
    int rc = 0;
    
    for (p = spec->sources; p != NULL; p = p->next) {
	if (! (p->flags & RPMBUILD_ISNO)) {
	    rc = unlink(p->path);
	    if (rc) goto exit;
	}
    }

    for (pkg = spec->packages; pkg != NULL; pkg = pkg->next) {
	for (p = pkg->icon; p != NULL; p = p->next) {
	    if (! (p->flags & RPMBUILD_ISNO)) {
		rc = unlink(p->path);
	        if (rc) goto exit;
	    }
	}
    }
exit:
    return rc;
}

/*
 * @todo Single use by %%doc in files.c prevents static.
 */
rpmRC doScript(rpmSpec spec, rpmBuildFlags what, const char *name,
	       const char *sb, int test, StringBuf * sb_stdoutp)
{
    char *scriptName = NULL;
    char * buildDir = rpmGenPath(spec->rootDir, "%{builddir}", "");
    char * buildSubdir = rpmGetPath("%{?buildsubdir}", NULL);
    char * buildCmd = NULL;
    char * buildTemplate = NULL;
    char * buildPost = NULL;
    const char * mTemplate = NULL;
    const char * mCmd = NULL;
    const char * mPost = NULL;
    int argc = 0;
    const char **argv = NULL;
    FILE * fp = NULL;

    FD_t fd = NULL;
    rpmRC rc = RPMRC_FAIL; /* assume failure */
    
    switch (what) {
    case RPMBUILD_MKBUILDDIR:
	mTemplate = "%{__spec_builddir_template}";
	mPost = "%{__spec_builddir_post}";
	mCmd = "%{__spec_builddir_cmd}";
	break;
    case RPMBUILD_PREP:
	mTemplate = "%{__spec_prep_template}";
	mPost = "%{__spec_prep_post}";
	mCmd = "%{__spec_prep_cmd}";
	break;
    case RPMBUILD_BUILDREQUIRES:
	mTemplate = "%{__spec_buildrequires_template}";
	mPost = "%{__spec_buildrequires_post}";
	mCmd = "%{__spec_buildrequires_cmd}";
	break;
    case RPMBUILD_CONF:
	mTemplate = "%{__spec_conf_template}";
	mPost = "%{__spec_conf_post}";
	mCmd = "%{__spec_conf_cmd}";
	break;
    case RPMBUILD_BUILD:
	mTemplate = "%{__spec_build_template}";
	mPost = "%{__spec_build_post}";
	mCmd = "%{__spec_build_cmd}";
	break;
    case RPMBUILD_INSTALL:
	mTemplate = "%{__spec_install_template}";
	mPost = "%{__spec_install_post}";
	mCmd = "%{__spec_install_cmd}";
	break;
    case RPMBUILD_CHECK:
	mTemplate = "%{__spec_check_template}";
	mPost = "%{__spec_check_post}";
	mCmd = "%{__spec_check_cmd}";
	break;
    case RPMBUILD_CLEAN:
	mTemplate = "%{__spec_clean_template}";
	mPost = "%{__spec_clean_post}";
	mCmd = "%{__spec_clean_cmd}";
	break;
    case RPMBUILD_RMBUILD:
	mTemplate = "%{__spec_clean_template}";
	mPost = "%{__spec_clean_post}";
	mCmd = "%{__spec_clean_cmd}";
	break;
    case RPMBUILD_STRINGBUF:
    default:
	mTemplate = "%{___build_template}";
	mPost = "%{___build_post}";
	mCmd = "%{___build_cmd}";
	break;
    }

    if ((what != RPMBUILD_RMBUILD) && sb == NULL) {
	rc = RPMRC_OK;
	goto exit;
    }
    
    fd = rpmMkTempFile(spec->rootDir, &scriptName);
    if (Ferror(fd)) {
	rpmlog(RPMLOG_ERR, _("Unable to open temp file: %s\n"), Fstrerror(fd));
	goto exit;
    }

    if ((fp = fdopen(Fileno(fd), "w")) == NULL) {
	rpmlog(RPMLOG_ERR, _("Unable to open stream: %s\n"), strerror(errno));
	goto exit;
    }
    
    buildTemplate = rpmExpand(mTemplate, NULL);
    buildPost = rpmExpand(mPost, NULL);

    (void) fputs(buildTemplate, fp);

    if (what != RPMBUILD_MKBUILDDIR && what != RPMBUILD_PREP && what != RPMBUILD_RMBUILD && buildSubdir[0] != '\0')
	fprintf(fp, "cd '%s'\n", buildSubdir);

    if (what == RPMBUILD_RMBUILD) {
	char *fix = rpmExpand("%{_fixperms}", NULL);
	fprintf(fp, "test -d '%s' && %s '%s'\n",
			spec->buildDir, fix, spec->buildDir);
	fprintf(fp, "rm -rf '%s'\n", spec->buildDir);
	free(fix);
    } else if (sb != NULL)
	fprintf(fp, "%s", sb);

    (void) fputs(buildPost, fp);
    (void) fclose(fp);

    if (test) {
	rc = RPMRC_OK;
	goto exit;
    }
    
    if (buildDir && buildDir[0] != '/') {
	goto exit;
    }

    buildCmd = rpmExpand(mCmd, " ", scriptName, NULL);
    (void) poptParseArgvString(buildCmd, &argc, &argv);

    if (sb_stdoutp && *sb_stdoutp)
	*sb_stdoutp = freeStringBuf(*sb_stdoutp);

    rpmlog(RPMLOG_NOTICE, _("Executing(%s): %s\n"), name, buildCmd);
    if (rpmfcExec((ARGV_const_t)argv, NULL, sb_stdoutp, 1, buildSubdir)) {
	rpmlog(RPMLOG_ERR, _("Bad exit status from %s (%s)\n"),
		scriptName, name);
	goto exit;
    }
    rc = RPMRC_OK;
    
exit:
    Fclose(fd);
    if (scriptName) {
	if (rc == RPMRC_OK && !rpmIsDebug())
	    (void) unlink(scriptName);
	free(scriptName);
    }
    free(argv);
    free(buildCmd);
    free(buildTemplate);
    free(buildPost);
    free(buildSubdir);
    free(buildDir);

    return rc;
}

static int doBuildRequires(rpmSpec spec, int test)
{
    StringBuf sb_stdout = NULL;
    const char *buildrequires = rpmSpecGetSection(spec, RPMBUILD_BUILDREQUIRES);
    int outc;
    ARGV_t output = NULL;

    int rc = 1; /* assume failure */

    if (!buildrequires) {
	rc = RPMRC_OK;
	goto exit;
    }

    if ((rc = doScript(spec, RPMBUILD_BUILDREQUIRES, "%generate_buildrequires",
		       buildrequires, test, &sb_stdout)))
	goto exit;

    /* add results to requires of the srpm */
    argvSplit(&output, getStringBuf(sb_stdout), "\n\r");
    outc = argvCount(output);

    for (int i = 0; i < outc; i++) {
	if (parseRCPOT(spec, spec->sourcePackage, output[i], RPMTAG_REQUIRENAME,
		       0, RPMSENSE_FIND_REQUIRES, addReqProvPkg, NULL))
	    goto exit;
    }

    rpmdsPutToHeader(
	*packageDependencies(spec->sourcePackage, RPMTAG_REQUIRENAME),
	spec->sourcePackage->header);

    rc = RPMRC_MISSINGBUILDREQUIRES;

 exit:
    freeStringBuf(sb_stdout);
    argvFree(output);
    return rc;
}

static int doCheckBuildRequires(rpmts ts, rpmSpec spec, int test)
{
    int rc = RPMRC_OK;
    rpmps ps = rpmSpecCheckDeps(ts, spec);

    if (ps) {
	rpmlog(RPMLOG_ERR, _("Failed build dependencies:\n"));
	rpmpsPrint(NULL, ps);
	rc = RPMRC_MISSINGBUILDREQUIRES;
    }

    rpmpsFree(ps);
    return rc;
}

static rpmRC doBuildDir(rpmSpec spec, int test, int inPlace, StringBuf *sbp)
{
    char *doDir = rpmExpand("test -d '", spec->buildDir, "' && ",
			   "%{_fixperms} '", spec->buildDir, "'\n",
			   "%{__rm} -rf '", spec->buildDir, "'\n",
			   "%{__mkdir_p} '", spec->buildDir, "'\n",
			   "%{__mkdir_p} '%{specpartsdir}'\n",
			   NULL);

    if (inPlace) {
	/* note that pwd needs to be from parse, not build time */
	char *buf = rpmExpand("%{__ln} -s %(pwd) %{builddir}/%{buildsubdir}", NULL);
	doDir = rstrcat(&doDir, buf);
	free(buf);
    }

    rpmRC rc = doScript(spec, RPMBUILD_MKBUILDDIR, "%mkbuilddir",
			doDir, test, sbp);
    if (rc) {
	rpmlog(RPMLOG_ERR,
		_("failed to create package build directory %s: %s\n"),
		spec->buildDir, strerror(errno));
    }
    free(doDir);
    return rc;
}

static int buildSpec(rpmts ts, BTA_t buildArgs, rpmSpec spec, int what)
{
    int rc = RPMRC_OK;
    int missing_buildreqs = 0;
    int test = (what & RPMBUILD_NOBUILD);
    char *cookie = buildArgs->cookie ? xstrdup(buildArgs->cookie) : NULL;
    /* handle quiet mode by capturing the output into a sink buffer */
    StringBuf sink = NULL;
    StringBuf *sbp = rpmIsVerbose() ? NULL : &sink;

#ifdef ENABLE_OPENMP
    /* Set number of OMP threads centrally */
    int prev_threads = omp_get_num_threads();
    int nthreads = rpmExpandNumeric("%{?_smp_build_nthreads}");
    int nthreads_max = rpmExpandNumeric("%{?_smp_nthreads_max}");
    if (nthreads <= 0)
        nthreads = omp_get_max_threads();
    if (nthreads_max > 0 && nthreads > nthreads_max)
	nthreads = nthreads_max;
    if (nthreads > 0)
	omp_set_num_threads(nthreads);
#endif

    if (rpmExpandNumeric("%{?source_date_epoch_from_changelog}") &&
	getenv("SOURCE_DATE_EPOCH") == NULL) {
	/* Use date of first (== latest) changelog entry */
	Header h = spec->packages->header;
	struct rpmtd_s td;
	if (headerGet(h, RPMTAG_CHANGELOGTIME, &td, (HEADERGET_MINMEM|HEADERGET_RAW))) {
	    char sdestr[22];
	    long long sdeint = rpmtdGetNumber(&td);
	    if (sdeint % 86400 == 43200) /* date was rounded to 12:00 */
		/* make sure it is in the past, so that clamping times works */
		sdeint -= 43200;
	    snprintf(sdestr, sizeof(sdestr), "%lli", sdeint);
	    rpmlog(RPMLOG_NOTICE, _("setting %s=%s\n"), "SOURCE_DATE_EPOCH", sdestr);
	    setenv("SOURCE_DATE_EPOCH", sdestr, 0);
	    rpmtdFreeData(&td);
	} else {
	    rpmlog(RPMLOG_WARNING, _("%%source_date_epoch_from_changelog is set, but "
	        "%%changelog has no entries to take a date from\n"));
	}
    }

    spec->buildTime = getBuildTime();
    spec->buildHost = buildHost();

    /* Don't generate debug packages on noarch no matter what --target says */
    const char *arch = headerGetString(spec->packages->header, RPMTAG_ARCH);
    if (rstreq(arch, "noarch"))
	rpmPushMacro(spec->macros, "_enable_debug_packages", NULL, "0", RMIL_SPEC);

    /* XXX TODO: rootDir is only relevant during build, eliminate from spec */
    spec->rootDir = buildArgs->rootdir;
    if (!spec->recursing && spec->BACount) {
	int x;
	/* When iterating over BANames, do the source    */
	/* packaging on the first run, and skip RMSOURCE altogether */
	if (spec->BASpecs != NULL)
	for (x = 0; x < spec->BACount; x++) {
	    if ((rc = buildSpec(ts, buildArgs, spec->BASpecs[x],
				(what & ~RPMBUILD_RMSOURCE) |
				(x ? 0 : (what & RPMBUILD_PACKAGESOURCE))))) {
		goto exit;
	    }
	}
    } else {
	int didBuild = (what & (RPMBUILD_PREP|RPMBUILD_CONF|RPMBUILD_BUILD|RPMBUILD_INSTALL));
	int sourceOnly = ((what & RPMBUILD_PACKAGESOURCE) &&
	   !(what & (RPMBUILD_CONF|RPMBUILD_BUILD|RPMBUILD_INSTALL|RPMBUILD_PACKAGEBINARY)));
	int inPlace = (rpmExpandNumeric("%{?_build_in_place}") > 0);

	if (!rpmSpecGetSection(spec, RPMBUILD_BUILDREQUIRES) && sourceOnly) {
		/* don't run prep if not needed for source build */
		/* with(out) dynamic build requires*/
	    what &= ~(RPMBUILD_PREP|RPMBUILD_MKBUILDDIR);
	}

	if (inPlace) {
	    /* in-place builds counter-intuitively always have buildsubdir */
	    rpmPushMacro(spec->macros,
			"buildsubdir", NULL, "%{NAME}-%{VERSION}", RMIL_SPEC);
	    if (didBuild)
		what |= RPMBUILD_MKBUILDDIR;
	    what &= ~(RPMBUILD_PREP|RPMBUILD_RMBUILD);
	}

	if ((what & RPMBUILD_CHECKBUILDREQUIRES) &&
	    (rc = doCheckBuildRequires(ts, spec, test)))
		goto exit;

	if ((what & RPMBUILD_MKBUILDDIR) && (rc = doBuildDir(spec, test, inPlace, sbp)))
		goto exit;

	if ((what & RPMBUILD_PREP) &&
	    (rc = doScript(spec, RPMBUILD_PREP, "%prep",
			   rpmSpecGetSection(spec, RPMBUILD_PREP),
			   test, sbp)))
		goto exit;

	if (what & RPMBUILD_BUILDREQUIRES)
            rc = doBuildRequires(spec, test);
	if ((what & RPMBUILD_CHECKBUILDREQUIRES) &&
	        (rc == RPMRC_MISSINGBUILDREQUIRES))
	    rc = doCheckBuildRequires(ts, spec, test);
	if (rc == RPMRC_MISSINGBUILDREQUIRES) {
	    if ((what & RPMBUILD_DUMPBUILDREQUIRES) &&
		!(spec->flags & RPMSPEC_FORCE)) {
		/* Create buildreqs package */
		char *nvr = headerGetAsString(spec->packages->header, RPMTAG_NVR);
		free(spec->sourceRpmName);
		rasprintf(&spec->sourceRpmName, "%s.buildreqs.nosrc.rpm", nvr);
		free(nvr);
		/* free sources to not include them in the buildreqs package */
		spec->sources = freeSources(spec->sources);
		spec->numSources = 0;
		missing_buildreqs = 1;
		what = RPMBUILD_PACKAGESOURCE;
	    } else {
		rc = RPMRC_OK;
	    }
	} else if (rc) {
	    goto exit;
	}

	if ((what & RPMBUILD_CONF) &&
	    (rc = doScript(spec, RPMBUILD_BUILD, "%conf",
			   rpmSpecGetSection(spec, RPMBUILD_CONF),
			   test, sbp)))
		goto exit;

	if ((what & RPMBUILD_BUILD) &&
	    (rc = doScript(spec, RPMBUILD_BUILD, "%build",
			   rpmSpecGetSection(spec, RPMBUILD_BUILD),
			   test, sbp)))
		goto exit;

	if ((what & RPMBUILD_INSTALL) &&
	    (rc = doScript(spec, RPMBUILD_INSTALL, "%install",
			   rpmSpecGetSection(spec, RPMBUILD_INSTALL),
			   test, sbp)))
		goto exit;

	if (((what & RPMBUILD_INSTALL) || (what & RPMBUILD_PACKAGEBINARY) ||
	     (what & RPMBUILD_FILECHECK)) &&
	    (rc = parseGeneratedSpecs(spec)))
		goto exit;

	if ((what & RPMBUILD_CHECK) &&
	    (rc = doScript(spec, RPMBUILD_CHECK, "%check",
			   rpmSpecGetSection(spec, RPMBUILD_CHECK),
			   test, sbp)))
		goto exit;

	if ((what & RPMBUILD_PACKAGESOURCE) &&
	    (rc = processSourceFiles(spec, buildArgs->pkgFlags)))
		goto exit;

	if (((what & RPMBUILD_INSTALL) || (what & RPMBUILD_PACKAGEBINARY) ||
	    (what & RPMBUILD_FILECHECK)) &&
	    (rc = processBinaryFiles(spec, buildArgs->pkgFlags,
				     what & RPMBUILD_INSTALL, test)))
		goto exit;

	if (((what & RPMBUILD_INSTALL) || (what & RPMBUILD_PACKAGEBINARY)) &&
	    (rc = processBinaryPolicies(spec, test)))
		goto exit;

	if (((what & RPMBUILD_PACKAGESOURCE) && !test) &&
	    (rc = packageSources(spec, &cookie)))
		goto exit;

	if (((what & RPMBUILD_PACKAGEBINARY) && !test) &&
	    (rc = packageBinaries(spec, cookie, (didBuild == 0))))
		goto exit;
	
	if ((what & RPMBUILD_CLEAN) &&
	    (rc = doScript(spec, RPMBUILD_CLEAN, "%clean",
			   rpmSpecGetSection(spec, RPMBUILD_CLEAN),
			   test, sbp)))
		goto exit;

	if ((what & RPMBUILD_RMBUILD) &&
	    (rc = doScript(spec, RPMBUILD_RMBUILD, "rmbuild", NULL, test, sbp)))
		goto exit;
    }

    if (what & RPMBUILD_RMSOURCE)
	doRmSource(spec);

    if (what & RPMBUILD_RMSPEC)
	(void) unlink(spec->specFile);

exit:
#ifdef ENABLE_OPENMP
    omp_set_num_threads(prev_threads);
#endif
    freeStringBuf(sink);
    free(cookie);
    spec->rootDir = NULL;

    /* Suppress summaries on --quiet */
    if (rpmIsNormal()) {
	unsigned maskWarn = RPMLOG_MASK(RPMLOG_WARNING);
	unsigned maskErrs = RPMLOG_UPTO(RPMLOG_ERR);

	if (rpmlogGetNrecsByMask(maskWarn)) {
	    rpmlog(RPMLOG_NOTICE, _("\nRPM build warnings:\n"));
	    rpmlogPrintByMask(NULL, maskWarn);
	}

	if (rc != RPMRC_OK && rc != RPMRC_MISSINGBUILDREQUIRES) {
	    if (rpmlogGetNrecsByMask(maskErrs)) {
		rpmlog(RPMLOG_NOTICE, _("\nRPM build errors:\n"));
		rpmlogPrintByMask(NULL, maskErrs);
	    }
	}
    }

    if (missing_buildreqs && !rc) {
	rc = RPMRC_MISSINGBUILDREQUIRES;
    }
    if (rc == RPMRC_FAIL) {
	rc = 1;
    }
    return rc;
}

int rpmSpecBuild(rpmts ts, rpmSpec spec, BTA_t buildArgs)
{
    /* buildSpec() can recurse with different buildAmount, pass it separately */
    return buildSpec(ts, buildArgs, spec, buildArgs->buildAmount);
}
