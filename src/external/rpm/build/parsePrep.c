/** \ingroup rpmbuild
 * \file build/parsePrep.c
 *  Parse %prep section from spec file.
 */

#include "system.h"

#include <errno.h>
#include <libgen.h>

#include <rpm/header.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmfileutil.h>
#include "rpmbuild_internal.h"
#include "rpmbuild_misc.h"
#include "rpmmacro_internal.h"
#include "debug.h"

static void appendMb(rpmMacroBuf mb, const char *s, int nl)
{
    rpmMacroBufAppendStr(mb, s);
    if (nl)
	rpmMacroBufAppend(mb, '\n');
}

/**
 * Check if file can be determined non-compressed
 * @param urlfn		file url
 * @return		1 if known uncompressed, 0 otherwise
 */
static int notCompressed(const char * fn)
{
    rpmCompressedMagic compressed = COMPRESSED_OTHER; /* arbitrary non-zero */
    struct stat sb;

    if (lstat(fn, &sb) == 0)
	rpmFileIsCompressed(fn, &compressed);

    return (compressed == COMPRESSED_NOT);
}

/**
 * Expand %patchN macro into %prep scriptlet.
 * @param spec		build info
 * @param c		patch index
 * @param strip		patch level (i.e. patch -p argument)
 * @param db		saved file suffix (i.e. patch --suffix argument)
 * @param reverse	include -R?
 * @param removeEmpties	include -E?
 * @param fuzz		fuzz factor, fuzz<0 means no fuzz set
 * @param dir		dir to change to (i.e. patch -d argument)
 * @param outfile	send output to this file (i.e. patch -o argument)
 * @param setUtc	include -Z?
 * @return		expanded %patch macro (NULL on error)
 */

static char *doPatch(rpmSpec spec, uint32_t c, int strip, const char *db,
		     int reverse, int removeEmpties, int fuzz, const char *dir,
		     const char *outfile, int setUtc)
{
    char *buf = NULL;
    char *arg_backup = NULL;
    char *arg_fuzz = NULL;
    char *arg_dir = NULL;
    char *arg_outfile = NULL;
    char *args = NULL;
    char *arg_patch_flags = rpmExpand("%{?_default_patch_flags}", NULL);
    struct Source *sp;
    char *patchcmd;

    if ((sp = findSource(spec, c, RPMBUILD_ISPATCH)) == NULL) {
	rpmlog(RPMLOG_ERR, _("No patch number %u\n"), c);
	goto exit;
    }

    if (db) {
	rasprintf(&arg_backup, "-b --suffix %s", db);
    } else arg_backup = xstrdup("");

    if (dir) {
	rasprintf(&arg_dir, " -d %s", dir);
    } else arg_dir = xstrdup("");

    if (outfile) {
	rasprintf(&arg_outfile, " -o %s", outfile);
    } else arg_outfile = xstrdup("");

    if (fuzz >= 0) {
	rasprintf(&arg_fuzz, " --fuzz=%d", fuzz);
    } else arg_fuzz = xstrdup("");

    rasprintf(&args, "%s -p%d %s%s%s%s%s%s%s", arg_patch_flags, strip, arg_backup, arg_fuzz, arg_dir, arg_outfile,
		reverse ? " -R" : "", 
		removeEmpties ? " -E" : "",
		setUtc ? " -Z" : "");

    /* Avoid the extra cost of fork and pipe for uncompressed patches */
    if (notCompressed(sp->path)) {
	patchcmd = rpmExpand("%{__patch} ", args, " < ", sp->path, NULL);
    } else {
	patchcmd = rpmExpand("{ %{__rpmuncompress} ", sp->path, " || echo patch_fail ; } | "
                             "%{__patch} ", args, NULL);
    }

    free(arg_fuzz);
    free(arg_outfile);
    free(arg_dir);
    free(arg_backup);
    free(args);

    rasprintf(&buf, "echo \"Patch #%u (%s):\"\n"
			"%s\n", 
			c, sp->source, patchcmd);
    free(patchcmd);

exit:
    free(arg_patch_flags);
    return buf;
}

/**
 * Expand %setup macro into %prep scriptlet.
 * @param spec		build info
 * @param c		source index
 * @param quietly	should -vv be omitted from tar?
 * @return		expanded %setup macro (NULL on error)
 */
static char *doUntar(rpmSpec spec, uint32_t c, int quietly, int autoPath)
{
    char *buf = NULL;
    struct Source *sp;

    if ((sp = findSource(spec, c, RPMBUILD_ISSOURCE)) == NULL) {
	rpmlog(RPMLOG_ERR, _("No source number %u\n"), c);
	goto exit;
    }

    buf = rpmExpand("%{__rpmuncompress} -x ",
		    quietly ? "" : "-v ",
		    autoPath ? "-C %{buildsubdir} " : "",
		    "%{shescape:", sp->path, "}", NULL);
    rstrcat(&buf,
	"\nSTATUS=$?\n"
	"if [ $STATUS -ne 0 ]; then\n"
	"  exit $STATUS\n"
	"fi");

exit:
    return buf;
}

/**
 * Parse %setup macro.
 * @param spec		build info
 * @param line		current line from spec file
 * @return		RPMRC_OK on success
 */
void doSetupMacro(rpmMacroBuf mb, rpmMacroEntry me, ARGV_t margs, size_t *parsed)
{
    rpmSpec spec = (rpmSpec)rpmMacroEntryPriv(me);
    char *line = argvJoin(margs, " ");
    char *buf = NULL;
    StringBuf before = newStringBuf();
    StringBuf after = newStringBuf();
    poptContext optCon = NULL;
    int argc;
    const char ** argv = NULL;
    int arg;
    int xx;
    uint32_t num;
    int leaveDirs = 0, skipDefaultAction = 0;
    int createDir = 0, quietly = 0, autoPath = 0;
    char * dirName = NULL;
    struct poptOption optionsTable[] = {
	    { NULL, 'a', POPT_ARG_STRING, NULL, 'a',	NULL, NULL},
	    { NULL, 'b', POPT_ARG_STRING, NULL, 'b',	NULL, NULL},
	    { NULL, 'c', 0, &createDir, 0,		NULL, NULL},
	    { NULL, 'C', 0, &autoPath, 0,		NULL, NULL},
	    { NULL, 'D', 0, &leaveDirs, 0,		NULL, NULL},
	    { NULL, 'n', POPT_ARG_STRING, &dirName, 0,	NULL, NULL},
	    { NULL, 'T', 0, &skipDefaultAction, 0,	NULL, NULL},
	    { NULL, 'q', 0, &quietly, 0,		NULL, NULL},
	    { 0, 0, 0, 0, 0,	NULL, NULL}
    };

    if (strstr(line+5, " -q")) quietly = 1;

    if ((xx = poptParseArgvString(line, &argc, &argv))) {
	rpmMacroBufErr(mb, 1, _("Error parsing %%setup: %s\n"), poptStrerror(xx));
	goto exit;
    }

    optCon = poptGetContext(NULL, argc, argv, optionsTable, 0);
    while ((arg = poptGetNextOpt(optCon)) > 0) {
	char *optArg = poptGetOptArg(optCon);

	/* We only parse -a and -b here */

	if (parseUnsignedNum(optArg, &num)) {
	    rpmMacroBufErr(mb, 1, _("line %d: Bad arg to %%setup: %s\n"),
		     spec->lineNum, (optArg ? optArg : "???"));
	    goto exit;
	}

	{   char *chptr = doUntar(spec, num, quietly, 0);
	    if (chptr == NULL)
		goto exit;

	    appendLineStringBuf((arg == 'a' ? after : before), chptr);
	    free(chptr);
	}
	free(optArg);
    }

    if (arg < -1) {
	rpmMacroBufErr(mb, 1, _("line %d: Bad %%setup option %s: %s\n"),
		 spec->lineNum,
		 poptBadOption(optCon, POPT_BADOPTION_NOALIAS), 
		 poptStrerror(arg));
	goto exit;
    }

    if (dirName) {
	rpmPushMacro(spec->macros, "buildsubdir", NULL, dirName, RMIL_SPEC);
    } else {
	char * buildSubdir = NULL;
	rasprintf(&buildSubdir, "%s-%s",
		  headerGetString(spec->packages->header, RPMTAG_NAME),
		  headerGetString(spec->packages->header, RPMTAG_VERSION));
	rpmPushMacro(spec->macros, "buildsubdir", NULL, buildSubdir, RMIL_SPEC);
	free(buildSubdir);
    }
    
    /* cd to the build dir */
    {	char * buildDir = rpmGenPath(spec->rootDir, "%{_builddir}", "");

	rasprintf(&buf, "cd '%s'", buildDir);
	appendMb(mb, buf, 1);
	free(buf);
	free(buildDir);
    }
    
    /* delete any old sources */
    if (!leaveDirs) {
	buf = rpmExpand("rm -rf '%{buildsubdir}'", NULL);
	appendMb(mb, buf, 1);
	free(buf);
    }

    appendMb(mb, getStringBuf(before), 0);

    /* if necessary, create and cd into the proper dir */
    if (createDir) {
	buf = rpmExpand("%{__mkdir_p} '%{buildsubdir}'\n",
			"cd '%{buildsubdir}'", NULL);
	appendMb(mb, buf, 1);
	free(buf);
    }

    /* do the default action */
   if (!skipDefaultAction) {
	char *chptr = doUntar(spec, 0, quietly, autoPath);
	if (!chptr)
	    goto exit;
	appendMb(mb, chptr, 1);
	free(chptr);
    }

    if (!createDir) {
	buf = rpmExpand("cd '%{buildsubdir}'", NULL);
	appendMb(mb, buf, 1);
	free(buf);
    }

    appendMb(mb, getStringBuf(after), 0);

    /* Fix the permissions of the setup build tree */
    {	char *fix = rpmExpand("%{_fixperms} .", NULL);
	if (fix && *fix != '%') {
	    appendMb(mb, fix, 1);
	}
	free(fix);
    }

exit:
    freeStringBuf(before);
    freeStringBuf(after);
    poptFreeContext(optCon);
    free(dirName);
    free(argv);
    free(line);

    return;
}

/**
 * Parse %patch line.
 * This supports too many crazy syntaxes:
 * - %patchN is equal to %patch -P\<N\>
 * - -P\<N\> -P\<N+1\>... can be used to apply several patch on a single line
 * - Any trailing arguments are treated as patch numbers
 * - Any combination of the above
 *
 * @param spec		build info
 * @param line		current line from spec file
 * @return		RPMRC_OK on success
 */
void doPatchMacro(rpmMacroBuf mb, rpmMacroEntry me, ARGV_t margs, size_t *parsed)
{
    rpmSpec spec = (rpmSpec)rpmMacroEntryPriv(me);
    char *line = argvJoin(margs, " ");
    char *opt_b, *opt_d, *opt_o;
    int opt_p, opt_R, opt_E, opt_F, opt_Z;
    int argc, c;
    const char **argv = NULL;
    ARGV_t patch, patchnums = NULL;
    
    struct poptOption const patchOpts[] = {
	{ NULL, 'P', POPT_ARG_STRING, NULL, 'P', NULL, NULL },
	{ NULL, 'p', POPT_ARG_INT, &opt_p, 'p', NULL, NULL },
	{ NULL, 'R', POPT_ARG_NONE, &opt_R, 'R', NULL, NULL },
	{ NULL, 'E', POPT_ARG_NONE, &opt_E, 'E', NULL, NULL },
	{ NULL, 'b', POPT_ARG_STRING, &opt_b, 'b', NULL, NULL },
	{ NULL, 'z', POPT_ARG_STRING, &opt_b, 'z', NULL, NULL },
	{ NULL, 'F', POPT_ARG_INT, &opt_F, 'F', NULL, NULL },
	{ NULL, 'd', POPT_ARG_STRING, &opt_d, 'd', NULL, NULL },
	{ NULL, 'o', POPT_ARG_STRING, &opt_o, 'o', NULL, NULL },
	{ NULL, 'Z', POPT_ARG_NONE, &opt_Z, 'Z', NULL, NULL},
	{ NULL, 0, 0, NULL, 0, NULL, NULL }
    };
    poptContext optCon = NULL;

    opt_p = opt_R = opt_E = opt_Z = 0;
    opt_F = rpmExpandNumeric("%{_default_patch_fuzz}");		/* get default fuzz factor for %patch */
    opt_b = opt_d = opt_o = NULL;

    poptParseArgvString(line, &argc, &argv);

    /* 
     * Grab all -P<N> numbers for later processing. Stored as strings
     * at this point so we only have to worry about conversion in one place.
     */
    optCon = poptGetContext(NULL, argc, argv, patchOpts, 0);
    while ((c = poptGetNextOpt(optCon)) > 0) {
	switch (c) {
	case 'P': {
	    char *arg = poptGetOptArg(optCon);
	    if (arg) {
	    	argvAdd(&patchnums, arg);
	    	free(arg);
	    }
	    break;
	}
	default:
	    break;
	}
    }

    if (c < -1) {
	rpmMacroBufErr(mb, 1, "%s: %s: %s\n", poptStrerror(c),
		poptBadOption(optCon, POPT_BADOPTION_NOALIAS), line);
	goto exit;
    }

    /* Any trailing arguments are treated as patch numbers */
    argvAppend(&patchnums, (ARGV_const_t) poptGetArgs(optCon));

    if (argvCount(patchnums) == 0) {
	rpmMacroBufErr(mb, 1, _("Patch number not specified: %s\n"), line);
	goto exit;
    }

    /* Convert to number, generate patch command and append to %prep script */
    for (patch = patchnums; *patch; patch++) {
	uint32_t pnum;
	char *s;
	if (parseUnsignedNum(*patch, &pnum)) {
	    rpmMacroBufErr(mb, 1, _("Invalid patch number %s: %s\n"),
		     *patch, line);
	    goto exit;
	}
	s = doPatch(spec, pnum, opt_p, opt_b, opt_R, opt_E, opt_F, opt_d, opt_o, opt_Z);
	if (s == NULL) {
	    goto exit;
	}
	appendMb(mb, s, 1);
	free(s);
    }
	
exit:
    argvFree(patchnums);
    free(opt_b);
    free(opt_d);
    free(opt_o);
    free(argv);
    free(line);
    poptFreeContext(optCon);
    return;
}
