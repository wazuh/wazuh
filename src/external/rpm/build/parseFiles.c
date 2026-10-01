/** \ingroup rpmbuild
 * \file build/parseFiles.c
 *  Parse %files section from spec file.
 */

#include "system.h"

#include <rpm/rpmlog.h>
#include <rpm/rpmfileutil.h>
#include "rpmbuild_internal.h"
#include "debug.h"

int parseFiles(rpmSpec spec)
{
    int res = PART_ERROR;
    Package pkg;
    int rc, argc;
    int arg;
    const char ** argv = NULL;
    char *name = NULL;
    int flag = PART_SUBNAME;
    poptContext optCon = NULL;
    struct poptOption optionsTable[] = {
	{ NULL, 'n', POPT_ARG_STRING, &name, 'n', NULL, NULL},
	{ NULL, 'f', POPT_ARG_STRING, NULL, 'f', NULL, NULL},
	{ 0, 0, 0, 0, 0, NULL, NULL}
    };

    /* XXX unmask %license while parsing %files */
    rpmPushMacroFlags(spec->macros, "license", NULL, "%license", RMIL_SPEC, RPMMACRO_LITERAL);

    if ((rc = poptParseArgvString(spec->line, &argc, &argv))) {
	rpmlog(RPMLOG_ERR, _("line %d: Error parsing %%files: %s\n"),
		 spec->lineNum, poptStrerror(rc));
	goto exit;
    }

    optCon = poptGetContext(NULL, argc, argv, optionsTable, 0);
    while ((arg = poptGetNextOpt(optCon)) > 0) {
	if (arg == 'n') {
	    flag = PART_NAME;
	}
    }

    if (arg < -1) {
	rpmlog(RPMLOG_ERR, _("line %d: Bad option %s: %s\n"),
		 spec->lineNum,
		 poptBadOption(optCon, POPT_BADOPTION_NOALIAS), 
		 spec->line);
	goto exit;
    }

    if (poptPeekArg(optCon)) {
	if (name == NULL)
	    name = xstrdup(poptGetArg(optCon));
	if (poptPeekArg(optCon)) {
	    rpmlog(RPMLOG_ERR, _("line %d: Too many names: %s\n"),
		     spec->lineNum,
		     spec->line);
	    goto exit;
	}
    }

    if (lookupPackage(spec, name, flag, &pkg))
	goto exit;

    /*
     * This should be an error, but its surprisingly commonly abused for the
     * effect of multiple -f arguments in versions that dont support it.
     * Warn but preserve behavior, except for leaking memory.
     */
    if (pkg->fileList != NULL) {
	rpmlog(RPMLOG_WARNING, _("line %d: multiple %%files for package '%s'\n"),
	       spec->lineNum, rpmstrPoolStr(pkg->pool, pkg->name));
	pkg->fileList = argvFree(pkg->fileList);
    }

    for (arg=1; arg<argc; arg++) {
	if (rstreq(argv[arg], "-f") && argv[arg+1]) {
	    char *file = rpmGetPath(argv[arg+1], NULL);
	    argvAdd(&(pkg->fileFile), file);
	    free(file);
	}
    }

    pkg->fileList = argvNew();
    res = parseLines(spec, STRIP_COMMENTS, &(pkg->fileList), NULL);

exit:
    rpmPopMacro(NULL, "license");
    free(argv);
    free(name);
    poptFreeContext(optCon);
	
    return res;
}
