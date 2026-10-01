/** \ingroup rpmbuild
 * \file build/parsePolicies.c
 *  Parse %policies section from spec file.
 */

#include "system.h"

#include <rpm/header.h>
#include <rpm/rpmbuild.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmfileutil.h>
#include "rpmbuild_internal.h"
#include "debug.h"

int parsePolicies(rpmSpec spec)
{
    int res = PART_ERROR;
    Package pkg;
    int rc, argc;
    int arg;
    const char **argv = NULL;
    char *name = NULL;
    int flag = PART_SUBNAME;
    poptContext optCon = NULL;

    struct poptOption optionsTable[] = {
	{NULL, 'n', POPT_ARG_STRING, &name, 'n', NULL, NULL},
	{0, 0, 0, 0, 0, NULL, NULL}
    };

    if ((rc = poptParseArgvString(spec->line, &argc, &argv))) {
	rpmlog(RPMLOG_ERR, _("line %d: Error parsing %%policies: %s\n"),
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
	       poptBadOption(optCon, POPT_BADOPTION_NOALIAS), spec->line);
	goto exit;
    }

    if (poptPeekArg(optCon)) {
	if (name == NULL)
	    name = xstrdup(poptGetArg(optCon));
	if (poptPeekArg(optCon)) {
	    rpmlog(RPMLOG_ERR, _("line %d: Too many names: %s\n"),
		   spec->lineNum, spec->line);
	    goto exit;
	}
    }

    if (lookupPackage(spec, name, flag, &pkg))
	goto exit;

    res = parseLines(spec, (STRIP_TRAILINGSPACE | STRIP_COMMENTS),
		     &(pkg->policyList), NULL);

  exit:
    free(argv);
    free(name);
    poptFreeContext(optCon);

    return res;
}
