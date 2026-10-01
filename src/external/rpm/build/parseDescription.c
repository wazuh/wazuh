/** \ingroup rpmbuild
 * \file build/parseDescription.c
 *  Parse %description section from spec file.
 */

#include "system.h"

#include <rpm/header.h>
#include <rpm/rpmlog.h>
#include "rpmbuild_internal.h"
#include "debug.h"

int parseDescription(rpmSpec spec)
{
    int nextPart = PART_ERROR;	/* assume error */
    StringBuf sb = NULL;
    int flag = PART_SUBNAME;
    Package pkg;
    int rc, argc;
    int arg;
    const char **argv = NULL;
    char *name = NULL;
    char *lang = NULL;
    const char *descr = "";
    poptContext optCon = NULL;
    struct poptOption optionsTable[] = {
	{ NULL, 'n', POPT_ARG_STRING, &name, 'n', NULL, NULL},
	{ NULL, 'l', POPT_ARG_STRING, &lang, 'l', NULL, NULL},
	{ 0, 0, 0, 0, 0, NULL, NULL}
    };

    if ((rc = poptParseArgvString(spec->line, &argc, &argv))) {
	rpmlog(RPMLOG_ERR, _("line %d: Error parsing %%description: %s\n"),
		 spec->lineNum, poptStrerror(rc));
	return PART_ERROR;
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

    if ((nextPart = parseLines(spec, (STRIP_TRAILINGSPACE |STRIP_COMMENTS),
				NULL, &sb)) == PART_ERROR) {
	goto exit;
    }

    if (sb) {
	stripTrailingBlanksStringBuf(sb);
	descr = getStringBuf(sb);
    }

    if (addLangTag(spec, pkg->header,
		   RPMTAG_DESCRIPTION, descr,
		   lang ? lang : RPMBUILD_DEFAULT_LANG)) {
	nextPart = PART_ERROR;
    }
     
exit:
    freeStringBuf(sb);
    free(lang);
    free(name);
    free(argv);
    poptFreeContext(optCon);
    return nextPart;
}
