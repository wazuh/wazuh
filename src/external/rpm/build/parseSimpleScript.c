/** \ingroup rpmbuild
 * \file build/parseBuildInstallClean.c
 *  Parse %build/%install/%clean section from spec file.
 */
#include "system.h"

#include <rpm/rpmlog.h>
#include "rpmbuild_internal.h"
#include "debug.h"


int parseSimpleScript(rpmSpec spec, const char * name,
		      StringBuf *sbp, ARGV_t *avp, int *modep)
{
    int res = PART_ERROR;
    poptContext optCon = NULL;
    int argc;
    const char **argv = NULL;
    StringBuf *target = sbp;
    StringBuf buf = NULL;
    int rc, mode = PARSE_NONE;
    struct poptOption optionsTable[] = {
	{ NULL, 'a', POPT_BIT_SET, &mode, PARSE_APPEND, NULL, NULL },
	{ NULL, 'p', POPT_BIT_SET, &mode, PARSE_PREPEND, NULL, NULL },
	{ NULL, 0, 0, NULL, 0, NULL, NULL }
    };


    if ((rc = poptParseArgvString(spec->line, &argc, &argv))) {
	rpmlog(RPMLOG_ERR, _("line %d: Error parsing script: %s: %s\n"),
		spec->lineNum, spec->line, poptStrerror(rc));
	goto exit;
    }

    optCon = poptGetContext(NULL, argc, argv, optionsTable, 0);
    while ((rc = poptGetNextOpt(optCon)) > 0) {};
    if (rc < -1) {
	rpmlog(RPMLOG_ERR, _("line %d: Bad %s option %s: %s\n"),
		spec->lineNum, argv[0],
		poptBadOption(optCon, POPT_BADOPTION_NOALIAS),
		poptStrerror(rc));
	goto exit;
    }

    if (*sbp != NULL && mode == PARSE_NONE) {
	rpmlog(RPMLOG_ERR, _("line %d: second %s\n"),
		spec->lineNum, name);
	goto exit;
    }

    if (mode == (PARSE_APPEND|PARSE_PREPEND)) {
	rpmlog(RPMLOG_ERR, _("line %d: append and prepend specified: %s\n"),
		spec->lineNum, spec->line);
	goto exit;
    }

    if (mode) {
	buf = newStringBuf();
	target = &buf;
    }

    res = parseLines(spec, STRIP_NOTHING, NULL, target);

    if (buf) {
	argvAdd(avp, getStringBuf(buf));
	freeStringBuf(buf);
    }

exit:
    if (modep)
	*modep = mode;
    free(argv);
    poptFreeContext(optCon);

    return res;
}
