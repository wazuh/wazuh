/** \ingroup rpmbuild
 * \file build/parseBuildInstallClean.c
 *  Parse %build/%install/%clean section from spec file.
 */
#include "system.h"

#include <rpm/rpmlog.h>
#include "rpmbuild_internal.h"
#include "debug.h"


int parseList(rpmSpec spec, const char *name, rpmTagVal tag)
{
    int res = PART_ERROR;
    ARGV_t lst = NULL;

    /* There are no options to %patchlist and %sourcelist */
    if ((res = parseLines(spec, (STRIP_TRAILINGSPACE | STRIP_COMMENTS),
			  &lst, NULL)) == PART_ERROR) {
	goto exit;
    }

    for (ARGV_const_t l = lst; l && *l; l++) {
	if (rstreq(*l, ""))
	    continue;
	addSource(spec, 0, *l, tag);
    }

exit:
    argvFree(lst);
    return res;
}
