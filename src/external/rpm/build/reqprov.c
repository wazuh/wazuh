/** \ingroup rpmbuild
 * \file build/reqprov.c
 *  Add dependency tags to package header(s).
 */

#include "system.h"

#include <rpm/header.h>
#include <rpm/rpmstring.h>
#include <rpm/rpmlog.h>
#include "rpmbuild_internal.h"
#include "debug.h"

int addReqProv(Package pkg, rpmTagVal tagN,
		const char * N, const char * EVR, rpmsenseFlags Flags,
		uint32_t index)
{
    rpmds newds, *dsp = NULL;

    dsp = packageDependencies(pkg, tagN);

    /* rpmlib() dependency sanity:
     * - Provides are permitted only for source packages
     * - Otherwise only requires
     * - Ensure sense bit
     */
    if (rstreqn(N, "rpmlib(", sizeof("rpmlib(")-1)) {
	if (tagN != RPMTAG_REQUIRENAME &&
	        (tagN == RPMTAG_PROVIDENAME && !(Flags & RPMSENSE_RPMLIB)))
	    return 1;
	Flags |= RPMSENSE_RPMLIB;
    }

    newds = rpmdsSinglePoolTix(pkg->pool, tagN, N, EVR,
			       rpmSanitizeDSFlags(tagN, Flags), index);

    rpmdsMerge(dsp, newds);
    rpmdsFree(newds);

    return 0;
}

rpmRC addReqProvPkg(void *cbdata, rpmTagVal tagN,
		    const char * N, const char *EVR, rpmsenseFlags Flags,
		    int index)
{
    Package pkg = (Package)cbdata;
    return addReqProv(pkg, tagN, N, EVR, Flags, index) ? RPMRC_FAIL : RPMRC_OK;
}

int rpmlibNeedsFeature(Package pkg, const char * feature, const char * featureEVR)
{
    char *reqname = NULL;
    int flags = RPMSENSE_RPMLIB|RPMSENSE_LESS|RPMSENSE_EQUAL;
    int res;

    /* XXX HACK: avoid changing rpmlibNeedsFeature() for just one user */
    if (rstreq(feature, "DynamicBuildRequires"))
	flags |= RPMSENSE_MISSINGOK;

    rasprintf(&reqname, "rpmlib(%s)", feature);

    res = addReqProv(pkg, RPMTAG_REQUIRENAME, reqname, featureEVR, flags, 0);

    free(reqname);

    return res;
}
