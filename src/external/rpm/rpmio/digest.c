/** \ingroup signature
 * \file rpmio/digest.c
 */

#include "system.h"

#include <string.h>
#include <stdlib.h>
#include <rpm/rpmcrypto.h>

#include "debug.h"

#define DIGESTS_MAX 12
struct rpmDigestBundle_s {
    int index_max;			/*!< Largest index of active digest */
    off_t nbytes;			/*!< Length of total input data */
    DIGEST_CTX digests[DIGESTS_MAX];	/*!< Digest contexts identified by id */
    int ids[DIGESTS_MAX];		/*!< Digest ID (arbitrary non-zero) */
};

static int findID(rpmDigestBundle bundle, int id)
{
    int ix = -1;
    if (bundle) {
	for (int i = 0; i < DIGESTS_MAX; i++) {
	    if (bundle->ids[i] == id) {
		ix = i;
		break;
	    }
	}
    }
    return ix;
}

rpmDigestBundle rpmDigestBundleNew(void)
{
    rpmDigestBundle bundle = (rpmDigestBundle)xcalloc(1, sizeof(*bundle));
    return bundle;
}

rpmDigestBundle rpmDigestBundleFree(rpmDigestBundle bundle)
{
    if (bundle) {
	for (int i = 0; i <= bundle->index_max ; i++) {
	    if (bundle->digests[i] == NULL)
		continue;
	    rpmDigestFinal(bundle->digests[i], NULL, NULL, 0);
	    bundle->digests[i] = NULL;
	}
	memset(bundle, 0, sizeof(*bundle));
	free(bundle);
    }
    return NULL;
}

int rpmDigestBundleAdd(rpmDigestBundle bundle, int algo,
			rpmDigestFlags flags)
{
    return rpmDigestBundleAddID(bundle, algo, algo, flags);
}

int rpmDigestBundleAddID(rpmDigestBundle bundle, int algo, int id,
			rpmDigestFlags flags)
{
    int rc = -1;
    if (id > 0 && findID(bundle, id) < 0) {
	int ix = findID(bundle, 0); /* Find first free slot */
	if (ix >= 0) {
	    bundle->digests[ix] = rpmDigestInit(algo, flags);
	    if (bundle->digests[ix]) {
		bundle->ids[ix]= id;
		if (ix > bundle->index_max)
		    bundle->index_max = ix;
		rc = 0;
	    }
	}
    }
    return rc;
}
int rpmDigestBundleUpdate(rpmDigestBundle bundle, const void *data, size_t len)
{
    int rc = -1;
    if (bundle && data && len > 0) {
	rc = 0;
	for (int i = 0; i <= bundle->index_max; i++) {
	    if (bundle->ids[i] > 0)
		rc += rpmDigestUpdate(bundle->digests[i], data, len);
	}
	bundle->nbytes += len;
    }
    return rc;
}

int rpmDigestBundleFinal(rpmDigestBundle bundle, int id,
			 void ** datap, size_t * lenp, int asAscii)
{
    int rc = -1;
    int ix = findID(bundle, id);

    if (ix >= 0) {
	rc = rpmDigestFinal(bundle->digests[ix], datap, lenp, asAscii);
	bundle->digests[ix] = NULL;
	bundle->ids[ix] = 0;
    }
    return rc;
}

DIGEST_CTX rpmDigestBundleDupCtx(rpmDigestBundle bundle, int id)
{
    int ix = findID(bundle, id);
    DIGEST_CTX dup = (ix >= 0) ? rpmDigestDup(bundle->digests[ix]) : NULL;
    return dup;
}

