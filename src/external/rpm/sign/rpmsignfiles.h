#ifndef H_RPMSIGNFILES
#define H_RPMSIGNFILES

#include <rpm/rpmtypes.h>
#include <rpm/rpmutil.h>

#ifdef __cplusplus
extern "C" {
#endif

/* This doesn't have c++ guards on its own */
#include <imaevm.h>

#ifdef __cplusplus
}
#endif

/**
 * Sign file digests in header into signature header
 * @param sigh		package signature header
 * @param h		package header
 * @param key		signing key
 * @param keypass	signing key password
 * @return		RPMRC_OK on success
 */
RPM_GNUC_INTERNAL
rpmRC rpmSignFiles(Header sigh, Header h, const char *key, char *keypass);

#endif /* H_RPMSIGNFILES */
