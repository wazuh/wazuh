#ifndef H_RPMSIGNVERITY
#define H_RPMSIGNVERITY

#include <rpm/rpmtypes.h>
#include <rpm/rpmutil.h>

/*
 * Block size used to generate the Merkle tree for fsverity. For now
 * we only support 4K blocks, if we ever decide to support different
 * block sizes, we will need a tag to indicate this.
 */
#define RPM_FSVERITY_BLKSZ	4096

/**
 * Sign file digests in header into signature header
 * @param fd		file descriptor of RPM
 * @param sigh		package signature header
 * @param h		package header
 * @param key		signing key
 * @param keypass	signing key password
 * @param cert		signing cert
 * @return		RPMRC_OK on success
 */
RPM_GNUC_INTERNAL
rpmRC rpmSignVerity(FD_t fd, Header sigh, Header h, char *key,
		    char *keypass, char *cert, uint16_t algo);

#endif /* H_RPMSIGNVERITY */
