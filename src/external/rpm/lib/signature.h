#ifndef H_SIGNATURE
#define	H_SIGNATURE

/** \ingroup signature
 * \file signature.h
 * Generate and verify signatures.
 */
#include <rpm/rpmtypes.h>

/** \ingroup signature
 * Read (and verify header+payload size) signature header.
 * If an old-style signature is found, we emulate a new style one.
 * @param fd		file handle
 * @param[out] sighp	address of (signature) header (or NULL)
 * @param[out] msg		failure msg
 * @return		rpmRC return code
 */
rpmRC rpmReadSignature(FD_t fd, Header *sighp, char ** msg);

/** \ingroup signature
 * Write signature header.
 * @param fd		file handle
 * @param h		(signature) header
 * @return		0 on success, 1 on error
 */
int rpmWriteSignature(FD_t fd, Header h);

/** \ingroup signature
 * Generate signature and write to file
 * @param SHA256	SHA256 digest
 * @param SHA1		SHA1 digest
 * @param MD5		MD5 digest
 * @param size		size of header
 * @param payloadSize	size of archive
 * @param fd		output file
 */
rpmRC rpmGenerateSignature(char *SHA256, char *SHA1, uint8_t *MD5,
			rpm_loff_t size, rpm_loff_t payloadSize, FD_t fd);

#endif	/* H_SIGNATURE */
