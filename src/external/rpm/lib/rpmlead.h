#ifndef _H_RPMLEAD
#define _H_RPMLEAD

/** \ingroup lead
 * \file rpmlead.h
 * Routines to read and write an rpm lead structure for a a package.
 */
#define RPMLEAD_BINARY 0
#define RPMLEAD_SOURCE 1

#define RPMLEAD_MAGIC0 0xed
#define RPMLEAD_MAGIC1 0xab
#define RPMLEAD_MAGIC2 0xee
#define RPMLEAD_MAGIC3 0xdb

#define RPMLEAD_SIZE 96         /*!< Don't rely on sizeof(struct) */

/** \ingroup lead
 * Write lead to file handle.
 * @param fd		file handle
 * @param h		package header
 * @return		RPMRC_OK on success, RPMRC_FAIL on error
 */
rpmRC rpmLeadWrite(FD_t fd, Header h);

/** \ingroup lead
 * Read lead from file handle.
 * @param fd		file handle
 * @param[out] emsg		failure message on error (malloced)
 * @return		RPMRC_OK on success, RPMRC_FAIL/RPMRC_NOTFOUND on error
 */
rpmRC rpmLeadRead(FD_t fd, char **emsg);

#endif	/* _H_RPMLEAD */
