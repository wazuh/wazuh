#ifndef H_CPIO
#define H_CPIO

/** \ingroup payload
 * \file cpio.h
 *  Structures used to handle cpio payloads within rpm packages.
 *
 *  @warning Rpm's cpio implementation may be different than standard cpio.
 *  The implementation is pretty close, but it has some behaviors which are
 *  more to RPM's liking. I tried to document the differing behavior in cpio.c,
 *  but I may have missed some (ewt).
 *
 */

typedef struct rpmcpio_s * rpmcpio_t;

/**
 * Create CPIO file object
 * @param fd		file
 * @param mode		XXX
 * @return CPIO object
 **/
rpmcpio_t rpmcpioOpen(FD_t fd, char mode);

int rpmcpioClose(rpmcpio_t cpio);

off_t rpmcpioTell(rpmcpio_t cpio);

rpmcpio_t rpmcpioFree(rpmcpio_t cpio);

/**
 * Write cpio header.
 * @param cpio		cpio archive
 * @param path		file name
 * @param st		stat struct with meta data
 * @return		0 on success
 */
RPM_GNUC_INTERNAL
int rpmcpioHeaderWrite(rpmcpio_t cpio, char * path, struct stat * st);
RPM_GNUC_INTERNAL
int rpmcpioStrippedHeaderWrite(rpmcpio_t cpio, int fx, off_t fsize);

ssize_t rpmcpioWrite(rpmcpio_t cpio, const void * buf, size_t size);

/**
 * Read cpio header. Iff fx is returned as -1 a cpio header was read
 * and the file name is found in path. Otherwise a stripped header was read
 * and the fx is the number of the file in the header/rpmfi. In this case
 * rpmcpioSetExpectedFileSize() needs to be called with the file size of the
 * payload content - with may be zero for hard links, directory or other
 * special files.
 * @param[out] fsm		file path and stat info
 * @param[out] path		path of the file
 * @param[out] fx		number in the header of the file read
 * @return		0 on success
 */
RPM_GNUC_INTERNAL
int rpmcpioHeaderRead(rpmcpio_t cpio, char ** path, int * fx);

/**
 * Tell the cpio object the expected file size in the payload.
 * The size must be zero for all but the last of hard linked files,
 * directories and special files.
 * This is needed after reading a stripped cpio header! See above.
 */
RPM_GNUC_INTERNAL
void rpmcpioSetExpectedFileSize(rpmcpio_t cpio, off_t fsize);

ssize_t rpmcpioRead(rpmcpio_t cpio, void * buf, size_t size);

#endif	/* H_CPIO */
