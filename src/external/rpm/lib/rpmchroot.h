#ifndef _RPMCHROOT_H
#define _RPMCHROOT_H

#include <rpm/rpmutil.h>

/** \ingroup rpmchroot
 * Set or clear process-wide chroot directory.
 * Calling this while chrooted is an error.
 * param rootDir	new chroot directory (or NULL to reset)
 * return		-1 on error, 0 on success
 */
RPM_GNUC_INTERNAL
int rpmChrootSet(const char *rootDir);

/** \ingroup rpmchroot
 * Enter chroot if necessary.
 * return		-1 on error, 0 on success.
 */
/* RPM_GNUC_INTERNAL */
int rpmChrootIn(void);

/** \ingroup rpmchroot
 * Return from chroot if necessary.
 * return		-1 on error, 0 succes.
 */
/* RPM_GNUC_INTERNAL */
int rpmChrootOut(void);

/** \ingroup rpmchroot
 * Return chrooted status.
 * return		1 if chrooted, 0 otherwise
 */
/* RPM_GNUC_INTERNAL */
int rpmChrootDone(void);

#endif /* _RPMCHROOT_H */
