#ifndef _RPMFI_INTERNAL_H
#define _RPMFI_INTERNAL_H

#include <rpm/header.h>
#include <rpm/rpmfi.h>
#include <rpm/rpmstrpool.h>
#include "fprint.h"
#include "cpio.h"

#define	RPMFIMAGIC	0x09697923

/** \ingroup rpmfi
 * Callback on file iterator directory changes
 * @param fi		file info
 * @param data		caller private callback data
 * @return		0 on success, < 0 on error (to stop iteration)
 */
typedef int (*rpmfiChdirCb)(rpmfi fi, void *data);

/** \ingroup rpmfi
 * Set a callback for directory changes during iteration.
 * @param fi		file info
 * @param cb		callback function
 * @param data		caller private callback data
 * @return		string pool handle (weak reference)
 */
int rpmfiSetOnChdir(rpmfi fi, rpmfiChdirCb cb, void *data);

/** \ingroup rpmfi
 * Return file info set string pool handle
 * @param fi		file info
 * @return		string pool handle (weak reference)
 */
RPM_GNUC_INTERNAL
rpmstrPool rpmfilesPool(rpmfiles fi);

/** \ingroup rpmfi
 * Return current base name pool id from file info set.
 * @param fi		file info set
 * @return		current base name id, 0 on invalid
 */
RPM_GNUC_INTERNAL
rpmsid rpmfiBNId(rpmfi fi);

/** \ingroup rpmfi
 * Return current directory name pool id from file info set.
 * @param fi		file info set
 * @return		current base name id, 0 on invalid
 */
RPM_GNUC_INTERNAL
rpmsid rpmfiDNId(rpmfi fi);

RPM_GNUC_INTERNAL
rpmsid rpmfilesBNId(rpmfiles fi, int ix);

RPM_GNUC_INTERNAL
rpmsid rpmfilesDNId(rpmfiles fi, int jx);

/** \ingroup rpmfi
 * Return current original base name pool id from file info set.
 * @param fi		file info set
 * @return		current base name id, 0 on invalid
 */
RPM_GNUC_INTERNAL
rpmsid rpmfiOBNId(rpmfi fi);

/** \ingroup rpmfi
 * Return current original directory name pool id from file info set.
 * @param fi		file info set
 * @return		current base name id, 0 on invalid
 */
RPM_GNUC_INTERNAL
rpmsid rpmfiODNId(rpmfi fi);

RPM_GNUC_INTERNAL
rpmsid rpmfilesOBNId(rpmfiles fi, int ix);

RPM_GNUC_INTERNAL
rpmsid rpmfilesODNId(rpmfiles fi, int jx);

RPM_GNUC_INTERNAL
struct fingerPrint_s *rpmfilesFps(rpmfiles fi);

/** \ingroup rpmfi
 * Check if the file in new package, in old package and on the disk have the same contents.
 * @param 	new file info set
 * @param 	new file index
 * @param 	old file info set
 * @param 	old file index
 * @return	1 if the condition is satisfied, 0 otherwise
 */
RPM_GNUC_INTERNAL
int rpmfileContentsEqual(rpmfiles ofi, int oix, rpmfiles nfi, int nix);


RPM_GNUC_INTERNAL
rpmFileAction rpmfilesDecideFate(rpmfiles ofi, int oix,
				   rpmfiles nfi, int nix,
                                   int skipMissing);

RPM_GNUC_INTERNAL
int rpmfilesConfigConflict(rpmfiles fi, int ix);

RPM_GNUC_INTERNAL
void rpmfilesSetFReplacedSize(rpmfiles fi, int ix, rpm_loff_t newsize);

RPM_GNUC_INTERNAL
rpm_loff_t rpmfilesFReplacedSize(rpmfiles fi, int ix);

RPM_GNUC_INTERNAL
void rpmfilesFpLookup(rpmfiles fi, fingerPrintCache fpc);

rpmfiles rpmfiFiles(rpmfi fi);

/** \ingroup rpmfi
 * Return file iterator through files starting with given prefix.
 * @param fi		file info set
 * @param pfx		prefix
 * @return		file iterator
 */
RPM_GNUC_INTERNAL
rpmfi rpmfilesFindPrefix(rpmfiles fi, const char *pfx);

#endif	/* _RPMFI_INTERNAL_H */

