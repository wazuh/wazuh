#ifndef H_RPMDB_INTERNAL
#define H_RPMDB_INTERNAL

#include <assert.h>

#include <rpm/rpmsw.h>
#include <rpm/rpmtypes.h>
#include <rpm/rpmutil.h>
#include "backend/dbi.h"

#define HASHTYPE packageHash
#define HTKEYTYPE unsigned int
#define HTDATATYPE struct rpmte_s *
#include "rpmhash.H"
#undef HASHTYPE
#undef HTKEYTYPE
#undef HTDATATYPE

enum rpmdbRebuildFlags_e {
    RPMDB_REBUILD_FLAG_SALVAGE	= (1 << 0),
};

/** \ingroup rpmdb
 * Reference a database instance.
 * @param db		rpm database
 * @return		new rpm database reference
 */
rpmdb rpmdbLink(rpmdb db);

/** \ingroup rpmdb
 * Open rpm database.
 * @param prefix	path to top of install tree
 * @param[out] dbp		address of rpm database
 * @param mode		open(2) flags:  O_RDWR or O_RDONLY (O_CREAT also)
 * @param perms		database permissions
 * @return		0 on success
 */
RPM_GNUC_INTERNAL
int rpmdbOpen (const char * prefix, rpmdb * dbp, int mode, int perms);

/** \ingroup rpmdb
 * Initialize database.
 * @param prefix	path to top of install tree
 * @param perms		database permissions
 * @return		0 on success
 */
RPM_GNUC_INTERNAL
int rpmdbInit(const char * prefix, int perms);

/** \ingroup rpmdb
 * Close all database indices and free rpmdb.
 * @param db		rpm database
 * @return		0 on success
 */
RPM_GNUC_INTERNAL
int rpmdbClose (rpmdb db);

/** \ingroup rpmdb
 * Rebuild database indices from package headers.
 * @param prefix	path to top of install tree
 * @param ts		transaction set (or NULL)
 * @param (*hdrchk)	headerCheck() vector (or NULL)
 * @param rebuildflags	flags
 * @return		0 on success
 */
RPM_GNUC_INTERNAL
int rpmdbRebuild(const char * prefix, rpmts ts,
		rpmRC (*hdrchk) (rpmts ts, const void *uh, size_t uc, char ** msg),
		int rebuildflags);

/** \ingroup rpmdb
 * Verify database components.
 * @param prefix	path to top of install tree
 * @return		0 on success
 */
RPM_GNUC_INTERNAL
int rpmdbVerify(const char * prefix);

/** \ingroup rpmdb
 * Add package header to rpm database and indices.
 * @param db		rpm database
 * @param h		header
 * @return		0 on success
 */
RPM_GNUC_INTERNAL
int rpmdbAdd(rpmdb db, Header h);

/** \ingroup rpmdb
 * Remove package header from rpm database and indices.
 * @param db		rpm database
 * @param hdrNum	package instance number in database
 * @return		0 on success
 */
RPM_GNUC_INTERNAL
int rpmdbRemove(rpmdb db, unsigned int hdrNum);

/** \ingroup rpmdb
 * Return rpmdb home directory (depending on chroot state)
 * param db		rpmdb handle
 * return		db home directory (or NULL on error)
 */
RPM_GNUC_INTERNAL
const char *rpmdbHome(rpmdb db);

/** \ingroup rpmdb
 * Return database iterator.
 * @param mi		rpm database iterator
 * @param keyp		key data (NULL for sequential access)
 * @param keylen	key data length (0 will use strlen(keyp))
 * @return		0 on success
 */
int rpmdbExtendIterator(rpmdbMatchIterator mi,
			const char * keyp, size_t keylen);

/** \ingroup rpmdb
 * sort the iterator by (recnum, filenum)
 * Return database iterator.
 * @param mi		rpm database iterator
 */
void rpmdbSortIterator(rpmdbMatchIterator mi);

/** \ingroup rpmdb
 * uniq the iterator by recnum
 * Return database iterator.
 * @param mi		rpm database iterator
 */
void rpmdbUniqIterator(rpmdbMatchIterator mi);

/** \ingroup rpmdb
 * If neg equals to zero then it leaves in iterator only packages that
 * header numbers are in hdrNums. If neg is not zero then removes from iterator
 * all packages that header numbers are in hdrNums.
 * @param mi		rpm database iterator
 * @param hdrNums	hash of package numbers
 * @param neg		mode
 * return		0 on success, 1 on failure (bad args)
 */
int rpmdbFilterIterator(rpmdbMatchIterator mi, packageHash hdrNums, int neg);

/** \ingroup rpmdb
 * Remove items from set of package instances to iterate.
 * @note Sorted hdrNums are always passed in rpmlib.
 * @param mi		rpm database iterator
 * @param hdrNums	hash of package instances
 * @return		0 on success, 1 on failure (bad args)
 */
int rpmdbPruneIterator(rpmdbMatchIterator mi, packageHash hdrNums);

/** \ingroup rpmdb
 * Create a new, empty match iterator (for purposes of extending it
 * through other means)
 * @param db		rpm database
 * @param dbitag	database index tag
 * @return		empty match iterator
 */
RPM_GNUC_INTERNAL
rpmdbMatchIterator rpmdbNewIterator(rpmdb db, rpmDbiTagVal dbitag);

/** \ingroup rpmdb
 * Return database iterator that iterates over database items
 * starting with pfx.
 * @param db		rpm database
 * @param rpmtag	database index tag
 * @param pfx		prefix data
 * @param plen		prefix data length (0 will use strlen(keyp))
 * @return		NULL on failure
 */
RPM_GNUC_INTERNAL
rpmdbMatchIterator rpmdbInitPrefixIterator(rpmdb db, rpmDbiTagVal rpmtag,
					const char* pfx, size_t plen);
/** \ingroup rpmdb
 * Get package offsets of entries
 * @param ii		index iterator
 * @return		db offsets of pkgs
 */
RPM_GNUC_INTERNAL
const unsigned int *rpmdbIndexIteratorPkgOffsets(rpmdbIndexIterator ii);

/** \ingroup rpmdb
 * Return current index (position) in iterator.
 * @param mi		rpm database iterator
 * @return		current index
 */
RPM_GNUC_INTERNAL
int rpmdbGetIteratorIndex(rpmdbMatchIterator mi);

/** \ingroup rpmdb
 * Set iterator index.
 * @param mi		rpm database iterator
 * @param ix		index
 */
RPM_GNUC_INTERNAL
void rpmdbSetIteratorIndex(rpmdbMatchIterator mi, unsigned int ix);

/** \ingroup rpmdb
 * Return offset of package with given index.
 * @param mi		rpm database iterator
 * @param ix		index
 * @return		package offset
 */
RPM_GNUC_INTERNAL
unsigned int rpmdbGetIteratorOffsetFor(rpmdbMatchIterator mi, unsigned int ix);

/** \ingroup rpmdb
 * Return header located in rpmdb at given offset.
 * @param db		rpm database
 * @param offset	database offset
 * @return		header at given offset
 */
RPM_GNUC_INTERNAL
Header rpmdbGetHeaderAt(rpmdb db, unsigned int offset);

#endif
