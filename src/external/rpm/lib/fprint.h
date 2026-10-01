#ifndef H_FINGERPRINT
#define H_FINGERPRINT

/** \ingroup rpmtrans
 * \file fprint.h
 * Identify a file name path by a unique "finger print".
 */

#include <rpm/rpmtypes.h>

/**
 */
typedef struct fprintCache_s * fingerPrintCache;

/**
 * @todo Convert to pointer and make abstract.
 */
typedef struct fingerPrint_s fingerPrint;

struct rpmffi_s {
  rpmte p;
  int   fileno;
};

/**
 * Create finger print cache.
 * @param sizeHint	number of elements expected
 * @param pool		string pool (or NULL for private)
 * @return pointer to initialized fingerprint cache
 */
RPM_GNUC_INTERNAL
fingerPrintCache fpCacheCreate(int sizeHint, rpmstrPool pool);

/**
 * Destroy finger print cache.
 * @param cache		pointer to fingerprint cache
 * @return		NULL always
 */
RPM_GNUC_INTERNAL
fingerPrintCache fpCacheFree(fingerPrintCache cache);

RPM_GNUC_INTERNAL
fingerPrint * fpCacheGetByFp(fingerPrintCache cache,
			     struct fingerPrint_s * fp, int ix,
			     struct rpmffi_s ** recs, int * numRecs);

RPM_GNUC_INTERNAL
void fpCachePopulate(fingerPrintCache cache, rpmts ts, int fileCount);

/* compare an existing fingerprint with a looked-up fingerprint for db/bn */
RPM_GNUC_INTERNAL
int fpLookupEquals(fingerPrintCache cache, fingerPrint * fp,
	           const char * dirName, const char * baseName);

RPM_GNUC_INTERNAL
int fpLookupEqualsId(fingerPrintCache cache, fingerPrint * fp,
	             rpmsid dirNameId, rpmsid baseNameId);

RPM_GNUC_INTERNAL
const char *fpEntryDir(fingerPrintCache cache, fingerPrint *fp);

RPM_GNUC_INTERNAL
dev_t fpEntryDev(fingerPrintCache cache, fingerPrint *fp);

/**
 * Return finger print of a file path.
 * @param cache		pointer to fingerprint cache
 * @param dirName	leading directory name of file path
 * @param baseName	base name of file path
 * @param[out] fp		pointer of fingerprint struct to fill out
 * @return		0 on success
 */
RPM_GNUC_INTERNAL
int fpLookup(fingerPrintCache cache,
	     const char * dirName, const char * baseName,
	     fingerPrint **fp);

/**
 * Return finger print of a file path given as ids.
 * @param cache		pointer to fingerprint cache
 * @param dirNameId	id of leading directory name of file path
 * @param baseNameId	id of base name of file path
 * @param[out] fp		pointer of fingerprint struct to fill out
 * @return		0 on success
 */
RPM_GNUC_INTERNAL
int fpLookupId(fingerPrintCache cache,
	       rpmsid dirNameId, rpmsid BaseNameId,
	       fingerPrint **fp);

/**
 * Compare two finger print entries.
 * This routine is exactly equivalent to the FP_EQUAL macro.
 * @param key1		finger print 1
 * @param key2		finger print 2
 * @return result of comparing key1 and key2
 */
RPM_GNUC_INTERNAL
int fpEqual(const fingerPrint * key1, const fingerPrint * key2);

/**
 * Return finger prints of an array of file paths.
 * @param cache		pointer to fingerprint cache
 * @param pool		pointer to file name pool
 * @param dirNames	directory names
 * @param baseNames	file base names
 * @param dirIndexes	index into dirNames for each baseNames
 * @param fileCount	number of file entries
 * @return		pointer to array of finger prints
 */
RPM_GNUC_INTERNAL
fingerPrint * fpLookupList(fingerPrintCache cache, rpmstrPool pool,
			   rpmsid * dirNames, rpmsid * baseNames,
			   const uint32_t * dirIndexes, int fileCount);

#endif
