#ifndef _RPMDS_INTERNAL_H
#define _RPMDS_INTERNAL_H

#include <rpm/rpmds.h>

/** \ingroup rpmds
 * Swiss army knife dependency matching function.
 * @param pool		string pool (or NULL for private pool)
 * @param h		header
 * @param prix		index to provides (or -1 or any)
 * @param req		dependency set
 * @param selfevr	only look at package EVR?
 * @return		1 if dependency overlaps, 0 otherwise
 */
RPM_GNUC_INTERNAL
int rpmdsMatches(rpmstrPool pool, Header h, int prix,
		 rpmds req, int selfevr);

/** \ingroup rpmds
 * Notify of results of dependency match.
 * @param ds		dependency set
 * @param where		where dependency was resolved (or NULL)
 * @param rc		0 == YES, otherwise NO
 */
RPM_GNUC_INTERNAL
void rpmdsNotify(rpmds ds, const char * where, int rc);

/** \ingroup rpmds
 * Return current dependency name pool id.
 * @param ds            dependency set
 * @return              current dependency name id, 0 on invalid
 */
RPM_GNUC_INTERNAL
rpmsid rpmdsNId(rpmds ds);

/** \ingroup rpmds
 * Return current dependency epoch-version-release pool id.
 * @param ds            dependency set
 * @return              current dependency EVR id, 0 on invalid
 */
RPM_GNUC_INTERNAL
rpmsid rpmdsEVRId(rpmds ds);

/** \ingroup rpmds
 * Return dependency set string pool handle
 * @param ds		dependency set
 * @return		string pool handle (weak reference)
 */
RPM_GNUC_INTERNAL
rpmstrPool rpmdsPool(rpmds ds);

RPM_GNUC_INTERNAL
rpmsid rpmdsNIdIndex(rpmds ds, int i);

RPM_GNUC_INTERNAL
rpmsid rpmdsEVRIdIndex(rpmds ds, int i);

RPM_GNUC_INTERNAL
const char * rpmdsNIndex(rpmds ds, int i);

RPM_GNUC_INTERNAL
const char * rpmdsEVRIndex(rpmds ds, int i);

RPM_GNUC_INTERNAL
rpmsenseFlags rpmdsFlagsIndex(rpmds ds, int i);

RPM_GNUC_INTERNAL
int rpmdsTiIndex(rpmds ds, int i);

RPM_GNUC_INTERNAL
rpm_color_t rpmdsColorIndex(rpmds ds, int i);

RPM_GNUC_INTERNAL
int rpmdsCompareIndex(rpmds A, int aix, rpmds B, int bix);

/** \ingroup rpmds
 * Filter dependency set and return new dependency set containing only items
 * with given trigger index.
 * @param ds		dependency set
 * @param ti		trigger index
 * @return		new filtered dependency set
 */
RPM_GNUC_INTERNAL
rpmds rpmdsFilterTi(rpmds ds, int ti);

#endif /* _RPMDS_INTERNAL_H */
