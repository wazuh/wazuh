#ifndef H_RPMAL
#define H_RPMAL

/** \ingroup rpmdep rpmtrans
 * \file rpmal.h
 * Structures used for managing added/available package lists.
 */

#include <rpm/rpmtypes.h>
#include <rpm/rpmts.h>

typedef struct rpmal_s * rpmal;

/**
 * Initialize available packages, items, and directory list.
 * @param ts		transaction set
 * @param delta		no. of entries to add on each realloc
 * @return al		new available list
 */
RPM_GNUC_INTERNAL
rpmal rpmalCreate(rpmts ts, int delta);

/**
 * Free available packages, items, and directory members.
 * @param al		available list
 * @return		NULL always
 */
RPM_GNUC_INTERNAL
rpmal rpmalFree(rpmal al);

/**
 * Delete package from available list.
 * @param al		available list
 * @param p	        package
 */
RPM_GNUC_INTERNAL
void rpmalDel(rpmal al, rpmte p);

/**
 * Add package to available list.
 * @param al	        available list
 * @param p             package
 */
RPM_GNUC_INTERNAL
void rpmalAdd(rpmal al, rpmte p);

/**
 * Lookup all obsoleters for a dependency in the available list
 * @param al		available list
 * @param ds		dependency set
 * @return		obsoleting packages for ds, NULL if none
 */
RPM_GNUC_INTERNAL
rpmte * rpmalAllObsoletes(const rpmal al, const rpmds ds);

/**
 * Lookup all providers for a dependency in the available list
 * @param al		available list
 * @param ds		dependency set
 * @return		best provider for the dependency, NULL if none
 */
RPM_GNUC_INTERNAL
rpmte * rpmalAllSatisfiesDepend(const rpmal al, const rpmds ds);

/**
 * Lookup best provider for a dependency in the available list
 * @param al		available list
 * @param te		transaction element
 * @param ds		dependency set
 * @return		best provider for the dependency, NULL if none
 */
RPM_GNUC_INTERNAL
rpmte rpmalSatisfiesDepend(const rpmal al, const rpmte te, const rpmds ds);

/**
 * Return index of a transaction element  in the available list
 * @param al           available list
 * @param te           transaction element
 * @return             index, (unsigned int)-1 if not found
 */
RPM_GNUC_INTERNAL
unsigned int rpmalLookupTE(const rpmal al, const rpmte te);

#endif	/* H_RPMAL */
