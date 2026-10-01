#ifndef	H_RPMGI
#define	H_RPMGI

/** \ingroup rpmio
 * \file rpmgi.h
 */

#include <rpm/rpmtypes.h>
#include <rpm/argv.h>

/** \ingroup rpmgi
 */
enum rpmgiFlags_e {
    RPMGI_NONE		= 0,
    RPMGI_NOGLOB	= (1 << 2),
    RPMGI_NOMANIFEST	= (1 << 3),
};

typedef rpmFlags rpmgiFlags;

extern rpmgiFlags giFlags;

/** \ingroup rpmgi 
 * Destroy a generalized iterator.
 * @param gi		generalized iterator
 * @return		NULL always
 */
RPM_GNUC_INTERNAL
rpmgi rpmgiFree(rpmgi gi);

/** \ingroup rpmgi
 * Return a generalized iterator.
 * @param ts		transaction set
 * @param flags		iterator flags
 * @param argv		arg list
 * @return		new iterator
 */
RPM_GNUC_INTERNAL
rpmgi rpmgiNew(rpmts ts, rpmgiFlags flags, ARGV_const_t argv);

/** \ingroup rpmgi
 * Perform next iteration step.
 * @param gi		generalized iterator
 * @returns		next header (new reference), NULL on end of iteration
 */
RPM_GNUC_INTERNAL
Header rpmgiNext(rpmgi gi);

/** \ingroup rpmgi
 * Return number of errors (file not found etc) encountered during iteration
 * @param gi		generalized iterator
 * @return 		number of errors
 */
RPM_GNUC_INTERNAL
int rpmgiNumErrors(rpmgi gi);

#endif	/* H_RPMGI */
