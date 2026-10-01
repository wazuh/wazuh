#ifndef	H_RPMSQ
#define	H_RPMSQ

/** \ingroup rpmio
 * \file rpmsq.h
 *
 * Signal Queue API (obsolete, do not use)
 */
#include <rpm/rpmsw.h>
#include <signal.h>

#ifdef __cplusplus
extern "C" {
#endif

/** \ingroup rpmsq
 * Block or unblock (almost) all signals.
 * The operation is "reference counted" so the calls can be nested,
 * and signals are only unblocked when the reference count falls to zero.
 * @param op		SIG_BLOCK/SIG_UNBLOCK
 * @return		0 on success, -1 on error
 */
int rpmsqBlock(int op);

#ifdef __cplusplus
}
#endif

#endif	/* H_RPMSQ */
