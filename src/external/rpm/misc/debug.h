/**
 * To be included after all other includes.
 */
#ifndef	H_DEBUG
#define	H_DEBUG

#include <assert.h>

#define RPMDBG_TOSTR(a)		RPMDBG_TOSTR_ARG(a)
#define RPMDBG_TOSTR_ARG(a)	#a

#define RPMDBG()		"at: " __FILE__ ":" RPMDBG_TOSTR (__LINE__)
#define RPMDBG_M_DEBUG(msg)	msg " " RPMDBG()
#define RPMDBG_M_NODEBUG(msg)	NULL

#define RPMDBG_M(msg)		RPMDBG_M_DEBUG(msg)

#endif	/* H_DEBUG */
