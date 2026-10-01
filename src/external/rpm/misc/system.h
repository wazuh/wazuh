/**
 * \file system.h
 *
 *  Some misc low-level API
 */

#ifndef	H_SYSTEM
#define	H_SYSTEM

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

/* <unistd.h> should be included before any preprocessor test
   of _POSIX_VERSION.  */
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#if !defined(__GLIBC__)
#ifdef __APPLE__
#include <crt_externs.h>
#define environ (*_NSGetEnviron())
#else
extern char ** environ;
#endif /* __APPLE__ */
#endif
#endif

#if defined(HAVE_SECURE_GETENV)
#define	getenv(_s)	secure_getenv(_s)
#elif defined(HAVE___SECURE_GETENV)
#define	getenv(_s)	__secure_getenv(_s)
#endif

#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif

#ifndef PATH_MAX
#ifdef _POSIX_PATH_MAX
#define PATH_MAX _POSIX_PATH_MAX
#elif defined MAXPATHLEN
#define PATH_MAX MAXPATHLEN
#else
#define PATH_MAX 256
#endif
#endif

#if defined(HAVE_FDATASYNC) && !HAVE_DECL_FDATASYNC
extern int fdatasync(int fildes);
#endif

#include <rpm/rpmutil.h>
/* compatibility macros to avoid a mass-renaming all over the codebase */
#define xmalloc(_size) rmalloc((_size))
#define xmallocn(_nmemb, _size) rreallocn(NULL, (_nmemb), (_size))
#define xcalloc(_nmemb, _size) rcalloc((_nmemb), (_size))
#define xrealloc(_ptr, _size) rrealloc((_ptr), (_size))
#define xreallocn(_ptr, _nmemb, _size) rreallocn((_ptr), (_nmemb), (_size))
#define xstrdup(_str) rstrdup((_str))
#define _free(_ptr) rfree((_ptr))

/* To extract program's name: use calls (reimplemented or shipped with system):
   - void setprogname(const char *pn)
   - const char *getprogname(void)

   setprogname(*pn) must be the first call in main() in order to set the name
   as soon as possible. */
#if defined(HAVE_SETPROGNAME) /* BSD'ish systems */
# include <stdlib.h> /* Make sure this header is included */
# define xsetprogname(pn) setprogname(pn)
# define xgetprogname(pn) getprogname(pn)
#elif defined(HAVE___PROGNAME) /* glibc and others */
# define xsetprogname(pn)
  extern const char *__progname;
# define xgetprogname(pn) __progname
#else
# error "Did not find any sutable implementation of xsetprogname/xgetprogname"
#endif

/* Take care of NLS matters.  */
#if defined(ENABLE_NLS)
# include <locale.h>
# include <libintl.h>
# define _(Text) dgettext (PACKAGE, Text)
#else
# define _(Text) Text
#endif

#define N_(Text) Text

#endif	/* H_SYSTEM */
