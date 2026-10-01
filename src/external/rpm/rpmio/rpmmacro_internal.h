#ifndef _H_MACRO_INTERNAL
#define	_H_MACRO_INTERNAL

#include <rpm/rpmutil.h>
#include <rpm/argv.h>

/** \ingroup rpmio
 * \file rpmmacro_internal.h
 *
 * Internal Macro API
 */

/** \ingroup rpmmacro
 * Find the end of a macro call
 * @param str           pointer to the character after the initial '%'
 * @return              pointer to the next character after the macro
 */
RPM_GNUC_INTERNAL
const char *findMacroEnd(const char *str);

typedef int (*rgetoptcb)(int c, const char *oarg, int oint, void *data);

RPM_GNUC_INTERNAL
int rgetopt(int argc, char * const argv[], const char *opts,
		rgetoptcb callback, void *data);

RPM_GNUC_INTERNAL
void splitQuoted(ARGV_t *av, const char * str, const char * seps);

RPM_GNUC_INTERNAL
char *unsplitQuoted(ARGV_const_t av, const char *sep);

#endif	/* _H_ MACRO_INTERNAL */
