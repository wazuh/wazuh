#include "system.h"
#include <string.h>
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#else
extern char *optarg;
extern int optind;
#endif

#include <rpm/argv.h>
#include "rpmmacro_internal.h"

int rgetopt(int argc, char * const argv[], const char *opts,
		rgetoptcb callback, void *data)
{
    int rc = 0;
    int c;

    /* If option processing is disabled, get out */
    if (strcmp(opts, "-") == 0)
	return 1;

    /*
     * POSIX states optind must be 1 before any call but glibc uses 0
     * to (re)initialize getopt structures, eww.
     */
#ifdef __GLIBC__
    optind = 0;
#else
    optind = 1;
    optarg = NULL;
#endif

    while ((c = getopt(argc, argv, opts)) != -1) {
	if (c == '?' || strchr(opts, c) == NULL) {
	    rc = -1;
	    break;
	}
	if (callback && callback(c, optarg, optind, data) == -1) {
	    rc = -1;
	    break;
	}
	optarg = NULL;
    }
    return (rc < 0) ? -optopt : optind;
}

