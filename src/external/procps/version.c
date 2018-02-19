/* Suite version information for procps utilities
 * Copyright (c) 1995 Martin Schulze <joey@infodrom.north.de>
 * Ammended by cblake to only export the function symbol.
 *
 * Modified by Albert Cahalan, ????-2003
 *
 * Redistributable under the terms of the
 * GNU Library General Public License; see COPYING
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include "version.h"


const char procps_version[] = "procps version 2.8.3";

void display_version(void) {
    fprintf(stdout, "%s\n", procps_version);
}

/* Linux kernel version information for procps utilities
 * Copyright (c) 1996 Charles Blake <cblake@bbn.com>
 */
#include <sys/utsname.h>

#define LINUX_VERSION(x,y,z)   (0x10000*(x) + 0x100*(y) + z)

int linux_version_code;

static void init_Linux_version(void) __attribute__((constructor));
static void init_Linux_version(void) {
    static struct utsname uts;
    int x = 0, y = 0, z = 0;	/* cleared in case sscanf() < 3 */

    if (uname(&uts) == -1)	/* failure implies impending death */
	exit(1);
    if (sscanf(uts.release, "%d.%d.%d", &x, &y, &z) < 3)
	fprintf(stderr,		/* *very* unlikely to happen by accident */
		"Non-standard uts for running kernel:\n"
		"release %s=%d.%d.%d gives version code %d\n",
		uts.release, x, y, z, LINUX_VERSION(x,y,z));
    linux_version_code = LINUX_VERSION(x, y, z);
}
