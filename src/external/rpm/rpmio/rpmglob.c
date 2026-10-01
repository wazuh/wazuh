#include "system.h"

/* Copyright (C) 1991,92,93,94,95,96,97,98,99 Free Software Foundation, Inc.

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with this library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

#include "system.h"

#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <pwd.h>
#include <assert.h>
#include <sys/stat.h>		/* S_ISDIR */
#include <fnmatch.h>
#include <glob.h>

#include <rpm/rpmfileutil.h>
#include <rpm/rpmurl.h>

#include "debug.h"

/* Return 1 if pattern contains a magic char, see glob(7) for a list */
static int ismagic(const char *pattern)
{
    for (const char *p = pattern; *p != '\0'; p++)
	switch (*p) {
	case '?':
	case '*':
	case '[':
	case '{':
	case '\\':
	case '~':
	    return 1;
	}
    return 0;
}

/* librpmio exported interfaces */

int rpmGlobPath(const char * pattern, rpmglobFlags flags,
		int * argcPtr, ARGV_t * argvPtr)
{
    int argc = 0;
    ARGV_t argv = NULL;
    const char *home = getenv("HOME");
    const char *path;
    int local = (urlPath(pattern, &path) == URL_IS_UNKNOWN);
    size_t plen = strlen(path);
    int dir_only = (plen > 0 && path[plen-1] == '/');
    glob_t gl;
    int gflags = 0;
    int i;
    int rc = 0;

#ifdef ENABLE_NLS
    char * old_collate = NULL;
    char * old_ctype = NULL;
    const char * t;
#endif

    if (argvPtr == NULL)
	/* We still want to count matches so use a scratch list */
	argvPtr = &argv;

    if ((flags & RPMGLOB_NOCHECK) && (!local || !ismagic(pattern))) {
	argvAdd(argvPtr, pattern);
	goto exit;
    }

    gflags |= GLOB_BRACE;
    if (home != NULL && strlen(home) > 0) 
	gflags |= GLOB_TILDE;
#if HAVE_GLOB_ONLYDIR
    if (dir_only)
	gflags |= GLOB_ONLYDIR;
#endif
    if (flags & RPMGLOB_NOCHECK)
	gflags |= GLOB_NOCHECK;

#ifdef ENABLE_NLS
    t = setlocale(LC_COLLATE, NULL);
    if (t)
    	old_collate = xstrdup(t);
    t = setlocale(LC_CTYPE, NULL);
    if (t)
    	old_ctype = xstrdup(t);
    (void) setlocale(LC_COLLATE, C_LOCALE);
    (void) setlocale(LC_CTYPE, C_LOCALE);
#endif
    
    gl.gl_pathc = 0;
    gl.gl_pathv = NULL;
    
    rc = glob(pattern, gflags, NULL, &gl);
    if (rc)
	goto exit;

    for (i = 0; i < gl.gl_pathc; i++) {
	if (dir_only && !(flags & RPMGLOB_NOCHECK)) {
	    struct stat sb;
	    if (lstat(gl.gl_pathv[i], &sb) || !S_ISDIR(sb.st_mode))
		continue;
	}
	argvAdd(argvPtr, gl.gl_pathv[i]);
    }
    globfree(&gl);

exit:
    argc = argvCount(*argvPtr);
    argvFree(argv);
    if (argcPtr)
	*argcPtr = argc;
    if (argc == 0 && rc == 0)
	rc = GLOB_NOMATCH;

#ifdef ENABLE_NLS	
    if (old_collate) {
	(void) setlocale(LC_COLLATE, old_collate);
	free(old_collate);
    }
    if (old_ctype) {
	(void) setlocale(LC_CTYPE, old_ctype);
	free(old_ctype);
    }
#endif

    return rc;
}

int rpmGlob(const char * pattern, int * argcPtr, ARGV_t * argvPtr)
{
    return rpmGlobPath(pattern, RPMGLOB_NONE, argcPtr, argvPtr);
}
