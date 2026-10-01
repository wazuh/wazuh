/** \ingroup rpmcli
 * \file lib/manifest.c
 */

#include "system.h"

#include <string.h>

#include <popt.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmfileutil.h>
#include <rpm/argv.h>
#include <rpm/rpmstring.h>

#include "manifest.h"

#include "debug.h"


char * rpmPermsString(int mode)
{
    char *perms = xstrdup("----------");
   
    if (S_ISREG(mode)) 
	perms[0] = '-';
    else if (S_ISDIR(mode)) 
	perms[0] = 'd';
    else if (S_ISLNK(mode))
	perms[0] = 'l';
    else if (S_ISFIFO(mode)) 
	perms[0] = 'p';
    else if (S_ISSOCK(mode)) 
	perms[0] = 's';
    else if (S_ISCHR(mode))
	perms[0] = 'c';
    else if (S_ISBLK(mode))
	perms[0] = 'b';
    else
	perms[0] = '?';

    if (mode & S_IRUSR) perms[1] = 'r';
    if (mode & S_IWUSR) perms[2] = 'w';
    if (mode & S_IXUSR) perms[3] = 'x';
 
    if (mode & S_IRGRP) perms[4] = 'r';
    if (mode & S_IWGRP) perms[5] = 'w';
    if (mode & S_IXGRP) perms[6] = 'x';

    if (mode & S_IROTH) perms[7] = 'r';
    if (mode & S_IWOTH) perms[8] = 'w';
    if (mode & S_IXOTH) perms[9] = 'x';

    if (mode & S_ISUID)
	perms[3] = ((mode & S_IXUSR) ? 's' : 'S'); 

    if (mode & S_ISGID)
	perms[6] = ((mode & S_IXGRP) ? 's' : 'S'); 

    if (mode & S_ISVTX)
	perms[9] = ((mode & S_IXOTH) ? 't' : 'T');

    return perms;
}

/**@todo Infinite loops through manifest files exist, operator error for now. */
rpmRC rpmReadPackageManifest(FD_t fd, int * argcPtr, char *** argvPtr)
{
    ARGV_t p, sb = NULL;
    char * s = NULL;
    char * se;
    int ac = 0;
    char ** av = NULL;
    int argc = (argcPtr ? *argcPtr : 0);
    char ** argv = (argvPtr ? *argvPtr : NULL);
    FILE * f = fdopen(Fileno(fd), "r");
    rpmRC rpmrc = RPMRC_OK;
    int i, j, next, npre;

    if (f != NULL)
    while (1) {
	char line[BUFSIZ];
	int pac = 0;
	const char ** pav = NULL;

	/* Read next line. */
	s = fgets(line, sizeof(line) - 1, f);
	if (s == NULL) {
	    /* XXX Ferror check needed */
	    break;
	}

	/* Skip comments. */
	if (*s == '#')
	    continue;

	/* Trim white space. */
	se = s + strlen(s);
	while (se > s && (se[-1] == '\n' || se[-1] == '\r'))
	    *(--se) = '\0';
	while (*s && strchr(" \f\n\r\t\v", *s) != NULL)
	    s++;
	if (*s == '\0') continue;

	/* Sanity checks: skip obviously binary lines */
	if (*s < 32) {
	    s = NULL;
	    rpmrc = RPMRC_NOTFOUND;
	    goto exit;
	}

	/* Concatenate next line in buffer. */
	*se = '\0';

	poptParseArgvString(s, &pac, &pav);
	for (j = 0; j < pac; j++)
	    argvAdd(&sb, pav[j]);
	_free(pav);
    }

    if (sb == NULL) {
	rpmrc = RPMRC_NOTFOUND;
	goto exit;
    }

    /* Glob manifest items. */
    for (p = sb; *p; p++) {
	if (rpmGlobPath(*p, RPMGLOB_NOCHECK, &ac, &av)) {
	    rpmrc = RPMRC_FAIL;
	    goto exit;
	}
    }

    /* Sanity check: skip dash (for stdin) */
    for (i = 0; i < ac; i++) {
	if (rstreq(av[i], "-")) {
	    rpmrc = RPMRC_NOTFOUND;
	    goto exit;
	}
    }

    rpmlog(RPMLOG_DEBUG, "adding %d args from manifest.\n", ac);

    /* Count non-NULL args, keeping track of 1st arg after last NULL. */
    npre = 0;
    next = 0;
    if (argv != NULL)
    for (i = 0; i < argc; i++) {
	if (argv[i] != NULL)
	    npre++;
	else if (i >= next)
	    next = i + 1;
    }

    /* Copy old arg list, inserting manifest before argv[next]. */
    if (argv != NULL) {
	int nac = npre + ac;
	char ** nav = (char **)xcalloc((nac + 1), sizeof(*nav));

	for (i = 0, j = 0; i < next; i++) {
	    if (argv[i] != NULL)
		nav[j++] = argv[i];
	}

	if (ac)
	    memcpy(nav + j, av, ac * sizeof(*nav));
	if ((argc - next) > 0)
	    memcpy(nav + j + ac, argv + next, (argc - next) * sizeof(*nav));
	nav[nac] = NULL;

	if (argvPtr)
	    *argvPtr = argv = _free(argv);
	av = _free(av);
	av = nav;
	ac = nac;
    }

    /* Save new argc/argv list. */
    if (argvPtr) {
	*argvPtr = _free(*argvPtr);
	*argvPtr = av;
    }
    if (argcPtr)
	*argcPtr = ac;

exit:
    if (f)
	fclose(f);
    if (argvPtr == NULL || (rpmrc != RPMRC_OK && av)) {
	if (av)
	for (i = 0; i < ac; i++)
	   av[i] = _free(av[i]);
	av = _free(av);
    }
    argvFree(sb);
    free(s);
    /* FIX: *argvPtr may be NULL. */
    return rpmrc;
}
