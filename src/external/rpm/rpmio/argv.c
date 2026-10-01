/** \ingroup rpmio
 * \file rpmio/argv.c
 */

#include "system.h"

#include <stdlib.h>
#include <rpm/argv.h>
#include <rpm/rpmstring.h>

#include "debug.h"

void argvPrint(const char * msg, ARGV_const_t argv, FILE * fp)
{
    ARGV_const_t av;

    if (fp == NULL) fp = stderr;

    if (msg)
	fprintf(fp, "===================================== %s\n", msg);

    if (argv)
    for (av = argv; *av; av++)
	fprintf(fp, "%s\n", *av);

}

ARGV_t argvNew(void)
{
    ARGV_t argv = (ARGV_t)xcalloc(1, sizeof(*argv));
    return argv;
}

ARGI_t argiFree(ARGI_t argi)
{
    if (argi) {
	argi->nvals = 0;
	free(argi->vals);
	free(argi);
    }
    return NULL;
}

ARGV_t argvFree(ARGV_t argv)
{
    if (argv) {
	for (ARGV_t av = argv; *av; av++)
	    free(*av);
	free(argv);
    }
    return NULL;
}

int argiCount(ARGI_const_t argi)
{
    int nvals = 0;
    if (argi)
	nvals = argi->nvals;
    return nvals;
}

ARGint_t argiData(ARGI_const_t argi)
{
    ARGint_t vals = NULL;
    if (argi && argi->nvals > 0)
	vals = argi->vals;
    return vals;
}

int argvCount(ARGV_const_t argv)
{
    int argc = 0;
    if (argv)
    while (argv[argc] != NULL)
	argc++;
    return argc;
}

ARGV_t argvData(ARGV_t argv)
{
    return argv;
}

int argvCmp(const void * a, const void * b)
{
    const char *astr = *(ARGV_t)a;
    const char *bstr = *(ARGV_t)b;
    return strcmp(astr, bstr);
}

int argvSort(ARGV_t argv, int (*compar)(const void *, const void *))
{
    if (compar == NULL)
	compar = argvCmp;
    if (argv)
	qsort(argv, argvCount(argv), sizeof(*argv), compar);
    return 0;
}

ARGV_t argvSearch(ARGV_const_t argv, const char *val,
		int (*compar)(const void *, const void *))
{
    if (argv == NULL)
	return NULL;
    if (compar == NULL)
	compar = argvCmp;
    return (ARGV_t)bsearch(&val, argv, argvCount(argv), sizeof(*argv), compar);
}

int argiAdd(ARGI_t * argip, int ix, int val)
{
    ARGI_t argi;

    if (argip == NULL)
	return -1;
    if (*argip == NULL)
	*argip = (ARGI_t)xcalloc(1, sizeof(**argip));
    argi = *argip;
    if (ix < 0)
	ix = argi->nvals;
    if (ix >= argi->nvals) {
	argi->vals = xrealloc(argi->vals, (ix + 1) * sizeof(*argi->vals));
	memset(argi->vals + argi->nvals, 0,
		(ix - argi->nvals) * sizeof(*argi->vals));
	argi->nvals = ix + 1;
    }
    argi->vals[ix] = val;
    return 0;
}

int argvAdd(ARGV_t * argvp, const char *val)
{
    return argvAddN(argvp, val, strlen(val));
}

int argvAddN(ARGV_t * argvp, const char *val, size_t len)
{
    ARGV_t argv;
    int argc;

    if (argvp == NULL)
	return -1;
    argc = argvCount(*argvp);
    *argvp = xrealloc(*argvp, (argc + 1 + 1) * sizeof(**argvp));
    argv = *argvp;

    argv[argc] = rstrndup(val, len);
    argv[argc + 1] = NULL;
    return 0;
}

int argvAddNum(ARGV_t *argvp, int val)
{
    char *valstr = NULL;
    int rc;
    rasprintf(&valstr, "%d", val);
    rc = argvAdd(argvp, valstr);
    free(valstr);
    return rc;
}

int argvAppend(ARGV_t * argvp, ARGV_const_t av)
{
    ARGV_t argv = *argvp;
    int argc = argvCount(argv);
    int ac = argvCount(av);
    int i;

    argv = xrealloc(argv, (argc + ac + 1) * sizeof(*argv));
    for (i = 0; i < ac; i++)
	argv[argc + i] = xstrdup(av[i]);
    argv[argc + ac] = NULL;
    *argvp = argv;
    return 0;
}

ARGV_t argvSplitString(const char * str, const char * seps, argvFlags flags)
{
    char *dest = NULL;
    ARGV_t argv;
    int argc = 1;
    const char * s;
    char * t;
    int c;

    if (str == NULL || seps == NULL)
	return NULL;

    dest = (char *)xmalloc(strlen(str) + 1);
    for (argc = 1, s = str, t = dest; (c = *s); s++, t++) {
	if (strchr(seps, c)) {
	    argc++;
	    c = '\0';
	}
	*t = c;
    }
    *t = '\0';

    argv = (ARGV_t)xmalloc( (argc + 1) * sizeof(*argv));

    for (c = 0, s = dest; s < t; s+= strlen(s) + 1) {
	if (*s == '\0' && (flags & ARGV_SKIPEMPTY))
	    continue;
	argv[c] = xstrdup(s);
	c++;
    }
    argv[c] = NULL;
    free(dest);
    return argv;
}

/* Backwards compatibility */
int argvSplit(ARGV_t * argvp, const char * str, const char * seps)
{
    if (argvp) {
	*argvp = argvSplitString(str, seps, ARGV_SKIPEMPTY);
    }
    return 0;
}

char *argvJoin(ARGV_const_t argv, const char *sep)
{
    int argc = 0;
    size_t argvlen = 0;
    char *dest = NULL;

    if (argv) {
	ARGV_const_t arg;
	for (arg = argv; *arg; arg++)
	    argvlen += strlen(*arg);
	argc = arg - argv;
    }

    if (argc > 0) {
	size_t seplen = (sep != NULL) ? strlen(sep) : 0;
	char *p;

	dest = (char *)xmalloc(argvlen + (seplen * (argc - 1)) + 1);

	p = stpcpy(dest, argv[0]);
	for (int i = 1; i < argc; i++) {
	    if (seplen)
		p = stpcpy(p, sep);
	    p = stpcpy(p, argv[i]);
	}
	*p = '\0';
    }

    return dest;
}
    
