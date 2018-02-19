// Copyright (C) 1992-1998 by Michael K. Johnson, johnsonm@redhat.com
// Copyright 2002 Albert Cahalan
//
// This file is placed under the conditions of the GNU Library
// General Public License, version 2, or any later version.
// See file COPYING for information on distribution conditions.

#include <stdlib.h>
#include <stdio.h>
#include "alloc.h"

void *xcalloc(void *pointer, int size) {
    void * ret;
    if (pointer)
        free(pointer);
    if (!(ret = calloc(1, size))) {
        fprintf(stderr, "xcalloc: allocation error, size = %d\n", size);
        exit(1);
    }
    return ret;
}

void *xmalloc(unsigned int size) {
    void *p;

    if (size == 0)
        ++size;
    p = malloc(size);
    if (!p) {
	fprintf(stderr, "xmalloc: malloc(%d) failed", size);
	perror(NULL);
	exit(1);
    }
    return(p);
}

void *xrealloc(void *oldp, unsigned int size) {
    void *p;

    if (size == 0)
        ++size;
    p = realloc(oldp, size);
    if (!p) {
	fprintf(stderr, "xrealloc: realloc(%d) failed", size);
	perror(NULL);
	exit(1);
    }
    return(p);
}
