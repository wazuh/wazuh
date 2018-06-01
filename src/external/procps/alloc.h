#ifndef PROCPS_PROC_ALLOC_H
#define PROCPS_PROC_ALLOC_H

#include "procps.h"

EXTERN_C_BEGIN

extern void *xrealloc(void *oldp, unsigned int size) MALLOC;
extern void *xmalloc(unsigned int size) MALLOC;
extern void *xcalloc(void *pointer, int size) MALLOC;

EXTERN_C_END

#endif
