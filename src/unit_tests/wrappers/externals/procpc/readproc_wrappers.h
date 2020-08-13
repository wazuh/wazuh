/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef READPROC_WRAPPERS_H
#define READPROC_WRAPPERS_H

#include "external/procps/readproc.h"

void __wrap_closeproc(PROCTAB* PT);


void __wrap_freeproc(proc_t* p);

PROCTAB* __wrap_openproc(int flags, ...);

proc_t* __wrap_readproc(PROCTAB *restrict const PT,
                        proc_t *restrict p);

#endif
