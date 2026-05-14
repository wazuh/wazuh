/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef DLFCN_WRAPPERS_H
#define DLFCN_WRAPPERS_H

#include <dlfcn.h>

void * __wrap_dlopen(const char *filename, int flag);

int __wrap_dlclose(void *handle);

void * __wrap_dlsym(void *handle, const char *symbol);

char * __wrap_dlerror(void);

#endif
