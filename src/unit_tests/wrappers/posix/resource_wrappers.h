/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef RESOURCE_WRAPPERS_H
#define RESOURCE_WRAPPERS_H

#ifndef WIN32
#include <sys/resource.h>

int __wrap_getrlimit(int resource, struct rlimit *rlim);

int __wrap_setrlimit(int resource, const struct rlimit *rlim);
#endif

#endif
