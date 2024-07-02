/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */
#ifndef STAT64_WRAPPERS_H
#define STAT64_WRAPPERS_H

#include <sys/stat.h>

#define _stat64(x, y) wrap__stat64(x, y)

int wrap__stat64(const char * __file, struct _stat64 * __buf);

#endif
