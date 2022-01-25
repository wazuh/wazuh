/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef IO_WIN_WRAPPERS_H
#define IO_WIN_WRAPPERS_H

#include <io.h>

#undef _mktemp_s
#define _mktemp_s  wrap_mktemp_s

char * wrap_mktemp_s(const char *path, ssize_t length);

#endif
