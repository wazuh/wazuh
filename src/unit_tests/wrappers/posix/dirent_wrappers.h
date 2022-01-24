/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef DIRENT_WRAPPERS_H
#define DIRENT_WRAPPERS_H

#include <dirent.h>

int __wrap_closedir(DIR *dirp);

int __wrap_opendir();

struct dirent * __wrap_readdir();

#endif
