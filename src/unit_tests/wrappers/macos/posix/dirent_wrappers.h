/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef DIRENT_WRAPPERS_MACOS_H
#define DIRENT_WRAPPERS_MACOS_H

#include <dirent.h>

#undef closedir
#define closedir wrap_closedir
#undef opendir
#define opendir wrap_opendir
#undef readdir
#define readdir wrap_readdir

int wrap_closedir(__attribute__((unused)) DIR *dirp);

DIR * wrap_opendir(const char *filename);

struct dirent * wrap_readdir(DIR *dirp);

#endif
