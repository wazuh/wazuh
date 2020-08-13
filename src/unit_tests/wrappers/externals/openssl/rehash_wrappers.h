/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef REHASH_WRAPPERS_H
#define REHASH_WRAPPERS_H


int __wrap_readlink(void **state);

int __wrap_symlink(const char *path1, const char *path2);

#endif
