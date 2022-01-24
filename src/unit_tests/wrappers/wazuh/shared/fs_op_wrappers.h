/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef FS_OP_WRAPPERS_H
#define FS_OP_WRAPPERS_H

#include <stdbool.h>
#include <fs_op.h>

bool __wrap_HasFilesystem(const char * path, fs_set set);

#endif
