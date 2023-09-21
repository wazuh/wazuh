/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef BINARIES_OP_WRAPPERS_H
#define BINARIES_OP_WRAPPERS_H


int __wrap_get_binary_path(const char *command, char **path);

#endif
