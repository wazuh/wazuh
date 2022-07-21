/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef SYSCHECK_CONFIG_WRAPPERS
#define SYSCHECK_CONFIG_WRAPPERS

char **__wrap_expand_wildcards(const char *path);

#endif // SYSCHECK_CONFIG_WRAPPERS
