/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef unistd_WRAPPERS_WINDOWS_H
#define unistd_WRAPPERS_WINDOWS_H

#include <unistd.h>
#define gethostname wrap_gethostname

int wrap_gethostname(char *name, int len);

#endif
