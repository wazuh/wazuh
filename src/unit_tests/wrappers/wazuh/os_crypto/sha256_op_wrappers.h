/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef SHA256_OP_WRAPPERS_H
#define SHA256_OP_WRAPPERS_H

#include "../../../../headers/shared.h"
#include <string.h>
#include <sys/types.h>

typedef char os_sha256[65];

int __wrap_OS_SHA256_String(const char *str, os_sha256 output);

#endif
