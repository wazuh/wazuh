/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef OS_AUTH_WRAPPERS_H
#define OS_AUTH_WRAPPERS_H

#include "sec.h"
#include "shared.h"

void __wrap_add_remove(const keyentry* entry);

#endif
