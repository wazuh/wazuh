/* Copyright (C) Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef WAIT_OP_WRAPPERS_H
#define WAIT_OP_WRAPPERS_H
#include <stdbool.h>

void __wrap_os_wait_predicate(bool (*fn_ptr)());

bool __wrap_os_iswait(void);

#endif
