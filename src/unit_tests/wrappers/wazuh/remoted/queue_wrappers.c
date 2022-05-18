/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include "queue_wrappers.h"

size_t __wrap_rem_get_qsize() {
    return mock();
}

size_t __wrap_rem_get_tsize() {
    return mock();
}
