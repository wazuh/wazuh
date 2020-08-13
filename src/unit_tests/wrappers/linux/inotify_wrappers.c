/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "inotify_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>


int __wrap_inotify_add_watch() {
    return mock();
}

int __wrap_inotify_init() {
    return mock();
}

int __wrap_inotify_rm_watch() {
    return mock();
}
