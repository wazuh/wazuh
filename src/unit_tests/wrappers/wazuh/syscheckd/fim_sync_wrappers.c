/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "fim_sync_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

void __wrap_fim_sync_push_msg(const char * msg) {
    check_expected(msg);
}
