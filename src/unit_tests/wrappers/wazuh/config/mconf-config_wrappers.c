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
#include "mconf-config_wrappers.h"

int __wrap_w_mconf_load(const char *cfgfile) {
    check_expected(cfgfile);

    return mock_type(int);
}

cJSON *__wrap_w_mconf_section(const char *section) {
    check_expected(section);

    return mock_type(cJSON *);
}
