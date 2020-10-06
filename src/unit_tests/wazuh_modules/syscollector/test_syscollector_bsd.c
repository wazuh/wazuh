/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Test corresponding to the syscollector capacities
 * for BSD and MAC
 * */


#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <time.h>

#include "shared.h"
#include "../../../wazuh_modules/syscollector/syscollector.h"
#include "../../../wazuh_modules/wmodules.h"

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_normalize_mac_package_name)
    };
}