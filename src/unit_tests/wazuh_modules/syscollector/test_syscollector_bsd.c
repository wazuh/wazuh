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


static void test_normalize_mac_package_name(void **state) {
#if defined(__FreeBSD__) || defined(__MACH__)
    int ret;
    int i;
    char * vendor = NULL;
    char * package = NULL;
    char * source_package[6][3] = {
        {"Microsoft Word", "Microsoft", "Word"},
        {"Microsoft Word", "Microsoft", "Excel"},
        {"VMware Fusion", "VMware", "Fusion"},
        {"VMware Fusion", "VMware", "Horizon Client"},
        {"1Password 7", NULL, "1Password"},
        {"zoom.us", NULL, "zoom"},
    };

    for (i = 0; i < 6; i++) {
        ret = normalize_mac_package_name(source_package[i][0], &vendor, &package);
        assert_int_equal(ret, 1);
        if (source_package[i][1]) {
            assert_string_equal(vendor, source_package[i][1]);
            os_free(vendor);
        }
        assert_string_equal(package, source_package[i][2]);
        os_free(package);
    }

    assert_int_equal(0, normalize_mac_package_name("Foxit Reader", &vendor, &package));
    os_free(package);
#endif
}


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_normalize_mac_package_name)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
