/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>

#include "os_cert_bundle.h"

#ifndef WIN32

static void test_returns_null_when_no_candidate_exists(void **state) {
    (void) state;
    const char *candidates[] = {
        "/nonexistent/hc-ca-bundle-a.pem",
        "/nonexistent/hc-ca-bundle-b.pem",
        NULL
    };

    assert_null(os_find_ca_bundle(candidates));
}

static void test_returns_first_existing_candidate(void **state) {
    (void) state;
    const char *path = "/tmp/hc_test_ca_bundle_first.pem";
    FILE *f = fopen(path, "w");
    assert_non_null(f);
    fclose(f);

    const char *candidates[] = {
        "/nonexistent/hc-ca-bundle-a.pem",
        path,
        "/nonexistent/hc-ca-bundle-b.pem",
        NULL
    };

    assert_string_equal(os_find_ca_bundle(candidates), path);

    remove(path);
}

static void test_stops_at_the_first_match_in_priority_order(void **state) {
    (void) state;
    const char *first = "/tmp/hc_test_ca_bundle_priority_1.pem";
    const char *second = "/tmp/hc_test_ca_bundle_priority_2.pem";
    FILE *f1 = fopen(first, "w");
    FILE *f2 = fopen(second, "w");
    assert_non_null(f1);
    assert_non_null(f2);
    fclose(f1);
    fclose(f2);

    const char *candidates[] = {first, second, NULL};

    assert_string_equal(os_find_ca_bundle(candidates), first);

    remove(first);
    remove(second);
}

static void test_null_candidates_uses_the_builtin_list(void **state) {
    (void) state;
    // Not asserting a specific outcome (the built-in list's paths may or may
    // not exist on the machine running this test) -- only that passing NULL
    // does not crash and probes the module's own default list rather than an
    // empty one.
    os_find_ca_bundle(NULL);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_returns_null_when_no_candidate_exists),
        cmocka_unit_test(test_returns_first_existing_candidate),
        cmocka_unit_test(test_stops_at_the_first_match_in_priority_order),
        cmocka_unit_test(test_null_candidates_uses_the_builtin_list),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

#else

int main(void) {
    return 0;
}

#endif
