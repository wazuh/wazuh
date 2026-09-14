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
#include <stdbool.h>
#include <string.h>

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

static const char *const expected_builtin_candidates[] = {
    "/etc/ssl/certs/ca-certificates.crt",       // Debian systems
    "/etc/pki/tls/certs/ca-bundle.crt",         // Redhat and Mandriva
    "/usr/share/ssl/certs/ca-bundle.crt",       // RedHat
    "/usr/local/share/certs/ca-root-nss.crt",   // FreeBSD
    "/etc/ssl/cert.pem",                        // OpenBSD, FreeBSD, MacOS
    "/etc/ssl/ca-bundle.pem",                   // SUSE (SLES, openSUSE)
    NULL
};

static void test_builtin_list_probes_the_expected_paths_in_order(void **state) {
    (void) state;
    size_t i = 0;

    for (; expected_builtin_candidates[i] != NULL; ++i) {
        assert_non_null(os_ca_bundle_candidates[i]);
        assert_string_equal(os_ca_bundle_candidates[i], expected_builtin_candidates[i]);
    }

    assert_null(os_ca_bundle_candidates[i]);
}

static void test_builtin_list_holds_only_absolute_paths(void **state) {
    (void) state;

    for (size_t i = 0; os_ca_bundle_candidates[i] != NULL; ++i) {
        assert_int_equal(os_ca_bundle_candidates[i][0], '/');
        assert_int_not_equal(os_ca_bundle_candidates[i][strlen(os_ca_bundle_candidates[i]) - 1], '/');
    }
}

static void test_builtin_list_covers_the_suse_trust_store(void **state) {
    (void) state;
    bool found = false;

    for (size_t i = 0; os_ca_bundle_candidates[i] != NULL; ++i) {
        if (strcmp(os_ca_bundle_candidates[i], "/etc/ssl/ca-bundle.pem") == 0) {
            found = true;
            break;
        }
    }

    assert_true(found);
}

static void test_null_candidates_uses_the_builtin_list(void **state) {
    (void) state;

    const char *found = os_find_ca_bundle(NULL);

    if (found != NULL) {
        bool from_builtin = false;

        for (size_t i = 0; os_ca_bundle_candidates[i] != NULL; ++i) {
            if (os_ca_bundle_candidates[i] == found) {
                from_builtin = true;
                break;
            }
        }

        assert_true(from_builtin);
    }
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_returns_null_when_no_candidate_exists),
        cmocka_unit_test(test_returns_first_existing_candidate),
        cmocka_unit_test(test_stops_at_the_first_match_in_priority_order),
        cmocka_unit_test(test_builtin_list_probes_the_expected_paths_in_order),
        cmocka_unit_test(test_builtin_list_holds_only_absolute_paths),
        cmocka_unit_test(test_builtin_list_covers_the_suse_trust_store),
        cmocka_unit_test(test_null_candidates_uses_the_builtin_list),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

#else

int main(void) {
    return 0;
}

#endif
