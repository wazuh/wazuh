/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <setjmp.h>
#include <stdio.h>
#include <cmocka.h>
#include <stdlib.h>
#include <string.h>

#include "shared.h"
#include "active_responses.h"
#include "firewall_helpers.h"

#include "../wrappers/posix/unistd_wrappers.h"
#include "../wrappers/wazuh/shared/binaries_op_wrappers.h"
#include "../wrappers/wazuh/shared/exec_op_wrappers.h"

/* block-ip-macos.c is compiled directly into this target (see CMakeLists.txt)
 * with its `main` renamed at compile time, so these symbols aren't declared
 * in any shared header -- redeclare the ones under test here. */
firewall_result_t try_pf_macos(const char *srcip, int action, int ip_version, const char *argv0);
firewall_result_t try_hostsdeny_macos(const char *srcip, int action, int ip_version, const char *argv0);
firewall_result_t try_route_macos(const char *srcip, int action, int ip_version, const char *argv0);

static wfd_t *dummy_wfd(void) {
    static wfd_t wfd;
    memset(&wfd, 0, sizeof(wfd));
    return &wfd;
}

// ============================================================================
// try_route_macos: new in this PR, the fallback wazuh/wazuh#39192 was missing
// ============================================================================

void test_try_route_macos_binary_not_found(void **state) {
    expect_string(__wrap_get_binary_path, command, "route");
    will_return(__wrap_get_binary_path, NULL);
    will_return(__wrap_get_binary_path, -1);

    firewall_result_t result = try_route_macos("192.168.1.100", ENABLE_COMMAND, 4, "block-ip");

    assert_int_equal(result, FIREWALL_NOT_AVAILABLE);
}

void test_try_route_macos_command_fails(void **state) {
    char *route_path = strdup("/sbin/route");

    expect_string(__wrap_get_binary_path, command, "route");
    will_return(__wrap_get_binary_path, route_path);
    will_return(__wrap_get_binary_path, 0);
    will_return(__wrap_wpopenv, NULL);

    firewall_result_t result = try_route_macos("192.168.1.100", ENABLE_COMMAND, 4, "block-ip");

    assert_int_equal(result, FIREWALL_EXECUTION_FAILED);
}

void test_try_route_macos_enable_succeeds(void **state) {
    char *route_path = strdup("/sbin/route");

    expect_string(__wrap_get_binary_path, command, "route");
    will_return(__wrap_get_binary_path, route_path);
    will_return(__wrap_get_binary_path, 0);
    will_return(__wrap_wpopenv, dummy_wfd());
    will_return(__wrap_wpclose, 0);

    firewall_result_t result = try_route_macos("192.168.1.100", ENABLE_COMMAND, 4, "block-ip");

    assert_int_equal(result, FIREWALL_SUCCESS);
}

void test_try_route_macos_disable_succeeds(void **state) {
    char *route_path = strdup("/sbin/route");

    expect_string(__wrap_get_binary_path, command, "route");
    will_return(__wrap_get_binary_path, route_path);
    will_return(__wrap_get_binary_path, 0);
    will_return(__wrap_wpopenv, dummy_wfd());
    will_return(__wrap_wpclose, 0);

    firewall_result_t result = try_route_macos("192.168.1.100", DISABLE_COMMAND, 4, "block-ip");

    assert_int_equal(result, FIREWALL_SUCCESS);
}

void test_try_route_macos_ipv6_enable_succeeds(void **state) {
    char *route_path = strdup("/sbin/route");

    expect_string(__wrap_get_binary_path, command, "route");
    will_return(__wrap_get_binary_path, route_path);
    will_return(__wrap_get_binary_path, 0);
    will_return(__wrap_wpopenv, dummy_wfd());
    will_return(__wrap_wpclose, 0);

    firewall_result_t result = try_route_macos("2001:db8::1", ENABLE_COMMAND, 6, "block-ip");

    assert_int_equal(result, FIREWALL_SUCCESS);
}

// Exercises the exit-status check itself: wpopenv succeeds (non-NULL wfd) but
// the route command exited non-zero -- must be reported as a failure, not the
// false FIREWALL_SUCCESS this function returned before the fix.
void test_try_route_macos_nonzero_exit_is_failure(void **state) {
    char *route_path = strdup("/sbin/route");

    expect_string(__wrap_get_binary_path, command, "route");
    will_return(__wrap_get_binary_path, route_path);
    will_return(__wrap_get_binary_path, 0);
    will_return(__wrap_wpopenv, dummy_wfd());
    will_return(__wrap_wpclose, 1 << 8);  // WIFEXITED true, WEXITSTATUS 1

    firewall_result_t result = try_route_macos("192.168.1.100", ENABLE_COMMAND, 4, "block-ip");

    assert_int_equal(result, FIREWALL_EXECUTION_FAILED);
}

// ============================================================================
// try_pf_macos / try_hostsdeny_macos: pre-existing, unmodified by this PR --
// covering only the exact decline paths that reproduce #39192's stock-install
// symptom, which is what the new route fallback needs to trigger on.
// ============================================================================

void test_try_pf_macos_disabled_is_invalid_state(void **state) {
    char *pfctl_path = strdup("/sbin/pfctl");
    const char *pfctl_output = "Status: Disabled\n";
    FILE *info_stream = fmemopen((void *)pfctl_output, strlen(pfctl_output), "r");
    wfd_t info_wfd = { .file_in = NULL, .file_out = info_stream };

    expect_string(__wrap_get_binary_path, command, "pfctl");
    will_return(__wrap_get_binary_path, pfctl_path);
    will_return(__wrap_get_binary_path, 0);

    expect_string(__wrap_access, __name, "/dev/pf");
    expect_value(__wrap_access, __type, F_OK);
    will_return(__wrap_access, 0);

    will_return(__wrap_wpopenv, &info_wfd);
    will_return(__wrap_wpclose, 0);

    firewall_result_t result = try_pf_macos("192.168.1.100", ENABLE_COMMAND, 4, "block-ip");

    assert_int_equal(result, FIREWALL_INVALID_STATE);

    fclose(info_stream);
}

void test_try_hostsdeny_macos_missing_file_is_not_available(void **state) {
    expect_string(__wrap_access, __name, "/etc/hosts.deny");
    expect_value(__wrap_access, __type, F_OK);
    will_return(__wrap_access, -1);

    firewall_result_t result = try_hostsdeny_macos("192.168.1.100", ENABLE_COMMAND, 4, "block-ip");

    assert_int_equal(result, FIREWALL_NOT_AVAILABLE);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_try_route_macos_binary_not_found),
        cmocka_unit_test(test_try_route_macos_command_fails),
        cmocka_unit_test(test_try_route_macos_enable_succeeds),
        cmocka_unit_test(test_try_route_macos_disable_succeeds),
        cmocka_unit_test(test_try_route_macos_ipv6_enable_succeeds),
        cmocka_unit_test(test_try_route_macos_nonzero_exit_is_failure),
        cmocka_unit_test(test_try_pf_macos_disabled_is_invalid_state),
        cmocka_unit_test(test_try_hostsdeny_macos_missing_file_is_not_available),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
