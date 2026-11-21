/* Copyright (C) Wazuh Inc.
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

#include "../wrappers/common.h"
#include "../wrappers/posix/unistd_wrappers.h"
#include "../wrappers/wazuh/shared/binaries_op_wrappers.h"
#include "../wrappers/wazuh/shared/exec_op_wrappers.h"
#include "../wrappers/wazuh/shared/file_op_wrappers.h"

/* block-ip-macos.c is compiled directly into this target (see CMakeLists.txt)
 * with its `main` renamed at compile time, so these symbols aren't declared
 * in any shared header -- redeclare the ones under test here. */
firewall_result_t try_pf_macos(const char *srcip, int action, int ip_version, const char *argv0);
firewall_result_t try_route_macos(const char *srcip, int action, int ip_version, const char *argv0);
bool remove_legacy_hostsdeny_rule(const char *srcip, const char *argv0);
int block_ip_macos_main(int argc, char **argv);

/* setup_and_check_message/get_srcip_from_json/send_keys_and_check_message are
 * real functions in active_responses.c (linked in via the shared library,
 * not compiled into this target), wrapped here -- target-locally, via this
 * target's own CMakeLists.txt flags, not a shared wrapper file -- purely so
 * test_block_ip_macos_main_* below can drive block_ip_macos_main() end to
 * end without needing to fake the real JSON-on-stdin protocol. */
int __wrap_setup_and_check_message(__attribute__((unused)) char **argv, cJSON **message) {
    *message = mock_ptr_type(cJSON *);
    return mock_type(int);
}

const char *__wrap_get_srcip_from_json(__attribute__((unused)) const cJSON *input) {
    return mock_ptr_type(const char *);
}

int __wrap_send_keys_and_check_message(__attribute__((unused)) char **argv, __attribute__((unused)) char **keys) {
    return mock_type(int);
}

// The hosts.deny lock is a mkdir under the install dir; counted so the tests can
// check every path that took it also released it.
static int lock_releases = 0;

int __wrap_acquire_ar_lock(__attribute__((unused)) lock_context_t *ctx) {
    return mock_type(int);
}

void __wrap_release_ar_lock(__attribute__((unused)) lock_context_t *ctx) {
    lock_releases++;
}

// try_route_macos now drains wfd->file_out (W_BIND_STDERR) before wpclose,
// so every mocked wfd needs a real, readable stream -- stderr_text is what
// route(8) is simulated to have printed (pass "" for the success paths that
// don't care about it).
static wfd_t *dummy_wfd(const char *stderr_text) {
    static wfd_t wfd;
    // fmemopen() rejects a zero-length buffer on some libc implementations
    // (POSIX leaves size==0 undefined) -- fall back to a single blank line.
    static const char empty[] = "\n";
    memset(&wfd, 0, sizeof(wfd));
    size_t len = strlen(stderr_text);
    wfd.file_out = len > 0 ? fmemopen((void *)stderr_text, len, "r")
                            : fmemopen((void *)empty, strlen(empty), "r");
    return &wfd;
}

/* dummy_wfd() above returns one shared static, enough for the single-spawn
 * route tests. try_pf_macos() spawns pfctl up to four times per call, so its
 * tests need one wfd_t and stream each. __wrap_wpclose() frees neither. */
#define MAX_MOCK_WFD 8
static wfd_t *mock_wfds[MAX_MOCK_WFD];
static int mock_wfd_count = 0;

static wfd_t *make_wfd(const char *output) {
    /* fmemopen() leaves size==0 undefined */
    static const char empty[] = "\n";
    const char *text = (output && *output) ? output : empty;

    wfd_t *wfd = calloc(1, sizeof(wfd_t));
    assert_non_null(wfd);
    wfd->file_out = fmemopen((void *)text, strlen(text), "r");
    assert_non_null(wfd->file_out);

    assert_true(mock_wfd_count < MAX_MOCK_WFD);
    mock_wfds[mock_wfd_count++] = wfd;
    return wfd;
}

static int teardown_wfds(void **state) {
    (void)state;
    for (int i = 0; i < mock_wfd_count; i++) {
        if (mock_wfds[i]->file_out) {
            fclose(mock_wfds[i]->file_out);
        }
        free(mock_wfds[i]);
    }
    mock_wfd_count = 0;
    return 0;
}

/* try_pf_macos()'s prologue: pfctl found, /dev/pf reachable, PF enabled. */
static void expect_pf_enabled(void) {
    expect_string(__wrap_get_binary_path, command, "pfctl");
    will_return(__wrap_get_binary_path, strdup("/sbin/pfctl"));
    will_return(__wrap_get_binary_path, 0);

    expect_string(__wrap_access, __name, "/dev/pf");
    expect_value(__wrap_access, __type, F_OK);
    will_return(__wrap_access, 0);

    will_return(__wrap_wpopenv, make_wfd("Status: Enabled\n"));
    will_return(__wrap_wpclose, 0);
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
    will_return(__wrap_wpopenv, dummy_wfd(""));
    will_return(__wrap_wpclose, 0);

    firewall_result_t result = try_route_macos("192.168.1.100", ENABLE_COMMAND, 4, "block-ip");

    assert_int_equal(result, FIREWALL_SUCCESS);
    // Only stderr may be bound: an empty capture is the success signal, and
    // binding stdout would put route's always-present line in it
    assert_int_equal(wpopenv_captured_flags(), W_BIND_STDERR);
    // Confirms the exact command run, not just that *some* command succeeded
    // -- the mock ignores argv on its own, see wpopenv_captured_argv()'s doc.
    assert_int_equal(wpopenv_captured_argc(), 6);
    assert_string_equal(wpopenv_captured_argv(0), "/sbin/route");  // route_path itself is already os_free()d inside try_route_macos by this point
    assert_string_equal(wpopenv_captured_argv(1), "-q");
    assert_string_equal(wpopenv_captured_argv(2), "add");
    assert_string_equal(wpopenv_captured_argv(3), "192.168.1.100");
    assert_string_equal(wpopenv_captured_argv(4), "127.0.0.1");
    assert_string_equal(wpopenv_captured_argv(5), "-blackhole");
}

void test_try_route_macos_disable_succeeds(void **state) {
    char *route_path = strdup("/sbin/route");

    expect_string(__wrap_get_binary_path, command, "route");
    will_return(__wrap_get_binary_path, route_path);
    will_return(__wrap_get_binary_path, 0);
    will_return(__wrap_wpopenv, dummy_wfd(""));
    will_return(__wrap_wpclose, 0);

    firewall_result_t result = try_route_macos("192.168.1.100", DISABLE_COMMAND, 4, "block-ip");

    assert_int_equal(result, FIREWALL_SUCCESS);
    assert_int_equal(wpopenv_captured_argc(), 6);
    assert_string_equal(wpopenv_captured_argv(0), "/sbin/route");  // route_path itself is already os_free()d inside try_route_macos by this point
    assert_string_equal(wpopenv_captured_argv(1), "-q");
    assert_string_equal(wpopenv_captured_argv(2), "delete");
    assert_string_equal(wpopenv_captured_argv(3), "192.168.1.100");
    assert_string_equal(wpopenv_captured_argv(4), "127.0.0.1");
    assert_string_equal(wpopenv_captured_argv(5), "-blackhole");
}

void test_try_route_macos_ipv6_enable_succeeds(void **state) {
    char *route_path = strdup("/sbin/route");

    expect_string(__wrap_get_binary_path, command, "route");
    will_return(__wrap_get_binary_path, route_path);
    will_return(__wrap_get_binary_path, 0);
    will_return(__wrap_wpopenv, dummy_wfd(""));
    will_return(__wrap_wpclose, 0);

    firewall_result_t result = try_route_macos("2001:db8::1", ENABLE_COMMAND, 6, "block-ip");

    assert_int_equal(result, FIREWALL_SUCCESS);
    // This is the exact assertion the argv-blind mock couldn't make before:
    // -inet6 present, and the gateway is the IPv6 loopback, not 127.0.0.1.
    assert_int_equal(wpopenv_captured_argc(), 7);
    assert_string_equal(wpopenv_captured_argv(0), "/sbin/route");  // route_path itself is already os_free()d inside try_route_macos by this point
    assert_string_equal(wpopenv_captured_argv(1), "-q");
    assert_string_equal(wpopenv_captured_argv(2), "add");
    assert_string_equal(wpopenv_captured_argv(3), "-inet6");
    assert_string_equal(wpopenv_captured_argv(4), "2001:db8::1");
    assert_string_equal(wpopenv_captured_argv(5), "::1");
    assert_string_equal(wpopenv_captured_argv(6), "-blackhole");
}

// Exercises the exit-status check itself: wpopenv succeeds (non-NULL wfd) but
// the route command exited non-zero for a reason that is NOT the known
// already-blocked/already-clear case below -- must be reported as a failure,
// not the false FIREWALL_SUCCESS this function returned before the fix.
void test_try_route_macos_nonzero_exit_is_failure(void **state) {
    char *route_path = strdup("/sbin/route");

    expect_string(__wrap_get_binary_path, command, "route");
    will_return(__wrap_get_binary_path, route_path);
    will_return(__wrap_get_binary_path, 0);
    will_return(__wrap_wpopenv, dummy_wfd("add net 192.168.1.100: gateway 127.0.0.1: Network is unreachable\n"));
    will_return(__wrap_wpclose, 1 << 8);  // WIFEXITED true, WEXITSTATUS 1

    firewall_result_t result = try_route_macos("192.168.1.100", ENABLE_COMMAND, 4, "block-ip");

    assert_int_equal(result, FIREWALL_EXECUTION_FAILED);
}

// route(8) exits non-zero (EEXIST) when the blackhole route is already
// present -- a repeat ENABLE for an already-blocked IP must not be reported
// as a total chain failure. Verified against Apple's route.tproj/route.c:
// EEXIST falls through to strerror(), which is "File exists" on macOS/BSD.
void test_try_route_macos_enable_already_blocked_is_success(void **state) {
    char *route_path = strdup("/sbin/route");

    expect_string(__wrap_get_binary_path, command, "route");
    will_return(__wrap_get_binary_path, route_path);
    will_return(__wrap_get_binary_path, 0);
    will_return(__wrap_wpopenv, dummy_wfd("add net 192.168.1.100: gateway 127.0.0.1: File exists\n"));
    will_return(__wrap_wpclose, 1 << 8);  // WIFEXITED true, WEXITSTATUS 1

    firewall_result_t result = try_route_macos("192.168.1.100", ENABLE_COMMAND, 4, "block-ip");

    assert_int_equal(result, FIREWALL_SUCCESS);
}

// route(8) exits non-zero (ESRCH -> "not in table") when a DISABLE is
// requested for a route that's already gone -- the end state is the one asked
// for, so it is a success.
// Verified against Apple's route.tproj/route.c: route_strerror() maps ESRCH
// to the literal string "not in table".
void test_try_route_macos_disable_not_in_table_is_success(void **state) {
    char *route_path = strdup("/sbin/route");

    expect_string(__wrap_get_binary_path, command, "route");
    will_return(__wrap_get_binary_path, route_path);
    will_return(__wrap_get_binary_path, 0);
    will_return(__wrap_wpopenv, dummy_wfd("delete net 192.168.1.100: not in table\n"));
    will_return(__wrap_wpclose, 1 << 8);  // WIFEXITED true, WEXITSTATUS 1

    firewall_result_t result = try_route_macos("192.168.1.100", DISABLE_COMMAND, 4, "block-ip");

    assert_int_equal(result, FIREWALL_SUCCESS);
}

// ============================================================================
// try_pf_macos: the decline path that reproduces the stock-install symptom,
// which is what the route fallback triggers on.
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

// ============================================================================
// try_pf_macos: wazuh_fwtable existence check
// ============================================================================

/* Declines without touching /etc/pf.conf. cmocka enforces the "without":
 * a further access()/wpopenv() has no queued expectation and fails. */
void test_try_pf_macos_missing_table_declines(void **state) {
    (void)state;

    expect_pf_enabled();

    /* pfctl -T show: exit 255, table absent */
    will_return(__wrap_wpopenv, make_wfd("pfctl: Table does not exist.\n"));
    will_return(__wrap_wpclose, 255 << 8);

    firewall_result_t result = try_pf_macos("192.0.2.66", ENABLE_COMMAND, 4, "block-ip");

    assert_int_equal(result, FIREWALL_INVALID_STATE);
}

/* Undrained output makes wpclose() kill pfctl with SIGPIPE, so an existing
 * table reads as missing. feof() pins the drain in place. */
void test_try_pf_macos_existing_table_check_output_is_drained(void **state) {
    (void)state;

    expect_pf_enabled();

    wfd_t *show_wfd = make_wfd("   192.0.2.1\n   192.0.2.2\n   192.0.2.3\n");
    will_return(__wrap_wpopenv, show_wfd);
    will_return(__wrap_wpclose, 0);

    /* pfctl -T add, then pfctl -k -- the kill's pipe carries the ALTQ warnings
     * and has to be drained too, or pfctl dies before DIOCKILLSTATES */
    will_return(__wrap_wpopenv, make_wfd(""));
    will_return(__wrap_wpclose, 0);
    wfd_t *kill_wfd = make_wfd("No ALTQ support in kernel\nALTQ related functions disabled\n");
    will_return(__wrap_wpopenv, kill_wfd);
    will_return(__wrap_wpclose, 0);

    firewall_result_t result = try_pf_macos("192.0.2.66", ENABLE_COMMAND, 4, "block-ip");

    assert_int_equal(result, FIREWALL_SUCCESS);
    assert_true(feof(show_wfd->file_out));
    assert_true(feof(kill_wfd->file_out));
    // The last spawn on the block path is the connection kill
    assert_int_equal(wpopenv_captured_argc(), 3);
    assert_string_equal(wpopenv_captured_argv(1), "-k");
    assert_string_equal(wpopenv_captured_argv(2), "192.0.2.66");
}

/* A signalled check answers nothing, so it must not read as "table present". */
void test_try_pf_macos_signalled_table_check_declines(void **state) {
    (void)state;

    expect_pf_enabled();

    will_return(__wrap_wpopenv, make_wfd("No ALTQ support in kernel\n"));
    will_return(__wrap_wpclose, SIGPIPE);

    firewall_result_t result = try_pf_macos("192.0.2.66", ENABLE_COMMAND, 4, "block-ip");

    assert_int_equal(result, FIREWALL_INVALID_STATE);
}

/* A check that cannot be spawned is an execution failure, not a missing table,
 * and still must not reach /etc/pf.conf. */
void test_try_pf_macos_table_check_spawn_failure_is_execution_failed(void **state) {
    (void)state;

    expect_pf_enabled();

    will_return(__wrap_wpopenv, NULL);

    firewall_result_t result = try_pf_macos("192.0.2.66", ENABLE_COMMAND, 4, "block-ip");

    assert_int_equal(result, FIREWALL_EXECUTION_FAILED);
}

/* Same on the unblock path. */
void test_try_pf_macos_missing_table_declines_on_disable(void **state) {
    (void)state;

    expect_pf_enabled();

    will_return(__wrap_wpopenv, make_wfd("pfctl: Table does not exist.\n"));
    will_return(__wrap_wpclose, 255 << 8);

    firewall_result_t result = try_pf_macos("192.0.2.66", DISABLE_COMMAND, 4, "block-ip");

    assert_int_equal(result, FIREWALL_INVALID_STATE);
}

/* With the table configured pf still works: delete, and no pfctl -k. */
void test_try_pf_macos_existing_table_deletes_ip(void **state) {
    (void)state;

    expect_pf_enabled();

    will_return(__wrap_wpopenv, make_wfd("   192.0.2.66\n"));
    will_return(__wrap_wpclose, 0);

    will_return(__wrap_wpopenv, make_wfd(""));
    will_return(__wrap_wpclose, 0);

    firewall_result_t result = try_pf_macos("192.0.2.66", DISABLE_COMMAND, 4, "block-ip");

    assert_int_equal(result, FIREWALL_SUCCESS);
    // The last spawn is the table operation: confirms delete, not add
    assert_int_equal(wpopenv_captured_argc(), 6);
    assert_string_equal(wpopenv_captured_argv(3), "-T");
    assert_string_equal(wpopenv_captured_argv(4), "delete");
    assert_string_equal(wpopenv_captured_argv(5), "192.0.2.66");
}

/* pfctl reports "0/1 addresses deleted." and still exits 0 when the address was
 * never in the table. pf is then not the method that blocked it, so it must
 * decline and let the chain reach the one that did. */
void test_try_pf_macos_disable_address_not_in_table_declines(void **state) {
    (void)state;

    expect_pf_enabled();

    will_return(__wrap_wpopenv, make_wfd("   198.51.100.1\n"));
    will_return(__wrap_wpclose, 0);

    /* Measured on macOS 26.5.1: pfctl puts its two ALTQ notices on stderr ahead
     * of the stdout verdict, so the line that decides this is never the first */
    will_return(__wrap_wpopenv, make_wfd("No ALTQ support in kernel\nALTQ related functions disabled\n0/1 addresses deleted.\n"));
    will_return(__wrap_wpclose, 0);

    firewall_result_t result = try_pf_macos("192.0.2.66", DISABLE_COMMAND, 4, "block-ip");

    assert_int_equal(result, FIREWALL_INVALID_STATE);
}

/* The symmetric case: the address was in the table, so pf did the unblock and
 * the chain must stop here. Same ALTQ prefix, different verdict. */
void test_try_pf_macos_disable_address_in_table_succeeds(void **state) {
    (void)state;

    expect_pf_enabled();

    will_return(__wrap_wpopenv, make_wfd("   192.0.2.66\n"));
    will_return(__wrap_wpclose, 0);

    will_return(__wrap_wpopenv, make_wfd("No ALTQ support in kernel\nALTQ related functions disabled\n1/1 addresses deleted.\n"));
    will_return(__wrap_wpclose, 0);

    firewall_result_t result = try_pf_macos("192.0.2.66", DISABLE_COMMAND, 4, "block-ip");

    assert_int_equal(result, FIREWALL_SUCCESS);
}

/* A non-zero status with nothing on stderr means the child never became
 * route(8) -- a failed execvp() _exit(127)s silently. */
void test_try_route_macos_spawn_never_exec_is_failure(void **state) {
    (void)state;

    char *route_path = strdup("/sbin/route");
    expect_string(__wrap_get_binary_path, command, "route");
    will_return(__wrap_get_binary_path, route_path);
    will_return(__wrap_get_binary_path, 0);
    will_return(__wrap_wpopenv, make_wfd(""));
    will_return(__wrap_wpclose, 127 << 8);

    firewall_result_t result = try_route_macos("192.0.2.66", ENABLE_COMMAND, 4, "block-ip");

    assert_int_equal(result, FIREWALL_EXECUTION_FAILED);
}

/* macOS route(8) exits 0 even when the routing socket write failed, so a zero
 * status must not be read as success on its own. */
void test_try_route_macos_zero_exit_with_stderr_is_failure(void **state) {
    (void)state;

    char *route_path = strdup("/sbin/route");
    expect_string(__wrap_get_binary_path, command, "route");
    will_return(__wrap_get_binary_path, route_path);
    will_return(__wrap_get_binary_path, 0);
    will_return(__wrap_wpopenv, make_wfd("route: writing to routing socket: Network is unreachable\n"));
    will_return(__wrap_wpclose, 0);

    firewall_result_t result = try_route_macos("2001:db8::1", ENABLE_COMMAND, 6, "block-ip");

    assert_int_equal(result, FIREWALL_EXECUTION_FAILED);
}

// ============================================================================
// remove_legacy_hostsdeny_rule: earlier versions appended "ALL:<ip>" to
// /etc/hosts.deny, which macOS never enforces. Unblock removes that exact line.
// ============================================================================

#define HOSTS_DENY "/etc/hosts.deny"
#define TEMP_HOSTS_DENY "active-response/bin/temp-hosts-deny"

static char temp_copy_path[64];
static FILE *hosts_deny_in = NULL;

// The real file behind the mocked temp-file wfopen(), read back after the call
static int setup_hostsdeny(void **state) {
    (void)state;
    test_mode = 1;
    lock_releases = 0;
    hosts_deny_in = NULL;
    snprintf(temp_copy_path, sizeof(temp_copy_path), "/tmp/test_block_ip_macos_XXXXXX");
    int fd = mkstemp(temp_copy_path);
    assert_true(fd >= 0);
    close(fd);
    return 0;
}

static int teardown_hostsdeny(void **state) {
    (void)state;
    test_mode = 0;
    unlink(temp_copy_path);
    teardown_wfds(state);
    return 0;
}

static void expect_hostsdeny_access(int ret) {
    expect_string(__wrap_access, __name, HOSTS_DENY);
    expect_value(__wrap_access, __type, F_OK);
    will_return(__wrap_access, ret);
}

// The function under test fcloses every stream handed to it
static void expect_hostsdeny_read(const char *content) {
    hosts_deny_in = fmemopen((void *)content, strlen(content), "r");
    assert_non_null(hosts_deny_in);
    expect_wfopen(HOSTS_DENY, "r", hosts_deny_in);
}

// File present and read without the lock. No lock is queued: a content without
// a match must not take it.
static void expect_hostsdeny_prescan(const char *content) {
    expect_hostsdeny_access(0);
    expect_hostsdeny_read(content);
}

// Prescan finds a match, lock taken, both files opened
static void expect_hostsdeny_copy_to(const char *content, FILE *copy) {
    expect_hostsdeny_prescan(content);
    will_return(__wrap_acquire_ar_lock, 0);
    expect_hostsdeny_read(content);
    expect_wfopen(TEMP_HOSTS_DENY, "w", copy);
}

static void expect_hostsdeny_copy(const char *content) {
    FILE *copy = fopen(temp_copy_path, "w");
    assert_non_null(copy);
    expect_hostsdeny_copy_to(content, copy);
}

static void expect_hostsdeny_move(int ret) {
    expect_string(__wrap_OS_MoveFile, src, TEMP_HOSTS_DENY);
    expect_string(__wrap_OS_MoveFile, dst, HOSTS_DENY);
    will_return(__wrap_OS_MoveFile, ret);
}

static void assert_copy_equals(const char *expected) {
    char buffer[256] = {0};
    FILE *fp = fopen(temp_copy_path, "r");
    assert_non_null(fp);
    size_t len = fread(buffer, 1, sizeof(buffer) - 1, fp);
    fclose(fp);
    buffer[len] = '\0';
    assert_string_equal(buffer, expected);
}

// Lines that merely contain the address, or name it in another form, are kept
void test_remove_legacy_hostsdeny_rule_exact_match_only(void **state) {
    (void)state;

    expect_hostsdeny_copy("ALL:9.9.9.99\nALL:9.9.9.9\nsshd: 9.9.9.9\nALL:19.9.9.9\n");
    expect_hostsdeny_move(0);

    assert_true(remove_legacy_hostsdeny_rule("9.9.9.9", "block-ip"));
    assert_copy_equals("ALL:9.9.9.99\nsshd: 9.9.9.9\nALL:19.9.9.9\n");
    assert_int_equal(lock_releases, 1);
}

// A substring hit is not a match: no lock, no copy, no OS_MoveFile (none is
// queued, so calling any of them fails the test)
void test_remove_legacy_hostsdeny_rule_substring_only_is_kept(void **state) {
    (void)state;

    expect_hostsdeny_prescan("ALL:9.9.9.99\nsshd: 9.9.9.9\n");

    assert_false(remove_legacy_hostsdeny_rule("9.9.9.9", "block-ip"));
    assert_int_equal(lock_releases, 0);
}

// Unreadable file: nothing is locked or replaced
void test_remove_legacy_hostsdeny_rule_prescan_read_failure(void **state) {
    (void)state;

    expect_hostsdeny_access(0);
    expect_wfopen(HOSTS_DENY, "r", NULL);

    assert_false(remove_legacy_hostsdeny_rule("192.0.2.66", "block-ip"));
    assert_int_equal(lock_releases, 0);
}

// The line was written with the address as received; a canonical spelling of
// the same address is removed too
void test_remove_legacy_hostsdeny_rule_ipv6_raw_and_canonical(void **state) {
    (void)state;

    expect_hostsdeny_copy("ALL:2001:0DB8::0001\nALL:2001:db8::1\nALL:2001:db8::10\n");
    expect_hostsdeny_move(0);

    assert_true(remove_legacy_hostsdeny_rule("2001:0DB8::0001", "block-ip"));
    assert_copy_equals("ALL:2001:db8::10\n");
}

// Trailing whitespace and CRLF do not hide the line
void test_remove_legacy_hostsdeny_rule_trailing_whitespace(void **state) {
    (void)state;

    expect_hostsdeny_copy("ALL:192.0.2.66 \r\nALL:192.0.2.67\n");
    expect_hostsdeny_move(0);

    assert_true(remove_legacy_hostsdeny_rule("192.0.2.66", "block-ip"));
    assert_copy_equals("ALL:192.0.2.67\n");
}

// Stock install: no file, no lock, nothing opened
void test_remove_legacy_hostsdeny_rule_missing_file(void **state) {
    (void)state;

    expect_hostsdeny_access(-1);

    assert_false(remove_legacy_hostsdeny_rule("192.0.2.66", "block-ip"));
    assert_int_equal(lock_releases, 0);
}

void test_remove_legacy_hostsdeny_rule_lock_failure(void **state) {
    (void)state;

    expect_hostsdeny_prescan("ALL:192.0.2.66\n");
    will_return(__wrap_acquire_ar_lock, OS_INVALID);

    assert_false(remove_legacy_hostsdeny_rule("192.0.2.66", "block-ip"));
    assert_int_equal(lock_releases, 0);
}

void test_remove_legacy_hostsdeny_rule_read_failure(void **state) {
    (void)state;

    expect_hostsdeny_prescan("ALL:192.0.2.66\n");
    will_return(__wrap_acquire_ar_lock, 0);
    expect_wfopen(HOSTS_DENY, "r", NULL);

    assert_false(remove_legacy_hostsdeny_rule("192.0.2.66", "block-ip"));
    assert_int_equal(lock_releases, 1);
}

void test_remove_legacy_hostsdeny_rule_temp_open_failure(void **state) {
    (void)state;

    expect_hostsdeny_prescan("ALL:192.0.2.66\n");
    will_return(__wrap_acquire_ar_lock, 0);
    expect_hostsdeny_read("ALL:192.0.2.66\n");
    expect_wfopen(TEMP_HOSTS_DENY, "w", NULL);

    assert_false(remove_legacy_hostsdeny_rule("192.0.2.66", "block-ip"));
    assert_int_equal(lock_releases, 1);
}

// A line longer than the stdio buffer is written straight through and the
// write fails: the truncated copy must not replace the file
void test_remove_legacy_hostsdeny_rule_copy_write_failure(void **state) {
    static char content[16384];
    (void)state;

    memset(content, 0, sizeof(content));
    strcpy(content, "ALL:192.0.2.66\n# ");
    memset(content + strlen(content), 'x', 8192);
    strcat(content, "\n");

    FILE *full = fopen("/dev/full", "w");
    assert_non_null(full);
    expect_hostsdeny_copy_to(content, full);

    assert_false(remove_legacy_hostsdeny_rule("192.0.2.66", "block-ip"));
    assert_int_equal(lock_releases, 1);
}

// A short kept line stays buffered until fclose(), which then fails
void test_remove_legacy_hostsdeny_rule_copy_close_failure(void **state) {
    (void)state;

    FILE *full = fopen("/dev/full", "w");
    assert_non_null(full);
    expect_hostsdeny_copy_to("ALL:192.0.2.66\nALL:192.0.2.67\n", full);

    assert_false(remove_legacy_hostsdeny_rule("192.0.2.66", "block-ip"));
    assert_int_equal(lock_releases, 1);
}

void test_remove_legacy_hostsdeny_rule_move_failure(void **state) {
    (void)state;

    expect_hostsdeny_copy("ALL:192.0.2.66\n");
    expect_hostsdeny_move(-1);

    assert_false(remove_legacy_hostsdeny_rule("192.0.2.66", "block-ip"));
    assert_int_equal(lock_releases, 1);
}

// ============================================================================
// block_ip_macos_main: runs the real pf -> route methods[] literal in main()
// through execute_firewall_chain, which the tests above don't.
// ============================================================================

void test_block_ip_macos_main_stock_install_falls_back_to_route(void **state) {
    char *argv[] = {"block-ip", NULL};
    cJSON *input_json = cJSON_CreateObject();

    will_return(__wrap_setup_and_check_message, input_json);
    will_return(__wrap_setup_and_check_message, ENABLE_COMMAND);

    will_return(__wrap_get_srcip_from_json, "192.168.1.100");

    will_return(__wrap_send_keys_and_check_message, CONTINUE_COMMAND);

    // pf declines: /dev/pf not accessible (stock install, PF never configured)
    char *pfctl_path = strdup("/sbin/pfctl");
    expect_string(__wrap_get_binary_path, command, "pfctl");
    will_return(__wrap_get_binary_path, pfctl_path);
    will_return(__wrap_get_binary_path, 0);
    expect_string(__wrap_access, __name, "/dev/pf");
    expect_value(__wrap_access, __type, F_OK);
    will_return(__wrap_access, -1);

    // Nothing touches /etc/hosts.deny on a block: an access() on it has no
    // queued expectation and fails the test

    // route succeeds
    char *route_path = strdup("/sbin/route");
    expect_string(__wrap_get_binary_path, command, "route");
    will_return(__wrap_get_binary_path, route_path);
    will_return(__wrap_get_binary_path, 0);
    will_return(__wrap_wpopenv, dummy_wfd(""));
    will_return(__wrap_wpclose, 0);

    int result = block_ip_macos_main(1, argv);

    assert_int_equal(result, OS_SUCCESS);
    // Confirms it's really route that ran, with the right add/IPv4 syntax,
    // not e.g. a mock mismatch that happened to still return OS_SUCCESS.
    assert_int_equal(wpopenv_captured_argc(), 6);
    assert_string_equal(wpopenv_captured_argv(0), "/sbin/route");  // route_path itself is already os_free()d inside try_route_macos by this point
    assert_string_equal(wpopenv_captured_argv(2), "add");
    assert_string_equal(wpopenv_captured_argv(3), "192.168.1.100");
}

static void expect_main_disable(const char *srcip) {
    will_return(__wrap_setup_and_check_message, cJSON_CreateObject());
    will_return(__wrap_setup_and_check_message, DISABLE_COMMAND);
    will_return(__wrap_get_srcip_from_json, srcip);
}

// pf declines (/dev/pf not accessible) and route deletes the blackhole route
static void expect_pf_declines_route_deletes(const char *route_stderr) {
    expect_string(__wrap_get_binary_path, command, "pfctl");
    will_return(__wrap_get_binary_path, strdup("/sbin/pfctl"));
    will_return(__wrap_get_binary_path, 0);
    expect_string(__wrap_access, __name, "/dev/pf");
    expect_value(__wrap_access, __type, F_OK);
    will_return(__wrap_access, -1);

    expect_string(__wrap_get_binary_path, command, "route");
    will_return(__wrap_get_binary_path, strdup("/sbin/route"));
    will_return(__wrap_get_binary_path, 0);
    will_return(__wrap_wpopenv, make_wfd(route_stderr));
    will_return(__wrap_wpclose, 0);
}

// Removing a leftover hosts.deny line must not stop the unblock before route
void test_block_ip_macos_main_disable_removes_legacy_entry_and_runs_route(void **state) {
    char *argv[] = {"block-ip", NULL};
    (void)state;

    expect_main_disable("192.0.2.66");
    expect_hostsdeny_copy("ALL:192.0.2.66\n");
    expect_hostsdeny_move(0);
    expect_pf_declines_route_deletes("");

    assert_int_equal(block_ip_macos_main(1, argv), OS_SUCCESS);
    assert_copy_equals("");
    assert_string_equal(wpopenv_captured_argv(0), "/sbin/route");
    assert_string_equal(wpopenv_captured_argv(2), "delete");
    assert_string_equal(wpopenv_captured_argv(3), "192.0.2.66");
}

// A cleanup that fails does not change the unblock's result
void test_block_ip_macos_main_disable_cleanup_failure_keeps_result(void **state) {
    char *argv[] = {"block-ip", NULL};
    (void)state;

    expect_main_disable("192.0.2.66");
    expect_hostsdeny_prescan("ALL:192.0.2.66\n");
    will_return(__wrap_acquire_ar_lock, 0);
    expect_wfopen(HOSTS_DENY, "r", NULL);
    expect_pf_declines_route_deletes("delete host 192.0.2.66: not in table\n");

    assert_int_equal(block_ip_macos_main(1, argv), OS_SUCCESS);
    assert_int_equal(lock_releases, 1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_try_route_macos_binary_not_found),
        cmocka_unit_test(test_try_route_macos_command_fails),
        cmocka_unit_test(test_try_route_macos_enable_succeeds),
        cmocka_unit_test(test_try_route_macos_disable_succeeds),
        cmocka_unit_test(test_try_route_macos_ipv6_enable_succeeds),
        cmocka_unit_test(test_try_route_macos_nonzero_exit_is_failure),
        cmocka_unit_test(test_try_route_macos_enable_already_blocked_is_success),
        cmocka_unit_test(test_try_route_macos_disable_not_in_table_is_success),
        cmocka_unit_test(test_try_pf_macos_disabled_is_invalid_state),
        cmocka_unit_test_teardown(test_try_pf_macos_missing_table_declines, teardown_wfds),
        cmocka_unit_test_teardown(test_try_pf_macos_existing_table_check_output_is_drained, teardown_wfds),
        cmocka_unit_test_teardown(test_try_pf_macos_signalled_table_check_declines, teardown_wfds),
        cmocka_unit_test_teardown(test_try_pf_macos_table_check_spawn_failure_is_execution_failed, teardown_wfds),
        cmocka_unit_test_teardown(test_try_pf_macos_missing_table_declines_on_disable, teardown_wfds),
        cmocka_unit_test_teardown(test_try_pf_macos_existing_table_deletes_ip, teardown_wfds),
        cmocka_unit_test_teardown(test_try_pf_macos_disable_address_not_in_table_declines, teardown_wfds),
        cmocka_unit_test_teardown(test_try_pf_macos_disable_address_in_table_succeeds, teardown_wfds),
        cmocka_unit_test_teardown(test_try_route_macos_spawn_never_exec_is_failure, teardown_wfds),
        cmocka_unit_test_teardown(test_try_route_macos_zero_exit_with_stderr_is_failure, teardown_wfds),
        cmocka_unit_test_setup_teardown(test_remove_legacy_hostsdeny_rule_exact_match_only, setup_hostsdeny, teardown_hostsdeny),
        cmocka_unit_test_setup_teardown(test_remove_legacy_hostsdeny_rule_substring_only_is_kept, setup_hostsdeny, teardown_hostsdeny),
        cmocka_unit_test_setup_teardown(test_remove_legacy_hostsdeny_rule_ipv6_raw_and_canonical, setup_hostsdeny, teardown_hostsdeny),
        cmocka_unit_test_setup_teardown(test_remove_legacy_hostsdeny_rule_trailing_whitespace, setup_hostsdeny, teardown_hostsdeny),
        cmocka_unit_test_setup_teardown(test_remove_legacy_hostsdeny_rule_missing_file, setup_hostsdeny, teardown_hostsdeny),
        cmocka_unit_test_setup_teardown(test_remove_legacy_hostsdeny_rule_lock_failure, setup_hostsdeny, teardown_hostsdeny),
        cmocka_unit_test_setup_teardown(test_remove_legacy_hostsdeny_rule_read_failure, setup_hostsdeny, teardown_hostsdeny),
        cmocka_unit_test_setup_teardown(test_remove_legacy_hostsdeny_rule_move_failure, setup_hostsdeny, teardown_hostsdeny),
        cmocka_unit_test_setup_teardown(test_remove_legacy_hostsdeny_rule_prescan_read_failure, setup_hostsdeny, teardown_hostsdeny),
        cmocka_unit_test_setup_teardown(test_remove_legacy_hostsdeny_rule_temp_open_failure, setup_hostsdeny, teardown_hostsdeny),
        cmocka_unit_test_setup_teardown(test_remove_legacy_hostsdeny_rule_copy_write_failure, setup_hostsdeny, teardown_hostsdeny),
        cmocka_unit_test_setup_teardown(test_remove_legacy_hostsdeny_rule_copy_close_failure, setup_hostsdeny, teardown_hostsdeny),
        cmocka_unit_test(test_block_ip_macos_main_stock_install_falls_back_to_route),
        cmocka_unit_test_setup_teardown(test_block_ip_macos_main_disable_removes_legacy_entry_and_runs_route, setup_hostsdeny, teardown_hostsdeny),
        cmocka_unit_test_setup_teardown(test_block_ip_macos_main_disable_cleanup_failure_keeps_result, setup_hostsdeny, teardown_hostsdeny),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
