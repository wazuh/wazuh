/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <unistd.h>

#include "shared.h"
#include "rootcheck.h"

rkconfig rootcheck;

/* Defined here so rootcheck.o is not linked in */
char total_ports_tcp[65535 + 1];
char total_ports_udp[65535 + 1];

#define SS_PROBE_CMD    "ss -an --tcp > /dev/null 2>&1 && ss -an --udp > /dev/null 2>&1 && " \
                        "awk 'BEGIN {exit 0}' > /dev/null 2>&1"
#define SS_TCP_22       "{ ss -an --tcp 2> /dev/null || echo FAIL; } | awk '/^FAIL$/ {e = 1} " \
                        "$4 ~ /:22$/ {f = 1} END {exit (e || NR < 2) ? 2 : !f}' > /dev/null 2>&1"
#define SS_UDP_53       "{ ss -an --udp 2> /dev/null || echo FAIL; } | awk '/^FAIL$/ {e = 1} " \
                        "$4 ~ /:53$/ {f = 1} END {exit (e || NR < 2) ? 2 : !f}' > /dev/null 2>&1"
#define NETSTAT_TCP_22  "netstat -an | grep \"^tcp\" | grep \"[^0-9]22 \" > /dev/null 2>&1"

#define ALL_PORTS_OK    "No kernel-level rootkit hiding any port.\n      " \
                        "Netstat is acting correctly. Analyzed 131072 ports."

#define MAX_COMMANDS    8

/* Port reported as in use by the wrapped bind(), and its socket type */
static int busy_port;
static int busy_type;
static int last_socket_type;

/* What the wrapped system() reports for each command */
static bool ss_runs;
static bool ss_lists;
static bool netstat_lists;
static int ss_fail_status;

static char commands[MAX_COMMANDS][OS_SIZE_1024];
static int system_calls;

int __wrap_socket(__attribute__((unused)) int domain,
                  int type,
                  __attribute__((unused)) int protocol)
{
    last_socket_type = type;
    return 3;
}

int __wrap_bind(__attribute__((unused)) int fd, const struct sockaddr *addr,
                __attribute__((unused)) socklen_t len)
{
    const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;

    if (last_socket_type == busy_type && ntohs(sin->sin_port) == busy_port) {
        return -1;
    }
    return 0;
}

/* Keep the mocked descriptor from reaching the real close() */
int __wrap_close(__attribute__((unused)) int fd)
{
    return 0;
}

/* Only the probe and the busy port get this far, so record every command */
int __real_system(const char *command);

int __wrap_system(const char *command)
{
    assert_true(system_calls < MAX_COMMANDS);
    snprintf(commands[system_calls++], OS_SIZE_1024, "%s", command);

    if (strcmp(command, SS_PROBE_CMD) == 0) {
        return ss_runs ? 0 : 255 << 8;
    }

    /* grep/awk exit 1 when the port is not in the listing */
    if (strncmp(command, "{ ss ", 5) == 0) {
        if (ss_fail_status) {
            return ss_fail_status << 8;
        }
        return ss_lists ? 0 : 1 << 8;
    }
    return netstat_lists ? 0 : 1 << 8;
}

bool __wrap_is_program_available(const char *program)
{
    check_expected(program);
    return mock_type(bool);
}

int __wrap_notify_rk(int rk_type, const char *msg)
{
    check_expected(rk_type);
    check_expected(msg);
    return mock_type(int);
}

void __wrap__minfo(__attribute__((unused)) const char *file,
                   __attribute__((unused)) int line,
                   __attribute__((unused)) const char *func,
                   const char *msg, ...)
{
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__mtdebug1(const char *tag,
                      __attribute__((unused)) const char *file,
                      __attribute__((unused)) int line,
                      __attribute__((unused)) const char *func,
                      const char *msg, ...)
{
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(tag);
    check_expected(formatted_msg);
}

void __wrap__mtwarn(const char *tag,
                    __attribute__((unused)) const char *file,
                    __attribute__((unused)) int line,
                    __attribute__((unused)) const char *func,
                    const char *msg, ...)
{
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(tag);
    check_expected(formatted_msg);
}

void __wrap__mterror(const char *tag,
                     __attribute__((unused)) const char *file,
                     __attribute__((unused)) int line,
                     __attribute__((unused)) const char *func,
                     const char *msg, ...)
{
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(tag);
    check_expected(formatted_msg);
}

static void expect_notify_rk(int rk_type, const char *msg)
{
    expect_value(__wrap_notify_rk, rk_type, rk_type);
    expect_string(__wrap_notify_rk, msg, msg);
    will_return(__wrap_notify_rk, 0);
}

static void expect_program(const char *program, bool available)
{
    expect_string(__wrap_is_program_available, program, program);
    will_return(__wrap_is_program_available, available);
}

/* cmocka keeps the pointer, so the message must be a literal */
#define expect_tools(tools) do { \
    expect_string(__wrap__mtdebug1, tag, "rootcheck"); \
    expect_string(__wrap__mtdebug1, formatted_msg, "Using " tools " for the port check."); \
} while (0)

static void assert_commands(const char **expected, int count)
{
    assert_int_equal(system_calls, count);
    for (int i = 0; i < count; i++) {
        assert_string_equal(commands[i], expected[i]);
    }
}

static int setup(void **state)
{
    (void)state;
    memset(&rootcheck, 0, sizeof(rkconfig));
    busy_port = 22;
    busy_type = SOCK_STREAM;
    last_socket_type = 0;
    ss_runs = true;
    ss_lists = true;
    netstat_lists = true;
    ss_fail_status = 0;
    memset(commands, 0, sizeof(commands));
    system_calls = 0;
    return 0;
}

/* ===================================================================
 * Tests
 * =================================================================== */

static void test_ss_only(void **state)
{
    (void)state;
    static const char *expected[] = {SS_PROBE_CMD, SS_TCP_22};

    expect_program("ss", true);
    expect_program("netstat", false);
    expect_tools("ss");
    expect_notify_rk(ALERT_OK, ALL_PORTS_OK);

    check_rc_ports();

    assert_commands(expected, 2);
}

static void test_ss_and_netstat_both_list(void **state)
{
    (void)state;
    static const char *expected[] = {SS_PROBE_CMD, SS_TCP_22, NETSTAT_TCP_22};

    expect_program("ss", true);
    expect_program("netstat", true);
    expect_tools("ss and netstat");
    expect_notify_rk(ALERT_OK, ALL_PORTS_OK);

    check_rc_ports();

    assert_commands(expected, 3);
}

/* Hidden from /proc only: ss still lists it, netstat does not */
static void test_hidden_from_netstat_only(void **state)
{
    (void)state;
    static const char *expected[] = {SS_PROBE_CMD, SS_TCP_22, NETSTAT_TCP_22,
                                     SS_TCP_22, NETSTAT_TCP_22};
    netstat_lists = false;

    expect_program("ss", true);
    expect_program("netstat", true);
    expect_tools("ss and netstat");
    expect_notify_rk(ALERT_ROOTKIT_FOUND, "Port '22'(tcp) hidden. Kernel-level rootkit "
                                          "or trojaned version of netstat.");

    check_rc_ports();

    assert_commands(expected, 5);
}

/* Hidden from netlink only: netstat still lists it, ss does not */
static void test_hidden_from_ss_only(void **state)
{
    (void)state;
    static const char *expected[] = {SS_PROBE_CMD, SS_TCP_22, SS_TCP_22};
    ss_lists = false;

    expect_program("ss", true);
    expect_program("netstat", true);
    expect_tools("ss and netstat");
    expect_notify_rk(ALERT_ROOTKIT_FOUND, "Port '22'(tcp) hidden. Kernel-level rootkit "
                                          "or trojaned version of netstat.");

    check_rc_ports();

    assert_commands(expected, 3);
}

static void test_ss_hidden_udp(void **state)
{
    (void)state;
    static const char *expected[] = {SS_PROBE_CMD, SS_UDP_53, SS_UDP_53};
    busy_port = 53;
    busy_type = SOCK_DGRAM;
    ss_lists = false;

    expect_program("ss", true);
    expect_program("netstat", false);
    expect_tools("ss");
    expect_notify_rk(ALERT_ROOTKIT_FOUND, "Port '53'(udp) hidden. Kernel-level rootkit "
                                          "or trojaned version of netstat.");

    check_rc_ports();

    assert_commands(expected, 3);
}

static void test_netstat_fallback(void **state)
{
    (void)state;
    static const char *expected[] = {NETSTAT_TCP_22};

    expect_program("ss", false);
    expect_program("netstat", true);
    expect_tools("netstat");
    expect_notify_rk(ALERT_OK, ALL_PORTS_OK);

    check_rc_ports();

    assert_commands(expected, 1);
}

static void test_broken_ss_falls_back_to_netstat(void **state)
{
    (void)state;
    static const char *expected[] = {SS_PROBE_CMD, NETSTAT_TCP_22};
    ss_runs = false;

    expect_program("ss", true);
    expect_string(__wrap__mtwarn, tag, "rootcheck");
    expect_string(__wrap__mtwarn, formatted_msg, "ss or awk failed to run. Not using ss for the port check.");
    expect_program("netstat", true);
    expect_tools("netstat");
    expect_notify_rk(ALERT_OK, ALL_PORTS_OK);

    check_rc_ports();

    assert_commands(expected, 2);
}

/* ss failing after the probe (exit 2), or awk missing (exit 127), is not a hidden port */
static void test_ss_error_is_not_hidden(void **state)
{
    (void)state;
    static const int statuses[] = {2, 127};

    for (int i = 0; i < 2; i++) {
        static const char *expected[] = {SS_PROBE_CMD, SS_TCP_22};
        setup(NULL);
        ss_fail_status = statuses[i];

        expect_program("ss", true);
        expect_program("netstat", false);
        expect_tools("ss");
        expect_string(__wrap__mtwarn, tag, "rootcheck");
        expect_string(__wrap__mtwarn, formatted_msg, "1 port listing commands failed during the port check.");
        expect_notify_rk(ALERT_OK, ALL_PORTS_OK);

        check_rc_ports();

        assert_commands(expected, 2);
    }
}

/* Runs the real ss pipeline against a stub ss, to pin down its exit codes */
static int run_with_stub_ss(const char *stub_body, const char *command)
{
    /* Working directory, since /tmp may be mounted noexec */
    char dir[] = "test_check_rc_ports_XXXXXX";
    char stub[OS_SIZE_256];
    char path[OS_SIZE_1024];
    char cwd[OS_SIZE_512];
    const char *old_path = getenv("PATH");
    char *saved_path = old_path ? strdup(old_path) : NULL;
    FILE *fp;
    int ret;

    assert_non_null(mkdtemp(dir));
    snprintf(stub, sizeof(stub), "%s/ss", dir);
    fp = fopen(stub, "w");
    assert_non_null(fp);
    fprintf(fp, "#!/bin/sh\n%s\n", stub_body);
    fclose(fp);
    assert_int_equal(chmod(stub, 0700), 0);

    assert_non_null(getcwd(cwd, sizeof(cwd)));
    snprintf(path, sizeof(path), "%s/%s:%s", cwd, dir, saved_path ? saved_path : "/usr/bin:/bin");
    setenv("PATH", path, 1);
    ret = __real_system(command);
    if (saved_path) {
        setenv("PATH", saved_path, 1);
        free(saved_path);
    }

    unlink(stub);
    rmdir(dir);
    return WEXITSTATUS(ret);
}

/* ss always prints its header first */
#define SS_HEADER "echo 'State Recv-Q Send-Q Local Address:Port Peer Address:Port'\n"

static void test_ss_pipeline_exit_codes(void **state)
{
    (void)state;

    /* Listed as local port */
    assert_int_equal(run_with_stub_ss(SS_HEADER "echo 'LISTEN 0 128 0.0.0.0:22 0.0.0.0:*'", SS_TCP_22), 0);
    /* Only as backlog or peer port */
    assert_int_equal(run_with_stub_ss(SS_HEADER "echo 'LISTEN 0 22 0.0.0.0:80 0.0.0.0:*'\n"
                                      "echo 'ESTAB 0 0 10.0.0.1:40000 10.0.0.2:22'", SS_TCP_22), 1);
    /* IPv6, scoped and wildcard local addresses */
    assert_int_equal(run_with_stub_ss(SS_HEADER "echo 'LISTEN 0 128 [::]:22 [::]:*'", SS_TCP_22), 0);
    assert_int_equal(run_with_stub_ss(SS_HEADER "echo 'LISTEN 0 128 :::22 :::*'", SS_TCP_22), 0);
    assert_int_equal(run_with_stub_ss(SS_HEADER "echo 'LISTEN 0 128 *:22 *:*'", SS_TCP_22), 0);
    assert_int_equal(run_with_stub_ss(SS_HEADER "echo 'LISTEN 0 128 127.0.0.53%lo:22 0.0.0.0:*'", SS_TCP_22), 0);
    /* A port that only ends in the same digits */
    assert_int_equal(run_with_stub_ss(SS_HEADER "echo 'LISTEN 0 128 0.0.0.0:122 0.0.0.0:*'", SS_TCP_22), 1);
    /* ss failing */
    assert_int_equal(run_with_stub_ss("exit 1", SS_TCP_22), 2);
    /* ss unable to read any socket: only the header, exit 0 */
    assert_int_equal(run_with_stub_ss(SS_HEADER, SS_TCP_22), 2);
}

static void test_no_tool_available(void **state)
{
    (void)state;

    expect_program("ss", false);
    expect_program("netstat", false);
    expect_string(__wrap__minfo, formatted_msg, "ss or netstat not available. Skipping port check.");
    expect_notify_rk(ALERT_SYSTEM_ERR, "ss or netstat not available. Skipping port check.");

    check_rc_ports();

    assert_int_equal(system_calls, 0);
}

/* ===================================================================
 * Main
 * =================================================================== */

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_ss_only, setup),
        cmocka_unit_test_setup(test_ss_and_netstat_both_list, setup),
        cmocka_unit_test_setup(test_hidden_from_netstat_only, setup),
        cmocka_unit_test_setup(test_hidden_from_ss_only, setup),
        cmocka_unit_test_setup(test_ss_hidden_udp, setup),
        cmocka_unit_test_setup(test_netstat_fallback, setup),
        cmocka_unit_test_setup(test_broken_ss_falls_back_to_netstat, setup),
        cmocka_unit_test_setup(test_ss_error_is_not_hidden, setup),
        cmocka_unit_test(test_ss_pipeline_exit_codes),
        cmocka_unit_test_setup(test_no_tool_available, setup),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
