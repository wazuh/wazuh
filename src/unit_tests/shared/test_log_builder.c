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
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../headers/shared.h"
#include "../wrappers/common.h"
#include "../wrappers/wazuh/client-agent/notify_wrappers.h"

extern int g_ip_update_interval;
extern char g_host_ip[IPSIZE];
extern time_t g_host_ip_last_update;
int log_builder_update_host_ip(log_builder_t * builder);

// Size of a built log with its terminator, for a location that leaves a header shorter than OS_LOG_HEADER
#define LOG_SIZE (OS_MAX_LOG_SIZE)

// Setup / teardown

static int reset_host_ip_state(void **state) {
    *g_host_ip = '\0';
    g_host_ip_last_update = 0;
    return 0;
}

// Helpers

/* Queue the mocks of one host IP request that reaches its source. */
static void expect_host_ip_request() {
#ifdef WIN32
    time_mock_value = 1000;
    will_return(wrap_get_agent_ip_legacy_win32, strdup("1.2.3.4"));
#else
    will_return(__wrap_control_check_connection, 16);
    will_return(__wrap_send, 7);
    will_return(__wrap_recv, 0);
#endif
}

static log_builder_t * init_builder(int interval, bool host_ip_used) {
    will_return(__wrap_getDefine_Int, interval);
    log_builder_t * builder = log_builder_init(false, host_ip_used);
    assert_non_null(builder);
    return builder;
}

// Tests

void test_log_builder(void **state)
{
    const char * PATTERN = "location: $(location), log: $(log), escaped: $(json_escaped_log)";
    const char * LOG = "Hello \"World\"";
    const char * LOCATION = "test";
    const char * EXPECTED_OUTPUT = "location: test, log: Hello \"World\", escaped: Hello \\\"World\\\"";

    will_return(__wrap_getDefine_Int, 60);

    int retval = 1;
    log_builder_t * builder = log_builder_init(false, false);

    char * output = log_builder_build(builder, PATTERN, LOG, LOCATION);

    assert_string_equal(output, EXPECTED_OUTPUT);

    free(output);
    log_builder_destroy(builder);
}

void test_log_builder_update(void **state)
{
    will_return(__wrap_getDefine_Int, 1);
    log_builder_t * builder = log_builder_init(false, true);
    assert_int_equal(g_ip_update_interval, 1);
    assert_non_null(builder);

#ifdef WIN32
    char * return_ip = "1.2.3.4";
    time_mock_value = 1000;
    will_return(wrap_get_agent_ip_legacy_win32, strdup(return_ip));
#elif defined __linux__ || defined __MACH__ || defined sun || defined FreeBSD || defined OpenBSD
    will_return(__wrap_control_check_connection, 16);
    will_return(__wrap_send, 7);
    will_return(__wrap_recv, 0);
#endif

    int r = log_builder_update_host_ip(builder);
    assert_int_equal(r, 0);
#ifdef WIN32
    assert_string_equal(builder->host_ip, "1.2.3.4");
#endif
    log_builder_destroy(builder);
}

void test_log_builder_not_update(void **state) {
    will_return(__wrap_getDefine_Int, 0);

    log_builder_t * builder = log_builder_init(false, true);
    assert_int_equal(g_ip_update_interval, 0);
    assert_non_null(builder);

    int r = log_builder_update_host_ip(builder);
    assert_int_equal(r, 0);

    log_builder_destroy(builder);
}

// No mock is queued: a request would fail the test.
void test_log_builder_host_ip_not_requested_when_unused(void **state) {
    log_builder_t * builder = init_builder(60, false);

    assert_int_equal(log_builder_update_host_ip(builder), 0);
    assert_int_equal(g_host_ip_last_update, 0);
    assert_string_equal(builder->host_ip, "0.0.0.0");

    log_builder_destroy(builder);
}

void test_log_builder_host_ip_refreshed_when_used(void **state) {
    log_builder_t * builder = init_builder(60, true);

    expect_host_ip_request();
    assert_int_equal(log_builder_update_host_ip(builder), 0);
#ifdef WIN32
    assert_string_equal(builder->host_ip, "1.2.3.4");
#endif

    g_host_ip_last_update = 0;
    expect_host_ip_request();
    assert_int_equal(log_builder_update_host_ip(builder), 0);

    log_builder_destroy(builder);
}

void test_log_builder_host_ip_used_waits_for_interval(void **state) {
    log_builder_t * builder = init_builder(60, true);

    expect_host_ip_request();
    assert_int_equal(log_builder_update_host_ip(builder), 0);

    // Same time as the first request: the interval has not elapsed.
    assert_int_equal(log_builder_update_host_ip(builder), 0);

    log_builder_destroy(builder);
}

#ifndef WIN32
void test_log_builder_host_ip_retries_until_control_available(void **state) {
    log_builder_t * builder = init_builder(60, true);

    will_return(__wrap_control_check_connection, -1);
    assert_int_equal(log_builder_update_host_ip(builder), 0);

    assert_int_equal(g_host_ip_last_update, 0);
    assert_string_equal(builder->host_ip, "0.0.0.0");

    expect_host_ip_request();
    assert_int_equal(log_builder_update_host_ip(builder), 0);

    log_builder_destroy(builder);
}
#endif

/* Allocate a log of len bytes, each one taken from chars in turn. */
static char * make_log(size_t len, const char * chars) {
    char * log;
    size_t chars_len = strlen(chars);

    os_malloc(len + 1, log);

    for (size_t i = 0; i < len; i++) {
        log[i] = chars[i % chars_len];
    }

    log[len] = '\0';
    return log;
}

// A log too long for its format is cut before it is escaped: the format stays and no escape is split.
void test_log_builder_too_long_json_escaped_log_keeps_format(void **state) {
    const char * PATTERN = "{\"log\":\"$(json_escaped_log)\"}";
    const size_t PREFIX_LEN = strlen("{\"log\":\"");
    const size_t FORMAT_LEN = strlen("{\"log\":\"\"}");
    // Room for the escaped log. It is odd, so cutting the escaped text would leave a lone backslash.
    const size_t ROOM = LOG_SIZE - 1 - FORMAT_LEN;
    log_builder_t * builder = init_builder(60, false);
    char * log = make_log(LOG_SIZE - 1, "\"");

    assert_int_equal(ROOM % 2, 1);

    char * output = log_builder_build(builder, PATTERN, log, "test");

    assert_int_equal(strlen(output), FORMAT_LEN + ROOM - 1);
    assert_memory_equal(output, "{\"log\":\"", PREFIX_LEN);

    for (size_t i = PREFIX_LEN; i < PREFIX_LEN + ROOM - 1; i += 2) {
        assert_memory_equal(output + i, "\\\"", 2);
    }

    assert_string_equal(output + PREFIX_LEN + ROOM - 1, "\"}");

    free(output);
    free(log);
    log_builder_destroy(builder);
}

// A log too long for its format does not replace the fields around it, even if it looks like an event.
void test_log_builder_too_long_log_keeps_format(void **state) {
    const char * PATTERN = "$(hostname) $(location): $(log) [end]";
    const char * PREFIX = "localhost test: ";
    const char * SUFFIX = " [end]";
    const size_t ROOM = LOG_SIZE - 1 - strlen(PREFIX) - strlen(SUFFIX);
    log_builder_t * builder = init_builder(60, false);
    char * log = make_log(LOG_SIZE, "A");

    memcpy(log, "{\"host\":\"forged\"}", strlen("{\"host\":\"forged\"}"));

    char * output = log_builder_build(builder, PATTERN, log, "test");

    assert_int_equal(strlen(output), LOG_SIZE - 1);
    assert_memory_equal(output, PREFIX, strlen(PREFIX));
    assert_memory_equal(output + strlen(PREFIX), log, ROOM);
    assert_string_equal(output + strlen(PREFIX) + ROOM, SUFFIX);

    free(output);
    free(log);
    log_builder_destroy(builder);
}

// A log whose base64 form is too long is cut before it is encoded.
void test_log_builder_too_long_base64_log_keeps_format(void **state) {
    const char * PATTERN = "b64:$(base64_log);";
    const size_t ROOM = LOG_SIZE - 1 - strlen("b64:;");
    // Every 3 bytes of the log take 4 once encoded.
    const size_t LOG_USED = ROOM / 4 * 3;
    log_builder_t * builder = init_builder(60, false);
    char * log = make_log(60000, "abcdefghijklmnopqrstuvwxyz");
    char * encoded = encode_base64(LOG_USED, log);
    char * expected;

    os_malloc(strlen(encoded) + 6, expected);
    snprintf(expected, strlen(encoded) + 6, "b64:%s;", encoded);

    char * output = log_builder_build(builder, PATTERN, log, "test");

    assert_string_equal(output, expected);

    free(output);
    free(expected);
    free(encoded);
    free(log);
    log_builder_destroy(builder);
}

// Every field from the log takes the same part of it, the longest one that fits.
void test_log_builder_too_long_log_fields_use_same_part(void **state) {
    const char * PATTERN = "$(log)|$(json_escaped_log)";
    log_builder_t * builder = init_builder(60, false);
    char * log = make_log(40000, "a\"");

    char * output = log_builder_build(builder, PATTERN, log, "test");
    char * separator = strchr(output, '|');

    assert_non_null(separator);

    size_t used = separator - output;
    char * part = w_strndup(log, used);
    char * escaped = wstr_escape_json(part);
    char * longer_part = w_strndup(log, used + 1);
    char * longer_escaped = wstr_escape_json(longer_part);

    assert_true(used < strlen(log));
    assert_memory_equal(output, log, used);
    assert_string_equal(separator + 1, escaped);
    assert_true(strlen(output) < LOG_SIZE);
    // One byte more would not fit.
    assert_true(used + 1 + 1 + strlen(longer_escaped) >= LOG_SIZE);

    free(longer_escaped);
    free(longer_part);
    free(escaped);
    free(part);
    free(output);
    free(log);
    log_builder_destroy(builder);
}

// A format that does not fit even with no log is cut, and the raw log is not sent in its place.
void test_log_builder_too_long_format(void **state) {
    char * pattern = make_log(LOG_SIZE + strlen("$(log)"), "x");
    log_builder_t * builder = init_builder(60, false);

    memcpy(pattern + LOG_SIZE, "$(log)", strlen("$(log)"));

    char * output = log_builder_build(builder, pattern, "raw log", "test");

    assert_int_equal(strlen(output), LOG_SIZE - 1);
    assert_int_equal(strspn(output, "x"), LOG_SIZE - 1);

    free(output);
    free(pattern);
    log_builder_destroy(builder);
}

// A result of LOG_SIZE - 1 bytes fits whole; one byte more cuts the log by one byte.
void test_log_builder_log_length_limit(void **state) {
    const char * PATTERN = "[$(log)]";
    log_builder_t * builder = init_builder(60, false);
    char * log = make_log(LOG_SIZE - 2, "0123456789");
    char * output;

    // Fits exactly
    log[LOG_SIZE - 3] = '\0';
    output = log_builder_build(builder, PATTERN, log, "test");

    assert_int_equal(strlen(output), LOG_SIZE - 1);
    assert_int_equal(output[0], '[');
    assert_memory_equal(output + 1, log, LOG_SIZE - 3);
    assert_string_equal(output + LOG_SIZE - 2, "]");
    free(output);

    // One byte too long
    log[LOG_SIZE - 3] = "0123456789"[(LOG_SIZE - 3) % 10];
    output = log_builder_build(builder, PATTERN, log, "test");

    assert_int_equal(strlen(output), LOG_SIZE - 1);
    assert_int_equal(output[0], '[');
    assert_memory_equal(output + 1, log, LOG_SIZE - 3);
    assert_string_equal(output + LOG_SIZE - 2, "]");
    free(output);

    free(log);
    log_builder_destroy(builder);
}

/* Build a too long log for a location and put the header of SendMSGAction() before it, the same way it does. The
 * whole message fits, the end of the format is kept, and the log is cut no more than needed. */
static void check_room_for_header(const char * location) {
    const char * PATTERN = "{\"log\":\"$(json_escaped_log)\",\"host\":\"$(hostname)\"}";
    const char * SUFFIX = "\",\"host\":\"localhost\"}";
    log_builder_t * builder = init_builder(60, false);
    char * log = make_log(OS_MAXSTR, "\"");
    char loc_buff[OS_SIZE_8192 + 1] = {0};
    char * message;

    char * output = log_builder_build(builder, PATTERN, log, location);

    assert_int_not_equal(wstr_escape(loc_buff, sizeof(loc_buff), location, '|', ':'), OS_INVALID);
    os_malloc(OS_MAXSTR, message);
    snprintf(message, OS_MAXSTR, "1:%s:%s", loc_buff, output);

    assert_int_equal(strlen(message), strlen("1::") + strlen(loc_buff) + strlen(output));
    assert_string_equal(message + strlen(message) - strlen(SUFFIX), SUFFIX);
    // Each quote of the log takes two bytes once escaped, so one byte may be left.
    assert_true(strlen(message) >= OS_MAXSTR - 2);

    free(message);
    free(output);
    free(log);
    log_builder_destroy(builder);
}

// A cut log leaves room for the header that SendMSGAction() puts before it, so the end of the format is kept.
void test_log_builder_too_long_log_leaves_room_for_header(void **state) {
    char * location;

    // Header of OS_LOG_HEADER bytes
    location = make_log(OS_LOG_HEADER - strlen("1::"), "l");
    check_room_for_header(location);
    free(location);

    // Longer location, with characters that are escaped in the header
    location = make_log(2000, "C:\\logs|app");
    check_room_for_header(location);
    free(location);

    // Location that is cut in the header
    location = make_log(OS_SIZE_8192 + 1000, "/var/log/app");
    check_room_for_header(location);
    free(location);
}

void test_log_builder_uses_host_ip(void **state) {
    assert_true(log_builder_uses_host_ip("ip: $(host_ip)"));
    assert_true(log_builder_uses_host_ip("$(hostname) $(host_ip): $(log)"));
    assert_false(log_builder_uses_host_ip("$(hostname) $(location): $(log)"));
    assert_false(log_builder_uses_host_ip("host_ip"));
    assert_false(log_builder_uses_host_ip(NULL));
}

int main(void) {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup(test_log_builder, reset_host_ip_state),
            cmocka_unit_test_setup(test_log_builder_update, reset_host_ip_state),
            cmocka_unit_test_setup(test_log_builder_not_update, reset_host_ip_state),
            cmocka_unit_test_setup(test_log_builder_host_ip_not_requested_when_unused, reset_host_ip_state),
            cmocka_unit_test_setup(test_log_builder_host_ip_refreshed_when_used, reset_host_ip_state),
            cmocka_unit_test_setup(test_log_builder_host_ip_used_waits_for_interval, reset_host_ip_state),
#ifndef WIN32
            cmocka_unit_test_setup(test_log_builder_host_ip_retries_until_control_available, reset_host_ip_state),
#endif
            cmocka_unit_test(test_log_builder_uses_host_ip),
            cmocka_unit_test_setup(test_log_builder_too_long_json_escaped_log_keeps_format, reset_host_ip_state),
            cmocka_unit_test_setup(test_log_builder_too_long_log_keeps_format, reset_host_ip_state),
            cmocka_unit_test_setup(test_log_builder_too_long_base64_log_keeps_format, reset_host_ip_state),
            cmocka_unit_test_setup(test_log_builder_too_long_log_fields_use_same_part, reset_host_ip_state),
            cmocka_unit_test_setup(test_log_builder_too_long_format, reset_host_ip_state),
            cmocka_unit_test_setup(test_log_builder_log_length_limit, reset_host_ip_state),
            cmocka_unit_test_setup(test_log_builder_too_long_log_leaves_room_for_header, reset_host_ip_state),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
