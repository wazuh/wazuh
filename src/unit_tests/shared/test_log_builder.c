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

// Size of the result, with its terminator, that the tests give to log_builder_build()
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

    char * output = log_builder_build(builder, PATTERN, LOG, LOCATION, OS_MAXSTR);

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
    expect_any(__wrap__mdebug1, formatted_msg);
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

/* Expect the debug message of a log cut from from_len to to_len bytes. The check keeps a pointer to the message, so
 * it is static. */
static void expect_log_cut(size_t from_len, size_t to_len) {
    static char message[128];

    snprintf(message, sizeof(message), "Log cut from %lu to %lu bytes to fit in its output format.", (unsigned long)from_len, (unsigned long)to_len);
    expect_string(__wrap__mdebug1, formatted_msg, message);
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
    expect_log_cut(LOG_SIZE - 1, ROOM / 2);

    char * output = log_builder_build(builder, PATTERN, log, "test", LOG_SIZE);

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
    expect_log_cut(LOG_SIZE, ROOM);

    char * output = log_builder_build(builder, PATTERN, log, "test", LOG_SIZE);

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
    expect_log_cut(60000, LOG_USED);

    char * output = log_builder_build(builder, PATTERN, log, "test", LOG_SIZE);

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

    expect_any(__wrap__mdebug1, formatted_msg);

    char * output = log_builder_build(builder, PATTERN, log, "test", LOG_SIZE);
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
    expect_string(__wrap__mdebug1, formatted_msg, "Too long message format");

    char * output = log_builder_build(builder, pattern, "raw log", "test", LOG_SIZE);

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
    output = log_builder_build(builder, PATTERN, log, "test", LOG_SIZE);

    assert_int_equal(strlen(output), LOG_SIZE - 1);
    assert_int_equal(output[0], '[');
    assert_memory_equal(output + 1, log, LOG_SIZE - 3);
    assert_string_equal(output + LOG_SIZE - 2, "]");
    free(output);

    // One byte too long
    log[LOG_SIZE - 3] = "0123456789"[(LOG_SIZE - 3) % 10];
    expect_log_cut(LOG_SIZE - 2, LOG_SIZE - 3);
    output = log_builder_build(builder, PATTERN, log, "test", LOG_SIZE);

    assert_int_equal(strlen(output), LOG_SIZE - 1);
    assert_int_equal(output[0], '[');
    assert_memory_equal(output + 1, log, LOG_SIZE - 3);
    assert_string_equal(output + LOG_SIZE - 2, "]");
    free(output);

    free(log);
    log_builder_destroy(builder);
}

/* Build a log made of a prefix and then a character repeated, too long for its format, and check that the cut keeps
 * used_len bytes of it and whether the result is valid UTF-8. */
static void check_utf8_cut(const char * prefix, const char * character, size_t used_len, bool valid) {
    const char * PATTERN = "[$(log)]";
    const size_t LOG_LEN = OS_MAXSTR;
    log_builder_t * builder = init_builder(60, false);
    char * characters = make_log(LOG_LEN - strlen(prefix), character);
    char * log;

    os_malloc(LOG_LEN + 1, log);
    snprintf(log, LOG_LEN + 1, "%s%s", prefix, characters);
    expect_log_cut(LOG_LEN, used_len);

    char * output = log_builder_build(builder, PATTERN, log, "test", LOG_SIZE);

    assert_int_equal(strlen(output), used_len + 2);
    assert_int_equal(output[0], '[');
    assert_memory_equal(output + 1, log, used_len);
    assert_string_equal(output + 1 + used_len, "]");
    assert_int_equal(w_utf8_valid(output), valid);

    free(output);
    free(log);
    free(characters);
    log_builder_destroy(builder);
}

// A cut log does not split a UTF-8 character: it ends before the first byte of the one that does not fit.
void test_log_builder_too_long_log_keeps_utf8(void **state) {
    // Room for the log
    const size_t ROOM = LOG_SIZE - 1 - strlen("[]");

    // ROOM is odd, so the cut falls after the first byte of a two-byte character.
    assert_int_equal(ROOM % 2, 1);
    check_utf8_cut("", "\xc3\xa9", ROOM - 1, true);

    // After one ASCII byte, the cut falls after the first two bytes of a three-byte character.
    assert_int_equal((ROOM - 1) % 3, 2);
    check_utf8_cut("a", "\xe2\x82\xac", ROOM - 2, true);

    // After two ASCII bytes, the cut falls after the first three bytes of a four-byte character.
    assert_int_equal((ROOM - 2) % 4, 3);
    check_utf8_cut("ab", "\xf0\x9f\x98\x80", ROOM - 3, true);
}

// A log that is not UTF-8 is cut where it fits, even if the next bytes look like the end of a character.
void test_log_builder_too_long_log_not_utf8(void **state) {
    const size_t ROOM = LOG_SIZE - 1 - strlen("[]");

    // Bytes that continue a UTF-8 character, with no first byte before them
    check_utf8_cut("", "\x80", ROOM, false);
    // A first byte that is too far before the cut
    check_utf8_cut("\xc3", "\x80", ROOM, false);
}

// A format field that cannot be filled is reported once, even if the log is cut.
void test_log_builder_too_long_log_reports_once(void **state) {
    const char * PATTERN = "$(unknown)[$(log)]";
    log_builder_t * builder = init_builder(60, false);
    char * log = make_log(OS_MAXSTR, "a");

    expect_string(__wrap__mdebug1, formatted_msg, "Invalid parameter 'unknown' for log format.");
    expect_log_cut(OS_MAXSTR, LOG_SIZE - 1 - strlen("[]"));

    char * output = log_builder_build(builder, PATTERN, log, "test", LOG_SIZE);

    assert_int_equal(strlen(output), LOG_SIZE - 1);
    assert_int_equal(output[0], '[');
    assert_string_equal(output + LOG_SIZE - 2, "]");

    free(output);
    free(log);
    log_builder_destroy(builder);
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
            cmocka_unit_test_setup(test_log_builder_too_long_log_keeps_utf8, reset_host_ip_state),
            cmocka_unit_test_setup(test_log_builder_too_long_log_not_utf8, reset_host_ip_state),
            cmocka_unit_test_setup(test_log_builder_too_long_log_reports_once, reset_host_ip_state),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
