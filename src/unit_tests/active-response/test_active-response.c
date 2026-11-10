/*
 * Copyright (C) 2015, Wazuh Inc.
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

#include "../../headers/shared.h"
#include "../../active-response/active_responses.h"

#include "../wrappers/common.h"

// Tests
void test_get_ip_version_success_ipv4(void **state) {
    (void) state;
    assert_int_equal(get_ip_version("10.0.0.1"), 4);
    assert_int_equal(get_ip_version("0.0.0.0"), 4);
    assert_int_equal(get_ip_version("255.255.255.255"), 4);
}

void test_get_ip_version_success_ipv6(void **state) {
    (void) state;
    assert_int_equal(get_ip_version("2001:db8::1"), 6);
    assert_int_equal(get_ip_version("2001:DB8::1"), 6);
    assert_int_equal(get_ip_version("::1"), 6);
    assert_int_equal(get_ip_version("::ffff:10.0.0.1"), 6);
}

void test_get_ip_version_rejects_non_standard_ipv6_text(void **state) {
    (void) state;
    assert_int_equal(get_ip_version("2001:0db8:0000::0001"), OS_INVALID);
    assert_int_equal(get_ip_version("2001:db8:0:0:0:0:0:1"), OS_INVALID);
    assert_int_equal(get_ip_version("2001:db8::0001"), OS_INVALID);
    assert_int_equal(get_ip_version("2001:db8::0.0.0.1"), OS_INVALID);
    assert_int_equal(get_ip_version("0:0:0:0:0:0:0:1"), OS_INVALID);
    assert_int_equal(get_ip_version("::ffff:a00:1"), OS_INVALID);
}

void test_get_ip_version_rejects_non_standard_ipv4_text(void **state) {
    (void) state;
    assert_int_equal(get_ip_version("010.0.0.1"), OS_INVALID);
    assert_int_equal(get_ip_version("10.0.0.01"), OS_INVALID);
    assert_int_equal(get_ip_version("167772161"), OS_INVALID);
    assert_int_equal(get_ip_version("0x0a000001"), OS_INVALID);
    assert_int_equal(get_ip_version("10.1"), OS_INVALID);
    assert_int_equal(get_ip_version("0"), OS_INVALID);
}

void test_get_ip_version_invalid(void **state) {
    (void) state;
    assert_int_equal(get_ip_version(NULL), OS_INVALID);
    assert_int_equal(get_ip_version(""), OS_INVALID);
    assert_int_equal(get_ip_version("256.0.0.1"), OS_INVALID);
    assert_int_equal(get_ip_version("fe80::1%eth0"), OS_INVALID);
    assert_int_equal(get_ip_version("10.0.0.1 "), OS_INVALID);
    assert_int_equal(get_ip_version("host.example"), OS_INVALID);
}

// Tests for aix_filter_rule_matches

#define AIX_RULE(id, action, src, src_mask, dst, dst_mask, desc) \
    id "|" action "|" src "|" src_mask "|" dst "|" dst_mask "|no|all|any|0|any|0|both|both|no|all packets|0|all|0|||" desc "\n"
#define AIX_WAZUH_DESC "\"" AIX_FILTER_DESCRIPTION "\""

void test_aix_filter_rule_matches_exact(void **state) {
    (void) state;
    assert_true(aix_filter_rule_matches(AIX_RULE("5", "deny", "10.0.0.1", "255.255.255.255", "0.0.0.0", "0.0.0.0", AIX_WAZUH_DESC), "10.0.0.1"));
    assert_true(aix_filter_rule_matches(AIX_RULE("5", "deny", "10.0.0.1", "255.255.255.255", "0.0.0.0", "0.0.0.0", AIX_FILTER_DESCRIPTION), "10.0.0.1"));
}

void test_aix_filter_rule_matches_other_rules(void **state) {
    (void) state;
    assert_false(aix_filter_rule_matches(AIX_RULE("2", "deny", "110.0.0.1", "255.255.255.255", "0.0.0.0", "0.0.0.0", AIX_WAZUH_DESC), "10.0.0.1"));
    assert_false(aix_filter_rule_matches(AIX_RULE("3", "deny", "10.0.0.10", "255.255.255.255", "0.0.0.0", "0.0.0.0", AIX_WAZUH_DESC), "10.0.0.1"));
    assert_false(aix_filter_rule_matches(AIX_RULE("4", "permit", "0.0.0.0", "0.0.0.0", "10.0.0.1", "255.255.255.255", "allow ssh"), "10.0.0.1"));
    assert_false(aix_filter_rule_matches(AIX_RULE("6", "permit", "10.0.0.1", "255.255.255.255", "0.0.0.0", "0.0.0.0", AIX_WAZUH_DESC), "10.0.0.1"));
    assert_false(aix_filter_rule_matches(AIX_RULE("7", "deny", "10.0.0.0", "255.255.255.0", "0.0.0.0", "0.0.0.0", AIX_WAZUH_DESC), "10.0.0.0"));
    assert_false(aix_filter_rule_matches(AIX_RULE("8", "deny", "10.0.0.1", "255.255.255.255", "10.1.1.1", "255.255.255.255", AIX_WAZUH_DESC), "10.0.0.1"));
    assert_false(aix_filter_rule_matches(AIX_RULE("8", "deny", "10.0.0.1", "255.255.255.255", "10.1.1.1", "0.0.0.0", AIX_WAZUH_DESC), "10.0.0.1"));
    assert_false(aix_filter_rule_matches(AIX_RULE("8", "deny", "10.0.0.1", "255.255.255.255", "0.0.0.0", "255.255.255.255", AIX_WAZUH_DESC), "10.0.0.1"));
    assert_false(aix_filter_rule_matches(AIX_RULE("9", "deny", "10.0.0.1", "255.255.255.255", "0.0.0.0", "0.0.0.0", "admin block"), "10.0.0.1"));
    assert_false(aix_filter_rule_matches(AIX_RULE("1", "permit", "0.0.0.0", "0.0.0.0", "0.0.0.0", "0.0.0.0", "Default Rule"), "0.0.0.0"));
}

void test_aix_filter_rule_matches_malformed(void **state) {
    (void) state;
    assert_false(aix_filter_rule_matches(NULL, "10.0.0.1"));
    assert_false(aix_filter_rule_matches(AIX_RULE("5", "deny", "10.0.0.1", "255.255.255.255", "0.0.0.0", "0.0.0.0", AIX_WAZUH_DESC), NULL));
    assert_false(aix_filter_rule_matches("", "10.0.0.1"));
    assert_false(aix_filter_rule_matches("5|deny|10.0.0.1|255.255.255.255|" AIX_WAZUH_DESC "\n", "10.0.0.1"));
    assert_false(aix_filter_rule_matches("Beginning of IPv4 filter rules.\n", "10.0.0.1"));
    assert_false(aix_filter_rule_matches(AIX_WAZUH_DESC "|deny|10.0.0.1|255.255.255.255|0.0.0.0", "10.0.0.1"));
}

// Tests for is_valid_username

void test_is_valid_username_valid_simple(void **state) {
    (void) state;
    assert_int_equal(is_valid_username("testuser"), 1);
}

void test_is_valid_username_valid_with_numbers(void **state) {
    (void) state;
    assert_int_equal(is_valid_username("user123"), 1);
    assert_int_equal(is_valid_username("1testuser"), 1);  // Now valid
}

void test_is_valid_username_valid_with_underscore(void **state) {
    (void) state;
    assert_int_equal(is_valid_username("_testuser"), 1);
    assert_int_equal(is_valid_username("test_user"), 1);
}

void test_is_valid_username_valid_with_hyphen(void **state) {
    (void) state;
    assert_int_equal(is_valid_username("test-user"), 1);
}

void test_is_valid_username_valid_with_dollar(void **state) {
    (void) state;
    assert_int_equal(is_valid_username("machine$"), 1);
    assert_int_equal(is_valid_username("test$user"), 1);  // Now valid
}

void test_is_valid_username_valid_uppercase(void **state) {
    (void) state;
    assert_int_equal(is_valid_username("TestUser"), 1);  // Now valid
    assert_int_equal(is_valid_username("TESTUSER"), 1);  // Now valid
}

void test_is_valid_username_valid_with_dot(void **state) {
    (void) state;
    assert_int_equal(is_valid_username("test.user"), 1);  // Now valid
}

void test_is_valid_username_invalid_root(void **state) {
    (void) state;
    assert_int_equal(is_valid_username("root"), 0);
}

void test_is_valid_username_invalid_null(void **state) {
    (void) state;
    assert_int_equal(is_valid_username(NULL), 0);
}

void test_is_valid_username_invalid_empty(void **state) {
    (void) state;
    assert_int_equal(is_valid_username(""), 0);
}

void test_is_valid_username_invalid_starts_with_dash(void **state) {
    (void) state;
    assert_int_equal(is_valid_username("-testuser"), 0);
}

void test_is_valid_username_invalid_starts_with_plus(void **state) {
    (void) state;
    assert_int_equal(is_valid_username("+testuser"), 0);
}

void test_is_valid_username_invalid_starts_with_tilde(void **state) {
    (void) state;
    assert_int_equal(is_valid_username("~testuser"), 0);
}

void test_is_valid_username_invalid_with_colon(void **state) {
    (void) state;
    assert_int_equal(is_valid_username("test:user"), 0);  // Field separator
}

void test_is_valid_username_invalid_with_comma(void **state) {
    (void) state;
    assert_int_equal(is_valid_username("test,user"), 0);  // GECOS separator
}

void test_is_valid_username_invalid_with_whitespace(void **state) {
    (void) state;
    assert_int_equal(is_valid_username("test user"), 0);
    assert_int_equal(is_valid_username("test\tuser"), 0);
    assert_int_equal(is_valid_username("test\nuser"), 0);
    assert_int_equal(is_valid_username("test\ruser"), 0);
}

void test_is_valid_username_invalid_with_slash(void **state) {
    (void) state;
    assert_int_equal(is_valid_username("test/user"), 0);
    assert_int_equal(is_valid_username("test\\user"), 0);
}

// Traversal sequences are rejected by the separator rule, not by a dedicated guard
void test_is_valid_username_invalid_separators_in_traversal(void **state) {
    (void) state;
    assert_int_equal(is_valid_username("../root"), 0);
    assert_int_equal(is_valid_username("test/../user"), 0);
    assert_int_equal(is_valid_username("..\\root"), 0);
}

void test_is_valid_username_valid_with_consecutive_dots(void **state) {
    (void) state;
    assert_int_equal(is_valid_username("john..doe"), 1);
    assert_int_equal(is_valid_username("a..b"), 1);
    assert_int_equal(is_valid_username(".."), 1);
    assert_int_equal(is_valid_username("."), 1);
}

// The 256 bound is the current contract, not a settled one: LOGIN_NAME_MAX counts
// the NUL, so the real maximum is 255. Confirm before changing.
void test_is_valid_username_length_boundary(void **state) {
    (void) state;
    char username[300];

    memset(username, 'a', 256);
    username[256] = '\0';
    assert_int_equal(is_valid_username(username), 1);

    memset(username, 'a', 257);
    username[257] = '\0';
    assert_int_equal(is_valid_username(username), 0);
}

void test_is_valid_username_invalid_shell_metacharacters(void **state) {
    (void) state;
    assert_int_equal(is_valid_username("test;user"), 0);
    assert_int_equal(is_valid_username("test|user"), 0);
    assert_int_equal(is_valid_username("test&user"), 0);
    assert_int_equal(is_valid_username("test`user`"), 0);
    assert_int_equal(is_valid_username("test$(id)"), 0);
    assert_int_equal(is_valid_username("test'user"), 0);
    assert_int_equal(is_valid_username("test\"user"), 0);
    assert_int_equal(is_valid_username("test*user"), 0);
    assert_int_equal(is_valid_username("test>user"), 0);
}

void test_is_valid_username_invalid_plus_or_tilde_anywhere(void **state) {
    (void) state;
    assert_int_equal(is_valid_username("test+user"), 0);
    assert_int_equal(is_valid_username("test~user"), 0);
}

void test_is_valid_username_invalid_qualified_name(void **state) {
    (void) state;
    assert_int_equal(is_valid_username("alice@example.com"), 0);
    assert_int_equal(is_valid_username("user@REALM"), 0);
}

void test_is_valid_username_invalid_control_characters(void **state) {
    (void) state;
    assert_int_equal(is_valid_username("test\x01" "user"), 0);
    assert_int_equal(is_valid_username("test\x1b" "user"), 0);
    assert_int_equal(is_valid_username("test\x7f" "user"), 0);
}

void test_is_valid_username_invalid_non_ascii(void **state) {
    (void) state;
    assert_int_equal(is_valid_username("caf\xc3\xa9"), 0);
    assert_int_equal(is_valid_username("\xff" "user"), 0);
}

// Tests for get_srcip_from_json

static void assert_srcip(const char *json, const char *expected) {
    cJSON *input = cJSON_Parse(json);
    assert_non_null(input);
    const char *srcip = get_srcip_from_json(input);
    if (expected) {
        assert_non_null(srcip);
        assert_string_equal(srcip, expected);
    } else {
        assert_null(srcip);
    }
    cJSON_Delete(input);
}

#define SRCIP_JSON(ip) "{\"parameters\":{\"alert\":{\"data\":{\"srcip\":\"" ip "\"}}}}"
#define WIN_IP_JSON(ip) "{\"parameters\":{\"alert\":{\"data\":{\"win\":{\"eventdata\":{\"ipAddress\":\"" ip "\"}}}}}}"

void test_get_srcip_from_json_valid(void **state) {
    (void) state;
    assert_srcip(SRCIP_JSON("10.0.0.1"), "10.0.0.1");
    assert_srcip(SRCIP_JSON("2001:db8::1"), "2001:db8::1");
    assert_srcip(WIN_IP_JSON("10.0.0.1"), "10.0.0.1");
}

void test_get_srcip_from_json_mapped_ipv4(void **state) {
    (void) state;
    assert_srcip(SRCIP_JSON("::ffff:10.0.0.1"), "10.0.0.1");
    assert_srcip(WIN_IP_JSON("::ffff:10.0.0.1"), "10.0.0.1");
    // Any other case of the prefix stays an IPv6 address, as on the manager
    assert_srcip(SRCIP_JSON("::FFFF:10.0.0.1"), "::FFFF:10.0.0.1");
    assert_srcip(SRCIP_JSON("0:0:0:0:0:ffff:10.0.0.1"), NULL);
    assert_srcip(SRCIP_JSON("::ffff:a00:1"), NULL);
}

void test_get_srcip_from_json_invalid(void **state) {
    (void) state;
    assert_srcip(SRCIP_JSON("010.0.0.1"), NULL);
    assert_srcip(SRCIP_JSON("::ffff:010.0.0.1"), NULL);
    assert_srcip(SRCIP_JSON("::ffff:167772161"), NULL);
    assert_srcip(SRCIP_JSON("::ffff:"), NULL);
    assert_srcip(SRCIP_JSON(""), NULL);
    assert_srcip("{\"parameters\":{\"alert\":{\"data\":{}}}}", NULL);
}

// Tests for get_username_from_json (the getter must apply is_valid_username)

void test_get_username_from_json_accepts_valid(void **state) {
    (void) state;
    cJSON *input = cJSON_Parse("{\"parameters\":{\"alert\":{\"data\":{\"dstuser\":\"alice\"}}}}");
    assert_non_null(input);
    const char *username = get_username_from_json(input);
    assert_non_null(username);
    assert_string_equal(username, "alice");
    cJSON_Delete(input);
}

void test_get_username_from_json_rejects_invalid(void **state) {
    (void) state;
    cJSON *input = cJSON_Parse("{\"parameters\":{\"alert\":{\"data\":{\"dstuser\":\"--help\"}}}}");
    assert_non_null(input);
    assert_null(get_username_from_json(input));
    cJSON_Delete(input);
}

void test_get_username_from_json_accepts_consecutive_dots(void **state) {
    (void) state;
    cJSON *input = cJSON_Parse("{\"parameters\":{\"alert\":{\"data\":{\"dstuser\":\"john..doe\"}}}}");
    assert_non_null(input);
    const char *username = get_username_from_json(input);
    assert_non_null(username);
    assert_string_equal(username, "john..doe");
    cJSON_Delete(input);
}

void test_get_username_from_json_rejects_root(void **state) {
    (void) state;
    cJSON *input = cJSON_Parse("{\"parameters\":{\"alert\":{\"data\":{\"dstuser\":\"root\"}}}}");
    assert_non_null(input);
    assert_null(get_username_from_json(input));
    cJSON_Delete(input);
}

// write_debug_file tests

// Same rationale as the w_fopen_nofollow tests in test_file_op.c: these run against the real file system.

#define LOG_FILE_PATH AR_LOG_DIR "/" AR_LOG_FILE_NAME

static char ar_log_dir[PATH_MAX + 1];
static char ar_log_cwd[PATH_MAX + 1];
static int ar_log_saved_test_mode;

static off_t ar_log_size(const char * name) {
    struct stat statbuf;

    assert_int_equal(stat(name, &statbuf), 0);
    return statbuf.st_size;
}

static void ar_log_create_other(void) {
    FILE * fp = fopen("other", "w");

    assert_non_null(fp);
    assert_true(fputs("sensitive data", fp) >= 0);
    assert_int_equal(fclose(fp), 0);
}

static int setup_ar_log(void **state) {
    // The file operations below must reach the file system, not the wrappers.
    ar_log_saved_test_mode = test_mode;
    test_mode = 0;
    assert_non_null(getcwd(ar_log_cwd, sizeof(ar_log_cwd)));
    snprintf(ar_log_dir, sizeof(ar_log_dir), "/tmp/wazuh_ar_log_XXXXXX");
    assert_non_null(mkdtemp(ar_log_dir));
    assert_int_equal(chdir(ar_log_dir), 0);
    assert_int_equal(mkdir(AR_LOG_DIR, 0770), 0);
    return 0;
}

static int teardown_ar_log(void **state) {
    remove(LOG_FILE_PATH);
    remove("other");
    remove(AR_LOG_DIR);
    assert_int_equal(chdir(ar_log_cwd), 0);
    remove(ar_log_dir);
    test_mode = ar_log_saved_test_mode;
    return 0;
}

void test_write_debug_file_appends(void **state) {
    write_debug_file("ar-name", "first");
    off_t size = ar_log_size(LOG_FILE_PATH);
    assert_true(size > 0);

    write_debug_file("ar-name", "second");
    assert_true(ar_log_size(LOG_FILE_PATH) > size);
}

void test_write_debug_file_symlink_not_followed(void **state) {
    char target[PATH_MAX + 1];

    ar_log_create_other();
    snprintf(target, sizeof(target), "%s/other", ar_log_dir);
    assert_int_equal(symlink(target, LOG_FILE_PATH), 0);

    write_debug_file("ar-name", "message");

    assert_int_equal(ar_log_size("other"), 14);
}

void test_write_debug_file_hard_link_not_followed(void **state) {
    ar_log_create_other();
    assert_int_equal(link("other", LOG_FILE_PATH), 0);

    write_debug_file("ar-name", "message");

    assert_int_equal(ar_log_size("other"), 14);
}

// Tests for execute_command_with_retry
static char *test_command[] = { "/usr/sbin/iptables", "-I", "INPUT", "-s", "10.0.0.1", "-j", "DROP", NULL };
static wfd_t test_wfd[AR_COMMAND_ATTEMPTS];

// Queue one attempt: the command starts, prints output and ends with status
static void expect_attempt(int i, const char *output, int status) {
    test_wfd[i].file_out = tmpfile();
    assert_non_null(test_wfd[i].file_out);
    fputs(output, test_wfd[i].file_out);
    rewind(test_wfd[i].file_out);
    will_return(__wrap_wpopenv, &test_wfd[i]);
    will_return(__wrap_wpclose, status);
}

static void close_attempts(int count) {
    for (int i = 0; i < count; i++) {
        // The output is drained before waiting for the command
        assert_int_equal(fgetc(test_wfd[i].file_out), EOF);
        fclose(test_wfd[i].file_out);
    }
}

void test_execute_command_with_retry_success(void **state) {
    expect_attempt(0, "output\n", 0);

    assert_int_equal(execute_command_with_retry("ar-name", test_command[0], test_command), OS_SUCCESS);

    close_attempts(1);
    assert_int_not_equal(access(LOG_FILE_PATH, F_OK), 0);
}

void test_execute_command_with_retry_succeeds_after_failures(void **state) {
    will_return(__wrap_wpopenv, NULL);
    expect_value(__wrap_sleep, seconds, 1);
    expect_attempt(0, "Another app is currently holding the xtables lock.\n", 4 << 8);
    expect_value(__wrap_sleep, seconds, 2);
    expect_attempt(1, "", 0);

    assert_int_equal(execute_command_with_retry("ar-name", test_command[0], test_command), OS_SUCCESS);

    close_attempts(2);
    assert_int_not_equal(access(LOG_FILE_PATH, F_OK), 0);
}

void test_execute_command_with_retry_fails_after_all_attempts(void **state) {
    char line[OS_MAXSTR] = {0};

    for (int i = 0; i < AR_COMMAND_ATTEMPTS - 1; i++) {
        expect_attempt(i, "Another app is currently holding the xtables lock.\n", 4 << 8);
        expect_value(__wrap_sleep, seconds, i + 1);
    }
    will_return(__wrap_wpopenv, NULL);

    assert_int_equal(execute_command_with_retry("ar-name", test_command[0], test_command), OS_INVALID);

    close_attempts(AR_COMMAND_ATTEMPTS - 1);
    FILE *fp = fopen(LOG_FILE_PATH, "r");
    assert_non_null(fp);
    assert_non_null(fgets(line, sizeof(line), fp));
    fclose(fp);
    assert_non_null(strstr(line, "ar-name: Command failed (exit code -1): /usr/sbin/iptables -I INPUT -s 10.0.0.1 -j DROP\n"));
}

void test_execute_command_with_retry_other_error_not_retried(void **state) {
    char line[OS_MAXSTR] = {0};

    expect_attempt(0, "iptables: Bad rule (does a matching rule exist in that chain?).\n", 1 << 8);

    assert_int_equal(execute_command_with_retry("ar-name", test_command[0], test_command), OS_INVALID);

    close_attempts(1);
    FILE *fp = fopen(LOG_FILE_PATH, "r");
    assert_non_null(fp);
    assert_non_null(fgets(line, sizeof(line), fp));
    fclose(fp);
    assert_non_null(strstr(line, "ar-name: Command failed (exit code 1): /usr/sbin/iptables -I INPUT -s 10.0.0.1 -j DROP\n"));
}

// Tests for canonicalize_ip
void test_canonicalize_ip_ipv4_canonical(void **state) {
    (void)state;
    char out[NI_MAXHOST] = {0};

    assert_true(canonicalize_ip("10.0.0.1", out, sizeof(out)));
    assert_string_equal(out, "10.0.0.1");
}

void test_canonicalize_ip_ipv6_compressed(void **state) {
    (void)state;
    char out[NI_MAXHOST] = {0};

    assert_true(canonicalize_ip("2001:0db8::0001", out, sizeof(out)));
    assert_string_equal(out, "2001:db8::1");
}

void test_canonicalize_ip_rejects_non_canonical(void **state) {
    (void)state;
    char out[NI_MAXHOST] = {0};

    // Octal, hex, short and decimal-integer IPv4 forms must be rejected, not reinterpreted.
    assert_false(canonicalize_ip("012.0.0.1", out, sizeof(out)));
    assert_false(canonicalize_ip("0177.0.0.1", out, sizeof(out)));
    assert_false(canonicalize_ip("127.1", out, sizeof(out)));
    assert_false(canonicalize_ip("2130706433", out, sizeof(out)));
    assert_false(canonicalize_ip("192.168.001.010", out, sizeof(out)));
}

void test_canonicalize_ip_invalid(void **state) {
    (void)state;
    char out[NI_MAXHOST] = {0};

    assert_false(canonicalize_ip("not_an_ip", out, sizeof(out)));
    assert_false(canonicalize_ip(NULL, out, sizeof(out)));
}

// Tests for hosts_deny_rule_matches
void test_hosts_deny_rule_matches_exact(void **state) {
    (void)state;
    assert_true(hosts_deny_rule_matches("ALL:10.0.0.1\n", "ALL:10.0.0.1"));
    assert_true(hosts_deny_rule_matches("ALL:10.0.0.1  \t\n", "ALL:10.0.0.1"));
}

void test_hosts_deny_rule_matches_substring_no_match(void **state) {
    (void)state;
    assert_false(hosts_deny_rule_matches("ALL: 110.0.0.1\n", "ALL:10.0.0.1"));
    assert_false(hosts_deny_rule_matches("sshd: 210.0.0.1\n", "ALL:10.0.0.1"));
    assert_false(hosts_deny_rule_matches("ALL:10.0.0.10\n", "ALL:10.0.0.1"));
}

void test_hosts_deny_rule_matches_null(void **state) {
    (void)state;
    assert_false(hosts_deny_rule_matches(NULL, "ALL:10.0.0.1"));
    assert_false(hosts_deny_rule_matches("ALL:10.0.0.1", NULL));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // get_ip_version tests
        cmocka_unit_test(test_get_ip_version_success_ipv4),
        cmocka_unit_test(test_get_ip_version_success_ipv6),
        cmocka_unit_test(test_get_ip_version_rejects_non_standard_ipv4_text),
        cmocka_unit_test(test_get_ip_version_rejects_non_standard_ipv6_text),
        cmocka_unit_test(test_get_ip_version_invalid),
        cmocka_unit_test(test_aix_filter_rule_matches_exact),
        cmocka_unit_test(test_aix_filter_rule_matches_other_rules),
        cmocka_unit_test(test_aix_filter_rule_matches_malformed),
        cmocka_unit_test(test_get_srcip_from_json_valid),
        cmocka_unit_test(test_get_srcip_from_json_mapped_ipv4),
        cmocka_unit_test(test_get_srcip_from_json_invalid),

        // canonicalize_ip tests
        cmocka_unit_test(test_canonicalize_ip_ipv4_canonical),
        cmocka_unit_test(test_canonicalize_ip_ipv6_compressed),
        cmocka_unit_test(test_canonicalize_ip_rejects_non_canonical),
        cmocka_unit_test(test_canonicalize_ip_invalid),

        // hosts_deny_rule_matches tests
        cmocka_unit_test(test_hosts_deny_rule_matches_exact),
        cmocka_unit_test(test_hosts_deny_rule_matches_substring_no_match),
        cmocka_unit_test(test_hosts_deny_rule_matches_null),

        // is_valid_username tests
        cmocka_unit_test(test_is_valid_username_valid_simple),
        cmocka_unit_test(test_is_valid_username_valid_with_numbers),
        cmocka_unit_test(test_is_valid_username_valid_with_underscore),
        cmocka_unit_test(test_is_valid_username_valid_with_hyphen),
        cmocka_unit_test(test_is_valid_username_valid_with_dollar),
        cmocka_unit_test(test_is_valid_username_valid_uppercase),
        cmocka_unit_test(test_is_valid_username_valid_with_dot),
        cmocka_unit_test(test_is_valid_username_invalid_root),
        cmocka_unit_test(test_is_valid_username_invalid_null),
        cmocka_unit_test(test_is_valid_username_invalid_empty),
        cmocka_unit_test(test_is_valid_username_invalid_starts_with_dash),
        cmocka_unit_test(test_is_valid_username_invalid_starts_with_plus),
        cmocka_unit_test(test_is_valid_username_invalid_starts_with_tilde),
        cmocka_unit_test(test_is_valid_username_invalid_with_colon),
        cmocka_unit_test(test_is_valid_username_invalid_with_comma),
        cmocka_unit_test(test_is_valid_username_invalid_with_whitespace),
        cmocka_unit_test(test_is_valid_username_invalid_with_slash),
        cmocka_unit_test(test_is_valid_username_invalid_separators_in_traversal),
        cmocka_unit_test(test_is_valid_username_valid_with_consecutive_dots),
        cmocka_unit_test(test_is_valid_username_length_boundary),
        cmocka_unit_test(test_is_valid_username_invalid_shell_metacharacters),
        cmocka_unit_test(test_is_valid_username_invalid_plus_or_tilde_anywhere),
        cmocka_unit_test(test_is_valid_username_invalid_qualified_name),
        cmocka_unit_test(test_is_valid_username_invalid_control_characters),
        cmocka_unit_test(test_is_valid_username_invalid_non_ascii),

        // get_username_from_json tests
        cmocka_unit_test(test_get_username_from_json_accepts_valid),
        cmocka_unit_test(test_get_username_from_json_rejects_invalid),
        cmocka_unit_test(test_get_username_from_json_accepts_consecutive_dots),
        cmocka_unit_test(test_get_username_from_json_rejects_root),

        // write_debug_file tests
        cmocka_unit_test_setup_teardown(test_write_debug_file_appends, setup_ar_log, teardown_ar_log),
        cmocka_unit_test_setup_teardown(test_write_debug_file_symlink_not_followed, setup_ar_log, teardown_ar_log),
        cmocka_unit_test_setup_teardown(test_write_debug_file_hard_link_not_followed, setup_ar_log, teardown_ar_log),

        // execute_command_with_retry tests
        cmocka_unit_test_setup_teardown(test_execute_command_with_retry_success, setup_ar_log, teardown_ar_log),
        cmocka_unit_test_setup_teardown(test_execute_command_with_retry_succeeds_after_failures, setup_ar_log, teardown_ar_log),
        cmocka_unit_test_setup_teardown(test_execute_command_with_retry_fails_after_all_attempts, setup_ar_log, teardown_ar_log),
        cmocka_unit_test_setup_teardown(test_execute_command_with_retry_other_error_not_retried, setup_ar_log, teardown_ar_log),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
