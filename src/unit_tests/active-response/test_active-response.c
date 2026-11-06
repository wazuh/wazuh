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

// Structs
typedef struct test_struct {
    struct addrinfo *addr;
} test_struct_t;

// Setup / Teardown

static int test_setup(void **state) {
    test_struct_t *init_data = NULL;

    os_calloc(1,sizeof(test_struct_t),init_data);
    os_calloc(1, sizeof(struct addrinfo), init_data->addr);
    os_calloc(1, sizeof(struct sockaddr), init_data->addr->ai_addr);

    *state = init_data;

    test_mode = 1;

    return OS_SUCCESS;
}

static int test_teardown(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;

    os_free(data->addr->ai_addr);
    os_free(data->addr);
    os_free(data);

    test_mode = 0;

    return OS_SUCCESS;
}

// Tests
void test_get_ip_version_success_ipv4(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    char *dummy_ipaddr = "";

    data->addr->ai_family = AF_INET;

    expect_string(__wrap_getaddrinfo, node, dummy_ipaddr);
    will_return(__wrap_getaddrinfo, data->addr);
    will_return(__wrap_getaddrinfo, 0);     //0 means success

    int ret = get_ip_version(dummy_ipaddr);

    assert_int_equal(ret, 4);
}

void test_get_ip_version_success_ipv6(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    char *dummy_ipaddr = "";

    data->addr->ai_family = AF_INET6;

    expect_string(__wrap_getaddrinfo, node, dummy_ipaddr);
    will_return(__wrap_getaddrinfo, data->addr);
    will_return(__wrap_getaddrinfo, 0);     //0 means success

    int ret = get_ip_version(dummy_ipaddr);

    assert_int_equal(ret, 6);
}

void test_get_ip_version_no_success(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    char *dummy_ipaddr = "";

    data->addr->ai_family = AF_INET6;

    expect_string(__wrap_getaddrinfo, node, dummy_ipaddr);
    will_return(__wrap_getaddrinfo, data->addr);
    will_return(__wrap_getaddrinfo, 1);

    int ret = get_ip_version(dummy_ipaddr);

    assert_int_equal(ret, -1);    //OS_INVALID
}

void test_get_ip_version_success_invalid_ip(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    char *dummy_ipaddr = "";

    data->addr->ai_family = -1;         //invalid family

    expect_string(__wrap_getaddrinfo, node, dummy_ipaddr);
    will_return(__wrap_getaddrinfo, data->addr);
    will_return(__wrap_getaddrinfo, 0);     //0 means success

    int ret = get_ip_version(dummy_ipaddr);

    assert_int_equal(ret, -1);    //OS_INVALID
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

// Tests for format_hostsdeny_client
void test_format_hostsdeny_client_ipv4(void **state) {
    (void)state;
    char out[NI_MAXHOST] = {0};

    assert_true(format_hostsdeny_client("10.0.0.1", out, sizeof(out)));
    assert_string_equal(out, "10.0.0.1");
}

void test_format_hostsdeny_client_ipv6_bracketed(void **state) {
    (void)state;
    char out[NI_MAXHOST] = {0};

    assert_true(format_hostsdeny_client("2001:0db8::0001", out, sizeof(out)));
    assert_string_equal(out, "[2001:db8::1]");
    assert_true(format_hostsdeny_client("::1", out, sizeof(out)));
    assert_string_equal(out, "[::1]");
}

void test_format_hostsdeny_client_ipv4_mapped(void **state) {
    (void)state;
    char out[NI_MAXHOST] = {0};

    assert_true(format_hostsdeny_client("::ffff:10.0.0.1", out, sizeof(out)));
    assert_string_equal(out, "10.0.0.1");
}

void test_format_hostsdeny_client_ipv4_mapped_other_spellings(void **state) {
    (void)state;
    char out[NI_MAXHOST] = {0};

    // Only the "::ffff:a.b.c.d" spelling is converted; other mapped spellings are refused.
    assert_false(format_hostsdeny_client("::FFFF:127.0.0.1", out, sizeof(out)));
    assert_false(format_hostsdeny_client("0:0:0:0:0:ffff:127.0.0.1", out, sizeof(out)));
    assert_false(format_hostsdeny_client("0::ffff:127.0.0.1", out, sizeof(out)));
    assert_false(format_hostsdeny_client("::ffff:7f00:1", out, sizeof(out)));
}

void test_format_hostsdeny_client_nat64_stays_ipv6(void **state) {
    (void)state;
    char out[NI_MAXHOST] = {0};

    assert_true(format_hostsdeny_client("64:ff9b::1.2.3.4", out, sizeof(out)));
    assert_string_equal(out, "[64:ff9b::102:304]");
}

void test_format_hostsdeny_client_buffer_too_small(void **state) {
    (void)state;
    char out[8] = {0};

    assert_false(format_hostsdeny_client("2001:db8::1", out, sizeof(out)));
}

void test_format_hostsdeny_client_invalid(void **state) {
    (void)state;
    char out[NI_MAXHOST] = {0};

    assert_false(format_hostsdeny_client("not_an_ip", out, sizeof(out)));
    assert_false(format_hostsdeny_client("127.1", out, sizeof(out)));
    assert_false(format_hostsdeny_client(NULL, out, sizeof(out)));
    assert_false(format_hostsdeny_client("10.0.0.1", NULL, sizeof(out)));
}

// Tests for build_hostsdeny_rules
void test_build_hostsdeny_rules_ipv4(void **state) {
    (void)state;
    char rule[OS_SIZE_256] = {0};
    char legacy[OS_SIZE_256] = {0};

    assert_true(build_hostsdeny_rules("10.0.0.1", false, rule, sizeof(rule), legacy, sizeof(legacy)));
    assert_string_equal(rule, "ALL:10.0.0.1");
    assert_string_equal(legacy, "");

    assert_true(build_hostsdeny_rules("10.0.0.1", true, rule, sizeof(rule), legacy, sizeof(legacy)));
    assert_string_equal(rule, "ALL : 10.0.0.1 : deny");
    assert_string_equal(legacy, "");
}

void test_build_hostsdeny_rules_ipv6(void **state) {
    (void)state;
    char rule[OS_SIZE_256] = {0};
    char legacy[OS_SIZE_256] = {0};

    assert_true(build_hostsdeny_rules("2001:0DB8::0001", false, rule, sizeof(rule), legacy, sizeof(legacy)));
    assert_string_equal(rule, "ALL:[2001:db8::1]");
    assert_string_equal(legacy, "ALL:2001:db8::1");

    assert_true(build_hostsdeny_rules("2001:db8::1", true, rule, sizeof(rule), legacy, sizeof(legacy)));
    assert_string_equal(rule, "ALL : [2001:db8::1] : deny");
    assert_string_equal(legacy, "ALL : 2001:db8::1 : deny");
}

void test_build_hostsdeny_rules_ipv4_mapped(void **state) {
    (void)state;
    char rule[OS_SIZE_256] = {0};
    char legacy[OS_SIZE_256] = {0};

    assert_true(build_hostsdeny_rules("::ffff:10.0.0.1", false, rule, sizeof(rule), legacy, sizeof(legacy)));
    assert_string_equal(rule, "ALL:10.0.0.1");
    assert_string_equal(legacy, "ALL:::ffff:10.0.0.1");

    assert_true(build_hostsdeny_rules("::ffff:10.0.0.1", true, rule, sizeof(rule), legacy, sizeof(legacy)));
    assert_string_equal(rule, "ALL : 10.0.0.1 : deny");
    assert_string_equal(legacy, "ALL : ::ffff:10.0.0.1 : deny");
}

void test_build_hostsdeny_rules_rejected(void **state) {
    (void)state;
    char rule[OS_SIZE_256] = "stale";
    char legacy[OS_SIZE_256] = "stale";
    char small[12] = {0};

    assert_false(build_hostsdeny_rules("::FFFF:127.0.0.1", false, rule, sizeof(rule), legacy, sizeof(legacy)));
    assert_string_equal(rule, "");
    assert_string_equal(legacy, "");
    assert_false(build_hostsdeny_rules("127.1", false, rule, sizeof(rule), legacy, sizeof(legacy)));
    assert_false(build_hostsdeny_rules(NULL, false, rule, sizeof(rule), legacy, sizeof(legacy)));
    assert_false(build_hostsdeny_rules("10.0.0.1", false, NULL, sizeof(rule), legacy, sizeof(legacy)));
    assert_false(build_hostsdeny_rules("2001:db8::1", false, small, sizeof(small), legacy, sizeof(legacy)));
    assert_string_equal(small, "");
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

// Tests for hosts_deny_remove_rules
static FILE *hosts_deny_tmp(const char *content) {
    FILE *fp = tmpfile();
    assert_non_null(fp);
    assert_int_equal(fputs(content, fp) >= 0, 1);
    rewind(fp);
    return fp;
}

static void assert_file_content(FILE *fp, const char *expected) {
    char buf[OS_SIZE_1024] = {0};
    rewind(fp);
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    buf[n] = '\0';
    assert_string_equal(buf, expected);
}

void test_hosts_deny_remove_rules_new_and_legacy(void **state) {
    (void)state;
    bool removed = false;
    FILE *in = hosts_deny_tmp("# admin\nALL: 110.0.0.1\nALL:2001:db8::1\nALL:[2001:db8::1]\nsshd: [2001:db8::1]\n");
    FILE *out = tmpfile();

    assert_int_equal(hosts_deny_remove_rules(in, out, "ALL:[2001:db8::1]", "ALL:2001:db8::1", &removed), OS_SUCCESS);
    assert_true(removed);
    assert_file_content(out, "# admin\nALL: 110.0.0.1\nsshd: [2001:db8::1]\n");

    fclose(in);
    fclose(out);
}

void test_hosts_deny_remove_rules_ipv4_exact_only(void **state) {
    (void)state;
    bool removed = false;
    FILE *in = hosts_deny_tmp("ALL:10.0.0.10\nALL:10.0.0.1\nALL: 110.0.0.1\nALL:10.0.0.1");
    FILE *out = tmpfile();

    assert_int_equal(hosts_deny_remove_rules(in, out, "ALL:10.0.0.1", "", &removed), OS_SUCCESS);
    assert_true(removed);
    assert_file_content(out, "ALL:10.0.0.10\nALL: 110.0.0.1\n");

    fclose(in);
    fclose(out);
}

void test_hosts_deny_remove_rules_nothing_removed(void **state) {
    (void)state;
    bool removed = true;
    const char *content = "# admin\nALL: 110.0.0.1\n";
    FILE *in = hosts_deny_tmp(content);
    FILE *out = tmpfile();

    assert_int_equal(hosts_deny_remove_rules(in, out, "ALL:[2001:db8::1]", NULL, &removed), OS_SUCCESS);
    assert_false(removed);
    assert_file_content(out, content);

    fclose(in);
    fclose(out);
}

void test_hosts_deny_remove_rules_write_error(void **state) {
    (void)state;
    bool removed = false;
    FILE *in = hosts_deny_tmp("# admin\nALL: 110.0.0.1\nALL:10.0.0.1\n");
    // Writes to /dev/full fail with ENOSPC once flushed, like a full disk.
    FILE *out = fopen("/dev/full", "w");
    assert_non_null(out);

    assert_int_equal(hosts_deny_remove_rules(in, out, "ALL:10.0.0.1", NULL, &removed), OS_INVALID);

    fclose(in);
    fclose(out);
}

void test_hosts_deny_remove_rules_invalid_args(void **state) {
    (void)state;
    bool removed = false;
    FILE *fp = tmpfile();

    assert_int_equal(hosts_deny_remove_rules(NULL, fp, "ALL:10.0.0.1", NULL, &removed), OS_INVALID);
    assert_int_equal(hosts_deny_remove_rules(fp, NULL, "ALL:10.0.0.1", NULL, &removed), OS_INVALID);
    assert_int_equal(hosts_deny_remove_rules(fp, fp, NULL, NULL, &removed), OS_INVALID);
    assert_int_equal(hosts_deny_remove_rules(fp, fp, "ALL:10.0.0.1", NULL, NULL), OS_INVALID);

    fclose(fp);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // get_ip_version tests
        cmocka_unit_test_setup_teardown(test_get_ip_version_success_ipv4, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_ip_version_success_ipv6, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_ip_version_no_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_ip_version_success_invalid_ip, test_setup, test_teardown),

        // canonicalize_ip tests
        cmocka_unit_test(test_canonicalize_ip_ipv4_canonical),
        cmocka_unit_test(test_canonicalize_ip_ipv6_compressed),
        cmocka_unit_test(test_canonicalize_ip_rejects_non_canonical),
        cmocka_unit_test(test_canonicalize_ip_invalid),

        // format_hostsdeny_client tests
        cmocka_unit_test(test_format_hostsdeny_client_ipv4),
        cmocka_unit_test(test_format_hostsdeny_client_ipv6_bracketed),
        cmocka_unit_test(test_format_hostsdeny_client_ipv4_mapped),
        cmocka_unit_test(test_format_hostsdeny_client_ipv4_mapped_other_spellings),
        cmocka_unit_test(test_format_hostsdeny_client_nat64_stays_ipv6),
        cmocka_unit_test(test_format_hostsdeny_client_buffer_too_small),
        cmocka_unit_test(test_format_hostsdeny_client_invalid),

        // build_hostsdeny_rules tests
        cmocka_unit_test(test_build_hostsdeny_rules_ipv4),
        cmocka_unit_test(test_build_hostsdeny_rules_ipv6),
        cmocka_unit_test(test_build_hostsdeny_rules_ipv4_mapped),
        cmocka_unit_test(test_build_hostsdeny_rules_rejected),

        // hosts_deny_rule_matches tests
        cmocka_unit_test(test_hosts_deny_rule_matches_exact),
        cmocka_unit_test(test_hosts_deny_rule_matches_substring_no_match),
        cmocka_unit_test(test_hosts_deny_rule_matches_null),

        // hosts_deny_remove_rules tests
        cmocka_unit_test(test_hosts_deny_remove_rules_new_and_legacy),
        cmocka_unit_test(test_hosts_deny_remove_rules_ipv4_exact_only),
        cmocka_unit_test(test_hosts_deny_remove_rules_nothing_removed),
        cmocka_unit_test(test_hosts_deny_remove_rules_write_error),
        cmocka_unit_test(test_hosts_deny_remove_rules_invalid_args),

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
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
