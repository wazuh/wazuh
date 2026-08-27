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

int main(void) {
    const struct CMUnitTest tests[] = {
        // get_ip_version tests
        cmocka_unit_test_setup_teardown(test_get_ip_version_success_ipv4, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_ip_version_success_ipv6, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_ip_version_no_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_get_ip_version_success_invalid_ip, test_setup, test_teardown),

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
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
