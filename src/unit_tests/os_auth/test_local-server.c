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

#include "auth.h"
#include "shared.h"
#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

#include "cJSON.h"

/* local_add_clustered() bridges a worker's local-socket "add" request to the master over the
 * cluster. It is declared (non-static) in auth.h and defined in local-server.c; these tests
 * exercise its three outcomes by mocking its only external dependency,
 * w_request_agent_add_clustered(). */

/* authd_lib (see os_auth/CMakeLists.txt) deliberately excludes main-server.c from the unit-test
 * library, since it owns main(). Linking any symbol out of local-server.c.o pulls in the whole
 * object file, including run_local_server()/local_add()/local_remove()/local_get() -- none of
 * which this suite calls -- and those reference globals that normally live in main-server.c.
 * Stub them here purely to satisfy the linker; their values are never exercised. */
volatile int write_pending = 0;
volatile int running = 0;
pthread_mutex_t mutex_keys = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond_pending = PTHREAD_COND_INITIALIZER;
void authd_sigblock(void) {}

/* wraps */

int __wrap_w_request_agent_add_clustered(char *err_response,
                                         const char *name,
                                         const char *ip,
                                         __attribute__((unused)) const char *groups,
                                         __attribute__((unused)) const char *key_hash,
                                         char **id,
                                         char **key,
                                         authd_force_options_t *force_options,
                                         const char *agent_id,
                                         int *master_error_code) {
    check_expected(name);
    check_expected(ip);

    // Mirrors local_add_clustered()'s contract: no caller-supplied id/key/force is ever
    // forwarded on a worker.
    assert_null(force_options);
    assert_null(agent_id);

    int result = mock_type(int);

    if (result == 0) {
        const char *mock_id = mock_ptr_type(const char *);
        const char *mock_key = mock_ptr_type(const char *);
        os_strdup(mock_id, *id);
        os_strdup(mock_key, *key);
    } else {
        int code = mock_type(int);
        if (code > 0) {
            *master_error_code = code;
        }
        const char *message = mock_ptr_type(const char *);
        if (message) {
            strncpy(err_response, message, OS_SIZE_2048 - 1);
        }
    }

    return result;
}

/* tests */

static void test_local_add_clustered_success(void **state) {
    (void) state;
    cJSON *response;
    cJSON *data;

    expect_any_always(__wrap__mdebug2, formatted_msg);
    expect_any_always(__wrap__minfo, formatted_msg);
    expect_string(__wrap_w_request_agent_add_clustered, name, "agent1");
    expect_string(__wrap_w_request_agent_add_clustered, ip, "any");
    will_return(__wrap_w_request_agent_add_clustered, 0);
    will_return(__wrap_w_request_agent_add_clustered, "003");
    will_return(__wrap_w_request_agent_add_clustered, "675aaf366e6827ee7a77b2f7b4d89e603a21333c09afbb02c40191f199d7c915");

    response = local_add_clustered("agent1", "any", NULL, NULL);
    assert_non_null(response);

    assert_int_equal(cJSON_GetObjectItem(response, "error")->valueint, 0);
    data = cJSON_GetObjectItem(response, "data");
    assert_non_null(data);
    assert_string_equal(cJSON_GetObjectItem(data, "id")->valuestring, "003");
    assert_string_equal(cJSON_GetObjectItem(data, "name")->valuestring, "agent1");
    assert_string_equal(cJSON_GetObjectItem(data, "ip")->valuestring, "any");
    assert_string_equal(cJSON_GetObjectItem(data, "key")->valuestring,
                        "675aaf366e6827ee7a77b2f7b4d89e603a21333c09afbb02c40191f199d7c915");

    cJSON_Delete(response);
}

static void test_local_add_clustered_business_rejection_preserves_master_code(void **state) {
    (void) state;
    cJSON *response;

    expect_any_always(__wrap__mdebug2, formatted_msg);
    expect_any_always(__wrap__minfo, formatted_msg);
    expect_any_always(__wrap__merror, formatted_msg);
    expect_string(__wrap_w_request_agent_add_clustered, name, "agent1");
    expect_string(__wrap_w_request_agent_add_clustered, ip, "any");
    will_return(__wrap_w_request_agent_add_clustered, -1);
    will_return(__wrap_w_request_agent_add_clustered, 9008);
    will_return(__wrap_w_request_agent_add_clustered, "ERROR: Duplicate name");

    response = local_add_clustered("agent1", "any", NULL, NULL);
    assert_non_null(response);

    // The master's own numeric code (9008, Duplicate name) must be surfaced verbatim --
    // not collapsed into the generic 9016 -- and the redundant "ERROR: " prefix stripped.
    assert_int_equal(cJSON_GetObjectItem(response, "error")->valueint, 9008);
    assert_string_equal(cJSON_GetObjectItem(response, "message")->valuestring, "Duplicate name");

    cJSON_Delete(response);
}

static void test_local_add_clustered_transport_failure_maps_to_9016(void **state) {
    (void) state;
    cJSON *response;

    expect_any_always(__wrap__mdebug2, formatted_msg);
    expect_any_always(__wrap__minfo, formatted_msg);
    expect_any_always(__wrap__merror, formatted_msg);
    expect_string(__wrap_w_request_agent_add_clustered, name, "agent1");
    expect_string(__wrap_w_request_agent_add_clustered, ip, "any");
    will_return(__wrap_w_request_agent_add_clustered, -2);
    will_return(__wrap_w_request_agent_add_clustered, 0); // master_error_code left untouched
    will_return(__wrap_w_request_agent_add_clustered, "ERROR: Cannot comunicate with master");

    response = local_add_clustered("agent1", "any", NULL, NULL);
    assert_non_null(response);

    // No well-formed business code came back -- transport failure and a malformed/unparseable
    // master response are indistinguishable from here, and both map to the new 9016.
    assert_int_equal(cJSON_GetObjectItem(response, "error")->valueint, 9016);
    assert_string_equal(cJSON_GetObjectItem(response, "message")->valuestring,
                        "Cannot communicate with master node");

    cJSON_Delete(response);
}

/* is_storable_agent_name() is STATIC in local-server.c (visible here under WAZUH_UNIT_TESTING).
 * It guards the ONE invariant every caller of the local socket must satisfy: the name has to
 * survive a round trip through client.keys' `<id> <name> <ip> <key>` line format. It is
 * deliberately NOT OS_IsValidName()'s charset -- see the tests below for the names that
 * distinction keeps working. */
int is_storable_agent_name(const char *name);

static void test_storable_agent_name_accepts_ordinary_names(void **state) {
    (void) state;

    assert_int_equal(is_storable_agent_name("agent1"), 1);
    assert_int_equal(is_storable_agent_name("web-01.example.com"), 1);
    assert_int_equal(is_storable_agent_name("host_name.2"), 1);
}

static void test_storable_agent_name_accepts_names_os_isvalidname_rejects(void **state) {
    (void) state;

    /* The whole point of not reusing OS_IsValidName() here: the API's own documented contract for
     * `agent_name` is `^[\w\-.%]+$` with no minimum length, so all three of these have always been
     * accepted through this socket by manage_agents/the API. None of them can corrupt client.keys,
     * so rejecting them would be a regression for existing callers with no safety gain. */
    assert_int_equal(is_storable_agent_name("a"), 1);          // single character
    assert_int_equal(is_storable_agent_name("100%cpu"), 1);    // '%' is outside OS_IsValidName()
    assert_int_equal(is_storable_agent_name(".hidden"), 1);    // leading '.'
}

static void test_storable_agent_name_rejects_whitespace_and_control_bytes(void **state) {
    (void) state;

    /* client.keys is whitespace-delimited, so any of these would split the name into extra fields
     * and shift every later column -- the agent would be stored with a bogus IP and an undecodable
     * key, then get 401 on every request it ever made. */
    assert_int_equal(is_storable_agent_name("web 01"), 0);
    assert_int_equal(is_storable_agent_name("web\t01"), 0);
    assert_int_equal(is_storable_agent_name("web\n01"), 0);
    assert_int_equal(is_storable_agent_name("web\r01"), 0);
    assert_int_equal(is_storable_agent_name("web\x01" "01"), 0);
    assert_int_equal(is_storable_agent_name("web\x7f" "01"), 0);
    assert_int_equal(is_storable_agent_name(" leading"), 0);
    assert_int_equal(is_storable_agent_name("trailing "), 0);
}

static void test_storable_agent_name_rejects_removed_entry_markers(void **state) {
    (void) state;

    /* Both OS_ReadKeys() and remoted's keystore treat a leading '#'/'!' on this field as the
     * removed/disabled-entry marker and skip the line, silently dropping the agent. */
    assert_int_equal(is_storable_agent_name("#agent"), 0);
    assert_int_equal(is_storable_agent_name("!agent"), 0);

    /* Only in the FIRST position -- these are storable. */
    assert_int_equal(is_storable_agent_name("agent#1"), 1);
    assert_int_equal(is_storable_agent_name("agent!1"), 1);
}

static void test_storable_agent_name_rejects_empty_and_overlong(void **state) {
    (void) state;
    char overlong[130];
    char at_limit[129];

    assert_int_equal(is_storable_agent_name(NULL), 0);
    assert_int_equal(is_storable_agent_name(""), 0);

    memset(at_limit, 'a', 128);
    at_limit[128] = '\0';
    assert_int_equal(is_storable_agent_name(at_limit), 1); // exactly 128 is allowed

    memset(overlong, 'a', 129);
    overlong[129] = '\0';
    assert_int_equal(is_storable_agent_name(overlong), 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_local_add_clustered_success),
        cmocka_unit_test(test_local_add_clustered_business_rejection_preserves_master_code),
        cmocka_unit_test(test_local_add_clustered_transport_failure_maps_to_9016),
        cmocka_unit_test(test_storable_agent_name_accepts_ordinary_names),
        cmocka_unit_test(test_storable_agent_name_accepts_names_os_isvalidname_rejects),
        cmocka_unit_test(test_storable_agent_name_rejects_whitespace_and_control_bytes),
        cmocka_unit_test(test_storable_agent_name_rejects_removed_entry_markers),
        cmocka_unit_test(test_storable_agent_name_rejects_empty_and_overlong),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
