/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* OS_AddNewAgent()'s key generation and OS_IsValidAgentKey(): the agent key is exactly 32 CSPRNG
 * bytes stored as 64 lowercase hex chars (the HS256 secret of remoted's wazuh-agent+jwt profile). */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "shared.h"
#include "sec.h"
#include "agent_validate_op.h"
#include "../wrappers/externals/openssl/rand_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/validate_op_wrappers.h"

static keystore keys;

static int setup_keys(void **state) {
    (void) state;
    memset(&keys, 0, sizeof(keys));
    OS_PassEmptyKeyfile();
    keys.keytree_id = rbtree_init();
    keys.keytree_ip = rbtree_init();
    keys.keytree_sock = rbtree_init();
    os_calloc(1, sizeof(keyentry *), keys.keyentries);
    return 0;
}

static int teardown_keys(void **state) {
    (void) state;
    OS_FreeKeys(&keys);
    return 0;
}

/* OS_AddKey() validates the ip column through OS_IsValidIP(), which is mocked in libwazuh_test: one
 * expectation per entry that actually reaches OS_AddKey(). -1 = "any". */
static void expect_add_key_ip_check(void) {
    expect_any(__wrap_OS_IsValidIP, ip_address);
    expect_any(__wrap_OS_IsValidIP, final_ip);
    will_return(__wrap_OS_IsValidIP, -1);
}

static int is_lower_hex_64(const char *s) {
    size_t i;
    if (!s || strlen(s) != 64) {
        return 0;
    }
    for (i = 0; i < 64; i++) {
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) {
            return 0;
        }
    }
    return 1;
}

/* --- generation ------------------------------------------------------------------------------ */

static void test_add_new_agent_generates_a_64_hex_key(void **state) {
    (void) state;
    will_return(__wrap_RAND_bytes, 1); /* pass through to the real CSPRNG */
    expect_add_key_ip_check();

    int index = OS_AddNewAgent(&keys, NULL, "agent1", "any", NULL, 0);
    assert_true(index >= 0);
    assert_string_equal(keys.keyentries[index]->id, "001");
    assert_true(is_lower_hex_64(keys.keyentries[index]->raw_key));
    assert_true(OS_IsValidAgentKey(keys.keyentries[index]->raw_key));
}

static void test_two_generated_keys_differ(void **state) {
    (void) state;
    will_return(__wrap_RAND_bytes, 1);
    will_return(__wrap_RAND_bytes, 1);
    expect_add_key_ip_check();
    expect_add_key_ip_check();

    int a = OS_AddNewAgent(&keys, NULL, "agent1", "any", NULL, 0);
    int b = OS_AddNewAgent(&keys, NULL, "agent2", "any", NULL, 0);
    assert_true(a >= 0 && b >= 0);
    assert_string_not_equal(keys.keyentries[a]->raw_key, keys.keyentries[b]->raw_key);
    assert_int_equal(keys.keysize, 2);
}

static void test_csprng_failure_adds_nothing_and_reports_error(void **state) {
    (void) state;
    will_return(__wrap_RAND_bytes, 0); /* do not pass through... */
    will_return(__wrap_RAND_bytes, 0); /* ...and report failure */
    expect_string(__wrap__merror, formatted_msg,
                  "Unable to generate a key for agent 'agent1': the CSPRNG (RAND_bytes) failed.");

    int index = OS_AddNewAgent(&keys, NULL, "agent1", "any", NULL, 0);
    assert_int_equal(index, OS_INVALID);
    assert_int_equal(keys.keysize, 0);
}

static void test_explicit_key_is_stored_verbatim(void **state) {
    (void) state;
    const char *key = "0030557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c61ff";

    /* No RAND_bytes call when the caller supplies the key. */
    expect_add_key_ip_check();
    int index = OS_AddNewAgent(&keys, "007", "agent7", "any", key, 0);
    assert_true(index >= 0);
    assert_string_equal(keys.keyentries[index]->id, "007");
    assert_string_equal(keys.keyentries[index]->raw_key, key);
}

static void test_agent_limit_is_checked_before_generating(void **state) {
    (void) state;
    will_return(__wrap_RAND_bytes, 1);
    expect_add_key_ip_check();
    assert_true(OS_AddNewAgent(&keys, NULL, "agent1", "any", NULL, 0) >= 0);

    /* max_agents = 1 with one agent already present: refused without touching the CSPRNG. */
    assert_int_equal(OS_AddNewAgent(&keys, NULL, "agent2", "any", NULL, 1), OS_ADDAGENT_LIMIT_REACHED);
}

/* --- OS_IsValidAgentKey ------------------------------------------------------------------------ */

static void test_valid_agent_key_accepts_exactly_64_lowercase_hex(void **state) {
    (void) state;
    assert_true(OS_IsValidAgentKey("0030557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c61ff"));
    assert_true(OS_IsValidAgentKey("0000000000000000000000000000000000000000000000000000000000000000"));
    assert_true(OS_IsValidAgentKey("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
}

static void test_valid_agent_key_rejects_other_shapes(void **state) {
    (void) state;
    assert_false(OS_IsValidAgentKey(NULL));
    assert_false(OS_IsValidAgentKey(""));
    /* 32 hex chars: 16 bytes, half the required key. */
    assert_false(OS_IsValidAgentKey("2b7e151628aed2a6abf7158809cf4f3c"));
    /* 48 hex chars: 24 bytes. */
    assert_false(OS_IsValidAgentKey("2b7e151628aed2a6abf7158809cf4f3c2b7e151628aed2a6"));
    /* 63 and 65 chars. */
    assert_false(OS_IsValidAgentKey("0030557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c61f"));
    assert_false(OS_IsValidAgentKey("0030557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c61ff0"));
    /* Uppercase, non-hex, whitespace. */
    assert_false(OS_IsValidAgentKey("0030557A9FC4E90E33587DA2C7EC11365B80A5CAEF14395E83A8CDF2173C61FF"));
    assert_false(OS_IsValidAgentKey("0030557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c61fg"));
    assert_false(OS_IsValidAgentKey("0030557a9fc4e90e33587da2c7ec11365b80a5caef14395e83a8cdf2173c61f "));
    /* The API's alphanumeric shape that is not hex. */
    assert_false(OS_IsValidAgentKey("asdfASD0101asdfASD0101asdfASD0101asdfASD0101asdfASD0101asdfASD01"));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_add_new_agent_generates_a_64_hex_key, setup_keys, teardown_keys),
        cmocka_unit_test_setup_teardown(test_two_generated_keys_differ, setup_keys, teardown_keys),
        cmocka_unit_test_setup_teardown(test_csprng_failure_adds_nothing_and_reports_error, setup_keys, teardown_keys),
        cmocka_unit_test_setup_teardown(test_explicit_key_is_stored_verbatim, setup_keys, teardown_keys),
        cmocka_unit_test_setup_teardown(test_agent_limit_is_checked_before_generating, setup_keys, teardown_keys),
        cmocka_unit_test(test_valid_agent_key_accepts_exactly_64_lowercase_hex),
        cmocka_unit_test(test_valid_agent_key_rejects_other_shapes),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
