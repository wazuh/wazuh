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
#include <string.h>
#include <stdlib.h>

#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

#include "agentd.h"
#include "../os_crypto/md5/md5_op.h"

extern agent *agt;

/* A 32-char hex MD5 string used as the canonical expected value across tests. */
static const char *VALID_MD5_A = "0123456789abcdef0123456789abcdef";
static const char *VALID_MD5_B = "fedcba9876543210fedcba9876543210";
static const char *INVALID_MD5_NONHEX = "0123456789abcdef0123456789abcdez";   /* trailing 'z' */
static const char *INVALID_MD5_SHORT  = "0123456789abcdef";                    /* too short */

/* Mock getsharedfiles(): each test that needs it primes a strdup'd return value
 * with will_return(__wrap_getsharedfiles, strdup("...")). The production code
 * frees the returned string with os_free(). */
char * __wrap_getsharedfiles(void) {
    return mock_ptr_type(char *);
}

/* Helper: query gate state and assert it matches expected. */
static void assert_gate_state(bool expected_ready, const char *expected_reason) {
    bool ready = !expected_ready;
    char reason[OS_SIZE_128] = {0};
    startup_gate_get_status(&ready, reason, sizeof(reason));
    assert_int_equal((int)ready, (int)expected_ready);
    assert_string_equal(reason, expected_reason);
}

/* --- setup/teardown ------------------------------------------------------ */

static int setup_remote_conf_enabled(void **state) {
    (void)state;
    test_mode = 1;
    agt = (agent *)calloc(1, sizeof(agent));
    agt->flags.remote_conf = 1;
    startup_gate_initialize();
    return 0;
}

static int setup_remote_conf_disabled(void **state) {
    (void)state;
    test_mode = 1;
    agt = (agent *)calloc(1, sizeof(agent));
    agt->flags.remote_conf = 0;
    startup_gate_initialize();
    return 0;
}

static int teardown_gate(void **state) {
    (void)state;
    free(agt);
    agt = NULL;
    test_mode = 0;
    return 0;
}

/* --- tests -------------------------------------------------------------- */

/* When remote_conf is disabled, initialize() releases the gate. */
static void test_initialize_remote_conf_disabled_releases_gate(void **state) {
    (void)state;
    assert_gate_state(true, "disabled");
}

/* When remote_conf is enabled, initialize() leaves the gate blocked. */
static void test_initialize_remote_conf_enabled_blocks_gate(void **state) {
    (void)state;
    assert_gate_state(false, "waiting_handshake");
}

/* process_handshake with is_startup=false is a no-op (gate state unchanged). */
static void test_process_handshake_not_startup_is_noop(void **state) {
    (void)state;
    /* Pre-condition: gate is blocked (waiting_handshake) from initialize(). */
    startup_gate_process_handshake(false, VALID_MD5_A);
    /* No mdebug1 expected — no_op path */
    assert_gate_state(false, "waiting_handshake");
}

/* With remote_conf disabled, process_handshake immediately releases the gate. */
static void test_process_handshake_remote_conf_disabled(void **state) {
    (void)state;
    expect_any(__wrap__mdebug1, formatted_msg);
    startup_gate_process_handshake(true, VALID_MD5_A);
    assert_gate_state(true, "disabled");
}

/* NULL merged_sum → legacy_handshake (gate released). */
static void test_process_handshake_null_merged_sum_releases_gate(void **state) {
    (void)state;
    expect_any(__wrap__mdebug1, formatted_msg);
    startup_gate_process_handshake(true, NULL);
    assert_gate_state(true, "legacy_handshake");
}

/* Empty merged_sum → legacy_handshake (gate released). */
static void test_process_handshake_empty_merged_sum_releases_gate(void **state) {
    (void)state;
    expect_any(__wrap__mdebug1, formatted_msg);
    startup_gate_process_handshake(true, "");
    assert_gate_state(true, "legacy_handshake");
}

/* Invalid (non-hex) merged_sum → gate stays BLOCKED at invalid_handshake_hash.
 * The agent must not start modules when the manager handshake gives us no
 * valid hash to validate against; modules stay blocked until a fresh
 * handshake (typically after an agentd restart) provides a valid hash. */
static void test_process_handshake_invalid_md5_nonhex_blocks_gate(void **state) {
    (void)state;
    expect_any(__wrap__mdebug1, formatted_msg);
    startup_gate_process_handshake(true, INVALID_MD5_NONHEX);
    assert_gate_state(false, "invalid_handshake_hash");
}

/* Short merged_sum (not 32 chars) → gate stays BLOCKED. */
static void test_process_handshake_invalid_md5_short_blocks_gate(void **state) {
    (void)state;
    expect_any(__wrap__mdebug1, formatted_msg);
    startup_gate_process_handshake(true, INVALID_MD5_SHORT);
    assert_gate_state(false, "invalid_handshake_hash");
}

/* Valid MD5 + local hash matches → gate released immediately. */
static void test_process_handshake_valid_md5_local_matches_releases_gate(void **state) {
    (void)state;
    /* getsharedfiles() will be called once by startup_gate_hash_matches_local(). */
    will_return(__wrap_getsharedfiles, strdup(VALID_MD5_A));
    /* Two debug logs: "expected merged_sum set" + "local hash matches". */
    expect_any_count(__wrap__mdebug1, formatted_msg, 2);

    startup_gate_process_handshake(true, VALID_MD5_A);
    assert_gate_state(true, "hash_match");
}

/* Valid MD5 + local hash does NOT match → gate stays blocked at waiting_hash_match. */
static void test_process_handshake_valid_md5_local_mismatch_blocks_gate(void **state) {
    (void)state;
    will_return(__wrap_getsharedfiles, strdup(VALID_MD5_B));
    /* Two debug logs: "expected merged_sum set" + "local hash does not match". */
    expect_any_count(__wrap__mdebug1, formatted_msg, 2);

    startup_gate_process_handshake(true, VALID_MD5_A);
    assert_gate_state(false, "waiting_hash_match");
}

/* refresh_from_local_hash releases the gate when local hash now matches expected. */
static void test_refresh_from_local_hash_matches_releases_gate(void **state) {
    (void)state;
    /* First: place the gate into "waiting_hash_match" with expected = VALID_MD5_A. */
    will_return(__wrap_getsharedfiles, strdup(VALID_MD5_B));
    expect_any_count(__wrap__mdebug1, formatted_msg, 2);
    startup_gate_process_handshake(true, VALID_MD5_A);
    assert_gate_state(false, "waiting_hash_match");

    /* Now refresh: local hash matches expected → released. */
    will_return(__wrap_getsharedfiles, strdup(VALID_MD5_A));
    startup_gate_refresh_from_local_hash();
    assert_gate_state(true, "hash_match");
}

/* refresh_from_local_hash leaves the gate blocked when local hash still doesn't match. */
static void test_refresh_from_local_hash_mismatch_keeps_gate_blocked(void **state) {
    (void)state;
    will_return(__wrap_getsharedfiles, strdup(VALID_MD5_B));
    expect_any_count(__wrap__mdebug1, formatted_msg, 2);
    startup_gate_process_handshake(true, VALID_MD5_A);
    assert_gate_state(false, "waiting_hash_match");

    /* refresh with still-mismatching local hash → no change. */
    will_return(__wrap_getsharedfiles, strdup(VALID_MD5_B));
    startup_gate_refresh_from_local_hash();
    assert_gate_state(false, "waiting_hash_match");
}

/* refresh_from_local_hash is a no-op when expected_sum is empty (no handshake yet). */
static void test_refresh_from_local_hash_without_expected_sum_is_noop(void **state) {
    (void)state;
    /* No handshake processed → expected_sum stays empty → getsharedfiles
     * must NOT be called. If it were, cmocka would fail on missing will_return. */
    startup_gate_refresh_from_local_hash();
    assert_gate_state(false, "waiting_handshake");
}

/* check_hash_match returns true only when blocked AND local hash matches. */
static void test_check_hash_match_true_when_blocked_and_matches(void **state) {
    (void)state;
    will_return(__wrap_getsharedfiles, strdup(VALID_MD5_B));
    expect_any_count(__wrap__mdebug1, formatted_msg, 2);
    startup_gate_process_handshake(true, VALID_MD5_A);
    /* Now blocked at waiting_hash_match with expected=VALID_MD5_A. */

    will_return(__wrap_getsharedfiles, strdup(VALID_MD5_A));
    assert_true(startup_gate_check_hash_match());
}

/* check_hash_match returns false when not blocked. */
static void test_check_hash_match_false_when_not_blocked(void **state) {
    (void)state;
    /* Gate is at "waiting_handshake" (initialize), which is blocked. Move to
     * released first via the disabled-conf shortcut. */
    expect_any(__wrap__mdebug1, formatted_msg);
    startup_gate_process_handshake(true, NULL);  /* legacy_handshake → released */
    assert_true(startup_gate_is_ready());

    /* No will_return needed: check_hash_match's "can_check" guard returns
     * early when the gate is already ready, so getsharedfiles is not called. */
    assert_false(startup_gate_check_hash_match());
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_initialize_remote_conf_disabled_releases_gate,
                                        setup_remote_conf_disabled, teardown_gate),
        cmocka_unit_test_setup_teardown(test_initialize_remote_conf_enabled_blocks_gate,
                                        setup_remote_conf_enabled, teardown_gate),
        cmocka_unit_test_setup_teardown(test_process_handshake_not_startup_is_noop,
                                        setup_remote_conf_enabled, teardown_gate),
        cmocka_unit_test_setup_teardown(test_process_handshake_remote_conf_disabled,
                                        setup_remote_conf_disabled, teardown_gate),
        cmocka_unit_test_setup_teardown(test_process_handshake_null_merged_sum_releases_gate,
                                        setup_remote_conf_enabled, teardown_gate),
        cmocka_unit_test_setup_teardown(test_process_handshake_empty_merged_sum_releases_gate,
                                        setup_remote_conf_enabled, teardown_gate),
        cmocka_unit_test_setup_teardown(test_process_handshake_invalid_md5_nonhex_blocks_gate,
                                        setup_remote_conf_enabled, teardown_gate),
        cmocka_unit_test_setup_teardown(test_process_handshake_invalid_md5_short_blocks_gate,
                                        setup_remote_conf_enabled, teardown_gate),
        cmocka_unit_test_setup_teardown(test_process_handshake_valid_md5_local_matches_releases_gate,
                                        setup_remote_conf_enabled, teardown_gate),
        cmocka_unit_test_setup_teardown(test_process_handshake_valid_md5_local_mismatch_blocks_gate,
                                        setup_remote_conf_enabled, teardown_gate),
        cmocka_unit_test_setup_teardown(test_refresh_from_local_hash_matches_releases_gate,
                                        setup_remote_conf_enabled, teardown_gate),
        cmocka_unit_test_setup_teardown(test_refresh_from_local_hash_mismatch_keeps_gate_blocked,
                                        setup_remote_conf_enabled, teardown_gate),
        cmocka_unit_test_setup_teardown(test_refresh_from_local_hash_without_expected_sum_is_noop,
                                        setup_remote_conf_enabled, teardown_gate),
        cmocka_unit_test_setup_teardown(test_check_hash_match_true_when_blocked_and_matches,
                                        setup_remote_conf_enabled, teardown_gate),
        cmocka_unit_test_setup_teardown(test_check_hash_match_false_when_not_blocked,
                                        setup_remote_conf_enabled, teardown_gate),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
