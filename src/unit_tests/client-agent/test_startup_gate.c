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
#include "sha256_op.h"

extern agent *agt;

/* One feed since #38030: the manager's SHA-256 config_hash against a SHA-256 of
 * the local merged.mg. The MD5 merged_sum feed went with the TCP data path. */

static const char *MANAGER_SHA256 =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
static const char *OTHER_SHA256 =
    "0000000000000000000000000000000000000000000000000000000000000000";

/* Mock OS_SHA256_File(): a test primes the local merged.mg's hash, or a
 * non-zero return for "no readable local file". */
int __wrap_OS_SHA256_File(const char *fname, os_sha256 output, int mode) {
    check_expected(fname);
    check_expected(mode);
    const char *hash = mock_ptr_type(const char *);

    if (hash != NULL) {
        snprintf(output, sizeof(os_sha256), "%s", hash);
    }

    return (int)mock();
}

static void expect_local_sha256(const char *hash, int retval) {
    expect_string(__wrap_OS_SHA256_File, fname, SHAREDCFG_FILE);
    expect_value(__wrap_OS_SHA256_File, mode, OS_BINARY);
    will_return(__wrap_OS_SHA256_File, hash);
    will_return(__wrap_OS_SHA256_File, retval);
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

/* When remote_conf is enabled, initialize() leaves the gate blocked waiting for
 * the manager's config hash. */
static void test_initialize_remote_conf_enabled_blocks_gate(void **state) {
    (void)state;
    assert_gate_state(false, "waiting_config_hash");
}

/* --- startup_gate_check_manager_config_hash ----------------------------- */

/* The manager's hash matches the local merged.mg: the agent booted in sync, so
 * nothing downloads or reloads and this is what opens the gate. */
static void test_manager_config_hash_match_releases_gate(void **state) {
    (void)state;
    expect_local_sha256(MANAGER_SHA256, 0);
    expect_string(__wrap__mdebug1, formatted_msg,
                  "Startup hash gate: manager config hash (SHA-256) matches local, gate released.");

    startup_gate_check_manager_config_hash(MANAGER_SHA256);

    assert_gate_state(true, "https_hash_match");
}

/* A different hash means a download is coming: the gate stays blocked. */
static void test_manager_config_hash_mismatch_keeps_gate_blocked(void **state) {
    (void)state;
    expect_local_sha256(OTHER_SHA256, 0);

    startup_gate_check_manager_config_hash(MANAGER_SHA256);

    assert_gate_state(false, "waiting_config_hash");
}

/* An empty (contract-legal) manager hash means there is no configuration to
 * wait for: nothing downloads, so the gate must open or every module blocks
 * forever in startup_gate_wait_for_ready(). No OS_SHA256_File mock is queued --
 * the local file is irrelevant here. */
static void test_manager_config_hash_empty_releases_gate(void **state) {
    (void)state;
    expect_string(__wrap__mdebug1, formatted_msg,
                  "Startup hash gate: the manager reported no configuration, gate released.");

    startup_gate_check_manager_config_hash("");

    assert_gate_state(true, "no_manager_config");
}

/* Same for an absent field (NULL). */
static void test_manager_config_hash_null_releases_gate(void **state) {
    (void)state;
    expect_string(__wrap__mdebug1, formatted_msg,
                  "Startup hash gate: the manager reported no configuration, gate released.");

    startup_gate_check_manager_config_hash(NULL);

    assert_gate_state(true, "no_manager_config");
}

/* Already released (remote_conf disabled): silent, and no file is read. */
static void test_manager_config_hash_is_noop_when_released(void **state) {
    (void)state;

    startup_gate_check_manager_config_hash(MANAGER_SHA256);
    startup_gate_check_manager_config_hash("");

    assert_gate_state(true, "disabled");
}

/* First boot, no local merged.mg: nothing to compare. */
static void test_manager_config_hash_without_local_file_keeps_gate_blocked(void **state) {
    (void)state;
    expect_local_sha256(NULL, -1);

    startup_gate_check_manager_config_hash(MANAGER_SHA256);

    assert_gate_state(false, "waiting_config_hash");
}

/* bridge_on_config_downloaded() writes SHAREDCFG_FILE with the manager's exact
 * bytes before it has dispatched (or even decided whether to dispatch) the
 * reload that is supposed to release the gate with https_config_applied. A
 * Notify landing in that window must not let the opportunistic hash-match
 * path steal the release with the wrong reason -- no OS_SHA256_File mock is
 * queued, so cmocka fails this test if the hash comparison runs at all. */
static void test_manager_config_hash_match_suppressed_while_download_pending(void **state) {
    (void)state;
    startup_gate_mark_download_pending();

    startup_gate_check_manager_config_hash(MANAGER_SHA256);

    assert_gate_state(false, "waiting_config_hash");
}

/* Once the download's own reload completes, release_from_https_apply() must
 * still be the one to open the gate -- with https_config_applied, not
 * whatever the suppressed hash-match attempt would have set. */
static void test_release_from_https_apply_wins_race_over_pending_hash_match(void **state) {
    (void)state;
    startup_gate_mark_download_pending();
    startup_gate_check_manager_config_hash(MANAGER_SHA256);
    assert_gate_state(false, "waiting_config_hash");

    expect_string(__wrap__mdebug1, formatted_msg,
                  "Startup hash gate released via HTTPS configuration apply (https_config_applied).");

    startup_gate_release_from_https_apply();

    assert_gate_state(true, "https_config_applied");
}

/* --- startup_gate_release_from_https_apply ------------------------------ */

/* Blocked + remote_conf enabled: releases directly, with no hash comparison (no
 * OS_SHA256_File mock is queued, so cmocka fails if one is attempted). */
static void test_release_from_https_apply_releases_blocked_gate(void **state) {
    (void)state;
    expect_string(__wrap__mdebug1, formatted_msg,
                  "Startup hash gate released via HTTPS configuration apply (https_config_applied).");

    startup_gate_release_from_https_apply();

    assert_gate_state(true, "https_config_applied");
}

/* remote_conf disabled: the gate is already released (by initialize()); this
 * must be a silent no-op, not re-log a release. */
static void test_release_from_https_apply_is_noop_when_disabled(void **state) {
    (void)state;
    /* No expect_any(__wrap__mdebug1, ...): must not log anything. */
    startup_gate_release_from_https_apply();

    assert_gate_state(true, "disabled");
}

/* Idempotent: calling it again once already released (e.g. a later config
 * download after the gate is already open) must not re-log or change state. */
static void test_release_from_https_apply_is_noop_once_already_released(void **state) {
    (void)state;
    expect_string(__wrap__mdebug1, formatted_msg,
                  "Startup hash gate released via HTTPS configuration apply (https_config_applied).");
    startup_gate_release_from_https_apply();
    assert_gate_state(true, "https_config_applied");

    /* Second call: already ready, so the enabled-and-not-ready guard skips the
     * log/reason-update entirely -- no expect_any queued means cmocka fails
     * this test if it logs again. */
    startup_gate_release_from_https_apply();
    assert_gate_state(true, "https_config_applied");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_initialize_remote_conf_disabled_releases_gate,
                                        setup_remote_conf_disabled, teardown_gate),
        cmocka_unit_test_setup_teardown(test_initialize_remote_conf_enabled_blocks_gate,
                                        setup_remote_conf_enabled, teardown_gate),
        cmocka_unit_test_setup_teardown(test_manager_config_hash_match_releases_gate,
                                        setup_remote_conf_enabled, teardown_gate),
        cmocka_unit_test_setup_teardown(test_manager_config_hash_mismatch_keeps_gate_blocked,
                                        setup_remote_conf_enabled, teardown_gate),
        cmocka_unit_test_setup_teardown(test_manager_config_hash_without_local_file_keeps_gate_blocked,
                                        setup_remote_conf_enabled, teardown_gate),
        cmocka_unit_test_setup_teardown(test_manager_config_hash_empty_releases_gate,
                                        setup_remote_conf_enabled, teardown_gate),
        cmocka_unit_test_setup_teardown(test_manager_config_hash_null_releases_gate,
                                        setup_remote_conf_enabled, teardown_gate),
        cmocka_unit_test_setup_teardown(test_manager_config_hash_is_noop_when_released,
                                        setup_remote_conf_disabled, teardown_gate),
        cmocka_unit_test_setup_teardown(test_manager_config_hash_match_suppressed_while_download_pending,
                                        setup_remote_conf_enabled, teardown_gate),
        cmocka_unit_test_setup_teardown(test_release_from_https_apply_wins_race_over_pending_hash_match,
                                        setup_remote_conf_enabled, teardown_gate),
        cmocka_unit_test_setup_teardown(test_release_from_https_apply_releases_blocked_gate,
                                        setup_remote_conf_enabled, teardown_gate),
        cmocka_unit_test_setup_teardown(test_release_from_https_apply_is_noop_when_disabled,
                                        setup_remote_conf_disabled, teardown_gate),
        cmocka_unit_test_setup_teardown(test_release_from_https_apply_is_noop_once_already_released,
                                        setup_remote_conf_enabled, teardown_gate),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
