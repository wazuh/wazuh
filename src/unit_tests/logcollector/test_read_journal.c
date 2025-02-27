/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Includes */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <time.h>

#include "../../logcollector/logcollector.h"
#include "../../logcollector/journal_log.h"
#include "../../headers/shared.h"
#include "../wrappers/common.h"

bool w_journald_can_read(unsigned long owner_id);
void set_gs_journald_global(unsigned long owner_id, bool is_disabled, void * journal_ctx);

/* setup/teardown */

static int group_setup(void ** state) {
    test_mode = 1;
    return 0;
}

static int group_teardown(void ** state) {
    test_mode = 0;
    return 0;
}

/* Wraps of journal_log */
int __wrap_w_journal_context_create(w_journal_context_t ** ctx) { return mock_type(int); }

int __wrap_w_journal_context_seek_most_recent(w_journal_context_t * ctx) { return mock_type(int); }

int __wrap_w_journal_context_seek_timestamp(w_journal_context_t * ctx, uint64_t timestamp) {
    // check timestamp
    check_expected(timestamp);
    return mock_type(int);
}

int __wrap_w_journal_context_next_newest_filtered(w_journal_context_t * ctx, w_journal_filters_list_t filters) {
    return mock_type(int);
}

w_journal_entry_t * __wrap_w_journal_entry_dump(w_journal_context_t * ctx, w_journal_entry_dump_type_t type) {
    return mock_type(w_journal_entry_t *);
}

char * __wrap_w_journal_entry_to_string(w_journal_entry_t * entry) { return mock_type(char *); }

void __wrap_w_journal_entry_free(w_journal_entry_t * entry) { function_called(); }

bool __wrap_w_journal_rotation_detected(w_journal_context_t* ctx) { return mock_type(bool); }

/* Aux setters */
void set_gs_journald_ofe(bool exist, bool ofe, uint64_t timestamp);
bool journald_isDisabled();

/* Other wraps */
int __wrap_isDebug() { return mock(); }

int __wrap_w_msg_hash_queues_push(
    const char * str, char * file, unsigned long size, logtarget * targets, char queue_mq) {
    check_expected(str);
    check_expected(size);
    return mock_type(int);
}

int __wrap_can_read() { return mock_type(int); }

/* Test w_journald_can_read */
void test_w_journald_can_read_disable(void ** state) {
    set_gs_journald_global(0, true, NULL);
    assert_false(w_journald_can_read(0));
}

void test_w_journald_can_read_check_owner(void ** state) {
    set_gs_journald_global(2, false, NULL);
    assert_false(w_journald_can_read(1));
    will_return(__wrap_w_journal_rotation_detected, false);
    assert_true(w_journald_can_read(2));
}

void test_w_journald_can_read_first_time_init_fail() {
    int tid = 3;

    set_gs_journald_global(0, false, NULL);

    will_return(__wrap_w_journal_context_create, -1);
    expect_string(__wrap__merror, formatted_msg, "(1608): Failed to connect to the journal, disabling journal log.");

    assert_false(w_journald_can_read(tid));
    assert_true(journald_isDisabled());
}

void test_w_journald_can_read_first_time_init_fail_seek() {
    int tid = 3;

    set_gs_journald_global(0, false, NULL);
    set_gs_journald_ofe(true, true, 123);

    will_return(__wrap_w_journal_context_create, 0);

    will_return(__wrap_w_journal_context_seek_most_recent, -1);

    expect_string(__wrap__merror,
                  formatted_msg,
                  "(1609): Failed to move to the end of the journal, disabling journal log: Operation not permitted.");

    assert_false(w_journald_can_read(tid));
    assert_true(journald_isDisabled());
}

void test_w_journald_can_read_first_time_init_ofe_yes(void ** state) {

    int tid = 3;

    set_gs_journald_global(0, false, NULL);
    set_gs_journald_ofe(true, true, 123);

    will_return(__wrap_w_journal_context_create, 0);

    will_return(__wrap_w_journal_context_seek_most_recent, 0);

    expect_string(__wrap__minfo, formatted_msg, "(9203): Monitoring journal entries.");

    assert_true(w_journald_can_read(tid));
    assert_false(journald_isDisabled());
}

void test_w_journald_can_read_first_time_init_ofe_no(void ** state) {
    int tid = 3;

    set_gs_journald_global(0, false, NULL);
    set_gs_journald_ofe(true, false, 123);

    will_return(__wrap_w_journal_context_create, 0);

    expect_value(__wrap_w_journal_context_seek_timestamp, timestamp, 123);
    will_return(__wrap_w_journal_context_seek_timestamp, 0);

    expect_string(__wrap__minfo, formatted_msg, "(9203): Monitoring journal entries.");

    assert_true(w_journald_can_read(tid));
    assert_false(journald_isDisabled());
}

void test_w_journald_rotation_detected(void** state)
{
    int tid = 3;

    w_journal_context_t ctxt = {0};
    set_gs_journald_global(3, false, &ctxt);
    set_gs_journald_ofe(true, false, 123);

    will_return(__wrap_w_journal_rotation_detected, true);

    expect_string(__wrap__minfo, formatted_msg, "(9204): 'Journald' files rotation detected.");

    assert_false(w_journald_can_read(tid));
    assert_false(journald_isDisabled());
}

/* w_journald_set_ofe */
void test_w_journald_set_ofe(void ** state) {
    w_journald_set_ofe(true);
    w_journald_set_ofe(false);
}

void test_read_journald_can_read_false(void ** state) {

    // Prepare environment
    w_journal_context_t ctxt = {0};
    set_gs_journald_global(0, false, &ctxt);

    // Prepare args
    logreader lf = {0};
    w_journal_log_config_t journal_log = {0};
    lf.journal_log = &journal_log;
    int rc = 0;

    will_return(__wrap_can_read, 0);

    assert_null(read_journald(&lf, &rc, 0));
    assert_false(journald_isDisabled());
}

void test_read_journald_next_entry_error(void ** state) {
    // Prepare environment
    w_journal_context_t ctxt = {0};
    set_gs_journald_global(0, false, &ctxt);

    // Prepare args
    logreader lf = {0};
    w_journal_log_config_t journal_log = {0};
    lf.journal_log = &journal_log;
    int rc = 0;

    // Can read
    will_return(__wrap_can_read, 1);

    // Fail get nex entry
    will_return(__wrap_w_journal_context_next_newest_filtered, -1);
    expect_string(__wrap__merror,
                  formatted_msg,
                  "(1610): Failed to get the next entry, disabling journal log: Operation not permitted.");

    assert_null(read_journald(&lf, &rc, 0));
    assert_true(journald_isDisabled());
}

void test_read_journald_next_entry_no_new_entry(void ** state) {

    // Prepare environment
    w_journal_context_t ctxt = {0};
    set_gs_journald_global(0, false, &ctxt);

    // Prepare args
    logreader lf = {0};
    w_journal_log_config_t journal_log = {0};
    lf.journal_log = &journal_log;
    int rc = 0;

    // Can read
    will_return(__wrap_can_read, 1);

    // Nothing to read
    will_return(__wrap_w_journal_context_next_newest_filtered, 0);
    expect_string(__wrap__mdebug2, formatted_msg, "(9006): No new entries in the journal.");

    assert_null(read_journald(&lf, &rc, 0));
    assert_false(journald_isDisabled());
}

void test_read_journald_dump_entry_error(void ** state) {

    // Prepare environment
    w_journal_context_t ctxt = {0};
    set_gs_journald_global(0, false, &ctxt);

    // Prepare args
    logreader lf = {0};
    w_journal_log_config_t journal_log = {0};
    lf.journal_log = &journal_log;
    int rc = 0;

    // Can read
    will_return(__wrap_can_read, 1);

    // Fail get nex entry
    will_return(__wrap_w_journal_context_next_newest_filtered, 1);
    will_return(__wrap_w_journal_entry_dump, NULL);
    will_return(__wrap_w_journal_entry_to_string, NULL);
    expect_function_call(__wrap_w_journal_entry_free);

    expect_string(__wrap__mdebug1, formatted_msg, "(1611): Failed to get the message from the journal");

    assert_null(read_journald(&lf, &rc, 0));
    assert_false(journald_isDisabled());
}

void test_read_journald_dump_entry_max_len(void ** state) {

    // Prepare environment
    w_journal_context_t ctxt = {0};
    set_gs_journald_global(0, false, &ctxt);

    // Prepare args
    logreader lf = {0};
    w_journal_log_config_t journal_log = {0};
    lf.journal_log = &journal_log;
    int rc = 0;

    // Can read
    will_return(__wrap_can_read, 1);

    // Fail get nex entry
    will_return(__wrap_w_journal_context_next_newest_filtered, 1);
    will_return(__wrap_w_journal_entry_dump, 0x1);
    will_return(__wrap_w_journal_entry_to_string, strdup("MAX_STR_>>>_16_|xxxxxxxx"));
    expect_function_call(__wrap_w_journal_entry_free);

    expect_string(
        __wrap__mdebug1, formatted_msg, "(9007): Message size > maximum allowed, The message will be truncated.");

    will_return(__wrap_isDebug, 0);

    // Check message
    expect_string(__wrap_w_msg_hash_queues_push, str, "MAX_STR_>>>_16_|");
    expect_value(__wrap_w_msg_hash_queues_push, size, strlen("MAX_STR_>>>_16_|") + 1);
    will_return(__wrap_w_msg_hash_queues_push, 0);

    // Brek the loop
    will_return(__wrap_can_read, 0);

    assert_null(read_journald(&lf, &rc, 0));
    assert_false(journald_isDisabled());
}

void test_read_journald_dump_entry_debug(void ** state) {

    // Prepare environment
    w_journal_context_t ctxt = {0};
    set_gs_journald_global(0, false, &ctxt);

    // Prepare args
    logreader lf = {0};
    w_journal_log_config_t journal_log = {0};
    lf.journal_log = &journal_log;
    int rc = 0;

    // Can read
    will_return(__wrap_can_read, 1);

    // Fail get nex entry
    will_return(__wrap_w_journal_context_next_newest_filtered, 1);
    will_return(__wrap_w_journal_entry_dump, 0x1);
    will_return(__wrap_w_journal_entry_to_string, strdup("message test"));
    expect_function_call(__wrap_w_journal_entry_free);

    will_return(__wrap_isDebug, 2);

    expect_string(__wrap__mdebug2, formatted_msg, "(9008): Reading from journal: 'message test'.");

    // Check message
    expect_string(__wrap_w_msg_hash_queues_push, str, "message test");
    expect_value(__wrap_w_msg_hash_queues_push, size, strlen("message test") + 1);
    will_return(__wrap_w_msg_hash_queues_push, 0);

    // Brek the loop
    will_return(__wrap_can_read, 0);

    assert_null(read_journald(&lf, &rc, 0));
    assert_false(journald_isDisabled());
}

int main(void) {

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_w_journald_set_ofe),
        /* Test w_journald_can_read */
        cmocka_unit_test(test_w_journald_can_read_disable),
        cmocka_unit_test(test_w_journald_can_read_check_owner),
        cmocka_unit_test(test_w_journald_can_read_first_time_init_fail),
        cmocka_unit_test(test_w_journald_can_read_first_time_init_fail_seek),
        cmocka_unit_test(test_w_journald_can_read_first_time_init_ofe_yes),
        cmocka_unit_test(test_w_journald_can_read_first_time_init_ofe_no),
        cmocka_unit_test(test_w_journald_rotation_detected),
        /* Test read_journald */
        cmocka_unit_test(test_read_journald_can_read_false),
        cmocka_unit_test(test_read_journald_next_entry_error),
        cmocka_unit_test(test_read_journald_next_entry_no_new_entry),
        cmocka_unit_test(test_read_journald_dump_entry_error),
        cmocka_unit_test(test_read_journald_dump_entry_max_len),
        cmocka_unit_test(test_read_journald_dump_entry_debug),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
