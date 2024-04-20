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
int __wrap_w_journal_context_create(w_journal_context_t ** ctx) {
    return mock_type(int);
}

int __wrap_w_journal_context_seek_most_recent(w_journal_context_t * ctx) {
    return mock_type(int);
}

int __wrap_w_journal_context_seek_timestamp(w_journal_context_t * ctx, uint64_t timestamp) {
    // check timestamp
    

    return mock_type(int);
}

int __wrap_w_journal_context_next_newest_filtered(w_journal_context_t * ctx, w_journal_filters_list_t filters) {
    return 0;
}

w_journal_entry_t * __wrap_w_journal_entry_dump(w_journal_context_t * ctx, w_journal_entry_dump_type_t type) {
    return 0;
}

char * __wrap_w_journal_entry_to_string(w_journal_entry_t * entry) {
    return 0;
}

void __wrap_w_journal_entry_free(w_journal_entry_t * entry) {
    return;
}

/* Aux setters */
void set_gs_journald_ofe(bool exist, bool ofe, uint64_t timestamp);

/*  */
int __wrap_isDebug() {
    return mock();
}

int __wrap_w_msg_hash_queues_push(const char * str, char * file, unsigned long size, logtarget * targets,
                                  char queue_mq) {
    return mock_type(int);
}


/* Test w_journald_can_read */
void test_w_journald_can_read_disable(void **  state) {
    set_gs_journald_global(0, true, NULL);
    assert_false(w_journald_can_read(0));
}

void test_w_journald_can_read_check_owner(void **  state) {
    set_gs_journald_global(2, false, NULL);
    assert_false(w_journald_can_read(1));
    assert_true(w_journald_can_read(2));
}


void test_w_journald_can_read_first_time_init_fail() {
    int tid = 3;


    set_gs_journald_global(0, false, NULL);

    will_return(__wrap_w_journal_context_create, -1);
    expect_string(__wrap__merror, formatted_msg, "(1608): Failed to connect to the journal, disabling journal log.");
   
    assert_false(w_journald_can_read(tid));
}


void test_w_journald_can_read_first_time_init_fail_seek() {
    int tid = 3;


    set_gs_journald_global(0, false, NULL);
    set_gs_journald_ofe(true, true, 123);

    will_return(__wrap_w_journal_context_create, 0);

    will_return(__wrap_w_journal_context_seek_most_recent, -1);

    expect_string(__wrap__merror, formatted_msg, "(1609): Failed to move to the end of the journal, disabling journal log: Operation not permitted.");
   
    assert_false(w_journald_can_read(tid));
}



/* w_journald_set_ofe */
void test_w_journald_set_ofe(void **state) {
    w_journald_set_ofe(true);
    w_journald_set_ofe(false);
}

int main(void) {

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_w_journald_set_ofe),
        /* Test w_journald_can_read */
        cmocka_unit_test(test_w_journald_can_read_disable),
        cmocka_unit_test(test_w_journald_can_read_check_owner),
        cmocka_unit_test(test_w_journald_can_read_first_time_init_fail),
        cmocka_unit_test(test_w_journald_can_read_first_time_init_fail_seek),

    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
