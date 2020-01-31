/*
 * Copyright (C) 2015-2019, Wazuh Inc.
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

#include "../syscheckd/syscheck.h"

/* Globals */
extern w_queue_t * fim_sync_queue;

/* redefinitons/wrapping */
int __wrap_fim_send_sync_msg(char * msg) {
    check_expected(msg);
    return 1;
}

int __wrap_time() {
    return 1572521857;
}

void __wrap__mwarn(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__mdebug1(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__mdebug2(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

int __wrap_queue_push_ex(w_queue_t * queue, void * data) {
    int retval = mock();

    check_expected_ptr(queue);
    check_expected(data);

    if(retval != -1)
        free(data);     //  This won't be used, free it

    return retval;
}

/* setup/teardown */
static int setup_fim_sync_queue(void **state) {
    fim_sync_queue = queue_init(10);

    return 0;
}

static int teardown_fim_sync_queue(void **state) {
    queue_free(fim_sync_queue);

    fim_sync_queue = NULL;

    return 0;
}

// static int teardown_free_fim_entry_mutex(void **state) {
//     w_mutex_unlock(&syscheck.fim_entry_mutex);

//     return 0;
// }

/* tests */
static void test_fim_sync_push_msg_success(void **state) {
    char *msg = "This is a mock message, it won't go anywhere";

    expect_value(__wrap_queue_push_ex, queue, fim_sync_queue);
    expect_string(__wrap_queue_push_ex, data, msg);
    will_return(__wrap_queue_push_ex, 0);

    fim_sync_push_msg(msg);
}

static void test_fim_sync_push_msg_queue_full(void **state) {
    char *msg = "This is a mock message, it won't go anywhere";

    expect_value(__wrap_queue_push_ex, queue, fim_sync_queue);
    expect_string(__wrap_queue_push_ex, data, msg);
    will_return(__wrap_queue_push_ex, -1);

    expect_string(__wrap__mdebug2, formatted_msg, "Cannot push a data synchronization message: queue is full.");

    fim_sync_push_msg(msg);
}

static void test_fim_sync_push_msg_no_response(void **state) {
    expect_string(__wrap__mwarn, formatted_msg,
        "A data synchronization response was received before sending the first message.");

    fim_sync_push_msg("test");
}

/* fim_sync_checksum */
static void test_fim_sync_checksum_first_row_error(void **state) {}
static void test_fim_sync_checksum_last_row_error(void **state) {}
static void test_fim_sync_checksum_checksum_error(void **state) {}
static void test_fim_sync_checksum_empty_db(void **state) {}
static void test_fim_sync_checksum_success(void **state) {}

/* fim_sync_checksum_split */
static void test_fim_sync_checksum_split_get_count_range_error(void **state) {}
static void test_fim_sync_checksum_split_range_size_0(void **state) {}
static void test_fim_sync_checksum_split_range_size_1(void **state) {}
static void test_fim_sync_checksum_split_range_size_1_get_path_error(void **state) {}
static void test_fim_sync_checksum_split_range_size_default(void **state) {}

/* fim_sync_send_list */
static void test_fim_sync_send_list_sync_path_range_error(void **state) {}
static void test_fim_sync_send_list_success(void **state) {}

/* fim_sync_dispatch */
static void test_fim_sync_dispatch_null_payload(void **state) {}
static void test_fim_sync_dispatch_no_argument(void **state) {}
static void test_fim_sync_dispatch_invalid_argument(void **state) {}
static void test_fim_sync_dispatch_id_not_number(void **state) {}
static void test_fim_sync_dispatch_drop_message(void **state) {}
static void test_fim_sync_dispatch_no_begin_object(void **state) {}
static void test_fim_sync_dispatch_checksum_fail(void **state) {}
static void test_fim_sync_dispatch_no_data(void **state) {}
static void test_fim_sync_dispatch_unwknown_command(void **state) {}

int main(void) {
    const struct CMUnitTest tests[] = {
        /* fim_sync_push */
        cmocka_unit_test_setup_teardown(test_fim_sync_push_msg_success, setup_fim_sync_queue, teardown_fim_sync_queue),
        cmocka_unit_test_setup_teardown(test_fim_sync_push_msg_queue_full, setup_fim_sync_queue, teardown_fim_sync_queue),
        cmocka_unit_test(test_fim_sync_push_msg_no_response),

        cmocka_unit_test(test_fim_sync_checksum_first_row_error),
        cmocka_unit_test(test_fim_sync_checksum_last_row_error),
        cmocka_unit_test(test_fim_sync_checksum_checksum_error),
        cmocka_unit_test(test_fim_sync_checksum_empty_db),
        cmocka_unit_test(test_fim_sync_checksum_success),
        cmocka_unit_test(test_fim_sync_checksum_split_get_count_range_error),
        cmocka_unit_test(test_fim_sync_checksum_split_range_size_0),
        cmocka_unit_test(test_fim_sync_checksum_split_range_size_1),
        cmocka_unit_test(test_fim_sync_checksum_split_range_size_1_get_path_error),
        cmocka_unit_test(test_fim_sync_checksum_split_range_size_default),
        cmocka_unit_test(test_fim_sync_send_list_sync_path_range_error),
        cmocka_unit_test(test_fim_sync_send_list_success),
        cmocka_unit_test(test_fim_sync_dispatch_null_payload),
        cmocka_unit_test(test_fim_sync_dispatch_no_argument),
        cmocka_unit_test(test_fim_sync_dispatch_invalid_argument),
        cmocka_unit_test(test_fim_sync_dispatch_id_not_number),
        cmocka_unit_test(test_fim_sync_dispatch_drop_message),
        cmocka_unit_test(test_fim_sync_dispatch_no_begin_object),
        cmocka_unit_test(test_fim_sync_dispatch_checksum_fail),
        cmocka_unit_test(test_fim_sync_dispatch_no_data),
        cmocka_unit_test(test_fim_sync_dispatch_unwknown_command),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
