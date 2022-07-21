/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "../headers/bqueue_op.h"

static const char * MESSAGE = "AB";


static int test_setup_2(void **state) {
    test_mode = 1;

    bqueue_t *bqueue = bqueue_init(2, BQUEUE_NOFLAG);
    *state = bqueue;
    return 0;
}

static int test_setup_3(void **state) {
    test_mode = 1;

    bqueue_t *bqueue = bqueue_init(3, BQUEUE_NOFLAG);
    *state = bqueue;
    return 0;
}

static int test_setup_20(void **state) {
    test_mode = 1;

    bqueue_t *bqueue = bqueue_init(20, BQUEUE_NOFLAG);
    *state = bqueue;
    return 0;
}

static int test_setup_1024(void **state) {
    test_mode = 1;

    bqueue_t *bqueue = bqueue_init(1024+1, BQUEUE_SHRINK);
    *state = bqueue;
    return 0;
}

static int test_teardown(void **state) {
    test_mode = 0;

    bqueue_t *bqueue = *state;
    bqueue_destroy(bqueue);
    return 0;
}

static void test_bqueue_init_fail(void **state) {
    (void) state;

    // 1-byte queue is forbidden
    bqueue_t * queue = bqueue_init(1, BQUEUE_NOFLAG);
    assert_null(queue);

    free(queue);
}

static void test_bqueue_init_ok(void **state) {
    (void) state;

    // 2-byte queue is allowed
    bqueue_t * queue = bqueue_init(2, BQUEUE_NOFLAG);
    assert_non_null(queue);
    bqueue_destroy(queue);
}

static void test_bqueue_destroy_fail(void **state) {
    (void) state;

    bqueue_t * queue = NULL;
    bqueue_destroy(queue);
    assert_null(queue);
}

static void test_bqueue_destroy_ok(void **state) {
    (void) state;

    bqueue_t * queue = bqueue_init(2, BQUEUE_NOFLAG);
    bqueue_destroy(queue);
    assert_non_null(queue);
}

static void test_bqueue_push_fail(void **state) {
    bqueue_t *queue = *state;

    assert_non_null(queue);
    assert_int_equal(bqueue_push(queue, MESSAGE, strlen(MESSAGE), BQUEUE_NOFLAG), -1);
}

static void test_bqueue_push_fail_non_space(void **state) {
    bqueue_t *queue = *state;

    assert_non_null(queue);
    assert_int_equal(bqueue_push(queue, MESSAGE, strlen(MESSAGE), BQUEUE_NOFLAG), 0);
    assert_int_equal(bqueue_push(queue, MESSAGE, strlen(MESSAGE), BQUEUE_NOFLAG), -1);
}

static void test_bqueue_push_ok(void **state) {
    bqueue_t *queue = *state;

    assert_non_null(queue);
    assert_int_equal(bqueue_push(queue, MESSAGE, strlen(MESSAGE), BQUEUE_NOFLAG), 0);
}

static void test_bqueue_push_pop_ok(void **state) {
    bqueue_t *queue = *state;

    assert_non_null(queue);
    assert_int_equal(bqueue_push(queue, MESSAGE, strlen(MESSAGE), BQUEUE_NOFLAG), 0);

    char buffer[3] = "";
    assert_int_equal(bqueue_pop(queue, buffer, sizeof(buffer), BQUEUE_NOFLAG), strlen(MESSAGE));
    assert_string_equal(MESSAGE, buffer);
}

static void test_bqueue_push_second_pop_fail(void **state) {
    bqueue_t *queue = *state;

    assert_non_null(queue);
    assert_int_equal(bqueue_push(queue, MESSAGE, strlen(MESSAGE), BQUEUE_NOFLAG), 0);

    char buffer[3] = "";
    assert_int_equal(bqueue_pop(queue, buffer, sizeof(buffer), BQUEUE_NOFLAG), strlen(MESSAGE));
    assert_int_equal(bqueue_pop(queue, buffer, sizeof(buffer), BQUEUE_NOFLAG), 0);
}

static void test_bqueue_push_pop_used_ok(void **state) {
    bqueue_t *queue = *state;

    assert_non_null(queue);
    // Push 2 char
    assert_int_equal(bqueue_push(queue, MESSAGE, strlen(MESSAGE), BQUEUE_NOFLAG), 0);

    char buffer[3] = "";
    // Try to pop 3 bytes, but it should return 2
    assert_int_equal(bqueue_pop(queue, buffer, sizeof(buffer), BQUEUE_WAIT), strlen(MESSAGE));
    // queue should be 0
    assert_int_equal(bqueue_used(queue), 0);
    assert_string_equal(MESSAGE, buffer);
}

static void test_bqueue_push_second_peek_empty(void **state) {
    bqueue_t *queue = *state;

    assert_non_null(queue);
    // Push 2 char
    assert_int_equal(bqueue_push(queue, MESSAGE, strlen(MESSAGE), BQUEUE_NOFLAG), 0);

    char buffer[3] = "";
    // Try to peek 3 bytes, but it should return 2
    assert_int_equal(bqueue_peek(queue, buffer, sizeof(buffer), BQUEUE_WAIT), strlen(MESSAGE));
    // drop more bytes than used.
    assert_int_equal(bqueue_drop(queue, 2), 0);
    // second peek
    assert_int_equal(bqueue_peek(queue, buffer, sizeof(buffer), BQUEUE_NOFLAG), 0);
}

static void test_bqueue_push_peek_drop_ok(void **state) {
    bqueue_t *queue = *state;

    assert_non_null(queue);

    // Push 2 char
    assert_int_equal(bqueue_push(queue, MESSAGE, strlen(MESSAGE), BQUEUE_NOFLAG), 0);

    char buffer[3] = "";
    // Try to peek 3 bytes, but it should return 2
    assert_int_equal(bqueue_peek(queue, buffer, sizeof(buffer), BQUEUE_NOFLAG), strlen(MESSAGE));
    // drop peeked bytes
    assert_int_equal(bqueue_drop(queue, 2), 0);
    // queue should be 0
    assert_int_equal(bqueue_used(queue), 0);
    assert_string_equal(MESSAGE, buffer);
}

static void test_bqueue_push_peek_drop_fail(void **state) {
    bqueue_t *queue = *state;

    assert_non_null(queue);
    // Push 2 char
    assert_int_equal(bqueue_push(queue, MESSAGE, strlen(MESSAGE), BQUEUE_NOFLAG), 0);

    char buffer[3] = "";
    // Try to peek 3 bytes, but it should return 2
    assert_int_equal(bqueue_peek(queue, buffer, sizeof(buffer), BQUEUE_WAIT), strlen(MESSAGE));
    // drop more bytes than used.
    assert_int_equal(bqueue_drop(queue, 4), -1);
}

static void test_bqueue_push_clear_ok(void **state) {
    bqueue_t *queue = *state;

    assert_non_null(queue);

    // Push 2 char
    int push = bqueue_push(queue, MESSAGE, strlen(MESSAGE), BQUEUE_WAIT);
    assert_int_equal(push, 0);

    size_t used = bqueue_used(queue);
    assert_int_equal(used, strlen(MESSAGE));

    bqueue_clear(queue);
    used = bqueue_used(queue);
    assert_int_equal(used, 0);
}

static void test_bqueue_push_pop_full_buff(void **state) {
    /* This test will complete 1024 bytes of bufer with AB string,
       pop and validate last 2 bytes

       Buffer: |ABABABAB........ABABAB|
                                    ^^
    */
    bqueue_t *queue = *state;

    for (int a = 0; a < (1024 / strlen(MESSAGE)); a++) {
        if (bqueue_push(queue, MESSAGE, strlen(MESSAGE), BQUEUE_NOFLAG) != 0) {
            assert_null(queue);
            break;
        }
    }

    assert_int_equal(bqueue_used(queue), 1024);

    char buffer[3] = "";

    for (int a = 0; a < (1024 / strlen(MESSAGE)); a++) {
        if (bqueue_pop(queue, buffer, strlen(MESSAGE), BQUEUE_NOFLAG) != strlen(MESSAGE)) {
            assert_null(queue);
            break;
        }
    }

    assert_string_equal(MESSAGE, buffer);
    assert_int_equal(bqueue_used(queue), 0);
    assert_non_null(queue);
}

static void test_bqueue_push_pop_rollover(void **state) {
    /* This test will complete 1022 spaces of 1024 bufer with AB string,
       and pop first 3 bytes, then push 5 new bytes and validate last 5 bytes

       Buffer: |345BABAB........ABAB12|
                ^^^                 ^^
    */
    bqueue_t *queue = *state;

    char buffer[1024] = "";
    // complete fist 1022 buffer spaces with "AB"
    for (int a = 0; a < (1024 / strlen(MESSAGE) -1 ); a++) {
        if (bqueue_push(queue, MESSAGE, strlen(MESSAGE), BQUEUE_NOFLAG) != 0) {
            assert_null(queue);
            break;
        }
    }
    assert_int_equal(bqueue_used(queue), 1022);

    // pop first 3 bytes.
    bqueue_pop(queue, buffer, 3, BQUEUE_NOFLAG);
    assert_string_equal(buffer, "ABA");

    // push new string "12345" to roll over buffer
    assert_int_equal(bqueue_push(queue, "12345", 5, BQUEUE_NOFLAG), 0);

    // pop 1022 - 3 bytes to point before last bytes of the buffer "1"
    assert_int_equal(bqueue_pop(queue, buffer, 1019, BQUEUE_NOFLAG), 1019);

    memset(buffer, 0, sizeof(buffer));
    /* pop 5 bytes, before last and last byte of the buffer,
       and first 3 bytes of the buffer "12345"   */
    assert_int_equal(bqueue_pop(queue, buffer, 5, BQUEUE_NOFLAG), 5);

    assert_string_equal("12345", buffer);
    assert_non_null(queue);
}

static void test_bqueue_push_drop_cross_pointers(void **state) {
    /*
       Buffer: |345...AB12|
                  T   H
    */
    bqueue_t *queue = *state;

    char buffer[11] = "";
    assert_non_null(queue);

    // complete fist 10 buffer spaces with "AB"
    for (int a = 0; a < (10 / strlen(MESSAGE)-1); a++) {
        if (bqueue_push(queue, MESSAGE, strlen(MESSAGE), BQUEUE_NOFLAG) != 0) {
            assert_null(queue);
            break;
        }
    }
    assert_int_equal(bqueue_used(queue), 8);

    // drop first 6 bytes.
    assert_int_equal(bqueue_drop(queue, 6), 0);

    // push new string "12345" to roll over buffer
    assert_int_equal(bqueue_push(queue, "12345", 5, BQUEUE_NOFLAG), 0);

    // push another string "67890" to roll over buffer
    assert_int_equal(bqueue_push(queue, "67890", 5, BQUEUE_NOFLAG), 0);

    // pop 2 bytes
    assert_int_equal(bqueue_pop(queue, buffer, 2, BQUEUE_NOFLAG), 2);
    assert_string_equal("AB", buffer);

    memset(buffer, 0, sizeof(buffer));
    /* pop 5 bytes, before last and last byte of the buffer,
       and first 3 bytes of the buffer "12345"   */
    assert_int_equal(bqueue_pop(queue, buffer, 10, BQUEUE_NOFLAG), 10);

    assert_string_equal("1234567890", buffer);
}

static void test_bqueue_push_drop_to_expand(void **state) {

    bqueue_t *queue = *state;

    char buffer[10] = "";
    assert_non_null(queue);

    // push 10 elements into the table.
    assert_int_equal(bqueue_push(queue, "1234567890", 10, BQUEUE_NOFLAG), 0);
    assert_int_equal(bqueue_used(queue), 10);

    // drop first 6 bytes.
    assert_int_equal(bqueue_drop(queue, 6), 0);

    // push new string "12345" to roll over buffer
    assert_int_equal(bqueue_push(queue, "12345", 5, BQUEUE_NOFLAG), 0);

    // pop 3 bytes
    assert_int_equal(bqueue_pop(queue, buffer, 3, BQUEUE_NOFLAG), 3);
    assert_string_equal("789", buffer);

    // push another string "67890"
    assert_int_equal(bqueue_push(queue, "67890", 5, BQUEUE_NOFLAG), 0);

    memset(buffer, 0, sizeof(buffer));
    // pop 2 bytes
    assert_int_equal(bqueue_pop(queue, buffer, 2, BQUEUE_NOFLAG), 2);
    assert_string_equal("01", buffer);

    memset(buffer, 0, sizeof(buffer));
    // pop 7 bytes
    assert_int_equal(bqueue_pop(queue, buffer, 7, BQUEUE_NOFLAG), 7);

    assert_string_equal("2345678", buffer);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_bqueue_init_fail),
        cmocka_unit_test(test_bqueue_init_ok),
        cmocka_unit_test(test_bqueue_destroy_fail),
        cmocka_unit_test(test_bqueue_destroy_ok),
        cmocka_unit_test_setup_teardown(test_bqueue_push_fail, test_setup_2, test_teardown),
        cmocka_unit_test_setup_teardown(test_bqueue_push_fail_non_space, test_setup_3, test_teardown),
        cmocka_unit_test_setup_teardown(test_bqueue_push_ok, test_setup_3, test_teardown),
        cmocka_unit_test_setup_teardown(test_bqueue_push_pop_ok, test_setup_3, test_teardown),
        cmocka_unit_test_setup_teardown(test_bqueue_push_second_pop_fail, test_setup_3, test_teardown),
        cmocka_unit_test_setup_teardown(test_bqueue_push_pop_used_ok, test_setup_3, test_teardown),
        cmocka_unit_test_setup_teardown(test_bqueue_push_second_peek_empty, test_setup_3, test_teardown),
        cmocka_unit_test_setup_teardown(test_bqueue_push_peek_drop_ok, test_setup_3, test_teardown),
        cmocka_unit_test_setup_teardown(test_bqueue_push_peek_drop_fail, test_setup_3, test_teardown),
        cmocka_unit_test_setup_teardown(test_bqueue_push_clear_ok, test_setup_3, test_teardown),
        cmocka_unit_test_setup_teardown(test_bqueue_push_pop_full_buff, test_setup_1024, test_teardown),
        cmocka_unit_test_setup_teardown(test_bqueue_push_pop_rollover, test_setup_1024, test_teardown),
        cmocka_unit_test_setup_teardown(test_bqueue_push_drop_cross_pointers, test_setup_20, test_teardown),
        cmocka_unit_test_setup_teardown(test_bqueue_push_drop_to_expand, test_setup_20, test_teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
