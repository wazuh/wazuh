/*
 * Copyright (C) 2015-2021, Wazuh Inc.
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


static int group_setup(void **state) {
    test_mode = 1;
    return 0;
}

static int group_teardown(void **state) {
    test_mode = 0;
    return 0;
}

static const char * MESSAGE = "AB";


static void test_bqueue_init_fail(void **state) {
    (void) state;
    
    // 1-byte queue is forbidden
    bqueue_t * queue = bqueue_init(1, 0);
    assert_null(queue);

    free(queue);
}

static void test_bqueue_init_ok(void **state) {
    (void) state;

    // 2-byte queue is allowed
    bqueue_t * queue = bqueue_init(2, 0);
    assert_non_null(queue);
    bqueue_destroy(queue);
}

static void test_bqueue_destroy_ok(void **state) {
    (void) state;

    bqueue_t * queue = bqueue_init(2, 0);
    bqueue_destroy(queue);
    assert_non_null(queue);
}

static void test_bqueue_push_fail(void **state) {
    (void) state;
    // inserting 2 bytes is forbidden
    bqueue_t * queue = bqueue_init(2, 0);

    int r = bqueue_push(queue, MESSAGE, strlen(MESSAGE), 0);

    assert_non_null(queue);
    assert_int_equal(r, -1);

    bqueue_destroy(queue);
}

static void test_bqueue_push_ok(void **state) {
    (void) state;
    // inserting 2 bytes is allowed
    bqueue_t * queue = bqueue_init(3, 0);

    int r = bqueue_push(queue, MESSAGE, strlen(MESSAGE), 0);

    assert_non_null(queue);
    assert_int_equal(r, 0);

    bqueue_destroy(queue);
}

static void test_bqueue_push_pop_ok(void **state) {
    (void) state;

    bqueue_t * queue = bqueue_init(3, 0);

    int push = bqueue_push(queue, MESSAGE, strlen(MESSAGE), 0);

    char buffer[3] = "";

    int pop = bqueue_pop(queue, buffer, sizeof(buffer), 0);

    assert_non_null(queue);
    assert_int_equal(push, 0);
    assert_int_equal(pop, strlen(MESSAGE));
    assert_string_equal(MESSAGE, buffer);

    bqueue_destroy(queue);
}

static void test_bqueue_push_pop_used_ok(void **state) {
    (void) state;

    bqueue_t * queue = bqueue_init(3, 0);
    // Push 2 char
    int push = bqueue_push(queue, MESSAGE, strlen(MESSAGE), 0);

    char buffer[3] = "";
    // Try to pop 3 bytes, but it should return 2 
    int pop = bqueue_pop(queue, buffer, sizeof(buffer), 0);
    // queue should be 0
    size_t used = bqueue_used(queue);

    assert_non_null(queue);
    assert_int_equal(push, 0);
    assert_int_equal(pop, strlen(MESSAGE));
    assert_int_equal(used, 0);
    assert_string_equal(MESSAGE, buffer);

    bqueue_destroy(queue);
}

static void test_bqueue_push_peek_drop_ok(void **state) {
    (void) state;

    bqueue_t * queue = bqueue_init(3, 0);
    // Push 2 char
    int push = bqueue_push(queue, MESSAGE, strlen(MESSAGE), 0);

    char buffer[3] = "";
    // Try to peek 3 bytes, but it should return 2 
    int peek = bqueue_peek(queue, buffer, sizeof(buffer), 0);
    // drop peeked bytes
    int ret = bqueue_drop(queue, peek);
    // queue should be 0
    size_t used = bqueue_used(queue);

    assert_non_null(queue);
    assert_int_equal(push, 0);
    assert_int_equal(peek, strlen(MESSAGE));
    assert_int_equal(ret, 0);
    assert_int_equal(used, 0);
    assert_string_equal(MESSAGE, buffer);

    bqueue_destroy(queue);
}

static void test_bqueue_push_peek_drop_fail(void **state) {
    (void) state;

    bqueue_t * queue = bqueue_init(3, 0);
    // Push 2 char
    int push = bqueue_push(queue, MESSAGE, strlen(MESSAGE), 0);

    char buffer[3] = "";
    // Try to peek 3 bytes, but it should return 2 
    int peek = bqueue_peek(queue, buffer, sizeof(buffer), 0);
    // drop more bytes than used.
    int ret = bqueue_drop(queue, peek + 2);

    assert_non_null(queue);
    assert_int_equal(push, 0);
    assert_int_equal(peek, strlen(MESSAGE));
    assert_int_equal(ret, -1);

    bqueue_destroy(queue);
}

static void test_bqueue_push_clear_ok(void **state) {
    (void) state;

    bqueue_t * queue = bqueue_init(3, 0);
    assert_non_null(queue);

    // Push 2 char
    int push = bqueue_push(queue, MESSAGE, strlen(MESSAGE), 0);
    assert_int_equal(push, 0);

    size_t used = bqueue_used(queue);
    assert_int_equal(used, strlen(MESSAGE));
    
    bqueue_clear(queue);
    used = bqueue_used(queue);
    assert_int_equal(used, 0);
    
    bqueue_destroy(queue);
}

static void test_bqueue_push_pop_full_buff(void **state) {
    (void) state;

    /* This test will complete 1024 bytes of bufer with AB string,
       pop and validate last 2 bytes

       Buffer: |ABABABAB........ABABAB| 
                                    ^^
    */

    bqueue_t * queue = bqueue_init(1024+1, 0);
    int push;
    int a;
    
    for (a = 0; a < (1024 / strlen(MESSAGE)); a++) {
        if (bqueue_push(queue, MESSAGE, strlen(MESSAGE), 0) != 0) {
            assert_null(queue);
            break;
        }
    }

    assert_int_equal(bqueue_used(queue), 1024);

    char buffer[3] = "";

    for (a = 0; a < (1024 / strlen(MESSAGE)); a++) {
        if (bqueue_pop(queue, buffer, strlen(MESSAGE), 0) != strlen(MESSAGE)) {
            assert_null(queue);
            break;
        }
    }
    
    assert_string_equal(MESSAGE, buffer);
    assert_int_equal(bqueue_used(queue), 0);
    assert_non_null(queue);

    bqueue_destroy(queue);
}

static void test_bqueue_push_pop_rollover(void **state) {
    (void) state;

    /* This test will complete 1022 spaces of 1024 bufer with AB string, 
       and pop first 3 bytes, then push 5 new bytes and validate last 5 bytes
       
       Buffer: |345BABAB........ABAB12| 
                ^^^                 ^^
    */

    int push;
    int a;
    char buffer[1024] = "";
    bqueue_t * queue = bqueue_init(1024+1, BQUEUE_SHRINK);
    
    // complete fist 1022 buffer spaces with "AB"     
    for (a = 0; a < (1024 / strlen(MESSAGE) -1 ); a++) {
        if (bqueue_push(queue, MESSAGE, strlen(MESSAGE), 0) != 0) {
            assert_null(queue);
            break;
        }
    }
    assert_int_equal(bqueue_used(queue), 1022);
    
    // pop fist 3 bytes.
    bqueue_pop(queue, buffer, 3, 0);
    assert_string_equal(buffer, "ABA");
    
    // push new string "12345" to roll over buffer
    assert_int_equal(bqueue_push(queue, "12345", 5, 0), 0);
    
    // pop 1022 - 3 bytes to point before last bytes of the buffer "1"
    assert_int_equal(bqueue_pop(queue, buffer, 1019, 0), 1019);

    memset(buffer, 0, sizeof(buffer));
    /* pop 5 bytes, before last and last byte of the buffer, 
       and first 3 bytes of the buffer "12345"   */
    assert_int_equal(bqueue_pop(queue, buffer, 5, 0), 5);

    assert_string_equal("12345", buffer);
    assert_non_null(queue);

    bqueue_destroy(queue);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_bqueue_init_fail),
        cmocka_unit_test(test_bqueue_init_ok),
        cmocka_unit_test(test_bqueue_destroy_ok),
        cmocka_unit_test(test_bqueue_push_fail),
        cmocka_unit_test(test_bqueue_push_ok),
        cmocka_unit_test(test_bqueue_push_pop_ok),
        cmocka_unit_test(test_bqueue_push_pop_used_ok),
        cmocka_unit_test(test_bqueue_push_peek_drop_ok),
        cmocka_unit_test(test_bqueue_push_peek_drop_fail),
        cmocka_unit_test(test_bqueue_push_clear_ok),
        cmocka_unit_test(test_bqueue_push_pop_full_buff),
        cmocka_unit_test(test_bqueue_push_pop_rollover),
    };
    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
