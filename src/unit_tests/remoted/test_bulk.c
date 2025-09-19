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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "../../remoted/bulk.h"
#include "../../headers/shared.h"

/*
 * Test: test_init_no_hint
 * Purpose: Verify that bulk_init with cap_hint = 0 leaves the buffer
 *          unallocated (buf == NULL), with len = 0 and cap = 0.
 * Why: Ensures the lazy-allocation contract is kept when no hint is provided.
 */
static void test_init_no_hint(void **state) {
    (void)state;
    bulk_t b;
    bulk_init(&b, 0);
    assert_null(b.buf);
    assert_int_equal(b.len, 0);
    assert_int_equal(b.cap, 0);
    bulk_free(&b);
}

/*
 * Test: test_init_with_small_hint_rounds_to_4096
 * Purpose: Verify that a small cap_hint (e.g., 100) triggers a reserve to the
 *          base capacity (4096), with len = 0 and cap >= 4096 (exactly 4096 by impl).
 * Why: Confirms the initial capacity growth policy and the base size semantics.
 */
static void test_init_with_small_hint_rounds_to_4096(void **state) {
    (void)state;
    bulk_t b;
    bulk_init(&b, 100);  // small hint -> grow to base 4096
    assert_non_null(b.buf);
    assert_int_equal(b.len, 0);
    assert_true(b.cap >= 4096);
    assert_int_equal(b.cap, 4096);   // matches current implementation
    bulk_free(&b);
}

/*
 * Test: test_reserve_pow2_growth
 * Purpose: Request 5000 bytes on an empty bulk; capacity should grow from base
 *          4096 to the next power-of-two-like step used by impl (8192).
 * Why: Validates the growth loop that multiplies capacity until need is met.
 */
static void test_reserve_pow2_growth(void **state) {
    (void)state;
    bulk_t b;
    bulk_init(&b, 0);
    assert_int_equal(bulk_reserve(&b, 5000), 0);
    assert_non_null(b.buf);
    assert_int_equal(b.cap, 8192);
    assert_int_equal(b.len, 0);
    bulk_free(&b);
}

/*
 * Test: test_append_bytes_updates_len_and_content
 * Purpose: Append two byte sequences and verify:
 *          - append succeeds,
 *          - len advances correctly,
 *          - buffer content matches the concatenated payload.
 * Why: Ensures bulk_append both reserves and copies correctly.
 */
static void test_append_bytes_updates_len_and_content(void **state) {
    (void)state;
    bulk_t b;
    bulk_init(&b, 0);

    const char *s = "hello";
    assert_int_equal(bulk_append(&b, s, 5), 0);
    assert_int_equal(b.len, 5);
    assert_memory_equal(b.buf, "hello", 5);

    const char *t = " world";
    assert_int_equal(bulk_append(&b, t, 6), 0);
    assert_int_equal(b.len, 11);
    assert_memory_equal(b.buf, "hello world", 11);

    bulk_free(&b);
}

/*
 * Test: test_append_triggers_growth_from_base
 * Purpose: Append 5000 bytes into an empty bulk and verify:
 *          - capacity grows to at least need (8192 by current policy),
 *          - len equals appended size,
 *          - content at boundaries is correct ('A' at 0 and 4999).
 * Why: Confirms growth path through bulk_append and correct memcpy.
 */
static void test_append_triggers_growth_from_base(void **state) {
    (void)state;
    bulk_t b;
    bulk_init(&b, 0);

    char buf[5000];
    memset(buf, 'A', sizeof(buf));
    assert_int_equal(bulk_append(&b, buf, sizeof(buf)), 0);
    assert_int_equal(b.len, 5000);
    assert_true(b.cap >= 5000);
    assert_int_equal(b.cap, 8192);
    assert_int_equal(b.buf[0], 'A');
    assert_int_equal(b.buf[4999], 'A');

    bulk_free(&b);
}

/*
 * Test: test_append_fmt_small_uses_stack_tmp
 * Purpose: Append a small formatted string that fits into the local 512-byte
 *          scratch buffer and verify len and content.
 * Why: Ensures the “small path” of bulk_append_fmt works and matches snprintf result.
 */
static void test_append_fmt_small_uses_stack_tmp(void **state) {
    (void)state;
    bulk_t b;
    bulk_init(&b, 0);

    int rc = bulk_append_fmt(&b, "x=%d y=%d", 7, 42);
    assert_int_equal(rc, 0);
    assert_int_equal(b.len, (int)strlen("x=7 y=42"));
    assert_memory_equal(b.buf, "x=7 y=42", b.len);

    bulk_free(&b);
}

/*
 * Test: test_append_fmt_large_allocates_and_appends
 * Purpose: Append a large formatted string (>511 chars) to force the “large path,”
 *          which allocates a temporary buffer, formats into it, then appends.
 *          Verifies len and boundary characters.
 * Why: Validates the heap-allocating branch and correct handoff to bulk_append.
 */
static void test_append_fmt_large_allocates_and_appends(void **state) {
    (void)state;
    bulk_t b;
    bulk_init(&b, 0);

    int width = 600;  // force the large path (more than 511 bytes)
    int rc = bulk_append_fmt(&b, "%0*d", width, 0);
    assert_int_equal(rc, 0);
    assert_int_equal((int)b.len, width);
    assert_int_equal(b.buf[0], '0');
    assert_int_equal(b.buf[width - 1], '0');

    bulk_free(&b);
}

/*
 * Test: test_append_fmt_chain_small_then_large
 * Purpose: Chain two formatted appends:
 *          - first a small formatted string,
 *          - then a large one (>511) to exercise both code paths back-to-back.
 *          Verifies final len, prefix content, and last char.
 * Why: Ensures state remains consistent across mixed small/large fmt appends.
 */
static void test_append_fmt_chain_small_then_large(void **state) {
    (void)state;
    bulk_t b;
    bulk_init(&b, 0);

    assert_int_equal(bulk_append_fmt(&b, "[%s]", "ok"), 0);
    int width = 520; // forces the large path
    assert_int_equal(bulk_append_fmt(&b, "%0*d", width, 0), 0);

    // Expected total: 4 ("[ok]") + 520 = 524
    assert_int_equal((int)b.len, 524);
    assert_memory_equal(b.buf, "[ok]", 4);
    assert_int_equal(b.buf[523], '0');

    bulk_free(&b);
}

/*
 * Test runner
 */
int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_init_no_hint),
        cmocka_unit_test(test_init_with_small_hint_rounds_to_4096),
        cmocka_unit_test(test_reserve_pow2_growth),
        cmocka_unit_test(test_append_bytes_updates_len_and_content),
        cmocka_unit_test(test_append_triggers_growth_from_base),
        cmocka_unit_test(test_append_fmt_small_uses_stack_tmp),
        cmocka_unit_test(test_append_fmt_large_allocates_and_appends),
        cmocka_unit_test(test_append_fmt_chain_small_then_large),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
