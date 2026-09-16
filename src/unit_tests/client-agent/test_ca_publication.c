/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cmocka.h>

#include "../../client-agent/include/ca_publication.h"

#define STORE_PATH "ca_publication_test.pem"

/* A real certificate is not needed: w_ca_publication_read() stops at the first encapsulation
 * boundary and never parses what follows. */
#define CERT_BODY "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n"

static void write_store(const char *content) {
    FILE *fp = fopen(STORE_PATH, "w");
    assert_non_null(fp);
    fputs(content, fp);
    fclose(fp);
}

static int teardown_store(void **state) {
    (void) state;
    unlink(STORE_PATH);
    return 0;
}

/* The shape w_ca_publication_render() writes, read back. */
static void test_reads_the_publication_it_rendered(void **state) {
    (void) state;
    char block[128];
    char store[512];

    assert_int_equal(w_ca_publication_render(1789000012LL, block, sizeof(block)), 0);

    snprintf(store, sizeof(store), "%s%s", block, CERT_BODY);
    write_store(store);

    assert_int_equal(w_ca_publication_read(STORE_PATH), 1789000012LL);
}

/* A store written by an agent predating this feature, or placed by hand: the bundle is still
 * usable, the publication simply is not known. */
static void test_a_bare_bundle_has_no_publication(void **state) {
    (void) state;
    write_store(CERT_BODY);

    assert_int_equal(w_ca_publication_read(STORE_PATH), W_CA_PUBLICATION_UNKNOWN);
}

static void test_a_missing_store_has_no_publication(void **state) {
    (void) state;

    assert_int_equal(w_ca_publication_read("no-such-store.pem"), W_CA_PUBLICATION_UNKNOWN);
}

static void test_a_null_path_has_no_publication(void **state) {
    (void) state;

    assert_int_equal(w_ca_publication_read(NULL), W_CA_PUBLICATION_UNKNOWN);
}

/* Comments the agent did not write are skipped rather than tripped over. */
static void test_unrelated_comments_are_ignored(void **state) {
    (void) state;
    write_store("## something else\n# operator note\n## generation: 42\n" CERT_BODY);

    assert_int_equal(w_ca_publication_read(STORE_PATH), 42);
}

/* A publication is only ever positive; 0 is what the manager sends for "published by nobody",
 * and the agent never adopts that, so it can never be what is on disk either. */
static void test_a_zero_publication_is_not_accepted(void **state) {
    (void) state;
    write_store("## generation: 0\n" CERT_BODY);

    assert_int_equal(w_ca_publication_read(STORE_PATH), W_CA_PUBLICATION_UNKNOWN);
}

static void test_a_negative_publication_is_not_accepted(void **state) {
    (void) state;
    write_store("## generation: -5\n" CERT_BODY);

    assert_int_equal(w_ca_publication_read(STORE_PATH), W_CA_PUBLICATION_UNKNOWN);
}

static void test_a_non_numeric_publication_is_not_accepted(void **state) {
    (void) state;
    write_store("## generation: latest\n" CERT_BODY);

    assert_int_equal(w_ca_publication_read(STORE_PATH), W_CA_PUBLICATION_UNKNOWN);
}

/* Reading "1789000012" out of "1789000012x" would be guessing at what the writer meant. */
static void test_trailing_junk_rejects_the_line(void **state) {
    (void) state;
    write_store("## generation: 1789000012x\n" CERT_BODY);

    assert_int_equal(w_ca_publication_read(STORE_PATH), W_CA_PUBLICATION_UNKNOWN);
}

static void test_a_publication_beyond_64_bits_is_not_accepted(void **state) {
    (void) state;
    write_store("## generation: 99999999999999999999999\n" CERT_BODY);

    assert_int_equal(w_ca_publication_read(STORE_PATH), W_CA_PUBLICATION_UNKNOWN);
}

/* Only the header is searched. A file whose certificates somehow contain the prefix must not
 * have a publication read out of their body. */
static void test_the_search_stops_at_the_first_certificate(void **state) {
    (void) state;
    write_store(CERT_BODY "## generation: 1789000012\n");

    assert_int_equal(w_ca_publication_read(STORE_PATH), W_CA_PUBLICATION_UNKNOWN);
}

/* A file that is all comments and no certificates is not a trust store; the scan gives up
 * rather than reading it to its end. */
static void test_a_very_long_header_gives_up(void **state) {
    (void) state;
    char store[4096] = {0};
    size_t used = 0;
    int i;

    for (i = 0; i < 64; i++) {
        used += (size_t) snprintf(store + used, sizeof(store) - used, "## filler %d\n", i);
    }

    snprintf(store + used, sizeof(store) - used, "## generation: 7\n" CERT_BODY);
    write_store(store);

    assert_int_equal(w_ca_publication_read(STORE_PATH), W_CA_PUBLICATION_UNKNOWN);
}

static void test_render_refuses_a_non_positive_publication(void **state) {
    (void) state;
    char block[128];

    assert_int_equal(w_ca_publication_render(0, block, sizeof(block)), -1);
    assert_int_equal(w_ca_publication_render(-1, block, sizeof(block)), -1);
}

static void test_render_refuses_a_buffer_it_would_overrun(void **state) {
    (void) state;
    char block[8];

    assert_int_equal(w_ca_publication_render(1789000012LL, block, sizeof(block)), -1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_teardown(test_reads_the_publication_it_rendered, teardown_store),
        cmocka_unit_test_teardown(test_a_bare_bundle_has_no_publication, teardown_store),
        cmocka_unit_test(test_a_missing_store_has_no_publication),
        cmocka_unit_test(test_a_null_path_has_no_publication),
        cmocka_unit_test_teardown(test_unrelated_comments_are_ignored, teardown_store),
        cmocka_unit_test_teardown(test_a_zero_publication_is_not_accepted, teardown_store),
        cmocka_unit_test_teardown(test_a_negative_publication_is_not_accepted, teardown_store),
        cmocka_unit_test_teardown(test_a_non_numeric_publication_is_not_accepted, teardown_store),
        cmocka_unit_test_teardown(test_trailing_junk_rejects_the_line, teardown_store),
        cmocka_unit_test_teardown(test_a_publication_beyond_64_bits_is_not_accepted, teardown_store),
        cmocka_unit_test_teardown(test_the_search_stops_at_the_first_certificate, teardown_store),
        cmocka_unit_test_teardown(test_a_very_long_header_gives_up, teardown_store),
        cmocka_unit_test(test_render_refuses_a_non_positive_publication),
        cmocka_unit_test(test_render_refuses_a_buffer_it_would_overrun),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
