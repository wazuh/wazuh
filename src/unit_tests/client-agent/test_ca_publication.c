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

/* A real certificate, copied from test_x509_op.c: the install path parses what it wrote,
 * so a placeholder would only ever exercise the refusal. */
#define ROOT_CA_PEM \
    "-----BEGIN CERTIFICATE-----\n" \
    "MIIDSzCCAjOgAwIBAgIUJP7/SAPLSdxLbWKDzjDp88k4AAAwDQYJKoZIhvcNAQEL\n" \
    "BQAwNTEOMAwGA1UECwwFV2F6dWgxDjAMBgNVBAoMBVdhenVoMRMwEQYDVQQHDApD\n" \
    "YWxpZm9ybmlhMB4XDTI2MDQxNDEzNTAzN1oXDTM2MDQxMTEzNTAzN1owNTEOMAwG\n" \
    "A1UECwwFV2F6dWgxDjAMBgNVBAoMBVdhenVoMRMwEQYDVQQHDApDYWxpZm9ybmlh\n" \
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtQFyQMfZg9BkCde6Sa6O\n" \
    "8834rzeI81clYfEuDjflnwUTyp6BwHZTZ4F/cOBchKt2ZtnNR7Vx2wU5muDdF1QR\n" \
    "xnzDEV3vqETcGN7dxarYQtNCuvi/V0Zm0rme9Q9tW8u4iVwhva/jB5VJuDxlREfH\n" \
    "RL9pcjf9Dmvr1A9QRBgN0gsofAPri6gi8fLOfqddyNhLDHVd4BhYvB4wgxN5gXs/\n" \
    "KOCPGBhIuBb7BbdZDXMm+1PrBebZ1PgL1NEN4dtLQEq7/JXsJpeh8HGsH+WA91V7\n" \
    "HRI6O2nsT7YEiw4lGK/DfNroPrQ+G5Qq+Ouy5Z+8NnWV/WJu6tsv2TtqVCNG2Ift\n" \
    "vwIDAQABo1MwUTAdBgNVHQ4EFgQU2CaFfHEP1s0zMeo5QL/yLQl69EAwHwYDVR0j\n" \
    "BBgwFoAU2CaFfHEP1s0zMeo5QL/yLQl69EAwDwYDVR0TAQH/BAUwAwEB/zANBgkq\n" \
    "hkiG9w0BAQsFAAOCAQEAW2F0iQS92w4Q1im3ijS9qg2rnLuzrFeLkbhDNc1P4UIR\n" \
    "Wst/FKUV0MsYBvbotf2gNWSZEsKqDV5kYB4Ad1RUFIJGq0HEnrLEIgXZDgUkHaLQ\n" \
    "2FXSWDbq4Q3tROB2SiXk61Md6HOvfgT4/MYx/IoZB3fE8pP0vINA/TPw6WZsbz+K\n" \
    "93PEjHaMASUlUoowImFgV4uxzgfVWYWcUwi+IUehMqBgU3apvZ1ntUgw8CZTR7BQ\n" \
    "E3f6uPqaFJnQg2NZpc0bST6iF/bwKemDhdtd0pwgTivB3RrgSDjBqcR0DGTCKydU\n" \
    "gifB+SqxOI0UFNS5zvIQzUTRxMVDcdnB4NnkcZ/CBQ==\n" \
    "-----END CERTIFICATE-----\n"


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

/* The happy path, end to end on a real file: the bundle is installed and the publication it was
 * adopted at reads back from the same file. */
static void test_install_writes_the_bundle_and_its_publication(void **state) {
    (void) state;

    /* TempFile() emits a benign FSTAT_ERROR debug line the first time it templates on a path
     * that does not exist yet; a test that wrote the store first never sees it. */
    expect_any(__wrap__mdebug1, formatted_msg);

    expect_any(__wrap__minfo, formatted_msg);

    assert_int_equal(w_ca_publication_install(STORE_PATH, ROOT_CA_PEM, strlen(ROOT_CA_PEM),
                                              1789000012LL), 0);
    assert_int_equal(w_ca_publication_read(STORE_PATH), 1789000012LL);
}

/* Wholesale, not a merge: whatever was there is gone, which is how an operator retires a CA. */
static void test_install_replaces_what_was_there(void **state) {
    (void) state;

    write_store("## generation: 1\n" CERT_BODY);

    expect_any(__wrap__minfo, formatted_msg);

    assert_int_equal(w_ca_publication_install(STORE_PATH, ROOT_CA_PEM, strlen(ROOT_CA_PEM),
                                              1789000012LL), 0);
    assert_int_equal(w_ca_publication_read(STORE_PATH), 1789000012LL);

    /* The old placeholder body is gone rather than appended to. */
    FILE *fp = fopen(STORE_PATH, "r");
    char buf[4096] = {0};
    size_t n = fread(buf, 1, sizeof(buf) - 1, fp);
    (void) n;
    fclose(fp);
    assert_null(strstr(buf, "QUJD"));
}

/* Rule 6: a body that is not certificates must leave the existing trust store exactly as it
 * was. This is the case that would otherwise install something nothing can verify against. */
static void test_install_refuses_a_body_that_is_not_certificates(void **state) {
    (void) state;

    expect_any(__wrap__mdebug1, formatted_msg);
    const char *junk = "this is not a certificate at all\n";

    expect_any(__wrap__minfo, formatted_msg);
    expect_any(__wrap__merror, formatted_msg);

    assert_int_equal(w_ca_publication_install(STORE_PATH, ROOT_CA_PEM, strlen(ROOT_CA_PEM),
                                              1789000012LL), 0);
    assert_int_equal(w_ca_publication_install(STORE_PATH, junk, strlen(junk), 1789000013LL), -1);

    /* Still the bundle and publication from before the refusal. */
    assert_int_equal(w_ca_publication_read(STORE_PATH), 1789000012LL);
}

/* A bundle whose second block is corrupt is refused whole: w_x509_load_all_pem() reads to the
 * end of the file, so this cannot install a store that verifies less than it appears to. */
static void test_install_refuses_a_partially_corrupt_bundle(void **state) {
    (void) state;

    expect_any(__wrap__mdebug1, formatted_msg);
    char bundle[8192];

    snprintf(bundle, sizeof(bundle), "%s-----BEGIN CERTIFICATE-----\nnot base64\n"
             "-----END CERTIFICATE-----\n", ROOT_CA_PEM);

    expect_any(__wrap__merror, formatted_msg);

    assert_int_equal(w_ca_publication_install(STORE_PATH, bundle, strlen(bundle), 1789000012LL), -1);
    assert_int_equal(w_ca_publication_read(STORE_PATH), W_CA_PUBLICATION_UNKNOWN);
}

static void test_install_refuses_a_non_positive_publication(void **state) {
    (void) state;

    expect_any(__wrap__merror, formatted_msg);
    expect_any(__wrap__merror, formatted_msg);

    assert_int_equal(w_ca_publication_install(STORE_PATH, ROOT_CA_PEM, strlen(ROOT_CA_PEM), 0), -1);
    assert_int_equal(w_ca_publication_install(STORE_PATH, ROOT_CA_PEM, strlen(ROOT_CA_PEM), -1), -1);
}

static void test_install_refuses_an_empty_body(void **state) {
    (void) state;

    assert_int_equal(w_ca_publication_install(STORE_PATH, "", 0, 1789000012LL), -1);
    assert_int_equal(w_ca_publication_install(STORE_PATH, NULL, 10, 1789000012LL), -1);
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
        cmocka_unit_test_teardown(test_install_writes_the_bundle_and_its_publication, teardown_store),
        cmocka_unit_test_teardown(test_install_replaces_what_was_there, teardown_store),
        cmocka_unit_test_teardown(test_install_refuses_a_body_that_is_not_certificates, teardown_store),
        cmocka_unit_test_teardown(test_install_refuses_a_partially_corrupt_bundle, teardown_store),
        cmocka_unit_test_teardown(test_install_refuses_a_non_positive_publication, teardown_store),
        cmocka_unit_test_teardown(test_install_refuses_an_empty_body, teardown_store),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
