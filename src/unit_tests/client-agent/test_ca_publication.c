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
#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <cmocka.h>

#include "../../client-agent/include/ca_publication.h"

#define STORE_PATH "ca_publication_test.pem"
/* Stands in for a file an attacker would want the install to truncate. */
#define SENTINEL_PATH "ca_publication_test_sentinel"

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

/* rename() is the instant the trust store is committed, and #39321's crash-atomicity
 * criterion is a claim about exactly that instant: everything before it is invisible, and the
 * call itself either happens whole or not at all. The kernel guarantees the second half. The
 * first half is this code's responsibility, and wrapping rename() is what makes it assertable
 * -- the wrapper records what the destination held at the moment of commit, which is precisely
 * what a crash one instruction earlier would have left behind.
 *
 * It delegates to the real call unless a test asks otherwise, so the install still runs end to
 * end against real files. */
static int rename_fail_errno = 0;
static int rename_calls = 0;
static char rename_source[512] = {0};
static char rename_destination_at_commit[8192] = {0};

int __real_rename(const char *from, const char *to);

static size_t slurp(const char *path, char *out, size_t size) {
    FILE *fp = fopen(path, "r");
    size_t read = 0;

    out[0] = '\0';

    if (fp == NULL) {
        return 0;
    }

    read = fread(out, 1, size - 1, fp);
    out[read] = '\0';
    fclose(fp);
    return read;
}

int __wrap_rename(const char *from, const char *to) {
    rename_calls++;
    snprintf(rename_source, sizeof(rename_source), "%s", from);
    slurp(to, rename_destination_at_commit, sizeof(rename_destination_at_commit));

    if (rename_fail_errno != 0) {
        errno = rename_fail_errno;
        return -1;
    }

    return __real_rename(from, to);
}

/* How many files in the working directory begin with `prefix`. The staging file is the only
 * thing that ever creates one beside the store, so this counts orphans. */
static int count_files_with_prefix(const char *prefix) {
    DIR *dir = opendir(".");
    struct dirent *entry;
    int found = 0;

    assert_non_null(dir);

    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, prefix, strlen(prefix)) == 0) {
            found++;
        }
    }

    closedir(dir);
    return found;
}

static void write_store(const char *content) {
    FILE *fp = fopen(STORE_PATH, "w");
    assert_non_null(fp);
    fputs(content, fp);
    fclose(fp);
}

static int teardown_store(void **state) {
    (void) state;
    unlink(STORE_PATH);
    /* Fixed name, so a leftover really would be inherited by the next test rather than being
     * one more uniquely-named file nobody notices. */
    unlink(STORE_PATH ".tmp");
    unlink(SENTINEL_PATH);
    rename_fail_errno = 0;
    rename_calls = 0;
    rename_source[0] = '\0';
    rename_destination_at_commit[0] = '\0';
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

/* The crash-atomicity criterion, stated as the invariant it actually is: a crash at any point
 * before the commit leaves the old pair, because nothing before the commit touches the store.
 * The wrapper reads the destination at the instant of rename() -- the last moment a crash could
 * still find the old content there -- and it is still, byte for byte, what was installed before. */
static void test_install_leaves_the_store_untouched_until_the_commit(void **state) {
    (void) state;
    const char *original = "## generation: 1789000012\n" CERT_BODY;

    write_store(original);

    expect_any(__wrap__minfo, formatted_msg);

    assert_int_equal(w_ca_publication_install(STORE_PATH, ROOT_CA_PEM, strlen(ROOT_CA_PEM),
                                              1789000013LL), 0);

    assert_int_equal(rename_calls, 1);
    assert_string_equal(rename_destination_at_commit, original);

    /* And after it, the new pair -- so the assertion above is about timing, not about an
     * install that never happened. */
    assert_int_equal(w_ca_publication_read(STORE_PATH), 1789000013LL);
}

/* The commit is the only writer, so when it fails nothing has changed. This is a regression
 * test with a name: the install used to go through OS_MoveFile(), which falls back to a
 * read-write copy when rename() fails -- and a copy truncates the destination first. A crash
 * during that copy would leave the agent holding a fragment of a bundle: unable to verify the
 * manager, and so unable to reach /cacerts to repair itself.
 *
 * EPERM is not hypothetical here. The anchor lives in a sticky directory, where renaming over a
 * file owned by someone else is refused -- which is what a pre-#39321 install looks like until
 * its ownership is repaired. */
static void test_install_leaves_the_store_intact_when_the_commit_fails(void **state) {
    (void) state;
    const char *original = "## generation: 1789000012\n" CERT_BODY;
    char after[8192];

    write_store(original);
    rename_fail_errno = EPERM;

    expect_any(__wrap__merror, formatted_msg);

    assert_int_equal(w_ca_publication_install(STORE_PATH, ROOT_CA_PEM, strlen(ROOT_CA_PEM),
                                              1789000013LL), -1);

    slurp(STORE_PATH, after, sizeof(after));
    assert_string_equal(after, original);
    assert_int_equal(w_ca_publication_read(STORE_PATH), 1789000012LL);
}

/* Two properties of the staging file's name, both load-bearing, neither visible in any other
 * test here -- a refactor that broke either would pass the whole rest of this suite.
 *
 * Beside the store: rename() is atomic only within one filesystem, and across a boundary it
 * fails outright. A staging file in /tmp would work on most hosts and fail on the ones that
 * mount it separately.
 *
 * And exactly one name, not a template: a kill between the create and the rename leaves the
 * staging file behind, so a random name accumulates one orphan per interrupted install in a
 * directory whose contents are meant to be trust stores. A fixed name is reused by the next
 * attempt instead. */
static void test_the_temporary_file_is_committed_from_beside_the_store(void **state) {
    (void) state;

    expect_any(__wrap__minfo, formatted_msg);

    assert_int_equal(w_ca_publication_install(STORE_PATH, ROOT_CA_PEM, strlen(ROOT_CA_PEM),
                                              1789000012LL), 0);

    assert_int_equal(rename_calls, 1);
    assert_null(strchr(rename_source, '/'));     /* Same directory as STORE_PATH. */
    assert_string_equal(rename_source, STORE_PATH ".tmp");
}

/* The leftover a killed install leaves behind. The name is fixed, so the next attempt meets its
 * own debris rather than a free path -- if that were treated as a failure, one interrupted
 * install would stop the agent adopting anything ever again, which is far worse than the orphan
 * the fixed name exists to prevent. */
static void test_a_leftover_staging_file_is_reclaimed(void **state) {
    (void) state;
    FILE *fp = fopen(STORE_PATH ".tmp", "w");

    assert_non_null(fp);
    fputs("half a certificate, from an install that was killed\n", fp);
    fclose(fp);

    expect_any(__wrap__minfo, formatted_msg);

    assert_int_equal(w_ca_publication_install(STORE_PATH, ROOT_CA_PEM, strlen(ROOT_CA_PEM),
                                              1789000012LL), 0);
    assert_int_equal(w_ca_publication_read(STORE_PATH), 1789000012LL);
}

/* The property the fixed name buys, stated directly: however many installs are interrupted, the
 * directory never accumulates. Two failed commits in a row, and the staging file is still the
 * one name -- with a template it would be two files here and one per interruption forever. */
static void test_interrupted_installs_do_not_accumulate_staging_files(void **state) {
    (void) state;
    int attempt;

    write_store("## generation: 1789000012\n" CERT_BODY);

    /* The commit fails, which is where a kill would land: the body is written and validated,
     * and the store is never replaced. */
    rename_fail_errno = EPERM;

    for (attempt = 0; attempt < 2; attempt++) {
        expect_any(__wrap__merror, formatted_msg);
        assert_int_equal(w_ca_publication_install(STORE_PATH, ROOT_CA_PEM, strlen(ROOT_CA_PEM),
                                                  1789000013LL), -1);
    }

    assert_int_equal(rename_calls, 2);
    /* Nothing but the store and, at most, its one staging sibling. */
    assert_int_equal(count_files_with_prefix(STORE_PATH "."), 0);
    assert_int_equal(w_ca_publication_read(STORE_PATH), 1789000012LL);
}

/* etc/certs is group-writable and sticky since #39321, so the staging file's name is a path the
 * runtime user can plant something at. A symlink there must never be followed: opening it with
 * "w" would truncate whatever it points at, with the agent's privileges, on a schedule the
 * manager controls.
 *
 * What refuses it is the exclusive create, not O_NOFOLLOW -- O_CREAT|O_EXCL fails EEXIST on an
 * existing symlink on its own. So this case discriminates the create from a plain fopen("w"),
 * which is the distinction that matters; it would still pass if O_NOFOLLOW were dropped. */
static void test_a_symlink_at_the_staging_path_is_not_followed(void **state) {
    (void) state;
    char sentinel[64] = {'\0'};
    FILE *fp = fopen(SENTINEL_PATH, "w");

    assert_non_null(fp);
    fputs("do not truncate me\n", fp);
    fclose(fp);

    assert_int_equal(symlink(SENTINEL_PATH, STORE_PATH ".tmp"), 0);

    expect_any(__wrap__minfo, formatted_msg);

    assert_int_equal(w_ca_publication_install(STORE_PATH, ROOT_CA_PEM, strlen(ROOT_CA_PEM),
                                              1789000012LL), 0);

    /* The link itself was removed -- unlink() never follows one -- and its target was left
     * alone. The install then proceeded into a file it had created itself. */
    slurp(SENTINEL_PATH, sentinel, sizeof(sentinel));
    assert_string_equal(sentinel, "do not truncate me\n");
    assert_int_equal(w_ca_publication_read(STORE_PATH), 1789000012LL);
}

/* A body that is not certificates is refused before the commit is ever reached, so there is no
 * window in which the store holds it. */
static void test_a_rejected_body_never_reaches_the_commit(void **state) {
    (void) state;
    const char *junk = "this is not a certificate at all\n";

    write_store("## generation: 1789000012\n" CERT_BODY);

    expect_any(__wrap__merror, formatted_msg);

    assert_int_equal(w_ca_publication_install(STORE_PATH, junk, strlen(junk), 1789000013LL), -1);
    assert_int_equal(rename_calls, 0);
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
        cmocka_unit_test_teardown(test_install_leaves_the_store_untouched_until_the_commit, teardown_store),
        cmocka_unit_test_teardown(test_install_leaves_the_store_intact_when_the_commit_fails, teardown_store),
        cmocka_unit_test_teardown(test_the_temporary_file_is_committed_from_beside_the_store, teardown_store),
        cmocka_unit_test_teardown(test_a_leftover_staging_file_is_reclaimed, teardown_store),
        cmocka_unit_test_teardown(test_interrupted_installs_do_not_accumulate_staging_files, teardown_store),
        cmocka_unit_test_teardown(test_a_symlink_at_the_staging_path_is_not_followed, teardown_store),
        cmocka_unit_test_teardown(test_a_rejected_body_never_reaches_the_commit, teardown_store),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
