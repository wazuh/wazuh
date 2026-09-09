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
#include <unistd.h>
#include <sys/stat.h>

#include "agentd.h"

/* Covers ClientConf()'s own resolution step -- the part of #38684's fix, and of #39025's
 * trust-anchor latch on top of it, that only exercises correctly when the whole function
 * runs end to end against a real file (Read_Agent_SSL() alone, tested elsewhere, cannot see
 * it: it only sets fields when a tag is present, never resolves what "absent" should
 * become). The per-row decisions live in test_agent_ssl_ca.c, which can fake the anchor
 * probe; what is proved here is that ClientConf() actually calls the resolver.
 *
 * The anchor is a real file at AGENT_ANCHOR_CA, relative to this binary's working
 * directory, so these tests create and remove one. Every test in this file depends on that
 * file being absent unless it put it there -- a stray one flips the two tests that assert
 * 'system' and 'none' -- and the build tree is never cleaned, so the group setup clears it
 * before anything runs rather than trusting the previous run to have exited cleanly. */

#define TEST_CONF_PATH_TEMPLATE "/tmp/test_client_conf_ssl_XXXXXX"
static char test_conf_path[sizeof(TEST_CONF_PATH_TEMPLATE)];
static agent test_agt;
#ifndef WIN32
static anti_tampering test_atc;
#endif

static int setup_agent(void **state) {
    (void) state;

    memset(&test_agt, 0, sizeof(test_agt));
    agt = &test_agt;
#ifndef WIN32
    memset(&test_atc, 0, sizeof(test_atc));
    atc = &test_atc;
#endif

    /* mkstemp() mutates its argument in place, replacing the XXXXXX template with
     * the actual generated name -- re-copy the template before every call, or every
     * test after the first hands it an already-consumed (X-less) string. */
    strcpy(test_conf_path, TEST_CONF_PATH_TEMPLATE);
    int fd = mkstemp(test_conf_path);
    if (fd == -1) {
        return -1;
    }
    close(fd);

    return 0;
}

static int teardown_agent(void **state) {
    (void) state;

    unlink(test_conf_path);
    /* ClientConf() allocates into agt (server list, ssl.*, enrollment.*) same as
     * production startup, which never frees it because the process just exits.
     * Free it here instead, or every test after the first leaks the previous
     * run's allocations under ASan/LSan. */
    Free_Agent(&test_agt);
    agt = NULL;
#ifndef WIN32
    atc = NULL;
#endif

    return 0;
}

/* Content is irrelevant: the resolver only asks whether the path opens. Nothing in this
 * binary parses the PEM -- that is the transport module, which is not linked here. */
static void create_anchor(void) {
    mkdir("etc", 0755);
    mkdir("etc/certs", 0755);

    FILE *f = fopen(AGENT_ANCHOR_CA, "w");
    assert_non_null(f);
    fputs("not a real certificate\n", f);
    fclose(f);
}

static void remove_anchor(void) {
    unlink(AGENT_ANCHOR_CA);
    rmdir("etc/certs");
}

static int group_clear_anchor(void **state) {
    (void) state;

    remove_anchor();

    return 0;
}

static int setup_agent_with_anchor(void **state) {
    if (setup_agent(state) != 0) {
        return -1;
    }

    create_anchor();

    return 0;
}

static int teardown_agent_with_anchor(void **state) {
    remove_anchor();

    return teardown_agent(state);
}

static void write_conf(const char *body) {
    FILE *f = fopen(test_conf_path, "w");
    fprintf(f, "<ossec_config>\n  <agent>\n%s  </agent>\n</ossec_config>\n", body);
    fclose(f);
}

static void test_no_ssl_block_resolves_to_none(void **state) {
    (void) state;

    write_conf("    <manager><endpoint>127.0.0.1:1517/</endpoint></manager>\n");

    assert_int_equal(ClientConf(test_conf_path), 1);
    assert_int_equal(agt->ssl.verification_mode, AGENT_VERIFY_NONE);
    assert_null(agt->ssl.certificate_authorities);
}

static void test_ca_without_explicit_mode_resolves_to_certificate(void **state) {
    (void) state;

    write_conf(
        "    <manager><endpoint>127.0.0.1:1517/</endpoint></manager>\n"
        "    <ssl><certificate_authorities>/etc/wazuh/ca.pem</certificate_authorities></ssl>\n"
    );

    assert_int_equal(ClientConf(test_conf_path), 1);
    assert_int_equal(agt->ssl.verification_mode, AGENT_VERIFY_CERT);
    assert_string_equal(agt->ssl.certificate_authorities, "/etc/wazuh/ca.pem");
}

static void test_explicit_full_with_ca_is_kept(void **state) {
    (void) state;

    write_conf(
        "    <manager><endpoint>127.0.0.1:1517/</endpoint></manager>\n"
        "    <ssl>\n"
        "      <certificate_authorities>/etc/wazuh/ca.pem</certificate_authorities>\n"
        "      <verification_mode>full</verification_mode>\n"
        "    </ssl>\n"
    );

    assert_int_equal(ClientConf(test_conf_path), 1);
    assert_int_equal(agt->ssl.verification_mode, AGENT_VERIFY_FULL);
}

static void test_explicit_none_is_kept_even_without_ca(void **state) {
    (void) state;

    write_conf(
        "    <manager><endpoint>127.0.0.1:1517/</endpoint></manager>\n"
        "    <ssl><verification_mode>none</verification_mode></ssl>\n"
    );

    assert_int_equal(ClientConf(test_conf_path), 1);
    assert_int_equal(agt->ssl.verification_mode, AGENT_VERIFY_NONE);
}

static void test_explicit_system_with_no_ca_is_kept(void **state) {
    (void) state;

    write_conf(
        "    <manager><endpoint>127.0.0.1:1517/</endpoint></manager>\n"
        "    <ssl><verification_mode>system</verification_mode></ssl>\n"
    );

    assert_int_equal(ClientConf(test_conf_path), 1);
    assert_int_equal(agt->ssl.verification_mode, AGENT_VERIFY_SYSTEM);
    assert_null(agt->ssl.certificate_authorities);
}

/* --- with a trust anchor on disk (#39025) --- */

static void test_no_ssl_block_with_anchor_resolves_to_full(void **state) {
    (void) state;

    write_conf("    <manager><endpoint>127.0.0.1:1517/</endpoint></manager>\n");

    assert_int_equal(ClientConf(test_conf_path), 1);
    assert_int_equal(agt->ssl.verification_mode, AGENT_VERIFY_FULL);
    assert_string_equal(agt->ssl.certificate_authorities, AGENT_ANCHOR_CA);
}

static void test_explicit_none_with_anchor_is_overridden_to_full(void **state) {
    (void) state;

    write_conf(
        "    <manager><endpoint>127.0.0.1:1517/</endpoint></manager>\n"
        "    <ssl><verification_mode>none</verification_mode></ssl>\n"
    );

    assert_int_equal(ClientConf(test_conf_path), 1);
    assert_int_equal(agt->ssl.verification_mode, AGENT_VERIFY_FULL);
    assert_string_equal(agt->ssl.certificate_authorities, AGENT_ANCHOR_CA);
}

/* Also the guard against injecting the constant itself: teardown's Free_Agent() would
 * free a string literal. */
static void test_explicit_full_without_ca_gets_the_anchor(void **state) {
    (void) state;

    write_conf(
        "    <manager><endpoint>127.0.0.1:1517/</endpoint></manager>\n"
        "    <ssl><verification_mode>full</verification_mode></ssl>\n"
    );

    assert_int_equal(ClientConf(test_conf_path), 1);
    assert_int_equal(agt->ssl.verification_mode, AGENT_VERIFY_FULL);
    assert_string_equal(agt->ssl.certificate_authorities, AGENT_ANCHOR_CA);
}

/* An explicit 'system' is a deliberate choice of the OS trust store, so an anchor on disk
 * must not pull the agent onto it -- and must not set a CA, which would be a (4120)
 * refusal to start. */
static void test_explicit_system_with_anchor_is_kept(void **state) {
    (void) state;

    write_conf(
        "    <manager><endpoint>127.0.0.1:1517/</endpoint></manager>\n"
        "    <ssl><verification_mode>system</verification_mode></ssl>\n"
    );

    assert_int_equal(ClientConf(test_conf_path), 1);
    assert_int_equal(agt->ssl.verification_mode, AGENT_VERIFY_SYSTEM);
    assert_null(agt->ssl.certificate_authorities);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_no_ssl_block_resolves_to_none, setup_agent, teardown_agent),
        cmocka_unit_test_setup_teardown(test_ca_without_explicit_mode_resolves_to_certificate, setup_agent, teardown_agent),
        cmocka_unit_test_setup_teardown(test_explicit_full_with_ca_is_kept, setup_agent, teardown_agent),
        cmocka_unit_test_setup_teardown(test_explicit_none_is_kept_even_without_ca, setup_agent, teardown_agent),
        cmocka_unit_test_setup_teardown(test_explicit_system_with_no_ca_is_kept, setup_agent, teardown_agent),

        /* Last on purpose: these are the only tests that create the anchor, so a crash
         * inside one cannot leave it behind for a test that expects it gone. */
        cmocka_unit_test_setup_teardown(test_no_ssl_block_with_anchor_resolves_to_full,
                                        setup_agent_with_anchor, teardown_agent_with_anchor),
        cmocka_unit_test_setup_teardown(test_explicit_none_with_anchor_is_overridden_to_full,
                                        setup_agent_with_anchor, teardown_agent_with_anchor),
        cmocka_unit_test_setup_teardown(test_explicit_full_without_ca_gets_the_anchor,
                                        setup_agent_with_anchor, teardown_agent_with_anchor),
        cmocka_unit_test_setup_teardown(test_explicit_system_with_anchor_is_kept,
                                        setup_agent_with_anchor, teardown_agent_with_anchor),
    };

    return cmocka_run_group_tests(tests, group_clear_anchor, group_clear_anchor);
}
