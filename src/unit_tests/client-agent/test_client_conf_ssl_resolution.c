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

#include "agentd.h"

/* Covers ClientConf()'s own UNSET-resolution step -- the part of #38684's fix that
 * only exercises correctly when the whole function runs end to end against a real
 * file (Read_Agent_SSL() alone, tested elsewhere, cannot see it: it only sets fields
 * when a tag is present, never resolves what "absent" should become). */

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

static void write_conf(const char *body) {
    FILE *f = fopen(test_conf_path, "w");
    fprintf(f, "<ossec_config>\n  <agent>\n%s  </agent>\n</ossec_config>\n", body);
    fclose(f);
}

static void test_no_ssl_block_resolves_to_system(void **state) {
    (void) state;

    write_conf("    <manager><endpoint>127.0.0.1:1517/</endpoint></manager>\n");

    assert_int_equal(ClientConf(test_conf_path), 1);
    assert_int_equal(agt->ssl.verification_mode, AGENT_VERIFY_SYSTEM);
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

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_no_ssl_block_resolves_to_system, setup_agent, teardown_agent),
        cmocka_unit_test_setup_teardown(test_ca_without_explicit_mode_resolves_to_certificate, setup_agent, teardown_agent),
        cmocka_unit_test_setup_teardown(test_explicit_full_with_ca_is_kept, setup_agent, teardown_agent),
        cmocka_unit_test_setup_teardown(test_explicit_none_is_kept_even_without_ca, setup_agent, teardown_agent),
        cmocka_unit_test_setup_teardown(test_explicit_system_with_no_ca_is_kept, setup_agent, teardown_agent),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
