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
#include <stdbool.h>
#include <unistd.h>

#include "os_win32ui.h"

/* Covers get_ossec_server()'s own precedence between the 5.x <endpoint> shape (#38624)
 * and the deprecated <address>/<server-ip>/<server-hostname> triplet it replaced. The
 * function reads a real ossec.conf at the hardcoded relative path CONFIG ("ossec.conf",
 * os_win32ui.h) rather than taking a path argument, so these tests write and remove that
 * exact relative file -- a stray one left by a crashed previous run would make every test
 * here see the wrong content, hence the unconditional group setup below. */

/* The deprecated <address> path runs OS_IsValidIP(), which calls into PCRE2 --
 * globally mocked in this binary and unusable without an explicit opt-out
 * (mirrors test_localfile-config.c's own group setup/teardown). */
void w_test_pcre2_wrappers(bool enable);

static int group_setup(void **state) {
    (void) state;
    w_test_pcre2_wrappers(false);
    return 0;
}

static int group_teardown(void **state) {
    (void) state;
    w_test_pcre2_wrappers(true);
    return 0;
}

static int setup(void **state) {
    (void) state;

    memset(&config_inst, 0, sizeof(config_inst));

    return 0;
}

static int teardown(void **state) {
    (void) state;

    unlink(CONFIG);

    if (config_inst.server) {
        free(config_inst.server);
        config_inst.server = NULL;
    }

    return 0;
}

static void write_conf(const char *body) {
    FILE *f = fopen(CONFIG, "w");
    assert_non_null(f);
    fputs(body, f);
    fclose(f);
}

static void test_agent_manager_endpoint_is_read_verbatim(void **state) {
    (void) state;

    write_conf("<ossec_config>\n  <agent>\n    <manager>\n      <endpoint>manager.example.com:1517/wazuh-manager/</endpoint>\n    </manager>\n  </agent>\n</ossec_config>\n");

    assert_int_equal(get_ossec_server(), 1);
    assert_string_equal(config_inst.server, "manager.example.com:1517/wazuh-manager/");
    assert_int_equal(config_inst.server_type, SERVER_HOST_USED);
}

/* The shape InstallerScripts.vbs writes into a preserved 4.x file that has no <agent>
 * block: <client><server><endpoint>, not <client><server><address>. */
static void test_client_server_endpoint_upgraded_4x_file_is_read(void **state) {
    (void) state;

    write_conf("<ossec_config>\n  <client>\n    <server>\n      <endpoint>10.0.0.5:1517/</endpoint>\n    </server>\n  </client>\n</ossec_config>\n");

    assert_int_equal(get_ossec_server(), 1);
    assert_string_equal(config_inst.server, "10.0.0.5:1517/");
}

/* A genuine, untouched 4.x file: no <endpoint> anywhere, only the deprecated
 * <client><server><address>. Already worked before this change; must keep working. */
static void test_legacy_client_server_address_still_works(void **state) {
    (void) state;

    write_conf("<ossec_config>\n  <client>\n    <server>\n      <address>192.168.1.10</address>\n    </server>\n  </client>\n</ossec_config>\n");

    assert_int_equal(get_ossec_server(), 1);
    assert_string_equal(config_inst.server, "192.168.1.10");
    assert_int_equal(config_inst.server_type, SERVER_IP_USED);
}

/* <endpoint> wins over <address> whenever both are present, mirroring
 * client-config.c's Read_Agent_Manager() precedence. */
static void test_endpoint_wins_over_address_when_both_present(void **state) {
    (void) state;

    write_conf("<ossec_config>\n  <agent>\n    <manager>\n      <address>203.0.113.1</address>\n      <endpoint>203.0.113.1:1517/</endpoint>\n    </manager>\n  </agent>\n</ossec_config>\n");

    assert_int_equal(get_ossec_server(), 1);
    assert_string_equal(config_inst.server, "203.0.113.1:1517/");
}

/* Both a 5.x <agent><manager> block and a leftover 4.x <client><server> block
 * present in the same file -- e.g. a config-management tool wrote the new
 * block without cleaning up the old one. <agent> must win, matching
 * Read_Legacy_Client()'s address_taken gate (client-config.c), which skips
 * the legacy <server> block entirely once <agent> has resolved anything. */
static void test_agent_block_wins_over_legacy_client_block_when_both_present(void **state) {
    (void) state;

    write_conf("<ossec_config>\n"
               "  <agent>\n    <manager>\n      <endpoint>five-x.example.com:1517/</endpoint>\n    </manager>\n  </agent>\n"
               "  <client>\n    <server>\n      <address>10.0.0.9</address>\n    </server>\n  </client>\n"
               "</ossec_config>\n");

    assert_int_equal(get_ossec_server(), 1);
    assert_string_equal(config_inst.server, "five-x.example.com:1517/");
}

/* The narrower edge case: <agent> uses only the deprecated <address> (no
 * <endpoint>), while the leftover <client><server> uses <endpoint>. Block
 * precedence must still win over tag precedence -- <agent>'s address is
 * shown, not <client>'s endpoint -- exactly as Read_Legacy_Client() would:
 * it never even looks at <client><server> once <agent> supplied anything. */
static void test_agent_address_wins_over_legacy_client_endpoint(void **state) {
    (void) state;

    write_conf("<ossec_config>\n"
               "  <agent>\n    <manager>\n      <address>203.0.113.9</address>\n    </manager>\n  </agent>\n"
               "  <client>\n    <server>\n      <endpoint>stale-legacy.example.com:1517/</endpoint>\n    </server>\n  </client>\n"
               "</ossec_config>\n");

    assert_int_equal(get_ossec_server(), 1);
    assert_string_equal(config_inst.server, "203.0.113.9");
    assert_int_equal(config_inst.server_type, SERVER_IP_USED);
}

static void test_no_manager_configuration_returns_no_server(void **state) {
    (void) state;

    write_conf("<ossec_config>\n</ossec_config>\n");

    assert_int_equal(get_ossec_server(), 0);
    assert_string_equal(config_inst.server, FL_NOSERVER);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_agent_manager_endpoint_is_read_verbatim, setup, teardown),
        cmocka_unit_test_setup_teardown(test_client_server_endpoint_upgraded_4x_file_is_read, setup, teardown),
        cmocka_unit_test_setup_teardown(test_legacy_client_server_address_still_works, setup, teardown),
        cmocka_unit_test_setup_teardown(test_endpoint_wins_over_address_when_both_present, setup, teardown),
        cmocka_unit_test_setup_teardown(test_agent_block_wins_over_legacy_client_block_when_both_present, setup, teardown),
        cmocka_unit_test_setup_teardown(test_agent_address_wins_over_legacy_client_endpoint, setup, teardown),
        cmocka_unit_test_setup_teardown(test_no_manager_configuration_returns_no_server, setup, teardown),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
