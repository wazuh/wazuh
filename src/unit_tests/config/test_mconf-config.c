/* Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* w_mconf_*(): the libconfig layer over the manager_config library (etc/wazuh-manager.conf). Real
 * loader, temporary XML files in the working directory. Manager only. */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "shared.h"
#include "config.h"
#include "mconf-config.h"
#include "mconf_hook.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../external/cJSON/cJSON.h"

static const char *TEST_CONF = "test_mconf-config.conf";

static int write_conf(const char *body) {
    FILE *fp = fopen(TEST_CONF, "w");

    if (!fp) {
        return -1;
    }

    fputs(body, fp);
    fclose(fp);
    return 0;
}

static const char *TEST_CONF_B = "test_mconf-config-b.conf";

static int teardown_conf(void **state) {
    (void) state;
    unlink(TEST_CONF);
    unlink(TEST_CONF_B);
    unlink("etc/wazuh-manager.conf");
    rmdir("etc");
    w_mconf_free();
    return 0;
}

static void test_w_mconf_section_before_load_is_null(void **state) {
    (void) state;

    w_mconf_free();
    assert_null(w_mconf_section("remote"));
    assert_null(w_mconf_file());
}

static void test_w_mconf_load_and_section_from_xml_file(void **state) {
    (void) state;

    /* Only schema defaults: the certificate files they name do not exist here, and the loader must not
     * care (start-up path) -- w_mconf_validate() is the one that checks them. */
    if (write_conf("<wazuh_config>\n"
                   "  <global><agents_disconnection_time>10m</agents_disconnection_time></global>\n"
                   "</wazuh_config>\n") != 0) {
        fail();
    }

    assert_int_equal(w_mconf_load(TEST_CONF), 0);
    assert_string_equal(w_mconf_file(), TEST_CONF);

    cJSON *remote = w_mconf_section("remote");
    assert_non_null(remote);
    assert_int_equal(cJSON_GetObjectItem(cJSON_GetObjectItem(remote, "https"), "port")->valueint, 1517); // schema default
    assert_true(cJSON_IsFalse(cJSON_GetObjectItem(cJSON_GetObjectItem(remote, "legacy"), "enabled"))); // absent block
    cJSON_Delete(remote);

    cJSON *global = w_mconf_section("global");
    assert_non_null(global);
    assert_string_equal(cJSON_GetObjectItem(global, "agents_disconnection_time")->valuestring, "10m");
    cJSON_Delete(global);

    assert_null(w_mconf_section("syscheck"));

    /* One document at a time: loading the same path again is a no-op (another path reloads, see
     * test_w_mconf_load_reloads_when_the_path_changes) */
    assert_int_equal(w_mconf_load(TEST_CONF), 0);
    assert_string_equal(w_mconf_file(), TEST_CONF);
}

static void test_w_mconf_validate_checks_files(void **state) {
    (void) state;
    const char prefix[] = "(1244): Invalid configuration at 'test_mconf-config.conf': /remote/https/certificate";

    /* Valid document whose default certificate does not exist in the working directory: the loader
     * accepts it, the -t validation does not. */
    if (write_conf("<wazuh_config>\n"
                   "  <global><agents_disconnection_time>10m</agents_disconnection_time></global>\n"
                   "</wazuh_config>\n") != 0) {
        fail();
    }

    assert_int_equal(w_mconf_load(TEST_CONF), 0);

    expect_memory(__wrap__merror, formatted_msg, prefix, sizeof(prefix) - 1);
    assert_int_equal(w_mconf_validate(TEST_CONF), -1);

    /* And the whole check passes once every named file exists (this file stands in for the certificates) */
    if (write_conf("<wazuh_config>\n"
                   "  <remote><https>\n"
                   "    <certificate>test_mconf-config.conf</certificate>\n"
                   "    <key>test_mconf-config.conf</key>\n"
                   "  </https></remote>\n"
                   "  <auth>\n"
                   "    <ssl_manager_cert>test_mconf-config.conf</ssl_manager_cert>\n"
                   "    <ssl_manager_key>test_mconf-config.conf</ssl_manager_key>\n"
                   "  </auth>\n"
                   "</wazuh_config>\n") != 0) {
        fail();
    }
    assert_int_equal(w_mconf_validate(TEST_CONF), 0);
}

static void test_w_mconf_load_invalid_logs_1244(void **state) {
    (void) state;
    const char prefix[] = "(1244): Invalid configuration at 'test_mconf-config.conf': /auth/disabled";

    /* Booleans are yes/no in the XML dialect: true is a plain string and fails the schema type. */
    if (write_conf("<wazuh_config><auth><disabled>true</disabled></auth></wazuh_config>\n") != 0) {
        fail();
    }

    expect_memory(__wrap__merror, formatted_msg, prefix, sizeof(prefix) - 1);

    assert_int_equal(w_mconf_load(TEST_CONF), -1);
    assert_null(w_mconf_section("auth"));
    assert_null(w_mconf_file());
}

/* The provider libconfig registers in libwazuh's hook (constructor): when nothing is loaded it loads the
 * default file silently, so cluster_utils.c/debug_op.c work even before the daemon called w_mconf_load(). */
static void test_w_mconf_hook_provider_loads_default_file_silently(void **state) {
    (void) state;

    w_mconf_free();
    mkdir("etc", 0755);
    FILE *fp = fopen("etc/wazuh-manager.conf", "w");
    assert_non_null(fp);
    fputs("<wazuh_config><cluster>\n"
          "  <key>0123456789abcdef0123456789abcdef</key>\n"
          "  <node_type>worker</node_type>\n"
          "</cluster></wazuh_config>\n",
          fp);
    fclose(fp);

    cJSON *cluster = w_mconf_hook_section("cluster");
    assert_non_null(cluster);
    assert_string_equal(cJSON_GetObjectItem(cluster, "node_type")->valuestring, "worker");
    assert_string_equal(cJSON_GetObjectItem(cluster, "name")->valuestring, "wazuh"); // schema default
    cJSON_Delete(cluster);
    assert_string_equal(w_mconf_file(), WAZUHCONF);

    /* Invalid default file (malformed XML): the provider stays silent and answers NULL */
    w_mconf_free();
    fp = fopen("etc/wazuh-manager.conf", "w");
    fputs("<wazuh_config><cluster>\n", fp);
    fclose(fp);
    assert_null(w_mconf_hook_section("cluster"));
    assert_null(w_mconf_file());
}

static void test_w_mconf_load_reloads_when_the_path_changes(void **state) {
    (void) state;

    if (write_conf("<wazuh_config>\n"
                   "  <global><agents_disconnection_time>10m</agents_disconnection_time></global>\n"
                   "</wazuh_config>\n") != 0) {
        fail();
    }
    FILE *fp = fopen(TEST_CONF_B, "w");
    assert_non_null(fp);
    fputs("<wazuh_config>\n"
          "  <global><agents_disconnection_time>20m</agents_disconnection_time></global>\n"
          "</wazuh_config>\n",
          fp);
    fclose(fp);

    assert_int_equal(w_mconf_load(TEST_CONF), 0);
    assert_string_equal(w_mconf_file(), TEST_CONF);

    expect_string(__wrap__mdebug1, formatted_msg,
                  "Replacing the manager configuration loaded from 'test_mconf-config.conf' with 'test_mconf-config-b.conf'.");
    assert_int_equal(w_mconf_load(TEST_CONF_B), 0);
    assert_string_equal(w_mconf_file(), TEST_CONF_B);

    cJSON *global = w_mconf_section("global");
    assert_string_equal(cJSON_GetObjectItem(global, "agents_disconnection_time")->valuestring, "20m");
    cJSON_Delete(global);

    /* Same path again: no-op */
    assert_int_equal(w_mconf_load(TEST_CONF_B), 0);
    assert_string_equal(w_mconf_file(), TEST_CONF_B);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_w_mconf_section_before_load_is_null),
        cmocka_unit_test_teardown(test_w_mconf_load_and_section_from_xml_file, teardown_conf),
        cmocka_unit_test_teardown(test_w_mconf_validate_checks_files, teardown_conf),
        cmocka_unit_test_teardown(test_w_mconf_load_invalid_logs_1244, teardown_conf),
        cmocka_unit_test_teardown(test_w_mconf_hook_provider_loads_default_file_silently, teardown_conf),
        cmocka_unit_test_teardown(test_w_mconf_load_reloads_when_the_path_changes, teardown_conf),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
