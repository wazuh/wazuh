/* Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* w_mconf_*(): the libconfig layer over the manager_config library (etc/wazuh-manager.yml). Real
 * loader, temporary YAML files in the working directory. Manager only. */

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

static const char *TEST_YML = "test_mconf-config.yml";

static int write_yml(const char *body) {
    FILE *fp = fopen(TEST_YML, "w");

    if (!fp) {
        return -1;
    }

    fputs(body, fp);
    fclose(fp);
    return 0;
}

static const char *TEST_YML_B = "test_mconf-config-b.yml";

static int teardown_yml(void **state) {
    (void) state;
    unlink(TEST_YML);
    unlink(TEST_YML_B);
    unlink("etc/wazuh-manager.yml");
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

static void test_w_mconf_load_and_section_from_yaml_file(void **state) {
    (void) state;

    /* Only schema defaults: the certificate files they name do not exist here, and the loader must not
     * care (start-up path, P44) -- w_mconf_validate() is the one that checks them. */
    if (write_yml("global:\n  agents_disconnection_time: 10m\n") != 0) {
        fail();
    }

    assert_int_equal(w_mconf_load(TEST_YML), 0);
    assert_string_equal(w_mconf_file(), TEST_YML);

    cJSON *remote = w_mconf_section("remote");
    assert_non_null(remote);
    assert_int_equal(cJSON_GetObjectItem(cJSON_GetObjectItem(remote, "https"), "port")->valueint, 1517); // schema default
    assert_true(cJSON_IsFalse(cJSON_GetObjectItem(cJSON_GetObjectItem(remote, "legacy"), "enabled"))); // absent block
    cJSON_Delete(remote);

    cJSON *global = w_mconf_section("global");
    assert_non_null(global);
    assert_string_equal(cJSON_GetObjectItem(global, "agents_disconnection_time")->valuestring, "10m");
    assert_int_equal(cJSON_GetObjectItem(global, "agents_disconnection_alert_time")->valueint, 0);
    cJSON_Delete(global);

    assert_null(w_mconf_section("syscheck"));

    /* One document at a time: loading the same path again is a no-op (another path reloads, see
     * test_w_mconf_load_reloads_when_the_path_changes) */
    assert_int_equal(w_mconf_load(TEST_YML), 0);
    assert_string_equal(w_mconf_file(), TEST_YML);
}

static void test_w_mconf_validate_checks_files(void **state) {
    (void) state;
    const char prefix[] = "(1244): Invalid configuration at 'test_mconf-config.yml': /remote/https/certificate";

    /* Valid document whose default certificate does not exist in the working directory: the loader
     * accepts it, the -t validation does not. */
    if (write_yml("global:\n  agents_disconnection_time: 10m\n") != 0) {
        fail();
    }

    assert_int_equal(w_mconf_load(TEST_YML), 0);

    expect_memory(__wrap__merror, formatted_msg, prefix, sizeof(prefix) - 1);
    assert_int_equal(w_mconf_validate(TEST_YML), -1);

    /* And the whole check passes once every named file exists (this file stands in for the certificates) */
    if (write_yml("remote:\n"
                  "  https:\n"
                  "    certificate: test_mconf-config.yml\n"
                  "    key: test_mconf-config.yml\n"
                  "auth:\n"
                  "  ssl_manager_cert: test_mconf-config.yml\n"
                  "  ssl_manager_key: test_mconf-config.yml\n") != 0) {
        fail();
    }
    assert_int_equal(w_mconf_validate(TEST_YML), 0);
}

static void test_w_mconf_load_invalid_logs_1244(void **state) {
    (void) state;
    const char prefix[] = "(1244): Invalid configuration at 'test_mconf-config.yml': /auth/disabled";

    if (write_yml("auth:\n  disabled: yes\n") != 0) {
        fail();
    }

    expect_memory(__wrap__merror, formatted_msg, prefix, sizeof(prefix) - 1);

    assert_int_equal(w_mconf_load(TEST_YML), -1);
    assert_null(w_mconf_section("auth"));
    assert_null(w_mconf_file());
}

/* The provider libconfig registers in libwazuh's hook (constructor): when nothing is loaded it loads the
 * default file silently, so cluster_utils.c/debug_op.c work even before the daemon called w_mconf_load(). */
static void test_w_mconf_hook_provider_loads_default_file_silently(void **state) {
    (void) state;

    w_mconf_free();
    mkdir("etc", 0755);
    FILE *fp = fopen("etc/wazuh-manager.yml", "w");
    assert_non_null(fp);
    fputs("cluster:\n  key: 0123456789abcdef0123456789abcdef\n  node_type: worker\n", fp);
    fclose(fp);

    cJSON *cluster = w_mconf_hook_section("cluster");
    assert_non_null(cluster);
    assert_string_equal(cJSON_GetObjectItem(cluster, "node_type")->valuestring, "worker");
    assert_string_equal(cJSON_GetObjectItem(cluster, "name")->valuestring, "wazuh"); // schema default
    cJSON_Delete(cluster);
    assert_string_equal(w_mconf_file(), WAZUHCONF_YML);

    /* Invalid default file: the provider stays silent and answers NULL */
    w_mconf_free();
    fp = fopen("etc/wazuh-manager.yml", "w");
    fputs("cluster: [1, 2]\n", fp);
    fclose(fp);
    assert_null(w_mconf_hook_section("cluster"));
    assert_null(w_mconf_file());
}

static void test_w_mconf_load_reloads_when_the_path_changes(void **state) {
    (void) state;

    if (write_yml("global:\n  agents_disconnection_time: 10m\n") != 0) {
        fail();
    }
    FILE *fp = fopen(TEST_YML_B, "w");
    assert_non_null(fp);
    fputs("global:\n  agents_disconnection_time: 20m\n", fp);
    fclose(fp);

    assert_int_equal(w_mconf_load(TEST_YML), 0);
    assert_string_equal(w_mconf_file(), TEST_YML);

    expect_string(__wrap__mdebug1, formatted_msg,
                  "Replacing the manager configuration loaded from 'test_mconf-config.yml' with 'test_mconf-config-b.yml'.");
    assert_int_equal(w_mconf_load(TEST_YML_B), 0);
    assert_string_equal(w_mconf_file(), TEST_YML_B);

    cJSON *global = w_mconf_section("global");
    assert_string_equal(cJSON_GetObjectItem(global, "agents_disconnection_time")->valuestring, "20m");
    cJSON_Delete(global);

    /* Same path again: no-op */
    assert_int_equal(w_mconf_load(TEST_YML_B), 0);
    assert_string_equal(w_mconf_file(), TEST_YML_B);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_w_mconf_section_before_load_is_null),
        cmocka_unit_test_teardown(test_w_mconf_load_and_section_from_yaml_file, teardown_yml),
        cmocka_unit_test_teardown(test_w_mconf_validate_checks_files, teardown_yml),
        cmocka_unit_test_teardown(test_w_mconf_load_invalid_logs_1244, teardown_yml),
        cmocka_unit_test_teardown(test_w_mconf_hook_provider_loads_default_file_silently, teardown_yml),
        cmocka_unit_test_teardown(test_w_mconf_load_reloads_when_the_path_changes, teardown_yml),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
