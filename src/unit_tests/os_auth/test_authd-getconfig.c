/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* authd_read_config() and getAuthdConfig() over the document: w_mconf_load()/w_mconf_section() are
 * wrapped, Read_Authd_JSON() runs for real. */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <stdlib.h>

#include "auth.h"
#include "shared.h"
#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/validate_op_wrappers.h"
#include "../wrappers/wazuh/config/mconf-config_wrappers.h"
#include "../../external/cJSON/cJSON.h"

static int teardown_config(void **state) {
    (void) state;
    os_free(config.ciphers);
    os_free(config.agent_ca);
    os_free(config.manager_cert);
    os_free(config.manager_key);
    memset(&config, 0, sizeof(config));
    return 0;
}

static void test_authd_read_config_loads_auth_section(void **state) {
    (void) state;
    memset(&config, 0, sizeof(config));

    expect_string(__wrap__mdebug2, formatted_msg, "Reading configuration 'etc/wazuh-manager.conf'");
    expect_string(__wrap_w_mconf_load, cfgfile, WAZUHCONF);
    will_return(__wrap_w_mconf_load, 0);
    expect_string(__wrap_w_mconf_section, section, "auth");
    will_return(__wrap_w_mconf_section, cJSON_Parse("{\"disabled\":false,\"port\":1516,\"use_password\":true}"));
    will_return(__wrap_getDefine_Int_default, 1);     // auth.timeout_seconds
    will_return(__wrap_getDefine_Int_default, 0);     // auth.timeout_microseconds
    will_return(__wrap_getDefine_Int_default, 7);     // authd.max_agents
    will_return(__wrap_getDefine_Int_default, 120);   // authd.purge_delay
    will_return(__wrap_getDefine_Int_default, 10);    // authd.wdb_timeout
    will_return(__wrap_getDefine_Int_default, 20000); // wazuh_modules.manager_task_max_pending_deletes

    assert_int_equal(authd_read_config(WAZUHCONF), 0);

    assert_int_equal(config.port, 1516);
    assert_int_equal(config.flags.use_password, 1);
    assert_int_equal(config.flags.disabled, 0);
    assert_int_equal(config.flags.remote_enrollment, 1); // reader default
    assert_string_equal(config.ciphers, DEFAULT_CIPHERS);
    assert_string_equal(config.manager_cert, "etc/certs/remoted.pem");
    assert_int_equal(config.timeout_sec, 1);
    assert_int_equal(config.max_agents, 7);
    assert_int_equal(config.purge_delay, 120);
    assert_int_equal(config.wdb_timeout, 10);
    assert_int_equal(config.max_pending_deletes, 20000);
}

static void test_authd_read_config_fails_when_load_fails(void **state) {
    (void) state;
    memset(&config, 0, sizeof(config));

    expect_string(__wrap__mdebug2, formatted_msg, "Reading configuration '/etc/other.conf'");
    expect_string(__wrap_w_mconf_load, cfgfile, "/etc/other.conf");
    will_return(__wrap_w_mconf_load, -1); // the helper already logged CONFIG_INVALID

    assert_int_equal(authd_read_config("/etc/other.conf"), OS_INVALID);
}

static void test_getAuthdConfig_returns_effective_section(void **state) {
    (void) state;

    expect_string(__wrap_w_mconf_section, section, "auth");
    will_return(__wrap_w_mconf_section,
                cJSON_Parse("{\"disabled\":false,\"port\":1515,\"use_password\":false,"
                            "\"force\":{\"enabled\":true,\"disconnected_time\":{\"enabled\":true,\"value\":\"1h\"}}}"));

    cJSON *root = getAuthdConfig();
    cJSON *auth = cJSON_GetObjectItem(root, "auth");
    assert_true(cJSON_IsObject(auth));
    assert_true(cJSON_IsBool(cJSON_GetObjectItem(auth, "disabled")));
    assert_int_equal(cJSON_GetObjectItem(auth, "port")->valueint, 1515);

    cJSON *disconnected = cJSON_GetObjectItem(cJSON_GetObjectItem(auth, "force"), "disconnected_time");
    assert_true(cJSON_IsObject(disconnected));
    assert_string_equal(cJSON_GetObjectItem(disconnected, "value")->valuestring, "1h");
    /* Internal options are not part of the section */
    assert_null(cJSON_GetObjectItem(auth, "purge_delay"));

    cJSON_Delete(root);
}

static void test_getAuthdConfig_without_document_is_empty(void **state) {
    (void) state;

    expect_string(__wrap_w_mconf_section, section, "auth");
    will_return(__wrap_w_mconf_section, NULL);

    cJSON *root = getAuthdConfig();
    cJSON *auth = cJSON_GetObjectItem(root, "auth");
    assert_true(cJSON_IsObject(auth));
    assert_null(auth->child);

    cJSON_Delete(root);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_teardown(test_authd_read_config_loads_auth_section, teardown_config),
        cmocka_unit_test_teardown(test_authd_read_config_fails_when_load_fails, teardown_config),
        cmocka_unit_test(test_getAuthdConfig_returns_effective_section),
        cmocka_unit_test(test_getAuthdConfig_without_document_is_empty),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
