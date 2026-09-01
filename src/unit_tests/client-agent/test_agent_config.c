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

#include "agentd.h"

/* getAgentConfig() is the whole answer to "getconfig agent" and the payload of the
 * periodic /config push, so anything it leaves out is invisible to the manager even
 * though the agent is running on it. These tests pin the entire reported section:
 * which keys it carries, which optional ones it omits, and the value of every one. */

static agent test_agt;
static agent_server test_servers[3];

static int setup_agent(void **state)
{
    (void)state;

    memset(&test_agt, 0, sizeof(test_agt));
    memset(test_servers, 0, sizeof(test_servers));

    /* The defaults ClientConf() seeds before parsing, so an "unconfigured" case here
     * is the same struct an agent with an untouched ossec.conf ends up running on. */
    test_agt.flags.auto_restart = 1;
    test_agt.ssl.verification_mode = AGENT_VERIFY_NONE;
    test_agt.batch.interval = 10;
    test_agt.stats_report.interval = 60;
    test_agt.config_report.enabled = 1;
    test_agt.config_report.interval = 3600;

    /* #38465: <agent><enrollment> is a by-value struct now, always present
     * (like <ssl>/<batch>) -- no more enrollment_cfg pointer to leave null. */
    test_agt.enrollment.enabled = true;
    test_agt.enrollment.delay_after_enrollment = 20;

    agt = &test_agt;

    return 0;
}

static int teardown_agent(void **state)
{
    (void)state;
    agt = NULL;

    return 0;
}

static void with_servers(void)
{
    test_servers[0].rip = "192.168.0.1";
    test_servers[0].port = 1517;
    test_servers[0].max_retries = 5;
    test_servers[0].retry_interval = 10;

    test_servers[1].rip = "192.168.0.2";
    test_servers[1].port = 1518;
    test_servers[1].scope_id = 3;
    test_servers[1].max_retries = 7;
    test_servers[1].retry_interval = 20;

    test_agt.server = test_servers;
    test_agt.server_count = 2;
}

static cJSON *get_agent_section(cJSON **root)
{
    *root = getAgentConfig();
    assert_non_null(*root);

    cJSON *section = cJSON_GetObjectItem(*root, "agent");
    assert_non_null(section);

    return section;
}

static void assert_string_field(const cJSON *object, const char *field, const char *expected)
{
    cJSON *item = cJSON_GetObjectItem(object, field);

    assert_non_null(item);
    assert_string_equal(cJSON_GetStringValue(item), expected);
}

static void assert_number_field(const cJSON *object, const char *field, double expected)
{
    cJSON *item = cJSON_GetObjectItem(object, field);

    assert_non_null(item);
    assert_true(cJSON_IsNumber(item));
    assert_true(item->valuedouble == expected);
}

static void assert_has_exactly(const cJSON *object, const char *const *expected, size_t count)
{
    size_t reported = 0;

    for (const cJSON *item = object->child; item; item = item->next) {
        reported++;
    }

    assert_int_equal(reported, count);

    for (size_t i = 0; i < count; i++) {
        assert_non_null(cJSON_GetObjectItem(object, expected[i]));
    }
}

/* The document as a whole: a key silently dropped from the report is the defect this
 * whole issue is about, so the key set is asserted, not just the values. */
static void test_reports_every_section(void **state)
{
    (void)state;
    cJSON *root = NULL;

    with_servers();
    test_agt.profile = "ubuntu, ubuntu24";

    const char *const expected[] = {
        "config-profile", "notify_time", "time-reconnect", "ip_update_interval",
        "auto_restart", "remote_conf", "manager", "enrollment", "ssl", "batch",
        "stats_report", "config_report"
    };

    cJSON *section = get_agent_section(&root);

    assert_has_exactly(section, expected, sizeof(expected) / sizeof(*expected));

    cJSON_Delete(root);
}

static void test_reports_scalars_and_flags(void **state)
{
    (void)state;
    cJSON *root = NULL;

    test_agt.profile = "ubuntu, ubuntu24";
    test_agt.notify_time = 10;
    test_agt.max_time_reconnect_try = 60;
    test_agt.main_ip_update_interval = 30;
    test_agt.flags.remote_conf = 1;

    cJSON *section = get_agent_section(&root);

    assert_string_field(section, "config-profile", "ubuntu, ubuntu24");
    assert_number_field(section, "notify_time", 10);
    assert_number_field(section, "time-reconnect", 60);
    assert_number_field(section, "ip_update_interval", 30);
    assert_string_field(section, "auto_restart", "yes");
    assert_string_field(section, "remote_conf", "yes");

    cJSON_Delete(root);
}

static void test_reports_disabled_flags_as_no(void **state)
{
    (void)state;
    cJSON *root = NULL;

    test_agt.flags.auto_restart = 0;
    test_agt.flags.remote_conf = 0;

    cJSON *section = get_agent_section(&root);

    assert_string_field(section, "auto_restart", "no");
    assert_string_field(section, "remote_conf", "no");
    assert_null(cJSON_GetObjectItem(section, "config-profile"));

    cJSON_Delete(root);
}

static void test_reports_every_manager(void **state)
{
    (void)state;
    cJSON *root = NULL;

    with_servers();

    cJSON *managers = cJSON_GetObjectItem(get_agent_section(&root), "manager");

    assert_non_null(managers);
    assert_int_equal(cJSON_GetArraySize(managers), 2);

    cJSON *first = cJSON_GetArrayItem(managers, 0);
    assert_string_field(first, "address", "192.168.0.1");
    assert_number_field(first, "port", 1517);
    assert_number_field(first, "max_retries", 5);
    assert_number_field(first, "retry_interval", 10);
    assert_null(cJSON_GetObjectItem(first, "scope_id"));

    cJSON *second = cJSON_GetArrayItem(managers, 1);
    assert_string_field(second, "address", "192.168.0.2");
    assert_number_field(second, "port", 1518);
    assert_number_field(second, "scope_id", 3);

    cJSON_Delete(root);
}

static void test_omits_manager_without_servers(void **state)
{
    (void)state;
    cJSON *root = NULL;

    assert_null(cJSON_GetObjectItem(get_agent_section(&root), "manager"));

    cJSON_Delete(root);
}

static void test_reports_enrollment_with_every_optional_field(void **state)
{
    (void)state;
    cJSON *root = NULL;

    test_agt.enrollment.agent_name = "agent-01";
    test_agt.enrollment.groups = "default";
    test_agt.enrollment.agent_address = "192.168.0.1";
    test_agt.enrollment.use_source_ip = true;
    test_agt.enrollment.authorization_pass_path = "etc/authd.pass";

    cJSON *enrollment = cJSON_GetObjectItem(get_agent_section(&root), "enrollment");

    assert_non_null(enrollment);
    assert_string_field(enrollment, "enabled", "yes");
    assert_number_field(enrollment, "delay_after_enrollment", 20);
    assert_string_field(enrollment, "agent_name", "agent-01");
    assert_string_field(enrollment, "group", "default");
    assert_string_field(enrollment, "agent_address", "192.168.0.1");
    assert_string_field(enrollment, "use_source_ip", "yes");
    assert_string_field(enrollment, "authorization_pass_path", "etc/authd.pass");

    cJSON_Delete(root);
}

static void test_reports_enrollment_without_optional_fields(void **state)
{
    (void)state;
    cJSON *root = NULL;

    test_agt.enrollment.enabled = false;

    cJSON *enrollment = cJSON_GetObjectItem(get_agent_section(&root), "enrollment");

    assert_non_null(enrollment);
    assert_string_field(enrollment, "enabled", "no");
    assert_string_field(enrollment, "use_source_ip", "no");
    assert_null(cJSON_GetObjectItem(enrollment, "agent_name"));
    assert_null(cJSON_GetObjectItem(enrollment, "group"));
    assert_null(cJSON_GetObjectItem(enrollment, "agent_address"));
    assert_null(cJSON_GetObjectItem(enrollment, "authorization_pass_path"));

    cJSON_Delete(root);
}

/* <agent><enrollment> is a by-value struct (#38465, like <ssl>/<batch>): it can
 * never be "unset" the way a null enrollment_cfg pointer used to be -- an
 * agent that never configured anything beyond ClientConf()'s own defaults
 * still reports the section, with the optional fields simply absent. */
static void test_reports_default_enrollment_posture(void **state)
{
    (void)state;
    cJSON *root = NULL;

    cJSON *enrollment = cJSON_GetObjectItem(get_agent_section(&root), "enrollment");

    assert_non_null(enrollment);
    assert_string_field(enrollment, "enabled", "yes");
    assert_number_field(enrollment, "delay_after_enrollment", 20);
    assert_string_field(enrollment, "use_source_ip", "no");
    assert_null(cJSON_GetObjectItem(enrollment, "agent_name"));
    assert_null(cJSON_GetObjectItem(enrollment, "group"));
    assert_null(cJSON_GetObjectItem(enrollment, "agent_address"));
    assert_null(cJSON_GetObjectItem(enrollment, "authorization_pass_path"));

    cJSON_Delete(root);
}

static void test_reports_every_configured_ssl_field(void **state)
{
    (void)state;
    cJSON *root = NULL;

    test_agt.ssl.verification_mode = AGENT_VERIFY_CERT;
    test_agt.ssl.certificate = "etc/agent.cert";
    test_agt.ssl.key = "etc/agent.key";
    test_agt.ssl.certificate_authorities = "etc/root-ca.pem";
    test_agt.ssl.ciphers = "TLS_AES_256_GCM_SHA384";

    cJSON *ssl = cJSON_GetObjectItem(get_agent_section(&root), "ssl");

    assert_non_null(ssl);
    assert_string_field(ssl, "verification_mode", "certificate");
    assert_string_field(ssl, "certificate", "etc/agent.cert");
    assert_string_field(ssl, "key", "etc/agent.key");
    assert_string_field(ssl, "certificate_authorities", "etc/root-ca.pem");
    assert_string_field(ssl, "ciphers", "TLS_AES_256_GCM_SHA384");

    cJSON_Delete(root);
}

/* An agent with no <ssl> block still runs with a posture, so the block is still
 * reported -- with the optional paths absent rather than empty. */
static void test_reports_default_ssl_posture(void **state)
{
    (void)state;
    cJSON *root = NULL;

    cJSON *ssl = cJSON_GetObjectItem(get_agent_section(&root), "ssl");

    assert_non_null(ssl);
    assert_string_field(ssl, "verification_mode", "none");
    assert_null(cJSON_GetObjectItem(ssl, "certificate"));
    assert_null(cJSON_GetObjectItem(ssl, "key"));
    assert_null(cJSON_GetObjectItem(ssl, "certificate_authorities"));
    assert_null(cJSON_GetObjectItem(ssl, "ciphers"));

    cJSON_Delete(root);
}

static void test_reports_full_verification_mode(void **state)
{
    (void)state;
    cJSON *root = NULL;

    test_agt.ssl.verification_mode = AGENT_VERIFY_FULL;

    assert_string_field(cJSON_GetObjectItem(get_agent_section(&root), "ssl"), "verification_mode", "full");

    cJSON_Delete(root);
}

static void test_reports_system_verification_mode(void **state)
{
    (void)state;
    cJSON *root = NULL;

    test_agt.ssl.verification_mode = AGENT_VERIFY_SYSTEM;

    assert_string_field(cJSON_GetObjectItem(get_agent_section(&root), "ssl"), "verification_mode", "system");

    cJSON_Delete(root);
}

static void test_reports_configured_batch_limits(void **state)
{
    (void)state;
    cJSON *root = NULL;

    test_agt.batch.size = 2097152;
    test_agt.batch.interval = 15;

    cJSON *batch = cJSON_GetObjectItem(get_agent_section(&root), "batch");

    assert_non_null(batch);
    assert_number_field(batch, "size", 2097152);
    assert_number_field(batch, "interval", 15);

    cJSON_Delete(root);
}

/* Unconfigured <size> is reported as the cap every reader applies to its zero, 1 MiB,
 * without seeding it into agt; <interval> is the value ClientConf() seeds. */
static void test_reports_batch_defaults(void **state)
{
    (void)state;
    cJSON *root = NULL;

    cJSON *batch = cJSON_GetObjectItem(get_agent_section(&root), "batch");

    assert_non_null(batch);
    assert_number_field(batch, "size", 1048576);
    assert_number_field(batch, "interval", 10);

    cJSON_Delete(root);
}

static void test_reports_both_periodic_pushes(void **state)
{
    (void)state;
    cJSON *root = NULL;

    cJSON *section = get_agent_section(&root);
    cJSON *stats = cJSON_GetObjectItem(section, "stats_report");
    cJSON *config = cJSON_GetObjectItem(section, "config_report");

    assert_non_null(stats);
    assert_string_field(stats, "enabled", "no");
    assert_number_field(stats, "interval", 60);

    assert_non_null(config);
    assert_string_field(config, "enabled", "yes");
    assert_number_field(config, "interval", 3600);

    cJSON_Delete(root);
}

static void test_no_config_returns_null(void **state)
{
    (void)state;

    agt = NULL;

    assert_null(getAgentConfig());
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_reports_every_section, setup_agent, teardown_agent),
        cmocka_unit_test_setup_teardown(test_reports_scalars_and_flags, setup_agent, teardown_agent),
        cmocka_unit_test_setup_teardown(test_reports_disabled_flags_as_no, setup_agent, teardown_agent),
        cmocka_unit_test_setup_teardown(test_reports_every_manager, setup_agent, teardown_agent),
        cmocka_unit_test_setup_teardown(test_omits_manager_without_servers, setup_agent, teardown_agent),
        cmocka_unit_test_setup_teardown(test_reports_enrollment_with_every_optional_field, setup_agent, teardown_agent),
        cmocka_unit_test_setup_teardown(test_reports_enrollment_without_optional_fields, setup_agent, teardown_agent),
        cmocka_unit_test_setup_teardown(test_reports_default_enrollment_posture, setup_agent, teardown_agent),
        cmocka_unit_test_setup_teardown(test_reports_every_configured_ssl_field, setup_agent, teardown_agent),
        cmocka_unit_test_setup_teardown(test_reports_default_ssl_posture, setup_agent, teardown_agent),
        cmocka_unit_test_setup_teardown(test_reports_full_verification_mode, setup_agent, teardown_agent),
        cmocka_unit_test_setup_teardown(test_reports_system_verification_mode, setup_agent, teardown_agent),
        cmocka_unit_test_setup_teardown(test_reports_configured_batch_limits, setup_agent, teardown_agent),
        cmocka_unit_test_setup_teardown(test_reports_batch_defaults, setup_agent, teardown_agent),
        cmocka_unit_test_setup_teardown(test_reports_both_periodic_pushes, setup_agent, teardown_agent),
        cmocka_unit_test_setup_teardown(test_no_config_returns_null, setup_agent, teardown_agent),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
