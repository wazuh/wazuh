/* Copyright (C) 2015, Wazuh Inc.
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
#include <stdio.h>
#include <stdlib.h>

#include "shared.h"
#include "os_xml.h"
#include "config.h"
#include "global-config.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../external/cJSON/cJSON.h"

static const char *TEST_CONF_PATH = "test_config-elements.conf";

/* ReadConfig() only parses agent files: ossec.conf on the agent and agent.conf everywhere.
 * The manager's own configuration is YAML, so the root element is the same in both targets. */
#define CONF_ROOT "ossec_config"

#define CONF_OPEN  "<" CONF_ROOT ">"
#define CONF_CLOSE "</" CONF_ROOT ">"

static int write_conf(const char *body) {
    FILE *fp = fopen(TEST_CONF_PATH, "w");

    if (!fp) {
        return -1;
    }

    fputs(CONF_OPEN, fp);
    fputs(body, fp);
    fputs(CONF_CLOSE, fp);
    fclose(fp);

    return 0;
}

static int teardown_conf_file(void **state) {
    unlink(TEST_CONF_PATH);
    return 0;
}

/* A top-level element that was valid in 4.x and has no parser left must be
 * ignored with a warning. Rejecting it is fatal, which is what took the whole
 * daemon down when a configuration file was carried over from 4.x. */
static void test_obsolete_element_is_ignored(void **state) {
    if (write_conf("<command>"
                   "<name>ar-test</name>"
                   "<executable>block-ip</executable>"
                   "</command>") != 0) {
        fail();
    }

    expect_string(__wrap__mwarn, formatted_msg,
                  "(1223): 'command' is no longer supported and will be ignored. "
                  "Active Response commands are not defined in the configuration file.");

    assert_int_equal(ReadConfig(CLOCALFILE, TEST_CONF_PATH, NULL, NULL), 0);
}

/* Every entry of the table warns with its own explanation, and one obsolete
 * element does not stop the rest of the file from being read. */
static void test_several_obsolete_elements_are_ignored(void **state) {
    if (write_conf("<labels><label key=\"test\">value</label></labels>"
                   "<ruleset><rule_dir>etc/rules</rule_dir></ruleset>"
                   "<syslog_output><server>192.0.2.1</server></syslog_output>") != 0) {
        fail();
    }

    expect_string(__wrap__mwarn, formatted_msg,
                  "(1223): 'labels' is no longer supported and will be ignored. "
                  "Agent labels were removed in 5.0.0.");
    expect_string(__wrap__mwarn, formatted_msg,
                  "(1223): 'ruleset' is no longer supported and will be ignored. "
                  "Rules and decoders are managed by the engine.");
    expect_string(__wrap__mwarn, formatted_msg,
                  "(1223): 'syslog_output' is no longer supported and will be ignored. "
                  "The wazuh-csyslogd daemon was removed in 5.0.0.");

    assert_int_equal(ReadConfig(CLOCALFILE, TEST_CONF_PATH, NULL, NULL), 0);
}

/* An empty obsolete element has no children, so it takes a different path
 * through the reader than the ones above. It must be ignored just the same. */
static void test_empty_obsolete_element_is_ignored(void **state) {
    if (write_conf("<client_buffer></client_buffer>") != 0) {
        fail();
    }

    expect_string(__wrap__mwarn, formatted_msg,
                  "(1223): 'client_buffer' is no longer supported and will be ignored. "
                  "Event batching is configured under <agent><batch>.");

    assert_int_equal(ReadConfig(CLOCALFILE, TEST_CONF_PATH, NULL, NULL), 0);
}

/* Leniency is limited to the elements that were removed on purpose. An element
 * nobody ever supported is still an error, so typos keep being caught. */
static void test_unknown_element_is_still_fatal(void **state) {
    if (write_conf("<not_a_wazuh_element>x</not_a_wazuh_element>") != 0) {
        fail();
    }

    expect_string(__wrap__merror, formatted_msg,
                  "(1230): Invalid element in the configuration: 'not_a_wazuh_element'.");
    expect_string(__wrap__merror, formatted_msg,
                  "(1202): Configuration error at 'test_config-elements.conf'.");

    assert_int_equal(ReadConfig(CLOCALFILE, TEST_CONF_PATH, NULL, NULL), OS_INVALID);
}

/* <active-response> is live configuration on an agent -- execd reads it from the
 * file itself -- and the manager parses agent.conf on the agents' behalf, so both
 * builds accept it without a word. */
static void test_active_response_is_valid(void **state) {
    if (write_conf("<active-response>"
                   "<disabled>no</disabled>"
                   "<ca_verification>yes</ca_verification>"
                   "</active-response>") != 0) {
        fail();
    }

    assert_int_equal(ReadConfig(CLOCALFILE, TEST_CONF_PATH, NULL, NULL), 0);
}

/* The manager's own sections have no XML reader anymore (etc/wazuh-manager.yml):
 * an agent file that still carries one is told so and the block is ignored. */
static void test_manager_section_is_ignored_with_warning(void **state) {
    if (write_conf("<global>"
                   "<agents_disconnection_time>10m</agents_disconnection_time>"
                   "</global>"
                   "<remote>"
                   "<legacy><enabled>yes</enabled></legacy>"
                   "</remote>") != 0) {
        fail();
    }

    expect_string(__wrap__mwarn, formatted_msg, "global configuration is only set in the manager.");
    expect_string(__wrap__mwarn, formatted_msg, "remote configuration is only set in the manager.");

    assert_int_equal(ReadConfig(CLOCALFILE, TEST_CONF_PATH, NULL, NULL), 0);
}

#ifndef TEST_AGENT_TARGET

/* Read_Global_JSON(): the `global` section of the effective YAML document (manager only). */
static void test_Read_Global_JSON_accepts_int_and_duration(void **state) {
    _Config config = { .agents_disconnection_time = 900, .agents_disconnection_alert_time = 0 };
    cJSON *global = cJSON_Parse("{\"agents_disconnection_time\":\"15m\",\"agents_disconnection_alert_time\":30}");
    assert_non_null(global);

    assert_int_equal(Read_Global_JSON(global, &config), 0);
    assert_int_equal(config.agents_disconnection_time, 900);
    assert_int_equal(config.agents_disconnection_alert_time, 30);

    cJSON_Delete(global);
}

static void test_Read_Global_JSON_absent_keeps_defaults(void **state) {
    _Config config = { .agents_disconnection_time = 600, .agents_disconnection_alert_time = 0 };
    cJSON *global = cJSON_Parse("{}");
    assert_non_null(global);

    assert_int_equal(Read_Global_JSON(global, &config), 0);
    assert_int_equal(config.agents_disconnection_time, 600);
    assert_int_equal(config.agents_disconnection_alert_time, 0);

    cJSON_Delete(global);
}

static void test_Read_Global_JSON_rejects_zero_disconnection_time(void **state) {
    _Config config = { .agents_disconnection_time = 900, .agents_disconnection_alert_time = 0 };
    cJSON *global = cJSON_Parse("{\"agents_disconnection_time\":0}");
    assert_non_null(global);

    expect_string(__wrap__merror, formatted_msg, "(1235): Invalid value for element 'agents_disconnection_time': 0.");
    assert_int_equal(Read_Global_JSON(global, &config), OS_INVALID);
    assert_int_equal(config.agents_disconnection_time, 900);

    cJSON_Delete(global);
}

#endif

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_teardown(test_obsolete_element_is_ignored, teardown_conf_file),
        cmocka_unit_test_teardown(test_several_obsolete_elements_are_ignored, teardown_conf_file),
        cmocka_unit_test_teardown(test_empty_obsolete_element_is_ignored, teardown_conf_file),
        cmocka_unit_test_teardown(test_unknown_element_is_still_fatal, teardown_conf_file),
        cmocka_unit_test_teardown(test_active_response_is_valid, teardown_conf_file),
        cmocka_unit_test_teardown(test_manager_section_is_ignored_with_warning, teardown_conf_file),
#ifndef TEST_AGENT_TARGET
        cmocka_unit_test(test_Read_Global_JSON_accepts_int_and_duration),
        cmocka_unit_test(test_Read_Global_JSON_absent_keeps_defaults),
        cmocka_unit_test(test_Read_Global_JSON_rejects_zero_disconnection_time),
#endif
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
