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
#include "wmodules.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

static const char *TEST_CONF_PATH = "test_wmodules-config.conf";

static int write_conf(const char *content) {
    FILE *fp = fopen(TEST_CONF_PATH, "w");

    if (!fp) {
        return -1;
    }

    fputs(content, fp);
    fclose(fp);

    return 0;
}

static int teardown_conf_file(void **state) {
    unlink(TEST_CONF_PATH);
    return 0;
}

/* Test_WModule() is what verify-agent-conf uses to validate an agent group's
 * agent.conf. Agent-only modules must not raise the "only works for the
 * agent" warning in that context. */
static void test_Test_WModule_syscollector_no_warning(void **state) {
    if (write_conf("<agent_config>"
                    "<wodle name=\"syscollector\">"
                    "<disabled>no</disabled>"
                    "</wodle>"
                    "</agent_config>") != 0) {
        fail();
    }

    assert_int_equal(Test_WModule(TEST_CONF_PATH), 0);
}

/* Suppressing the false-positive warning must not turn validation off:
 * genuinely invalid content inside a <wodle name="syscollector"> block
 * still has to be reported by verify-agent-conf. */
static void test_Test_WModule_syscollector_invalid_content_is_reported(void **state) {
    if (write_conf("<agent_config>"
                    "<wodle name=\"syscollector\">"
                    "<disabled>notabool</disabled>"
                    "</wodle>"
                    "</agent_config>") != 0) {
        fail();
    }

    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'disabled' at module 'syscollector'.");
    expect_string(__wrap__merror, formatted_msg, "(1202): Configuration error at 'test_wmodules-config.conf'.");
    expect_string(__wrap__merror, formatted_msg, "(1207): WModule remote configuration in 'test_wmodules-config.conf' is corrupted.");

    assert_int_equal(Test_WModule(TEST_CONF_PATH), -1);
}

/* Same false-positive check for a standalone reader (Read_Github) that
 * received the same agent_cfg plumbing as Read_WModule, this time with a
 * complete, valid config so wm_github_read() actually runs and succeeds. */
static void test_Test_WModule_github_no_warning(void **state) {
    if (write_conf("<agent_config>"
                    "<github>"
                    "<enabled>yes</enabled>"
                    "<api_auth>"
                    "<org_name>test-org</org_name>"
                    "<api_token>test-token</api_token>"
                    "</api_auth>"
                    "</github>"
                    "</agent_config>") != 0) {
        fail();
    }

    assert_int_equal(Test_WModule(TEST_CONF_PATH), 0);
}

/* Suppressing the false-positive warning must not turn validation off:
 * genuinely invalid content inside an agent-only module block still has to
 * be reported by verify-agent-conf. */
static void test_Test_WModule_github_invalid_content_is_reported(void **state) {
    if (write_conf("<agent_config>"
                    "<github>"
                    "<enabled>invalid</enabled>"
                    "</github>"
                    "</agent_config>") != 0) {
        fail();
    }

    expect_string(__wrap__merror, formatted_msg, "Invalid content for tag 'enabled' at module 'github'.");
    expect_string(__wrap__merror, formatted_msg, "(1202): Configuration error at 'test_wmodules-config.conf'.");
    expect_string(__wrap__merror, formatted_msg, "(1207): WModule remote configuration in 'test_wmodules-config.conf' is corrupted.");

    assert_int_equal(Test_WModule(TEST_CONF_PATH), -1);
}

/* Read_SCA never warned on the manager (it silently skipped <sca> blocks
 * both for the manager's own config and while validating agent config), so
 * there is no false-positive warning to check here — only that validation
 * now actually happens for agent-only SCA blocks too. */
static void test_Test_WModule_sca_valid_content_is_accepted(void **state) {
    if (write_conf("<agent_config>"
                    "<sca>"
                    "<enabled>yes</enabled>"
                    "</sca>"
                    "</agent_config>") != 0) {
        fail();
    }

    assert_int_equal(Test_WModule(TEST_CONF_PATH), 0);
}

static void test_Test_WModule_sca_invalid_content_is_reported(void **state) {
    if (write_conf("<agent_config>"
                    "<sca>"
                    "<enabled>invalid</enabled>"
                    "</sca>"
                    "</agent_config>") != 0) {
        fail();
    }

    expect_any(__wrap__mterror, tag);
    expect_string(__wrap__mterror, formatted_msg, "Invalid content for tag 'enabled'");
    expect_string(__wrap__merror, formatted_msg, "(1202): Configuration error at 'test_wmodules-config.conf'.");
    expect_string(__wrap__merror, formatted_msg, "(1207): WModule remote configuration in 'test_wmodules-config.conf' is corrupted.");

    assert_int_equal(Test_WModule(TEST_CONF_PATH), -1);
}

/* When the manager parses its own configuration (agent_cfg = 0), the warning
 * must still be raised: syscollector genuinely does not belong there. */
static void test_Read_WModule_syscollector_warns_without_agent_cfg(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    wmodule *wmodules = NULL;
    int ret;

    if (OS_ReadXMLString("<wodle name=\"syscollector\"><disabled>no</disabled></wodle>", &xml) != 0) {
        fail();
    }

    if (nodes = OS_GetElementsbyNode(&xml, NULL), nodes == NULL) {
        fail();
    }

    expect_string(__wrap__mwarn, formatted_msg, "The 'syscollector' module only works for the agent");

    ret = Read_WModule(&xml, nodes[0], &wmodules, NULL);

    assert_int_equal(ret, 0);

    os_free(wmodules);
    OS_ClearNode(nodes);
    OS_ClearXML(&xml);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_teardown(test_Test_WModule_syscollector_no_warning, teardown_conf_file),
        cmocka_unit_test_teardown(test_Test_WModule_syscollector_invalid_content_is_reported, teardown_conf_file),
        cmocka_unit_test_teardown(test_Test_WModule_github_no_warning, teardown_conf_file),
        cmocka_unit_test_teardown(test_Test_WModule_github_invalid_content_is_reported, teardown_conf_file),
        cmocka_unit_test_teardown(test_Test_WModule_sca_valid_content_is_accepted, teardown_conf_file),
        cmocka_unit_test_teardown(test_Test_WModule_sca_invalid_content_is_reported, teardown_conf_file),
        cmocka_unit_test(test_Read_WModule_syscollector_warns_without_agent_cfg),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
