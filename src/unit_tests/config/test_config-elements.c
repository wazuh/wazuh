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
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

static const char *TEST_CONF_PATH = "test_config-elements.conf";

/* The root element and the treatment of <active-response> both depend on whether
 * the config library under test was built for an agent, and the test cannot ask
 * CLIENT: the unit-test build never defines it, while the library it links does
 * for agent targets. WAZUHCONFIG is derived from CLIENT, so it is unusable here
 * for the same reason -- it would expand to the manager's root element in a
 * binary linked against an agent library. TEST_AGENT_TARGET comes from
 * CMakeLists.txt, which does know the target. */
#ifdef TEST_AGENT_TARGET
#define CONF_ROOT "ossec_config"
#else
#define CONF_ROOT "wazuh_config"
#endif

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

    assert_int_equal(ReadConfig(CGLOBAL, TEST_CONF_PATH, NULL, NULL), 0);
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

    assert_int_equal(ReadConfig(CGLOBAL, TEST_CONF_PATH, NULL, NULL), 0);
}

/* An empty obsolete element has no children, so it takes a different path
 * through the reader than the ones above. It must be ignored just the same. */
static void test_empty_obsolete_element_is_ignored(void **state) {
    if (write_conf("<agentless></agentless>") != 0) {
        fail();
    }

    expect_string(__wrap__mwarn, formatted_msg,
                  "(1223): 'agentless' is no longer supported and will be ignored. "
                  "The wazuh-agentlessd daemon was removed in 5.0.0.");

    assert_int_equal(ReadConfig(CGLOBAL, TEST_CONF_PATH, NULL, NULL), 0);
}

/* <client_buffer> was removed in 5.0.0, but to preserve smooth upgrades from
 * 4.x it is ignored with an info log rather than warned or rejected. */
static void test_client_buffer_is_ignored_with_info(void **state) {
    if (write_conf("<client_buffer>"
                   "<disabled>no</disabled>"
                   "<queue_size>5000</queue_size>"
                   "<events_per_second>500</events_per_second>"
                   "</client_buffer>") != 0) {
        fail();
    }

    expect_string(__wrap__minfo, formatted_msg,
                  "'client_buffer' is no longer used and will be ignored. "
                  "Event batching is configured under <agent><batch>.");

    assert_int_equal(ReadConfig(CGLOBAL, TEST_CONF_PATH, NULL, NULL), 0);
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

    assert_int_equal(ReadConfig(CGLOBAL, TEST_CONF_PATH, NULL, NULL), OS_INVALID);
}

#ifdef TEST_AGENT_TARGET

/* <active-response> is live configuration on an agent -- execd reads it from the
 * file itself -- so it must be accepted without a word. */
static void test_active_response_is_valid_on_agent(void **state) {
    if (write_conf("<active-response>"
                   "<disabled>no</disabled>"
                   "<ca_verification>yes</ca_verification>"
                   "</active-response>") != 0) {
        fail();
    }

    assert_int_equal(ReadConfig(CGLOBAL, TEST_CONF_PATH, NULL, NULL), 0);
}

#else

/* Nothing on the manager reads <active-response>. It used to be dropped without
 * a word, which left an operator with a block that parses, looks configured and
 * never fires. It is obsolete here, and says so. */
static void test_active_response_is_obsolete_on_manager(void **state) {
    if (write_conf("<active-response>"
                   "<disabled>no</disabled>"
                   "<command>ar-test</command>"
                   "<location>local</location>"
                   "</active-response>") != 0) {
        fail();
    }

    expect_string(__wrap__mwarn, formatted_msg,
                  "(1223): 'active-response' is no longer supported and will be ignored. "
                  "Active Response is not configured on the manager. This block only applies to agents.");

    assert_int_equal(ReadConfig(CGLOBAL, TEST_CONF_PATH, NULL, NULL), 0);
}

/* Both halves of the 4.x Active Response configuration behave the same way now:
 * the block that defined a response and the block that referenced it are both
 * ignored with a warning, instead of one being fatal and the other silent. */
static void test_active_response_pair_is_symmetric(void **state) {
    if (write_conf("<command>"
                   "<name>ar-test</name>"
                   "<executable>block-ip</executable>"
                   "</command>"
                   "<active-response>"
                   "<command>ar-test</command>"
                   "<location>local</location>"
                   "</active-response>") != 0) {
        fail();
    }

    expect_string(__wrap__mwarn, formatted_msg,
                  "(1223): 'command' is no longer supported and will be ignored. "
                  "Active Response commands are not defined in the configuration file.");
    expect_string(__wrap__mwarn, formatted_msg,
                  "(1223): 'active-response' is no longer supported and will be ignored. "
                  "Active Response is not configured on the manager. This block only applies to agents.");

    assert_int_equal(ReadConfig(CGLOBAL, TEST_CONF_PATH, NULL, NULL), 0);
}

#endif

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_teardown(test_obsolete_element_is_ignored, teardown_conf_file),
        cmocka_unit_test_teardown(test_several_obsolete_elements_are_ignored, teardown_conf_file),
        cmocka_unit_test_teardown(test_empty_obsolete_element_is_ignored, teardown_conf_file),
        cmocka_unit_test_teardown(test_client_buffer_is_ignored_with_info, teardown_conf_file),
        cmocka_unit_test_teardown(test_unknown_element_is_still_fatal, teardown_conf_file),
#ifdef TEST_AGENT_TARGET
        cmocka_unit_test_teardown(test_active_response_is_valid_on_agent, teardown_conf_file),
#else
        cmocka_unit_test_teardown(test_active_response_is_obsolete_on_manager, teardown_conf_file),
        cmocka_unit_test_teardown(test_active_response_pair_is_symmetric, teardown_conf_file),
#endif
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
