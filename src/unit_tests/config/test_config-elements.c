/* Copyright (C) Wazuh Inc.
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
#include "syscheck-config.h"
#include "wmodules.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../external/cJSON/cJSON.h"

static const char *TEST_CONF_PATH = "test_config-elements.conf";

/* The root element depends on whether the config library under test was built
 * for an agent, and the test cannot ask CLIENT: the unit-test build never defines it, while the library it links does
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
    if (write_conf("<agentless></agentless>") != 0) {
        fail();
    }

    expect_string(__wrap__mwarn, formatted_msg,
                  "(1223): 'agentless' is no longer supported and will be ignored. "
                  "The wazuh-agentlessd daemon was removed in 5.0.0.");

    assert_int_equal(ReadConfig(CLOCALFILE, TEST_CONF_PATH, NULL, NULL), 0);
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

    assert_int_equal(ReadConfig(CLOCALFILE, TEST_CONF_PATH, NULL, NULL), 0);
}

/* The top-level <container_images> block moved under <container_security>. It is
 * ignored with one message that names the new location, the rest of the file is
 * still read, and no images module is registered from it. */
static void test_container_images_block_is_obsolete(void **state) {
    wmodule *wmodules = NULL;

    if (write_conf("<container_images>"
                   "<enabled>yes</enabled>"
                   "<references><archive>/var/tmp/app.tar</archive></references>"
                   "</container_images>") != 0) {
        fail();
    }

    expect_string(__wrap__mwarn, formatted_msg,
                  "(1223): 'container_images' is no longer supported and will be ignored. "
                  "Image scanning is configured in <container_security><images>.");

    assert_int_equal(ReadConfig(CWMODULE, TEST_CONF_PATH, &wmodules, NULL), 0);
    assert_null(wmodules);
}

/* A daemon that reads none of the container security settings steps over the block
 * instead of rejecting it as an unknown element. */
static void test_container_security_is_valid_for_other_daemons(void **state) {
    if (write_conf("<container_security>"
                   "<docker><enabled>yes</enabled></docker>"
                   "<images><enabled>yes</enabled></images>"
                   "</container_security>") != 0) {
        fail();
    }

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

/* The manager's own sections have no XML reader anymore (/etc/wazuh-manager/wazuh-manager.conf):
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

#ifdef TEST_AGENT_TARGET
static int read_syscheck(void) {
    syscheck_config syscheck;
    int ret;

    if (initialize_syscheck_configuration(&syscheck) == OS_INVALID) {
        return OS_INVALID;
    }

    ret = ReadConfig(CSYSCHECK, TEST_CONF_PATH, &syscheck, NULL);
    Free_Syscheck(&syscheck);

    return ret;
}

static int read_wmodules(void) {
    wmodule *wmodules = NULL;
    int ret = ReadConfig(CWMODULE, TEST_CONF_PATH, &wmodules, NULL);

    wm_free(wmodules);

    return ret;
}

/* The SCA reader first tries to load the default ruleset, a path relative to the
 * installation directory that does not exist where the tests run. */
static void expect_sca_ruleset_not_found(void) {
    expect_any(__wrap__mtinfo, tag);
    expect_any(__wrap__mtinfo, formatted_msg);
}

/* A 4.x default ossec.conf sets these deprecated options, and an upgrade keeps
 * that file, so every upgraded agent reports them: they must log at INFO, not
 * WARNING, like the other harmless 4.x leftovers. */
static void test_syscheck_deprecated_defaults_are_info(void **state) {
    if (write_conf("<syscheck>"
                   "<scan_on_start>yes</scan_on_start>"
                   "<synchronization>"
                   "<max_interval>1h</max_interval>"
                   "<max_eps>10</max_eps>"
                   "</synchronization>"
                   "</syscheck>") != 0) {
        fail();
    }

    expect_string(__wrap__minfo, formatted_msg, "The <scan_on_start> option is deprecated and no longer has any effect.");
    expect_string(__wrap__minfo, formatted_msg, "The <max_interval> option is deprecated and no longer has any effect.");
    expect_string(__wrap__minfo, formatted_msg, "The <max_eps> option is deprecated and no longer has any effect.");

    assert_int_equal(read_syscheck(), 0);
}

/* Options only a user sets, some of which did something in 4.x, keep the warning. */
static void test_syscheck_deprecated_user_options_are_warning(void **state) {
    if (write_conf("<syscheck>"
                   "<synchronization><queue_size>16384</queue_size></synchronization>"
                   "<prefilter_cmd>/usr/sbin/prelink -y</prefilter_cmd>"
                   "</syscheck>") != 0) {
        fail();
    }

    expect_string(__wrap__mwarn, formatted_msg, "The <queue_size> option is deprecated and no longer has any effect.");
    expect_string(__wrap__mwarn, formatted_msg, "The <prefilter_cmd> option is deprecated and no longer has any effect.");

    assert_int_equal(read_syscheck(), 0);
}

/* The top-level <restart_audit> is still applied, only spelled the older way. */
static void test_syscheck_top_level_restart_audit_is_info(void **state) {
    if (write_conf("<syscheck><restart_audit>no</restart_audit></syscheck>") != 0) {
        fail();
    }

    expect_string(__wrap__minfo, formatted_msg,
                  "The <restart_audit> tag is deprecated, please use <whodata><restart_audit> instead.");

    assert_int_equal(read_syscheck(), 0);
}

/* An element <syscheck> does not know is rejected, as the other agent modules
 * reject theirs, so wazuh-syscheckd -t fails instead of the agent starting with
 * a setting that silently does nothing. */
static void test_syscheck_unknown_element_is_error(void **state) {
    if (write_conf("<syscheck><not_a_syscheck_option>1</not_a_syscheck_option></syscheck>") != 0) {
        fail();
    }

    expect_string(__wrap__merror, formatted_msg,
                  "(1230): Invalid element in the configuration: 'not_a_syscheck_option'.");
    expect_string(__wrap__mwarn, formatted_msg,
                  "(1230): Invalid element in the configuration: 'test_config-elements.conf'.");

    assert_int_equal(read_syscheck(), OS_INVALID);
}

/* Every top-level <syscheck> option 4.14.9 accepted and 5.0 dropped is still
 * recognized, so a configuration kept by an upgrade loads as before. */
static void test_syscheck_removed_4x_options_still_load(void **state) {
    if (write_conf("<syscheck>"
                   "<alert_new_files>yes</alert_new_files>"
                   "<auto_ignore frequency=\"10\" timeframe=\"3600\">no</auto_ignore>"
                   "<database>disk</database>"
                   "<prefilter_cmd>/usr/sbin/prelink -y</prefilter_cmd>"
                   "<allow_remote_prefilter_cmd>no</allow_remote_prefilter_cmd>"
                   "<remove_old_diff>yes</remove_old_diff>"
                   "<scan_on_start>yes</scan_on_start>"
                   "</syscheck>") != 0) {
        fail();
    }

    expect_string(__wrap__mwarn, formatted_msg, "The <alert_new_files> option is deprecated and no longer has any effect.");
    expect_string(__wrap__mwarn, formatted_msg, "The <auto_ignore> option is deprecated and no longer has any effect.");
    expect_string(__wrap__mwarn, formatted_msg, "The <database> option is deprecated and no longer has any effect.");
    expect_string(__wrap__mwarn, formatted_msg, "The <prefilter_cmd> option is deprecated and no longer has any effect.");
    expect_string(__wrap__mwarn, formatted_msg,
                  "The <allow_remote_prefilter_cmd> option is deprecated and no longer has any effect.");
    expect_string(__wrap__mwarn, formatted_msg, "The <remove_old_diff> option is deprecated and no longer has any effect.");
    expect_string(__wrap__minfo, formatted_msg, "The <scan_on_start> option is deprecated and no longer has any effect.");

    assert_int_equal(read_syscheck(), 0);
}

static void test_syscollector_deprecated_default_is_info(void **state) {
    if (write_conf("<wodle name=\"syscollector\">"
                   "<synchronization><max_eps>10</max_eps></synchronization>"
                   "</wodle>") != 0) {
        fail();
    }

    expect_string(__wrap__minfo, formatted_msg, "The <max_eps> option is deprecated and no longer has any effect.");

    assert_int_equal(read_wmodules(), 0);
}

static void test_sca_deprecated_default_is_info(void **state) {
    if (write_conf("<sca><skip_nfs>yes</skip_nfs></sca>") != 0) {
        fail();
    }

    expect_sca_ruleset_not_found();
    expect_any(__wrap__mtinfo, tag);
    expect_string(__wrap__mtinfo, formatted_msg, "The <skip_nfs> option is deprecated and no longer has any effect.");

    assert_int_equal(read_wmodules(), 0);
}

/* Only a user sets <day>, <wday> or <time>, and they changed when SCA scanned:
 * losing them still deserves a warning. */
static void test_sca_deprecated_schedule_is_warning(void **state) {
    if (write_conf("<sca><day>1</day></sca>") != 0) {
        fail();
    }

    expect_sca_ruleset_not_found();
    expect_any(__wrap__mtwarn, tag);
    expect_string(__wrap__mtwarn, formatted_msg, "The <day> option is deprecated and no longer has any effect.");

    assert_int_equal(read_wmodules(), 0);
}

static wm_container_images_t *container_images_data(const wmodule *module) {
    assert_non_null(module);
    assert_string_equal(module->tag, "container_images");
    assert_non_null(module->data);

    return (wm_container_images_t *)module->data;
}

/* Runtime security reads the rest of <container_security> on Linux only, so the images reader steps
 * over those children silently there and reports each one everywhere else. The expected message is a
 * string literal because cmocka keeps the pointer, not a copy, until the wrapper runs. */
#ifndef __linux__
#define expect_runtime_child_reported(child)                                                         \
    do {                                                                                             \
        expect_any(__wrap__mtwarn, tag);                                                             \
        expect_string(__wrap__mtwarn, formatted_msg,                                                 \
                      "The '" child "' tag inside 'container_security' is only supported on Linux "  \
                      "agents, ignoring it.");                                                       \
    } while (0)
#define expect_unknown_child_reported(child)                                                         \
    do {                                                                                             \
        expect_any(__wrap__mtwarn, tag);                                                             \
        expect_string(__wrap__mtwarn, formatted_msg,                                                 \
                      "No such tag '" child "' inside 'container_security', ignoring it.");          \
    } while (0)
#else
#define expect_runtime_child_reported(child) do { } while (0)
#define expect_unknown_child_reported(child) do { } while (0)
#endif

/* <images> alone is a valid <container_security> block: it configures the module with the
 * same options the top-level block had. */
static void test_container_security_images_only(void **state) {
    wmodule *wmodules = NULL;

    if (write_conf("<container_security>"
                   "<images>"
                   "<enabled>yes</enabled>"
                   "<scan_on_start>no</scan_on_start>"
                   "<interval>2h</interval>"
                   "<references>"
                   "<archive>/var/tmp/images/app.tar</archive>"
                   "<ref>ghcr.io/owner/app:1.4</ref>"
                   "</references>"
                   "<ca_bundle>/etc/ssl/ca.pem</ca_bundle>"
                   "</images>"
                   "</container_security>") != 0) {
        fail();
    }

    assert_int_equal(ReadConfig(CWMODULE, TEST_CONF_PATH, &wmodules, NULL), 0);

    wm_container_images_t *data = container_images_data(wmodules);
    assert_null(wmodules->next);
    assert_int_equal(data->enabled, 1);
    assert_int_equal(data->scan_on_start, 0);
    assert_int_equal(data->interval, 7200);
    assert_int_equal(data->references_count, 2);
    assert_string_equal(data->references[0].type, "archive");
    assert_string_equal(data->references[1].value, "ghcr.io/owner/app:1.4");
    assert_string_equal(data->ca_bundle, "/etc/ssl/ca.pem");

    wm_free(wmodules);
}

/* The runtime security children are stepped over without validation, whatever they hold, and
 * <images> is still read. Linux says nothing about them; other platforms report each one. */
static void test_container_security_linux_steps_over_runtime_children(void **state) {
    wmodule *wmodules = NULL;

    if (write_conf("<container_security>"
                   "<docker><enabled>yes</enabled></docker>"
                   "<container_instances><type>docker</type></container_instances>"
                   "<syscheck><directories>/etc</directories></syscheck>"
                   "<syscollector><interval>1h</interval></syscollector>"
                   "<kubernetes>anything</kubernetes>"
                   "<images><enabled>no</enabled></images>"
                   "</container_security>") != 0) {
        fail();
    }

    expect_runtime_child_reported("docker");
    expect_runtime_child_reported("container_instances");
    expect_runtime_child_reported("syscheck");
    expect_runtime_child_reported("syscollector");
    expect_runtime_child_reported("kubernetes");

    assert_int_equal(ReadConfig(CWMODULE, TEST_CONF_PATH, &wmodules, NULL), 0);
    assert_int_equal(container_images_data(wmodules)->enabled, 0);

    wm_free(wmodules);
}

/* Without <images> no module is registered: image scanning stays off. */
static void test_container_security_without_images_registers_nothing(void **state) {
    wmodule *wmodules = NULL;

    if (write_conf("<container_security>"
                   "<container_instances><type>docker</type></container_instances>"
                   "</container_security>") != 0) {
        fail();
    }

    expect_runtime_child_reported("container_instances");

    assert_int_equal(ReadConfig(CWMODULE, TEST_CONF_PATH, &wmodules, NULL), 0);
    assert_null(wmodules);
}

/* The platform decision is the reader's own: an unrecognised child is silent on Linux, where
 * runtime security owns the block, and reported on every other platform. */
static void test_container_security_other_children_follow_the_platform(void **state) {
    wmodule *wmodules = NULL;

    if (write_conf("<container_security>"
                   "<unknown>value</unknown>"
                   "<images></images>"
                   "</container_security>") != 0) {
        fail();
    }

    expect_unknown_child_reported("unknown");

    assert_int_equal(ReadConfig(CWMODULE, TEST_CONF_PATH, &wmodules, NULL), 0);
    assert_non_null(container_images_data(wmodules));

    wm_free(wmodules);
}

/* An empty <images> still turns the module on, with its defaults. */
static void test_container_security_empty_images_uses_defaults(void **state) {
    wmodule *wmodules = NULL;

    if (write_conf("<container_security><images></images></container_security>") != 0) {
        fail();
    }

    assert_int_equal(ReadConfig(CWMODULE, TEST_CONF_PATH, &wmodules, NULL), 0);

    wm_container_images_t *data = container_images_data(wmodules);
    assert_int_equal(data->enabled, 1);
    assert_int_equal(data->scan_on_start, 1);
    assert_int_equal(data->interval, WM_CONTAINER_IMAGES_DEFAULT_INTERVAL);
    assert_int_equal(data->references_count, 0);

    wm_free(wmodules);
}

/* ossec.conf and agent.conf can both carry the block: every <images> section reaches the
 * one module. References and registries add up, the other options keep the last value. */
static void test_container_security_repeated_blocks_merge(void **state) {
    wmodule *wmodules = NULL;

    if (write_conf("<container_security>"
                   "<images><interval>1h</interval>"
                   "<references><archive>/var/tmp/a.tar</archive></references></images>"
                   "</container_security>"
                   "<container_security>"
                   "<images><interval>30m</interval>"
                   "<references><archive>/var/tmp/b.tar</archive></references></images>"
                   "<images><enabled>no</enabled></images>"
                   "</container_security>") != 0) {
        fail();
    }

    assert_int_equal(ReadConfig(CWMODULE, TEST_CONF_PATH, &wmodules, NULL), 0);

    wm_container_images_t *data = container_images_data(wmodules);
    assert_null(wmodules->next);
    assert_int_equal(data->enabled, 0);
    assert_int_equal(data->interval, 1800);
    assert_int_equal(data->references_count, 2);
    assert_string_equal(data->references[0].value, "/var/tmp/a.tar");
    assert_string_equal(data->references[1].value, "/var/tmp/b.tar");

    wm_free(wmodules);
}

/* The old block and the new one in the same file: the old one is reported and the new one works. */
static void test_container_security_beside_the_obsolete_block(void **state) {
    wmodule *wmodules = NULL;

    if (write_conf("<container_images><enabled>no</enabled></container_images>"
                   "<container_security><images><interval>10m</interval></images></container_security>") != 0) {
        fail();
    }

    expect_string(__wrap__mwarn, formatted_msg,
                  "(1223): 'container_images' is no longer supported and will be ignored. "
                  "Image scanning is configured in <container_security><images>.");

    assert_int_equal(ReadConfig(CWMODULE, TEST_CONF_PATH, &wmodules, NULL), 0);

    wm_container_images_t *data = container_images_data(wmodules);
    assert_int_equal(data->enabled, 1);
    assert_int_equal(data->interval, 600);

    wm_free(wmodules);
}

/* A wrong value inside <images> is rejected like it was in the old block. */
static void test_container_security_invalid_images_is_rejected(void **state) {
    wmodule *wmodules = NULL;

    if (write_conf("<container_security><images><enabled>maybe</enabled></images></container_security>") != 0) {
        fail();
    }

    expect_any(__wrap__mterror, tag);
    expect_string(__wrap__mterror, formatted_msg, "Invalid content for tag 'enabled' at module 'container_images'.");
    expect_string(__wrap__merror, formatted_msg, "(1202): Configuration error at 'test_config-elements.conf'.");

    assert_int_equal(ReadConfig(CWMODULE, TEST_CONF_PATH, &wmodules, NULL), OS_INVALID);

    wm_free(wmodules);
}

/* The warning of a <local> entry that cannot be used: only that entry is dropped. Literal message,
 * because cmocka keeps the pointer, not a copy, until the wrapper runs. */
#define expect_local_warning(message)                       \
    do {                                                    \
        expect_any(__wrap__mtwarn, tag);                    \
        expect_string(__wrap__mtwarn, formatted_msg, message); \
    } while (0)

#ifdef __linux__
/* <local>docker takes the socket of the Docker engine in the same <container_security>, written the way
 * runtime security reads it today. The engine block is after <images>: the whole element is read first. */
static void test_local_docker_binds_the_container_instances_socket(void **state) {
    wmodule *wmodules = NULL;

    if (write_conf("<container_security>"
                   "<images><references><local>docker</local><archive>/var/tmp/a.tar</archive></references></images>"
                   "<container_instances><type>docker</type><socket_path>/run/d.sock</socket_path></container_instances>"
                   "</container_security>") != 0) {
        fail();
    }

    assert_int_equal(ReadConfig(CWMODULE, TEST_CONF_PATH, &wmodules, NULL), 0);

    wm_container_images_t *data = container_images_data(wmodules);
    assert_int_equal(data->references_count, 2);
    assert_string_equal(data->references[0].type, "local");
    assert_string_equal(data->references[0].value, "docker");
    assert_string_equal(data->references[1].type, "archive");
    assert_string_equal(data->docker_socket, "/run/d.sock");

    wm_free(wmodules);
}

/* The <docker> tag of the proposed runtime configuration is bound the same way. */
static void test_local_docker_binds_the_docker_tag_socket(void **state) {
    wmodule *wmodules = NULL;

    if (write_conf("<container_security>"
                   "<docker><enabled>yes</enabled><socket_path>/run/podman.sock</socket_path></docker>"
                   "<images><references><local>docker</local></references></images>"
                   "</container_security>") != 0) {
        fail();
    }

    assert_int_equal(ReadConfig(CWMODULE, TEST_CONF_PATH, &wmodules, NULL), 0);

    wm_container_images_t *data = container_images_data(wmodules);
    assert_int_equal(data->references_count, 1);
    assert_string_equal(data->docker_socket, "/run/podman.sock");

    wm_free(wmodules);
}

/* An engine block that names no socket means the socket runtime security defaults to, so both read the same. */
static void test_local_docker_without_a_socket_uses_the_default(void **state) {
    wmodule *wmodules = NULL;

    if (write_conf("<container_security>"
                   "<container_instances><type>docker</type></container_instances>"
                   "<images><references><local>docker</local></references></images>"
                   "</container_security>") != 0) {
        fail();
    }

    assert_int_equal(ReadConfig(CWMODULE, TEST_CONF_PATH, &wmodules, NULL), 0);

    wm_container_images_t *data = container_images_data(wmodules);
    assert_int_equal(data->references_count, 1);
    assert_string_equal(data->docker_socket, "/var/run/docker.sock");

    wm_free(wmodules);
}

/* No engine in the block: the entry is reported and dropped, the rest of <images> runs. */
static void test_local_docker_without_an_engine_is_dropped(void **state) {
    wmodule *wmodules = NULL;

    if (write_conf("<container_security>"
                   "<images><references><local>docker</local><archive>/var/tmp/a.tar</archive></references></images>"
                   "</container_security>") != 0) {
        fail();
    }

    expect_local_warning("The 'local' reference 'docker' at module 'container_images' needs the Docker engine of the "
                         "same 'container_security' block, and none is configured. Ignoring it.");

    assert_int_equal(ReadConfig(CWMODULE, TEST_CONF_PATH, &wmodules, NULL), 0);

    wm_container_images_t *data = container_images_data(wmodules);
    assert_int_equal(data->references_count, 1);
    assert_string_equal(data->references[0].type, "archive");
    assert_null(data->docker_socket);

    wm_free(wmodules);
}

/* Only a block of type docker is a Docker engine, and a disabled one is not usable. */
static void test_local_docker_needs_an_enabled_docker_engine(void **state) {
    wmodule *wmodules = NULL;

    if (write_conf("<container_security>"
                   "<container_instances><type>kubernetes</type><socket_path>/run/k.sock</socket_path></container_instances>"
                   "<images><references><local>docker</local></references></images>"
                   "</container_security>") != 0) {
        fail();
    }

    expect_local_warning("The 'local' reference 'docker' at module 'container_images' needs the Docker engine of the "
                         "same 'container_security' block, and none is configured. Ignoring it.");

    assert_int_equal(ReadConfig(CWMODULE, TEST_CONF_PATH, &wmodules, NULL), 0);
    assert_int_equal(container_images_data(wmodules)->references_count, 0);
    assert_null(container_images_data(wmodules)->docker_socket);
    wm_free(wmodules);

    wmodules = NULL;

    if (write_conf("<container_security>"
                   "<container_instances><enabled>no</enabled><type>docker</type></container_instances>"
                   "<images><references><local>docker</local></references></images>"
                   "</container_security>") != 0) {
        fail();
    }

    expect_local_warning("The 'local' reference 'docker' at module 'container_images' needs the Docker engine of the "
                         "same 'container_security' block, and it is disabled. Ignoring it.");

    assert_int_equal(ReadConfig(CWMODULE, TEST_CONF_PATH, &wmodules, NULL), 0);
    assert_int_equal(container_images_data(wmodules)->references_count, 0);
    wm_free(wmodules);
}

/* A disabled Docker block does not hide an enabled one: the enabled engine is the one bound, whatever the order. */
static void test_local_docker_an_enabled_engine_wins_over_a_disabled_one(void **state) {
    wmodule *wmodules = NULL;

    if (write_conf("<container_security>"
                   "<docker><enabled>no</enabled><socket_path>/run/off.sock</socket_path></docker>"
                   "<images><references><local>docker</local></references></images>"
                   "<container_instances><type>docker</type><socket_path>/run/on.sock</socket_path></container_instances>"
                   "</container_security>") != 0) {
        fail();
    }

    assert_int_equal(ReadConfig(CWMODULE, TEST_CONF_PATH, &wmodules, NULL), 0);

    wm_container_images_t *data = container_images_data(wmodules);
    assert_int_equal(data->references_count, 1);
    assert_string_equal(data->docker_socket, "/run/on.sock");

    wm_free(wmodules);
}

/* Kubernetes has no image export, and any other name is not an engine of the module: one message per entry. */
static void test_local_with_another_engine_name_is_refused(void **state) {
    wmodule *wmodules = NULL;

    if (write_conf("<container_security>"
                   "<container_instances><type>docker</type></container_instances>"
                   "<images><references>"
                   "<local>kubernetes</local><local>podman</local><local>alpine:latest</local><archive>/var/tmp/a.tar</archive>"
                   "</references></images>"
                   "</container_security>") != 0) {
        fail();
    }

    expect_local_warning("The 'local' reference 'kubernetes' at module 'container_images' cannot be read: Kubernetes "
                         "has no image export, so name the images with '<ref>'. Ignoring it.");
    expect_local_warning("The 'local' reference 'podman' at module 'container_images' names an engine that is not "
                         "supported, only 'docker' is. Ignoring it.");
    expect_local_warning("The 'local' reference 'alpine:latest' at module 'container_images' names an engine that is "
                         "not supported, only 'docker' is. Ignoring it.");

    assert_int_equal(ReadConfig(CWMODULE, TEST_CONF_PATH, &wmodules, NULL), 0);

    wm_container_images_t *data = container_images_data(wmodules);
    assert_int_equal(data->references_count, 1);
    assert_string_equal(data->references[0].type, "archive");
    assert_null(data->docker_socket);

    wm_free(wmodules);
}

/* The engine is one per module: a second <local>docker, in the block or in a later one, is a repeat and the
 * socket of the first is kept. */
static void test_local_docker_repeated_keeps_the_first_socket(void **state) {
    wmodule *wmodules = NULL;

    if (write_conf("<container_security>"
                   "<container_instances><type>docker</type><socket_path>/run/one.sock</socket_path></container_instances>"
                   "<images><references><local>docker</local><local>docker</local></references></images>"
                   "</container_security>"
                   "<container_security>"
                   "<container_instances><type>docker</type><socket_path>/run/two.sock</socket_path></container_instances>"
                   "<images><references><local>docker</local></references></images>"
                   "</container_security>") != 0) {
        fail();
    }

    expect_local_warning("The 'local' reference 'docker' at module 'container_images' repeats one already configured, "
                         "ignoring it. Its Docker socket, '/run/one.sock', is used.");
    expect_local_warning("The 'local' reference 'docker' at module 'container_images' repeats one already configured, "
                         "ignoring it. Its Docker socket, '/run/one.sock', is used.");

    assert_int_equal(ReadConfig(CWMODULE, TEST_CONF_PATH, &wmodules, NULL), 0);

    wm_container_images_t *data = container_images_data(wmodules);
    assert_int_equal(data->references_count, 1);
    assert_string_equal(data->docker_socket, "/run/one.sock");

    wm_free(wmodules);
}
#else
/* Engines are Linux only: the entry is reported and dropped, and the module keeps its other references. */
static void test_local_is_reported_outside_linux(void **state) {
    wmodule *wmodules = NULL;

    if (write_conf("<container_security>"
                   "<docker><enabled>yes</enabled></docker>"
                   "<images><references><local>docker</local><archive>/var/tmp/a.tar</archive></references></images>"
                   "</container_security>") != 0) {
        fail();
    }

    expect_runtime_child_reported("docker");
    expect_local_warning("The 'local' reference 'docker' at module 'container_images' needs a container engine, "
                         "which is only supported on Linux agents, ignoring it.");

    assert_int_equal(ReadConfig(CWMODULE, TEST_CONF_PATH, &wmodules, NULL), 0);

    wm_container_images_t *data = container_images_data(wmodules);
    assert_int_equal(data->references_count, 1);
    assert_string_equal(data->references[0].type, "archive");

    wm_free(wmodules);
}
#endif
#endif

#ifndef TEST_AGENT_TARGET

/* A group's agent.conf as the manager validates it: the root is <agent_config>,
 * never the configuration root write_conf() adds. */
static int write_agent_conf(const char *body) {
    FILE *fp = fopen(TEST_CONF_PATH, "w");

    if (!fp) {
        return -1;
    }

    fputs(body, fp);
    fclose(fp);

    return 0;
}

/* On the manager an unknown <agent_config> attribute fails the read, so
 * verify-agent-conf (and PUT /groups/{group_id}/configuration behind it) refuses
 * the file instead of storing a block the agents would apply to every host. */
static void test_agent_config_unknown_attribute_is_fatal(void **state) {
    if (write_agent_conf("<agent_config bogus=\"1\"><localfile><log_format>syslog</log_format>"
                         "<location>/var/log/test.log</location></localfile></agent_config>") != 0) {
        fail();
    }

    expect_string(__wrap__merror, formatted_msg,
                  "(1233): Invalid attribute 'bogus' in the configuration: 'test_config-elements.conf'.");

    assert_int_equal(ReadConfig(CAGENT_CONFIG | CLOCALFILE, TEST_CONF_PATH, NULL, NULL), OS_INVALID);
}

/* The rejection is per attribute: a known one in front of the unknown one does not hide it. */
static void test_agent_config_unknown_attribute_after_known_is_fatal(void **state) {
    if (write_agent_conf("<agent_config name=\"web\" nmae=\"db\"></agent_config>") != 0) {
        fail();
    }

    expect_string(__wrap__merror, formatted_msg,
                  "(1233): Invalid attribute 'nmae' in the configuration: 'test_config-elements.conf'.");

    assert_int_equal(ReadConfig(CAGENT_CONFIG | CLOCALFILE, TEST_CONF_PATH, NULL, NULL), OS_INVALID);
}

/* The four documented attributes stay accepted. */
static void test_agent_config_known_attributes_are_valid(void **state) {
    if (write_agent_conf("<agent_config name=\"web\" os=\"Linux\" profile=\"p1\" overwrite=\"yes\">"
                         "</agent_config>") != 0) {
        fail();
    }

    assert_int_equal(ReadConfig(CAGENT_CONFIG | CLOCALFILE, TEST_CONF_PATH, NULL, NULL), 0);
}

/* Read_Global_JSON(): the `global` section of the effective document (manager only). */
static void test_Read_Global_JSON_accepts_int_and_duration(void **state) {
    _Config config = { .agents_disconnection_time = 900 };
    cJSON *global = cJSON_Parse("{\"agents_disconnection_time\":\"15m\"}");
    assert_non_null(global);

    assert_int_equal(Read_Global_JSON(global, &config), 0);
    assert_int_equal(config.agents_disconnection_time, 900);

    cJSON_Delete(global);
}

static void test_Read_Global_JSON_absent_keeps_defaults(void **state) {
    _Config config = { .agents_disconnection_time = 600 };
    cJSON *global = cJSON_Parse("{}");
    assert_non_null(global);

    assert_int_equal(Read_Global_JSON(global, &config), 0);
    assert_int_equal(config.agents_disconnection_time, 600);

    cJSON_Delete(global);
}

static void test_Read_Global_JSON_rejects_zero_disconnection_time(void **state) {
    _Config config = { .agents_disconnection_time = 900 };
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
        cmocka_unit_test_teardown(test_client_buffer_is_ignored_with_info, teardown_conf_file),
        cmocka_unit_test_teardown(test_container_images_block_is_obsolete, teardown_conf_file),
        cmocka_unit_test_teardown(test_container_security_is_valid_for_other_daemons, teardown_conf_file),
        cmocka_unit_test_teardown(test_unknown_element_is_still_fatal, teardown_conf_file),
        cmocka_unit_test_teardown(test_active_response_is_valid, teardown_conf_file),
        cmocka_unit_test_teardown(test_manager_section_is_ignored_with_warning, teardown_conf_file),
#ifdef TEST_AGENT_TARGET
        cmocka_unit_test_teardown(test_syscheck_deprecated_defaults_are_info, teardown_conf_file),
        cmocka_unit_test_teardown(test_syscheck_deprecated_user_options_are_warning, teardown_conf_file),
        cmocka_unit_test_teardown(test_syscheck_top_level_restart_audit_is_info, teardown_conf_file),
        cmocka_unit_test_teardown(test_syscheck_unknown_element_is_error, teardown_conf_file),
        cmocka_unit_test_teardown(test_syscheck_removed_4x_options_still_load, teardown_conf_file),
        cmocka_unit_test_teardown(test_syscollector_deprecated_default_is_info, teardown_conf_file),
        cmocka_unit_test_teardown(test_sca_deprecated_default_is_info, teardown_conf_file),
        cmocka_unit_test_teardown(test_sca_deprecated_schedule_is_warning, teardown_conf_file),
        cmocka_unit_test_teardown(test_container_security_images_only, teardown_conf_file),
        cmocka_unit_test_teardown(test_container_security_linux_steps_over_runtime_children, teardown_conf_file),
        cmocka_unit_test_teardown(test_container_security_without_images_registers_nothing, teardown_conf_file),
        cmocka_unit_test_teardown(test_container_security_other_children_follow_the_platform, teardown_conf_file),
        cmocka_unit_test_teardown(test_container_security_empty_images_uses_defaults, teardown_conf_file),
        cmocka_unit_test_teardown(test_container_security_repeated_blocks_merge, teardown_conf_file),
        cmocka_unit_test_teardown(test_container_security_beside_the_obsolete_block, teardown_conf_file),
        cmocka_unit_test_teardown(test_container_security_invalid_images_is_rejected, teardown_conf_file),
#ifdef __linux__
        cmocka_unit_test_teardown(test_local_docker_binds_the_container_instances_socket, teardown_conf_file),
        cmocka_unit_test_teardown(test_local_docker_binds_the_docker_tag_socket, teardown_conf_file),
        cmocka_unit_test_teardown(test_local_docker_without_a_socket_uses_the_default, teardown_conf_file),
        cmocka_unit_test_teardown(test_local_docker_without_an_engine_is_dropped, teardown_conf_file),
        cmocka_unit_test_teardown(test_local_docker_needs_an_enabled_docker_engine, teardown_conf_file),
        cmocka_unit_test_teardown(test_local_docker_an_enabled_engine_wins_over_a_disabled_one, teardown_conf_file),
        cmocka_unit_test_teardown(test_local_with_another_engine_name_is_refused, teardown_conf_file),
        cmocka_unit_test_teardown(test_local_docker_repeated_keeps_the_first_socket, teardown_conf_file),
#else
        cmocka_unit_test_teardown(test_local_is_reported_outside_linux, teardown_conf_file),
#endif
#endif
#ifndef TEST_AGENT_TARGET
        cmocka_unit_test_teardown(test_agent_config_unknown_attribute_is_fatal, teardown_conf_file),
        cmocka_unit_test_teardown(test_agent_config_unknown_attribute_after_known_is_fatal, teardown_conf_file),
        cmocka_unit_test_teardown(test_agent_config_known_attributes_are_valid, teardown_conf_file),
        cmocka_unit_test(test_Read_Global_JSON_accepts_int_and_duration),
        cmocka_unit_test(test_Read_Global_JSON_absent_keeps_defaults),
        cmocka_unit_test(test_Read_Global_JSON_rejects_zero_disconnection_time),
#endif
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
