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
#include <stdio.h>

#include "shared.h"
#include "os_xml.h"
#include "client-config.h"
#include "config.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/validate_op_wrappers.h"

/* Read_Client_Server validates every <address> through OS_IsValidIP; queue one
 * "valid IPv4, no expansion needed" expectation per <address> in the fragment
 * before calling parse_client(). */
static void expect_valid_ip(const char *ip) {
    expect_string(__wrap_OS_IsValidIP, ip_address, ip);
    expect_value(__wrap_OS_IsValidIP, final_ip, NULL);
    will_return(__wrap_OS_IsValidIP, 1);
}

/* Parses `xml_str` as the body of <client>...</client> into a fresh agent
 * struct via the real Read_Client. Caller must Free_Client + OS_ClearNode +
 * OS_ClearXML the outputs. */
static int parse_client_into(const char *xml_str, OS_XML *xml, xml_node ***nodes, agent *cfg) {
    if (OS_ReadXMLString(xml_str, xml) != 0) {
        return OS_INVALID;
    }

    if (*nodes = OS_GetElementsbyNode(xml, NULL), *nodes == NULL) {
        return OS_INVALID;
    }

    return Read_Client(xml, *nodes, cfg, NULL);
}

static int parse_client(const char *xml_str, OS_XML *xml, xml_node ***nodes, agent *cfg) {
    memset(cfg, 0, sizeof(*cfg));

    return parse_client_into(xml_str, xml, nodes, cfg);
}

/* Parses `xml_str` as the body of <agent>...</agent>. Does not reset cfg, so it
 * can run before or after parse_client() on the same struct. */
static int parse_agent_into(const char *xml_str, OS_XML *xml, xml_node ***nodes, agent *cfg) {
    if (OS_ReadXMLString(xml_str, xml) != 0) {
        return OS_INVALID;
    }

    if (*nodes = OS_GetElementsbyNode(xml, NULL), *nodes == NULL) {
        return OS_INVALID;
    }

    return Read_Agent(xml, *nodes, cfg, NULL);
}

static int parse_agent(const char *xml_str, OS_XML *xml, xml_node ***nodes, agent *cfg) {
    memset(cfg, 0, sizeof(*cfg));

    return parse_agent_into(xml_str, xml, nodes, cfg);
}

static void cleanup(OS_XML *xml, xml_node **nodes, agent *cfg) {
    Free_Client(cfg);
    OS_ClearNode(nodes);
    OS_ClearXML(xml);
}

/* <ssl> block */

static void test_ssl_full_verification_mode(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<server><address>10.0.0.1</address></server>"
        "<ssl>"
        "<certificate>/etc/wazuh/agent.pem</certificate>"
        "<key>/etc/wazuh/agent.key</key>"
        "<certificate_authorities>/etc/wazuh/ca.pem</certificate_authorities>"
        "<verification_mode>full</verification_mode>"
        "<ciphers>HIGH:!aNULL</ciphers>"
        "</ssl>";

    expect_valid_ip("10.0.0.1");
    assert_int_equal(parse_client(xml_str, &xml, &nodes, &cfg), 0);

    assert_int_equal(cfg.ssl.verification_mode, AGENT_VERIFY_FULL);
    assert_string_equal(cfg.ssl.certificate, "/etc/wazuh/agent.pem");
    assert_string_equal(cfg.ssl.key, "/etc/wazuh/agent.key");
    assert_string_equal(cfg.ssl.certificate_authorities, "/etc/wazuh/ca.pem");
    assert_string_equal(cfg.ssl.ciphers, "HIGH:!aNULL");

    cleanup(&xml, nodes, &cfg);
}

static void test_ssl_certificate_verification_mode(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<server><address>10.0.0.1</address></server>"
        "<ssl><verification_mode>certificate</verification_mode></ssl>";

    expect_valid_ip("10.0.0.1");
    assert_int_equal(parse_client(xml_str, &xml, &nodes, &cfg), 0);
    assert_int_equal(cfg.ssl.verification_mode, AGENT_VERIFY_CERT);

    cleanup(&xml, nodes, &cfg);
}

static void test_ssl_none_verification_mode(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<server><address>10.0.0.1</address></server>"
        "<ssl><verification_mode>none</verification_mode></ssl>";

    expect_valid_ip("10.0.0.1");
    assert_int_equal(parse_client(xml_str, &xml, &nodes, &cfg), 0);
    assert_int_equal(cfg.ssl.verification_mode, AGENT_VERIFY_NONE);

    cleanup(&xml, nodes, &cfg);
}

static void test_ssl_default_is_full(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    /* No <ssl> block at all: zero-initialized struct must read as FULL
     * (AGENT_VERIFY_FULL == 0), so an agent that forgets TLS config still
     * fails closed rather than silently disabling verification. */
    const char *xml_str = "<server><address>10.0.0.1</address></server>";

    expect_valid_ip("10.0.0.1");
    assert_int_equal(parse_client(xml_str, &xml, &nodes, &cfg), 0);
    assert_int_equal(cfg.ssl.verification_mode, AGENT_VERIFY_FULL);

    cleanup(&xml, nodes, &cfg);
}

static void test_ssl_invalid_verification_mode_is_rejected(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<server><address>10.0.0.1</address></server>"
        "<ssl><verification_mode>bogus</verification_mode></ssl>";

    expect_valid_ip("10.0.0.1");
    expect_string(__wrap__merror, formatted_msg,
                  "(1235): Invalid value for element 'verification_mode': bogus.");

    assert_int_equal(parse_client(xml_str, &xml, &nodes, &cfg), OS_INVALID);

    cleanup(&xml, nodes, &cfg);
}

static void test_ssl_invalid_tag_is_rejected(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<server><address>10.0.0.1</address></server>"
        "<ssl><bogus_tag>x</bogus_tag></ssl>";

    expect_valid_ip("10.0.0.1");
    expect_string(__wrap__merror, formatted_msg,
                  "(1230): Invalid element in the configuration: 'bogus_tag'.");

    assert_int_equal(parse_client(xml_str, &xml, &nodes, &cfg), OS_INVALID);

    cleanup(&xml, nodes, &cfg);
}

/* <server> / <manager> naming (issue #37828, epic #37702 §10 decision: <server> canonical) */

static void test_server_tag_is_canonical_no_warning(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str = "<server><address>10.0.0.1</address><port>8443</port></server>";

    expect_valid_ip("10.0.0.1");
    expect_string(__wrap__minfo, formatted_msg,
                  "Ignoring the <client><server><port> option. The HTTPS port is taken from "
                  "<agent><server><port>.");

    assert_int_equal(parse_client(xml_str, &xml, &nodes, &cfg), 0);

    assert_int_equal(cfg.server_count, 1);
    assert_string_equal(cfg.server[0].rip, "10.0.0.1");
    assert_int_equal(cfg.server[0].port, DEFAULT_HTTPS_REMOTE_PORT);

    cleanup(&xml, nodes, &cfg);
}

static void test_manager_tag_is_deprecated_but_works(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str = "<manager><address>10.0.0.1</address><port>8443</port></manager>";

    expect_valid_ip("10.0.0.1");
    expect_string(__wrap__minfo, formatted_msg,
                  "The <manager> tag is deprecated, please use <server> instead.");
    expect_string(__wrap__minfo, formatted_msg,
                  "Ignoring the <client><server><port> option. The HTTPS port is taken from "
                  "<agent><server><port>.");

    assert_int_equal(parse_client(xml_str, &xml, &nodes, &cfg), 0);

    assert_int_equal(cfg.server_count, 1);
    assert_string_equal(cfg.server[0].rip, "10.0.0.1");
    assert_int_equal(cfg.server[0].port, DEFAULT_HTTPS_REMOTE_PORT);

    cleanup(&xml, nodes, &cfg);
}

/* Single <server>: the last one prevails (#37702 restriction 2) */

static void test_second_server_block_prevails_with_warning(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<server><address>10.0.0.1</address><port>1514</port></server>"
        "<server><address>10.0.0.2</address><port>8443</port></server>";

    expect_valid_ip("10.0.0.1");
    expect_valid_ip("10.0.0.2");
    expect_string(__wrap__minfo, formatted_msg,
                  "Ignoring the <client><server><port> option. The HTTPS port is taken from "
                  "<agent><server><port>.");
    expect_string(__wrap__minfo, formatted_msg,
                  "Ignoring the <client><server><port> option. The HTTPS port is taken from "
                  "<agent><server><port>.");
    expect_string(__wrap__mwarn, formatted_msg,
                  "Only one <server> block is supported; the last one prevails.");

    assert_int_equal(parse_client(xml_str, &xml, &nodes, &cfg), 0);

    assert_int_equal(cfg.server_count, 1);
    assert_string_equal(cfg.server[0].rip, "10.0.0.2");
    assert_int_equal(cfg.server[0].port, DEFAULT_HTTPS_REMOTE_PORT);

    cleanup(&xml, nodes, &cfg);
}

/* <agent><server>: the 5.x endpoint and its fallbacks (#38103) */

static void test_agent_server_address_and_port_are_parsed(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str = "<server><address>10.0.0.5</address><port>1600</port></server>";

    expect_valid_ip("10.0.0.5");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);

    assert_int_equal(cfg.server_count, 1);
    assert_string_equal(cfg.server[0].rip, "10.0.0.5");
    assert_int_equal(cfg.server[0].port, 1600);
    assert_int_equal(cfg.flags.agent_address, 1);
    assert_int_equal(cfg.flags.agent_port, 1);

    Reconcile_Agent_Server(&cfg);
    assert_int_equal(cfg.server[0].port, 1600);

    cleanup(&xml, nodes, &cfg);
}

static void test_agent_server_port_defaults_to_1517(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str = "<server><address>10.0.0.5</address></server>";

    expect_valid_ip("10.0.0.5");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);
    assert_int_equal(cfg.flags.agent_port, 0);

    expect_string(__wrap__minfo, formatted_msg,
                  "<agent><server><port> is not configured. Using the default port 1517.");

    Reconcile_Agent_Server(&cfg);
    assert_int_equal(cfg.server[0].port, DEFAULT_HTTPS_REMOTE_PORT);

    cleanup(&xml, nodes, &cfg);
}

static void test_agent_server_address_falls_back_to_client(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    /* What a 4.x agent upgraded over WPK looks like: only the legacy block. */
    const char *xml_str = "<server><address>10.0.0.1</address></server>";

    expect_valid_ip("10.0.0.1");

    assert_int_equal(parse_client(xml_str, &xml, &nodes, &cfg), 0);
    assert_int_equal(cfg.flags.agent_address, 0);

    expect_string(__wrap__minfo, formatted_msg,
                  "<agent><server><address> is not configured. Using <client><server><address> '10.0.0.1'.");
    expect_string(__wrap__minfo, formatted_msg,
                  "<agent><server><port> is not configured. Using the default port 1517.");

    Reconcile_Agent_Server(&cfg);

    assert_string_equal(cfg.server[0].rip, "10.0.0.1");
    assert_int_equal(cfg.server[0].port, DEFAULT_HTTPS_REMOTE_PORT);

    cleanup(&xml, nodes, &cfg);
}

static void test_agent_block_prevails_when_read_after_client(void **state) {
    OS_XML client_xml = {0};
    OS_XML agent_xml = {0};
    xml_node **client_nodes;
    xml_node **agent_nodes;
    agent cfg;

    expect_valid_ip("10.0.0.1");
    expect_string(__wrap__minfo, formatted_msg,
                  "Ignoring the <client><server><port> option. The HTTPS port is taken from "
                  "<agent><server><port>.");

    assert_int_equal(parse_client("<server><address>10.0.0.1</address><port>1514</port></server>",
                                  &client_xml, &client_nodes, &cfg), 0);

    expect_valid_ip("10.0.0.5");
    expect_string(__wrap__minfo, formatted_msg,
                  "Both <agent><server> and <client><server> are configured; <agent> prevails.");

    assert_int_equal(parse_agent_into("<server><address>10.0.0.5</address><port>1600</port></server>",
                                      &agent_xml, &agent_nodes, &cfg), 0);

    assert_int_equal(cfg.server_count, 1);
    assert_string_equal(cfg.server[0].rip, "10.0.0.5");
    assert_int_equal(cfg.server[0].port, 1600);

    OS_ClearNode(client_nodes);
    OS_ClearXML(&client_xml);
    cleanup(&agent_xml, agent_nodes, &cfg);
}

static void test_agent_block_prevails_when_read_before_client(void **state) {
    OS_XML client_xml = {0};
    OS_XML agent_xml = {0};
    xml_node **client_nodes;
    xml_node **agent_nodes;
    agent cfg;

    expect_valid_ip("10.0.0.5");

    assert_int_equal(parse_agent("<server><address>10.0.0.5</address><port>1600</port></server>",
                                 &agent_xml, &agent_nodes, &cfg), 0);

    expect_valid_ip("10.0.0.1");
    expect_string(__wrap__minfo, formatted_msg,
                  "Ignoring the <client><server><port> option. The HTTPS port is taken from "
                  "<agent><server><port>.");
    expect_string(__wrap__minfo, formatted_msg,
                  "Ignoring <client><server><address>: <agent><server><address> is already set.");

    assert_int_equal(parse_client_into("<server><address>10.0.0.1</address><port>1514</port></server>",
                                       &client_xml, &client_nodes, &cfg), 0);

    assert_int_equal(cfg.server_count, 1);
    assert_string_equal(cfg.server[0].rip, "10.0.0.5");
    assert_int_equal(cfg.server[0].port, 1600);

    OS_ClearNode(client_nodes);
    OS_ClearXML(&client_xml);
    cleanup(&agent_xml, agent_nodes, &cfg);
}

/* What the 5.x templates ship (etc/ossec-agent.conf, src/win32/ossec.conf): the whole
 * block renamed, so every <client> option is now read under <agent>. */
static void test_fresh_install_template_shape(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<server><address>10.0.0.1</address><port>1517</port></server>"
        "<ssl><verification_mode>full</verification_mode></ssl>"
        "<config-profile>debian, debian8</config-profile>"
        "<notify_time>20</notify_time>"
        "<auto_restart>yes</auto_restart>";

    expect_valid_ip("10.0.0.1");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);

    assert_int_equal(cfg.server_count, 1);
    assert_string_equal(cfg.server[0].rip, "10.0.0.1");
    assert_int_equal(cfg.server[0].port, DEFAULT_HTTPS_REMOTE_PORT);
    assert_int_equal(cfg.flags.agent_address, 1);
    assert_int_equal(cfg.flags.agent_port, 1);
    assert_int_equal(cfg.ssl.verification_mode, AGENT_VERIFY_FULL);
    assert_string_equal(cfg.profile, "debian, debian8");
    assert_int_equal(cfg.notify_time, 20);
    assert_int_equal(cfg.flags.auto_restart, 1);

    /* Nothing to reconcile: both options came from <agent>, so no log is emitted. */
    Reconcile_Agent_Server(&cfg);

    cleanup(&xml, nodes, &cfg);
}

static void test_agent_invalid_tag_is_rejected(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str = "<nonsense>1</nonsense>";

    expect_string(__wrap__merror, formatted_msg, "(1230): Invalid element in the configuration: 'nonsense'.");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), OS_INVALID);

    cleanup(&xml, nodes, &cfg);
}

static void test_reconcile_without_any_address_fails(void **state) {
    agent cfg;

    memset(&cfg, 0, sizeof(cfg));

    expect_string(__wrap__merror, formatted_msg,
                  "No manager address configured: set <agent><server><address>.");

    Reconcile_Agent_Server(&cfg);
}

/* <batch>: accepted, ignored here (owned by the events module, issue 06) */

static void test_batch_size_and_interval_are_parsed(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<server><address>10.0.0.1</address></server>"
        "<batch><size>1MB</size><interval>10s</interval></batch>";

    expect_valid_ip("10.0.0.1");

    assert_int_equal(parse_client(xml_str, &xml, &nodes, &cfg), 0);
    assert_int_equal(cfg.batch.size, 1024 * 1024);
    assert_int_equal(cfg.batch.interval, 10);

    cleanup(&xml, nodes, &cfg);
}

static void test_batch_is_unset_when_absent(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    /* Zero is what the transport module reads as "apply your own default". */
    const char *xml_str = "<server><address>10.0.0.1</address></server>";

    expect_valid_ip("10.0.0.1");

    assert_int_equal(parse_client(xml_str, &xml, &nodes, &cfg), 0);
    assert_int_equal(cfg.batch.size, 0);
    assert_int_equal(cfg.batch.interval, 0);

    cleanup(&xml, nodes, &cfg);
}

static void test_batch_size_without_a_suffix_is_bytes(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<server><address>10.0.0.1</address></server>"
        "<batch><size>2048</size></batch>";

    expect_valid_ip("10.0.0.1");

    assert_int_equal(parse_client(xml_str, &xml, &nodes, &cfg), 0);
    assert_int_equal(cfg.batch.size, 2048);

    cleanup(&xml, nodes, &cfg);
}

static void test_batch_zero_size_is_rejected(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    /* A zero payload can never carry an event; refuse it rather than let it
     * read as "unset" and silently fall back to the default. */
    const char *xml_str =
        "<server><address>10.0.0.1</address></server>"
        "<batch><size>0</size></batch>";

    expect_valid_ip("10.0.0.1");
    expect_string(__wrap__merror, formatted_msg,
                  "(1235): Invalid value for element 'size': 0.");

    assert_int_equal(parse_client(xml_str, &xml, &nodes, &cfg), OS_INVALID);

    cleanup(&xml, nodes, &cfg);
}

static void test_batch_interval_beyond_a_day_is_rejected(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<server><address>10.0.0.1</address></server>"
        "<batch><interval>2d</interval></batch>";

    expect_valid_ip("10.0.0.1");
    expect_string(__wrap__merror, formatted_msg,
                  "(1235): Invalid value for element 'interval': 2d.");

    assert_int_equal(parse_client(xml_str, &xml, &nodes, &cfg), OS_INVALID);

    cleanup(&xml, nodes, &cfg);
}

static void test_batch_invalid_tag_is_rejected(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<server><address>10.0.0.1</address></server>"
        "<batch><nonsense>1</nonsense></batch>";

    expect_valid_ip("10.0.0.1");
    expect_string(__wrap__merror, formatted_msg, "(1230): Invalid element in the configuration: 'nonsense'.");

    assert_int_equal(parse_client(xml_str, &xml, &nodes, &cfg), OS_INVALID);

    cleanup(&xml, nodes, &cfg);
}

/* Deprecated legacy-TCP options: accepted, ignored, warned (#37702 restriction 4) */

static void test_time_reconnect_is_deprecated(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<server><address>10.0.0.1</address></server>"
        "<time-reconnect>60</time-reconnect>";

    expect_valid_ip("10.0.0.1");
    expect_string(__wrap__mwarn, formatted_msg,
                  "The <time-reconnect> option is deprecated and no longer has any effect.");

    assert_int_equal(parse_client(xml_str, &xml, &nodes, &cfg), 0);

    cleanup(&xml, nodes, &cfg);
}

static void test_max_retries_is_deprecated(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str = "<server><address>10.0.0.1</address><max_retries>3</max_retries></server>";

    expect_valid_ip("10.0.0.1");
    expect_string(__wrap__mwarn, formatted_msg,
                  "The <max_retries> option is deprecated and no longer has any effect.");

    assert_int_equal(parse_client(xml_str, &xml, &nodes, &cfg), 0);

    cleanup(&xml, nodes, &cfg);
}

static void test_retry_interval_is_deprecated(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str = "<server><address>10.0.0.1</address><retry_interval>5</retry_interval></server>";

    expect_valid_ip("10.0.0.1");
    expect_string(__wrap__mwarn, formatted_msg,
                  "The <retry_interval> option is deprecated and no longer has any effect.");

    assert_int_equal(parse_client(xml_str, &xml, &nodes, &cfg), 0);

    cleanup(&xml, nodes, &cfg);
}


/* <stats_report> / <config_report> blocks (#37843) */

static void test_reports_are_off_when_absent(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    /* Both pushes must default to off: the manager's config/stats indices have
     * a single writer, and nobody asked for it yet. */
    const char *xml_str = "<server><address>10.0.0.1</address></server>";

    expect_valid_ip("10.0.0.1");

    assert_int_equal(parse_client(xml_str, &xml, &nodes, &cfg), 0);
    assert_int_equal(cfg.stats_report.enabled, 0);
    assert_int_equal(cfg.config_report.enabled, 0);
    assert_int_equal(cfg.stats_report.interval, 0);
    assert_int_equal(cfg.config_report.interval, 0);

    cleanup(&xml, nodes, &cfg);
}

static void test_reports_are_independent_of_each_other(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    /* The issue requires two separate toggles: enabling stats must leave the
     * config push alone. */
    const char *xml_str =
        "<server><address>10.0.0.1</address></server>"
        "<stats_report><enabled>yes</enabled><interval>30s</interval></stats_report>";

    expect_valid_ip("10.0.0.1");

    assert_int_equal(parse_client(xml_str, &xml, &nodes, &cfg), 0);
    assert_int_equal(cfg.stats_report.enabled, 1);
    assert_int_equal(cfg.stats_report.interval, 30);
    assert_int_equal(cfg.config_report.enabled, 0);

    cleanup(&xml, nodes, &cfg);
}

static void test_reports_accept_time_suffixes(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<server><address>10.0.0.1</address></server>"
        "<stats_report><enabled>yes</enabled><interval>2m</interval></stats_report>"
        "<config_report><enabled>yes</enabled><interval>1h</interval></config_report>";

    expect_valid_ip("10.0.0.1");

    assert_int_equal(parse_client(xml_str, &xml, &nodes, &cfg), 0);
    assert_int_equal(cfg.stats_report.interval, 120);
    assert_int_equal(cfg.config_report.interval, 3600);

    cleanup(&xml, nodes, &cfg);
}

static void test_report_enabled_rejects_a_non_boolean(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<server><address>10.0.0.1</address></server>"
        "<config_report><enabled>maybe</enabled></config_report>";

    expect_valid_ip("10.0.0.1");
    expect_any(__wrap__merror, formatted_msg);

    assert_int_equal(parse_client(xml_str, &xml, &nodes, &cfg), OS_INVALID);

    cleanup(&xml, nodes, &cfg);
}

static void test_report_interval_beyond_a_day_is_rejected(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<server><address>10.0.0.1</address></server>"
        "<stats_report><interval>2d</interval></stats_report>";

    expect_valid_ip("10.0.0.1");
    expect_any(__wrap__merror, formatted_msg);

    assert_int_equal(parse_client(xml_str, &xml, &nodes, &cfg), OS_INVALID);

    cleanup(&xml, nodes, &cfg);
}

static void test_report_invalid_tag_is_rejected(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<server><address>10.0.0.1</address></server>"
        "<stats_report><cadence>30s</cadence></stats_report>";

    expect_valid_ip("10.0.0.1");
    expect_any(__wrap__merror, formatted_msg);

    assert_int_equal(parse_client(xml_str, &xml, &nodes, &cfg), OS_INVALID);

    cleanup(&xml, nodes, &cfg);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ssl_full_verification_mode),
        cmocka_unit_test(test_ssl_certificate_verification_mode),
        cmocka_unit_test(test_ssl_none_verification_mode),
        cmocka_unit_test(test_ssl_default_is_full),
        cmocka_unit_test(test_ssl_invalid_verification_mode_is_rejected),
        cmocka_unit_test(test_ssl_invalid_tag_is_rejected),
        cmocka_unit_test(test_server_tag_is_canonical_no_warning),
        cmocka_unit_test(test_manager_tag_is_deprecated_but_works),
        cmocka_unit_test(test_second_server_block_prevails_with_warning),
        cmocka_unit_test(test_agent_server_address_and_port_are_parsed),
        cmocka_unit_test(test_agent_server_port_defaults_to_1517),
        cmocka_unit_test(test_agent_server_address_falls_back_to_client),
        cmocka_unit_test(test_agent_block_prevails_when_read_after_client),
        cmocka_unit_test(test_agent_block_prevails_when_read_before_client),
        cmocka_unit_test(test_fresh_install_template_shape),
        cmocka_unit_test(test_agent_invalid_tag_is_rejected),
        cmocka_unit_test(test_reconcile_without_any_address_fails),
        cmocka_unit_test(test_batch_size_and_interval_are_parsed),
        cmocka_unit_test(test_batch_is_unset_when_absent),
        cmocka_unit_test(test_batch_size_without_a_suffix_is_bytes),
        cmocka_unit_test(test_batch_zero_size_is_rejected),
        cmocka_unit_test(test_batch_interval_beyond_a_day_is_rejected),
        cmocka_unit_test(test_batch_invalid_tag_is_rejected),
        cmocka_unit_test(test_reports_are_off_when_absent),
        cmocka_unit_test(test_reports_are_independent_of_each_other),
        cmocka_unit_test(test_reports_accept_time_suffixes),
        cmocka_unit_test(test_report_enabled_rejects_a_non_boolean),
        cmocka_unit_test(test_report_interval_beyond_a_day_is_rejected),
        cmocka_unit_test(test_report_invalid_tag_is_rejected),
        cmocka_unit_test(test_time_reconnect_is_deprecated),
        cmocka_unit_test(test_max_retries_is_deprecated),
        cmocka_unit_test(test_retry_interval_is_deprecated),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
