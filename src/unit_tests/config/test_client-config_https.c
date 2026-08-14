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

/* Read_Agent_Server validates every <address> through OS_IsValidIP; queue one
 * "valid IPv4, no expansion needed" expectation per <address> in the fragment
 * before calling parse_agent(). */
static void expect_valid_ip(const char *ip) {
    expect_string(__wrap_OS_IsValidIP, ip_address, ip);
    expect_value(__wrap_OS_IsValidIP, final_ip, NULL);
    will_return(__wrap_OS_IsValidIP, 1);
}

/* Parses `xml_str` as the body of <agent>...</agent> into a fresh agent
 * struct via the real Read_Agent. Caller must Free_Agent + OS_ClearNode +
 * OS_ClearXML the outputs. */
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

/* Parses `xml_str` as the body of a legacy 4.x <client>...</client>. Does not reset
 * cfg, so it can run after parse_agent() on the same struct. */
static int parse_legacy_client(const char *xml_str, OS_XML *xml, xml_node ***nodes, agent *cfg) {
    if (OS_ReadXMLString(xml_str, xml) != 0) {
        return OS_INVALID;
    }

    if (*nodes = OS_GetElementsbyNode(xml, NULL), *nodes == NULL) {
        return OS_INVALID;
    }

    return Read_Legacy_Client_Address(xml, *nodes, cfg, NULL);
}

static void cleanup(OS_XML *xml, xml_node **nodes, agent *cfg) {
    Free_Agent(cfg);
    OS_ClearNode(nodes);
    OS_ClearXML(xml);
}

/* <ssl> block */

static void test_ssl_full_verification_mode(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<server><address>10.0.0.1</address><port>1517</port></server>"
        "<ssl>"
        "<certificate>/etc/wazuh/agent.pem</certificate>"
        "<key>/etc/wazuh/agent.key</key>"
        "<certificate_authorities>/etc/wazuh/ca.pem</certificate_authorities>"
        "<verification_mode>full</verification_mode>"
        "<ciphers>TLS_AES_256_GCM_SHA384</ciphers>"
        "</ssl>";

    expect_valid_ip("10.0.0.1");
    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);

    assert_int_equal(cfg.ssl.verification_mode, AGENT_VERIFY_FULL);
    assert_string_equal(cfg.ssl.certificate, "/etc/wazuh/agent.pem");
    assert_string_equal(cfg.ssl.key, "/etc/wazuh/agent.key");
    assert_string_equal(cfg.ssl.certificate_authorities, "/etc/wazuh/ca.pem");
    assert_string_equal(cfg.ssl.ciphers, "TLS_AES_256_GCM_SHA384");

    cleanup(&xml, nodes, &cfg);
}

/* The agent never negotiates below TLS 1.3, so <ciphers> only accepts TLS 1.3
 * suite names. A TLS 1.2 cipher string parses fine as XML but could never
 * constrain a session, which is the whole reason it is rejected here rather
 * than being handed to OpenSSL to ignore. */

static void test_ssl_ciphers_accepts_a_tls13_suite_list(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<server><address>10.0.0.1</address><port>1517</port></server>"
        "<ssl><ciphers>TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256</ciphers></ssl>";

    expect_valid_ip("10.0.0.1");
    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);
    assert_string_equal(cfg.ssl.ciphers, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256");

    cleanup(&xml, nodes, &cfg);
}

static void test_ssl_ciphers_rejects_a_tls12_cipher_string(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<server><address>10.0.0.1</address><port>1517</port></server>"
        "<ssl><ciphers>HIGH:!aNULL</ciphers></ssl>";

    expect_valid_ip("10.0.0.1");
    expect_string(__wrap__merror, formatted_msg,
                  "Invalid TLS 1.3 cipher suite 'HIGH' in the 'ciphers' option.");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), OS_INVALID);

    cleanup(&xml, nodes, &cfg);
}

static void test_ssl_ciphers_rejects_a_list_of_separators(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    /* Every element is empty, so there is no suite at all. */
    const char *xml_str =
        "<server><address>10.0.0.1</address><port>1517</port></server>"
        "<ssl><ciphers>:::</ciphers></ssl>";

    expect_valid_ip("10.0.0.1");
    expect_string(__wrap__merror, formatted_msg,
                  "Invalid 'ciphers' option: ':::' has an empty cipher suite name.");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), OS_INVALID);

    cleanup(&xml, nodes, &cfg);
}

/* A separator run names a suite that is not there. strtok_r() collapses these,
 * so each position -- leading, trailing and interior -- gets its own case. */

static void test_ssl_ciphers_rejects_a_leading_separator(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<server><address>10.0.0.1</address><port>1517</port></server>"
        "<ssl><ciphers>:TLS_AES_128_GCM_SHA256</ciphers></ssl>";

    expect_valid_ip("10.0.0.1");
    expect_string(__wrap__merror, formatted_msg,
                  "Invalid 'ciphers' option: ':TLS_AES_128_GCM_SHA256' has an empty cipher suite name.");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), OS_INVALID);

    cleanup(&xml, nodes, &cfg);
}

static void test_ssl_ciphers_rejects_a_trailing_separator(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<server><address>10.0.0.1</address><port>1517</port></server>"
        "<ssl><ciphers>TLS_AES_128_GCM_SHA256:</ciphers></ssl>";

    expect_valid_ip("10.0.0.1");
    expect_string(__wrap__merror, formatted_msg,
                  "Invalid 'ciphers' option: 'TLS_AES_128_GCM_SHA256:' has an empty cipher suite name.");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), OS_INVALID);

    cleanup(&xml, nodes, &cfg);
}

static void test_ssl_ciphers_rejects_a_doubled_separator(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<server><address>10.0.0.1</address><port>1517</port></server>"
        "<ssl><ciphers>TLS_AES_128_GCM_SHA256::TLS_AES_256_GCM_SHA384</ciphers></ssl>";

    expect_valid_ip("10.0.0.1");
    expect_string(__wrap__merror, formatted_msg,
                  "Invalid 'ciphers' option: 'TLS_AES_128_GCM_SHA256::TLS_AES_256_GCM_SHA384' "
                  "has an empty cipher suite name.");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), OS_INVALID);

    cleanup(&xml, nodes, &cfg);
}

static void test_ssl_certificate_verification_mode(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<server><address>10.0.0.1</address><port>1517</port></server>"
        "<ssl><verification_mode>certificate</verification_mode></ssl>";

    expect_valid_ip("10.0.0.1");
    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);
    assert_int_equal(cfg.ssl.verification_mode, AGENT_VERIFY_CERT);

    cleanup(&xml, nodes, &cfg);
}

static void test_ssl_none_verification_mode(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<server><address>10.0.0.1</address><port>1517</port></server>"
        "<ssl><verification_mode>none</verification_mode></ssl>";

    expect_valid_ip("10.0.0.1");
    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);
    assert_int_equal(cfg.ssl.verification_mode, AGENT_VERIFY_NONE);

    cleanup(&xml, nodes, &cfg);
}

static void test_ssl_zero_initialized_reads_as_full(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    /* No <ssl> block at all: a zero-initialized struct reads as FULL
     * (AGENT_VERIFY_FULL == 0), so a caller that never sets a default still
     * fails closed rather than silently disabling verification. */
    const char *xml_str = "<server><address>10.0.0.1</address><port>1517</port></server>";

    expect_valid_ip("10.0.0.1");
    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);
    assert_int_equal(cfg.ssl.verification_mode, AGENT_VERIFY_FULL);

    cleanup(&xml, nodes, &cfg);
}

static void test_ssl_absent_keeps_the_default_the_caller_set(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    /* The parser never invents a verification mode, which is what lets ClientConf
     * own the agent's own default of NONE: with no <ssl> block the value the
     * caller came in with is still there afterwards. */
    const char *xml_str = "<server><address>10.0.0.1</address><port>1517</port></server>";

    memset(&cfg, 0, sizeof(cfg));
    cfg.ssl.verification_mode = AGENT_VERIFY_NONE;

    expect_valid_ip("10.0.0.1");
    assert_int_equal(parse_agent_into(xml_str, &xml, &nodes, &cfg), 0);
    assert_int_equal(cfg.ssl.verification_mode, AGENT_VERIFY_NONE);

    cleanup(&xml, nodes, &cfg);
}

static void test_ssl_invalid_verification_mode_is_rejected(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<server><address>10.0.0.1</address><port>1517</port></server>"
        "<ssl><verification_mode>bogus</verification_mode></ssl>";

    expect_valid_ip("10.0.0.1");
    expect_string(__wrap__merror, formatted_msg,
                  "(1235): Invalid value for element 'verification_mode': bogus.");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), OS_INVALID);

    cleanup(&xml, nodes, &cfg);
}

static void test_ssl_invalid_tag_is_rejected(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<server><address>10.0.0.1</address><port>1517</port></server>"
        "<ssl><bogus_tag>x</bogus_tag></ssl>";

    expect_valid_ip("10.0.0.1");
    expect_string(__wrap__merror, formatted_msg,
                  "(1230): Invalid element in the configuration: 'bogus_tag'.");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), OS_INVALID);

    cleanup(&xml, nodes, &cfg);
}

/* <server> naming and the endpoint it carries */

static void test_server_address_and_explicit_port(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str = "<server><address>10.0.0.1</address><port>8443</port></server>";

    expect_valid_ip("10.0.0.1");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);

    assert_int_equal(cfg.server_count, 1);
    assert_string_equal(cfg.server[0].rip, "10.0.0.1");
    assert_int_equal(cfg.server[0].port, 8443);

    cleanup(&xml, nodes, &cfg);
}

static void test_manager_tag_is_rejected(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str = "<manager><address>10.0.0.1</address></manager>";

    expect_string(__wrap__merror, formatted_msg,
                  "(1230): Invalid element in the configuration: 'manager'.");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), OS_INVALID);

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
    expect_string(__wrap__mwarn, formatted_msg,
                  "Only one <server> block is supported; the last one prevails.");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);

    assert_int_equal(cfg.server_count, 1);
    assert_string_equal(cfg.server[0].rip, "10.0.0.2");
    assert_int_equal(cfg.server[0].port, 8443);

    cleanup(&xml, nodes, &cfg);
}

/* <agent><server> and the one value still read from a legacy <client> (#38103) */

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

    cleanup(&xml, nodes, &cfg);
}

static void test_agent_server_port_defaults_to_1517(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str = "<server><address>10.0.0.5</address></server>";

    expect_valid_ip("10.0.0.5");
    expect_string(__wrap__minfo, formatted_msg,
                  "<agent><server><port> is not configured. Using the default port 1517.");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);
    assert_int_equal(cfg.server[0].port, DEFAULT_HTTPS_REMOTE_PORT);

    cleanup(&xml, nodes, &cfg);
}

static void test_legacy_client_address_is_the_fallback(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    memset(&cfg, 0, sizeof(cfg));

    expect_string(__wrap__minfo, formatted_msg,
                  "<agent><server><address> is not configured. Using <client><server><address> "
                  "'10.0.0.1' with the default port 1517.");

    assert_int_equal(parse_legacy_client("<server><address>10.0.0.1</address><port>1517</port></server>",
                                         &xml, &nodes, &cfg), 0);

    assert_int_equal(cfg.server_count, 1);
    assert_string_equal(cfg.server[0].rip, "10.0.0.1");
    assert_int_equal(cfg.server[0].port, DEFAULT_HTTPS_REMOTE_PORT);

    cleanup(&xml, nodes, &cfg);
}

static void test_legacy_client_reads_nothing_but_the_address(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<server><address>10.0.0.1</address><port>1514</port><protocol>tcp</protocol></server>"
        "<crypto_method>aes</crypto_method>"
        "<config-profile>ubuntu, ubuntu22</config-profile>"
        "<notify_time>77</notify_time>"
        "<enrollment><enabled>yes</enabled></enrollment>";

    memset(&cfg, 0, sizeof(cfg));

    expect_string(__wrap__minfo, formatted_msg,
                  "<agent><server><address> is not configured. Using <client><server><address> "
                  "'10.0.0.1' with the default port 1517.");

    assert_int_equal(parse_legacy_client(xml_str, &xml, &nodes, &cfg), 0);

    assert_int_equal(cfg.server[0].port, DEFAULT_HTTPS_REMOTE_PORT);
    assert_int_equal(cfg.notify_time, 0);
    assert_null(cfg.profile);
    assert_null(cfg.enrollment_cfg);

    cleanup(&xml, nodes, &cfg);
}

static void test_legacy_client_takes_the_last_address(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<server><address>10.0.0.1</address></server>"
        "<server><address>10.0.0.2</address></server>";

    memset(&cfg, 0, sizeof(cfg));

    expect_string(__wrap__minfo, formatted_msg,
                  "<agent><server><address> is not configured. Using <client><server><address> "
                  "'10.0.0.2' with the default port 1517.");

    assert_int_equal(parse_legacy_client(xml_str, &xml, &nodes, &cfg), 0);

    assert_int_equal(cfg.server_count, 1);
    assert_string_equal(cfg.server[0].rip, "10.0.0.2");

    cleanup(&xml, nodes, &cfg);
}

static void test_legacy_client_without_an_address_sets_no_server(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    memset(&cfg, 0, sizeof(cfg));

    assert_int_equal(parse_legacy_client("<config-profile>ubuntu</config-profile>",
                                         &xml, &nodes, &cfg), 0);

    assert_null(cfg.server);
    assert_int_equal(cfg.server_count, 0);

    cleanup(&xml, nodes, &cfg);
}

static void test_agent_block_replaces_a_legacy_address(void **state) {
    OS_XML legacy_xml = {0};
    OS_XML agent_xml = {0};
    xml_node **legacy_nodes;
    xml_node **agent_nodes;
    agent cfg;

    memset(&cfg, 0, sizeof(cfg));

    expect_string(__wrap__minfo, formatted_msg,
                  "<agent><server><address> is not configured. Using <client><server><address> "
                  "'10.0.0.1' with the default port 1517.");

    assert_int_equal(parse_legacy_client("<server><address>10.0.0.1</address><port>1517</port></server>",
                                         &legacy_xml, &legacy_nodes, &cfg), 0);

    expect_valid_ip("10.0.0.5");
    expect_string(__wrap__mwarn, formatted_msg,
                  "Only one <server> block is supported; the last one prevails.");

    assert_int_equal(parse_agent_into("<server><address>10.0.0.5</address><port>1600</port></server>",
                                      &agent_xml, &agent_nodes, &cfg), 0);

    assert_int_equal(cfg.server_count, 1);
    assert_string_equal(cfg.server[0].rip, "10.0.0.5");
    assert_int_equal(cfg.server[0].port, 1600);

    OS_ClearNode(legacy_nodes);
    OS_ClearXML(&legacy_xml);
    cleanup(&agent_xml, agent_nodes, &cfg);
}

static void test_legacy_client_is_ignored_once_agent_set_the_address(void **state) {
    OS_XML agent_xml = {0};
    OS_XML legacy_xml = {0};
    xml_node **agent_nodes;
    xml_node **legacy_nodes;
    agent cfg;

    expect_valid_ip("10.0.0.5");

    assert_int_equal(parse_agent("<server><address>10.0.0.5</address><port>1600</port></server>",
                                 &agent_xml, &agent_nodes, &cfg), 0);

    assert_int_equal(parse_legacy_client("<server><address>10.0.0.1</address><port>1517</port></server>",
                                         &legacy_xml, &legacy_nodes, &cfg), 0);

    assert_int_equal(cfg.server_count, 1);
    assert_string_equal(cfg.server[0].rip, "10.0.0.5");
    assert_int_equal(cfg.server[0].port, 1600);

    OS_ClearNode(legacy_nodes);
    OS_ClearXML(&legacy_xml);
    cleanup(&agent_xml, agent_nodes, &cfg);
}

/* The 4.x <client> options are still read, just no longer written: the block was
 * renamed to <agent>, and an upgraded file carries whatever it was left with. */
static void test_agent_block_reads_the_legacy_client_options(void **state) {
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
    assert_int_equal(cfg.ssl.verification_mode, AGENT_VERIFY_FULL);
    assert_string_equal(cfg.profile, "debian, debian8");
    assert_int_equal(cfg.notify_time, 20);
    assert_int_equal(cfg.flags.auto_restart, 1);

    cleanup(&xml, nodes, &cfg);
}

/* What the templates actually ship now (etc/ossec-agent.conf, src/win32/ossec.conf,
 * and inst-functions.sh's WriteAgent): an address, a port, and nothing that only
 * restates a default. Everything left out has to come back as "unset" here, because
 * that is what makes ClientConf's defaults the ones an agent ends up running on. */
static void test_fresh_install_template_shape(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<server><address>10.0.0.1</address><port>1517</port></server>"
        "<config-profile>debian, debian8</config-profile>";

    expect_valid_ip("10.0.0.1");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);

    assert_int_equal(cfg.server_count, 1);
    assert_string_equal(cfg.server[0].rip, "10.0.0.1");
    assert_int_equal(cfg.server[0].port, DEFAULT_HTTPS_REMOTE_PORT);
    assert_string_equal(cfg.profile, "debian, debian8");
    assert_int_equal(cfg.notify_time, 0);        /* ClientConf turns 0 into NOTIFY_TIME. */
    assert_int_equal(cfg.batch.size, 0);         /* Module default (1 MiB / 5 MiB). */
    assert_int_equal(cfg.batch.interval, 0);

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

/* <batch>: accepted, ignored here (owned by the events module, issue 06) */

static void test_batch_size_and_interval_are_parsed(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<server><address>10.0.0.1</address><port>1517</port></server>"
        "<batch><size>1MB</size><interval>10s</interval></batch>";

    expect_valid_ip("10.0.0.1");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);
    assert_int_equal(cfg.batch.size, 1024 * 1024);
    assert_int_equal(cfg.batch.interval, 10);

    cleanup(&xml, nodes, &cfg);
}

static void test_batch_is_unset_when_absent(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    /* Zero is what the transport module reads as "apply your own default". */
    const char *xml_str = "<server><address>10.0.0.1</address><port>1517</port></server>";

    expect_valid_ip("10.0.0.1");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);
    assert_int_equal(cfg.batch.size, 0);
    assert_int_equal(cfg.batch.interval, 0);

    cleanup(&xml, nodes, &cfg);
}

static void test_batch_size_without_a_suffix_is_bytes(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<server><address>10.0.0.1</address><port>1517</port></server>"
        "<batch><size>2048</size></batch>";

    expect_valid_ip("10.0.0.1");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);
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
        "<server><address>10.0.0.1</address><port>1517</port></server>"
        "<batch><size>0</size></batch>";

    expect_valid_ip("10.0.0.1");
    expect_string(__wrap__merror, formatted_msg,
                  "(1235): Invalid value for element 'size': 0.");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), OS_INVALID);

    cleanup(&xml, nodes, &cfg);
}

static void test_batch_size_beyond_the_cap_is_rejected(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    /* Above a gigabyte the value stops being useful and starts being dangerous:
     * a 32-bit agent's size_t wraps past 4 GiB, and 4 GiB exactly wraps to zero,
     * which every reader downstream takes as "unset". */
    const char *xml_str =
        "<server><address>10.0.0.1</address><port>1517</port></server>"
        "<batch><size>2GB</size></batch>";

    expect_valid_ip("10.0.0.1");
    expect_string(__wrap__merror, formatted_msg,
                  "(1235): Invalid value for element 'size': 2GB.");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), OS_INVALID);

    cleanup(&xml, nodes, &cfg);
}

static void test_batch_interval_beyond_a_day_is_rejected(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<server><address>10.0.0.1</address><port>1517</port></server>"
        "<batch><interval>2d</interval></batch>";

    expect_valid_ip("10.0.0.1");
    expect_string(__wrap__merror, formatted_msg,
                  "(1235): Invalid value for element 'interval': 2d.");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), OS_INVALID);

    cleanup(&xml, nodes, &cfg);
}

static void test_batch_invalid_tag_is_rejected(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<server><address>10.0.0.1</address><port>1517</port></server>"
        "<batch><nonsense>1</nonsense></batch>";

    expect_valid_ip("10.0.0.1");
    expect_string(__wrap__merror, formatted_msg, "(1230): Invalid element in the configuration: 'nonsense'.");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), OS_INVALID);

    cleanup(&xml, nodes, &cfg);
}

/* <batch> through the centralized configuration (etc/shared/agent.conf) */

/* Parses `xml_str` as the body of an <agent> block pushed by the manager, via the
 * real Read_Agent_Shared. Same cleanup as parse_agent(). */
static int parse_agent_shared(const char *xml_str, OS_XML *xml, xml_node ***nodes, agent *cfg) {
    memset(cfg, 0, sizeof(*cfg));

    if (OS_ReadXMLString(xml_str, xml) != 0) {
        return OS_INVALID;
    }

    if (*nodes = OS_GetElementsbyNode(xml, NULL), *nodes == NULL) {
        return OS_INVALID;
    }

    return Read_Agent_Shared(xml, *nodes, cfg);
}

static void test_shared_batch_is_parsed(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str = "<batch><size>2MB</size><interval>30s</interval></batch>";

    assert_int_equal(parse_agent_shared(xml_str, &xml, &nodes, &cfg), 0);
    assert_int_equal(cfg.batch.size, 2 * 1024 * 1024);
    assert_int_equal(cfg.batch.interval, 30);

    cleanup(&xml, nodes, &cfg);
}

static void test_shared_batch_is_validated_like_a_local_one(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    /* Pushed centrally or written locally, the same value is the same mistake:
     * the manager does not get a laxer parser. */
    const char *xml_str = "<batch><size>0</size></batch>";

    expect_string(__wrap__merror, formatted_msg,
                  "(1235): Invalid value for element 'size': 0.");

    assert_int_equal(parse_agent_shared(xml_str, &xml, &nodes, &cfg), OS_INVALID);

    cleanup(&xml, nodes, &cfg);
}

static void test_shared_config_still_refuses_local_only_options(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    /* <batch> is opened up, not the whole block: the manager has no business
     * setting how often this endpoint checks in. */
    const char *xml_str = "<notify_time>5</notify_time>";

    expect_string(__wrap__merror, formatted_msg,
                  "(1230): Invalid element in the configuration: 'notify_time'.");

    assert_int_equal(parse_agent_shared(xml_str, &xml, &nodes, &cfg), OS_INVALID);

    cleanup(&xml, nodes, &cfg);
}

/* w_read_agent_batch: the limits as the sync-protocol daemons read them */

#define BATCH_TEST_CONF "/tmp/test_client-config_https_batch.conf"

static void write_conf(const char *body) {
    FILE *fp = fopen(BATCH_TEST_CONF, "w");

    assert_non_null(fp);
    fputs(body, fp);
    fclose(fp);
}

static void test_read_agent_batch_takes_the_limits_from_the_file(void **state) {
    agent_batch batch = {0};

    write_conf("<ossec_config><agent>"
               "<server><address>10.0.0.1</address></server>"
               "<batch><size>3MB</size><interval>45s</interval></batch>"
               "</agent></ossec_config>");

    /* No <server> parsing, so no OS_IsValidIP expectation: the walk only opens
     * <batch>, which is what keeps this off Read_Agent and its allocations. */
    w_read_agent_batch(BATCH_TEST_CONF, NULL, &batch);

    assert_int_equal(batch.size, 3 * 1024 * 1024);
    assert_int_equal(batch.interval, 45);

    remove(BATCH_TEST_CONF);
}

static void test_read_agent_batch_leaves_the_caller_defaults_when_absent(void **state) {
    agent_batch batch = { .size = 777, .interval = 42 };

    write_conf("<ossec_config><agent>"
               "<server><address>10.0.0.1</address></server>"
               "</agent></ossec_config>");

    w_read_agent_batch(BATCH_TEST_CONF, NULL, &batch);

    assert_int_equal(batch.size, 777);
    assert_int_equal(batch.interval, 42);

    remove(BATCH_TEST_CONF);
}

static void test_read_agent_batch_applies_the_local_file_with_no_shared_one(void **state) {
    agent_batch batch = {0};

    /* Most agents have never been pushed an agent.conf. The reader must treat that
     * as "nothing centralized to add", not as a failed read that discards the local
     * block along with it. */
    write_conf("<ossec_config><agent>"
               "<batch><size>3MB</size></batch>"
               "</agent></ossec_config>");

    w_read_agent_batch(BATCH_TEST_CONF, "/tmp/test_client-config_https_no_shared.conf", &batch);

    assert_int_equal(batch.size, 3 * 1024 * 1024);

    remove(BATCH_TEST_CONF);
}

static void test_read_agent_batch_applies_nothing_when_the_block_is_rejected(void **state) {
    agent_batch batch = { .size = 777, .interval = 42 };

    /* Read_Agent_Batch assigns each limit as it walks it, so by the time the bad
     * element is reached the size is already in the struct. Nothing may reach the
     * caller: a configuration the agent refuses must not be half-applied in the
     * daemons that only borrow it. */
    write_conf("<ossec_config><agent>"
               "<batch><size>3MB</size><nonsense>1</nonsense></batch>"
               "</agent></ossec_config>");

    expect_string(__wrap__merror, formatted_msg,
                  "(1230): Invalid element in the configuration: 'nonsense'.");

    w_read_agent_batch(BATCH_TEST_CONF, NULL, &batch);

    assert_int_equal(batch.size, 777);
    assert_int_equal(batch.interval, 42);

    remove(BATCH_TEST_CONF);
}

#define BATCH_SHARED_CONF "/tmp/test_client-config_https_batch_shared.conf"

static void write_shared_conf(const char *body) {
    FILE *fp = fopen(BATCH_SHARED_CONF, "w");

    assert_non_null(fp);
    fputs(body, fp);
    fclose(fp);
}

static void test_read_agent_batch_keeps_the_local_block_when_the_shared_one_is_rejected(void **state) {
    agent_batch batch = {0};

    /* The local block parsed cleanly and stands on its own; a centralized file the
     * agent cannot read is no reason to throw it away. Discarding it left the caller
     * on zero, which the sync protocol reads as "unset" and answers with its built-in
     * default -- while agentd, which never checks this same read, kept running on the
     * local value, so one agent ran two different session limits.
     *
     * Broken at the XML level rather than with an invalid element: a rejected element
     * sits behind ReadConfig's agent_config profile gate, which wants a real
     * queue/sockets/.agent_info to get past. Both routes end in ReadConfig answering
     * OS_INVALID, which is all this function reacts to.
     *
     * The warning is the only message the run produces. config.c is linked from the
     * agent build, so its XML_ERROR for a centralized read is compiled out under
     * CLIENT -- that silence is the reason the warning exists. */
    write_conf("<ossec_config><agent>"
               "<batch><size>3MB</size><interval>45s</interval></batch>"
               "</agent></ossec_config>");
    write_shared_conf("<agent_config><agent><batch><size>9MB</size>");

    expect_string(__wrap__mwarn, formatted_msg,
                  "Could not read the centralized configuration '" BATCH_SHARED_CONF
                  "'. Keeping the local <agent><batch> limits.");

    w_read_agent_batch(BATCH_TEST_CONF, BATCH_SHARED_CONF, &batch);

    /* The local values, and nothing from the file that failed. */
    assert_int_equal(batch.size, 3 * 1024 * 1024);
    assert_int_equal(batch.interval, 45);

    remove(BATCH_TEST_CONF);
    remove(BATCH_SHARED_CONF);
}

static void test_read_agent_batch_survives_a_missing_file(void **state) {
    agent_batch batch = { .size = 777, .interval = 42 };

    w_read_agent_batch("/tmp/test_client-config_https_no_such.conf", NULL, &batch);

    assert_int_equal(batch.size, 777);
    assert_int_equal(batch.interval, 42);
}

/* Deprecated legacy-TCP options: accepted, ignored, warned (#37702 restriction 4) */

static void test_time_reconnect_is_deprecated(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<server><address>10.0.0.1</address><port>1517</port></server>"
        "<time-reconnect>60</time-reconnect>";

    expect_valid_ip("10.0.0.1");
    expect_string(__wrap__mwarn, formatted_msg,
                  "The <time-reconnect> option is deprecated and no longer has any effect.");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);

    cleanup(&xml, nodes, &cfg);
}

static void test_max_retries_is_deprecated(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str = "<server><address>10.0.0.1</address><port>1517</port><max_retries>3</max_retries></server>";

    expect_valid_ip("10.0.0.1");
    expect_string(__wrap__mwarn, formatted_msg,
                  "The <max_retries> option is deprecated and no longer has any effect.");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);

    cleanup(&xml, nodes, &cfg);
}

static void test_retry_interval_is_deprecated(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str = "<server><address>10.0.0.1</address><port>1517</port><retry_interval>5</retry_interval></server>";

    expect_valid_ip("10.0.0.1");
    expect_string(__wrap__mwarn, formatted_msg,
                  "The <retry_interval> option is deprecated and no longer has any effect.");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);

    cleanup(&xml, nodes, &cfg);
}


/* <stats_report> / <config_report> blocks (#37843) */

static void test_reports_are_off_when_absent(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    /* Read_Agent() itself never sets a default -- it only writes report->enabled
     * when <enabled> is present, so a struct that starts zeroed stays zeroed here.
     * This is NOT the product's default for <config_report>: ClientConf() sets
     * that field to 1 before parsing (see test_agentd.c), so a real agent with
     * no <config_report> block ships with it enabled. Only <stats_report> is
     * actually off by default end-to-end. */
    const char *xml_str = "<server><address>10.0.0.1</address><port>1517</port></server>";

    expect_valid_ip("10.0.0.1");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);
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
        "<server><address>10.0.0.1</address><port>1517</port></server>"
        "<stats_report><enabled>yes</enabled><interval>30s</interval></stats_report>";

    expect_valid_ip("10.0.0.1");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);
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
        "<server><address>10.0.0.1</address><port>1517</port></server>"
        "<stats_report><enabled>yes</enabled><interval>2m</interval></stats_report>"
        "<config_report><enabled>yes</enabled><interval>1h</interval></config_report>";

    expect_valid_ip("10.0.0.1");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);
    assert_int_equal(cfg.stats_report.interval, 120);
    assert_int_equal(cfg.config_report.interval, 3600);

    cleanup(&xml, nodes, &cfg);
}

static void test_report_enabled_rejects_a_non_boolean(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<server><address>10.0.0.1</address><port>1517</port></server>"
        "<config_report><enabled>maybe</enabled></config_report>";

    expect_valid_ip("10.0.0.1");
    expect_any(__wrap__merror, formatted_msg);

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), OS_INVALID);

    cleanup(&xml, nodes, &cfg);
}

static void test_report_interval_beyond_a_day_is_rejected(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<server><address>10.0.0.1</address><port>1517</port></server>"
        "<stats_report><interval>2d</interval></stats_report>";

    expect_valid_ip("10.0.0.1");
    expect_any(__wrap__merror, formatted_msg);

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), OS_INVALID);

    cleanup(&xml, nodes, &cfg);
}

static void test_report_invalid_tag_is_rejected(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<server><address>10.0.0.1</address><port>1517</port></server>"
        "<stats_report><cadence>30s</cadence></stats_report>";

    expect_valid_ip("10.0.0.1");
    expect_any(__wrap__merror, formatted_msg);

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), OS_INVALID);

    cleanup(&xml, nodes, &cfg);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ssl_full_verification_mode),
        cmocka_unit_test(test_ssl_certificate_verification_mode),
        cmocka_unit_test(test_ssl_none_verification_mode),
        cmocka_unit_test(test_ssl_zero_initialized_reads_as_full),
        cmocka_unit_test(test_ssl_absent_keeps_the_default_the_caller_set),
        cmocka_unit_test(test_ssl_invalid_verification_mode_is_rejected),
        cmocka_unit_test(test_ssl_invalid_tag_is_rejected),
        cmocka_unit_test(test_ssl_ciphers_accepts_a_tls13_suite_list),
        cmocka_unit_test(test_ssl_ciphers_rejects_a_tls12_cipher_string),
        cmocka_unit_test(test_ssl_ciphers_rejects_a_list_of_separators),
        cmocka_unit_test(test_ssl_ciphers_rejects_a_leading_separator),
        cmocka_unit_test(test_ssl_ciphers_rejects_a_trailing_separator),
        cmocka_unit_test(test_ssl_ciphers_rejects_a_doubled_separator),
        cmocka_unit_test(test_server_address_and_explicit_port),
        cmocka_unit_test(test_manager_tag_is_rejected),
        cmocka_unit_test(test_second_server_block_prevails_with_warning),
        cmocka_unit_test(test_agent_server_address_and_port_are_parsed),
        cmocka_unit_test(test_agent_server_port_defaults_to_1517),
        cmocka_unit_test(test_legacy_client_address_is_the_fallback),
        cmocka_unit_test(test_legacy_client_reads_nothing_but_the_address),
        cmocka_unit_test(test_legacy_client_takes_the_last_address),
        cmocka_unit_test(test_legacy_client_without_an_address_sets_no_server),
        cmocka_unit_test(test_agent_block_replaces_a_legacy_address),
        cmocka_unit_test(test_legacy_client_is_ignored_once_agent_set_the_address),
        cmocka_unit_test(test_agent_block_reads_the_legacy_client_options),
        cmocka_unit_test(test_fresh_install_template_shape),
        cmocka_unit_test(test_agent_invalid_tag_is_rejected),
        cmocka_unit_test(test_read_agent_batch_takes_the_limits_from_the_file),
        cmocka_unit_test(test_read_agent_batch_leaves_the_caller_defaults_when_absent),
        cmocka_unit_test(test_read_agent_batch_applies_the_local_file_with_no_shared_one),
        cmocka_unit_test(test_read_agent_batch_applies_nothing_when_the_block_is_rejected),
        cmocka_unit_test(test_read_agent_batch_keeps_the_local_block_when_the_shared_one_is_rejected),
        cmocka_unit_test(test_read_agent_batch_survives_a_missing_file),
        cmocka_unit_test(test_shared_batch_is_parsed),
        cmocka_unit_test(test_shared_batch_is_validated_like_a_local_one),
        cmocka_unit_test(test_shared_config_still_refuses_local_only_options),
        cmocka_unit_test(test_batch_size_and_interval_are_parsed),
        cmocka_unit_test(test_batch_is_unset_when_absent),
        cmocka_unit_test(test_batch_size_without_a_suffix_is_bytes),
        cmocka_unit_test(test_batch_zero_size_is_rejected),
        cmocka_unit_test(test_batch_size_beyond_the_cap_is_rejected),
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
