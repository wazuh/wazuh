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

/* Read_Agent_Manager validates every <address> through OS_IsValidIP; queue one
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
        "<manager><endpoint>10.0.0.1:1517</endpoint></manager>"
        "<ssl>"
        "<certificate>/etc/wazuh/agent.pem</certificate>"
        "<key>/etc/wazuh/agent.key</key>"
        "<certificate_authorities>/etc/wazuh/ca.pem</certificate_authorities>"
        "<verification_mode>full</verification_mode>"
        "<ciphers>TLS_AES_256_GCM_SHA384</ciphers>"
        "</ssl>";

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
        "<manager><endpoint>10.0.0.1:1517</endpoint></manager>"
        "<ssl><ciphers>TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256</ciphers></ssl>";

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);
    assert_string_equal(cfg.ssl.ciphers, "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256");

    cleanup(&xml, nodes, &cfg);
}

static void test_ssl_ciphers_rejects_a_tls12_cipher_string(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<manager><endpoint>10.0.0.1:1517</endpoint></manager>"
        "<ssl><ciphers>HIGH:!aNULL</ciphers></ssl>";

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
        "<manager><endpoint>10.0.0.1:1517</endpoint></manager>"
        "<ssl><ciphers>:::</ciphers></ssl>";

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
        "<manager><endpoint>10.0.0.1:1517</endpoint></manager>"
        "<ssl><ciphers>:TLS_AES_128_GCM_SHA256</ciphers></ssl>";

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
        "<manager><endpoint>10.0.0.1:1517</endpoint></manager>"
        "<ssl><ciphers>TLS_AES_128_GCM_SHA256:</ciphers></ssl>";

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
        "<manager><endpoint>10.0.0.1:1517</endpoint></manager>"
        "<ssl><ciphers>TLS_AES_128_GCM_SHA256::TLS_AES_256_GCM_SHA384</ciphers></ssl>";

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
        "<manager><endpoint>10.0.0.1:1517</endpoint></manager>"
        "<ssl><verification_mode>certificate</verification_mode></ssl>";

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);
    assert_int_equal(cfg.ssl.verification_mode, AGENT_VERIFY_CERT);

    cleanup(&xml, nodes, &cfg);
}

static void test_ssl_none_verification_mode(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<manager><endpoint>10.0.0.1:1517</endpoint></manager>"
        "<ssl><verification_mode>none</verification_mode></ssl>";

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);
    assert_int_equal(cfg.ssl.verification_mode, AGENT_VERIFY_NONE);

    cleanup(&xml, nodes, &cfg);
}

static void test_ssl_system_verification_mode(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<manager><endpoint>10.0.0.1:1517</endpoint></manager>"
        "<ssl><verification_mode>system</verification_mode></ssl>";

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);
    assert_int_equal(cfg.ssl.verification_mode, AGENT_VERIFY_SYSTEM);

    cleanup(&xml, nodes, &cfg);
}

static void test_ssl_zero_initialized_reads_as_full(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    /* No <ssl> block at all: a zero-initialized struct reads as FULL
     * (AGENT_VERIFY_FULL == 0), so a caller that never sets a default still
     * fails closed rather than silently disabling verification. */
    const char *xml_str = "<manager><endpoint>10.0.0.1:1517</endpoint></manager>";

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
    const char *xml_str = "<manager><endpoint>10.0.0.1:1517</endpoint></manager>";

    memset(&cfg, 0, sizeof(cfg));
    cfg.ssl.verification_mode = AGENT_VERIFY_NONE;

    assert_int_equal(parse_agent_into(xml_str, &xml, &nodes, &cfg), 0);
    assert_int_equal(cfg.ssl.verification_mode, AGENT_VERIFY_NONE);

    cleanup(&xml, nodes, &cfg);
}

static void test_ssl_invalid_verification_mode_is_rejected(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<manager><endpoint>10.0.0.1:1517</endpoint></manager>"
        "<ssl><verification_mode>bogus</verification_mode></ssl>";

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
        "<manager><endpoint>10.0.0.1:1517</endpoint></manager>"
        "<ssl><bogus_tag>x</bogus_tag></ssl>";

    expect_string(__wrap__merror, formatted_msg,
                  "(1230): Invalid element in the configuration: 'bogus_tag'.");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), OS_INVALID);

    cleanup(&xml, nodes, &cfg);
}

/* <manager> naming and the endpoint it carries */

static void test_manager_address_and_explicit_port(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str = "<manager><endpoint>10.0.0.1:8443</endpoint></manager>";


    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);

    assert_int_equal(cfg.server_count, 1);
    assert_string_equal(cfg.server[0].rip, "10.0.0.1");
    assert_int_equal(cfg.server[0].port, 8443);

    cleanup(&xml, nodes, &cfg);
}

static void test_server_tag_is_rejected(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str = "<server><address>10.0.0.1</address></server>";

    expect_string(__wrap__merror, formatted_msg,
                  "(1230): Invalid element in the configuration: 'server'.");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), OS_INVALID);

    cleanup(&xml, nodes, &cfg);
}

/* Single <manager>: the last one prevails (#37702 restriction 2) */

static void test_second_manager_block_prevails_with_warning(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<manager><endpoint>10.0.0.1:1514</endpoint></manager>"
        "<manager><endpoint>10.0.0.2:8443</endpoint></manager>";

    expect_string(__wrap__mwarn, formatted_msg,
                  "Only one <manager> block is supported; the last one prevails.");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);

    assert_int_equal(cfg.server_count, 1);
    assert_string_equal(cfg.server[0].rip, "10.0.0.2");
    assert_int_equal(cfg.server[0].port, 8443);

    cleanup(&xml, nodes, &cfg);
}

/* <agent><manager> and the one value still read from a legacy <client> (#38103) */

static void test_agent_manager_address_and_port_are_parsed(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str = "<manager><endpoint>10.0.0.5:1600</endpoint></manager>";


    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);

    assert_int_equal(cfg.server_count, 1);
    assert_string_equal(cfg.server[0].rip, "10.0.0.5");
    assert_int_equal(cfg.server[0].port, 1600);

    cleanup(&xml, nodes, &cfg);
}

static void test_agent_manager_port_defaults_to_1517(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str = "<manager><endpoint>10.0.0.5</endpoint></manager>";

    expect_string(__wrap__minfo, formatted_msg,
                  "No port in <agent><manager><endpoint>. Using the default port 1517.");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);
    assert_int_equal(cfg.server[0].port, DEFAULT_HTTPS_REMOTE_PORT);

    cleanup(&xml, nodes, &cfg);
}

/* <agent><manager><endpoint> (#38492) */

static void test_agent_manager_endpoint_defaults_to_wazuh_manager_when_absent(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str = "<manager><endpoint>10.0.0.5</endpoint></manager>";

    expect_string(__wrap__minfo, formatted_msg,
                  "No port in <agent><manager><endpoint>. Using the default port 1517.");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);
    assert_string_equal(cfg.server[0].endpoint, "wazuh-manager");

    cleanup(&xml, nodes, &cfg);
}

/* #38624: <endpoint> carries the whole target, in the same language the
 * WAZUH_MANAGER_ENDPOINT installation variable accepts. Only the host is mandatory. */

static void test_agent_manager_endpoint_accepts_a_hostname(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str = "<manager><endpoint>manager.example.com:8443/proxy</endpoint></manager>";

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);
    assert_string_equal(cfg.server[0].rip, "manager.example.com");
    assert_int_equal(cfg.server[0].port, 8443);
    assert_string_equal(cfg.server[0].endpoint, "proxy");

    cleanup(&xml, nodes, &cfg);
}

/* The scheme is optional because the installers write an operator's value through
 * verbatim and a bare address is the common spelling. When present it must be the
 * one transport actually served. */

static void test_agent_manager_endpoint_tolerates_an_https_scheme(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str = "<manager><endpoint>HttPS://10.0.0.5:8443/gateway</endpoint></manager>";

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);
    assert_string_equal(cfg.server[0].rip, "10.0.0.5");
    assert_int_equal(cfg.server[0].port, 8443);
    assert_string_equal(cfg.server[0].endpoint, "gateway");

    cleanup(&xml, nodes, &cfg);
}

static void test_agent_manager_endpoint_rejects_a_non_https_scheme(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str = "<manager><endpoint>http://10.0.0.5/gateway</endpoint></manager>";

    expect_string(__wrap__merror, formatted_msg,
                  "Invalid endpoint 'http://10.0.0.5/gateway': unsupported scheme 'http'; "
                  "only https is served.");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), OS_INVALID);

    cleanup(&xml, nodes, &cfg);
}

/* The distinction the whole grammar turns on: no separator at all means the default
 * prefix, a trailing separator with nothing after it is the deliberate opt-out
 * (#38614). curl cannot tell these apart -- CURLUPART_PATH reports "/" for both --
 * so losing it would silently reinstate the default and undo #38658's fix. */

static void test_agent_manager_endpoint_trailing_slash_opts_out(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str = "<manager><endpoint>10.0.0.5:1517/</endpoint></manager>";

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);
    assert_string_equal(cfg.server[0].rip, "10.0.0.5");
    assert_int_equal(cfg.server[0].port, 1517);
    assert_null(cfg.server[0].endpoint);

    cleanup(&xml, nodes, &cfg);
}

static void test_agent_manager_endpoint_no_slash_keeps_the_default_prefix(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    /* Same address as the opt-out case above, one character apart. */
    const char *xml_str = "<manager><endpoint>10.0.0.5:1517</endpoint></manager>";

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);
    assert_string_equal(cfg.server[0].endpoint, "wazuh-manager");

    cleanup(&xml, nodes, &cfg);
}

/* IPv6 literals are bracketed so their colons cannot be read as the port separator.
 * The brackets are dropped from rip: OS_IsValidIP does not match a bracketed literal
 * and ModuleConfig::baseUrl() re-brackets it for the wire. */

static void test_agent_manager_endpoint_accepts_a_bracketed_ipv6(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str = "<manager><endpoint>[2001:db8::1]:8443/gateway</endpoint></manager>";

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);
    /* Brackets are stripped, then OS_ExpandIPv6() writes the literal out in full --
     * the same normalization <address> has always had for an IPv6 value. */
    assert_string_equal(cfg.server[0].rip, "2001:0DB8:0000:0000:0000:0000:0000:0001");
    assert_int_equal(cfg.server[0].port, 8443);
    assert_int_equal(cfg.server[0].scope_id, 0);

    cleanup(&xml, nodes, &cfg);
}

static void test_agent_manager_endpoint_resolves_a_numeric_ipv6_zone(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    /* A numeric zone passes through without consulting the interface table, so this
     * asserts a fixed scope id without depending on the host's interface names. */
    const char *xml_str = "<manager><endpoint>[fe80::1%257]:1517</endpoint></manager>";

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);
    assert_string_equal(cfg.server[0].rip, "FE80:0000:0000:0000:0000:0000:0000:0001");
    assert_int_equal(cfg.server[0].scope_id, 7);

    cleanup(&xml, nodes, &cfg);
}

static void test_agent_manager_endpoint_rejects_an_unknown_ipv6_zone(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<manager><endpoint>[fe80::1%25wz-no-such-if]:1517</endpoint></manager>";

    expect_string(__wrap__merror, formatted_msg,
                  "Invalid endpoint: no network interface named 'wz-no-such-if' on this host.");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), OS_INVALID);

    cleanup(&xml, nodes, &cfg);
}

/* A configuration value has to be exact, so a component this grammar has no slot for
 * is an error rather than something quietly dropped. */

static void test_agent_manager_endpoint_rejects_a_query_string(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str = "<manager><endpoint>10.0.0.5/gateway?debug=1</endpoint></manager>";

    expect_string(__wrap__merror, formatted_msg,
                  "Invalid endpoint '10.0.0.5/gateway?debug=1': a query string is not allowed.");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), OS_INVALID);

    cleanup(&xml, nodes, &cfg);
}

static void test_agent_manager_endpoint_rejects_embedded_credentials(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str = "<manager><endpoint>user:pass@10.0.0.5:1517</endpoint></manager>";

    expect_any(__wrap__merror, formatted_msg);

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), OS_INVALID);

    cleanup(&xml, nodes, &cfg);
}

static void test_agent_manager_endpoint_rejects_an_out_of_range_port(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str = "<manager><endpoint>10.0.0.5:99999</endpoint></manager>";

    expect_any(__wrap__merror, formatted_msg);

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), OS_INVALID);

    cleanup(&xml, nodes, &cfg);
}

static void test_agent_manager_endpoint_rejects_a_missing_host(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    /* The 5.0.0 prefix-only spelling, arriving without the <address> that used to
     * accompany it: there is no host to connect to. */
    const char *xml_str = "<manager><endpoint>/wazuh-manager/</endpoint></manager>";

    expect_any(__wrap__merror, formatted_msg);

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), OS_INVALID);

    cleanup(&xml, nodes, &cfg);
}

static void test_agent_manager_endpoint_is_parsed(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<manager><endpoint>10.0.0.5:1517/wazuh-manager</endpoint></manager>";


    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);
    assert_string_equal(cfg.server[0].endpoint, "wazuh-manager");

    cleanup(&xml, nodes, &cfg);
}

static void test_agent_manager_endpoint_strips_leading_and_trailing_slashes(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<manager><endpoint>10.0.0.5:1517/wazuh-manager/</endpoint></manager>";


    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);
    assert_string_equal(cfg.server[0].endpoint, "wazuh-manager");

    cleanup(&xml, nodes, &cfg);
}

static void test_agent_manager_endpoint_of_just_slashes_is_no_endpoint(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str = "<manager><endpoint>10.0.0.5:1517/</endpoint></manager>";


    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);
    assert_null(cfg.server[0].endpoint);

    cleanup(&xml, nodes, &cfg);
}

/* An empty <endpoint> is an error, not an opt-out. The manager rejects an empty
 * <global_prefix> the same way, and both sides spell "serve/expect no prefix" as a path
 * of just "/" -- so a value mirrored from one config into the other keeps its meaning
 * instead of being fatal on one side and silently different on the other. */

/* curl accepts ":0" and would go on to connect, and treats a trailing ":" as "no port"
 * and silently defaults. Every installer parser rejects both, so the agent must too or
 * the same value means different things either side of the install boundary. */

static void test_agent_manager_endpoint_rejects_port_zero(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str = "<manager><endpoint>10.0.0.5:0</endpoint></manager>";

    expect_string(__wrap__merror, formatted_msg,
                  "Invalid endpoint '10.0.0.5:0': port 0 is out of the range 1-65535.");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), OS_INVALID);

    cleanup(&xml, nodes, &cfg);
}

static void test_agent_manager_endpoint_rejects_a_trailing_colon(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str = "<manager><endpoint>10.0.0.5:</endpoint></manager>";

    expect_string(__wrap__merror, formatted_msg,
                  "Invalid endpoint '10.0.0.5:': a ':' must be followed by a port.");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), OS_INVALID);

    cleanup(&xml, nodes, &cfg);
}

static void test_agent_manager_empty_endpoint_is_rejected(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str = "<manager><endpoint></endpoint></manager>";

    expect_string(__wrap__merror, formatted_msg,
                  "Invalid endpoint '': a manager address is required.");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), OS_INVALID);

    cleanup(&xml, nodes, &cfg);
}

/* <endpoint> carries the whole target and outranks the deprecated pair, whichever order
 * they appear in -- the 5.0.0 spelling that put only a prefix here never shipped, so a
 * value like "gateway/foo" is a host and a path, not a bare prefix. */

static void test_agent_manager_endpoint_outranks_the_deprecated_pair(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<manager><address>10.0.0.5</address><port>8443</port>"
        "<endpoint>proxy.example:9000/gateway/foo</endpoint></manager>";

    expect_valid_ip("10.0.0.5");
    expect_string(__wrap__mwarn, formatted_msg,
                  "<agent><manager><address> and <port> are ignored when <endpoint> is "
                  "configured; <endpoint> carries the whole target.");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);
    assert_string_equal(cfg.server[0].rip, "proxy.example");
    assert_int_equal(cfg.server[0].port, 9000);
    assert_string_equal(cfg.server[0].endpoint, "gateway/foo");

    cleanup(&xml, nodes, &cfg);
}

/* Document order must not decide the winner: the same block with <endpoint> written
 * first resolves identically. */

static void test_agent_manager_endpoint_outranks_the_pair_whatever_the_order(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<manager><endpoint>proxy.example:9000/gateway/foo</endpoint>"
        "<address>10.0.0.5</address><port>8443</port></manager>";

    expect_valid_ip("10.0.0.5");
    expect_string(__wrap__mwarn, formatted_msg,
                  "<agent><manager><address> and <port> are ignored when <endpoint> is "
                  "configured; <endpoint> carries the whole target.");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);
    assert_string_equal(cfg.server[0].rip, "proxy.example");
    assert_int_equal(cfg.server[0].port, 9000);
    assert_string_equal(cfg.server[0].endpoint, "gateway/foo");

    cleanup(&xml, nodes, &cfg);
}

/* The suggested line must bracket an IPv6 address, or its trailing group would be read as
 * the port when pasted back. rip is the OS_ExpandIPv6'd form, which is what the agent is
 * actually using, so the suggestion stays behaviour-preserving. */

static void test_agent_manager_deprecation_notice_brackets_an_ipv6_address(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<manager><address>2001:db8::1</address><port>8443</port></manager>";

    expect_valid_ip("2001:db8::1");
    expect_string(__wrap__minfo, formatted_msg,
                  "<agent><manager><address> and <port> are deprecated. Replace them with a "
                  "single <endpoint>[2001:0DB8:0000:0000:0000:0000:0000:0001]:8443"
                  "/wazuh-manager</endpoint>");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);
    assert_int_equal(cfg.server[0].port, 8443);

    cleanup(&xml, nodes, &cfg);
}

static void test_agent_manager_endpoint_accepts_multiple_segments(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<manager><endpoint>10.0.0.5:1517/gateway/wazuh-manager</endpoint></manager>";


    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);
    assert_string_equal(cfg.server[0].endpoint, "gateway/wazuh-manager");

    cleanup(&xml, nodes, &cfg);
}

static void test_agent_manager_endpoint_rejects_an_invalid_character(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<manager><endpoint>10.0.0.5:1517/wazuh~manager</endpoint></manager>";

    expect_string(__wrap__merror, formatted_msg,
                  "Invalid endpoint 'wazuh~manager': only letters, digits, '-', '_', '.', "
                  "and '/' (as a segment separator) are allowed.");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), OS_INVALID);

    cleanup(&xml, nodes, &cfg);
}

static void test_agent_manager_endpoint_rejects_a_doubled_slash(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<manager><endpoint>10.0.0.5:1517/gateway//wazuh</endpoint></manager>";

    expect_string(__wrap__merror, formatted_msg,
                  "Invalid endpoint 'gateway//wazuh': empty path segment (repeated '/').");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), OS_INVALID);

    cleanup(&xml, nodes, &cfg);
}

static void test_agent_manager_endpoint_rejects_a_dot_dot_segment(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<manager><endpoint>10.0.0.5:1517/../etc</endpoint></manager>";

    expect_string(__wrap__merror, formatted_msg,
                  "Invalid endpoint '../etc': '.' and '..' are not allowed path segments.");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), OS_INVALID);

    cleanup(&xml, nodes, &cfg);
}

static void test_agent_manager_endpoint_too_long_is_rejected(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;
    char long_endpoint[130];
    char xml_str[256]; // Must fit the whole fragment; long_endpoint alone is 129 chars.
    char expected_msg[256];

    memset(long_endpoint, 'a', sizeof(long_endpoint) - 1);
    long_endpoint[sizeof(long_endpoint) - 1] = '\0';
    snprintf(xml_str, sizeof(xml_str),
             "<manager><endpoint>10.0.0.5:1517/%s</endpoint></manager>",
             long_endpoint);
    // Built from the same long_endpoint, not hand-typed, so the 'a' count can never drift from it.
    snprintf(expected_msg, sizeof(expected_msg), "Invalid endpoint '%s': longer than 128 characters.",
             long_endpoint);

    expect_string(__wrap__merror, formatted_msg, expected_msg);

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), OS_INVALID);

    cleanup(&xml, nodes, &cfg);
}

static void test_legacy_client_address_is_the_fallback(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    memset(&cfg, 0, sizeof(cfg));

    expect_string(__wrap__minfo, formatted_msg,
                  "<agent><manager><endpoint> is not configured. Using <client><server><address> "
                  "'10.0.0.1' with the default port 1517 and the default endpoint prefix 'wazuh-manager'. Replace the "
                  "<client><server> block with a single <endpoint>10.0.0.1:1517/wazuh-manager</endpoint>");

    assert_int_equal(parse_legacy_client("<server><address>10.0.0.1</address><port>1517</port></server>",
                                         &xml, &nodes, &cfg), 0);

    assert_int_equal(cfg.server_count, 1);
    assert_string_equal(cfg.server[0].rip, "10.0.0.1");
    assert_int_equal(cfg.server[0].port, DEFAULT_HTTPS_REMOTE_PORT);
    assert_string_equal(cfg.server[0].endpoint, "wazuh-manager");

    cleanup(&xml, nodes, &cfg);
}

/* The MSI reconfigures a preserved 4.x file in place and, with no <agent> block to
 * target, writes the endpoint into <client><server>. Reading only <address> there left
 * the upgraded agent with no manager at all and refusing to start. */

static void test_legacy_client_reads_an_endpoint(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    memset(&cfg, 0, sizeof(cfg));

    assert_int_equal(parse_legacy_client(
        "<server><endpoint>10.0.0.5:8443/gateway</endpoint></server>", &xml, &nodes, &cfg), 0);
    assert_non_null(cfg.server);
    assert_string_equal(cfg.server[0].rip, "10.0.0.5");
    assert_int_equal(cfg.server[0].port, 8443);
    assert_string_equal(cfg.server[0].endpoint, "gateway");

    cleanup(&xml, nodes, &cfg);
}

/* Bare host: the port and prefix fall back to the same defaults <agent><manager> uses. */

static void test_legacy_client_endpoint_defaults_port_and_prefix(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    memset(&cfg, 0, sizeof(cfg));

    assert_int_equal(parse_legacy_client(
        "<server><endpoint>10.0.0.5</endpoint></server>", &xml, &nodes, &cfg), 0);
    assert_string_equal(cfg.server[0].rip, "10.0.0.5");
    assert_int_equal(cfg.server[0].port, 1517);
    assert_string_equal(cfg.server[0].endpoint, "wazuh-manager");

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
                  "<agent><manager><endpoint> is not configured. Using <client><server><address> "
                  "'10.0.0.1' with the default port 1517 and the default endpoint prefix 'wazuh-manager'. Replace the "
                  "<client><server> block with a single <endpoint>10.0.0.1:1517/wazuh-manager</endpoint>");

    assert_int_equal(parse_legacy_client(xml_str, &xml, &nodes, &cfg), 0);

    /* The XML's own <port>1514</port> (the old 4.x connection port) must never be
     * honored -- a WPK-upgraded agent always reconnects on the 5.x HTTPS port with
     * the manager's default reverse-proxy prefix, not the stale 4.x port. */
    assert_int_equal(cfg.server[0].port, DEFAULT_HTTPS_REMOTE_PORT);
    assert_string_equal(cfg.server[0].endpoint, "wazuh-manager");
    assert_int_equal(cfg.notify_time, 0);
    assert_null(cfg.profile);
    /* The legacy <client> parser must not touch <enrollment> at all: despite
     * the XML above explicitly setting <enabled>yes</enabled>, cfg.enrollment
     * stays at its zeroed default (#38465: a by-value struct now). */
    assert_false(cfg.enrollment.enabled);

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
                  "<agent><manager><endpoint> is not configured. Using <client><server><address> "
                  "'10.0.0.2' with the default port 1517 and the default endpoint prefix 'wazuh-manager'. Replace the "
                  "<client><server> block with a single <endpoint>10.0.0.2:1517/wazuh-manager</endpoint>");

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
                  "<agent><manager><endpoint> is not configured. Using <client><server><address> "
                  "'10.0.0.1' with the default port 1517 and the default endpoint prefix 'wazuh-manager'. Replace the "
                  "<client><server> block with a single <endpoint>10.0.0.1:1517/wazuh-manager</endpoint>");

    assert_int_equal(parse_legacy_client("<server><address>10.0.0.1</address><port>1517</port></server>",
                                         &legacy_xml, &legacy_nodes, &cfg), 0);

    expect_string(__wrap__mwarn, formatted_msg,
                  "Only one <manager> block is supported; the last one prevails.");

    assert_int_equal(parse_agent_into("<manager><endpoint>10.0.0.5:1600</endpoint></manager>",
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

    assert_int_equal(parse_agent("<manager><endpoint>10.0.0.5:1600</endpoint></manager>",
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
        "<manager><endpoint>10.0.0.1:1517</endpoint></manager>"
        "<ssl><verification_mode>full</verification_mode></ssl>"
        "<config-profile>debian, debian8</config-profile>"
        "<notify_time>20</notify_time>"
        "<auto_restart>yes</auto_restart>";


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
        "<manager><endpoint>10.0.0.1:1517</endpoint></manager>"
        "<config-profile>debian, debian8</config-profile>";


    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);

    assert_int_equal(cfg.server_count, 1);
    assert_string_equal(cfg.server[0].rip, "10.0.0.1");
    assert_int_equal(cfg.server[0].port, DEFAULT_HTTPS_REMOTE_PORT);
    assert_string_equal(cfg.profile, "debian, debian8");
    assert_int_equal(cfg.notify_time, 0);        /* ClientConf turns 0 into NOTIFY_TIME. */
    assert_int_equal(cfg.batch.size, 0);         /* Reported and applied as 1 MiB. */
    assert_int_equal(cfg.batch.interval, 0);     /* ClientConf turns 0 into 10 s. */

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

/* <enrollment> block (#38465): by-value now, like <ssl> above -- previously
 * untestable through parse_agent() because Read_Agent_Enrollment() dereferenced
 * a lazily-allocated pointer parse_agent()'s memset() left NULL. */

static void test_enrollment_kept_options_are_parsed(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<manager><endpoint>10.0.0.1:1517</endpoint></manager>"
        "<enrollment>"
        "<enabled>no</enabled>"
        "<agent_name>my-agent</agent_name>"
        "<groups>default,web-servers</groups>"
        "<agent_address>10.0.0.15</agent_address>"
        "<use_source_ip>no</use_source_ip>"
        "<authorization_pass_path>/var/ossec/etc/my.pass</authorization_pass_path>"
        "<delay_after_enrollment>30</delay_after_enrollment>"
        "</enrollment>";

    /* <enrollment><agent_address> still goes through OS_IsValidIP; only the
     * <manager> block moved off it when <address> was folded into <endpoint>. */
    expect_valid_ip("10.0.0.15");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);

    assert_false(cfg.enrollment.enabled);
    assert_string_equal(cfg.enrollment.agent_name, "my-agent");
    assert_string_equal(cfg.enrollment.groups, "default,web-servers");
    assert_string_equal(cfg.enrollment.agent_address, "10.0.0.15");
    assert_false(cfg.enrollment.use_source_ip);
    assert_string_equal(cfg.enrollment.authorization_pass_path, "/var/ossec/etc/my.pass");
    assert_int_equal(cfg.enrollment.delay_after_enrollment, 30);

    cleanup(&xml, nodes, &cfg);
}

static void test_enrollment_use_source_ip_yes(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<manager><endpoint>10.0.0.1:1517</endpoint></manager>"
        "<enrollment><use_source_ip>yes</use_source_ip></enrollment>";

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);

    assert_true(cfg.enrollment.use_source_ip);

    cleanup(&xml, nodes, &cfg);
}

/* Superseded-by-<server>/<ssl> options (#38465 Q5): a 4.x ossec.conf (an
 * upgrade never rewrites it) still parses successfully, logging INFO per
 * recognized-but-ignored tag instead of rejecting the whole block. */
static void test_enrollment_legacy_options_are_ignored_not_rejected(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<manager><endpoint>10.0.0.1:1517</endpoint></manager>"
        "<enrollment>"
        "<manager_address>old-manager.example</manager_address>"
        "<port>1515</port>"
        "<interface_index>2</interface_index>"
        "<ssl_cipher>HIGH:!aNULL</ssl_cipher>"
        "<server_ca_path>/etc/wazuh/ca.pem</server_ca_path>"
        "<agent_certificate_path>/etc/wazuh/agent.pem</agent_certificate_path>"
        "<agent_key_path>/etc/wazuh/agent.key</agent_key_path>"
        "</enrollment>";

    expect_string(__wrap__minfo, formatted_msg,
                  "<manager_address> under <enrollment> is no longer used: enrollment reuses "
                  "<agent><manager>/<agent><ssl>. Ignoring.");
    expect_string(__wrap__minfo, formatted_msg,
                  "<port> under <enrollment> is no longer used: enrollment reuses "
                  "<agent><manager>/<agent><ssl>. Ignoring.");
    expect_string(__wrap__minfo, formatted_msg,
                  "<interface_index> under <enrollment> is no longer used: enrollment reuses "
                  "<agent><manager>/<agent><ssl>. Ignoring.");
    expect_string(__wrap__minfo, formatted_msg,
                  "<ssl_cipher> under <enrollment> is no longer used: enrollment reuses "
                  "<agent><manager>/<agent><ssl>. Ignoring.");
    expect_string(__wrap__minfo, formatted_msg,
                  "<server_ca_path> under <enrollment> is no longer used: enrollment reuses "
                  "<agent><manager>/<agent><ssl>. Ignoring.");
    expect_string(__wrap__minfo, formatted_msg,
                  "<agent_certificate_path> under <enrollment> is no longer used: enrollment reuses "
                  "<agent><manager>/<agent><ssl>. Ignoring.");
    expect_string(__wrap__minfo, formatted_msg,
                  "<agent_key_path> under <enrollment> is no longer used: enrollment reuses "
                  "<agent><manager>/<agent><ssl>. Ignoring.");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);

    /* None of the removed tags map to a surviving field: the struct stays at
     * its zeroed defaults. */
    assert_false(cfg.enrollment.enabled);
    assert_null(cfg.enrollment.agent_name);
    assert_null(cfg.enrollment.groups);
    assert_null(cfg.enrollment.agent_address);
    assert_null(cfg.enrollment.authorization_pass_path);

    cleanup(&xml, nodes, &cfg);
}

static void test_enrollment_unknown_element_is_still_rejected(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<manager><endpoint>10.0.0.1:1517</endpoint></manager>"
        "<enrollment><nonsense>1</nonsense></enrollment>";

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
        "<manager><endpoint>10.0.0.1:1517</endpoint></manager>"
        "<batch><size>1MB</size><interval>10s</interval></batch>";


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
    const char *xml_str = "<manager><endpoint>10.0.0.1:1517</endpoint></manager>";


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
        "<manager><endpoint>10.0.0.1:1517</endpoint></manager>"
        "<batch><size>2048</size></batch>";


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
        "<manager><endpoint>10.0.0.1:1517</endpoint></manager>"
        "<batch><size>0</size></batch>";

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
        "<manager><endpoint>10.0.0.1:1517</endpoint></manager>"
        "<batch><size>2GB</size></batch>";

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
        "<manager><endpoint>10.0.0.1:1517</endpoint></manager>"
        "<batch><interval>2d</interval></batch>";

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
        "<manager><endpoint>10.0.0.1:1517</endpoint></manager>"
        "<batch><nonsense>1</nonsense></batch>";

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
               "<manager><endpoint>10.0.0.1</endpoint></manager>"
               "<batch><size>3MB</size><interval>45s</interval></batch>"
               "</agent></ossec_config>");

    /* No <manager> parsing, so no OS_IsValidIP expectation: the walk only opens
     * <batch>, which is what keeps this off Read_Agent and its allocations. */
    w_read_agent_batch(BATCH_TEST_CONF, NULL, &batch);

    assert_int_equal(batch.size, 3 * 1024 * 1024);
    assert_int_equal(batch.interval, 45);

    remove(BATCH_TEST_CONF);
}

static void test_read_agent_batch_leaves_the_caller_defaults_when_absent(void **state) {
    agent_batch batch = { .size = 777, .interval = 42 };

    write_conf("<ossec_config><agent>"
               "<manager><endpoint>10.0.0.1</endpoint></manager>"
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
        "<manager><endpoint>10.0.0.1:1517</endpoint></manager>"
        "<time-reconnect>60</time-reconnect>";

    expect_string(__wrap__mwarn, formatted_msg,
                  "The <time-reconnect> option is deprecated and no longer has any effect.");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);

    cleanup(&xml, nodes, &cfg);
}

static void test_max_retries_is_deprecated(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str = "<manager><endpoint>10.0.0.1:1517</endpoint><max_retries>3</max_retries></manager>";

    expect_string(__wrap__mwarn, formatted_msg,
                  "The <max_retries> option is deprecated and no longer has any effect.");

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), 0);

    cleanup(&xml, nodes, &cfg);
}

static void test_retry_interval_is_deprecated(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str = "<manager><endpoint>10.0.0.1:1517</endpoint><retry_interval>5</retry_interval></manager>";

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
    const char *xml_str = "<manager><endpoint>10.0.0.1:1517</endpoint></manager>";


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
        "<manager><endpoint>10.0.0.1:1517</endpoint></manager>"
        "<stats_report><enabled>yes</enabled><interval>30s</interval></stats_report>";


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
        "<manager><endpoint>10.0.0.1:1517</endpoint></manager>"
        "<stats_report><enabled>yes</enabled><interval>2m</interval></stats_report>"
        "<config_report><enabled>yes</enabled><interval>1h</interval></config_report>";


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
        "<manager><endpoint>10.0.0.1:1517</endpoint></manager>"
        "<config_report><enabled>maybe</enabled></config_report>";

    expect_any(__wrap__merror, formatted_msg);

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), OS_INVALID);

    cleanup(&xml, nodes, &cfg);
}

static void test_report_interval_beyond_a_day_is_rejected(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<manager><endpoint>10.0.0.1:1517</endpoint></manager>"
        "<stats_report><interval>2d</interval></stats_report>";

    expect_any(__wrap__merror, formatted_msg);

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), OS_INVALID);

    cleanup(&xml, nodes, &cfg);
}

static void test_report_invalid_tag_is_rejected(void **state) {
    OS_XML xml = {0};
    xml_node **nodes;
    agent cfg;

    const char *xml_str =
        "<manager><endpoint>10.0.0.1:1517</endpoint></manager>"
        "<stats_report><cadence>30s</cadence></stats_report>";

    expect_any(__wrap__merror, formatted_msg);

    assert_int_equal(parse_agent(xml_str, &xml, &nodes, &cfg), OS_INVALID);

    cleanup(&xml, nodes, &cfg);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_ssl_full_verification_mode),
        cmocka_unit_test(test_ssl_certificate_verification_mode),
        cmocka_unit_test(test_ssl_none_verification_mode),
        cmocka_unit_test(test_ssl_system_verification_mode),
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
        cmocka_unit_test(test_enrollment_kept_options_are_parsed),
        cmocka_unit_test(test_enrollment_use_source_ip_yes),
        cmocka_unit_test(test_enrollment_legacy_options_are_ignored_not_rejected),
        cmocka_unit_test(test_enrollment_unknown_element_is_still_rejected),
        cmocka_unit_test(test_manager_address_and_explicit_port),
        cmocka_unit_test(test_server_tag_is_rejected),
        cmocka_unit_test(test_second_manager_block_prevails_with_warning),
        cmocka_unit_test(test_agent_manager_address_and_port_are_parsed),
        cmocka_unit_test(test_agent_manager_port_defaults_to_1517),
        cmocka_unit_test(test_agent_manager_endpoint_defaults_to_wazuh_manager_when_absent),
        cmocka_unit_test(test_agent_manager_endpoint_accepts_a_hostname),
        cmocka_unit_test(test_agent_manager_endpoint_tolerates_an_https_scheme),
        cmocka_unit_test(test_agent_manager_endpoint_rejects_a_non_https_scheme),
        cmocka_unit_test(test_agent_manager_endpoint_trailing_slash_opts_out),
        cmocka_unit_test(test_agent_manager_endpoint_no_slash_keeps_the_default_prefix),
        cmocka_unit_test(test_agent_manager_endpoint_accepts_a_bracketed_ipv6),
        cmocka_unit_test(test_agent_manager_endpoint_resolves_a_numeric_ipv6_zone),
        cmocka_unit_test(test_agent_manager_endpoint_rejects_an_unknown_ipv6_zone),
        cmocka_unit_test(test_agent_manager_endpoint_rejects_a_query_string),
        cmocka_unit_test(test_agent_manager_endpoint_rejects_embedded_credentials),
        cmocka_unit_test(test_agent_manager_endpoint_rejects_an_out_of_range_port),
        cmocka_unit_test(test_agent_manager_endpoint_rejects_a_missing_host),
        cmocka_unit_test(test_agent_manager_endpoint_is_parsed),
        cmocka_unit_test(test_agent_manager_endpoint_strips_leading_and_trailing_slashes),
        cmocka_unit_test(test_agent_manager_endpoint_of_just_slashes_is_no_endpoint),
        cmocka_unit_test(test_agent_manager_endpoint_rejects_port_zero),
        cmocka_unit_test(test_agent_manager_endpoint_rejects_a_trailing_colon),
        cmocka_unit_test(test_agent_manager_empty_endpoint_is_rejected),
        cmocka_unit_test(test_agent_manager_endpoint_outranks_the_deprecated_pair),
        cmocka_unit_test(test_agent_manager_endpoint_outranks_the_pair_whatever_the_order),
        cmocka_unit_test(test_agent_manager_deprecation_notice_brackets_an_ipv6_address),
        cmocka_unit_test(test_agent_manager_endpoint_accepts_multiple_segments),
        cmocka_unit_test(test_agent_manager_endpoint_rejects_an_invalid_character),
        cmocka_unit_test(test_agent_manager_endpoint_rejects_a_doubled_slash),
        cmocka_unit_test(test_agent_manager_endpoint_rejects_a_dot_dot_segment),
        cmocka_unit_test(test_agent_manager_endpoint_too_long_is_rejected),
        cmocka_unit_test(test_legacy_client_address_is_the_fallback),
        cmocka_unit_test(test_legacy_client_reads_an_endpoint),
        cmocka_unit_test(test_legacy_client_endpoint_defaults_port_and_prefix),
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
