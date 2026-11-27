/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <setjmp.h>
#include <stdio.h>
#include <cmocka.h>
#include <stdlib.h>
#include <string.h>

#include "../../headers/shared.h"
#include "../../active-response/active_responses.h"

#include "../wrappers/common.h"

// Tests
void test_get_ip_version_success_ipv4(void **state) {
    (void) state;
    assert_int_equal(get_ip_version("10.0.0.1"), 4);
    assert_int_equal(get_ip_version("0.0.0.0"), 4);
    assert_int_equal(get_ip_version("255.255.255.255"), 4);
}

void test_get_ip_version_success_ipv6(void **state) {
    (void) state;
    assert_int_equal(get_ip_version("2001:db8::1"), 6);
    assert_int_equal(get_ip_version("2001:DB8::1"), 6);
    assert_int_equal(get_ip_version("::1"), 6);
    assert_int_equal(get_ip_version("::ffff:10.0.0.1"), 6);
}

void test_get_ip_version_rejects_non_standard_ipv6_text(void **state) {
    (void) state;
    assert_int_equal(get_ip_version("2001:0db8:0000::0001"), OS_INVALID);
    assert_int_equal(get_ip_version("2001:db8:0:0:0:0:0:1"), OS_INVALID);
    assert_int_equal(get_ip_version("2001:db8::0001"), OS_INVALID);
    assert_int_equal(get_ip_version("2001:db8::0.0.0.1"), OS_INVALID);
    assert_int_equal(get_ip_version("0:0:0:0:0:0:0:1"), OS_INVALID);
    assert_int_equal(get_ip_version("::ffff:a00:1"), OS_INVALID);
}

void test_get_ip_version_rejects_non_standard_ipv4_text(void **state) {
    (void) state;
    assert_int_equal(get_ip_version("010.0.0.1"), OS_INVALID);
    assert_int_equal(get_ip_version("10.0.0.01"), OS_INVALID);
    assert_int_equal(get_ip_version("167772161"), OS_INVALID);
    assert_int_equal(get_ip_version("0x0a000001"), OS_INVALID);
    assert_int_equal(get_ip_version("10.1"), OS_INVALID);
    assert_int_equal(get_ip_version("0"), OS_INVALID);
}

void test_get_ip_version_invalid(void **state) {
    (void) state;
    assert_int_equal(get_ip_version(NULL), OS_INVALID);
    assert_int_equal(get_ip_version(""), OS_INVALID);
    assert_int_equal(get_ip_version("256.0.0.1"), OS_INVALID);
    assert_int_equal(get_ip_version("fe80::1%eth0"), OS_INVALID);
    assert_int_equal(get_ip_version("10.0.0.1 "), OS_INVALID);
    assert_int_equal(get_ip_version("host.example"), OS_INVALID);
}

// Tests for aix_filter_rule_matches

#define AIX_RULE(id, action, src, src_mask, dst, dst_mask, desc) \
    id "|" action "|" src "|" src_mask "|" dst "|" dst_mask "|no|all|any|0|any|0|both|both|no|all packets|0|all|0|||" desc "\n"
#define AIX_WAZUH_DESC "\"" AIX_FILTER_DESCRIPTION "\""

void test_aix_filter_rule_matches_exact(void **state) {
    (void) state;
    assert_true(aix_filter_rule_matches(AIX_RULE("5", "deny", "10.0.0.1", "255.255.255.255", "0.0.0.0", "0.0.0.0", AIX_WAZUH_DESC), "10.0.0.1"));
    assert_true(aix_filter_rule_matches(AIX_RULE("5", "deny", "10.0.0.1", "255.255.255.255", "0.0.0.0", "0.0.0.0", AIX_FILTER_DESCRIPTION), "10.0.0.1"));
}

void test_aix_filter_rule_matches_other_rules(void **state) {
    (void) state;
    assert_false(aix_filter_rule_matches(AIX_RULE("2", "deny", "110.0.0.1", "255.255.255.255", "0.0.0.0", "0.0.0.0", AIX_WAZUH_DESC), "10.0.0.1"));
    assert_false(aix_filter_rule_matches(AIX_RULE("3", "deny", "10.0.0.10", "255.255.255.255", "0.0.0.0", "0.0.0.0", AIX_WAZUH_DESC), "10.0.0.1"));
    assert_false(aix_filter_rule_matches(AIX_RULE("4", "permit", "0.0.0.0", "0.0.0.0", "10.0.0.1", "255.255.255.255", "allow ssh"), "10.0.0.1"));
    assert_false(aix_filter_rule_matches(AIX_RULE("6", "permit", "10.0.0.1", "255.255.255.255", "0.0.0.0", "0.0.0.0", AIX_WAZUH_DESC), "10.0.0.1"));
    assert_false(aix_filter_rule_matches(AIX_RULE("7", "deny", "10.0.0.0", "255.255.255.0", "0.0.0.0", "0.0.0.0", AIX_WAZUH_DESC), "10.0.0.0"));
    assert_false(aix_filter_rule_matches(AIX_RULE("8", "deny", "10.0.0.1", "255.255.255.255", "10.1.1.1", "255.255.255.255", AIX_WAZUH_DESC), "10.0.0.1"));
    assert_false(aix_filter_rule_matches(AIX_RULE("8", "deny", "10.0.0.1", "255.255.255.255", "10.1.1.1", "0.0.0.0", AIX_WAZUH_DESC), "10.0.0.1"));
    assert_false(aix_filter_rule_matches(AIX_RULE("8", "deny", "10.0.0.1", "255.255.255.255", "0.0.0.0", "255.255.255.255", AIX_WAZUH_DESC), "10.0.0.1"));
    assert_false(aix_filter_rule_matches(AIX_RULE("9", "deny", "10.0.0.1", "255.255.255.255", "0.0.0.0", "0.0.0.0", "admin block"), "10.0.0.1"));
    assert_false(aix_filter_rule_matches(AIX_RULE("1", "permit", "0.0.0.0", "0.0.0.0", "0.0.0.0", "0.0.0.0", "Default Rule"), "0.0.0.0"));
}

void test_aix_filter_rule_matches_malformed(void **state) {
    (void) state;
    assert_false(aix_filter_rule_matches(NULL, "10.0.0.1"));
    assert_false(aix_filter_rule_matches(AIX_RULE("5", "deny", "10.0.0.1", "255.255.255.255", "0.0.0.0", "0.0.0.0", AIX_WAZUH_DESC), NULL));
    assert_false(aix_filter_rule_matches("", "10.0.0.1"));
    assert_false(aix_filter_rule_matches("5|deny|10.0.0.1|255.255.255.255|" AIX_WAZUH_DESC "\n", "10.0.0.1"));
    assert_false(aix_filter_rule_matches("Beginning of IPv4 filter rules.\n", "10.0.0.1"));
    assert_false(aix_filter_rule_matches(AIX_WAZUH_DESC "|deny|10.0.0.1|255.255.255.255|0.0.0.0", "10.0.0.1"));
}

// Tests for get_srcip_from_json

static void assert_srcip(const char *json, const char *expected) {
    cJSON *input = cJSON_Parse(json);
    assert_non_null(input);
    const char *srcip = get_srcip_from_json(input);
    if (expected) {
        assert_non_null(srcip);
        assert_string_equal(srcip, expected);
    } else {
        assert_null(srcip);
    }
    cJSON_Delete(input);
}

#define SRCIP_JSON(ip) "{\"parameters\":{\"alert\":{\"data\":{\"srcip\":\"" ip "\"}}}}"
#define WIN_IP_JSON(ip) "{\"parameters\":{\"alert\":{\"data\":{\"win\":{\"eventdata\":{\"ipAddress\":\"" ip "\"}}}}}}"

void test_get_srcip_from_json_valid(void **state) {
    (void) state;
    assert_srcip(SRCIP_JSON("10.0.0.1"), "10.0.0.1");
    assert_srcip(SRCIP_JSON("2001:db8::1"), "2001:db8::1");
    assert_srcip(WIN_IP_JSON("10.0.0.1"), "10.0.0.1");
}

void test_get_srcip_from_json_mapped_ipv4(void **state) {
    (void) state;
    assert_srcip(SRCIP_JSON("::ffff:10.0.0.1"), "10.0.0.1");
    assert_srcip(WIN_IP_JSON("::ffff:10.0.0.1"), "10.0.0.1");
    // Any other case of the prefix stays an IPv6 address
    assert_srcip(SRCIP_JSON("::FFFF:10.0.0.1"), "::FFFF:10.0.0.1");
    assert_srcip(SRCIP_JSON("0:0:0:0:0:ffff:10.0.0.1"), NULL);
    assert_srcip(SRCIP_JSON("::ffff:a00:1"), NULL);
}

void test_get_srcip_from_json_invalid(void **state) {
    (void) state;
    assert_srcip(SRCIP_JSON("010.0.0.1"), NULL);
    assert_srcip(SRCIP_JSON("::ffff:010.0.0.1"), NULL);
    assert_srcip(SRCIP_JSON("::ffff:167772161"), NULL);
    assert_srcip(SRCIP_JSON("::ffff:"), NULL);
    assert_srcip(SRCIP_JSON(""), NULL);
    assert_srcip("{\"parameters\":{\"alert\":{\"data\":{}}}}", NULL);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_get_ip_version_success_ipv4),
        cmocka_unit_test(test_get_ip_version_success_ipv6),
        cmocka_unit_test(test_get_ip_version_rejects_non_standard_ipv4_text),
        cmocka_unit_test(test_get_ip_version_rejects_non_standard_ipv6_text),
        cmocka_unit_test(test_get_ip_version_invalid),
        cmocka_unit_test(test_aix_filter_rule_matches_exact),
        cmocka_unit_test(test_aix_filter_rule_matches_other_rules),
        cmocka_unit_test(test_aix_filter_rule_matches_malformed),
        cmocka_unit_test(test_get_srcip_from_json_valid),
        cmocka_unit_test(test_get_srcip_from_json_mapped_ipv4),
        cmocka_unit_test(test_get_srcip_from_json_invalid),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
