/*
 * Copyright (C) 2015-2019, Wazuh Inc.
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

#include "../analysisd/rules.h"
#include "../analysisd/eventinfo.h"

/* setup */
static int testSetup(void **state) {
    RuleInfo *rule = calloc(1, sizeof(RuleInfo));
    Eventinfo *lf = calloc(1, sizeof(Eventinfo));
    Eventinfo *my_lf = calloc(1, sizeof(Eventinfo));

    if(!rule || !lf || !my_lf) {
        return -1;
    }

    state[0] = rule;
    state[1] = lf;
    state[2] = my_lf;

    return 0;
}

/* redefinitons/wrapping */

int __wrap__merror()
{
    return 0;
}

/* tests for same_loop and different_loop from eventinfo.c */

void test_same_dstip(void **state)
{
    (void) state;
    bool ret;
    RuleInfo *rule = state[0];
    Eventinfo *lf = state[1];
    Eventinfo *my_lf = state[2];
    u_int32_t a = 1;

    rule->same_field = a << 2;

    /* Same destination ip strings should return true */
    lf->dstip = "100.200.50.30";
    my_lf->dstip = "100.200.50.30";
    ret = same_loop(rule, lf, my_lf);
    assert_true(ret);

    /* Different destination ip strings should return false */
    my_lf->dstip = "150.20.70.44";
    ret = same_loop(rule, lf, my_lf);
    assert_false(ret);

    /* different_loop should not return false */
    ret = different_loop(rule, lf, my_lf);
    assert_true(ret);

    os_free(rule);
    os_free(lf);
    os_free(my_lf);
}

void test_same_srcport(void **state)
{
    (void) state;
    bool ret;
    RuleInfo *rule = state[0];
    Eventinfo *lf = state[1];
    Eventinfo *my_lf = state[2];
    u_int32_t a = 1;

    rule->same_field = a << 3;

    /* Same source port strings should return true */
    lf->srcport = "30";
    my_lf->srcport = "30";
    ret = same_loop(rule, lf, my_lf);
    assert_true(ret);

    /* Different source port strings should return false */
    my_lf->srcport = "44";
    ret = same_loop(rule, lf, my_lf);
    assert_false(ret);

    /* different_loop should not return false */
    ret = different_loop(rule, lf, my_lf);
    assert_true(ret);

    os_free(rule);
    os_free(lf);
    os_free(my_lf);
}

void test_same_dstport(void **state)
{
    (void) state;
    bool ret;
    RuleInfo *rule = state[0];
    Eventinfo *lf = state[1];
    Eventinfo *my_lf = state[2];
    u_int32_t a = 1;

    rule->same_field = a << 4;

    /* Same source port strings should return true */
    lf->dstport = "40";
    my_lf->dstport = "40";
    ret = same_loop(rule, lf, my_lf);
    assert_true(ret);

    /* Different source port strings should return false */
    my_lf->dstport = "54";
    ret = same_loop(rule, lf, my_lf);
    assert_false(ret);

    /* different_loop should not return false */
    ret = different_loop(rule, lf, my_lf);
    assert_true(ret);

    os_free(rule);
    os_free(lf);
    os_free(my_lf);
}

void test_same_srcuser(void **state)
{
    (void) state;
    bool ret;
    RuleInfo *rule = state[0];
    Eventinfo *lf = state[1];
    Eventinfo *my_lf = state[2];
    u_int32_t a = 1;

    rule->same_field = a << 5;

    /* Same source user strings should return true */
    lf->srcuser = "User";
    my_lf->srcuser = "User";
    ret = same_loop(rule, lf, my_lf);
    assert_true(ret);

    /* Different source user strings should return false */
    my_lf->srcuser = "Admin";
    ret = same_loop(rule, lf, my_lf);
    assert_false(ret);

    /* different_loop should not return false */
    ret = different_loop(rule, lf, my_lf);
    assert_true(ret);

    os_free(rule);
    os_free(lf);
    os_free(my_lf);
}

void test_same_user(void **state)
{
    (void) state;
    bool ret;
    RuleInfo *rule = state[0];
    Eventinfo *lf = state[1];
    Eventinfo *my_lf = state[2];
    u_int32_t a = 1;

    rule->same_field = a << 6;

    /* Same user strings should return true */
    lf->dstuser = "User";
    my_lf->dstuser = "User";
    ret = same_loop(rule, lf, my_lf);
    assert_true(ret);

    /* Different user strings should return false */
    my_lf->dstuser = "Admin";
    ret = same_loop(rule, lf, my_lf);
    assert_false(ret);

    /* different_loop should not return false */
    ret = different_loop(rule, lf, my_lf);
    assert_true(ret);

    os_free(rule);
    os_free(lf);
    os_free(my_lf);
}

void test_same_protocol(void **state)
{
    (void) state;
    bool ret;
    RuleInfo *rule = state[0];
    Eventinfo *lf = state[1];
    Eventinfo *my_lf = state[2];
    u_int32_t a = 1;

    rule->same_field = a << 7;

    /* Same protocol strings should return true */
    lf->protocol = "TCP";
    my_lf->protocol = "TCP";
    ret = same_loop(rule, lf, my_lf);
    assert_true(ret);

    /* Different protocol strings should return false */
    my_lf->protocol = "UDP";
    ret = same_loop(rule, lf, my_lf);
    assert_false(ret);

    /* different_loop should not return false */
    ret = different_loop(rule, lf, my_lf);
    assert_true(ret);

    os_free(rule);
    os_free(lf);
    os_free(my_lf);
}

void test_same_action(void **state)
{
    (void) state;
    bool ret;
    RuleInfo *rule = state[0];
    Eventinfo *lf = state[1];
    Eventinfo *my_lf = state[2];
    u_int32_t a = 1;

    rule->same_field = a << 8;

    /* Same action strings should return true */
    lf->action = "install";
    my_lf->action = "install";
    ret = same_loop(rule, lf, my_lf);
    assert_true(ret);

    /* Different action strings should return false */
    my_lf->action = "remove";
    ret = same_loop(rule, lf, my_lf);
    assert_false(ret);

    /* different_loop should not return false */
    ret = different_loop(rule, lf, my_lf);
    assert_true(ret);

    os_free(rule);
    os_free(lf);
    os_free(my_lf);
}

void test_same_url(void **state)
{
    (void) state;
    bool ret;
    RuleInfo *rule = state[0];
    Eventinfo *lf = state[1];
    Eventinfo *my_lf = state[2];
    u_int32_t a = 1;

    rule->same_field = a << 9;

    /* Same url strings should return true */
    lf->url = "ossec";
    my_lf->url = "ossec";
    ret = same_loop(rule, lf, my_lf);
    assert_true(ret);

    /* Different url strings should return false */
    my_lf->url = "wazuh";
    ret = same_loop(rule, lf, my_lf);
    assert_false(ret);

    /* different_loop should not return false */
    ret = different_loop(rule, lf, my_lf);
    assert_true(ret);

    os_free(rule);
    os_free(lf);
    os_free(my_lf);
}

void test_same_data(void **state)
{
    (void) state;
    bool ret;
    RuleInfo *rule = state[0];
    Eventinfo *lf = state[1];
    Eventinfo *my_lf = state[2];
    u_int32_t a = 1;

    rule->same_field = a << 10;

    /* Same data strings should return true */
    lf->data = "data1";
    my_lf->data = "data1";
    ret = same_loop(rule, lf, my_lf);
    assert_true(ret);

    /* Different data strings should return false */
    my_lf->data = "data2";
    ret = same_loop(rule, lf, my_lf);
    assert_false(ret);

    /* different_loop should not return false */
    ret = different_loop(rule, lf, my_lf);
    assert_true(ret);

    os_free(rule);
    os_free(lf);
    os_free(my_lf);
}

void test_same_extradata(void **state)
{
    (void) state;
    bool ret;
    RuleInfo *rule = state[0];
    Eventinfo *lf = state[1];
    Eventinfo *my_lf = state[2];
    u_int32_t a = 1;

    rule->same_field = a << 11;

    /* Same extra data strings should return true */
    lf->extra_data = "extra data1";
    my_lf->extra_data = "extra data1";
    ret = same_loop(rule, lf, my_lf);
    assert_true(ret);

    /* Different extra data strings should return false */
    my_lf->extra_data = "extra data2";
    ret = same_loop(rule, lf, my_lf);
    assert_false(ret);

    /* different_loop should not return false */
    ret = different_loop(rule, lf, my_lf);
    assert_true(ret);

    os_free(rule);
    os_free(lf);
    os_free(my_lf);
}

void test_same_status(void **state)
{
    (void) state;
    bool ret;
    RuleInfo *rule = state[0];
    Eventinfo *lf = state[1];
    Eventinfo *my_lf = state[2];
    u_int32_t a = 1;

    rule->same_field = a << 12;

    /* Same status strings should return true */
    lf->status = "started";
    my_lf->status = "started";
    ret = same_loop(rule, lf, my_lf);
    assert_true(ret);

    /* Different status strings should return false */
    my_lf->status = "aborted";
    ret = same_loop(rule, lf, my_lf);
    assert_false(ret);

    /* different_loop should not return false */
    ret = different_loop(rule, lf, my_lf);
    assert_true(ret);

    os_free(rule);
    os_free(lf);
    os_free(my_lf);
}

void test_same_systemname(void **state)
{
    (void) state;
    bool ret;
    RuleInfo *rule = state[0];
    Eventinfo *lf = state[1];
    Eventinfo *my_lf = state[2];
    u_int32_t a = 1;

    rule->same_field = a << 13;

    /* Same system name strings should return true */
    lf->systemname = "centos";
    my_lf->systemname = "centos";
    ret = same_loop(rule, lf, my_lf);
    assert_true(ret);

    /* Different system name strings should return false */
    my_lf->systemname = "ubuntu";
    ret = same_loop(rule, lf, my_lf);
    assert_false(ret);

    /* different_loop should not return false */
    ret = different_loop(rule, lf, my_lf);
    assert_true(ret);

    os_free(rule);
    os_free(lf);
    os_free(my_lf);
}

void test_same_srcgeoip(void **state)
{
    (void) state;
    bool ret;
    RuleInfo *rule = state[0];
    Eventinfo *lf = state[1];
    Eventinfo *my_lf = state[2];
    u_int32_t a = 1;

    rule->same_field = a << 14;

    /* Same srcgeoip strings should return true */
    lf->srcgeoip = "ES / Madrid";
    my_lf->srcgeoip = "ES / Madrid";
    ret = same_loop(rule, lf, my_lf);
    assert_true(ret);

    /* Different srcgeoip strings should return false */
    my_lf->srcgeoip = "ARG / Cordoba";
    ret = same_loop(rule, lf, my_lf);
    assert_false(ret);

    /* different_loop should not return false */
    ret = different_loop(rule, lf, my_lf);
    assert_true(ret);

    os_free(rule);
    os_free(lf);
    os_free(my_lf);
}

void test_same_dstgeoip(void **state)
{
    (void) state;
    bool ret;
    RuleInfo *rule = state[0];
    Eventinfo *lf = state[1];
    Eventinfo *my_lf = state[2];
    u_int32_t a = 1;

    rule->same_field = a << 15;

    /* Same dstgeoip strings should return true */
    lf->dstgeoip = "ES / Madrid";
    my_lf->dstgeoip = "ES / Madrid";
    ret = same_loop(rule, lf, my_lf);
    assert_true(ret);

    /* Different dstgeoip strings should return false */
    my_lf->dstgeoip = "ARG / Cordoba";
    ret = same_loop(rule, lf, my_lf);
    assert_false(ret);

    /* different_loop should not return false */
    ret = different_loop(rule, lf, my_lf);
    assert_true(ret);

    os_free(rule);
    os_free(lf);
    os_free(my_lf);
}

void test_same_location(void **state)
{
    (void) state;
    bool ret;
    RuleInfo *rule = state[0];
    Eventinfo *lf = state[1];
    Eventinfo *my_lf = state[2];
    u_int32_t a = 1;

    rule->same_field = a << 16;

    /* Same location strings should return true */
    lf->location = "/var/ossec/logs/field1";
    my_lf->location = "/var/ossec/logs/field1";
    ret = same_loop(rule, lf, my_lf);
    assert_true(ret);

    /* Different location strings should return false */
    my_lf->location = "/var/ossec/logs/field2";
    ret = same_loop(rule, lf, my_lf);
    assert_false(ret);

    /* different_loop should not return false */
    ret = different_loop(rule, lf, my_lf);
    assert_true(ret);

    os_free(rule);
    os_free(lf);
    os_free(my_lf);
}

void test_different_srcip(void **state)
{
    (void) state;
    bool ret;
    RuleInfo *rule = state[0];
    Eventinfo *lf = state[1];
    Eventinfo *my_lf = state[2];
    u_int32_t a = 1;

    rule->different_field = a;
    
    /* Same source ip strings should return false */
    lf->srcip = "100.200.50.30";
    my_lf->srcip = "100.200.50.30";
    ret = different_loop(rule, lf, my_lf);
    assert_false(ret);

    /* Different source ip strings should return true */
    my_lf->srcip = "150.20.70.44";
    ret = different_loop(rule, lf, my_lf);
    assert_true(ret);

    /* same_loop should not return false */
    ret = same_loop(rule, lf, my_lf);
    assert_true(ret);

    os_free(rule);
    os_free(lf);
    os_free(my_lf);
}

void test_different_id(void **state)
{
    (void) state;
    bool ret;
    RuleInfo *rule = state[0];
    Eventinfo *lf = state[1];
    Eventinfo *my_lf = state[2];
    u_int32_t a = 1;

    rule->different_field = a << 1;
    
    /* Same id strings should return false */
    lf->id = "006";
    my_lf->id = "006";
    ret = different_loop(rule, lf, my_lf);
    assert_false(ret);

    /* Different source ip strings should return true */
    my_lf->id = "007";
    ret = different_loop(rule, lf, my_lf);
    assert_true(ret);

    /* same_loop should not return false */
    ret = same_loop(rule, lf, my_lf);
    assert_true(ret);

    os_free(rule);
    os_free(lf);
    os_free(my_lf);
}

void test_different_dstip(void **state)
{
    (void) state;
    bool ret;
    RuleInfo *rule = state[0];
    Eventinfo *lf = state[1];
    Eventinfo *my_lf = state[2];
    u_int32_t a = 1;

    rule->different_field = a << 2;

    /* Same destination ip strings should return false */
    lf->dstip = "100.200.50.30";
    my_lf->dstip =  "100.200.50.30";
    ret = different_loop(rule, lf, my_lf);
    assert_false(ret);

    /* Different destination ip strings should return true */
    my_lf->dstip = "150.20.70.44";
    ret = different_loop(rule, lf, my_lf);
    assert_true(ret);

    /* same_loop should not return false */
    ret = same_loop(rule, lf, my_lf);
    assert_true(ret);

    os_free(rule);
    os_free(lf);
    os_free(my_lf);
}

void test_different_srcport(void **state)
{
    (void) state;
    bool ret;
    RuleInfo *rule = state[0];
    Eventinfo *lf = state[1];
    Eventinfo *my_lf = state[2];
    u_int32_t a = 1;

    rule->different_field = a << 3;

    /* Same source port strings should return false */
    lf->srcport = "30";
    my_lf->srcport = "30";
    ret = different_loop(rule, lf, my_lf);
    assert_false(ret);

    /* Different source port strings should return true */
    my_lf->srcport = "44";
    ret = different_loop(rule, lf, my_lf);
    assert_true(ret);

    /* same_loop should not return false */
    ret = same_loop(rule, lf, my_lf);
    assert_true(ret);

    os_free(rule);
    os_free(lf);
    os_free(my_lf);
}

void test_different_dstport(void **state)
{
    (void) state;
    bool ret;
    RuleInfo *rule = state[0];
    Eventinfo *lf = state[1];
    Eventinfo *my_lf = state[2];
    u_int32_t a = 1;

    rule->different_field = a << 4;

    /* Same source port strings should return false */
    lf->dstport = "40";
    my_lf->dstport = "40";
    ret = different_loop(rule, lf, my_lf);
    assert_false(ret);

    /* Different source port strings should return true */
    my_lf->dstport = "54";
    ret = different_loop(rule, lf, my_lf);
    assert_true(ret);

    /* same_loop should not return false */
    ret = same_loop(rule, lf, my_lf);
    assert_true(ret);

    os_free(rule);
    os_free(lf);
    os_free(my_lf);
}

void test_different_srcuser(void **state)
{
    (void) state;
    bool ret;
    RuleInfo *rule = state[0];
    Eventinfo *lf = state[1];
    Eventinfo *my_lf = state[2];
    u_int32_t a = 1;

    rule->different_field = a << 5;

    /* Same source user strings should return false */
    lf->srcuser = "User";
    my_lf->srcuser = "User";
    ret = different_loop(rule, lf, my_lf);
    assert_false(ret);

    /* Different source user strings should return true */
    my_lf->srcuser = "Admin";
    ret = different_loop(rule, lf, my_lf);
    assert_true(ret);

    /* same_loop should not return false */
    ret = same_loop(rule, lf, my_lf);
    assert_true(ret);

    os_free(rule);
    os_free(lf);
    os_free(my_lf);
}

void test_different_user(void **state)
{
    (void) state;
    bool ret;
    RuleInfo *rule = state[0];
    Eventinfo *lf = state[1];
    Eventinfo *my_lf = state[2];
    u_int32_t a = 1;

    rule->different_field = a << 6;

    /* Same user strings should return false */
    lf->dstuser = "User";
    my_lf->dstuser = "User";
    ret = different_loop(rule, lf, my_lf);
    assert_false(ret);

    /* Different user strings should return true */
    my_lf->dstuser = "Admin";
    ret = different_loop(rule, lf, my_lf);
    assert_true(ret);

    /* same_loop should not return false */
    ret = same_loop(rule, lf, my_lf);
    assert_true(ret);

    os_free(rule);
    os_free(lf);
    os_free(my_lf);
}

void test_different_protocol(void **state)
{
    (void) state;
    bool ret;
    RuleInfo *rule = state[0];
    Eventinfo *lf = state[1];
    Eventinfo *my_lf = state[2];
    u_int32_t a = 1;

    rule->different_field = a << 7;

    /* Same protocol strings should return false */
    lf->protocol = "TCP";
    my_lf->protocol = "TCP";
    ret = different_loop(rule, lf, my_lf);
    assert_false(ret);

    /* Different protocol strings should return true */
    my_lf->protocol = "UDP";
    ret = different_loop(rule, lf, my_lf);
    assert_true(ret);

    /* same_loop should not return false */
    ret = same_loop(rule, lf, my_lf);
    assert_true(ret);

    os_free(rule);
    os_free(lf);
    os_free(my_lf);
}

void test_different_action(void **state)
{
    (void) state;
    bool ret;
    RuleInfo *rule = state[0];
    Eventinfo *lf = state[1];
    Eventinfo *my_lf = state[2];
    u_int32_t a = 1;

    rule->different_field = a << 8;

    /* Same action strings should return false */
    lf->action = "install";
    my_lf->action = "install";
    ret = different_loop(rule, lf, my_lf);
    assert_false(ret);

    /* Different action strings should return true */
    my_lf->action = "remove";
    ret = different_loop(rule, lf, my_lf);
    assert_true(ret);

    /* same_loop should not return false */
    ret = same_loop(rule, lf, my_lf);
    assert_true(ret);

    os_free(rule);
    os_free(lf);
    os_free(my_lf);
}

void test_different_url(void **state)
{
    (void) state;
    bool ret;
    RuleInfo *rule = state[0];
    Eventinfo *lf = state[1];
    Eventinfo *my_lf = state[2];
    u_int32_t a = 1;

    rule->different_field = a << 9;

    /* Same url strings should return false */
    lf->url = "ossec";
    my_lf->url = "ossec";
    ret = different_loop(rule, lf, my_lf);
    assert_false(ret);

    /* Different url strings should return true */
    my_lf->url = "wazuh";
    ret = different_loop(rule, lf, my_lf);
    assert_true(ret);

    /* same_loop should not return false */
    ret = same_loop(rule, lf, my_lf);
    assert_true(ret);

    os_free(rule);
    os_free(lf);
    os_free(my_lf);
}

void test_different_data(void **state)
{
    (void) state;
    bool ret;
    RuleInfo *rule = state[0];
    Eventinfo *lf = state[1];
    Eventinfo *my_lf = state[2];
    u_int32_t a = 1;

    rule->different_field = a << 10;

    /* Same data strings should return false */
    lf->data = "data1";
    my_lf->data = "data1";
    ret = different_loop(rule, lf, my_lf);
    assert_false(ret);

    /* Different data strings should return true */
    my_lf->data = "data2";
    ret = different_loop(rule, lf, my_lf);
    assert_true(ret);

    /* same_loop should not return false */
    ret = same_loop(rule, lf, my_lf);
    assert_true(ret);

    os_free(rule);
    os_free(lf);
    os_free(my_lf);
}

void test_different_extradata(void **state)
{
    (void) state;
    bool ret;
    RuleInfo *rule = state[0];
    Eventinfo *lf = state[1];
    Eventinfo *my_lf = state[2];
    u_int32_t a = 1;

    rule->different_field = a << 11;

    /* Same extra data strings should return false */
    lf->extra_data = "extra data1";
    my_lf->extra_data = "extra data1";
    ret = different_loop(rule, lf, my_lf);
    assert_false(ret);

    /* Different extra data strings should return true */
    my_lf->extra_data = "extra data2";
    ret = different_loop(rule, lf, my_lf);
    assert_true(ret);

    /* same_loop should not return false */
    ret = same_loop(rule, lf, my_lf);
    assert_true(ret);

    os_free(rule);
    os_free(lf);
    os_free(my_lf);
}

void test_different_status(void **state)
{
    (void) state;
    bool ret;
    RuleInfo *rule = state[0];
    Eventinfo *lf = state[1];
    Eventinfo *my_lf = state[2];
    u_int32_t a = 1;

    rule->different_field = a << 12;

    /* Same status strings should return false */
    lf->status = "started";
    my_lf->status = "started";
    ret = different_loop(rule, lf, my_lf);
    assert_false(ret);

    /* Different status strings should return true */
    my_lf->status = "aborted";
    ret = different_loop(rule, lf, my_lf);
    assert_true(ret);

    /* same_loop should not return false */
    ret = same_loop(rule, lf, my_lf);
    assert_true(ret);

    os_free(rule);
    os_free(lf);
    os_free(my_lf);
}

void test_different_systemname(void **state)
{
    (void) state;
    bool ret;
    RuleInfo *rule = state[0];
    Eventinfo *lf = state[1];
    Eventinfo *my_lf = state[2];
    u_int32_t a = 1;

    rule->different_field = a << 13;

    /* Same system name strings should return false */
    lf->systemname = "centos";
    my_lf->systemname = "centos";
    ret = different_loop(rule, lf, my_lf);
    assert_false(ret);

    /* Different system name strings should return true */
    my_lf->systemname = "ubuntu";
    ret = different_loop(rule, lf, my_lf);
    assert_true(ret);

    /* same_loop should not return false */
    ret = same_loop(rule, lf, my_lf);
    assert_true(ret);

    os_free(rule);
    os_free(lf);
    os_free(my_lf);
}

void test_different_srcgeoip(void **state)
{
    (void) state;
    bool ret;
    RuleInfo *rule = state[0];
    Eventinfo *lf = state[1];
    Eventinfo *my_lf = state[2];
    u_int32_t a = 1;

    rule->different_field = a << 14;

    /* Same srcgeoip strings should return false */
    lf->srcgeoip = "ES / Madrid";
    my_lf->srcgeoip = "ES / Madrid";
    ret = different_loop(rule, lf, my_lf);
    assert_false(ret);

    /* Different srcgeoip strings should return true */
    my_lf->srcgeoip = "ARG / Cordoba";
    ret = different_loop(rule, lf, my_lf);
    assert_true(ret);

    /* same_loop should not return false */
    ret = same_loop(rule, lf, my_lf);
    assert_true(ret);

    os_free(rule);
    os_free(lf);
    os_free(my_lf);
}

void test_different_dstgeoip(void **state)
{
    (void) state;
    bool ret;
    RuleInfo *rule = state[0];
    Eventinfo *lf = state[1];
    Eventinfo *my_lf = state[2];
    u_int32_t a = 1;

    rule->different_field = a << 15;

    /* Same dstgeoip strings should return false */
    lf->dstgeoip = "ES / Madrid";
    my_lf->dstgeoip = "ES / Madrid";
    ret = different_loop(rule, lf, my_lf);
    assert_false(ret);

    /* Different dstgeoip strings should return true */
    my_lf->dstgeoip = "ARG / Cordoba";
    ret = different_loop(rule, lf, my_lf);
    assert_true(ret);

    /* same_loop should not return false */
    ret = same_loop(rule, lf, my_lf);
    assert_true(ret);

    os_free(rule);
    os_free(lf);
    os_free(my_lf);
}

void test_different_location(void **state)
{
    (void) state;
    bool ret;
    RuleInfo *rule = state[0];
    Eventinfo *lf = state[1];
    Eventinfo *my_lf = state[2];
    u_int32_t a = 1;

    rule->different_field = a << 16;

    /* Same location strings should return false */
    lf->location = "/var/ossec/logs/field1";
    my_lf->location = "/var/ossec/logs/field1";
    ret = different_loop(rule, lf, my_lf);
    assert_false(ret);

    /* Different location strings should return true */
    my_lf->location = "/var/ossec/logs/field2";
    ret = different_loop(rule, lf, my_lf);
    assert_true(ret);

    /* same_loop should not return false */
    ret = same_loop(rule, lf, my_lf);
    assert_true(ret);

    os_free(rule);
    os_free(lf);
    os_free(my_lf);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        /* Tests for same loop function */
        cmocka_unit_test_setup(test_same_dstip, testSetup),
        cmocka_unit_test_setup(test_same_srcport, testSetup),
        cmocka_unit_test_setup(test_same_dstport, testSetup),
        cmocka_unit_test_setup(test_same_srcuser, testSetup),
        cmocka_unit_test_setup(test_same_user, testSetup),
        cmocka_unit_test_setup(test_same_protocol, testSetup),
        cmocka_unit_test_setup(test_same_action, testSetup),
        cmocka_unit_test_setup(test_same_url, testSetup),
        cmocka_unit_test_setup(test_same_data, testSetup),
        cmocka_unit_test_setup(test_same_extradata, testSetup),
        cmocka_unit_test_setup(test_same_status, testSetup),
        cmocka_unit_test_setup(test_same_systemname, testSetup),
        cmocka_unit_test_setup(test_same_srcgeoip, testSetup),
        cmocka_unit_test_setup(test_same_dstgeoip, testSetup),
        cmocka_unit_test_setup(test_same_location, testSetup),

        /* Tests for different loop function */
        cmocka_unit_test_setup(test_different_srcip, testSetup),
        cmocka_unit_test_setup(test_different_id, testSetup),
        cmocka_unit_test_setup(test_different_dstip, testSetup),
        cmocka_unit_test_setup(test_different_srcport, testSetup),
        cmocka_unit_test_setup(test_different_dstport, testSetup),
        cmocka_unit_test_setup(test_different_srcuser, testSetup),
        cmocka_unit_test_setup(test_different_user, testSetup),
        cmocka_unit_test_setup(test_different_protocol, testSetup),
        cmocka_unit_test_setup(test_different_action, testSetup),
        cmocka_unit_test_setup(test_different_url, testSetup),
        cmocka_unit_test_setup(test_different_data, testSetup),
        cmocka_unit_test_setup(test_different_extradata, testSetup),
        cmocka_unit_test_setup(test_different_status, testSetup),
        cmocka_unit_test_setup(test_different_systemname, testSetup),
        cmocka_unit_test_setup(test_different_srcgeoip, testSetup),
        cmocka_unit_test_setup(test_different_dstgeoip, testSetup),
        cmocka_unit_test_setup(test_different_location, testSetup)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
