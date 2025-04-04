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

#include "../analysisd/rules.h"
#include "../analysisd/eventinfo.h"

/* setup */

static int testSetup(void **state) {
    RuleInfo * rule = calloc(1, sizeof(RuleInfo));
    Eventinfo * lf = calloc(1, sizeof(Eventinfo));
    Eventinfo * same_lf = calloc(1, sizeof(Eventinfo));
    Eventinfo * different_lf = calloc(1, sizeof(Eventinfo));

    if(!rule || !lf || !same_lf || !different_lf) {
        return -1;
    }

    lf->srcip = "100.200.40.20";
    lf->id = "001";
    lf->dstip = "100.200.50.30";
    lf->srcport = "30";
    lf->dstport = "40";
    lf->srcuser = "User";
    lf->dstuser = "User";
    lf->protocol = "TCP";
    lf->action = "install";
    lf->url = "url1.com";
    lf->data = "data1";
    lf->extra_data = "extra data1";
    lf->status = "started";
    lf->systemname = "centos";
    lf->srcgeoip = "ES / Madrid";
    lf->dstgeoip = "ES / Madrid";
    lf->location = "/var/ossec/logs/field1";

    same_lf->srcip = "100.200.40.20";
    same_lf->id = "001";
    same_lf->dstip = "100.200.50.30";
    same_lf->srcport = "30";
    same_lf->dstport = "40";
    same_lf->srcuser = "User";
    same_lf->dstuser = "User";
    same_lf->protocol = "TCP";
    same_lf->action = "install";
    same_lf->url = "url1.com";
    same_lf->data = "data1";
    same_lf->extra_data = "extra data1";
    same_lf->status = "started";
    same_lf->systemname = "centos";
    same_lf->srcgeoip = "ES / Madrid";
    same_lf->dstgeoip = "ES / Madrid";
    same_lf->location = "/var/ossec/logs/field1";

    different_lf->srcip = "100.37.58.104";
    different_lf->id = "002";
    different_lf->dstip = "100.200.50.3";
    different_lf->srcport = "3";
    different_lf->dstport = "4";
    different_lf->srcuser = "Admin";
    different_lf->dstuser = "Admin";
    different_lf->protocol = "UDP";
    different_lf->action = "remove";
    different_lf->url = "url2.com";
    different_lf->data = "data2";
    different_lf->extra_data = "extra data2";
    different_lf->status = "finished";
    different_lf->systemname = "Ubuntu";
    different_lf->srcgeoip = "ES / Granade";
    different_lf->dstgeoip = "ES / Granade";
    different_lf->location = "/var/ossec/logs/field2";

    state[0] = rule;
    state[1] = lf;
    state[2] = same_lf;
    state[3] = different_lf;

    return 0;
}

/* tests for same_loop and different_loop from eventinfo.c */

void test_same(void **state)
{
    (void) state;
    bool ret;
    RuleInfo *rule = state[0];
    Eventinfo *lf = state[1];
    Eventinfo *same_lf = state[2];
    Eventinfo *different_lf = state[3];
    u_int32_t a = 65536;

    while (a != 2) {
        rule->same_field = a;

        /* Same static field values should return true */
        ret = same_loop(rule, lf, same_lf);
        assert_true(ret);

        /* Different static field values should return false */
        ret = same_loop(rule, lf, different_lf);
        assert_false(ret);

        a >>= 1;
    }

    os_free(rule);
    os_free(lf);
    os_free(same_lf);
    os_free(different_lf);
}

void test_different(void **state)
{
    (void) state;
    bool ret;
    RuleInfo *rule = state[0];
    Eventinfo *lf = state[1];
    Eventinfo *same_lf = state[2];
    Eventinfo *different_lf = state[3];
    u_int32_t a = 65536;

    while (a != 0) {
        rule->different_field = a;

        /* Same static field values should return false */
        ret = different_loop(rule, lf, same_lf);
        assert_false(ret);

        /* Different static field values should return true */
        ret = same_loop(rule, lf, different_lf);
        assert_true(ret);

        a >>= 1;
    }

    os_free(rule);
    os_free(lf);
    os_free(same_lf);
    os_free(different_lf);
}


void test_static_out_of_bound(void **state)
{
    (void) state;
    bool ret;
    RuleInfo *rule = state[0];
    Eventinfo *lf = state[1];
    Eventinfo *same_lf = state[2];
    Eventinfo *different_lf = state[3];
    rule->different_field = 0b1 << N_FIELDS;

    ret = different_loop(rule, lf, same_lf);
    assert_true(ret); // Nothing to compare, return true

    ret = same_loop(rule, lf, different_lf);
    assert_true(ret);


    os_free(rule);
    os_free(lf);
    os_free(same_lf);
    os_free(different_lf);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        /* Tests for same loop function */
        cmocka_unit_test_setup(test_same, testSetup),
        cmocka_unit_test_setup(test_different, testSetup),
        cmocka_unit_test_setup(test_static_out_of_bound, testSetup),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
