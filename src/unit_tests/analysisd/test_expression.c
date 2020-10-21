
/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <setjmp.h>
#include <stdio.h>
#include <cmocka.h>

#include "../../analysisd/expression.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

void w_calloc_expression_t(w_expression_t ** var, w_exp_type_t type);
bool w_expression_add_osip(w_expression_t ** var, char * ip);
void w_free_expression_t(w_expression_t ** var);

/* setup/teardown */

/* wraps */

/* tests */

// w_calloc_expression_t

void w_calloc_expression_t_match(void ** state)
{
    w_expression_t * var = NULL;

    w_calloc_expression_t(&var, EXP_TYPE_OSMATCH);

    assert_non_null(var);
    assert_non_null(var->match);
    assert_int_equal(var->exp_type, EXP_TYPE_OSMATCH);

    os_free(var->match);
    os_free(var);
}

void w_calloc_expression_t_regex(void ** state)
{
    w_expression_t * var = NULL;

    w_calloc_expression_t(&var, EXP_TYPE_OSREGEX);

    assert_non_null(var);
    assert_non_null(var->regex);
    assert_int_equal(var->exp_type, EXP_TYPE_OSREGEX);

    os_free(var->regex);
    os_free(var);
}

void w_calloc_expression_t_string(void ** state)
{
    w_expression_t * var = NULL;

    w_calloc_expression_t(&var, EXP_TYPE_STRING);

    assert_non_null(var);
    assert_int_equal(var->exp_type, EXP_TYPE_STRING);

    os_free(var);
}

void w_calloc_expression_t_osip(void ** state)
{
    w_expression_t * var = NULL;

    w_calloc_expression_t(&var, EXP_TYPE_OSIP_ARRAY);

    assert_non_null(var);
    assert_int_equal(var->exp_type, EXP_TYPE_OSIP_ARRAY);

    os_free(var);
}

// w_expression_add_osip

void w_expression_add_osip_empty_ok(void ** state)
{
    w_expression_t * list_ips = NULL;
    bool retval;

    expect_any(__wrap_OS_IsValidIP, ip_address);
    expect_not_value(__wrap_OS_IsValidIP, final_ip, NULL);
    will_return(__wrap_OS_IsValidIP, 1);

    retval = w_expression_add_osip(&list_ips, NULL);

    assert_true(retval);
    assert_int_equal(list_ips->exp_type, EXP_TYPE_OSIP_ARRAY);
    assert_null(list_ips->ips[1]);
    assert_non_null(list_ips->ips[0]);

    os_free(list_ips->ips[0]);
    os_free(list_ips->ips) os_free(list_ips);
}

void w_expression_add_osip_empty_fail(void ** state)
{
    w_expression_t * list_ips = NULL;
    bool retval;

    expect_any(__wrap_OS_IsValidIP, ip_address);
    expect_not_value(__wrap_OS_IsValidIP, final_ip, NULL);
    will_return(__wrap_OS_IsValidIP, 0);

    retval = w_expression_add_osip(&list_ips, NULL);

    assert_false(retval);
    assert_null(list_ips);
}

void w_expression_add_osip_non_empty_ok(void ** state)
{
    w_expression_t * list_ips = NULL;
    bool retval;

    os_calloc(1, sizeof(w_expression_t), list_ips);
    list_ips->exp_type = EXP_TYPE_OSIP_ARRAY;

    os_calloc(2, sizeof(os_ip *), list_ips->ips);
    os_calloc(1, sizeof(os_ip), list_ips->ips[0]);

    expect_any(__wrap_OS_IsValidIP, ip_address);
    expect_not_value(__wrap_OS_IsValidIP, final_ip, NULL);
    will_return(__wrap_OS_IsValidIP, 1);

    retval = w_expression_add_osip(&list_ips, NULL);

    assert_true(retval);

    assert_int_equal(list_ips->exp_type, EXP_TYPE_OSIP_ARRAY);
    assert_null(list_ips->ips[2]);
    assert_non_null(list_ips->ips[1]);
    assert_non_null(list_ips->ips[0]);

    os_free(list_ips->ips[1]);
    os_free(list_ips->ips[0]);
    os_free(list_ips->ips) os_free(list_ips);
}

void w_expression_add_osip_non_empty_fail(void ** state)
{
    w_expression_t * list_ips = NULL;
    bool retval;

    os_calloc(1, sizeof(w_expression_t), list_ips);
    list_ips->exp_type = EXP_TYPE_OSIP_ARRAY;

    os_calloc(2, sizeof(os_ip *), list_ips->ips);
    os_calloc(1, sizeof(os_ip), list_ips->ips[0]);

    expect_any(__wrap_OS_IsValidIP, ip_address);
    expect_not_value(__wrap_OS_IsValidIP, final_ip, NULL);
    will_return(__wrap_OS_IsValidIP, 0);

    retval = w_expression_add_osip(&list_ips, NULL);

    assert_false(retval);
    assert_null(list_ips);
}

//w_free_expression_t

void w_free_expression_t_NULL(void ** state)
{
    w_expression_t * var = NULL;

    w_free_expression_t(&var);
}

void w_free_expression_t_osmatch(void ** state)
{
    w_expression_t * var = NULL;

    os_calloc(1, sizeof(w_expression_t), var);
    var->exp_type = EXP_TYPE_OSMATCH;

    os_calloc(1, sizeof(OSMatch), var->match);
    os_strdup("test",var->match->raw);

    w_free_expression_t(&var);
}

void w_free_expression_t_osregex(void ** state)
{
    w_expression_t * var = NULL;

    os_calloc(1, sizeof(w_expression_t), var);
    var->exp_type = EXP_TYPE_OSREGEX;

    os_calloc(1, sizeof(OSRegex), var->regex);
    os_strdup("test",var->regex->raw);

    w_free_expression_t(&var);
}

void w_free_expression_t_string(void ** state)
{
    w_expression_t * var = NULL;

    os_calloc(1, sizeof(w_expression_t), var);
    var->exp_type = EXP_TYPE_STRING;

    os_strdup("test",var->string);

    w_free_expression_t(&var);
}

void w_free_expression_t_exp_type_osip_array_NULL(void ** state)
{
    w_expression_t * var = NULL;

    os_calloc(1, sizeof(w_expression_t), var);
    var->exp_type = EXP_TYPE_OSIP_ARRAY;

    var->ips = NULL;

    w_free_expression_t(&var);
}

void w_free_expression_t_exp_type_osip_array(void ** state)
{
    w_expression_t * var = NULL;

    os_calloc(1, sizeof(w_expression_t), var);
    var->exp_type = EXP_TYPE_OSIP_ARRAY;

    os_calloc(2, sizeof(os_ip *), var->ips);
    os_calloc(1, sizeof(os_ip), var->ips[0]);
    os_strdup("test", var->ips[0]->ip);

    w_free_expression_t(&var);
}

void w_free_expression_t_exp_type_exp_type_pcre2(void ** state)
{
    w_expression_t * var = NULL;

    os_calloc(1, sizeof(w_expression_t), var);
    var->exp_type = EXP_TYPE_PCRE2;

    int errornumber = 0;
    PCRE2_SIZE erroroffset = 0;
    char* pattern = NULL;
    os_strdup("test", pattern);

    var->pcre2 = pcre2_compile((PCRE2_SPTR) pattern, PCRE2_ZERO_TERMINATED,
                                               0, &errornumber, &erroroffset, NULL);
    w_free_expression_t(&var);

    os_free(pattern);
}

void w_free_expression_t_default(void ** state)
{
    w_expression_t * var = NULL;

    os_calloc(1, sizeof(w_expression_t), var);
    var->exp_type = 55;

    w_free_expression_t(&var);
}

int main(void)
{
    const struct CMUnitTest tests[] = {

        // Test w_calloc_expression_t
        cmocka_unit_test(w_calloc_expression_t_match),
        cmocka_unit_test(w_calloc_expression_t_regex),
        cmocka_unit_test(w_calloc_expression_t_string),
        cmocka_unit_test(w_calloc_expression_t_osip),

        // Tests w_add_ip_to_array
        cmocka_unit_test(w_expression_add_osip_empty_ok),
        cmocka_unit_test(w_expression_add_osip_empty_fail),
        cmocka_unit_test(w_expression_add_osip_non_empty_ok),
        cmocka_unit_test(w_expression_add_osip_non_empty_fail),

        //Test w_free_expression_t
        cmocka_unit_test(w_free_expression_t_NULL),
        cmocka_unit_test(w_free_expression_t_osmatch),
        cmocka_unit_test(w_free_expression_t_osregex),
        cmocka_unit_test(w_free_expression_t_string),
        cmocka_unit_test(w_free_expression_t_exp_type_osip_array_NULL),
        cmocka_unit_test(w_free_expression_t_exp_type_osip_array),
        cmocka_unit_test(w_free_expression_t_exp_type_exp_type_pcre2),
        cmocka_unit_test(w_free_expression_t_default)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
