
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

bool w_expression_add_osip(w_expression_t ** var, char * ip);


/* setup/teardown */

/* wraps */

/* tests */

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

int main(void)
{
    const struct CMUnitTest tests[] = {
        // Tests w_add_ip_to_array
        cmocka_unit_test(w_expression_add_osip_empty_ok),
        cmocka_unit_test(w_expression_add_osip_empty_fail),
        cmocka_unit_test(w_expression_add_osip_non_empty_ok),
        cmocka_unit_test(w_expression_add_osip_non_empty_fail),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}