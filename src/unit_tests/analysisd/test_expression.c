
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
#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/os_regex/os_regex_wrappers.h"
#include "../wrappers/externals/pcre2/pcre2_wrappers.h"

void w_calloc_expression_t(w_expression_t ** var, w_exp_type_t type);
bool w_expression_add_osip(w_expression_t ** var, char * ip);
void w_free_expression_t(w_expression_t ** var);
bool w_expression_match(w_expression_t * expression, const char * str_test, const char ** end_match,
                        regex_matching * regex_match);
void w_expression_PCRE2_fill_regex_match(int captured_groups, const char * str_test, pcre2_match_data * match_data,
                                         regex_matching * regex_match);
const char * w_expression_get_regex_pattern(w_expression_t * expression);

/* setup/teardown */
    
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

void w_calloc_expression_t_pcre2(void ** state)
{
    w_expression_t * var = NULL;

    w_calloc_expression_t(&var, EXP_TYPE_PCRE2);

    assert_non_null(var);
    assert_int_equal(var->exp_type, EXP_TYPE_PCRE2);

    os_free(var->pcre2);
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
    os_strdup("test", var->match->raw);

    w_free_expression_t(&var);
}

void w_free_expression_t_osregex(void ** state)
{
    w_expression_t * var = NULL;

    os_calloc(1, sizeof(w_expression_t), var);
    var->exp_type = EXP_TYPE_OSREGEX;

    os_calloc(1, sizeof(OSRegex), var->regex);
    os_strdup("test", var->regex->raw);

    w_free_expression_t(&var);
}

void w_free_expression_t_string(void ** state)
{
    w_expression_t * var = NULL;

    os_calloc(1, sizeof(w_expression_t), var);
    var->exp_type = EXP_TYPE_STRING;

    os_strdup("test", var->string);

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

void w_free_expression_t_exp_type_pcre2(void ** state)
{
    w_expression_t * var = NULL;

    os_calloc(1, sizeof(w_expression_t), var);
    var->exp_type = EXP_TYPE_PCRE2;
    os_calloc(1, sizeof(w_pcre2_code_t), var->pcre2);

    int errornumber = 0;
    PCRE2_SIZE erroroffset = 0;
    char* pattern = NULL;
    os_strdup("test", pattern);

    var->pcre2->code = pcre2_compile((PCRE2_SPTR) pattern, PCRE2_ZERO_TERMINATED,
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

// w_expression_compile

void w_expression_compile_osregex_fail(void ** state)
{
    test_mode = 1;

    w_expression_t * expression = NULL;
    os_calloc(1, sizeof(w_expression_t), expression);
    expression->exp_type = EXP_TYPE_OSREGEX;

    char * pattern = NULL;
    os_strdup("test", pattern);

    int flags = 0;

    expect_string(__wrap_OSRegex_Compile, pattern,"test");
    will_return(__wrap_OSRegex_Compile, 0);

    bool ret = w_expression_compile(expression, pattern, flags);
    assert_false(ret);

    os_free(pattern);
    os_free(expression);
}

void w_expression_compile_osregex(void ** state)
{
    test_mode = 1;

    w_expression_t * expression = NULL;
    os_calloc(1, sizeof(w_expression_t), expression);
    expression->exp_type = EXP_TYPE_OSREGEX;

    char * pattern = NULL;
    os_strdup("test", pattern);

    int flags = 0;

    expect_string(__wrap_OSRegex_Compile, pattern,"test");
    will_return(__wrap_OSRegex_Compile, 1);

    bool ret = w_expression_compile(expression, pattern, flags);
    assert_true(ret);

    os_free(pattern);
    os_free(expression);
}

void w_expression_compile_osmatch_fail(void ** state)
{
    test_mode = 1;

    w_expression_t * expression = NULL;
    os_calloc(1, sizeof(w_expression_t), expression);
    expression->exp_type = EXP_TYPE_OSMATCH;

    char * pattern = NULL;
    os_strdup("test", pattern);

    int flags = 0;

    expect_string(__wrap_OSMatch_Compile, pattern,"test");
    will_return(__wrap_OSMatch_Compile, 0);

    bool ret = w_expression_compile(expression, pattern, flags);
    assert_false(ret);

    os_free(pattern);
    os_free(expression);
}

void w_expression_compile_osmatch(void ** state)
{
    test_mode = 1;

    w_expression_t * expression = NULL;
    os_calloc(1, sizeof(w_expression_t), expression);
    expression->exp_type = EXP_TYPE_OSMATCH;

    char * pattern = NULL;
    os_strdup("test", pattern);

    int flags = 0;

    expect_string(__wrap_OSMatch_Compile, pattern,"test");
    will_return(__wrap_OSMatch_Compile, 1);

    bool ret = w_expression_compile(expression, pattern, flags);
    assert_true(ret);

    os_free(pattern);
    os_free(expression);
}

void w_expression_compile_pcre2(void ** state)
{
    test_mode = 1;

    w_expression_t * expression = NULL;
    os_calloc(1, sizeof(w_expression_t), expression);
    expression->exp_type = EXP_TYPE_PCRE2;

    os_calloc(1, sizeof(w_pcre2_code_t), expression->pcre2);

    char * pattern = NULL;
    os_strdup("test", pattern);

    int flags = 0;

    bool ret = w_expression_compile(expression, pattern, flags);
    assert_true(ret);

    os_free(pattern);
    os_free(expression->pcre2->code);
    os_free(expression->pcre2->raw_pattern);
    os_free(expression->pcre2);
    os_free(expression);
}

void w_expression_compile_string(void ** state)
{
    test_mode = 1;

    w_expression_t * expression = NULL;
    os_calloc(1, sizeof(w_expression_t), expression);
    expression->exp_type = EXP_TYPE_STRING;

    char * pattern = NULL;
    os_strdup("test", pattern);

    int flags = 0;

    bool ret = w_expression_compile(expression, pattern, flags);
    assert_true(ret);

    os_free(pattern);
    os_free(expression->string);
    os_free(expression);
}

void w_expression_compile_osip_array(void ** state)
{
    test_mode = 1;

    w_expression_t * expression = NULL;
    os_calloc(1, sizeof(w_expression_t), expression);
    expression->exp_type = EXP_TYPE_OSIP_ARRAY;

    char * pattern = NULL;
    os_strdup("test", pattern);

    int flags = 0;

    bool ret = w_expression_compile(expression, pattern, flags);
    assert_true(ret);

    os_free(pattern);
    os_free(expression);
}

void w_expression_compile_default(void ** state)
{
    test_mode = 1;

    w_expression_t * expression = NULL;
    os_calloc(1, sizeof(w_expression_t), expression);
    expression->exp_type = 55;

    char * pattern = NULL;
    os_strdup("test", pattern);

    int flags = 0;

    bool ret = w_expression_compile(expression, pattern, flags);
    assert_true(ret);

    os_free(pattern);
    os_free(expression);
}

// w_expression_match

void w_expression_match_NULL(void ** state)
{
    w_expression_t * expression = NULL;
    char * str_test = NULL;

    const char* end_match = "test_end_match";

    bool ret = w_expression_match(expression, str_test, &end_match, NULL);
    assert_false(ret);
}

void w_expression_match_osmatch(void ** state)
{
    test_mode = 1;

    w_expression_t * expression = NULL;
    os_calloc(1, sizeof(w_expression_t), expression);
    expression->exp_type = EXP_TYPE_OSMATCH;

    const char* end_match = "test_end_match";

    char * str_test = NULL;
    os_strdup("test", str_test);

    expect_string(__wrap_OSMatch_Execute, str,"test");
    will_return(__wrap_OSMatch_Execute, 1);

    bool ret = w_expression_match(expression, str_test, &end_match, NULL);
    assert_true(ret);

    os_free(str_test);
    os_free(expression);
}

void w_expression_match_osregex(void ** state)
{
    test_mode = 1;

    w_expression_t * expression = NULL;
    os_calloc(1, sizeof(w_expression_t), expression);
    expression->exp_type = EXP_TYPE_OSREGEX;

    const char* end_match = "test_end_match";

    char * str_test = NULL;
    os_strdup("test", str_test);

    expect_string(__wrap_OSRegex_Execute_ex, str,"test");
    will_return(__wrap_OSRegex_Execute_ex, "test_osregex");

    bool ret = w_expression_match(expression, str_test, &end_match, NULL);
    assert_true(ret);

    os_free(str_test);
    os_free(expression);
}

void w_expression_match_pcre2_match_data_NULL(void ** state)
{
    w_expression_t * expression = NULL;
    os_calloc(1, sizeof(w_expression_t), expression);
    expression->exp_type = EXP_TYPE_PCRE2;

    const char* end_match = "test_end_match";

    os_calloc(1, sizeof(w_pcre2_code_t), expression->pcre2);

    int errornumber = 0;
    PCRE2_SIZE erroroffset = 0;
    char* pattern = NULL;
    os_strdup("test", pattern);

    expression->pcre2->code = pcre2_compile((PCRE2_SPTR) pattern, PCRE2_ZERO_TERMINATED,
                                               0, &errornumber, &erroroffset, NULL);

    char * str_test = NULL;
    os_strdup("test", str_test);

    will_return(wrap_pcre2_match_data_create_from_pattern, NULL);

    bool ret = w_expression_match(expression, str_test, &end_match, NULL);
    assert_false(ret);

    os_free(str_test);
    os_free(pattern);
    w_free_expression_t(&expression);
}

void w_expression_match_pcre2_match_no_captured_groups(void ** state)
{
    w_expression_t * expression = NULL;
    os_calloc(1, sizeof(w_expression_t), expression);
    expression->exp_type = EXP_TYPE_PCRE2;

    const char* end_match = "test_end_match";

    os_calloc(1, sizeof(w_pcre2_code_t), expression->pcre2);

    int errornumber = 0;
    PCRE2_SIZE erroroffset = 0;
    char* pattern = NULL;
    os_strdup("test", pattern);

    expression->pcre2->code = pcre2_compile((PCRE2_SPTR) pattern, PCRE2_ZERO_TERMINATED,
                                               0, &errornumber, &erroroffset, NULL);

    char * str_test = NULL;
    os_strdup("test", str_test);

    will_return(wrap_pcre2_match_data_create_from_pattern, 1);
    will_return(wrap_pcre2_match, 0);

    bool ret = w_expression_match(expression, str_test, &end_match, NULL);
    assert_false(ret);

    os_free(str_test);
    os_free(pattern);
    w_free_expression_t(&expression);
}

void w_expression_match_pcre2_match_captured_groups(void ** state)
{
    w_expression_t * expression = NULL;
    os_calloc(1, sizeof(w_expression_t), expression);
    expression->exp_type = EXP_TYPE_PCRE2;

    const char* end_match = "test_end_match";

    os_calloc(1, sizeof(w_pcre2_code_t), expression->pcre2);

    int errornumber = 0;
    PCRE2_SIZE erroroffset = 0;
    char* pattern = NULL;
    os_strdup("test", pattern);

    expression->pcre2->code = pcre2_compile((PCRE2_SPTR) pattern, PCRE2_ZERO_TERMINATED,
                                               0, &errornumber, &erroroffset, NULL);

    char * str_test = NULL;
    os_strdup("test", str_test);

    char * aux[2];
    aux[0] = str_test;
    aux[1] = str_test+1;

    will_return(wrap_pcre2_match_data_create_from_pattern, 1);
    will_return(wrap_pcre2_match, 1);
    will_return(wrap_pcre2_get_ovector_pointer, aux);

    bool ret = w_expression_match(expression, str_test, &end_match, NULL);
    assert_true(ret);

    os_free(str_test);
    os_free(pattern);
    w_free_expression_t(&expression);
}

void w_expression_match_pcre2_match_regex_matching(void ** state)
{
    w_expression_t * expression = NULL;
    os_calloc(1, sizeof(w_expression_t), expression);
    expression->exp_type = EXP_TYPE_PCRE2;

    const char* end_match = "test_end_match";

    os_calloc(1, sizeof(w_pcre2_code_t), expression->pcre2);

    int errornumber = 0;
    PCRE2_SIZE erroroffset = 0;
    char* pattern = NULL;
    os_strdup("test", pattern);

    expression->pcre2->code = pcre2_compile((PCRE2_SPTR) pattern, PCRE2_ZERO_TERMINATED,
                                               0, &errornumber, &erroroffset, NULL);

    char * str_test = NULL;
    os_strdup("test", str_test);

    char * aux[2]   ;
    aux[0] = str_test;
    aux[1] = str_test+1;

    regex_matching * regex_match;
    os_calloc(1, sizeof(regex_matching), regex_match);

    will_return(wrap_pcre2_match_data_create_from_pattern, 1);
    will_return(wrap_pcre2_match, 1);
    will_return(wrap_pcre2_get_ovector_pointer, aux);

    bool ret = w_expression_match(expression, str_test, &end_match, regex_match);
    assert_true(ret);

    os_free(str_test);
    os_free(pattern);
    os_free(regex_match);
    w_free_expression_t(&expression);
}

void w_expression_match_string(void ** state)
{
    w_expression_t * expression = NULL;
    os_calloc(1, sizeof(w_expression_t), expression);
    expression->exp_type = EXP_TYPE_STRING;

    os_calloc(1, sizeof(char), expression->string);

    const char* end_match = "test_end_match";

    char * str_test = NULL;
    os_strdup("test", str_test);

    bool ret = w_expression_match(expression, str_test, &end_match, NULL);
    assert_false(ret);

    os_free(str_test);
    os_free(expression->string);
    os_free(expression);
}

void w_expression_match_osip_array(void ** state)
{
    w_expression_t * expression = NULL;
    os_calloc(1, sizeof(w_expression_t), expression);
    expression->exp_type = EXP_TYPE_OSIP_ARRAY;

    os_calloc(1, sizeof(os_ip*), expression->ips);

    const char* end_match = "test_end_match";

    char * str_test = NULL;
    os_strdup("test", str_test);

    bool ret = w_expression_match(expression, str_test, &end_match, NULL);
    assert_false(ret);

    os_free(str_test);
    os_free(expression->ips);
    os_free(expression);
}

/*
        case EXP_TYPE_STRING:
            retval = (strcmp(expression->string, str_test) != 0) ? false : true;
            break;

        case EXP_TYPE_OSIP_ARRAY:
            retval = OS_IPFoundList(str_test, expression->ips) ? true: false;
            break;
*/

void w_expression_match_default(void ** state)
{
    w_expression_t * expression = NULL;
    os_calloc(1, sizeof(w_expression_t), expression);
    expression->exp_type = 55;

    const char* end_match = "test_end_match";

    char * str_test = NULL;
    os_strdup("test", str_test);

    bool ret = w_expression_match(expression, str_test, &end_match, NULL);
    assert_false(ret);

    os_free(str_test);
    os_free(expression);
}

void w_expression_match_end_match_NULL(void ** state)
{
    w_expression_t * expression = NULL;
    os_calloc(1, sizeof(w_expression_t), expression);
    expression->exp_type = EXP_TYPE_PCRE2;

    os_calloc(1, sizeof(w_pcre2_code_t), expression->pcre2);

    int errornumber = 0;
    PCRE2_SIZE erroroffset = 0;
    char* pattern = NULL;
    os_strdup("test", pattern);

    expression->pcre2->code = pcre2_compile((PCRE2_SPTR) pattern, PCRE2_ZERO_TERMINATED,
                                               0, &errornumber, &erroroffset, NULL);

    char * str_test = NULL;
    os_strdup("test", str_test);

    char * aux[2];
    aux[0] = str_test;
    aux[1] = str_test+1;

    regex_matching * regex_match;
    os_calloc(1, sizeof(regex_matching), regex_match);

    will_return(wrap_pcre2_match_data_create_from_pattern, 1);
    will_return(wrap_pcre2_match, 1);
    will_return(wrap_pcre2_get_ovector_pointer, aux);

    bool ret = w_expression_match(expression, str_test, NULL, regex_match);
    assert_true(ret);

    os_free(str_test);
    os_free(pattern);
    os_free(regex_match);
    w_free_expression_t(&expression);
}

// w_expression_PCRE2_fill_regex_match

void w_expression_PCRE2_fill_regex_match_no_capture_groups(void ** state)
{
    int captured_groups = 0;

    const char * str_test = "test";

    pcre2_match_data * match_data = (pcre2_match_data*)1;

    regex_matching * regex_match;
    os_calloc(1, sizeof(regex_matching), regex_match);

    w_expression_PCRE2_fill_regex_match(captured_groups, str_test, match_data, regex_match);

    os_free(regex_match);
}

void w_expression_PCRE2_fill_regex_match_str_test_NULL(void ** state)
{
    int captured_groups = 2;

    const char * str_test = NULL;

    pcre2_match_data * match_data = (pcre2_match_data*)1;

    regex_matching * regex_match;
    os_calloc(1, sizeof(regex_matching), regex_match);

    w_expression_PCRE2_fill_regex_match(captured_groups, str_test, match_data, regex_match);

    os_free(regex_match);
}

void w_expression_PCRE2_fill_regex_match_match_data_NULL(void ** state)
{
    int captured_groups = 2;

    const char * str_test = "test";

    pcre2_match_data * match_data = NULL;

    regex_matching * regex_match;
    os_calloc(1, sizeof(regex_matching), regex_match);

    w_expression_PCRE2_fill_regex_match(captured_groups, str_test, match_data, regex_match);

    os_free(regex_match);
}

void w_expression_PCRE2_fill_regex_match_regex_match_NULL(void ** state)
{
    int captured_groups = 2;

    const char * str_test = "test";

    pcre2_match_data * match_data = (pcre2_match_data*)1;

    regex_matching * regex_match = NULL;

    w_expression_PCRE2_fill_regex_match(captured_groups, str_test, match_data, regex_match);

    os_free(regex_match);
}

void w_expression_PCRE2_fill_regex_match_done(void ** state)
{
    int captured_groups = 2;

    const char * str_test = "test";

    pcre2_match_data * match_data = (pcre2_match_data*)1;

    regex_matching * regex_match;
    os_calloc(1, sizeof(regex_matching), regex_match);

    char * str_aux = NULL;
    os_strdup("test_regex_match", str_aux);

    char * aux[4];
    aux[0] = (char*)0;
    aux[1] = (char*)1;
    aux[2] = (char*)2;
    aux[3] = (char*)3;

    will_return(wrap_pcre2_get_ovector_pointer, aux);

    w_expression_PCRE2_fill_regex_match(captured_groups, str_test, match_data, regex_match);

    os_free(str_aux);
    os_free(regex_match->sub_strings[0]);
    os_free(regex_match->sub_strings);
    os_free(regex_match);
}

// w_expression_get_regex_pattern

void w_expression_get_regex_pattern_expression_NULL(void ** state)
{
    w_expression_t * expression = NULL;

    w_expression_get_regex_pattern(expression);
}

void w_expression_get_regex_pattern_exp_type_osregex(void ** state)
{
    w_expression_t * expression = NULL;
    os_calloc(1, sizeof(w_expression_t), expression);
    expression->exp_type = EXP_TYPE_OSREGEX;

    os_calloc(1, sizeof(OSRegex), expression->regex);
    os_strdup("test", expression->regex->raw);

    const char* ret = w_expression_get_regex_pattern(expression);
    assert_string_equal(ret, "test");

    os_free(expression->regex->raw);
    os_free(expression->regex);
    os_free(expression);
}

void w_expression_get_regex_pattern_exp_type_osmatch(void ** state)
{
    w_expression_t * expression = NULL;
    os_calloc(1, sizeof(w_expression_t), expression);
    expression->exp_type = EXP_TYPE_OSMATCH;

    os_calloc(1, sizeof(OSMatch), expression->match);
    os_strdup("test", expression->match->raw);

    const char* ret = w_expression_get_regex_pattern(expression);
    assert_string_equal(ret, "test");

    os_free(expression->match->raw);
    os_free(expression->match);
    os_free(expression);
}

void w_expression_get_regex_pattern_exp_type_pcre2(void ** state)
{
    w_expression_t * expression = NULL;
    os_calloc(1, sizeof(w_expression_t), expression);
    expression->exp_type = EXP_TYPE_PCRE2;

    os_calloc(1, sizeof(OSMatch), expression->pcre2);
    os_strdup("test", expression->pcre2->raw_pattern);

    const char* ret = w_expression_get_regex_pattern(expression);
    assert_string_equal(ret, "test");

    os_free(expression->pcre2->raw_pattern);
    os_free(expression->pcre2);
    os_free(expression);
}

void w_expression_get_regex_pattern_exp_type_string(void ** state)
{
    w_expression_t * expression = NULL;
    os_calloc(1, sizeof(w_expression_t), expression);
    expression->exp_type = EXP_TYPE_STRING;

    os_strdup("test", expression->string);

    const char* ret = w_expression_get_regex_pattern(expression);
    assert_string_equal("test", ret);

    os_free(expression->string);
    os_free(expression);
}

void w_expression_get_regex_pattern_exp_type_osip_array(void ** state)
{
    w_expression_t * expression = NULL;
    os_calloc(1, sizeof(w_expression_t), expression);
    expression->exp_type = EXP_TYPE_OSIP_ARRAY;

    os_calloc(1, sizeof(OSRegex), expression->regex);
    os_strdup("test", expression->regex->raw);

    const char* ret = w_expression_get_regex_pattern(expression);
    assert_null(ret);

    os_free(expression->regex->raw);
    os_free(expression->regex);
    os_free(expression);
}

void w_expression_get_regex_pattern_exp_type_default(void ** state)
{
    w_expression_t * expression = NULL;
    os_calloc(1, sizeof(w_expression_t), expression);
    expression->exp_type = 55;

    os_calloc(1, sizeof(OSRegex), expression->regex);
    os_strdup("test", expression->regex->raw);

    const char* ret = w_expression_get_regex_pattern(expression);
    assert_null(ret);

    os_free(expression->regex->raw);
    os_free(expression->regex);
    os_free(expression);
}

// w_expression_get_regex_type

void w_expression_get_regex_type_expression_NULL(void ** state)
{
    w_expression_t * expression = NULL;

    w_expression_get_regex_type(expression);
}

void w_expression_get_regex_type_exp_type_osregex(void ** state)
{
    w_expression_t * expression = NULL;
    os_calloc(1, sizeof(w_expression_t), expression);
    expression->exp_type = EXP_TYPE_OSREGEX;

    os_calloc(1, sizeof(OSRegex), expression->regex);
    os_strdup("test", expression->regex->raw);

    const char* ret = w_expression_get_regex_type(expression);
    assert_string_equal(ret, "osregex");

    os_free(expression->regex->raw);
    os_free(expression->regex);
    os_free(expression);
}

void w_expression_get_regex_type_exp_type_osmatch(void ** state)
{
    w_expression_t * expression = NULL;
    os_calloc(1, sizeof(w_expression_t), expression);
    expression->exp_type = EXP_TYPE_OSMATCH;

    os_calloc(1, sizeof(OSMatch), expression->match);
    os_strdup("test", expression->match->raw);

    const char* ret = w_expression_get_regex_type(expression);
    assert_string_equal(ret, "osmatch");

    os_free(expression->match->raw);
    os_free(expression->match);
    os_free(expression);
}

void w_expression_get_regex_type_exp_type_pcre2(void ** state)
{
    w_expression_t * expression = NULL;
    os_calloc(1, sizeof(w_expression_t), expression);
    expression->exp_type = EXP_TYPE_PCRE2;

    os_calloc(1, sizeof(OSMatch), expression->pcre2);
    os_strdup("test", expression->pcre2->raw_pattern);

    const char* ret = w_expression_get_regex_type(expression);
    assert_string_equal(ret, "pcre2");

    os_free(expression->pcre2->raw_pattern);
    os_free(expression->pcre2);
    os_free(expression);
}

void w_expression_get_regex_type_exp_type_string(void ** state)
{
    w_expression_t * expression = NULL;
    os_calloc(1, sizeof(w_expression_t), expression);
    expression->exp_type = EXP_TYPE_STRING;

    os_strdup("test", expression->string);

    const char* ret = w_expression_get_regex_type(expression);
    assert_string_equal("string", ret);

    os_free(expression->string);
    os_free(expression);
}

void w_expression_get_regex_type_exp_type_osip_array(void ** state)
{
    w_expression_t * expression = NULL;
    os_calloc(1, sizeof(w_expression_t), expression);
    expression->exp_type = EXP_TYPE_OSIP_ARRAY;

    os_calloc(1, sizeof(OSRegex), expression->regex);
    os_strdup("test", expression->regex->raw);

    const char* ret = w_expression_get_regex_type(expression);
    assert_null(ret);

    os_free(expression->regex->raw);
    os_free(expression->regex);
    os_free(expression);
}

void w_expression_get_regex_type_exp_type_default(void ** state)
{
    w_expression_t * expression = NULL;
    os_calloc(1, sizeof(w_expression_t), expression);
    expression->exp_type = 55;

    os_calloc(1, sizeof(OSRegex), expression->regex);
    os_strdup("test", expression->regex->raw);

    const char* ret = w_expression_get_regex_type(expression);
    assert_null(ret);

    os_free(expression->regex->raw);
    os_free(expression->regex);
    os_free(expression);
}

int main(void)
{
    const struct CMUnitTest tests[] = {

        // Test w_calloc_expression_t
        cmocka_unit_test(w_calloc_expression_t_match),
        cmocka_unit_test(w_calloc_expression_t_regex),
        cmocka_unit_test(w_calloc_expression_t_string),
        cmocka_unit_test(w_calloc_expression_t_osip),
        cmocka_unit_test(w_calloc_expression_t_pcre2),

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
        cmocka_unit_test(w_free_expression_t_exp_type_pcre2),
        cmocka_unit_test(w_free_expression_t_default),

        //Test w_expression_compile
        cmocka_unit_test(w_expression_compile_osregex_fail),
        cmocka_unit_test(w_expression_compile_osregex),
        cmocka_unit_test(w_expression_compile_osmatch_fail),
        cmocka_unit_test(w_expression_compile_osmatch),
        cmocka_unit_test(w_expression_compile_pcre2),
        cmocka_unit_test(w_expression_compile_string),
        cmocka_unit_test(w_expression_compile_osip_array),
        cmocka_unit_test(w_expression_compile_default),

        //Test w_expression_match
        cmocka_unit_test(w_expression_match_NULL),
        cmocka_unit_test(w_expression_match_osmatch),
        cmocka_unit_test(w_expression_match_osregex),
        cmocka_unit_test(w_expression_match_pcre2_match_data_NULL),
        cmocka_unit_test(w_expression_match_pcre2_match_no_captured_groups),
        cmocka_unit_test(w_expression_match_pcre2_match_captured_groups),
        cmocka_unit_test(w_expression_match_pcre2_match_regex_matching),
        cmocka_unit_test(w_expression_match_string),
        cmocka_unit_test(w_expression_match_osip_array),
        cmocka_unit_test(w_expression_match_default),
        cmocka_unit_test(w_expression_match_end_match_NULL),

        //Test w_expression_PCRE2_fill_regex_match
        cmocka_unit_test(w_expression_PCRE2_fill_regex_match_no_capture_groups),
        cmocka_unit_test(w_expression_PCRE2_fill_regex_match_str_test_NULL),
        cmocka_unit_test(w_expression_PCRE2_fill_regex_match_match_data_NULL),
        cmocka_unit_test(w_expression_PCRE2_fill_regex_match_regex_match_NULL),
        cmocka_unit_test(w_expression_PCRE2_fill_regex_match_done),

        //Test w_expression_PCRE2_fill_regex_match
        cmocka_unit_test(w_expression_get_regex_pattern_expression_NULL),
        cmocka_unit_test(w_expression_get_regex_pattern_exp_type_osregex),
        cmocka_unit_test(w_expression_get_regex_pattern_exp_type_osmatch),
        cmocka_unit_test(w_expression_get_regex_pattern_exp_type_pcre2),
        cmocka_unit_test(w_expression_get_regex_pattern_exp_type_string),
        cmocka_unit_test(w_expression_get_regex_pattern_exp_type_osip_array),
        cmocka_unit_test(w_expression_get_regex_pattern_exp_type_default),

        //Test w_expression_get_regex_type
        cmocka_unit_test(w_expression_get_regex_type_expression_NULL),
        cmocka_unit_test(w_expression_get_regex_type_exp_type_osregex),
        cmocka_unit_test(w_expression_get_regex_type_exp_type_osmatch),
        cmocka_unit_test(w_expression_get_regex_type_exp_type_pcre2),
        cmocka_unit_test(w_expression_get_regex_type_exp_type_string),
        cmocka_unit_test(w_expression_get_regex_type_exp_type_osip_array),
        cmocka_unit_test(w_expression_get_regex_type_exp_type_default)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
