/*
 * Copyright (C) 2015-2021, Wazuh Inc.
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

#include "../../data_provider/include/sysInfo.h"
#include "../wrappers/wazuh/shared/sym_load_wrappers.h"
#include "../../headers/shared.h"
#include "../../headers/sysinfo_utils.h"
#include "../wrappers/common.h"

/* setup/teardown */

static int group_setup(void ** state) {
    test_mode = 1;
    return 0;
}

static int group_teardown(void ** state) {
    test_mode = 0;
    return 0;
}

/* wraps */

/* w_sysinfo_deinit */

void test_w_sysinfo_deinit_NULL(void ** state) {

    w_sysinfo_helpers_t * sysinfo = NULL; 

    bool ret = w_sysinfo_deinit(sysinfo);

    assert_false(ret);
    assert_null(sysinfo);
}

void test_w_sysinfo_deinit_OK(void ** state) {

    w_sysinfo_helpers_t sysinfo;
    
    expect_value(__wrap_so_free_library, handle, sysinfo.module);
    will_return(__wrap_so_free_library, true);

    bool ret = w_sysinfo_deinit(&sysinfo);

    assert_true(ret);
    assert_null(sysinfo.module);
    assert_null(sysinfo.processes);
    assert_null(sysinfo.os);
    assert_null(sysinfo.free_result);
}

/* w_sysinfo_init */

void test_w_sysinfo_init_sysinfo_NULL(void ** state) {

    w_sysinfo_helpers_t * sysinfo = NULL;

    bool ret = w_sysinfo_init(sysinfo);

    assert_false(ret);
    assert_null(sysinfo);
}

void test_w_sysinfo_init_sysinfo_module_NULL(void ** state) {

    w_sysinfo_helpers_t sysinfo;
    
    expect_string(__wrap_so_get_module_handle, so, "sysinfo");
    will_return(__wrap_so_get_module_handle, NULL);

    bool ret = w_sysinfo_init(&sysinfo);

    assert_false(ret);
}

void test_w_sysinfo_init_sysinfo_processes_NULL(void ** state) {

    w_sysinfo_helpers_t sysinfo;

    expect_string(__wrap_so_get_module_handle, so, "sysinfo");
    will_return(__wrap_so_get_module_handle, 123);
    expect_value(__wrap_so_get_function_sym, handle, 123);
    expect_string(__wrap_so_get_function_sym, function_name, "sysinfo_processes");
    will_return(__wrap_so_get_function_sym, NULL);
    expect_value(__wrap_so_get_function_sym, handle, 123);
    expect_string(__wrap_so_get_function_sym, function_name, "sysinfo_os");
    will_return(__wrap_so_get_function_sym, 1);
    expect_value(__wrap_so_get_function_sym, handle, 123);
    expect_string(__wrap_so_get_function_sym, function_name, "sysinfo_free_result");
    will_return(__wrap_so_get_function_sym, 1);
    expect_value(__wrap_so_free_library, handle, 123);
    will_return(__wrap_so_free_library, true);

    bool ret = w_sysinfo_init(&sysinfo);

    assert_null(sysinfo.module);
    assert_null(sysinfo.processes);
    assert_null(sysinfo.os);
    assert_null(sysinfo.free_result);
    assert_false(ret);
}

void test_w_sysinfo_init_sysinfo_os_NULL(void ** state) {

    w_sysinfo_helpers_t sysinfo;

    expect_string(__wrap_so_get_module_handle, so, "sysinfo");
    will_return(__wrap_so_get_module_handle, 123);
    expect_value(__wrap_so_get_function_sym, handle, 123);
    expect_string(__wrap_so_get_function_sym, function_name, "sysinfo_processes");
    will_return(__wrap_so_get_function_sym, 1);
    expect_value(__wrap_so_get_function_sym, handle, 123);
    expect_string(__wrap_so_get_function_sym, function_name, "sysinfo_os");
    will_return(__wrap_so_get_function_sym, NULL);
    expect_value(__wrap_so_get_function_sym, handle, 123);
    expect_string(__wrap_so_get_function_sym, function_name, "sysinfo_free_result");
    will_return(__wrap_so_get_function_sym, 1);
    expect_value(__wrap_so_free_library, handle, 123);
    will_return(__wrap_so_free_library, true);

    bool ret = w_sysinfo_init(&sysinfo);

    assert_null(sysinfo.module);
    assert_null(sysinfo.processes);
    assert_null(sysinfo.os);
    assert_null(sysinfo.free_result);
    assert_false(ret);
}

void test_w_sysinfo_init_sysinfo_free_result_NULL(void ** state) {
    w_sysinfo_helpers_t sysinfo;

    expect_string(__wrap_so_get_module_handle, so, "sysinfo");
    will_return(__wrap_so_get_module_handle, 123);
    expect_value(__wrap_so_get_function_sym, handle, 123);
    expect_string(__wrap_so_get_function_sym, function_name, "sysinfo_processes");
    will_return(__wrap_so_get_function_sym, 1);
    expect_value(__wrap_so_get_function_sym, handle, 123);
    expect_string(__wrap_so_get_function_sym, function_name, "sysinfo_os");
    will_return(__wrap_so_get_function_sym, 1);
    expect_value(__wrap_so_get_function_sym, handle, 123);
    expect_string(__wrap_so_get_function_sym, function_name, "sysinfo_free_result");
    will_return(__wrap_so_get_function_sym, NULL);
    expect_value(__wrap_so_free_library, handle, 123);
    will_return(__wrap_so_free_library, true);

    bool ret = w_sysinfo_init(&sysinfo);

    assert_null(sysinfo.module);
    assert_null(sysinfo.processes);
    assert_null(sysinfo.os);
    assert_null(sysinfo.free_result);
    assert_false(ret);
}

void test_w_sysinfo_init_sysinfo_OK(void ** state) {

    w_sysinfo_helpers_t sysinfo;

    expect_string(__wrap_so_get_module_handle, so, "sysinfo");
    will_return(__wrap_so_get_module_handle, 123);
    expect_value(__wrap_so_get_function_sym, handle, 123);
    expect_string(__wrap_so_get_function_sym, function_name, "sysinfo_processes");
    will_return(__wrap_so_get_function_sym, 1);
    expect_value(__wrap_so_get_function_sym, handle, 123);
    expect_string(__wrap_so_get_function_sym, function_name, "sysinfo_os");
    will_return(__wrap_so_get_function_sym, 2);
    expect_value(__wrap_so_get_function_sym, handle, 123);
    expect_string(__wrap_so_get_function_sym, function_name, "sysinfo_free_result");
    will_return(__wrap_so_get_function_sym, 3);

    bool ret = w_sysinfo_init(&sysinfo);

    assert_ptr_equal(sysinfo.module, 123);
    assert_ptr_equal(sysinfo.processes, 1);
    assert_ptr_equal(sysinfo.os, 2);
    assert_ptr_equal(sysinfo.free_result, 3);
    assert_true(ret);
}

/* w_sysinfo_get_processes */

void test_w_sysinfo_get_processes_sysinfo_NULL(void ** state) {

    w_sysinfo_helpers_t * sysinfo = NULL;

    cJSON * ret = w_sysinfo_get_processes(sysinfo);

    assert_null(ret);
}

void test_w_sysinfo_get_processes_processes_NULL(void ** state) {

    w_sysinfo_helpers_t sysinfo;
    sysinfo.processes = NULL;

    cJSON * ret = w_sysinfo_get_processes(&sysinfo);

    assert_null(ret);
}

void test_w_sysinfo_get_processes_OK(void ** state) {

    w_sysinfo_helpers_t sysinfo;
    sysinfo.processes = &sysinfo_processes;

    will_return(__wrap_sysinfo_processes, 123);
    will_return(__wrap_sysinfo_processes, 0);

    cJSON * ret = w_sysinfo_get_processes(&sysinfo);

    assert_ptr_equal(ret, 123);
}

/* w_sysinfo_get_os */


void test_w_sysinfo_get_os_sysinfo_NULL(void ** state) {

    w_sysinfo_helpers_t * sysinfo = NULL;

    cJSON * ret = w_sysinfo_get_os(sysinfo);

    assert_null(ret);
}

void test_w_sysinfo_get_os_os_NULL(void ** state) {

    w_sysinfo_helpers_t sysinfo;
    sysinfo.os = NULL;

    cJSON * ret = w_sysinfo_get_os(&sysinfo);

    assert_null(ret);
}

void test_w_sysinfo_get_os_OK(void ** state) {

    w_sysinfo_helpers_t sysinfo;
    sysinfo.os = &sysinfo_os;

    will_return(__wrap_sysinfo_os, 123);
    will_return(__wrap_sysinfo_os, 0);

    cJSON * ret = w_sysinfo_get_os(&sysinfo);

    assert_ptr_equal(ret, 123);
}

/* w_get_process_childs */

void test_w_get_process_childs_sysinfo_NULL(void ** state) {

}

void test_w_get_process_childs_empty_processes_list(void ** state) {

}

void test_w_get_process_childs_ppid_object_not_found(void ** state) {

}

void test_w_get_process_childs_ppid_not_valid_object_type(void ** state) {

}

void test_w_get_process_childs_ppid_dont_match(void ** state) {

}

void test_w_get_process_childs_pid_object_not_found(void ** state) {

}

void test_w_get_process_childs_pid_not_a_number(void ** state) {

}

void test_w_get_process_childs_new_childs_chunk(void ** state) {

}

void test_w_get_process_childs_already_allocated_childs_chunk(void ** state) {

}

void test_w_get_process_childs_no_childs_found(void ** state) {

}

void test_w_get_process_childs_more_childs_than_allowed(void ** state) {

}

/* w_get_os_codename */

void test_w_get_os_codename_sysinfo_error(void ** state) {
    
    w_sysinfo_helpers_t * sysinfo = NULL;

    char * ret = w_get_os_codename(sysinfo);

    assert_ptr_equal(ret, NULL);
}

void test_w_get_os_codename_no_codename_object(void ** state) {
    w_sysinfo_helpers_t sysinfo;
    sysinfo.os = &sysinfo_os;
    sysinfo.free_result = &sysinfo_free_result;

    will_return(__wrap_sysinfo_os, 123);
    will_return(__wrap_sysinfo_os, 0);
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetStringValue, NULL);
    will_return(__wrap_sysinfo_free_result, NULL);

    char * ret = w_get_os_codename(&sysinfo);

    assert_ptr_equal(ret, NULL);
    os_free(ret);
}

void test_w_get_os_codename_OK(void ** state) {
    w_sysinfo_helpers_t sysinfo;
    sysinfo.os = &sysinfo_os;
    sysinfo.free_result = &sysinfo_free_result;

    will_return(__wrap_sysinfo_os, 123);
    will_return(__wrap_sysinfo_os, 0);
    will_return(__wrap_cJSON_GetObjectItem, 123);
    will_return(__wrap_cJSON_GetStringValue, "test");
    will_return(__wrap_sysinfo_free_result, NULL);

    char * ret = w_get_os_codename(&sysinfo);

    assert_string_equal(ret, "test");
    os_free(ret);
}


int main(void) {

    const struct CMUnitTest tests[] = {
        // Tees w_sysinfo_deinit
        cmocka_unit_test(test_w_sysinfo_deinit_NULL),
        cmocka_unit_test(test_w_sysinfo_deinit_OK),
        // Tees w_sysinfo_init
        cmocka_unit_test(test_w_sysinfo_init_sysinfo_NULL),
        cmocka_unit_test(test_w_sysinfo_init_sysinfo_module_NULL),
        cmocka_unit_test(test_w_sysinfo_init_sysinfo_processes_NULL),
        cmocka_unit_test(test_w_sysinfo_init_sysinfo_os_NULL),
        cmocka_unit_test(test_w_sysinfo_init_sysinfo_free_result_NULL),
        cmocka_unit_test(test_w_sysinfo_init_sysinfo_OK),
        // Test w_sysinfo_get_processes
        cmocka_unit_test(test_w_sysinfo_get_processes_sysinfo_NULL),
        cmocka_unit_test(test_w_sysinfo_get_processes_processes_NULL),
        cmocka_unit_test(test_w_sysinfo_get_processes_OK),
        // Test w_sysinfo_get_os
        cmocka_unit_test(test_w_sysinfo_get_os_sysinfo_NULL),
        cmocka_unit_test(test_w_sysinfo_get_os_os_NULL),
        cmocka_unit_test(test_w_sysinfo_get_os_OK),
        // Test w_get_process_childs
        cmocka_unit_test(test_w_get_process_childs_sysinfo_NULL),
        cmocka_unit_test(test_w_get_process_childs_empty_processes_list),
        cmocka_unit_test(test_w_get_process_childs_ppid_object_not_found),
        cmocka_unit_test(test_w_get_process_childs_ppid_not_valid_object_type),
        cmocka_unit_test(test_w_get_process_childs_ppid_dont_match),
        cmocka_unit_test(test_w_get_process_childs_pid_object_not_found),
        cmocka_unit_test(test_w_get_process_childs_pid_not_a_number),
        cmocka_unit_test(test_w_get_process_childs_new_childs_chunk),
        cmocka_unit_test(test_w_get_process_childs_already_allocated_childs_chunk),
        cmocka_unit_test(test_w_get_process_childs_no_childs_found),
        cmocka_unit_test(test_w_get_process_childs_more_childs_than_allowed),
        // Test w_get_os_codename
        cmocka_unit_test(test_w_get_os_codename_sysinfo_error),
        cmocka_unit_test(test_w_get_os_codename_no_codename_object),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
