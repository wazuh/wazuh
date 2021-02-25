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

#include "../../wrappers/common.h"
#include "syscheckd/syscheck.h"

#include "wrappers/externals/audit/libaudit_wrappers.h"
#include "wrappers/externals/procpc/readproc_wrappers.h"
#include "wrappers/libc/stdio_wrappers.h"
#include "wrappers/libc/stdlib_wrappers.h"
#include "wrappers/posix/unistd_wrappers.h"
#include "wrappers/wazuh/shared/audit_op_wrappers.h"
#include "wrappers/wazuh/shared/debug_op_wrappers.h"
#include "wrappers/wazuh/shared/file_op_wrappers.h"
#include "wrappers/wazuh/syscheckd/audit_parse_wrappers.h"


#define PERMS (AUDIT_PERM_WRITE | AUDIT_PERM_ATTR)


extern volatile int audit_health_check_creation;
extern volatile int hc_thread_active;
extern volatile int audit_thread_active;
int hc_success = 0;

/* setup/teardown */
static int setup_group(void **state) {
    (void) state;
    test_mode = 1;
    return 0;
}

static int teardown_group(void **state) {
    (void) state;
    memset(&syscheck, 0, sizeof(syscheck_config));
    Free_Syscheck(&syscheck);
    test_mode = 0;
    return 0;
}

static int setup_hc_success(void **state) {
    hc_success = 1;
    audit_health_check_creation = 1;
    return 0;
}

static int teardown_hc_success(void **state) {
    hc_success = 0;
    audit_health_check_creation = 0;

    return 0;
}

int __wrap_pthread_cond_init(pthread_cond_t *__cond, const pthread_condattr_t *__cond_attr) {
    function_called();
    return 0;
}

int __wrap_pthread_cond_wait(pthread_cond_t *__cond, pthread_mutex_t *__mutex) {
    function_called();

    hc_thread_active = 1;

    return 0;
}

int __wrap_pthread_mutex_lock (pthread_mutex_t *__mutex) {
    function_called();
    return 0;
}

int __wrap_pthread_mutex_unlock (pthread_mutex_t *__mutex) {
    function_called();
    return 0;
}

int __wrap_CreateThread(void * (*function_pointer)(void *), void *data) {
    if(hc_success) {
        audit_health_check_creation = 1;
    }
    return 1;
}

/* audit_health_check() tests */
void test_audit_health_check_fail_to_add_rule(void **state) {
    int ret;

    will_return(__wrap_audit_add_rule, -1);

    expect_string(__wrap__mdebug1, formatted_msg, FIM_AUDIT_HEALTHCHECK_RULE);

    ret = audit_health_check(123456);

    assert_int_equal(ret, -1);
    assert_int_equal(hc_thread_active, 0);
}

void test_audit_health_check_fail_to_create_hc_file(void **state) {
    int ret;

    hc_thread_active = 0;

    will_return(__wrap_audit_add_rule, -EEXIST);

    expect_string(__wrap__mdebug1, formatted_msg, FIM_AUDIT_HEALTHCHECK_START);

    expect_function_call(__wrap_pthread_cond_init);
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_cond_wait);
    expect_function_call(__wrap_pthread_mutex_unlock);

    expect_string_count(__wrap_fopen, path, "/var/ossec/tmp/audit_hc", 10);
    expect_string_count(__wrap_fopen, mode, "w", 10);
    will_return_count(__wrap_fopen, 0, 10);

    expect_string_count(__wrap__mdebug1, formatted_msg, FIM_AUDIT_HEALTHCHECK_FILE, 10);

    expect_value_count(__wrap_sleep, seconds, 1, 10);

    expect_string(__wrap__mdebug1, formatted_msg, FIM_HEALTHCHECK_CREATE_ERROR);

    expect_string(__wrap_unlink, file, "/var/ossec/tmp/audit_hc");
    will_return(__wrap_unlink, 0);

    expect_string(__wrap_audit_delete_rule, path, "/var/ossec/tmp");
    expect_value(__wrap_audit_delete_rule, perms, PERMS);
    expect_string(__wrap_audit_delete_rule, key, "wazuh_hc");
    will_return(__wrap_audit_delete_rule, 1);

    ret = audit_health_check(123456);

    assert_int_equal(ret, -1);
    assert_int_equal(hc_thread_active, 0);
}

void test_audit_health_check_no_creation_event_detected(void **state) {
    int ret;

    hc_thread_active = 0;

    will_return(__wrap_audit_add_rule, -EEXIST);

    expect_string(__wrap__mdebug1, formatted_msg, FIM_AUDIT_HEALTHCHECK_START);

    expect_function_call(__wrap_pthread_cond_init);
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_cond_wait);
    expect_function_call(__wrap_pthread_mutex_unlock);

    expect_string_count(__wrap_fopen, path, "/var/ossec/tmp/audit_hc", 10);
    expect_string_count(__wrap_fopen, mode, "w", 10);
    will_return_count(__wrap_fopen, 1, 10);

    expect_value_count(__wrap_fclose, _File, 1, 10);
    will_return_count(__wrap_fclose, 0, 10);

    expect_value_count(__wrap_sleep, seconds, 1, 10);

    expect_string(__wrap__mdebug1, formatted_msg, FIM_HEALTHCHECK_CREATE_ERROR);

    expect_string(__wrap_unlink, file, "/var/ossec/tmp/audit_hc");
    will_return(__wrap_unlink, 0);

    expect_string(__wrap_audit_delete_rule, path, "/var/ossec/tmp");
    expect_value(__wrap_audit_delete_rule, perms, PERMS);
    expect_string(__wrap_audit_delete_rule, key, "wazuh_hc");
    will_return(__wrap_audit_delete_rule, 1);

    ret = audit_health_check(123456);

    assert_int_equal(ret, -1);
    assert_int_equal(hc_thread_active, 0);
}

void test_audit_health_check_success(void **state) {
    int ret;

    hc_thread_active = 0;

    will_return(__wrap_audit_add_rule, 1);

    expect_string(__wrap__mdebug1, formatted_msg, FIM_AUDIT_HEALTHCHECK_START);

    expect_function_call(__wrap_pthread_cond_init);
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_cond_wait);
    expect_function_call(__wrap_pthread_mutex_unlock);

    expect_string(__wrap_fopen, path, "/var/ossec/tmp/audit_hc");
    expect_string(__wrap_fopen, mode, "w");
    will_return(__wrap_fopen, 1);

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 0);

    expect_value(__wrap_sleep, seconds, 1);

    expect_string(__wrap__mdebug1, formatted_msg, FIM_HEALTHCHECK_SUCCESS);

    expect_string(__wrap_unlink, file, "/var/ossec/tmp/audit_hc");
    will_return(__wrap_unlink, 0);

    expect_string(__wrap_audit_delete_rule, path, "/var/ossec/tmp");
    expect_value(__wrap_audit_delete_rule, perms, PERMS);
    expect_string(__wrap_audit_delete_rule, key, "wazuh_hc");
    will_return(__wrap_audit_delete_rule, 1);

    ret = audit_health_check(123456);

    assert_int_equal(ret, 0);
    assert_int_equal(hc_thread_active, 0);
}


int main(void) {
    const struct CMUnitTest tests[] = {
       cmocka_unit_test(test_audit_health_check_fail_to_add_rule),
        cmocka_unit_test(test_audit_health_check_fail_to_create_hc_file),
        cmocka_unit_test(test_audit_health_check_no_creation_event_detected),
        cmocka_unit_test_setup_teardown(test_audit_health_check_success, setup_hc_success, teardown_hc_success),
        };

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
