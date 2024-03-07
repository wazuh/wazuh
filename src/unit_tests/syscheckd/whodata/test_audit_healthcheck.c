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

#include "../../wrappers/common.h"
#include "../../../syscheckd/include/syscheck.h"

#include "wrappers/externals/audit/libaudit_wrappers.h"
#include "wrappers/externals/procpc/readproc_wrappers.h"
#include "wrappers/libc/stdio_wrappers.h"
#include "wrappers/libc/stdlib_wrappers.h"
#include "wrappers/posix/unistd_wrappers.h"
#include "wrappers/wazuh/shared/audit_op_wrappers.h"
#include "wrappers/wazuh/shared/debug_op_wrappers.h"
#include "wrappers/wazuh/shared/file_op_wrappers.h"
#include "wrappers/wazuh/shared/atomic_wrappers.h"
#include "wrappers/wazuh/shared/time_op_wrappers.h"
#include "wrappers/wazuh/shared/pthreads_op_wrappers.h"


#include "wrappers/wazuh/syscheckd/audit_parse_wrappers.h"


#define PERMS (AUDIT_PERM_WRITE | AUDIT_PERM_ATTR)


extern atomic_int_t audit_health_check_creation;
extern atomic_int_t hc_thread_active;
extern atomic_int_t audit_thread_active;
extern pthread_mutex_t audit_hc_mutex;
extern pthread_cond_t audit_hc_cond;

extern void __real_atomic_int_set(atomic_int_t *atomic, int value);
extern int __real_atomic_int_get(atomic_int_t *atomic);

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

int __wrap_pthread_cond_timedwait(pthread_cond_t *restrict cond, pthread_mutex_t *restrict mutex,
                                   const struct timespec *restrict abstime) {
    function_called();
    return 0;
}

/**
 * @brief Functions that prepares the wraps calls for starting the audit healthcheck thread
 */
void prepare_audit_healthcheck_thread() {
    will_return(__wrap_audit_add_rule, -EEXIST);

    expect_string(__wrap__mdebug1, formatted_msg, FIM_AUDIT_HEALTHCHECK_START);

    expect_function_call(__wrap_pthread_mutex_lock);

    expect_value(__wrap_atomic_int_get, atomic, &hc_thread_active);
    will_return(__wrap_atomic_int_get, 0);
    expect_value(__wrap_pthread_cond_wait, cond, &audit_hc_cond);
    expect_value(__wrap_pthread_cond_wait, mutex, &audit_hc_mutex);

    expect_value(__wrap_atomic_int_get, atomic, &hc_thread_active);
    will_return(__wrap_atomic_int_get, 1);
    expect_function_call(__wrap_pthread_mutex_unlock);
}


/**
 * @brief Functions that prepares the wraps calls for stopping the audit healthcheck thread
 */
void prepare_post_audit_healthcheck_thread() {
    expect_string(__wrap_unlink, file, AUDIT_HEALTHCHECK_FILE);
    will_return(__wrap_unlink, 0);

    expect_string(__wrap_audit_delete_rule, path, AUDIT_HEALTHCHECK_DIR);
    expect_value(__wrap_audit_delete_rule, perms, PERMS);
    expect_string(__wrap_audit_delete_rule, key, "wazuh_hc");
    will_return(__wrap_audit_delete_rule, 1);

    expect_value(__wrap_atomic_int_set, atomic, &hc_thread_active);
    will_return(__wrap_atomic_int_set, 0);

    expect_function_call(__wrap_pthread_mutex_lock);
    will_return(__wrap_gettime, 1232);
    expect_function_call(__wrap_pthread_cond_timedwait);
    expect_function_call(__wrap_pthread_mutex_unlock);
}

/* audit_health_check() tests */
void test_audit_health_check_fail_to_add_rule(void **state) {
    int ret;

    expect_abspath(AUDIT_HEALTHCHECK_DIR, 1);
    expect_abspath(AUDIT_HEALTHCHECK_FILE, 1);

    will_return(__wrap_audit_add_rule, -1);

    expect_string(__wrap__mdebug1, formatted_msg, FIM_AUDIT_HEALTHCHECK_RULE);

    ret = audit_health_check(123456);

    assert_int_equal(ret, -1);
    assert_int_equal(hc_thread_active.data, 0);
}

void test_audit_health_check_fail_to_create_hc_file(void **state) {
    int ret;
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    __real_atomic_int_set(&hc_thread_active, 1);

    expect_abspath(AUDIT_HEALTHCHECK_DIR, 1);
    expect_abspath(AUDIT_HEALTHCHECK_FILE, 1);

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    __real_atomic_int_set(&audit_health_check_creation, 0);

    prepare_audit_healthcheck_thread();

    expect_string_count(__wrap_wfopen, path, AUDIT_HEALTHCHECK_FILE, 10);
    expect_string_count(__wrap_wfopen, mode, "w", 10);
    will_return_count(__wrap_wfopen, 0, 10);

    expect_string_count(__wrap__mdebug1, formatted_msg, FIM_AUDIT_HEALTHCHECK_FILE, 10);

    expect_value_count(__wrap_sleep, seconds, 1, 10);
    expect_value_count(__wrap_atomic_int_get, atomic, &audit_health_check_creation, 10);
    will_return_count(__wrap_atomic_int_get, 0, 10);
    // outside do while
    expect_value(__wrap_atomic_int_get, atomic, &audit_health_check_creation);
    will_return(__wrap_atomic_int_get, 0);
    expect_string(__wrap__mdebug1, formatted_msg, FIM_HEALTHCHECK_CREATE_ERROR);

    prepare_post_audit_healthcheck_thread();

    ret = audit_health_check(123456);

    assert_int_equal(ret, -1);
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    assert_int_equal(__real_atomic_int_get(&hc_thread_active), 0);
}

void test_audit_health_check_no_creation_event_detected(void **state) {
    int ret;

    expect_abspath(AUDIT_HEALTHCHECK_DIR, 1);
    expect_abspath(AUDIT_HEALTHCHECK_FILE, 1);

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    __real_atomic_int_set(&hc_thread_active, 0);

    prepare_audit_healthcheck_thread();

    expect_string_count(__wrap_wfopen, path, AUDIT_HEALTHCHECK_FILE, 10);
    expect_string_count(__wrap_wfopen, mode, "w", 10);
    will_return_count(__wrap_wfopen, 1, 10);

    expect_value_count(__wrap_fclose, _File, 1, 10);
    will_return_count(__wrap_fclose, 0, 10);

    expect_value_count(__wrap_sleep, seconds, 1, 10);
    expect_value_count(__wrap_atomic_int_get, atomic, &audit_health_check_creation, 10);
    will_return_count(__wrap_atomic_int_get, 0, 10);

    // outside the loop
    expect_value(__wrap_atomic_int_get, atomic, &audit_health_check_creation);
    will_return(__wrap_atomic_int_get, 0);
    expect_string(__wrap__mdebug1, formatted_msg, FIM_HEALTHCHECK_CREATE_ERROR);

    prepare_post_audit_healthcheck_thread();

    ret = audit_health_check(123456);

    assert_int_equal(ret, -1);

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    assert_int_equal(__real_atomic_int_get(&hc_thread_active), 0);
}

void test_audit_health_check_success(void **state) {
    int ret;

    expect_abspath(AUDIT_HEALTHCHECK_DIR, 1);
    expect_abspath(AUDIT_HEALTHCHECK_FILE, 1);

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    __real_atomic_int_set(&hc_thread_active, 0);

    prepare_audit_healthcheck_thread();

    expect_string(__wrap_wfopen, path, AUDIT_HEALTHCHECK_FILE);
    expect_string(__wrap_wfopen, mode, "w");
    will_return(__wrap_wfopen, 1);

    expect_value(__wrap_fclose, _File, 1);
    will_return(__wrap_fclose, 0);

    expect_value(__wrap_sleep, seconds, 1);
    expect_value(__wrap_atomic_int_get, atomic, &audit_health_check_creation);
    will_return(__wrap_atomic_int_get, 1);

    // outside the loop
    expect_value(__wrap_atomic_int_get, atomic, &audit_health_check_creation);
    will_return(__wrap_atomic_int_get, 1);
    expect_string(__wrap__mdebug1, formatted_msg, FIM_HEALTHCHECK_SUCCESS);

    prepare_post_audit_healthcheck_thread();

    ret = audit_health_check(123456);
    assert_int_equal(ret, 0);

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    assert_int_equal(__real_atomic_int_get(&hc_thread_active), 0);
}


int main(void) {
    const struct CMUnitTest tests[] = {
       cmocka_unit_test(test_audit_health_check_fail_to_add_rule),
        cmocka_unit_test(test_audit_health_check_fail_to_create_hc_file),
        cmocka_unit_test(test_audit_health_check_no_creation_event_detected),
        cmocka_unit_test(test_audit_health_check_success),
        };

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
