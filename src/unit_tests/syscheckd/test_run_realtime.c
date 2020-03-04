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
#include <string.h>

#include "../syscheckd/syscheck.h"
#include "../config/syscheck-config.h"

/* redefinitons/wrapping */

int __wrap_inotify_init() {
    return mock();
}

int __wrap_inotify_add_watch() {
    return mock();
}

int __wrap_OSHash_Get_ex() {
    return mock();
}

char *__wrap_OSHash_Get() {
    return mock_type(char *);
}

int __wrap_OSHash_Add_ex() {
    return mock();
}

int __wrap_OSHash_Update_ex(OSHash *self, const char *key, void *data) {
    int retval = mock();

    if(retval != 0)
        free(data); //  This won't be used, free it

    return retval;
}

void *__wrap_OSHash_Delete_ex() {
    char *ret = mock_type(char *);
    ret = calloc(1, sizeof(char *));

    return (void*)ret;
}

void * __wrap_rbtree_insert() {
    return NULL;
}

OSHash * __wrap_OSHash_Create() {
    return mock_type(OSHash*);
}

void __wrap__merror(const char * file, int line, const char * func, const char *msg, ...)
{
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__mwarn(const char * file, int line, const char * func, const char *msg, ...)
{
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__merror_exit(const char * file, int line, const char * func, const char *msg, ...)
{
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__mdebug1(const char * file, int line, const char * func, const char *msg, ...)
{
    char formatted_msg[OS_MAXSTR];
    va_list args;

    switch(mock()) {
        case 0:
            return;
        default:
            va_start(args, msg);
            vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
            va_end(args);

            check_expected(formatted_msg);
    }
}

void __wrap__mdebug2(const char * file, int line, const char * func, const char *msg, ...)
{
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

int __wrap_send_log_msg() {
    return mock();
}

char **__wrap_rbtree_keys(const rb_tree *tree) {
    return mock_type(char **);
}

void __wrap_fim_realtime_event(char *file) {
    check_expected(file);
}

ssize_t __real_read(int fildes, void *buf, size_t nbyte);
ssize_t __wrap_read(int fildes, void *buf, size_t nbyte) {
    //static char event[] = {1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 't', 'e', 's', 't', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    switch(mock_type(int)){
        case 0:
        return __real_read(fildes, buf, nbyte);

        case 1:
        return mock_type(ssize_t);

        case 2:
        memcpy(buf, mock_type(char *), 32);
        return mock_type(ssize_t);
    }
    // We should never reach this point
    return __real_read(fildes, buf, nbyte);
}

int __wrap_W_Vector_insert_unique(W_Vector *v, const char *element) {
    check_expected_ptr(v);
    check_expected(element);

    return mock();
}

#ifdef TEST_AGENT
char *_read_file(const char *high_name, const char *low_name, const char *defines_file) __attribute__((nonnull(3)));

int __wrap_getDefine_Int(const char *high_name, const char *low_name, int min, int max) {
    int ret;
    char *value;
    char *pt;

    /* Try to read from the local define file */
    value = _read_file(high_name, low_name, "./internal_options.conf");
    if (!value) {
        merror_exit(DEF_NOT_FOUND, high_name, low_name);
    }

    pt = value;
    while (*pt != '\0') {
        if (!isdigit((int)*pt)) {
            merror_exit(INV_DEF, high_name, low_name, value);
        }
        pt++;
    }

    ret = atoi(value);
    if ((ret < min) || (ret > max)) {
        merror_exit(INV_DEF, high_name, low_name, value);
    }

    /* Clear memory */
    free(value);

    return (ret);
}

int __wrap_isChroot() {
    return 1;
}
#endif

/* setup/teardown */
static int setup_group(void **state) {
    will_return_always(__wrap__mdebug1, 0);
    Read_Syscheck_Config("test_syscheck.conf");

    syscheck.realtime = (rtfim *) calloc(1, sizeof(rtfim));

    if(syscheck.realtime == NULL)
        return -1;

    return 0;
}

static int teardown_group(void **state) {
    Free_Syscheck(&syscheck);

    return 0;
}

#if defined(TEST_SERVER) || defined(TEST_AGENT)
    static int setup_w_vector(void **state)
    {
        audit_added_dirs = W_Vector_init(2);
        if(!audit_added_dirs)
            return -1;

        return 0;
    }

    static int teardown_w_vector(void **state)
    {
        W_Vector_free(audit_added_dirs);

        return 0;
    }
#endif

static int setup_realtime_start(void **state) {
    OSHash *hash = calloc(1, sizeof(OSHash));

    if(hash == NULL)
        return -1;

    *state = hash;

    state[1] = syscheck.realtime;
    syscheck.realtime = NULL;

    return 0;
}

static int teardown_realtime_start(void **state) {
    OSHash *hash = *state;

    free(hash);

    if (syscheck.realtime) {
        free(syscheck.realtime);
    }

    syscheck.realtime = state[1];
    state[1] = NULL;

    return 0;
}

/* tests */

void test_realtime_start_success(void **state) {
    OSHash *hash = *state;
    int ret;

    will_return(__wrap_OSHash_Create, hash);
    #if defined(TEST_SERVER) || defined(TEST_AGENT)
        will_return(__wrap_inotify_init, 0);
    #endif

    ret = realtime_start();

    assert_int_equal(ret, 0);
}


void test_realtime_start_failure_hash(void **state) {
    int ret;

    will_return(__wrap_OSHash_Create, NULL);

    errno = ENOMEM;
    expect_string(__wrap__merror, formatted_msg,
        "(1102): Could not acquire memory due to [(12)-(Cannot allocate memory)].");

    ret = realtime_start();

    errno = 0;
    assert_int_equal(ret, -1);
}

#if defined(TEST_SERVER) || defined(TEST_AGENT)

    void test_realtime_start_failure_inotify(void **state) {
        OSHash *hash = *state;
        int ret;

        will_return(__wrap_OSHash_Create, hash);
        will_return(__wrap_inotify_init, -1);

        expect_string(__wrap__merror, formatted_msg, FIM_ERROR_INOTIFY_INITIALIZE);

        ret = realtime_start();

        assert_int_equal(ret, -1);
    }

    void test_realtime_adddir_whodata(void **state) {
        int ret;

        const char * path = "/etc/folder";

        audit_thread_active = 1;

        expect_value(__wrap_W_Vector_insert_unique, v, audit_added_dirs);
        expect_string(__wrap_W_Vector_insert_unique, element, "/etc/folder");
        will_return(__wrap_W_Vector_insert_unique, 1);

        ret = realtime_adddir(path, 1, 0);

        assert_int_equal(ret, 1);
    }


    void test_realtime_adddir_whodata_new_directory(void **state) {
        int ret;

        const char * path = "/etc/folder";

        audit_thread_active = 1;

        expect_value(__wrap_W_Vector_insert_unique, v, audit_added_dirs);
        expect_string(__wrap_W_Vector_insert_unique, element, "/etc/folder");
        will_return(__wrap_W_Vector_insert_unique, 0);
        expect_string(__wrap__mdebug1, formatted_msg, "(6230): Monitoring with Audit: '/etc/folder'");
        will_return(__wrap__mdebug1, 1);

        ret = realtime_adddir(path, 1, 0);

        assert_int_equal(ret, 1);
    }

    void test_realtime_adddir_realtime_failure(void **state)
    {
        OSHash *hash = *state;
        int ret;

        const char * path = "/etc/folder";

        syscheck.realtime = NULL;
        will_return(__wrap_OSHash_Create, hash);
        will_return(__wrap_inotify_init, -1);

        expect_string(__wrap__merror, formatted_msg, FIM_ERROR_INOTIFY_INITIALIZE);

        ret = realtime_adddir(path, 0, 0);

        assert_int_equal(ret, -1);
    }


    void test_realtime_adddir_realtime_watch_max_reached_failure(void **state)
    {
        (void) state;
        int ret;

        const char * path = "/etc/folder";

        syscheck.realtime->fd = 1;
        will_return(__wrap_inotify_add_watch, -1);
        expect_string(__wrap__merror, formatted_msg, "(6700): Unable to add inotify watch to real time monitoring: '/etc/folder'. '-1' '28': "
                                                     "The maximum limit of inotify watches has been reached.");
        errno = 28;

        ret = realtime_adddir(path, 0, 0);

        errno = 0;

        assert_int_equal(ret, 1);
    }


    void test_realtime_adddir_realtime_watch_generic_failure(void **state)
    {
        (void) state;
        int ret;

        const char * path = "/etc/folder";

        syscheck.realtime->fd = 1;
        will_return(__wrap_inotify_add_watch, -1);
        expect_string(__wrap__mdebug1, formatted_msg, "(6272): Unable to add inotify watch to real time monitoring: '/etc/folder'. '-1' '0':'Success'");
        will_return(__wrap__mdebug1, 1);

        ret = realtime_adddir(path, 0, 0);

        assert_int_equal(ret, 1);
    }


    void test_realtime_adddir_realtime_add(void **state)
    {
        (void) state;
        int ret;

        const char * path = "/etc/folder";

        syscheck.realtime->fd = 1;
        will_return(__wrap_inotify_add_watch, 1);
        will_return(__wrap_OSHash_Get_ex, 0);
        will_return(__wrap_OSHash_Add_ex, 1);
        expect_string(__wrap__mdebug2, formatted_msg, "(6224): Entry '/etc/folder' already exists in the RT hash table.");
        expect_string(__wrap__mdebug1, formatted_msg, "(6227): Directory added for real time monitoring: '/etc/folder'");
        will_return(__wrap__mdebug1, 1);

        ret = realtime_adddir(path, 0, 0);

        assert_int_equal(ret, 1);
    }


    void test_realtime_adddir_realtime_add_hash_failure(void **state)
    {
        (void) state;
        int ret;

        const char * path = "/etc/folder";

        syscheck.realtime->fd = 1;
        will_return(__wrap_inotify_add_watch, 1);
        will_return(__wrap_OSHash_Get_ex, 0);
        will_return(__wrap_OSHash_Add_ex, 0);
        expect_string(__wrap__merror_exit, formatted_msg, "(6697): Out of memory. Exiting.");
        will_return_always(__wrap__mdebug1, 0);

        ret = realtime_adddir(path, 0, 0);

        assert_int_equal(ret, 1);
    }


    void test_realtime_adddir_realtime_update(void **state)
    {
        (void) state;
        int ret;

        const char * path = "/etc/folder";

        syscheck.realtime->fd = 1;
        will_return(__wrap_inotify_add_watch, 1);
        will_return(__wrap_OSHash_Get_ex, 1);
        will_return(__wrap_OSHash_Update_ex, 1);

        ret = realtime_adddir(path, 0, 0);

        assert_int_equal(ret, 1);
    }


    void test_realtime_adddir_realtime_update_failure(void **state)
    {
        (void) state;
        int ret;

        const char * path = "/etc/folder";

        syscheck.realtime->fd = 1;
        will_return(__wrap_inotify_add_watch, 1);
        will_return(__wrap_OSHash_Get_ex, 1);
        will_return(__wrap_OSHash_Update_ex, 0);

        expect_string(__wrap__merror, formatted_msg, "Unable to update 'dirtb'. Directory not found: '/etc/folder'");

        ret = realtime_adddir(path, 0, 0);

        assert_int_equal(ret, -1);
    }


    void test_free_syscheck_dirtb_data(void **state)
    {
        (void) state;
        char *data = strdup("test");

        free_syscheck_dirtb_data(data);

        assert_non_null(data);
    }


    void test_free_syscheck_dirtb_data_null(void **state)
    {
        (void) state;
        char *data = NULL;

        free_syscheck_dirtb_data(data);

        assert_null(data);
    }


    void test_realtime_process(void **state)
    {
        (void) state;

        syscheck.realtime->fd = 1;

        will_return(__wrap_read, 1); // Use wrap
        will_return(__wrap_read, 0);

        realtime_process();
    }

    void test_realtime_process_len(void **state)
    {
        (void) state;

        char event[] = {1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 't', 'e', 's', 't', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

        syscheck.realtime->fd = 1;

        will_return(__wrap_read, 2); // Use wrap
        will_return(__wrap_read, event);
        will_return(__wrap_read, 16);
        will_return(__wrap_OSHash_Get, "test");
        expect_string(__wrap__mdebug2, formatted_msg, "Duplicate event in real-time buffer: test/test");
        char **paths = NULL;
        paths = os_AddStrArray("/test", paths);
        will_return(__wrap_rbtree_keys, paths);
        expect_string(__wrap_fim_realtime_event, file, "/test");

        realtime_process();
    }

    void test_realtime_process_len_zero(void **state)
    {
        (void) state;

        char event[] = {1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 't', 'e', 's', 't', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

        syscheck.realtime->fd = 1;

        will_return(__wrap_read, 2); // Use wrap
        will_return(__wrap_read, event);
        will_return(__wrap_read, 16);
        will_return(__wrap_OSHash_Get, "test");
        expect_string(__wrap__mdebug2, formatted_msg, "Duplicate event in real-time buffer: test");
        char **paths = NULL;
        paths = os_AddStrArray("/test", paths);
        will_return(__wrap_rbtree_keys, paths);
        expect_string(__wrap_fim_realtime_event, file, "/test");

        realtime_process();
    }

    void test_realtime_process_len_path_separator(void **state)
    {
        (void) state;

        char event[] = {1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 't', 'e', 's', 't', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

        syscheck.realtime->fd = 1;

        will_return(__wrap_read, 2); // Use wrap
        will_return(__wrap_read, event);
        will_return(__wrap_read, 16);
        will_return(__wrap_OSHash_Get, "test/");
        expect_string(__wrap__mdebug2, formatted_msg, "Duplicate event in real-time buffer: test/test");
        char **paths = NULL;
        paths = os_AddStrArray("/test", paths);
        will_return(__wrap_rbtree_keys, paths);
        expect_string(__wrap_fim_realtime_event, file, "/test");

        realtime_process();
    }

    void test_realtime_process_overflow(void **state)
    {
        (void) state;

        char event[] = {255, 255, 255, 255, 0, 64, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 't', 'e', 's', 't', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

        syscheck.realtime->fd = 1;

        will_return(__wrap_read, 2); // Use wrap
        will_return(__wrap_read, event);
        will_return(__wrap_read, 16);
        expect_string(__wrap__mwarn, formatted_msg, "Real-time inotify kernel queue is full. Some events may be lost. Next scheduled scan will recover lost data.");
        will_return(__wrap_send_log_msg, 1);
        char **paths = NULL;
        paths = os_AddStrArray("/test", paths);
        will_return(__wrap_rbtree_keys, paths);
        expect_string(__wrap_fim_realtime_event, file, "/test");

        realtime_process();
    }

    void test_realtime_process_delete(void **state)
    {
        (void) state;

        char event[] = {1, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 't', 'e', 's', 't', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

        syscheck.realtime->fd = 1;

        will_return(__wrap_read, 2); // Use wrap
        will_return(__wrap_read, event);
        will_return(__wrap_read, 16);
        will_return(__wrap_OSHash_Get, "test");
        expect_string(__wrap__mdebug2, formatted_msg, "Duplicate event in real-time buffer: test/test");
        char *data;
        will_return_always(__wrap_OSHash_Delete_ex, data);
        char **paths = NULL;
        paths = os_AddStrArray("/test", paths);
        will_return(__wrap_rbtree_keys, paths);
        expect_string(__wrap_fim_realtime_event, file, "/test");

        realtime_process();
    }

    void test_realtime_process_failure(void **state)
    {
        (void) state;

        syscheck.realtime->fd = 1;

        will_return(__wrap_read, 1); // Use wrap
        will_return(__wrap_read, -1);

        expect_string(__wrap__merror, formatted_msg, FIM_ERROR_REALTIME_READ_BUFFER);

        realtime_process();
    }
#endif

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_realtime_start_success, setup_realtime_start, teardown_realtime_start),
        cmocka_unit_test_setup_teardown(test_realtime_start_failure_hash, setup_realtime_start, teardown_realtime_start),
        #if defined(TEST_SERVER) || defined(TEST_AGENT)
            cmocka_unit_test_setup_teardown(test_realtime_start_failure_inotify, setup_realtime_start, teardown_realtime_start),
            cmocka_unit_test_setup_teardown(test_realtime_adddir_whodata, setup_w_vector, teardown_w_vector),
            cmocka_unit_test_setup_teardown(test_realtime_adddir_whodata_new_directory, setup_w_vector, teardown_w_vector),
            cmocka_unit_test_setup_teardown(test_realtime_adddir_realtime_failure, setup_realtime_start, teardown_realtime_start),
            cmocka_unit_test(test_realtime_adddir_realtime_watch_max_reached_failure),
            cmocka_unit_test(test_realtime_adddir_realtime_watch_generic_failure),
            cmocka_unit_test(test_realtime_adddir_realtime_add),
            cmocka_unit_test(test_realtime_adddir_realtime_add_hash_failure),
            cmocka_unit_test(test_realtime_adddir_realtime_update),
            cmocka_unit_test(test_realtime_adddir_realtime_update_failure),
            cmocka_unit_test(test_free_syscheck_dirtb_data),
            cmocka_unit_test(test_free_syscheck_dirtb_data_null),
            cmocka_unit_test(test_realtime_process),
            cmocka_unit_test(test_realtime_process_len),
            cmocka_unit_test(test_realtime_process_len_zero),
            cmocka_unit_test(test_realtime_process_len_path_separator),
            cmocka_unit_test(test_realtime_process_overflow),
            cmocka_unit_test(test_realtime_process_delete),
            cmocka_unit_test(test_realtime_process_failure),
        #endif
    };

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
