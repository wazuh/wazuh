/*
 * Copyright (C) 2015-2020, Wazuh Inc.
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

#ifdef TEST_WINAGENT
#include "../wrappers/syscheckd/run_realtime.h"

// This struct should always reflect the one defined in run_realtime.c
typedef struct _win32rtfim {
    HANDLE h;
    OVERLAPPED overlap;

    char *dir;
    TCHAR buffer[65536];
} win32rtfim;

int realtime_win32read(win32rtfim *rtlocald);
void free_win32rtfim_data(win32rtfim *data);
void CALLBACK RTCallBack(DWORD dwerror, DWORD dwBytes, LPOVERLAPPED overlap);
#endif
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

int __wrap_OSHash_Add_ex(OSHash *self, const char *key, void *data) {
    #if TEST_WINAGENT
    if(data) {
        win32rtfim *rtlocald = data;

        free(rtlocald->dir);
        free(rtlocald->overlap.Pointer);
        free(rtlocald);
    }
    #endif

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

#if defined(TEST_AGENT) || defined(TEST_WINAGENT)
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

#ifdef TEST_WINAGENT
int __wrap_fim_configuration_directory(const char *path, const char *entry) {
    check_expected(path);
    check_expected(entry);

    return mock();
}
#endif

#ifdef WIN_WHODATA
int __wrap_whodata_audit_start() {
    return 0;
}

int __wrap_check_path_type(const char *dir) {
    check_expected(dir);

    return mock();
}

int __wrap_set_winsacl(const char *dir, int position) {
    check_expected(dir);
    check_expected(position);

    return mock();
}

unsigned int __wrap_w_directory_exists(const char *path) {
    check_expected(path);

    return mock();
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
#ifdef TEST_WINAGENT
#ifndef WIN_WHODATA
static int setup_RTCallBack(void **state) {
    win32rtfim *rt = calloc(1, sizeof(win32rtfim));

    if(rt == NULL)
        return -1;

    *state = rt;
    return 0;
}

static int teardown_RTCallBack(void **state) {
    win32rtfim *rt = *state;

    if(rt->dir)
        free(rt->dir);

    free(rt);

    return 0;
}
#endif
#endif

#ifdef WIN_WHODATA
static int setup_realtime_adddir_realtime_start_error(void **state) {
    *state = syscheck.realtime;
    syscheck.realtime = NULL;
    return 0;
}

static int teardown_realtime_adddir_realtime_start_error(void **state) {
    syscheck.realtime = *state;

    return 0;
}
#else
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
#endif

/* tests */

void test_realtime_start_success(void **state) {
    OSHash *hash = *state;
    int ret;

    will_return(__wrap_OSHash_Create, hash);

    #if defined(TEST_SERVER) || defined(TEST_AGENT)
    will_return(__wrap_inotify_init, 0);
    #else
    expect_value(wrap_run_realtime_CreateEvent, lpEventAttributes, NULL);
    expect_value(wrap_run_realtime_CreateEvent, bManualReset, TRUE);
    expect_value(wrap_run_realtime_CreateEvent, bInitialState, FALSE);
    expect_value(wrap_run_realtime_CreateEvent, lpName, NULL);
    will_return(wrap_run_realtime_CreateEvent, (HANDLE)123456);
    #endif

    ret = realtime_start();

    assert_int_equal(ret, 0);
    #ifdef TEST_WINAGENT
    assert_int_equal(syscheck.realtime->fd, -1);
    assert_ptr_equal(syscheck.realtime->evt, 123456);
    #endif
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
    (void) state;
    int ret;

    const char * path = "/etc/folder";

    syscheck.realtime->fd = -1;

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
#else // TEST_WINAGENT
void test_realtime_win32read_success(void **state) {
    win32rtfim rtlocal;
    int ret;

    will_return(wrap_run_realtime_ReadDirectoryChangesW, 1);

    ret = realtime_win32read(&rtlocal);

    assert_int_equal(ret, 0);
}

void test_realtime_win32read_unable_to_read_directory(void **state) {
    win32rtfim rtlocal;
    int ret;

    rtlocal.dir = "C:\\a\\path";

    will_return(wrap_run_realtime_ReadDirectoryChangesW, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "(6323): Unable to set 'ReadDirectoryChangesW' for directory: 'C:\\a\\path'");
    will_return(__wrap__mdebug1, 1);

    ret = realtime_win32read(&rtlocal);

    assert_int_equal(ret, 0);
}

void test_free_win32rtfim_data_null_input(void **state) {
    // Nothing to check on this condition
    free_win32rtfim_data(NULL);
}

void test_free_win32rtfim_data_full_data(void **state) {
    win32rtfim *data = calloc(1, sizeof(win32rtfim));

    if(data == NULL)
        fail();

    data->h = (HANDLE)123456;

    data->overlap.Pointer = calloc(1, sizeof(PVOID));

    if(data->overlap.Pointer == NULL) {
        free(data);
        fail();
    }

    data->dir = strdup("c:\\a\\path");

    if(data->dir == NULL) {
        free(data->overlap.Pointer);
        free(data);
        fail();
    }

    expect_value(wrap_run_realtime_CloseHandle, hObject, (HANDLE)123456);
    will_return(wrap_run_realtime_CloseHandle, 1);

    free_win32rtfim_data(data);
}

void test_realtime_adddir_whodata_non_existent_file(void **state) {
    int ret;

    syscheck.wdata.dirs_status[0].status &= ~WD_CHECK_WHODATA;
    syscheck.wdata.dirs_status[0].status |= WD_CHECK_REALTIME;

    expect_string(__wrap_check_path_type, dir, "C:\\a\\path");
    will_return(__wrap_check_path_type, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "(6907): 'C:\\a\\path' does not exist. Monitoring discarded.");
    will_return(__wrap__mdebug1, 1);

    ret = realtime_adddir("C:\\a\\path", 1, 0);

    assert_int_equal(ret, 0);
    assert_non_null(syscheck.wdata.dirs_status[0].status & WD_CHECK_WHODATA);
    assert_null(syscheck.wdata.dirs_status[0].status & WD_CHECK_REALTIME);
    assert_int_equal(syscheck.wdata.dirs_status[0].object_type, WD_STATUS_UNK_TYPE);
    assert_null(syscheck.wdata.dirs_status[0].status & WD_STATUS_EXISTS);
}

void test_realtime_adddir_whodata_error_adding_whodata_dir(void **state) {
    int ret;

    syscheck.wdata.dirs_status[0].status &= ~WD_CHECK_WHODATA;
    syscheck.wdata.dirs_status[0].status |= WD_CHECK_REALTIME;

    expect_string(__wrap_check_path_type, dir, "C:\\a\\path");
    will_return(__wrap_check_path_type, 2);

    expect_string(__wrap_set_winsacl, dir, "C:\\a\\path");
    expect_value(__wrap_set_winsacl, position, 0);
    will_return(__wrap_set_winsacl, 1);

    expect_string(__wrap__merror, formatted_msg,
        "(6619): Unable to add directory to whodata real time monitoring: 'C:\\a\\path'.");

    ret = realtime_adddir("C:\\a\\path", 1, 0);

    assert_int_equal(ret, 0);
    assert_non_null(syscheck.wdata.dirs_status[0].status & WD_CHECK_WHODATA);
    assert_null(syscheck.wdata.dirs_status[0].status & WD_CHECK_REALTIME);
    assert_int_equal(syscheck.wdata.dirs_status[0].object_type, WD_STATUS_DIR_TYPE);
    assert_non_null(syscheck.wdata.dirs_status[0].status & WD_STATUS_EXISTS);
}

void test_realtime_adddir_whodata_file_success(void **state) {
    int ret;

    syscheck.wdata.dirs_status[0].status &= ~WD_CHECK_WHODATA;
    syscheck.wdata.dirs_status[0].status |= WD_CHECK_REALTIME;

    expect_string(__wrap_check_path_type, dir, "C:\\a\\path");
    will_return(__wrap_check_path_type, 1);

    expect_string(__wrap_set_winsacl, dir, "C:\\a\\path");
    expect_value(__wrap_set_winsacl, position, 0);
    will_return(__wrap_set_winsacl, 0);

    ret = realtime_adddir("C:\\a\\path", 1, 0);

    assert_int_equal(ret, 1);
    assert_non_null(syscheck.wdata.dirs_status[0].status & WD_CHECK_WHODATA);
    assert_null(syscheck.wdata.dirs_status[0].status & WD_CHECK_REALTIME);
    assert_int_equal(syscheck.wdata.dirs_status[0].object_type, WD_STATUS_FILE_TYPE);
    assert_non_null(syscheck.wdata.dirs_status[0].status & WD_STATUS_EXISTS);
}

void test_realtime_adddir_whodata_dir_success(void **state) {
    int ret;

    syscheck.wdata.dirs_status[0].status &= ~WD_CHECK_WHODATA;
    syscheck.wdata.dirs_status[0].status |= WD_CHECK_REALTIME;

    expect_string(__wrap_check_path_type, dir, "C:\\a\\path");
    will_return(__wrap_check_path_type, 2);

    expect_string(__wrap_set_winsacl, dir, "C:\\a\\path");
    expect_value(__wrap_set_winsacl, position, 0);
    will_return(__wrap_set_winsacl, 0);

    ret = realtime_adddir("C:\\a\\path", 1, 0);

    assert_int_equal(ret, 1);
    assert_non_null(syscheck.wdata.dirs_status[0].status & WD_CHECK_WHODATA);
    assert_null(syscheck.wdata.dirs_status[0].status & WD_CHECK_REALTIME);
    assert_int_equal(syscheck.wdata.dirs_status[0].object_type, WD_STATUS_DIR_TYPE);
    assert_non_null(syscheck.wdata.dirs_status[0].status & WD_STATUS_EXISTS);
}

void test_realtime_adddir_realtime_start_error(void **state) {
    int ret;
    errno = 0;

    will_return(__wrap_OSHash_Create, NULL);

    expect_string(__wrap__merror, formatted_msg, "(1102): Could not acquire memory due to [(0)-(Success)].");

    ret = realtime_adddir("C:\\a\\path", 0, 0);

    assert_int_equal(ret, -1);
}

void test_realtime_adddir_max_limit_reached(void **state) {
    int ret;

    syscheck.realtime->fd = 1024;

    expect_string(__wrap__merror, formatted_msg,
        "(6616): Unable to add directory to real time monitoring: 'C:\\a\\path' - Maximum size permitted.");

    ret = realtime_adddir("C:\\a\\path", 0, 0);

    assert_int_equal(ret, 0);
}

void test_realtime_adddir_duplicate_entry(void **state) {
    int ret;

    syscheck.realtime->fd = 128;

    will_return(__wrap_OSHash_Get_ex, 1);

    expect_string(__wrap_w_directory_exists, path, "C:\\a\\path");
    will_return(__wrap_w_directory_exists, 1);

    ret = realtime_adddir("C:\\a\\path", 0, 0);

    assert_int_equal(ret, 1);
}

void test_realtime_adddir_handle_error(void **state) {
    int ret;

    syscheck.realtime->fd = 128;

    will_return(__wrap_OSHash_Get_ex, 0);

    expect_string(wrap_run_realtime_CreateFile, lpFileName, "C:\\a\\path");
    will_return(wrap_run_realtime_CreateFile, INVALID_HANDLE_VALUE);

    expect_string(__wrap__mdebug2, formatted_msg,
        "(6290): Unable to add directory to real time monitoring: 'C:\\a\\path'");

    ret = realtime_adddir("C:\\a\\path", 0, 0);

    assert_int_equal(ret, 0);
}

void test_realtime_adddir_out_of_memory_error(void **state) {
    int ret;

    will_return(__wrap_OSHash_Get_ex, 0);

    expect_string(wrap_run_realtime_CreateFile, lpFileName, "C:\\a\\path");
    will_return(wrap_run_realtime_CreateFile, (HANDLE)123456);

    will_return(__wrap_OSHash_Add_ex, NULL);

    expect_string(__wrap__merror_exit, formatted_msg, FIM_CRITICAL_ERROR_OUT_MEM);

    will_return(wrap_run_realtime_ReadDirectoryChangesW, 1);

    ret = realtime_adddir("C:\\a\\path", 0, 0);

    assert_int_equal(ret, 1);
}

void test_realtime_adddir_success(void **state) {
    int ret;

    will_return(__wrap_OSHash_Get_ex, 0);

    expect_string(wrap_run_realtime_CreateFile, lpFileName, "C:\\a\\path");
    will_return(wrap_run_realtime_CreateFile, (HANDLE)123456);

    will_return(__wrap_OSHash_Add_ex, 1);

    will_return(wrap_run_realtime_ReadDirectoryChangesW, 1);

    ret = realtime_adddir("C:\\a\\path", 0, 0);

    assert_int_equal(ret, 1);
}

void test_RTCallBack_error_on_callback(void **state) {
    OVERLAPPED ov;

    expect_string(__wrap__mwarn, formatted_msg, FIM_WARN_REALTIME_OVERFLOW);

    expect_string(__wrap__merror, formatted_msg, "(6613): Real time Windows callback process: 'Path not found.' (3).");

    RTCallBack(ERROR_PATH_NOT_FOUND, 0, &ov);
}

void test_RTCallBack_empty_hash_table(void **state) {
    OVERLAPPED ov;

    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap__merror, formatted_msg, FIM_ERROR_REALTIME_WINDOWS_CALLBACK_EMPTY);

    RTCallBack(ERROR_SUCCESS, 1, &ov);
}

void test_RTCallBack_no_bytes_returned(void **state) {
    win32rtfim *rt = *state;
    OVERLAPPED ov;

    expect_string(__wrap__mwarn, formatted_msg, FIM_WARN_REALTIME_OVERFLOW);

    will_return(__wrap_OSHash_Get, rt);

    // Inside realtime_win32read
    will_return(wrap_run_realtime_ReadDirectoryChangesW, 1);

    RTCallBack(ERROR_SUCCESS, 0, &ov);
}

void test_RTCallBack_acquired_changes_null_dir(void **state) {
    win32rtfim *rt = *state;
    OVERLAPPED ov;
    PFILE_NOTIFY_INFORMATION pinfo;

    // Fill the win32rtfim struct with testing data
    pinfo = (PFILE_NOTIFY_INFORMATION) rt->buffer;
    wcscpy(pinfo->FileName, L"C:\\a\\path");
    pinfo->FileNameLength = wcslen(pinfo->FileName) * sizeof(WCHAR);
    pinfo->NextEntryOffset = 0;

    // This condition is not taken into account
    rt->dir = NULL;

    ov.Pointer = "C:\\a\\path";

    // Begin calls to mock functions
    will_return(__wrap_OSHash_Get, rt);

    expect_string(__wrap_fim_configuration_directory, path, "C:\\a\\path");
    expect_string(__wrap_fim_configuration_directory, entry, "file");
    will_return(__wrap_fim_configuration_directory, 0);

    expect_string(__wrap_fim_configuration_directory, path, "");
    expect_string(__wrap_fim_configuration_directory, entry, "file");
    will_return(__wrap_fim_configuration_directory, -1);

    // Inside realtime_win32read
    will_return(wrap_run_realtime_ReadDirectoryChangesW, 1);

    RTCallBack(ERROR_SUCCESS, 1, &ov);
}

void test_RTCallBack_acquired_changes(void **state) {
    win32rtfim *rt = *state;
    OVERLAPPED ov;
    PFILE_NOTIFY_INFORMATION pinfo;

    // Fill the win32rtfim struct with testing data
    pinfo = (PFILE_NOTIFY_INFORMATION) rt->buffer;
    wcscpy(pinfo->FileName, L"file.test");
    pinfo->FileNameLength = wcslen(pinfo->FileName) * sizeof(WCHAR);
    pinfo->NextEntryOffset = 0;

    // This condition is not taken into account
    rt->dir = strdup("C:\\a\\path");

    ov.Pointer = "C:\\a\\path\\file.test";

    // Begin calls to mock functions
    will_return(__wrap_OSHash_Get, rt);

    expect_string(__wrap_fim_configuration_directory, path, "C:\\a\\path\\file.test");
    expect_string(__wrap_fim_configuration_directory, entry, "file");
    will_return(__wrap_fim_configuration_directory, 0);

    expect_string(__wrap_fim_configuration_directory, path, "c:\\a\\path\\file.test");
    expect_string(__wrap_fim_configuration_directory, entry, "file");
    will_return(__wrap_fim_configuration_directory, 0);

    expect_string(__wrap_fim_realtime_event, file, "c:\\a\\path\\file.test");

    // Inside realtime_win32read
    will_return(wrap_run_realtime_ReadDirectoryChangesW, 1);

    RTCallBack(ERROR_SUCCESS, 1, &ov);
}
#endif

int main(void) {
    #ifndef WIN_WHODATA
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_realtime_start_success, setup_realtime_start, teardown_realtime_start),
        cmocka_unit_test_setup_teardown(test_realtime_start_failure_hash, setup_realtime_start, teardown_realtime_start),
        #if defined(TEST_SERVER) || defined(TEST_AGENT)
        cmocka_unit_test_setup_teardown(test_realtime_start_failure_inotify, setup_realtime_start, teardown_realtime_start),
        cmocka_unit_test_setup_teardown(test_realtime_adddir_whodata, setup_w_vector, teardown_w_vector),
        cmocka_unit_test_setup_teardown(test_realtime_adddir_whodata_new_directory, setup_w_vector, teardown_w_vector),
        cmocka_unit_test(test_realtime_adddir_realtime_failure),
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
        #else
        // realtime_win32read
        cmocka_unit_test(test_realtime_win32read_success),
        cmocka_unit_test(test_realtime_win32read_unable_to_read_directory),
        // free_win32rtfim_data
        cmocka_unit_test(test_free_win32rtfim_data_null_input),
        cmocka_unit_test(test_free_win32rtfim_data_full_data),
        // RTCallBack
        cmocka_unit_test(test_RTCallBack_error_on_callback),
        cmocka_unit_test(test_RTCallBack_empty_hash_table),
        cmocka_unit_test_setup_teardown(test_RTCallBack_no_bytes_returned, setup_RTCallBack, teardown_RTCallBack),
        cmocka_unit_test_setup_teardown(test_RTCallBack_acquired_changes_null_dir, setup_RTCallBack, teardown_RTCallBack),
        cmocka_unit_test_setup_teardown(test_RTCallBack_acquired_changes, setup_RTCallBack, teardown_RTCallBack),
        #endif
    };
    #else
    const struct CMUnitTest tests[] = {
        // realtime_adddir
        cmocka_unit_test(test_realtime_adddir_whodata_non_existent_file),
        cmocka_unit_test(test_realtime_adddir_whodata_error_adding_whodata_dir),
        cmocka_unit_test(test_realtime_adddir_whodata_file_success),
        cmocka_unit_test(test_realtime_adddir_whodata_dir_success),
        cmocka_unit_test_setup_teardown(test_realtime_adddir_realtime_start_error, setup_realtime_adddir_realtime_start_error, teardown_realtime_adddir_realtime_start_error),
        cmocka_unit_test(test_realtime_adddir_max_limit_reached),
        cmocka_unit_test(test_realtime_adddir_duplicate_entry),
        cmocka_unit_test(test_realtime_adddir_handle_error),
        cmocka_unit_test(test_realtime_adddir_out_of_memory_error),
        cmocka_unit_test(test_realtime_adddir_success),
    };
    #endif

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
