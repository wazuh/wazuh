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
#ifndef TEST_WINAGENT
#include <sys/inotify.h>
#endif

#include "../wrappers/common.h"
#include "../wrappers/posix/pthread_wrappers.h"
#include "../wrappers/posix/unistd_wrappers.h"
#include "../wrappers/linux/inotify_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/fs_op_wrappers.h"
#include "../wrappers/wazuh/shared/hash_op_wrappers.h"
#include "../wrappers/wazuh/shared/randombytes_wrappers.h"
#include "../wrappers/wazuh/shared/syscheck_op_wrappers.h"
#include "../wrappers/wazuh/shared/vector_op_wrappers.h"
#include "../wrappers/wazuh/shared/file_op_wrappers.h"
#include "../wrappers/wazuh/syscheckd/create_db_wrappers.h"
#include "../wrappers/wazuh/syscheckd/run_check_wrappers.h"
#include "../wrappers/wazuh/syscheckd/win_whodata_wrappers.h"

#include "../syscheckd/syscheck.h"
#include "../config/syscheck-config.h"

#ifdef TEST_WINAGENT
// This struct should always reflect the one defined in run_realtime.c
typedef struct _win32rtfim {
    HANDLE h;
    OVERLAPPED overlap;

    char *dir;
    TCHAR buffer[65536];
    unsigned int watch_status;
} win32rtfim;

int realtime_win32read(win32rtfim *rtlocald);
void free_win32rtfim_data(win32rtfim *data);
void CALLBACK RTCallBack(DWORD dwerror, DWORD dwBytes, LPOVERLAPPED overlap);
#endif


typedef struct realtime_process_data{
    struct inotify_event *event;
    OSHashNode *node;
} realtime_process_data;

/* setup/teardown */
static int setup_group(void **state) {
    expect_any_always(__wrap__mdebug1, formatted_msg);

#ifdef TEST_AGENT
    will_return_always(__wrap_isChroot, 1);
#endif

    test_mode = 0;
    Read_Syscheck_Config("test_syscheck.conf");

    syscheck.realtime = (rtfim *) calloc(1, sizeof(rtfim));

    if(syscheck.realtime == NULL)
        return -1;

    test_mode = 1;
    return 0;
}

static int teardown_group(void **state) {
    test_mode = 0;
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

static int setup_realtime_adddir_realtime_start_error(void **state) {
    *state = syscheck.realtime;
    syscheck.realtime = NULL;
    return 0;
}

static int teardown_realtime_adddir_realtime_start_error(void **state) {
    if (syscheck.realtime) {
        free(syscheck.realtime);
    }
    syscheck.realtime = *state;

    return 0;
}

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

static int setup_inotify_event(void **state) {
    struct inotify_event *event;
    event = calloc(1, OS_SIZE_512);

    if (!event) {
        return -1;
    }
    *state = event;

    return 0;
}

static int teardown_inotify_event(void **state) {
    struct inotify_event *event = *state;

    if (event) {
        free(event);
    }

    return 0;
}

static int setup_hash_node(void **state) {
    OSHashNode *node = (OSHashNode *)calloc(1, sizeof(OSHashNode));

    if (!node) {
        return -1;
    }

    node->next = NULL;
    node->prev = NULL;
    node->key = "dummy_key";

    if (node->key == NULL) {
        return -1;
    }

    *state = node;

    return 0;
}

static int teardown_hash_node(void **state) {
    OSHashNode *node = *state;

    if (node) {
        free(node);
    }

    return 0;
}

static int setup_realtime_process(void **state) {
    realtime_process_data *data = (realtime_process_data *)calloc(1, sizeof(realtime_process_data));

    if (!data) {
        return -1;
    }

    if (setup_hash_node((void **) &data->node)) {
        return -1;
    }

    if (setup_inotify_event((void **) &data->event)) {
        return -1;
    }
    *state = data;

    return 0;
}

static int teardown_realtime_process(void **state) {
    realtime_process_data *data = *state;

    if (teardown_hash_node((void **) &data->node)) {
        return -1;
    }

    if (teardown_inotify_event((void **) &data->event)) {
        return -1;
    }
    if (data) {
        free(data);
    }

    return 0;
}

static int setup_OSHash(void **state) {
    test_mode = 0;
    will_return_always(__wrap_os_random, 12345);
    OSHash *hash = OSHash_Create();
    *state = hash;
    test_mode = 1;
    return 0;
}

static int teardown_OSHash(void **state) {
    test_mode = 0;
    OSHash *hash = *state;
    void *rtlocald = OSHash_Delete_ex(hash, "1");
#ifdef TEST_WINAGENT
    free_win32rtfim_data(rtlocald);
#endif
    return 0;
}

/* tests */

void test_realtime_start_success(void **state) {
    OSHash *hash = *state;
    int ret;

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, hash);

#if defined(TEST_SERVER) || defined(TEST_AGENT)
    will_return(__wrap_inotify_init, 0);
#else
    expect_value(wrap_CreateEvent, lpEventAttributes, NULL);
    expect_value(wrap_CreateEvent, bManualReset, TRUE);
    expect_value(wrap_CreateEvent, bInitialState, FALSE);
    expect_value(wrap_CreateEvent, lpName, NULL);
    will_return(wrap_CreateEvent, (HANDLE)123456);
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

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, NULL);

    errno = ENOMEM;
    expect_string(__wrap__merror, formatted_msg,
        "(1102): Could not acquire memory due to [(12)-(Cannot allocate memory)].");

    ret = realtime_start();

    errno = 0;
    assert_int_equal(ret, -1);
}


void test_count_watches_realtime_null(void **state) {
    (void) state;

    syscheck.realtime = NULL;

    count_watches();
}

void test_count_watches_hash_node_null(void **state) {
    (void) state;

    syscheck.realtime = (rtfim *) calloc(1, sizeof(rtfim));

    if (syscheck.realtime == NULL) {
        fail();
    }

    expect_function_call(__wrap_pthread_mutex_lock);

    expect_value(__wrap_OSHash_Begin, self, syscheck.realtime->dirtb);
    will_return(__wrap_OSHash_Begin, NULL);

    expect_function_call(__wrap_pthread_mutex_unlock);

    count_watches();
}

void test_count_watches_counting(void **state) {
    (void) state;
    OSHashNode *node = *state;

    node->data = "/test/sub";

    expect_function_call(__wrap_pthread_mutex_lock);

    expect_value(__wrap_OSHash_Begin, self, syscheck.realtime->dirtb);
    will_return(__wrap_OSHash_Begin, node);

    expect_value(__wrap_OSHash_Next, self, syscheck.realtime->dirtb);
    will_return(__wrap_OSHash_Next, NULL);

    expect_function_call(__wrap_pthread_mutex_unlock);

    count_watches();
}

#if defined(TEST_SERVER) || defined(TEST_AGENT)

void test_realtime_start_failure_inotify(void **state) {
    OSHash *hash = *state;
    int ret;

    expect_function_call(__wrap_OSHash_Create);
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

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_value(__wrap_W_Vector_insert_unique, v, audit_added_dirs);
    expect_string(__wrap_W_Vector_insert_unique, element, "/etc/folder");
    will_return(__wrap_W_Vector_insert_unique, 1);
    expect_function_call(__wrap_pthread_mutex_unlock);

    ret = realtime_adddir(path, 1, 0);

    assert_int_equal(ret, 1);
}


void test_realtime_adddir_whodata_new_directory(void **state) {
    int ret;

    const char * path = "/etc/folder";

    audit_thread_active = 1;

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_value(__wrap_W_Vector_insert_unique, v, audit_added_dirs);
    expect_string(__wrap_W_Vector_insert_unique, element, "/etc/folder");
    will_return(__wrap_W_Vector_insert_unique, 0);
    expect_string(__wrap__mdebug1, formatted_msg, "(6230): Monitoring with Audit: '/etc/folder'");
    expect_function_call(__wrap_pthread_mutex_unlock);

    ret = realtime_adddir(path, 1, 0);

    assert_int_equal(ret, 1);
}

void test_realtime_adddir_realtime_start_failure(void **state)
{
    (void) state;
    int ret;

    const char * path = "/etc/folder";

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, NULL);

    expect_string(__wrap__merror, formatted_msg, "(1102): Could not acquire memory due to [(0)-(Success)].");

    ret = realtime_adddir(path, 0, 0);

    assert_int_equal(ret, -1);
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

    ret = realtime_adddir(path, 0, 0);

    assert_int_equal(ret, 1);
}


void test_realtime_adddir_realtime_add(void **state)
{
    (void) state;
    int ret;
    const char * path = "/etc/folder";

    syscheck.realtime->fd = 1;
    syscheck.realtime->dirtb = *state;
    will_return(__wrap_inotify_add_watch, 1);

    expect_value(__wrap_OSHash_Get_ex, self, syscheck.realtime->dirtb);
    expect_string(__wrap_OSHash_Get_ex, key, "1");
    will_return(__wrap_OSHash_Get_ex, 0);

    expect_string(__wrap__mdebug2, formatted_msg, "(6224): Entry '/etc/folder' already exists in the RT hash table.");
    expect_string(__wrap__mdebug1, formatted_msg, "(6227): Directory added for real time monitoring: '/etc/folder'");

    test_mode = 0;
    OSHash_Add_ex(syscheck.realtime->dirtb, "1", "/etc/folder"); // Duplicate simulation
    ret = realtime_adddir(path, 0, 0);
    test_mode = 1;

    assert_int_equal(ret, 1);
}


void test_realtime_adddir_realtime_add_hash_failure(void **state)
{
    (void) state;
    int ret;

    const char * path = "/etc/folder";

    syscheck.realtime->fd = 1;
    will_return(__wrap_inotify_add_watch, 1);

    expect_value(__wrap_OSHash_Get_ex, self, syscheck.realtime->dirtb);
    expect_string(__wrap_OSHash_Get_ex, key, "1");
    will_return(__wrap_OSHash_Get_ex, 0);

    OSHash_Add_ex_check_data = 0;
    expect_value(__wrap_OSHash_Add_ex, self, syscheck.realtime->dirtb);
    expect_string(__wrap_OSHash_Add_ex, key, "1");
    will_return(__wrap_OSHash_Add_ex, 0);

    expect_string(__wrap__merror_exit, formatted_msg, "(6697): Out of memory. Exiting.");
    expect_string(__wrap__mdebug1, formatted_msg, "(6227): Directory added for real time monitoring: '/etc/folder'");

    test_mode = 1;
    ret = realtime_adddir(path, 0, 0);
    test_mode = 0;

    assert_int_equal(ret, 1);
}


void test_realtime_adddir_realtime_update(void **state)
{
    (void) state;
    int ret;

    const char * path = "/etc/folder";

    syscheck.realtime->fd = 1;
    will_return(__wrap_inotify_add_watch, 1);

    expect_value(__wrap_OSHash_Get_ex, self, syscheck.realtime->dirtb);
    expect_string(__wrap_OSHash_Get_ex, key, "1");
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

    expect_value(__wrap_OSHash_Get_ex, self, syscheck.realtime->dirtb);
    expect_string(__wrap_OSHash_Get_ex, key, "1");
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


void test_realtime_process(void **state) {

    syscheck.realtime->fd = 1;

    will_return(__wrap_read, "");
    will_return(__wrap_read, 0);

    realtime_process();
}

void test_realtime_process_len(void **state) {
    struct inotify_event *event = *state;
    event->wd = 1;
    event->mask = 2;
    event->cookie = 0;
    event->len = 5;
    strcpy(event->name, "test");

    syscheck.realtime->fd = 1;

    will_return(__wrap_read, event);
    will_return(__wrap_read, 21);

    expect_value(__wrap_OSHash_Get, self, syscheck.realtime->dirtb);
    expect_string(__wrap_OSHash_Get, key, "1");
    will_return(__wrap_OSHash_Get, "test");

    expect_string(__wrap__mdebug2, formatted_msg, "Duplicate event in real-time buffer: test/test");
    char **paths = NULL;
    paths = os_AddStrArray("/test", paths);
    will_return(__wrap_rbtree_keys, paths);
    expect_string(__wrap_fim_realtime_event, file, "/test");

    test_mode = 1;
    realtime_process();
    test_mode = 0;
}

void test_realtime_process_len_zero(void **state) {
    struct inotify_event *event = *state;
    event->wd = 1;
    event->mask = 2;
    event->cookie = 0;
    event->len = 0;
    strcpy(event->name, "test");

    syscheck.realtime->fd = 1;

    will_return(__wrap_read, event);
    will_return(__wrap_read, 16);

    expect_value(__wrap_OSHash_Get, self, syscheck.realtime->dirtb);
    expect_string(__wrap_OSHash_Get, key, "1");
    will_return(__wrap_OSHash_Get, "test");

    expect_string(__wrap__mdebug2, formatted_msg, "Duplicate event in real-time buffer: test");
    char **paths = NULL;
    paths = os_AddStrArray("/test", paths);
    will_return(__wrap_rbtree_keys, paths);
    expect_string(__wrap_fim_realtime_event, file, "/test");

    test_mode = 1;
    realtime_process();
    test_mode = 0;
}

void test_realtime_process_len_path_separator(void **state) {
    struct inotify_event *event = *state;
    event->wd = 1;
    event->mask = 2;
    event->cookie = 0;
    event->len = 5;
    strcpy(event->name, "test");

    syscheck.realtime->fd = 1;

    will_return(__wrap_read, event);
    will_return(__wrap_read, 21);

    expect_value(__wrap_OSHash_Get, self, syscheck.realtime->dirtb);
    expect_string(__wrap_OSHash_Get, key, "1");
    will_return(__wrap_OSHash_Get, "test/");

    expect_string(__wrap__mdebug2, formatted_msg, "Duplicate event in real-time buffer: test/test");
    char **paths = NULL;
    paths = os_AddStrArray("/test", paths);
    will_return(__wrap_rbtree_keys, paths);
    expect_string(__wrap_fim_realtime_event, file, "/test");

    test_mode = 1;
    realtime_process();
    test_mode = 0;
}

void test_realtime_process_overflow(void **state) {
    struct inotify_event *event = *state;
    event->wd = -1;
    event->mask = 16384;
    event->cookie = 0;
    event->len = 5;
    strcpy(event->name, "test");

    syscheck.realtime->fd = 1;

    will_return(__wrap_read, event);
    will_return(__wrap_read, 21);

    expect_string(__wrap__mwarn, formatted_msg, "Real-time inotify kernel queue is full. Some events may be lost. Next scheduled scan will recover lost data.");
    expect_string(__wrap_send_log_msg, msg, "ossec: Real-time inotify kernel queue is full. Some events may be lost. Next scheduled scan will recover lost data.");
    will_return(__wrap_send_log_msg, 1);
    char **paths = NULL;
    paths = os_AddStrArray("/test", paths);
    will_return(__wrap_rbtree_keys, paths);
    expect_string(__wrap_fim_realtime_event, file, "/test");

    realtime_process();
}

void test_realtime_process_delete(void **state) {
    struct inotify_event *event = *state;
    event->wd = 1;
    event->mask = 1024;
    event->cookie = 0;
    event->len = 5;
    strcpy(event->name, "test");

    syscheck.realtime->fd = 1;

    will_return(__wrap_read, event);
    will_return(__wrap_read, 21);

    expect_value(__wrap_OSHash_Get, self, syscheck.realtime->dirtb);
    expect_string(__wrap_OSHash_Get, key, "1");
    will_return(__wrap_OSHash_Get, "test");

    expect_string(__wrap__mdebug2, formatted_msg, "Duplicate event in real-time buffer: test/test");
    expect_function_call(__wrap_pthread_mutex_lock);

    char *data = strdup("delete this");
    expect_value(__wrap_OSHash_Delete_ex, self, syscheck.realtime->dirtb);
    expect_string(__wrap_OSHash_Delete_ex, key, "1");
    will_return(__wrap_OSHash_Delete_ex, data);

    expect_string(__wrap__mdebug2, formatted_msg, "(6344): Inotify watch deleted for 'test'");
    expect_function_call(__wrap_pthread_mutex_unlock);
    char **paths = NULL;
    paths = os_AddStrArray("/test", paths);
    will_return(__wrap_rbtree_keys, paths);
    expect_string(__wrap_fim_realtime_event, file, "/test");

    test_mode = 1;
    realtime_process();
    test_mode = 0;
}

void test_realtime_process_move_self(void **state) {
    realtime_process_data *data = *state;
    struct inotify_event *event = data->event;

    event->wd = 1;
    event->mask = 2048;
    event->cookie = 0;
    event->len = 5;
    strcpy(event->name, "test");

    syscheck.realtime->fd = 1;

    will_return(__wrap_read, event);
    will_return(__wrap_read, 21);

    expect_value(__wrap_OSHash_Get, self, syscheck.realtime->dirtb);
    expect_string(__wrap_OSHash_Get, key, "1");
    will_return(__wrap_OSHash_Get, "test");

    expect_string(__wrap__mdebug2, formatted_msg, "Duplicate event in real-time buffer: test/test");

    // In delete_subdirectories_watches
    OSHashNode *node = data->node;

    node->data = "test/sub";

    syscheck.realtime->fd = 1;

    expect_value(__wrap_OSHash_Begin, self, syscheck.realtime->dirtb);
    will_return(__wrap_OSHash_Begin, node);

    expect_string(__wrap__mdebug2, formatted_msg, "(6344): Inotify watch deleted for 'test/sub'");

    expect_value(__wrap_OSHash_Begin, self, syscheck.realtime->dirtb);
    will_return(__wrap_OSHash_Begin, NULL);

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    // Back to realtime_process
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    char *str_data = strdup("delete this");
    expect_value_count(__wrap_OSHash_Delete_ex, self, syscheck.realtime->dirtb, 2);
    expect_string(__wrap_OSHash_Delete_ex, key, "dummy_key");
    expect_string(__wrap_OSHash_Delete_ex, key, "1");
    will_return(__wrap_OSHash_Delete_ex, str_data);
    will_return(__wrap_OSHash_Delete_ex, NULL);

    expect_string(__wrap__mdebug2, formatted_msg, "(6344): Inotify watch deleted for 'test'");

    char **paths = NULL;
    paths = os_AddStrArray("/test", paths);
    will_return(__wrap_rbtree_keys, paths);
    expect_string(__wrap_fim_realtime_event, file, "/test");

    test_mode = 1;
    realtime_process();
    test_mode = 0;
}

void test_realtime_process_failure(void **state)
{
    (void) state;

    syscheck.realtime->fd = 1;

    will_return(__wrap_read, NULL);
    will_return(__wrap_read, 0);

    expect_string(__wrap__merror, formatted_msg, FIM_ERROR_REALTIME_READ_BUFFER);

    realtime_process();
}

void test_delete_subdirectories_watches_realtime_fd_null(void **state) {
    (void) state;
    char *dir = "/test";

    syscheck.realtime->fd = 0;

    delete_subdirectories_watches(dir);
}

void test_delete_subdirectories_watches_hash_node_null(void **state) {
    (void) state;
    char *dir = "/test";
    int inode_it = 0;

    syscheck.realtime->fd = 1;

    expect_function_call(__wrap_pthread_mutex_lock);

    expect_value(__wrap_OSHash_Begin, self, syscheck.realtime->dirtb);
    will_return(__wrap_OSHash_Begin, NULL);

    expect_function_call(__wrap_pthread_mutex_unlock);

    delete_subdirectories_watches(dir);
}

void test_delete_subdirectories_watches_not_same_name(void **state) {
    (void) state;
    char *dir = "/test/";
    OSHashNode *node = *state;

    node->data = "/other/sub";

    syscheck.realtime->fd = 1;

    expect_function_call(__wrap_pthread_mutex_lock);
    expect_value(__wrap_OSHash_Begin, self, syscheck.realtime->dirtb);
    will_return(__wrap_OSHash_Begin, node);

    expect_value(__wrap_OSHash_Next, self, syscheck.realtime->dirtb);
    will_return(__wrap_OSHash_Next, NULL);

    expect_function_call(__wrap_pthread_mutex_unlock);

    delete_subdirectories_watches(dir);
}

void test_delete_subdirectories_watches_deletes(void **state) {
    (void) state;
    char *dir = "/test";
    OSHashNode *node = *state;

    node->data = "/test/sub";

    syscheck.realtime->fd = 1;

    expect_function_call(__wrap_pthread_mutex_lock);

    expect_value(__wrap_OSHash_Begin, self, syscheck.realtime->dirtb);
    will_return(__wrap_OSHash_Begin, node);

    char *data = strdup("delete this");
    expect_value(__wrap_OSHash_Delete_ex, self, syscheck.realtime->dirtb);
    expect_string(__wrap_OSHash_Delete_ex, key, "dummy_key");
    will_return(__wrap_OSHash_Delete_ex, data);

    expect_string(__wrap__mdebug2, formatted_msg, "(6344): Inotify watch deleted for '/test/sub'");

    expect_value(__wrap_OSHash_Begin, self, syscheck.realtime->dirtb);
    will_return(__wrap_OSHash_Begin, NULL);

    expect_function_call(__wrap_pthread_mutex_unlock);

    test_mode = 1;
    delete_subdirectories_watches(dir);
    test_mode = 0;
}

#else // TEST_WINAGENT
void test_realtime_win32read_success(void **state) {
    win32rtfim rtlocal;
    int ret;

    will_return(wrap_ReadDirectoryChangesW, 1);

    ret = realtime_win32read(&rtlocal);

    assert_int_equal(ret, 1);
}

void test_realtime_win32read_unable_to_read_directory(void **state) {
    win32rtfim rtlocal;
    int ret;

    rtlocal.dir = "C:\\a\\path";

    will_return(wrap_ReadDirectoryChangesW, 0);

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

    free_win32rtfim_data(data);
}

void test_realtime_adddir_whodata_non_existent_file(void **state) {
    int ret;

    syscheck.wdata.dirs_status[0].status &= ~WD_CHECK_WHODATA;
    syscheck.wdata.dirs_status[0].status |= WD_CHECK_REALTIME;

    expect_string(__wrap_check_path_type, dir, "C:\\a\\path");
    will_return(__wrap_check_path_type, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "(6907): 'C:\\a\\path' does not exist. Monitoring discarded.");

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
        "(6619): Unable to add directory to whodata real time monitoring: 'C:\\a\\path'. It will be monitored in Realtime");

    ret = realtime_adddir("C:\\a\\path", 1, 0);

    assert_int_equal(ret, -2);
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

    expect_function_call(__wrap_OSHash_Create);
    will_return(__wrap_OSHash_Create, NULL);

    expect_string(__wrap__merror, formatted_msg, "(1102): Could not acquire memory due to [(0)-(Success)].");

    ret = realtime_adddir("C:\\a\\path", 0, 0);

    assert_int_equal(ret, -1);
}

void test_realtime_adddir_max_limit_reached(void **state) {
    int ret;

    syscheck.realtime->fd = 1024;

    expect_function_call(__wrap_pthread_mutex_lock);

    expect_string(__wrap__merror, formatted_msg,
        "(6616): Unable to add directory to real time monitoring: 'C:\\a\\path' - Maximum size permitted.");

    expect_function_call(__wrap_pthread_mutex_unlock);

    ret = realtime_adddir("C:\\a\\path", 0, 0);

    assert_int_equal(ret, 0);
}

void test_realtime_adddir_duplicate_entry(void **state) {
    int ret;

    syscheck.realtime->fd = 128;

    expect_function_call(__wrap_pthread_mutex_lock);

    expect_value(__wrap_OSHash_Get_ex, self, syscheck.realtime->dirtb);
    expect_string(__wrap_OSHash_Get_ex, key, "C:\\a\\path");
    will_return(__wrap_OSHash_Get_ex, 1);

    expect_string(__wrap_w_directory_exists, path, "C:\\a\\path");
    will_return(__wrap_w_directory_exists, 1);

    expect_function_call(__wrap_pthread_mutex_unlock);

    ret = realtime_adddir("C:\\a\\path", 0, 0);

    assert_int_equal(ret, 1);
}

void test_realtime_adddir_handle_error(void **state) {
    int ret;

    syscheck.realtime->fd = 128;

    expect_function_call(__wrap_pthread_mutex_lock);

    expect_value(__wrap_OSHash_Get_ex, self, syscheck.realtime->dirtb);
    expect_string(__wrap_OSHash_Get_ex, key, "C:\\a\\path");
    will_return(__wrap_OSHash_Get_ex, 0);

    expect_string(wrap_CreateFile, lpFileName, "C:\\a\\path");
    will_return(wrap_CreateFile, INVALID_HANDLE_VALUE);

    expect_string(__wrap__mdebug2, formatted_msg,
        "(6290): Unable to add directory to real time monitoring: 'C:\\a\\path'");

    expect_function_call(__wrap_pthread_mutex_unlock);

    ret = realtime_adddir("C:\\a\\path", 0, 0);

    assert_int_equal(ret, 0);
}

void test_realtime_adddir_success(void **state) {
    int ret;
    syscheck.realtime->dirtb = *state;

    expect_function_call(__wrap_pthread_mutex_lock);

    expect_value(__wrap_OSHash_Get_ex, self, syscheck.realtime->dirtb);
    expect_string(__wrap_OSHash_Get_ex, key, "C:\\a\\path");
    will_return(__wrap_OSHash_Get_ex, 0);

    expect_string(wrap_CreateFile, lpFileName, "C:\\a\\path");
    will_return(wrap_CreateFile, (HANDLE)123456);

    will_return(wrap_ReadDirectoryChangesW, 1);

    expect_string(__wrap__mdebug1, formatted_msg,
                  "(6227): Directory added for real time monitoring: 'C:\\a\\path'");
    expect_function_call(__wrap_pthread_mutex_unlock);

    test_mode = 0;
    ret = realtime_adddir("C:\\a\\path", 0, 0);
    test_mode = 1;

    assert_int_equal(ret, 1);
}

void test_RTCallBack_error_on_callback(void **state) {
    OVERLAPPED ov;

    will_return(wrap_FormatMessage, "Path not found.");
    expect_string(__wrap__merror, formatted_msg, "(6613): Real time Windows callback process: 'Path not found.' (3).");

    RTCallBack(ERROR_PATH_NOT_FOUND, 0, &ov);
}

void test_RTCallBack_empty_hash_table(void **state) {
    OVERLAPPED ov;

    expect_value(__wrap_OSHash_Get, self, syscheck.realtime->dirtb);
    expect_any(__wrap_OSHash_Get, key);
    will_return(__wrap_OSHash_Get, NULL);

    expect_string(__wrap__merror, formatted_msg, FIM_ERROR_REALTIME_WINDOWS_CALLBACK_EMPTY);

    RTCallBack(ERROR_SUCCESS, 1, &ov);
}

void test_RTCallBack_no_bytes_returned(void **state) {
    win32rtfim *rt = *state;
    OVERLAPPED ov;

    rt->watch_status = 1;

    expect_value(__wrap_OSHash_Get, self, syscheck.realtime->dirtb);
    expect_any(__wrap_OSHash_Get, key);
    will_return(__wrap_OSHash_Get, rt);

    expect_string(__wrap__mwarn, formatted_msg, FIM_WARN_REALTIME_OVERFLOW);

    // Inside realtime_win32read
    will_return(wrap_ReadDirectoryChangesW, 1);

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
    rt->watch_status = 1;

    ov.Pointer = "C:\\a\\path";

    // Begin calls to mock functions

    expect_value(__wrap_OSHash_Get, self, syscheck.realtime->dirtb);
    expect_string(__wrap_OSHash_Get, key, "C:\\a\\path");
    will_return(__wrap_OSHash_Get, rt);

    expect_string(__wrap_fim_configuration_directory, path, "C:\\a\\path");
    expect_string(__wrap_fim_configuration_directory, entry, "file");
    will_return(__wrap_fim_configuration_directory, 0);

    expect_string(__wrap_fim_configuration_directory, path, "");
    expect_string(__wrap_fim_configuration_directory, entry, "file");
    will_return(__wrap_fim_configuration_directory, -1);

    // Inside realtime_win32read
    will_return(wrap_ReadDirectoryChangesW, 1);

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
    rt->watch_status = 1;

    ov.Pointer = "C:\\a\\path\\file.test";

    // Begin calls to mock functions

    expect_value(__wrap_OSHash_Get, self, syscheck.realtime->dirtb);
    expect_string(__wrap_OSHash_Get, key, "C:\\a\\path\\file.test");
    will_return(__wrap_OSHash_Get, rt);

    expect_string(__wrap_fim_configuration_directory, path, "C:\\a\\path\\file.test");
    expect_string(__wrap_fim_configuration_directory, entry, "file");
    will_return(__wrap_fim_configuration_directory, 0);

    expect_string(__wrap_fim_configuration_directory, path, "c:\\a\\path\\file.test");
    expect_string(__wrap_fim_configuration_directory, entry, "file");
    will_return(__wrap_fim_configuration_directory, 0);

    expect_string(__wrap_fim_realtime_event, file, "c:\\a\\path\\file.test");

    // Inside realtime_win32read
    will_return(wrap_ReadDirectoryChangesW, 1);

    RTCallBack(ERROR_SUCCESS, 1, &ov);
}
#endif

int main(void) {
#ifndef WIN_WHODATA
    const struct CMUnitTest tests[] = {
        /* realtime_start */
        cmocka_unit_test_setup_teardown(test_realtime_start_success, setup_realtime_start, teardown_realtime_start),
        cmocka_unit_test_setup_teardown(test_realtime_start_failure_hash, setup_realtime_start, teardown_realtime_start),

#if defined(TEST_SERVER) || defined(TEST_AGENT)
        cmocka_unit_test_setup_teardown(test_realtime_start_failure_inotify, setup_realtime_start, teardown_realtime_start),

        /* realtime_adddir */
        cmocka_unit_test_setup_teardown(test_realtime_adddir_whodata, setup_w_vector, teardown_w_vector),
        cmocka_unit_test_setup_teardown(test_realtime_adddir_whodata_new_directory, setup_w_vector, teardown_w_vector),
        cmocka_unit_test_setup_teardown(test_realtime_adddir_realtime_start_failure, setup_realtime_adddir_realtime_start_error, teardown_realtime_adddir_realtime_start_error),
        cmocka_unit_test(test_realtime_adddir_realtime_failure),
        cmocka_unit_test(test_realtime_adddir_realtime_watch_max_reached_failure),
        cmocka_unit_test(test_realtime_adddir_realtime_watch_generic_failure),
        cmocka_unit_test_setup_teardown(test_realtime_adddir_realtime_add, setup_OSHash, teardown_OSHash),
        cmocka_unit_test(test_realtime_adddir_realtime_add_hash_failure),
        cmocka_unit_test(test_realtime_adddir_realtime_update),
        cmocka_unit_test(test_realtime_adddir_realtime_update_failure),

        /* free_syscheck_dirtb_data */
        cmocka_unit_test(test_free_syscheck_dirtb_data),
        cmocka_unit_test(test_free_syscheck_dirtb_data_null),

        /* realtime_process */
        cmocka_unit_test(test_realtime_process),
        cmocka_unit_test_setup_teardown(test_realtime_process_len, setup_inotify_event, teardown_inotify_event),
        cmocka_unit_test_setup_teardown(test_realtime_process_len_zero, setup_inotify_event, teardown_inotify_event),
        cmocka_unit_test_setup_teardown(test_realtime_process_len_path_separator, setup_inotify_event, teardown_inotify_event),
        cmocka_unit_test_setup_teardown(test_realtime_process_overflow, setup_inotify_event, teardown_inotify_event),
        cmocka_unit_test_setup_teardown(test_realtime_process_delete, setup_inotify_event, teardown_inotify_event),
        cmocka_unit_test_setup_teardown(test_realtime_process_move_self, setup_realtime_process, teardown_realtime_process),
        cmocka_unit_test(test_realtime_process_failure),

        /* delete_subdirectories_watches */
        cmocka_unit_test_setup_teardown(test_delete_subdirectories_watches_realtime_fd_null, setup_hash_node, teardown_hash_node),
        cmocka_unit_test_setup_teardown(test_delete_subdirectories_watches_hash_node_null, setup_hash_node, teardown_hash_node),
        cmocka_unit_test_setup_teardown(test_delete_subdirectories_watches_not_same_name, setup_hash_node, teardown_hash_node),
        cmocka_unit_test_setup_teardown(test_delete_subdirectories_watches_deletes, setup_hash_node, teardown_hash_node),

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

        /* count_watches */
        cmocka_unit_test_setup_teardown(test_count_watches_realtime_null, setup_hash_node, teardown_hash_node),
        cmocka_unit_test_setup_teardown(test_count_watches_hash_node_null, setup_hash_node, teardown_hash_node),
        cmocka_unit_test_setup_teardown(test_count_watches_counting, setup_hash_node, teardown_hash_node),
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
        cmocka_unit_test_setup_teardown(test_realtime_adddir_success, setup_OSHash, teardown_OSHash),
    };
#endif

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
