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
#include <string.h>

#include "../wrappers/common.h"
#include "../wrappers/posix/stat_wrappers.h"
#include "../wrappers/linux/inotify_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/file_op_wrappers.h"
#include "../wrappers/wazuh/shared/hash_op_wrappers.h"
#include "../wrappers/wazuh/shared/mq_op_wrappers.h"
#include "../wrappers/wazuh/shared/randombytes_wrappers.h"
#include "../wrappers/wazuh/syscheckd/create_db_wrappers.h"
#include "../wrappers/wazuh/syscheckd/fim_db_wrappers.h"
#include "../wrappers/wazuh/syscheckd/run_realtime_wrappers.h"
#include "../wrappers/wazuh/syscheckd/win_whodata_wrappers.h"

#include "../syscheckd/include/syscheck.h"
#include "../syscheckd/src/db/include/db.h"
#include "../config/syscheck-config.h"

#ifdef TEST_WINAGENT
#include "../wrappers/windows/processthreadsapi_wrappers.h"

void set_priority_windows_thread();
void set_whodata_mode_changes();
#endif

/* External 'static' functions prototypes */
void fim_send_msg(char mq, const char * location, const char * msg);
#ifdef WIN32
DWORD WINAPI fim_run_realtime(__attribute__((unused)) void * args);

extern void free_win32rtfim_data(win32rtfim *data);

#else
void * fim_run_realtime(__attribute__((unused)) void * args);
#endif

#ifndef TEST_WINAGENT
void fim_link_update(const char *new_path, directory_t *configuration);
void fim_link_check_delete(directory_t *configuration);
void fim_link_delete_range(const directory_t *configuration);
void fim_link_silent_scan(char *path, directory_t *configuration);
void fim_link_reload_broken_link(char *path, directory_t *configuration);
void fim_realtime_delete_watches(const directory_t *configuration);
#endif

extern time_t last_time;
extern unsigned int files_read;

/* redefinitons/wrapping */

#ifdef TEST_WINAGENT
int __wrap_audit_restore(void) {
    return mock();
}
#else
time_t __wrap_time(time_t *timer) {
    return mock_type(time_t);
}

#endif


extern bool fim_shutdown_process_on();
/* Setup/Teardown */

static int setup_group(void ** state) {
#ifdef TEST_WINAGENT
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);

    expect_string(__wrap__mdebug1, formatted_msg, "(6287): Reading configuration file: 'test_syscheck.conf'");
    expect_string(__wrap__mdebug1, formatted_msg, "Found ignore regex node .log$|.htm$|.jpg$|.png$|.chm$|.pnf$|.evtx$|.swp$");
    expect_string(__wrap__mdebug1, formatted_msg, "Found ignore regex node .log$|.htm$|.jpg$|.png$|.chm$|.pnf$|.evtx$|.swp$ OK?");
    expect_string(__wrap__mdebug1, formatted_msg, "Found ignore regex size 0");
    expect_string(__wrap__mdebug1, formatted_msg, "Found nodiff regex node ^file");
    expect_string(__wrap__mdebug1, formatted_msg, "Found nodiff regex node ^file OK?");
    expect_string(__wrap__mdebug1, formatted_msg, "Found nodiff regex size 0");
    expect_string(__wrap__mdebug1, formatted_msg, "Found nodiff regex node test_$");
    expect_string(__wrap__mdebug1, formatted_msg, "Found nodiff regex node test_$ OK?");
    expect_string(__wrap__mdebug1, formatted_msg, "Found nodiff regex size 1");
#else // !TEST_WINAGENT
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_string(__wrap__mdebug1, formatted_msg, "(6287): Reading configuration file: 'test_syscheck.conf'");
    expect_string(__wrap__mdebug1, formatted_msg, "Found ignore regex node .log$|.swp$");
    expect_string(__wrap__mdebug1, formatted_msg, "Found ignore regex node .log$|.swp$ OK?");
    expect_string(__wrap__mdebug1, formatted_msg, "Found ignore regex size 0");
    expect_string(__wrap__mdebug1, formatted_msg, "Found nodiff regex node ^file");
    expect_string(__wrap__mdebug1, formatted_msg, "Found nodiff regex node ^file OK?");
    expect_string(__wrap__mdebug1, formatted_msg, "Found nodiff regex size 0");

#endif // TEST_WINAGENT
#if defined(TEST_AGENT) || defined(TEST_WINAGENT)
    expect_string(__wrap__mdebug1, formatted_msg, "(6208): Reading Client Configuration [test_syscheck.conf]");
#endif

    will_return_always(__wrap_os_random, 12345);

    if(Read_Syscheck_Config("test_syscheck.conf"))
        fail();

    syscheck.realtime = (rtfim *) calloc(1, sizeof(rtfim));
    if(syscheck.realtime == NULL) {
        return -1;
    }
#ifndef TEST_WINAGENT
    will_return(__wrap_time, 1);
#endif
    syscheck.realtime->dirtb = OSHash_Create();
    if (syscheck.realtime->dirtb == NULL) {
        return -1;
    }


#ifdef TEST_WINAGENT
    time_mock_value = 1;
#else
    OSHash_Add_ex(syscheck.realtime->dirtb, "key", strdup("data"));
#endif
    return 0;
}

#ifndef TEST_WINAGENT

static int setup_symbolic_links(void **state) {
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);

    directory_t *config = (directory_t *)OSList_GetDataFromIndex(syscheck.directories, 1);

    if (config->path != NULL) {
        free(config->path);
        config->path = NULL;
    }

    config->path = strdup("/link");
    config->symbolic_links = strdup("/folder");
    config->options |= REALTIME_ACTIVE;

    if (config->path == NULL || config->symbolic_links == NULL) {
        return -1;
    }

    return 0;
}

static int teardown_symbolic_links(void **state) {
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);

    directory_t *config = (directory_t *)OSList_GetDataFromIndex(syscheck.directories, 1);
    if (config->path != NULL) {
        free(config->path);
        config->path = NULL;
    }

    if (config->symbolic_links != NULL) {
        free(config->symbolic_links);
        config->symbolic_links = NULL;
    }

    config->path = strdup("/etc");
    config->options &= ~REALTIME_ACTIVE;

    if (config->path == NULL) {
        return -1;
    }

    return 0;
}

static int setup_tmp_file(void **state) {
    fim_tmp_file *tmp_file = calloc(1, sizeof(fim_tmp_file));
    tmp_file->elements = 1;

    if (setup_symbolic_links(NULL) < 0) {
        return -1;
    }

    *state = tmp_file;

    return 0;
}

static int teardown_tmp_file(void **state) {
    fim_tmp_file *tmp_file = *state;
    free(tmp_file);

    if (teardown_symbolic_links(NULL) < 0) {
        return -1;
    }

    return 0;
}

#endif

static int teardown_group(void **state) {
#ifdef TEST_WINAGENT
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);

    if (syscheck.realtime) {
        if (syscheck.realtime->dirtb) {
            OSHash_Free(syscheck.realtime->dirtb);
        }
        free(syscheck.realtime);
        syscheck.realtime = NULL;
    }
#else
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
#endif

    Free_Syscheck(&syscheck);

    return 0;
}

/**
 * @brief This function loads expect and will_return calls for the function send_sync_msg
*/
static void expect_w_send_sync_msg(const char *msg, const char *locmsg, char location,  bool (*fn_ptr)(), int ret) {
    expect_SendMSGPredicated_call(msg, locmsg, location, fn_ptr, ret);
}

static int setup_max_fps(void **state) {
    syscheck.max_files_per_second = 1;
    return 0;
}

static int teardown_max_fps(void **state) {
    syscheck.max_files_per_second = 0;
    return 0;
}

#ifdef TEST_WINAGENT

static int setup_hash(void **state) {
    directory_t *dir_it;
    OSListNode *node_it;

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);

    win32rtfim *rtlocald;
    rtlocald = calloc(1, sizeof(win32rtfim));
    OSList_foreach(node_it, syscheck.directories) {
        dir_it = node_it->data;
        if (dir_it->options & REALTIME_ACTIVE) {
            OSHash_Add_ex(syscheck.realtime->dirtb, dir_it->path, rtlocald);
        }
    }
    syscheck.realtime->evt = (HANDLE)234;
    return 0;
}

static int teardown_hash(void **state) {
    directory_t *dir_it;
    OSListNode *node_it;

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);

    OSList_foreach(node_it, syscheck.directories) {
        dir_it = node_it->data;
        if (dir_it->options & REALTIME_ACTIVE) {
            free_win32rtfim_data(OSHash_Delete_ex(syscheck.realtime->dirtb, dir_it->path));
        }
    }
    return 0;
}
#endif

static int teardown_dbsync_msg(void **state) {
    char *ret_msg = *state;
    free(ret_msg);
    return 0;
}
/* tests */

void test_fim_whodata_initialize(void **state)
{
    int ret;
#ifdef TEST_WINAGENT
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);

    int i;
    char *dirs[] = {
        "%WINDIR%\\System32\\WindowsPowerShell\\v1.0",
        NULL
    };
    char expanded_dirs[1][OS_SIZE_1024];

    // Expand directories
    for(i = 0; dirs[i]; i++) {
        if(!ExpandEnvironmentStrings(dirs[i], expanded_dirs[i], OS_SIZE_1024))
            fail();

        str_lowercase(expanded_dirs[i]);
        expect_realtime_adddir_call(expanded_dirs[i], 0);
    }
    will_return(__wrap_run_whodata_scan, 0);
    will_return(wrap_CreateThread, (HANDLE)123456);
#endif

    ret = fim_whodata_initialize();

    assert_int_equal(ret, 0);
}

void test_log_realtime_status(void **state)
{
    (void) state;

    log_realtime_status(2);

    expect_string(__wrap__minfo, formatted_msg, FIM_REALTIME_STARTED);
    log_realtime_status(1);
    log_realtime_status(1);

    expect_string(__wrap__minfo, formatted_msg, FIM_REALTIME_PAUSED);
    log_realtime_status(2);
    log_realtime_status(2);

    expect_string(__wrap__minfo, formatted_msg, FIM_REALTIME_RESUMED);
    log_realtime_status(1);
}

#ifndef TEST_WINAGENT

void test_fim_run_realtime_first_error(void **state) {
    char debug_msg[OS_SIZE_128] = {0};
    syscheck.realtime->fd = 4;

    expect_function_call(__wrap_pthread_mutex_lock);
    snprintf(debug_msg, OS_SIZE_128, FIM_NUM_WATCHES, 1);
    expect_string(__wrap__mdebug2, formatted_msg, debug_msg);
    expect_function_call(__wrap_pthread_mutex_unlock);

    will_return(__wrap_FOREVER, 1);
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    will_return(__wrap_select, -1);
    expect_string(__wrap__merror, formatted_msg, FIM_ERROR_SELECT);

    will_return(__wrap_FOREVER, 0);

    fim_run_realtime(NULL);
}

void test_fim_run_realtime_first_timeout(void **state) {
    syscheck.realtime->fd = 4;
    char debug_msg[OS_SIZE_128] = {0};

    expect_function_call(__wrap_pthread_mutex_lock);
    snprintf(debug_msg, OS_SIZE_128, FIM_NUM_WATCHES, 1);
    expect_string(__wrap__mdebug2, formatted_msg, debug_msg);
    expect_function_call(__wrap_pthread_mutex_unlock);

    will_return(__wrap_FOREVER, 1);
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);


    will_return(__wrap_select, 0);

    will_return(__wrap_FOREVER, 0);

    fim_run_realtime(NULL);
}

void test_fim_run_realtime_first_sleep(void **state) {

    syscheck.realtime->fd = -1;
    char debug_msg[OS_SIZE_128] = {0};
    expect_function_call(__wrap_pthread_mutex_lock);
    snprintf(debug_msg, OS_SIZE_128, FIM_NUM_WATCHES, 1);
    expect_string(__wrap__mdebug2, formatted_msg, debug_msg);
    expect_function_call(__wrap_pthread_mutex_unlock);

    will_return(__wrap_FOREVER, 1);
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    expect_value(__wrap_sleep, seconds, SYSCHECK_WAIT);

    will_return(__wrap_FOREVER, 0);

    fim_run_realtime(NULL);
}

void test_fim_run_realtime_first_process(void **state) {
    syscheck.realtime->fd = 4;
    char debug_msg[OS_SIZE_128] = {0};

    expect_function_call(__wrap_pthread_mutex_lock);
    snprintf(debug_msg, OS_SIZE_128, FIM_NUM_WATCHES, 1);
    expect_string(__wrap__mdebug2, formatted_msg, debug_msg);
    expect_function_call(__wrap_pthread_mutex_unlock);

    will_return(__wrap_FOREVER, 1);
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    will_return(__wrap_select, 4);
    expect_function_call(__wrap_realtime_process);
    will_return(__wrap_FOREVER, 0);

    fim_run_realtime(NULL);
}

void test_fim_run_realtime_process_after_timeout(void **state) {
    syscheck.realtime->fd = 4;
    char debug_msg[OS_SIZE_128] = {0};

    expect_function_call(__wrap_pthread_mutex_lock);
    snprintf(debug_msg, OS_SIZE_128, FIM_NUM_WATCHES, 1);
    expect_string(__wrap__mdebug2, formatted_msg, debug_msg);
    expect_function_call(__wrap_pthread_mutex_unlock);

    will_return(__wrap_FOREVER, 1);
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    will_return(__wrap_select, 0);

    will_return(__wrap_FOREVER, 1);
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    will_return(__wrap_select, 4);
    expect_function_call(__wrap_realtime_process);
    will_return(__wrap_FOREVER, 0);

    fim_run_realtime(NULL);
}
#else

void test_fim_run_realtime_w_first_timeout(void **state) {
    char debug_msg[OS_SIZE_128] = {0};
    directory_t *dir_it;
    OSListNode *node_it;
    int added_dirs = 0;

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);

    // set_priority_windows_thread
    expect_string(__wrap__mdebug1, formatted_msg, "(6320): Setting process priority to: '10'");
    will_return(wrap_GetCurrentThread, (HANDLE)123456);
    expect_SetThreadPriority_call((HANDLE)123456, THREAD_PRIORITY_LOWEST, true);


    OSList_foreach(node_it, syscheck.directories) {
        dir_it = node_it->data;
        if (dir_it->options & REALTIME_ACTIVE) {
            expect_string(__wrap_realtime_adddir, dir, dir_it->path);
            will_return(__wrap_realtime_adddir, 0);
            added_dirs++;
        }
    }
    will_return(__wrap_FOREVER, 1);

    snprintf(debug_msg, OS_SIZE_128, FIM_NUM_WATCHES, added_dirs);
    expect_string(__wrap__mdebug2, formatted_msg, debug_msg);

    expect_value(wrap_WaitForSingleObjectEx, hHandle, (DWORD)234);
    expect_value(wrap_WaitForSingleObjectEx, dwMilliseconds, SYSCHECK_WAIT * 1000);
    expect_value(wrap_WaitForSingleObjectEx, bAlertable, TRUE);
    will_return(wrap_WaitForSingleObjectEx, WAIT_FAILED);

    expect_string(__wrap__merror, formatted_msg, FIM_ERROR_REALTIME_WAITSINGLE_OBJECT);
    OSList_foreach(node_it, syscheck.directories) {
        dir_it = node_it->data;
        if (dir_it->options & REALTIME_ACTIVE) {
            expect_string(__wrap_realtime_adddir, dir, dir_it->path);
            will_return(__wrap_realtime_adddir, 0);
            added_dirs++;
        }
    }
    will_return(__wrap_FOREVER, 0);

    fim_run_realtime(NULL);
}

void test_fim_run_realtime_w_wait_success(void **state) {
    char debug_msg[OS_SIZE_128] = {0};
    directory_t *dir_it;
    OSListNode *node_it;
    int added_dirs = 0;

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);

    // set_priority_windows_thread
    expect_string(__wrap__mdebug1, formatted_msg, "(6320): Setting process priority to: '10'");
    will_return(wrap_GetCurrentThread, (HANDLE)123456);
    expect_SetThreadPriority_call((HANDLE)123456, THREAD_PRIORITY_LOWEST, true);


    OSList_foreach(node_it, syscheck.directories) {
        dir_it = node_it->data;
        if (dir_it->options & REALTIME_ACTIVE) {
            expect_string(__wrap_realtime_adddir, dir, dir_it->path);
            will_return(__wrap_realtime_adddir, 0);
            added_dirs++;
        }
    }

    will_return(__wrap_FOREVER, 1);

    snprintf(debug_msg, OS_SIZE_128, FIM_NUM_WATCHES, added_dirs);
    expect_string(__wrap__mdebug2, formatted_msg, debug_msg);

    expect_value(wrap_WaitForSingleObjectEx, hHandle, (DWORD)234);
    expect_value(wrap_WaitForSingleObjectEx, dwMilliseconds, SYSCHECK_WAIT * 1000);
    expect_value(wrap_WaitForSingleObjectEx, bAlertable, TRUE);
    will_return(wrap_WaitForSingleObjectEx, WAIT_IO_COMPLETION);

    OSList_foreach(node_it, syscheck.directories) {
        dir_it = node_it->data;
        if (dir_it->options & REALTIME_ACTIVE) {
            expect_string(__wrap_realtime_adddir, dir, dir_it->path);
            will_return(__wrap_realtime_adddir, 0);
            added_dirs++;
        }
    }

    will_return(__wrap_FOREVER, 0);

    fim_run_realtime(NULL);
}

void test_fim_run_realtime_w_sleep(void **state) {
    char debug_msg[OS_SIZE_128] = {0};
    directory_t *dir_it;
    OSListNode *node_it;
    int added_dirs = 0;

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);

    // set_priority_windows_thread
    expect_string(__wrap__mdebug1, formatted_msg, "(6320): Setting process priority to: '10'");
    will_return(wrap_GetCurrentThread, (HANDLE)123456);
    expect_SetThreadPriority_call((HANDLE)123456, THREAD_PRIORITY_LOWEST, true);


    OSList_foreach(node_it, syscheck.directories) {
        dir_it = node_it->data;
        if (dir_it->options & REALTIME_ACTIVE) {
            expect_string(__wrap_realtime_adddir, dir, dir_it->path);
            will_return(__wrap_realtime_adddir, 0);
        }
    }
    will_return(__wrap_FOREVER, 1);

    expect_value(wrap_Sleep, dwMilliseconds, SYSCHECK_WAIT * 1000);

    OSList_foreach(node_it, syscheck.directories) {
        dir_it = node_it->data;
        if (dir_it->options & REALTIME_ACTIVE) {
            expect_string(__wrap_realtime_adddir, dir, dir_it->path);
            will_return(__wrap_realtime_adddir, 0);
            added_dirs++;
        }
    }

    will_return(__wrap_FOREVER, 0);

    fim_run_realtime(NULL);
}

void test_fim_whodata_initialize_fail_set_policies(void **state)
{
    int ret;
    int i;
    char *dirs[] = {
        "%WINDIR%\\System32\\WindowsPowerShell\\v1.0",
        NULL
    };
    char expanded_dirs[1][OS_SIZE_1024];

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);

    // Expand directories
    for(i = 0; dirs[i]; i++) {
        if(!ExpandEnvironmentStrings(dirs[i], expanded_dirs[i], OS_SIZE_1024))
            fail();

        str_lowercase(expanded_dirs[i]);
        expect_realtime_adddir_call(expanded_dirs[i], 0);
    }

    will_return(__wrap_run_whodata_scan, 1);
    expect_string(__wrap__merror, formatted_msg,
      "(6710): Failed to start the Whodata engine. Directories/files will be monitored in Realtime mode");

    will_return(__wrap_audit_restore, NULL);

    ret = fim_whodata_initialize();

    assert_int_equal(ret, -1);
}

void test_set_priority_windows_thread_highest(void **state) {
    syscheck.process_priority = -10;

    expect_string(__wrap__mdebug1, formatted_msg, "(6320): Setting process priority to: '-10'");

    will_return(wrap_GetCurrentThread, (HANDLE)123456);

    expect_SetThreadPriority_call((HANDLE)123456, THREAD_PRIORITY_HIGHEST, true);

    set_priority_windows_thread();
}

void test_set_priority_windows_thread_above_normal(void **state) {
    syscheck.process_priority = -8;

    expect_string(__wrap__mdebug1, formatted_msg, "(6320): Setting process priority to: '-8'");

    will_return(wrap_GetCurrentThread, (HANDLE)123456);
    expect_SetThreadPriority_call((HANDLE)123456, THREAD_PRIORITY_ABOVE_NORMAL, true);

    set_priority_windows_thread();
}

void test_set_priority_windows_thread_normal(void **state) {
    syscheck.process_priority = 0;

    expect_string(__wrap__mdebug1, formatted_msg, "(6320): Setting process priority to: '0'");

    will_return(wrap_GetCurrentThread, (HANDLE)123456);
    expect_SetThreadPriority_call((HANDLE)123456, THREAD_PRIORITY_NORMAL, true);

    set_priority_windows_thread();
}

void test_set_priority_windows_thread_below_normal(void **state) {
    syscheck.process_priority = 2;

    expect_string(__wrap__mdebug1, formatted_msg, "(6320): Setting process priority to: '2'");

    will_return(wrap_GetCurrentThread, (HANDLE)123456);
    expect_SetThreadPriority_call((HANDLE)123456, THREAD_PRIORITY_BELOW_NORMAL, true);

    set_priority_windows_thread();
}

void test_set_priority_windows_thread_lowest(void **state) {
    syscheck.process_priority = 7;

    expect_string(__wrap__mdebug1, formatted_msg, "(6320): Setting process priority to: '7'");

    will_return(wrap_GetCurrentThread, (HANDLE)123456);
    expect_SetThreadPriority_call((HANDLE)123456, THREAD_PRIORITY_LOWEST, true);

    set_priority_windows_thread();
}

void test_set_priority_windows_thread_idle(void **state) {
    syscheck.process_priority = 20;

    expect_string(__wrap__mdebug1, formatted_msg, "(6320): Setting process priority to: '20'");

    will_return(wrap_GetCurrentThread, (HANDLE)123456);
    expect_SetThreadPriority_call((HANDLE)123456, THREAD_PRIORITY_IDLE, true);

    set_priority_windows_thread();
}

void test_set_priority_windows_thread_error(void **state) {
    syscheck.process_priority = 10;

    expect_string(__wrap__mdebug1, formatted_msg, "(6320): Setting process priority to: '10'");

    will_return(wrap_GetCurrentThread, (HANDLE)123456);
    expect_SetThreadPriority_call((HANDLE)123456, THREAD_PRIORITY_LOWEST, false);

    will_return(wrap_GetLastError, 2345);

    expect_string(__wrap__merror, formatted_msg, "Can't set thread priority: 2345");

    set_priority_windows_thread();
}

#ifdef WIN_WHODATA
void test_set_whodata_mode_changes(void **state) {
    int i;
    char *dirs[] = {
        "%PROGRAMDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        "%WINDIR%\\System32\\wbem",
        "%WINDIR%\\System32\\Windowspowershell\\v1.0",
        NULL
    };
    char expanded_dirs[3][OS_SIZE_1024];

    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);

    // Mark directories to be added in realtime
    ((directory_t *)OSList_GetDataFromIndex(syscheck.directories, 0))->dirs_status.status |= WD_CHECK_REALTIME;
    ((directory_t *)OSList_GetDataFromIndex(syscheck.directories, 0))->dirs_status.status &= ~WD_CHECK_WHODATA;
    ((directory_t *)OSList_GetDataFromIndex(syscheck.directories, 4))->dirs_status.status |= WD_CHECK_REALTIME;
    ((directory_t *)OSList_GetDataFromIndex(syscheck.directories, 4))->dirs_status.status &= ~WD_CHECK_WHODATA;
    ((directory_t *)OSList_GetDataFromIndex(syscheck.directories, 5))->dirs_status.status |= WD_CHECK_REALTIME;
    ((directory_t *)OSList_GetDataFromIndex(syscheck.directories, 5))->dirs_status.status &= ~WD_CHECK_WHODATA;

    // Expand directories
    for(i = 0; dirs[i]; i++) {
        if(!ExpandEnvironmentStrings(dirs[i], expanded_dirs[i], OS_SIZE_1024))
            fail();

        str_lowercase(expanded_dirs[i]);
        expect_realtime_adddir_call(expanded_dirs[i], i % 2 == 0);
    }

    expect_string(__wrap__mdebug1, formatted_msg, "(6225): The 'c:\\programdata\\microsoft\\windows\\start menu\\programs\\startup' directory starts to be monitored in real-time mode.");
    expect_string(__wrap__merror, formatted_msg, "(6611): 'realtime_adddir' failed, the directory 'c:\\windows\\system32\\wbem' couldn't be added to real time mode.");
    expect_string(__wrap__mdebug1, formatted_msg, "(6225): The 'c:\\windows\\system32\\windowspowershell\\v1.0' directory starts to be monitored in real-time mode.");

    set_whodata_mode_changes();
}

void test_fim_whodata_initialize_eventchannel(void **state) {
    int ret;
    int i;
    char *dirs[] = {
        "%WINDIR%\\System32\\WindowsPowerShell\\v1.0",
        NULL
    };
    char expanded_dirs[1][OS_SIZE_1024];

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);

    // Expand directories
    for(i = 0; dirs[i]; i++) {
        if(!ExpandEnvironmentStrings(dirs[i], expanded_dirs[i], OS_SIZE_1024))
            fail();

        str_lowercase(expanded_dirs[i]);
        expect_realtime_adddir_call(expanded_dirs[i], 0);
    }

    will_return(__wrap_run_whodata_scan, 0);

    will_return(wrap_CreateThread, (HANDLE)123456);

    ret = fim_whodata_initialize();

    assert_int_equal(ret, 0);
}
#endif  // WIN_WHODATA
#endif

#ifndef TEST_WINAGENT
void test_fim_link_update(void **state) {
    char *new_path = "/new_path";
    char pattern[PATH_MAX] = {0};

    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    directory_t *affected_config = (directory_t *)OSList_GetDataFromIndex(syscheck.directories, 1);

    expect_string(__wrap_remove_audit_rule_syscheck, path, affected_config->symbolic_links);

    snprintf(pattern, PATH_MAX, "%s%c%%", affected_config->symbolic_links, PATH_SEP);
    expect_fim_db_file_pattern_search(pattern, 0);

    expect_fim_checker_call(new_path, affected_config);
    expect_realtime_adddir_call(new_path, 0);
    expect_string(__wrap_remove_audit_rule_syscheck, path, affected_config->path);

    fim_link_update(new_path, affected_config);

    assert_string_equal(affected_config->path, "/link");
    assert_string_equal(affected_config->symbolic_links, new_path);
}

void test_fim_link_update_already_added(void **state) {
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);

    char *link_path = "/home";
    char error_msg[OS_SIZE_128];
    directory_t *affected_config = (directory_t *)OSList_GetDataFromIndex(syscheck.directories, 1);

    free(affected_config->symbolic_links);
    affected_config->symbolic_links = strdup("/home");

    snprintf(error_msg, OS_SIZE_128, FIM_LINK_ALREADY_ADDED, link_path);

    expect_string(__wrap__mdebug2, formatted_msg, error_msg);

    fim_link_update(link_path, affected_config);

    assert_string_equal(affected_config->path, "/link");
    assert_null(affected_config->symbolic_links);
}

void test_fim_link_check_delete(void **state) {
    char *link_path = "/link";
    char *pointed_folder = "/folder";
    char pattern[PATH_MAX] = {0};

    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    directory_t *affected_config = (directory_t *)OSList_GetDataFromIndex(syscheck.directories, 1);

    expect_string(__wrap_lstat, filename, affected_config->symbolic_links);
    will_return(__wrap_lstat, 0);
    will_return(__wrap_lstat, 0);

    expect_string(__wrap_remove_audit_rule_syscheck, path, affected_config->symbolic_links);

    snprintf(pattern, PATH_MAX, "%s%c%%", affected_config->symbolic_links, PATH_SEP);
    expect_fim_db_file_pattern_search(pattern, 0);

    expect_fim_configuration_directory_call("data", NULL);
    fim_link_check_delete(affected_config);

    assert_string_equal(affected_config->path, link_path);
    assert_null(affected_config->symbolic_links);
}

void test_fim_link_check_delete_lstat_error(void **state) {
    char *link_path = "/link";
    char *pointed_folder = "/folder";
    char error_msg[OS_SIZE_128];

    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    directory_t *affected_config = (directory_t *)OSList_GetDataFromIndex(syscheck.directories, 1);

    expect_string(__wrap_lstat, filename, pointed_folder);
    will_return(__wrap_lstat, 0);
    will_return(__wrap_lstat, -1);
    errno = 0;

    snprintf(error_msg, OS_SIZE_128, FIM_STAT_FAILED, pointed_folder, 0, "Success");

    expect_string(__wrap__mdebug1, formatted_msg, error_msg);

    fim_link_check_delete(affected_config);

    assert_string_equal(affected_config->path, link_path);
    assert_string_equal(affected_config->symbolic_links, pointed_folder);
}

void test_fim_link_check_delete_noentry_error(void **state) {
    char *link_path = "/link";
    char *pointed_folder = "/folder";

    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    directory_t *affected_config = (directory_t *)OSList_GetDataFromIndex(syscheck.directories, 1);

    expect_string(__wrap_lstat, filename, pointed_folder);
    will_return(__wrap_lstat, 0);
    will_return(__wrap_lstat, -1);
    expect_string(__wrap_remove_audit_rule_syscheck, path, affected_config->symbolic_links);

    errno = ENOENT;

    fim_link_check_delete(affected_config);

    errno = 0;

    assert_string_equal(affected_config->path, link_path);
    assert_null(affected_config->symbolic_links);
}

void test_fim_delete_realtime_watches(void **state) {
    unsigned int pos;
    char *link_path = "/link";
    char *pointed_folder = "/folder";

    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);

    expect_fim_configuration_directory_call("data", ((directory_t *)OSList_GetDataFromIndex(syscheck.directories, 1)));

    will_return(__wrap_inotify_rm_watch, 1);

    fim_realtime_delete_watches(((directory_t *)OSList_GetDataFromIndex(syscheck.directories, 1)));

    assert_null(OSHash_Begin(syscheck.realtime->dirtb, &pos));
}

void test_fim_link_delete_range(void **state) {
    fim_tmp_file *tmp_file = *state;
    char pattern[PATH_MAX] = {0};

    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);

    snprintf(pattern, PATH_MAX, "%s%c%%", "/folder", PATH_SEP);
    expect_fim_db_file_pattern_search(pattern, 0);

    fim_link_delete_range(((directory_t *)OSList_GetDataFromIndex(syscheck.directories, 1)));
}

void test_fim_link_silent_scan(void **state) {
    char *link_path = "/link";

    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);

    directory_t *affected_config = (directory_t *)OSList_GetDataFromIndex(syscheck.directories, 3);

    expect_realtime_adddir_call(link_path, 0);
    expect_fim_checker_call(link_path, affected_config);

    fim_link_silent_scan(link_path, affected_config);
}

void test_fim_link_reload_broken_link_already_monitored(void **state) {
    char *link_path = "/link";
    char *pointed_folder = "/folder";
    char error_msg[OS_SIZE_128];

    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);

    directory_t *affected_config = (directory_t *)OSList_GetDataFromIndex(syscheck.directories, 1);

    snprintf(error_msg, OS_SIZE_128, FIM_LINK_ALREADY_ADDED, link_path);

    expect_string(__wrap__mdebug2, formatted_msg, error_msg);

    fim_link_reload_broken_link(link_path, affected_config);

    assert_string_equal(affected_config->path, link_path);
    assert_string_equal(affected_config->symbolic_links, pointed_folder);
}

void test_fim_link_reload_broken_link_reload_broken(void **state) {
    char *link_path = "/link";
    char *pointed_folder = "/new_path";

    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);

    directory_t *affected_config = (directory_t *)OSList_GetDataFromIndex(syscheck.directories, 1);

    expect_fim_checker_call(pointed_folder, affected_config);

    expect_string(__wrap_realtime_adddir, dir, pointed_folder);
    will_return(__wrap_realtime_adddir, 0);

    expect_string(__wrap_remove_audit_rule_syscheck, path, link_path);

    fim_link_reload_broken_link(pointed_folder, affected_config);

    assert_string_equal(affected_config->path, link_path);
    assert_string_equal(affected_config->symbolic_links, pointed_folder);
}
#endif

void test_check_max_fps_no_sleep(void **state) {
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    will_return(__wrap_gettime, last_time + 1);

    check_max_fps();
}

void test_check_max_fps_sleep(void **state) {
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);
    last_time = 10;
    files_read = syscheck.max_files_per_second;

    will_return(__wrap_gettime, last_time);
    expect_string(__wrap__mdebug2, formatted_msg, FIM_REACHED_MAX_FPS);
    check_max_fps();
}

int main(void) {
#ifndef WIN_WHODATA
    const struct CMUnitTest tests[] = {
#ifdef TEST_WINAGENT
        cmocka_unit_test(test_set_priority_windows_thread_highest),
        cmocka_unit_test(test_set_priority_windows_thread_above_normal),
        cmocka_unit_test(test_set_priority_windows_thread_normal),
        cmocka_unit_test(test_set_priority_windows_thread_below_normal),
        cmocka_unit_test(test_set_priority_windows_thread_lowest),
        cmocka_unit_test(test_set_priority_windows_thread_idle),
        cmocka_unit_test(test_set_priority_windows_thread_error),
#endif

        cmocka_unit_test(test_log_realtime_status),
        cmocka_unit_test_setup_teardown(test_check_max_fps_no_sleep, setup_max_fps, teardown_max_fps),
        cmocka_unit_test_setup_teardown(test_check_max_fps_sleep, setup_max_fps, teardown_max_fps),
#ifndef TEST_WINAGENT
        cmocka_unit_test(test_fim_run_realtime_first_error),
        cmocka_unit_test(test_fim_run_realtime_first_timeout),
        cmocka_unit_test(test_fim_run_realtime_first_sleep),
        cmocka_unit_test(test_fim_run_realtime_first_process),
        cmocka_unit_test(test_fim_run_realtime_process_after_timeout),
        cmocka_unit_test_setup_teardown(test_fim_link_update, setup_symbolic_links, teardown_symbolic_links),
        cmocka_unit_test_setup_teardown(test_fim_link_update_already_added, setup_symbolic_links, teardown_symbolic_links),
        cmocka_unit_test_setup_teardown(test_fim_link_check_delete, setup_symbolic_links, teardown_symbolic_links),
        cmocka_unit_test_setup_teardown(test_fim_link_check_delete_lstat_error, setup_symbolic_links, teardown_symbolic_links),
        cmocka_unit_test_setup_teardown(test_fim_link_check_delete_noentry_error, setup_symbolic_links, teardown_symbolic_links),
        cmocka_unit_test_setup_teardown(test_fim_delete_realtime_watches, setup_symbolic_links, teardown_symbolic_links),
        cmocka_unit_test_setup_teardown(test_fim_link_delete_range, setup_tmp_file, teardown_tmp_file),
        cmocka_unit_test_setup_teardown(test_fim_link_silent_scan, setup_symbolic_links, teardown_symbolic_links),
        cmocka_unit_test_setup_teardown(test_fim_link_reload_broken_link_already_monitored, setup_symbolic_links, teardown_symbolic_links),
        cmocka_unit_test_setup_teardown(test_fim_link_reload_broken_link_reload_broken, setup_symbolic_links, teardown_symbolic_links),
#else
        cmocka_unit_test_setup_teardown(test_fim_run_realtime_w_first_timeout, setup_hash, teardown_hash),
        cmocka_unit_test_setup_teardown(test_fim_run_realtime_w_wait_success, setup_hash, teardown_hash),
        cmocka_unit_test(test_fim_run_realtime_w_sleep),
#endif
    };

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
#else  // WIN_WHODATA
    const struct CMUnitTest eventchannel_tests[] = {
        cmocka_unit_test(test_fim_whodata_initialize),
        cmocka_unit_test(test_set_whodata_mode_changes),
        cmocka_unit_test(test_fim_whodata_initialize_eventchannel),
        cmocka_unit_test(test_fim_whodata_initialize_fail_set_policies),
    };
    return cmocka_run_group_tests(eventchannel_tests, setup_group, teardown_group);
#endif
}
