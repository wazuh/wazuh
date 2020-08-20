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

#include "../wrappers/common.h"
#include "../wrappers/posix/stat_wrappers.h"
#include "../wrappers/linux/inotify_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/mq_op_wrappers.h"
#include "../wrappers/wazuh/shared/randombytes_wrappers.h"
#include "../wrappers/wazuh/syscheckd/create_db_wrappers.h"
#include "../wrappers/wazuh/syscheckd/fim_db_wrappers.h"
#include "../wrappers/wazuh/syscheckd/run_realtime_wrappers.h"
#include "../wrappers/wazuh/syscheckd/win_whodata_wrappers.h"

#include "../syscheckd/syscheck.h"
#include "../syscheckd/fim_db.h"

#ifdef TEST_WINAGENT

void set_priority_windows_thread();
void set_whodata_mode_changes();
#endif

/* External 'static' functions prototypes */
void fim_send_msg(char mq, const char * location, const char * msg);

#ifndef TEST_WINAGENT
void fim_link_update(int pos, char *new_path);
void fim_link_check_delete(int pos);
void fim_link_delete_range(int pos);
void fim_link_silent_scan(char *path, int pos);
void fim_link_reload_broken_link(char *path, int index);
void fim_delete_realtime_watches(int pos);
#endif

/* redefinitons/wrapping */

#ifndef TEST_WINAGENT
int __wrap_time() {
    return 1;
}
#endif

#ifdef TEST_WINAGENT
int __wrap_audit_restore(void) {
    return mock();
}
#endif

/* Setup */

static int setup_group(void ** state) {
#ifdef TEST_WINAGENT
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
#else
    expect_string(__wrap__mdebug1, formatted_msg, "(6287): Reading configuration file: 'test_syscheck.conf'");
    expect_string(__wrap__mdebug1, formatted_msg, "Found ignore regex node .log$|.swp$");
    expect_string(__wrap__mdebug1, formatted_msg, "Found ignore regex node .log$|.swp$ OK?");
    expect_string(__wrap__mdebug1, formatted_msg, "Found ignore regex size 0");
    expect_string(__wrap__mdebug1, formatted_msg, "Found nodiff regex node ^file");
    expect_string(__wrap__mdebug1, formatted_msg, "Found nodiff regex node ^file OK?");
    expect_string(__wrap__mdebug1, formatted_msg, "Found nodiff regex size 0");
#endif

#if defined(TEST_AGENT) || defined(TEST_WINAGENT)
    expect_string(__wrap__mdebug1, formatted_msg, "(6208): Reading Client Configuration [test_syscheck.conf]");
#endif

    will_return_always(__wrap_os_random, 12345);

#ifdef TEST_AGENT
    will_return_always(__wrap_isChroot, 1);
#endif

    if(Read_Syscheck_Config("test_syscheck.conf"))
        fail();

    syscheck.realtime = (rtfim *) calloc(1, sizeof(rtfim));
    if(syscheck.realtime == NULL) {
        return -1;
    }

    syscheck.realtime->dirtb = OSHash_Create();
    if (syscheck.realtime->dirtb == NULL) {
        return -1;
    }

    OSHash_Add_ex(syscheck.realtime->dirtb, "key", strdup("data"));

#ifdef TEST_WINAGENT
    time_mock_value = 1;
#endif

    return 0;
}

#ifndef TEST_WINAGENT
static int setup_tmp_file(void **state) {
    fim_tmp_file *tmp_file = calloc(1, sizeof(fim_tmp_file));
    tmp_file->elements = 1;

    *state = tmp_file;

    return 0;
}
#endif

/* teardown */

static int teardown_group(void **state) {
#ifdef TEST_WINAGENT
    if (syscheck.realtime) {
        if (syscheck.realtime->dirtb) {
            OSHash_Free(syscheck.realtime->dirtb);
        }
        free(syscheck.realtime);
        syscheck.realtime = NULL;
    }
#endif

    Free_Syscheck(&syscheck);

    return 0;
}

#ifndef TEST_WINAGENT
static int teardown_tmp_file(void **state) {
    fim_tmp_file *tmp_file = *state;
    free(tmp_file);

    return 0;
}
#endif

/* tests */

void test_fim_whodata_initialize(void **state)
{
    int ret;
#ifdef TEST_WINAGENT
    int i;
    char *dirs[] = {
        "%WINDIR%\\System32\\WindowsPowerShell\\v1.0",
        NULL
    };
    char expanded_dirs[1][OS_SIZE_1024];
    will_return(wrap_GetCurrentThread, (HANDLE)123456);

    expect_value(wrap_SetThreadPriority, hThread, (HANDLE)123456);
    expect_value(wrap_SetThreadPriority, nPriority, THREAD_PRIORITY_LOWEST);
    will_return(wrap_SetThreadPriority, true);

    expect_string(__wrap__mdebug1, formatted_msg, "(6320): Setting process priority to: '10'");

    // Expand directories
    for(i = 0; dirs[i]; i++) {
        if(!ExpandEnvironmentStrings(dirs[i], expanded_dirs[i], OS_SIZE_1024))
            fail();

        str_lowercase(expanded_dirs[i]);
        expect_string(__wrap_realtime_adddir, dir, expanded_dirs[i]);
        expect_value(__wrap_realtime_adddir, whodata, 10);
        will_return(__wrap_realtime_adddir, 0);
    }
#else
    expect_string(__wrap_realtime_adddir, dir, "/etc");
    expect_value(__wrap_realtime_adddir, whodata, 2);
    will_return(__wrap_realtime_adddir, 0);
    expect_string(__wrap_realtime_adddir, dir, "/usr/bin");
    expect_value(__wrap_realtime_adddir, whodata, 5);
    will_return(__wrap_realtime_adddir, 0);
    expect_string(__wrap_realtime_adddir, dir, "/usr/sbin");
    expect_value(__wrap_realtime_adddir, whodata, 6);
    will_return(__wrap_realtime_adddir, 0);
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

void test_fim_send_msg(void **state) {
    (void) state;

    expect_string(__wrap_SendMSG, message, "test");
    expect_string(__wrap_SendMSG, locmsg, SYSCHECK);
    expect_value(__wrap_SendMSG, loc, SYSCHECK_MQ);
    will_return(__wrap_SendMSG, 0);

    fim_send_msg(SYSCHECK_MQ, SYSCHECK, "test");
}

void test_fim_send_msg_retry(void **state) {
    (void) state;

    expect_string(__wrap_SendMSG, message, "test");
    expect_string(__wrap_SendMSG, locmsg, SYSCHECK);
    expect_value(__wrap_SendMSG, loc, SYSCHECK_MQ);
    will_return(__wrap_SendMSG, -1);

    expect_string(__wrap__merror, formatted_msg, QUEUE_SEND);

    expect_string(__wrap_StartMQ, path, DEFAULTQPATH);
    expect_value(__wrap_StartMQ, type, WRITE);
    will_return(__wrap_StartMQ, 0);

    expect_string(__wrap_SendMSG, message, "test");
    expect_string(__wrap_SendMSG, locmsg, SYSCHECK);
    expect_value(__wrap_SendMSG, loc, SYSCHECK_MQ);
    will_return(__wrap_SendMSG, -1);

    fim_send_msg(SYSCHECK_MQ, SYSCHECK, "test");
}

void test_fim_send_msg_retry_error(void **state) {
    (void) state;

    expect_string(__wrap_SendMSG, message, "test");
    expect_string(__wrap_SendMSG, locmsg, SYSCHECK);
    expect_value(__wrap_SendMSG, loc, SYSCHECK_MQ);
    will_return(__wrap_SendMSG, -1);

    expect_string(__wrap__merror, formatted_msg, QUEUE_SEND);

    expect_string(__wrap_StartMQ, path, DEFAULTQPATH);
    expect_value(__wrap_StartMQ, type, WRITE);
    will_return(__wrap_StartMQ, -1);

    expect_string(__wrap__merror_exit, formatted_msg, "(1211): Unable to access queue: '/var/ossec/queue/ossec/queue'. Giving up.");

    // This code shouldn't run
    expect_string(__wrap_SendMSG, message, "test");
    expect_string(__wrap_SendMSG, locmsg, SYSCHECK);
    expect_value(__wrap_SendMSG, loc, SYSCHECK_MQ);
    will_return(__wrap_SendMSG, -1);

    fim_send_msg(SYSCHECK_MQ, SYSCHECK, "test");
}

#ifdef TEST_WINAGENT

void test_fim_whodata_initialize_fail_set_policies(void **state)
{
    int ret;
    int i;
    char *dirs[] = {
        "%WINDIR%\\System32\\WindowsPowerShell\\v1.0",
        NULL
    };
    char expanded_dirs[1][OS_SIZE_1024];

    will_return(wrap_GetCurrentThread, (HANDLE)123456);

    expect_value(wrap_SetThreadPriority, hThread, (HANDLE)123456);
    expect_value(wrap_SetThreadPriority, nPriority, THREAD_PRIORITY_LOWEST);
    will_return(wrap_SetThreadPriority, true);

    expect_string(__wrap__mdebug1, formatted_msg, "(6320): Setting process priority to: '10'");

    // Expand directories
    for(i = 0; dirs[i]; i++) {
        if(!ExpandEnvironmentStrings(dirs[i], expanded_dirs[i], OS_SIZE_1024))
            fail();

        str_lowercase(expanded_dirs[i]);
        expect_string(__wrap_realtime_adddir, dir, expanded_dirs[i]);
        expect_value(__wrap_realtime_adddir, whodata, 10);
        will_return(__wrap_realtime_adddir, 0);
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

    expect_value(wrap_SetThreadPriority, hThread, (HANDLE)123456);
    expect_value(wrap_SetThreadPriority, nPriority, THREAD_PRIORITY_HIGHEST);
    will_return(wrap_SetThreadPriority, true);

    set_priority_windows_thread();
}

void test_set_priority_windows_thread_above_normal(void **state) {
    syscheck.process_priority = -8;

    expect_string(__wrap__mdebug1, formatted_msg, "(6320): Setting process priority to: '-8'");

    will_return(wrap_GetCurrentThread, (HANDLE)123456);

    expect_value(wrap_SetThreadPriority, hThread, (HANDLE)123456);
    expect_value(wrap_SetThreadPriority, nPriority, THREAD_PRIORITY_ABOVE_NORMAL);
    will_return(wrap_SetThreadPriority, true);

    set_priority_windows_thread();
}

void test_set_priority_windows_thread_normal(void **state) {
    syscheck.process_priority = 0;

    expect_string(__wrap__mdebug1, formatted_msg, "(6320): Setting process priority to: '0'");

    will_return(wrap_GetCurrentThread, (HANDLE)123456);

    expect_value(wrap_SetThreadPriority, hThread, (HANDLE)123456);
    expect_value(wrap_SetThreadPriority, nPriority, THREAD_PRIORITY_NORMAL);
    will_return(wrap_SetThreadPriority, true);

    set_priority_windows_thread();
}

void test_set_priority_windows_thread_below_normal(void **state) {
    syscheck.process_priority = 2;

    expect_string(__wrap__mdebug1, formatted_msg, "(6320): Setting process priority to: '2'");

    will_return(wrap_GetCurrentThread, (HANDLE)123456);

    expect_value(wrap_SetThreadPriority, hThread, (HANDLE)123456);
    expect_value(wrap_SetThreadPriority, nPriority, THREAD_PRIORITY_BELOW_NORMAL);
    will_return(wrap_SetThreadPriority, true);

    set_priority_windows_thread();
}

void test_set_priority_windows_thread_lowest(void **state) {
    syscheck.process_priority = 7;

    expect_string(__wrap__mdebug1, formatted_msg, "(6320): Setting process priority to: '7'");

    will_return(wrap_GetCurrentThread, (HANDLE)123456);

    expect_value(wrap_SetThreadPriority, hThread, (HANDLE)123456);
    expect_value(wrap_SetThreadPriority, nPriority, THREAD_PRIORITY_LOWEST);
    will_return(wrap_SetThreadPriority, true);

    set_priority_windows_thread();
}

void test_set_priority_windows_thread_idle(void **state) {
    syscheck.process_priority = 20;

    expect_string(__wrap__mdebug1, formatted_msg, "(6320): Setting process priority to: '20'");

    will_return(wrap_GetCurrentThread, (HANDLE)123456);

    expect_value(wrap_SetThreadPriority, hThread, (HANDLE)123456);
    expect_value(wrap_SetThreadPriority, nPriority, THREAD_PRIORITY_IDLE);
    will_return(wrap_SetThreadPriority, true);

    set_priority_windows_thread();
}

void test_set_priority_windows_thread_error(void **state) {
    syscheck.process_priority = 10;

    expect_string(__wrap__mdebug1, formatted_msg, "(6320): Setting process priority to: '10'");

    will_return(wrap_GetCurrentThread, (HANDLE)123456);

    expect_value(wrap_SetThreadPriority, hThread, (HANDLE)123456);
    expect_value(wrap_SetThreadPriority, nPriority, THREAD_PRIORITY_LOWEST);
    will_return(wrap_SetThreadPriority, false);

    will_return(wrap_GetLastError, 2345);

    expect_string(__wrap__merror, formatted_msg, "Can't set thread priority: 2345");

    set_priority_windows_thread();
}

#ifdef WIN_WHODATA
void test_set_whodata_mode_changes(void **state) {
    int i;
    char *dirs[] = {
        "%PROGRAMDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        "%WINDIR%\\System32\\drivers\\etc",
        "%WINDIR%\\System32\\wbem",
        NULL
    };
    char expanded_dirs[3][OS_SIZE_1024];

    // Mark directories to be added in realtime
    syscheck.wdata.dirs_status[0].status |= WD_CHECK_REALTIME;
    syscheck.wdata.dirs_status[0].status &= ~WD_CHECK_WHODATA;
    syscheck.wdata.dirs_status[7].status |= WD_CHECK_REALTIME;
    syscheck.wdata.dirs_status[7].status &= ~WD_CHECK_WHODATA;
    syscheck.wdata.dirs_status[8].status |= WD_CHECK_REALTIME;
    syscheck.wdata.dirs_status[8].status &= ~WD_CHECK_WHODATA;

    // Expand directories
    for(i = 0; dirs[i]; i++) {
        if(!ExpandEnvironmentStrings(dirs[i], expanded_dirs[i], OS_SIZE_1024))
            fail();

        str_lowercase(expanded_dirs[i]);
        expect_string(__wrap_realtime_adddir, dir, expanded_dirs[i]);
        expect_value(__wrap_realtime_adddir, whodata, 0);
        if(i % 2 != 0) {
            will_return(__wrap_realtime_adddir, 0);
        } else {
            will_return(__wrap_realtime_adddir, 1);
        }
    }

    expect_string(__wrap__mdebug1, formatted_msg, "(6225): The 'c:\\programdata\\microsoft\\windows\\start menu\\programs\\startup' directory starts to be monitored in real-time mode.");
    expect_string(__wrap__merror, formatted_msg, "(6611): 'realtime_adddir' failed, the directory 'c:\\windows\\system32\\drivers\\etc'could't be added to real time mode.");
    expect_string(__wrap__mdebug1, formatted_msg, "(6225): The 'c:\\windows\\system32\\wbem' directory starts to be monitored in real-time mode.");

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

    will_return(wrap_GetCurrentThread, (HANDLE)123456);

    expect_value(wrap_SetThreadPriority, hThread, (HANDLE)123456);
    expect_value(wrap_SetThreadPriority, nPriority, THREAD_PRIORITY_LOWEST);
    will_return(wrap_SetThreadPriority, true);

    expect_string(__wrap__mdebug1, formatted_msg, "(6320): Setting process priority to: '10'");

    // Expand directories
    for(i = 0; dirs[i]; i++) {
        if(!ExpandEnvironmentStrings(dirs[i], expanded_dirs[i], OS_SIZE_1024))
            fail();

        str_lowercase(expanded_dirs[i]);
        expect_string(__wrap_realtime_adddir, dir, expanded_dirs[i]);
        expect_value(__wrap_realtime_adddir, whodata, 10);
        will_return(__wrap_realtime_adddir, 0);
    }

    will_return(__wrap_run_whodata_scan, 0);

    will_return(wrap_CreateThread, (HANDLE)123456);

    ret = fim_whodata_initialize();

    assert_int_equal(ret, 0);
}
#endif  // WIN_WHODATA
#endif
void test_fim_send_sync_msg_10_eps(void ** state) {
    (void) state;
    syscheck.sync_max_eps = 10;

    // We must not sleep the first 9 times

    for (int i = 1; i < syscheck.sync_max_eps; i++) {
        expect_string(__wrap__mdebug2, formatted_msg, "(6317): Sending integrity control message: ");
        expect_string(__wrap_SendMSG, message, "");
        expect_string(__wrap_SendMSG, locmsg, SYSCHECK);
        expect_value(__wrap_SendMSG, loc, DBSYNC_MQ);
        will_return(__wrap_SendMSG, 0);

        fim_send_sync_msg("");
    }

#ifndef TEST_WINAGENT
    expect_value(__wrap_sleep, seconds, 1);
#else
    expect_value(wrap_Sleep, dwMilliseconds, 1000);
#endif

    // After 10 times, sleep one second
    expect_string(__wrap__mdebug2, formatted_msg, "(6317): Sending integrity control message: ");
    expect_string(__wrap_SendMSG, message, "");
    expect_string(__wrap_SendMSG, locmsg, SYSCHECK);
    expect_value(__wrap_SendMSG, loc, DBSYNC_MQ);
    will_return(__wrap_SendMSG, 0);

    fim_send_sync_msg("");
}

void test_fim_send_sync_msg_0_eps(void ** state) {
    (void) state;
    syscheck.sync_max_eps = 0;

    // We must not sleep
    expect_string(__wrap__mdebug2, formatted_msg, "(6317): Sending integrity control message: ");
    expect_string(__wrap_SendMSG, message, "");
    expect_string(__wrap_SendMSG, locmsg, SYSCHECK);
    expect_value(__wrap_SendMSG, loc, DBSYNC_MQ);
    will_return(__wrap_SendMSG, 0);

    fim_send_sync_msg("");
}

void test_send_syscheck_msg_10_eps(void ** state) {
    (void) state;
    syscheck.max_eps = 10;

    // We must not sleep the first 9 times

    for (int i = 1; i < syscheck.max_eps; i++) {
        expect_string(__wrap__mdebug2, formatted_msg, "(6321): Sending FIM event: ");
        expect_string(__wrap_SendMSG, message, "");
        expect_string(__wrap_SendMSG, locmsg, SYSCHECK);
        expect_value(__wrap_SendMSG, loc, SYSCHECK_MQ);
        will_return(__wrap_SendMSG, 0);

        send_syscheck_msg("");
    }

#ifndef TEST_WINAGENT
    expect_value(__wrap_sleep, seconds, 1);
#else
    expect_value(wrap_Sleep, dwMilliseconds, 1000);
#endif

    // After 10 times, sleep one second
    expect_string(__wrap__mdebug2, formatted_msg, "(6321): Sending FIM event: ");
    expect_string(__wrap_SendMSG, message, "");
    expect_string(__wrap_SendMSG, locmsg, SYSCHECK);
    expect_value(__wrap_SendMSG, loc, SYSCHECK_MQ);
    will_return(__wrap_SendMSG, 0);

    send_syscheck_msg("");
}

void test_send_syscheck_msg_0_eps(void ** state) {
    (void) state;
    syscheck.max_eps = 0;

    // We must not sleep
    expect_string(__wrap__mdebug2, formatted_msg, "(6321): Sending FIM event: ");
    expect_string(__wrap_SendMSG, message, "");
    expect_string(__wrap_SendMSG, locmsg, SYSCHECK);
    expect_value(__wrap_SendMSG, loc, SYSCHECK_MQ);
    will_return(__wrap_SendMSG, 0);

    send_syscheck_msg("");
}

void test_fim_send_scan_info(void **state) {
    (void) state;

    expect_string(__wrap__mdebug2, formatted_msg, "(6321): Sending FIM event: {\"type\":\"scan_start\",\"data\":{\"timestamp\":1}}");
    expect_string(__wrap_SendMSG, message, "{\"type\":\"scan_start\",\"data\":{\"timestamp\":1}}");
    expect_string(__wrap_SendMSG, locmsg, SYSCHECK);
    expect_value(__wrap_SendMSG, loc, SYSCHECK_MQ);
    will_return(__wrap_SendMSG, 0);

    fim_send_scan_info(FIM_SCAN_START);
}

#ifndef TEST_WINAGENT
void test_fim_link_update(void **state) {
    (void) state;

    int pos = 0;
    char *link_path = "/folder/test";

    expect_value(__wrap_fim_db_get_path_range, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_get_path_range, start, "/boot/");
    expect_string(__wrap_fim_db_get_path_range, top, "/boot0");
    expect_value(__wrap_fim_db_get_path_range, storage, FIM_DB_DISK);
    will_return(__wrap_fim_db_get_path_range, NULL);
    will_return(__wrap_fim_db_get_path_range, FIMDB_OK);

    expect_string(__wrap_realtime_adddir, dir, link_path);
    expect_value(__wrap_realtime_adddir, whodata, 0);
    will_return(__wrap_realtime_adddir, 0);

    expect_string(__wrap_fim_checker, path, link_path);
    expect_value(__wrap_fim_checker, w_evt, 0);
    expect_value(__wrap_fim_checker, report, 0);

    fim_link_update(pos, link_path);

    assert_string_equal(syscheck.dir[pos], link_path);
}

void test_fim_link_update_already_added(void **state) {
    (void) state;

    int pos = 0;
    char *link_path = "/folder/test";

    expect_value(__wrap_fim_db_get_path_range, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_get_path_range, start, "/folder/test/");
    expect_string(__wrap_fim_db_get_path_range, top, "/folder/test0");
    expect_value(__wrap_fim_db_get_path_range, storage, FIM_DB_DISK);
    will_return(__wrap_fim_db_get_path_range, NULL);
    will_return(__wrap_fim_db_get_path_range, FIMDB_OK);

    expect_string(__wrap__mdebug1, formatted_msg, "(6234): Directory '/folder/test' already monitored, ignoring link '(null)'");

    fim_link_update(pos, link_path);

    assert_string_equal(syscheck.dir[pos], "");
}

void test_fim_link_check_delete(void **state) {
    (void) state;

    int pos = 1;
    char *link_path = "/etc";

    expect_string(__wrap_lstat, filename, link_path);
    will_return(__wrap_lstat, 0);
    will_return(__wrap_lstat, 0);

    expect_value(__wrap_fim_db_get_path_range, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_get_path_range, start, "/etc/");
    expect_string(__wrap_fim_db_get_path_range, top, "/etc0");
    expect_value(__wrap_fim_db_get_path_range, storage, FIM_DB_DISK);
    will_return(__wrap_fim_db_get_path_range, NULL);
    will_return(__wrap_fim_db_get_path_range, FIMDB_OK);

    expect_string(__wrap_fim_configuration_directory, path, "/etc");
    expect_string(__wrap_fim_configuration_directory, entry, "file");
    will_return(__wrap_fim_configuration_directory, -1);

    fim_link_check_delete(pos);

    assert_string_equal(syscheck.dir[pos], "");
}

void test_fim_link_check_delete_lstat_error(void **state) {
    (void) state;

    int pos = 2;
    char *link_path = "/home";

    expect_string(__wrap_lstat, filename, link_path);
    will_return(__wrap_lstat, 0);
    will_return(__wrap_lstat, -1);
    errno = 0;

    expect_string(__wrap__mdebug1, formatted_msg, "(6222): Stat() function failed on: '/home' due to [(0)-(Success)]");

    fim_link_check_delete(pos);

    assert_string_equal(syscheck.dir[pos], link_path);
}

void test_fim_link_check_delete_noentry_error(void **state) {
    (void) state;

    int pos = 2;
    char *link_path = "/home";

    expect_string(__wrap_lstat, filename, link_path);
    will_return(__wrap_lstat, 0);
    will_return(__wrap_lstat, -1);

    errno = ENOENT;

    fim_link_check_delete(pos);

    errno = 0;

    assert_string_equal(syscheck.dir[pos], "");
}

void test_fim_delete_realtime_watches(void **state) {
    (void) state;

    unsigned int pos = 1;

    expect_string(__wrap_fim_configuration_directory, path, "");
    expect_string(__wrap_fim_configuration_directory, entry, "file");
    will_return(__wrap_fim_configuration_directory, 0);
    expect_string(__wrap_fim_configuration_directory, path, "data");
    expect_string(__wrap_fim_configuration_directory, entry, "file");
    will_return(__wrap_fim_configuration_directory, 0);

    will_return(__wrap_inotify_rm_watch, 1);

    fim_delete_realtime_watches(pos);

    assert_null(OSHash_Begin(syscheck.realtime->dirtb, &pos));
}

void test_fim_link_delete_range(void **state) {
    int pos = 3;

    fim_tmp_file *tmp_file = *state;

    expect_value(__wrap_fim_db_get_path_range, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_get_path_range, start, "/media/");
    expect_string(__wrap_fim_db_get_path_range, top, "/media0");
    expect_value(__wrap_fim_db_get_path_range, storage, FIM_DB_DISK);
    will_return(__wrap_fim_db_get_path_range, tmp_file);
    will_return(__wrap_fim_db_get_path_range, FIMDB_OK);

    expect_value(__wrap_fim_db_delete_range, fim_sql, syscheck.database);
    expect_value(__wrap_fim_db_delete_range, storage, FIM_DB_DISK);
    expect_memory(__wrap_fim_db_delete_range, file, tmp_file, sizeof(tmp_file));
    will_return(__wrap_fim_db_delete_range, FIMDB_OK);

    fim_link_delete_range(pos);
}

void test_fim_link_delete_range_error(void **state) {
    int pos = 3;

    fim_tmp_file *tmp_file = *state;

    expect_value(__wrap_fim_db_get_path_range, fim_sql, syscheck.database);
    expect_string(__wrap_fim_db_get_path_range, start, "/media/");
    expect_string(__wrap_fim_db_get_path_range, top, "/media0");
    expect_value(__wrap_fim_db_get_path_range, storage, FIM_DB_DISK);
    will_return(__wrap_fim_db_get_path_range, tmp_file);
    will_return(__wrap_fim_db_get_path_range, FIMDB_ERR);

    expect_string(__wrap__merror, formatted_msg, "(6708): Failed to delete a range of paths between '/media/' and '/media0'");

    expect_value(__wrap_fim_db_delete_range, fim_sql, syscheck.database);
    expect_value(__wrap_fim_db_delete_range, storage, FIM_DB_DISK);
    expect_memory(__wrap_fim_db_delete_range, file, tmp_file, sizeof(tmp_file));
    will_return(__wrap_fim_db_delete_range, FIMDB_ERR);

    expect_string(__wrap__merror, formatted_msg, "(6708): Failed to delete a range of paths between '/media/' and '/media0'");

    fim_link_delete_range(pos);
}

void test_fim_link_silent_scan(void **state) {
    (void) state;

    int pos = 3;
    char *link_path = "/folder/test";

    expect_string(__wrap_realtime_adddir, dir, link_path);
    expect_value(__wrap_realtime_adddir, whodata, 0);
    will_return(__wrap_realtime_adddir, 0);

    expect_string(__wrap_fim_checker, path, link_path);
    expect_value(__wrap_fim_checker, w_evt, 0);
    expect_value(__wrap_fim_checker, report, 0);

    fim_link_silent_scan(link_path, pos);
}

void test_fim_link_reload_broken_link_already_monitored(void **state) {
    (void) state;

    int pos = 4;
    char *link_path = "/usr/bin";

    expect_string(__wrap__mdebug1, formatted_msg, "(6234): Directory '/usr/bin' already monitored, ignoring link '(null)'");

    fim_link_reload_broken_link(link_path, pos);

    assert_string_equal(syscheck.dir[pos], link_path);
}

void test_fim_link_reload_broken_link_reload_broken(void **state) {
    (void) state;

    int pos = 5;
    char *link_path = "/test";

    expect_string(__wrap_fim_checker, path, link_path);
    expect_value(__wrap_fim_checker, w_evt, 0);
    expect_value(__wrap_fim_checker, report, 0);

    fim_link_reload_broken_link(link_path, pos);

    assert_string_equal(syscheck.dir[pos], link_path);
}
#endif


int main(void) {
#ifndef WIN_WHODATA
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_fim_whodata_initialize),

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
        cmocka_unit_test(test_fim_send_msg),
        cmocka_unit_test(test_fim_send_msg_retry),
        cmocka_unit_test(test_fim_send_msg_retry_error),
        cmocka_unit_test(test_fim_send_sync_msg_10_eps),
        cmocka_unit_test(test_fim_send_sync_msg_0_eps),
        cmocka_unit_test(test_send_syscheck_msg_10_eps),
        cmocka_unit_test(test_send_syscheck_msg_0_eps),
        cmocka_unit_test(test_fim_send_scan_info),
#ifndef TEST_WINAGENT
        cmocka_unit_test(test_fim_link_update),
        cmocka_unit_test(test_fim_link_update_already_added),
        cmocka_unit_test(test_fim_link_check_delete),
        cmocka_unit_test(test_fim_link_check_delete_lstat_error),
        cmocka_unit_test(test_fim_link_check_delete_noentry_error),
        cmocka_unit_test(test_fim_delete_realtime_watches),
        cmocka_unit_test_setup_teardown(test_fim_link_delete_range, setup_tmp_file, teardown_tmp_file),
        cmocka_unit_test_setup_teardown(test_fim_link_delete_range_error, setup_tmp_file, teardown_tmp_file),
        cmocka_unit_test(test_fim_link_silent_scan),
        cmocka_unit_test(test_fim_link_reload_broken_link_already_monitored),
        cmocka_unit_test(test_fim_link_reload_broken_link_reload_broken),
#endif
    };

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
#else  // WIN_WHODATA
    const struct CMUnitTest eventchannel_tests[] = {
        cmocka_unit_test(test_set_whodata_mode_changes),
        cmocka_unit_test(test_fim_whodata_initialize_eventchannel),
        cmocka_unit_test(test_fim_whodata_initialize_fail_set_policies),
    };
    return cmocka_run_group_tests(eventchannel_tests, setup_group, teardown_group);
#endif
}
