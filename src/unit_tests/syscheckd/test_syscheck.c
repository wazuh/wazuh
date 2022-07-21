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

#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/fs_op_wrappers.h"
#include "../wrappers/wazuh/shared/validate_op_wrappers.h"

#include "../syscheckd/syscheck.h"

/* setup/teardowns */
static int setup_group(void **state) {
    fdb_t *fdb = calloc(1, sizeof(fdb_t));
    if (fdb == NULL)
        return -1;

    *state = fdb;
    return 0;
}

static int teardown_group(void **state) {
    fdb_t *fdb = *state;

    free(fdb);

    return 0;
}

#ifdef TEST_WINAGENT
static int setup_group_win(void **state) {
    syscheck.directories = OSList_Create();
    if (syscheck.directories == NULL) {
        return -1;
    }

    return 0;
}

static int teardown_group_win(void **state) {
    OSListNode *node_it;
    if (syscheck.directories) {
        OSList_foreach(node_it, syscheck.directories) {
            free_directory(node_it->data);
            node_it->data = NULL;
        }
        OSList_Destroy(syscheck.directories);
        syscheck.directories = NULL;
    }

    return 0;
}
#endif

/* tests */

void test_fim_initialize(void **state)
{
    fdb_t *fdb = *state;

    expect_value(__wrap_fim_db_init, memory, 0);
    will_return(__wrap_fim_db_init, fdb);

    fim_initialize();

    assert_ptr_equal(syscheck.database, fdb);
}

void test_fim_initialize_error(void **state)
{
    expect_value(__wrap_fim_db_init, memory, 0);
    will_return(__wrap_fim_db_init, NULL);

    expect_string(__wrap__merror_exit, formatted_msg, "(6698): Creating Data Structure: sqlite3 db. Exiting.");

    expect_assert_failure(fim_initialize());

    assert_null(syscheck.database);
}

void test_read_internal(void **state)
{
    (void) state;

    will_return_always(__wrap_getDefine_Int, 1);

    read_internal(0);
}

void test_read_internal_debug(void **state)
{
    (void) state;

    will_return_always(__wrap_getDefine_Int, 1);

    read_internal(1);
}
#ifdef TEST_WINAGENT
int Start_win32_Syscheck();

int __wrap_Read_Syscheck_Config(const char * file)
{
    check_expected_ptr(file);
    return mock();
}

int __wrap_rootcheck_init(int value, char * home_path)
{
    return mock();
}

void __wrap_os_wait()
{
    function_called();
}

void __wrap_start_daemon()
{
    function_called();
}

void __wrap_read_internal(int debug_level)
{
    function_called();
}

void test_Start_win32_Syscheck_no_config_file(void **state) {
    directory_t EMPTY = { 0 };
    registry REGISTRY_EMPTY[] = { { NULL, 0, 0, 0, 0, NULL, NULL } };

    syscheck.registry = REGISTRY_EMPTY;
    syscheck.disabled = 1;


    /* Conf file not found */
    will_return_always(__wrap_getDefine_Int, 1);
    expect_string(__wrap_File_DateofChange, file, "ossec.conf");
    will_return(__wrap_File_DateofChange, -1);
    expect_string(__wrap__merror_exit, formatted_msg, "(1239): Configuration file not found: 'ossec.conf'.");

    expect_assert_failure(Start_win32_Syscheck());
}

void test_Start_win32_Syscheck_corrupted_config_file(void **state) {
    directory_t EMPTY = { 0 };
    registry REGISTRY_EMPTY[] = { { NULL, 0, 0, 0, 0, NULL, NULL } };

    syscheck.registry = REGISTRY_EMPTY;
    syscheck.disabled = 1;

    will_return_always(__wrap_getDefine_Int, 1);
    expect_string(__wrap_File_DateofChange, file, "ossec.conf");
    will_return(__wrap_File_DateofChange, 0);

    expect_string(__wrap_Read_Syscheck_Config, file, "ossec.conf");
    will_return(__wrap_Read_Syscheck_Config, -1);
    expect_string(__wrap__merror, formatted_msg, "(1207): syscheck remote configuration in 'ossec.conf' is corrupted.");

    will_return(__wrap_rootcheck_init, 1);
    expect_value(__wrap_fim_db_init, memory, 0);
    will_return(__wrap_fim_db_init, NULL);
    expect_string(__wrap__merror_exit, formatted_msg, "(6698): Creating Data Structure: sqlite3 db. Exiting.");

    expect_assert_failure(Start_win32_Syscheck());
}

void test_Start_win32_Syscheck_syscheck_disabled_1(void **state) {
    syscheck.directories = NULL;
    syscheck.registry = NULL;
    syscheck.disabled = 0;
    char info_msg[OS_MAXSTR];

    will_return_always(__wrap_getDefine_Int, 1);

    expect_string(__wrap_File_DateofChange, file, "ossec.conf");
    will_return(__wrap_File_DateofChange, 0);

    expect_string(__wrap_Read_Syscheck_Config, file, "ossec.conf");
    will_return(__wrap_Read_Syscheck_Config, 1);

    expect_string(__wrap__minfo, formatted_msg, "(6678): No directory provided for syscheck to monitor.");

    expect_string(__wrap__minfo, formatted_msg, "(6001): File integrity monitoring disabled.");

    will_return(__wrap_rootcheck_init, 0);

    expect_value(__wrap_fim_db_init, memory, 0);
    will_return(__wrap_fim_db_init, NULL);

    expect_string(__wrap__merror_exit, formatted_msg, "(6698): Creating Data Structure: sqlite3 db. Exiting.");

    expect_string(__wrap__minfo, formatted_msg, FIM_FILE_SIZE_LIMIT_DISABLED);

    expect_string(__wrap__minfo, formatted_msg, FIM_DISK_QUOTA_LIMIT_DISABLED);

    snprintf(info_msg, OS_MAXSTR, "Started (pid: %d).", getpid());
    expect_string(__wrap__minfo, formatted_msg, info_msg);

    expect_assert_failure(Start_win32_Syscheck());
}

void test_Start_win32_Syscheck_syscheck_disabled_2(void **state) {
    directory_t EMPTY = { 0 };
    char info_msg[OS_MAXSTR];

    will_return_always(__wrap_getDefine_Int, 1);

    expect_string(__wrap_File_DateofChange, file, "ossec.conf");
    will_return(__wrap_File_DateofChange, 0);

    expect_string(__wrap_Read_Syscheck_Config, file, "ossec.conf");
    will_return(__wrap_Read_Syscheck_Config, 1);

    expect_string(__wrap__minfo, formatted_msg, "(6678): No directory provided for syscheck to monitor.");

    expect_string(__wrap__minfo, formatted_msg, "(6001): File integrity monitoring disabled.");

    will_return(__wrap_rootcheck_init, 0);

    expect_value(__wrap_fim_db_init, memory, 0);
    will_return(__wrap_fim_db_init, NULL);

    expect_string(__wrap__merror_exit, formatted_msg, "(6698): Creating Data Structure: sqlite3 db. Exiting.");

    expect_string(__wrap__minfo, formatted_msg, FIM_FILE_SIZE_LIMIT_DISABLED);

    expect_string(__wrap__minfo, formatted_msg, FIM_DISK_QUOTA_LIMIT_DISABLED);

    snprintf(info_msg, OS_MAXSTR, "Started (pid: %d).", getpid());
    expect_string(__wrap__minfo, formatted_msg, info_msg);
    expect_assert_failure(Start_win32_Syscheck());
}

void test_Start_win32_Syscheck_dirs_and_registry(void **state) {
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);

    directory_t *directory0 = fim_create_directory("c:\\dir1", 0, NULL, 512, NULL, 1024, 0);
    OSList_InsertData(syscheck.directories, NULL, directory0);

    syscheck.disabled = 0;

    registry syscheck_registry[] = { { "Entry1", 1, 0, 0, 0, NULL, NULL, "Tag1" },
                                     { NULL, 0, 0, 0, 0, NULL, NULL, NULL } };
    syscheck.registry = syscheck_registry;

    char *syscheck_ignore[] = {"dir1", NULL};
    syscheck.ignore = syscheck_ignore;

    OSMatch regex;
    regex.raw = "^regex$";
    OSMatch *syscheck_ignore_regex[] = {&regex, NULL};
    syscheck.ignore_regex = syscheck_ignore_regex;

    registry_ignore syscheck_registry_ignore[] = { { "Entry1", 1 }, { NULL, 0 } };
    syscheck.key_ignore = syscheck_registry_ignore;

    char *syscheck_nodiff[] = {"Diff", NULL};
    syscheck.nodiff = syscheck_nodiff;

    char info_msg[OS_MAXSTR];

    will_return_always(__wrap_getDefine_Int, 1);

    expect_string(__wrap_File_DateofChange, file, "ossec.conf");
    will_return(__wrap_File_DateofChange, 0);

    expect_string(__wrap_Read_Syscheck_Config, file, "ossec.conf");
    will_return(__wrap_Read_Syscheck_Config, 0);

    will_return(__wrap_rootcheck_init, 0);

    expect_string(__wrap__minfo, formatted_msg, "(6002): Monitoring registry entry: 'Entry1 [x64]', with options ''");

    expect_string(__wrap__minfo, formatted_msg, "(6003): Monitoring path: 'c:\\dir1', with options ''.");

    expect_string(__wrap__minfo, formatted_msg, FIM_FILE_SIZE_LIMIT_DISABLED);

    expect_string(__wrap__minfo, formatted_msg, FIM_DISK_QUOTA_LIMIT_DISABLED);

    expect_string(__wrap__minfo, formatted_msg, "(6206): Ignore 'file' entry 'dir1'");

    expect_string(__wrap__minfo, formatted_msg, "(6207): Ignore 'file' sregex '^regex$'");

    expect_string(__wrap__minfo, formatted_msg, "(6206): Ignore 'registry' entry 'Entry1'");

    expect_string(__wrap__minfo, formatted_msg, "(6004): No diff for file: 'Diff'");

    expect_value(__wrap_fim_db_init, memory, 0);
    will_return(__wrap_fim_db_init, NULL);

    expect_string(__wrap__merror_exit, formatted_msg, "(6698): Creating Data Structure: sqlite3 db. Exiting.");

    snprintf(info_msg, OS_MAXSTR, "Started (pid: %d).", getpid());
    expect_string(__wrap__minfo, formatted_msg, info_msg);


    expect_assert_failure(Start_win32_Syscheck());

    free_directory(directory0);
    OSList_DeleteThisNode(syscheck.directories, syscheck.directories->first_node);
}

void test_Start_win32_Syscheck_whodata_active(void **state) {
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);

    directory_t *directory0 = fim_create_directory("c:\\dir1", WHODATA_ACTIVE, NULL, 512, NULL, -1, 0);

    registry syscheck_registry[] = { { NULL, 0, 0, 0, 0, NULL, NULL } };

    syscheck.disabled = 0;

    OSList_InsertData(syscheck.directories, NULL, directory0);

    syscheck.registry = syscheck_registry;

    syscheck.ignore = NULL;
    syscheck.ignore_regex = NULL;
    syscheck.key_ignore = NULL;
    syscheck.nodiff = NULL;

    char info_msg[OS_MAXSTR];

    will_return_always(__wrap_getDefine_Int, 1);

    expect_string(__wrap_File_DateofChange, file, "ossec.conf");
    will_return(__wrap_File_DateofChange, 0);

    expect_string(__wrap_Read_Syscheck_Config, file, "ossec.conf");
    will_return(__wrap_Read_Syscheck_Config, 0);

    will_return(__wrap_rootcheck_init, 0);

    expect_string(__wrap__minfo, formatted_msg, "(6015): Real-time Whodata mode is not compatible with this version of Windows.");

    expect_string(__wrap__minfo, formatted_msg, "(6003): Monitoring path: 'c:\\dir1', with options 'realtime'.");

    expect_value(__wrap_fim_db_init, memory, 0);
    will_return(__wrap_fim_db_init, NULL);

    expect_string(__wrap__merror_exit, formatted_msg, "(6698): Creating Data Structure: sqlite3 db. Exiting.");

    expect_string(__wrap__minfo, formatted_msg, FIM_FILE_SIZE_LIMIT_DISABLED);

    expect_string(__wrap__minfo, formatted_msg, FIM_DISK_QUOTA_LIMIT_DISABLED);

    snprintf(info_msg, OS_MAXSTR, "Started (pid: %d).", getpid());
    expect_string(__wrap__minfo, formatted_msg, info_msg);

    expect_assert_failure(Start_win32_Syscheck());

    free_directory(directory0);
    OSList_DeleteThisNode(syscheck.directories, syscheck.directories->first_node);
}

#endif

int main(void) {
    int ret;
    const struct CMUnitTest tests[] = {
            cmocka_unit_test(test_fim_initialize),
            cmocka_unit_test(test_fim_initialize),
            cmocka_unit_test(test_fim_initialize_error),
            cmocka_unit_test(test_read_internal),
            cmocka_unit_test(test_read_internal_debug),
    };
        /* Windows specific tests */
#ifdef TEST_WINAGENT
    const struct CMUnitTest tests_win[] = {
            cmocka_unit_test(test_Start_win32_Syscheck_no_config_file),
            cmocka_unit_test(test_Start_win32_Syscheck_corrupted_config_file),
            cmocka_unit_test(test_Start_win32_Syscheck_dirs_and_registry),
            cmocka_unit_test(test_Start_win32_Syscheck_whodata_active),
            cmocka_unit_test(test_Start_win32_Syscheck_syscheck_disabled_1),
            cmocka_unit_test(test_Start_win32_Syscheck_syscheck_disabled_2),
    };
#endif

    ret = cmocka_run_group_tests(tests, setup_group, teardown_group);
#ifdef TEST_WINAGENT
    ret += cmocka_run_group_tests(tests_win, setup_group_win, teardown_group_win);
#endif

    return ret;
}
