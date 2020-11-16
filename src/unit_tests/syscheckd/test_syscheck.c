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

#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/fs_op_wrappers.h"
#include "../wrappers/wazuh/shared/validate_op_wrappers.h"

#include "../syscheckd/syscheck.h"

/* setup/teardowns */
static int setup_group(void **state) {
    fdb_t *fdb = calloc(1, sizeof(fdb_t));

    if(fdb == NULL)
        return -1;

    *state = fdb;

    return 0;
}

static int teardown_group(void **state) {
    fdb_t *fdb = *state;

    free(fdb);

    return 0;
}

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

    fim_initialize();

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

int __wrap_rootcheck_init(int value)
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

void test_Start_win32_Syscheck_no_config_file(void **state)
{
    (void) state;

    char *SYSCHECK_EMPTY[] = { NULL };
    registry REGISTRY_EMPTY[] = { { NULL, 0, NULL } };
    syscheck.dir = SYSCHECK_EMPTY;
    syscheck.registry = REGISTRY_EMPTY;
    syscheck.disabled = 1;

    expect_string(__wrap__mdebug1, formatted_msg, "Starting ...");

    expect_string(__wrap__minfo, formatted_msg, "(6678): No directory provided for syscheck to monitor.");
    expect_string(__wrap__minfo, formatted_msg, "(6001): File integrity monitoring disabled.");

    /* Conf file not found */
    will_return_always(__wrap_getDefine_Int, 1);
    expect_string(__wrap_File_DateofChange, file, "ossec.conf");
    will_return(__wrap_File_DateofChange, -1);
    expect_string(__wrap__merror_exit, formatted_msg, "(1239): Configuration file not found: 'ossec.conf'.");

    expect_string(__wrap_Read_Syscheck_Config, file, "ossec.conf");
    will_return(__wrap_Read_Syscheck_Config, 0);

    will_return(__wrap_rootcheck_init, 1);

    expect_value(__wrap_fim_db_init, memory, 0);
    will_return(__wrap_fim_db_init, NULL);

    expect_string(__wrap__merror_exit, formatted_msg, "(6698): Creating Data Structure: sqlite3 db. Exiting.");

    expect_function_call(__wrap_os_wait);

    expect_function_call(__wrap_start_daemon);
    Start_win32_Syscheck();
}

void test_Start_win32_Syscheck_corrupted_config_file(void **state)
{
    (void) state;

    char *SYSCHECK_EMPTY[] = { NULL };
    registry REGISTRY_EMPTY[] = { { NULL, 0, NULL } };
    syscheck.dir = SYSCHECK_EMPTY;
    syscheck.registry = REGISTRY_EMPTY;
    syscheck.disabled = 1;

    expect_string(__wrap__mdebug1, formatted_msg, "Starting ...");

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
    expect_function_call(__wrap_os_wait);
    expect_function_call(__wrap_start_daemon);

    Start_win32_Syscheck();
}

void test_Start_win32_Syscheck_syscheck_disabled_1(void **state)
{
    (void) state;

    syscheck.dir = NULL;
    syscheck.registry = NULL;
    syscheck.disabled = 0;
    char info_msg[OS_MAXSTR];

    expect_string(__wrap__mdebug1, formatted_msg, "Starting ...");

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

    expect_function_call(__wrap_os_wait);

    expect_function_call(__wrap_start_daemon);

    Start_win32_Syscheck();
}

void test_Start_win32_Syscheck_syscheck_disabled_2(void **state)
{
    (void) state;

    char *SYSCHECK_EMPTY[] = { NULL };

    syscheck.dir = SYSCHECK_EMPTY;

    char info_msg[OS_MAXSTR];

    expect_string(__wrap__mdebug1, formatted_msg, "Starting ...");

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

    expect_function_call(__wrap_os_wait);

    expect_function_call(__wrap_start_daemon);

    Start_win32_Syscheck();
}

void test_Start_win32_Syscheck_dirs_and_registry(void **state)
{
    (void) state;

    syscheck.disabled = 0;

    char *syscheck_dirs[] = {"Dir1", NULL};
    syscheck.dir = syscheck_dirs;

    registry syscheck_registry[] = { { "Entry1", 1, "Tag1" } , { NULL, 0, NULL }};
    syscheck.registry = syscheck_registry;

    char *syscheck_ignore[] = {"Dir1", NULL};
    syscheck.ignore = syscheck_ignore;

    OSMatch regex;
    regex.raw = "^regex$";
    OSMatch *syscheck_ignore_regex[] = {&regex, NULL};
    syscheck.ignore_regex = syscheck_ignore_regex;

    registry syscheck_registry_ignore[] = { { "Entry1", 1, "Tag1" } , { NULL, 0, NULL }};
    syscheck.registry_ignore = syscheck_registry_ignore;

    char *syscheck_nodiff[] = {"Diff", NULL};
    syscheck.nodiff = syscheck_nodiff;

    char info_msg[OS_MAXSTR];

    expect_string(__wrap__mdebug1, formatted_msg, "Starting ...");

    will_return_always(__wrap_getDefine_Int, 1);

    expect_string(__wrap_File_DateofChange, file, "ossec.conf");
    will_return(__wrap_File_DateofChange, 0);

    expect_string(__wrap_Read_Syscheck_Config, file, "ossec.conf");
    will_return(__wrap_Read_Syscheck_Config, 0);

    will_return(__wrap_rootcheck_init, 0);

    expect_string(__wrap__minfo, formatted_msg, "(6002): Monitoring registry entry: 'Entry1 [x64]'.");

    expect_string(__wrap__minfo, formatted_msg, "(6003): Monitoring path: 'Dir1', with options ''.");

    expect_string(__wrap__minfo, formatted_msg, FIM_FILE_SIZE_LIMIT_DISABLED);

    expect_string(__wrap__minfo, formatted_msg, FIM_DISK_QUOTA_LIMIT_DISABLED);

    expect_string(__wrap__minfo, formatted_msg, "(6206): Ignore 'file' entry 'Dir1'");

    expect_string(__wrap__minfo, formatted_msg, "(6207): Ignore 'file' sregex '^regex$'");

    expect_string(__wrap__minfo, formatted_msg, "(6206): Ignore 'registry' entry 'Entry1'");

    expect_string(__wrap__minfo, formatted_msg, "(6004): No diff for file: 'Diff'");

    expect_value(__wrap_fim_db_init, memory, 0);
    will_return(__wrap_fim_db_init, NULL);

    expect_string(__wrap__merror_exit, formatted_msg, "(6698): Creating Data Structure: sqlite3 db. Exiting.");

    snprintf(info_msg, OS_MAXSTR, "Started (pid: %d).", getpid());
    expect_string(__wrap__minfo, formatted_msg, info_msg);

    expect_function_call(__wrap_os_wait);

    expect_function_call(__wrap_start_daemon);

    Start_win32_Syscheck();
}

void test_Start_win32_Syscheck_whodata_active(void **state)
{
    (void) state;

    syscheck.disabled = 0;
    syscheck.opts[0] = WHODATA_ACTIVE;

    char *syscheck_dirs[] = { "Dir1", NULL };
    syscheck.dir = syscheck_dirs;

    registry syscheck_registry[] = { { NULL, 0, NULL } };
    syscheck.registry = syscheck_registry;

    syscheck.ignore = NULL;
    syscheck.ignore_regex = NULL;
    syscheck.registry_ignore = NULL;
    syscheck.nodiff = NULL;

    char info_msg[OS_MAXSTR];

    expect_string(__wrap__mdebug1, formatted_msg, "Starting ...");

    will_return_always(__wrap_getDefine_Int, 1);

    expect_string(__wrap_File_DateofChange, file, "ossec.conf");
    will_return(__wrap_File_DateofChange, 0);

    expect_string(__wrap_Read_Syscheck_Config, file, "ossec.conf");
    will_return(__wrap_Read_Syscheck_Config, 0);

    will_return(__wrap_rootcheck_init, 0);

    expect_string(__wrap__minfo, formatted_msg, "(6015): Real-time Whodata mode is not compatible with this version of Windows.");

    expect_string(__wrap__minfo, formatted_msg, "(6003): Monitoring path: 'Dir1', with options 'realtime'.");

    expect_value(__wrap_fim_db_init, memory, 0);
    will_return(__wrap_fim_db_init, NULL);

    expect_string(__wrap__merror_exit, formatted_msg, "(6698): Creating Data Structure: sqlite3 db. Exiting.");

    expect_string(__wrap__minfo, formatted_msg, FIM_FILE_SIZE_LIMIT_DISABLED);

    expect_string(__wrap__minfo, formatted_msg, FIM_DISK_QUOTA_LIMIT_DISABLED);

    snprintf(info_msg, OS_MAXSTR, "Started (pid: %d).", getpid());
    expect_string(__wrap__minfo, formatted_msg, info_msg);

    expect_function_call(__wrap_os_wait);

    expect_function_call(__wrap_start_daemon);

    Start_win32_Syscheck();
}

#endif

int main(void) {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test(test_fim_initialize),
            cmocka_unit_test(test_fim_initialize),
            cmocka_unit_test(test_fim_initialize_error),
            cmocka_unit_test(test_read_internal),
            cmocka_unit_test(test_read_internal_debug),
        /* Windows specific tests */
#ifdef TEST_WINAGENT
            cmocka_unit_test(test_Start_win32_Syscheck_no_config_file),
            cmocka_unit_test(test_Start_win32_Syscheck_corrupted_config_file),
            cmocka_unit_test(test_Start_win32_Syscheck_syscheck_disabled_1),
            cmocka_unit_test(test_Start_win32_Syscheck_syscheck_disabled_2),
            cmocka_unit_test(test_Start_win32_Syscheck_dirs_and_registry),
            cmocka_unit_test(test_Start_win32_Syscheck_whodata_active),
#endif
    };

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
