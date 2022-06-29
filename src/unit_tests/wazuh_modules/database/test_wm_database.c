/*
 * Copyright (C) 2022, Wazuh Inc.
 * March, 2022.
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
#include <string.h>
#include <stdlib.h>

#include <shared.h>
#include "../../../wazuh_modules/wmodules_def.h"
#include "../../../wazuh_modules/wm_database.h"

#include "../../wrappers/common.h"
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../wrappers/wazuh/shared/file_op_wrappers.h"
#include "../../wrappers/wazuh/wazuh_db/wdb_global_helpers_wrappers.h"
#include "../../wrappers/wazuh/wazuh_db/wdb_wrappers.h"
#include "../../wrappers/libc/stdio_wrappers.h"
#include "../../wrappers/libc/string_wrappers.h"
#include "../../wrappers/posix/dirent_wrappers.h"
#include "../../wrappers/posix/unistd_wrappers.h"

/* setup/teardown */

extern int test_mode;
extern int is_worker;

int setup_wmdb(void **state) {
    test_mode = 1;
    return OS_SUCCESS;
}

int teardown_wmdb(void **state) {
    test_mode = 0;
    return OS_SUCCESS;
}

/* helpers */

/**
 * @brief Generates a CSV string with the name of 'ngroups'. The string must
 *        be deallocated by the caller.
 *
 * @param ngroups The number of group names to be included in the CSV string
 * @return char* The groups CSV string.
 */
char *generate_groups_csv_string(unsigned int ngroups) {
    char *groups = NULL;
    os_calloc(OS_BUFFER_SIZE, sizeof(char), groups);

    int i = 0, position = 0;
    for (i = 0; i < ngroups-1; ++i) {
        snprintf(groups+position, OS_BUFFER_SIZE - position, "group%d,", i);
        position = strlen(groups);
    }
    snprintf(groups+position, OS_BUFFER_SIZE - position, "group%d\n", i);

    return groups;
}

/* Tests wm_sync_group_file */

void test_wm_sync_group_file_error_agent_id(void **state) {
    int ret = OS_INVALID;
    const char *group_file = "invalid_name";
    const char *group_file_path = "invalid_path";

    // Invalid agent ID obtained from 'group_file'
    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:database");
    expect_string(__wrap__mtdebug1, formatted_msg, "Couldn't extract agent ID from file 'invalid_path'.");

    ret = wm_sync_group_file(group_file, group_file_path);

    assert_int_equal(ret, OS_INVALID);
}

void test_wm_sync_group_file_error_opening_file(void **state) {
    int ret = OS_INVALID;
    const char *group_file = "001";
    const char *group_file_path = "invalid_path";

    // Error opening agent groups file specified by 'group_file_path'
    expect_string(__wrap_fopen, path, group_file_path);
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, NULL);
    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:database");
    expect_string(__wrap__mtdebug1, formatted_msg, "Groups file 'invalid_path' could not be opened for syncronization.");

    ret = wm_sync_group_file(group_file, group_file_path);

    assert_int_equal(ret, OS_INVALID);
}

void test_wm_sync_group_file_success_empty_file(void **state) {
    int ret = OS_INVALID;
    const char *group_file = "001";
    const char *group_file_path = GROUPS_DIR "/001";
    FILE *fp_group_file = (FILE *)1;
    const char *groups_in_file = NULL;

    // Agent groups file opened succesfully
    expect_string(__wrap_fopen, path, group_file_path);
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, fp_group_file);
    // No data when reading the file
    will_return(__wrap_fgets, groups_in_file);
    expect_value(__wrap_fgets, __stream, fp_group_file);
    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:database");
    expect_string(__wrap__mtdebug1, formatted_msg, "Empty group file 'queue/agent-groups/001'.");
    // Closing group file
    expect_value(__wrap_fclose, _File, fp_group_file);
    will_return(__wrap_fclose, OS_SUCCESS);

    ret = wm_sync_group_file(group_file, group_file_path);

    assert_int_equal(ret, OS_SUCCESS);
}

void test_wm_sync_group_file_success_more_than_max_groups(void **state) {
    int ret = OS_INVALID;
    const char *group_file = "001";
    const char *group_file_path = GROUPS_DIR "/001";
    int agent_id = atoi(group_file);
    FILE *fp_group_file = (FILE *)1;

    // Generating a CSV groups string with more than 128 groups
    char *groups_in_file = generate_groups_csv_string(MAX_GROUPS_PER_MULTIGROUP+1);

    // Agent groups file opened succesfully
    expect_string(__wrap_fopen, path, group_file_path);
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, fp_group_file);
    // Reading the file
    will_return(__wrap_fgets, groups_in_file);
    expect_value(__wrap_fgets, __stream, fp_group_file);
    // Setting groups
    will_return(__wrap_w_is_single_node, 1);
    expect_value(__wrap_wdb_set_agent_groups, id, agent_id);
    expect_string(__wrap_wdb_set_agent_groups, mode, "override");
    expect_string(__wrap_wdb_set_agent_groups, sync_status, "synced");
    will_return(__wrap_wdb_set_agent_groups, OS_SUCCESS);
    // Closing group file
    expect_value(__wrap_fclose, _File, fp_group_file);
    will_return(__wrap_fclose, OS_SUCCESS);

    ret = wm_sync_group_file(group_file, group_file_path);

    assert_int_equal(ret, OS_SUCCESS);
    os_free(groups_in_file);
}

void test_wm_sync_group_file_success_max_groups(void **state) {
    int ret = OS_INVALID;
    const char *group_file = "001";
    const char *group_file_path = GROUPS_DIR "/001";
    int agent_id = atoi(group_file);
    FILE *fp_group_file = (FILE *)1;

    // Generating a CSV groups string with 128 groups
    char *groups_in_file = generate_groups_csv_string(MAX_GROUPS_PER_MULTIGROUP);

    // Agent groups file opened succesfully
    expect_string(__wrap_fopen, path, group_file_path);
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, fp_group_file);
    // Reading the file
    will_return(__wrap_fgets, groups_in_file);
    expect_value(__wrap_fgets, __stream, fp_group_file);
    // Setting groups
    will_return(__wrap_w_is_single_node, 1);
    expect_value(__wrap_wdb_set_agent_groups, id, agent_id);
    expect_string(__wrap_wdb_set_agent_groups, mode, "override");
    expect_string(__wrap_wdb_set_agent_groups, sync_status, "synced");
    will_return(__wrap_wdb_set_agent_groups, OS_SUCCESS);
    // Closing group file
    expect_value(__wrap_fclose, _File, fp_group_file);
    will_return(__wrap_fclose, OS_SUCCESS);

    ret = wm_sync_group_file(group_file, group_file_path);

    assert_int_equal(ret, OS_SUCCESS);
    os_free(groups_in_file);
}

/* Tests wm_sync_legacy_groups_files */

void test_wm_sync_legacy_groups_files_error_opening_groups_dir(void **state) {
    // Error opening groups directory
    will_return(__wrap_opendir, NULL);
    will_return(__wrap_strerror, "ERROR");
    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:database");
    expect_string(__wrap__mtdebug1, formatted_msg, "Couldn't open directory 'queue/agent-groups': ERROR.");

    wm_sync_legacy_groups_files();
}

void test_wm_sync_legacy_groups_files_success_files_worker_error_dir(void **state) {
    DIR *dir = (DIR *)1;
    struct dirent *dir_ent = NULL;
    os_calloc(1, sizeof(struct dirent), dir_ent);
    strncpy(dir_ent->d_name, "001\0", 11);

    // Opening groups directory and iterating files
    will_return(__wrap_opendir, dir);
    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:database");
    expect_string(__wrap__mtdebug1, formatted_msg, "Scanning directory 'queue/agent-groups'.");
    will_return(__wrap_readdir, dir_ent);
    is_worker = 1;

    // Logging result, removing agent groups file, and finalizing the dir iteration
    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:database");
    expect_string(__wrap__mtdebug1, formatted_msg, "Group file 'queue/agent-groups/001' won't be synced in a worker node, removing.");
    expect_string(__wrap_unlink, file, "queue/agent-groups/001");
    will_return(__wrap_unlink, OS_SUCCESS);
    will_return(__wrap_readdir, NULL);

    // Error removing the groups directory
    expect_string(__wrap_rmdir_ex, name, GROUPS_DIR);
    will_return(__wrap_rmdir_ex, OS_INVALID);
    will_return(__wrap_strerror, "ERROR");
    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:database");
    expect_string(__wrap__mtdebug1, formatted_msg, "Unable to remove directory 'queue/agent-groups': 'ERROR' (39)");

    wm_sync_legacy_groups_files();

    os_free(dir_ent);
}

void test_wm_sync_legacy_groups_files_success_files_success_dir(void **state) {
    DIR *dir = (DIR *)1;
    struct dirent *dir_ent = NULL;
    os_calloc(1, sizeof(struct dirent), dir_ent);
    strncpy(dir_ent->d_name, "001\0", 11);

    // Opening groups directory and iterating files
    will_return(__wrap_opendir, dir);
    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:database");
    expect_string(__wrap__mtdebug1, formatted_msg, "Scanning directory 'queue/agent-groups'.");
    will_return(__wrap_readdir, dir_ent);
    is_worker = 0;

    // Preparing data for the call to wm_sync_group_file
    const char *group_file = "001";
    const char *group_file_path = GROUPS_DIR "/001";
    int agent_id = atoi(group_file);
    FILE *fp_group_file = (FILE *)1;
    // Generating a CSV groups string with 128 groups
    char *groups_in_file = generate_groups_csv_string(MAX_GROUPS_PER_MULTIGROUP);
    // Calling wm_sync_group_file
    // Agent groups file opened succesfully
    expect_string(__wrap_fopen, path, group_file_path);
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, fp_group_file);
    // Reading the file
    will_return(__wrap_fgets, groups_in_file);
    expect_value(__wrap_fgets, __stream, fp_group_file);
    // Setting groups
    will_return(__wrap_w_is_single_node, 1);
    expect_value(__wrap_wdb_set_agent_groups, id, agent_id);
    expect_string(__wrap_wdb_set_agent_groups, mode, "override");
    expect_string(__wrap_wdb_set_agent_groups, sync_status, "synced");
    will_return(__wrap_wdb_set_agent_groups, OS_SUCCESS);
    // Closing group file
    expect_value(__wrap_fclose, _File, fp_group_file);
    will_return(__wrap_fclose, OS_SUCCESS);

    // Logging result, removing agent groups file, and finalizing the dir iteration
    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:database");
    expect_string(__wrap__mtdebug1, formatted_msg, "Group file 'queue/agent-groups/001' successfully synced, removing.");
    expect_string(__wrap_unlink, file, "queue/agent-groups/001");
    will_return(__wrap_unlink, OS_SUCCESS);
    will_return(__wrap_readdir, NULL);

    // Removing the groups directory
    expect_string(__wrap_rmdir_ex, name, GROUPS_DIR);
    will_return(__wrap_rmdir_ex, OS_SUCCESS);

    wm_sync_legacy_groups_files();

    os_free(groups_in_file);
    os_free(dir_ent);
}

void test_wm_sync_legacy_groups_files_error_files(void **state) {
    DIR *dir = (DIR *)1;
    struct dirent *dir_ent = NULL;
    os_calloc(1, sizeof(struct dirent), dir_ent);
    strncpy(dir_ent->d_name, "001\0", 11);

    // Opening groups directory and iterating files
    will_return(__wrap_opendir, dir);
    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:database");
    expect_string(__wrap__mtdebug1, formatted_msg, "Scanning directory 'queue/agent-groups'.");
    will_return(__wrap_readdir, dir_ent);
    is_worker = 0;

    // Preparing data for the call to wm_sync_group_file
    const char *group_file_path = GROUPS_DIR "/001";
    // Calling wm_sync_group_file
    // Error opening agent groups file specified by 'group_file_path'
    expect_string(__wrap_fopen, path, group_file_path);
    expect_string(__wrap_fopen, mode, "r");
    will_return(__wrap_fopen, NULL);
    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:database");
    expect_string(__wrap__mtdebug1, formatted_msg, "Groups file 'queue/agent-groups/001' could not be opened for syncronization.");

    // Logging result and finalizing the dir iteration
    expect_string(__wrap__merror, formatted_msg, "Failed during the groups file 'queue/agent-groups/001' syncronization.");
    will_return(__wrap_readdir, NULL);

    wm_sync_legacy_groups_files();

    os_free(dir_ent);
}

// sync_agents_artifacts_with_wdb
void test_sync_agents_artifacts_with_wdb_opendir_error(void **state) {
    keystore *keys = NULL;
    os_calloc(1, sizeof(keystore), keys);

    will_return(__wrap_opendir, NULL);
    will_return(__wrap_strerror, "ERROR");
    expect_string(__wrap__mterror, tag, "wazuh-modulesd:database");
    expect_string(__wrap__mterror, formatted_msg, "Couldn't open directory 'var/db/agents': ERROR.");

    sync_agents_artifacts_with_wdb(keys);

    os_free(keys);
}

void test_sync_agents_artifacts_with_wdb_empty_agent_name(void **state) {
    struct dirent *dir_ent = NULL;
    keystore *keys = NULL;
    os_calloc(1, sizeof(struct dirent), dir_ent);
    os_calloc(1, sizeof(keystore), keys);
    strcpy(dir_ent->d_name, "001-centos.db");

    will_return(__wrap_opendir, (DIR *)1);
    will_return(__wrap_readdir, dir_ent);

    char *agent_name = NULL;
    os_strdup("", agent_name);
    expect_value(__wrap_wdb_get_agent_name, id, 1);
    will_return(__wrap_wdb_get_agent_name, agent_name);

    will_return(__wrap_readdir, NULL);

    // wm_clean_agent_artifacts
    char *wdb_response = "{\"agents\":{\"001\":\"ok\"}}";

    expect_value(__wrap_wdb_remove_agent_db, id, 1);
    expect_string(__wrap_wdb_remove_agent_db, name, "centos");
    will_return(__wrap_wdb_remove_agent_db, OS_SUCCESS);

    expect_value(__wrap_wdbc_query_ex, *sock, -1);
    expect_string(__wrap_wdbc_query_ex, query, "wazuhdb remove 1");
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, wdb_response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    char path[OS_MAXSTR] = {0};
    snprintf(path, OS_MAXSTR, "%s/centos", DIFF_DIR);

    expect_string(__wrap_rmdir_ex, name, path);
    will_return(__wrap_rmdir_ex, OS_SUCCESS);

    sync_agents_artifacts_with_wdb(keys);

    os_free(dir_ent);
    os_free(keys);
}

void test_sync_agents_artifacts_with_wdb_bad_file_name(void **state) {
    struct dirent *dir_ent = NULL;
    keystore *keys = NULL;
    os_calloc(1, sizeof(struct dirent), dir_ent);
    os_calloc(1, sizeof(keystore), keys);
    strcpy(dir_ent->d_name, "001.db");

    will_return(__wrap_opendir, (DIR *)1);
    will_return(__wrap_readdir, dir_ent);

    will_return(__wrap_readdir, NULL);

    sync_agents_artifacts_with_wdb(keys);

    os_free(dir_ent);
    os_free(keys);
}

void test_sync_agents_artifacts_with_wdb_bad_file_name2(void **state) {
    struct dirent *dir_ent = NULL;
    keystore *keys = NULL;
    os_calloc(1, sizeof(struct dirent), dir_ent);
    os_calloc(1, sizeof(keystore), keys);
    strcpy(dir_ent->d_name, "001-");

    will_return(__wrap_opendir, (DIR *)1);
    will_return(__wrap_readdir, dir_ent);

    char *agent_name = NULL;
    os_strdup("", agent_name);
    expect_value(__wrap_wdb_get_agent_name, id, 1);
    will_return(__wrap_wdb_get_agent_name, agent_name);

    will_return(__wrap_readdir, NULL);

    // wm_clean_agent_artifacts
    char *wdb_response = "{\"agents\":{\"001\":\"ok\"}}";

    expect_value(__wrap_wdb_remove_agent_db, id, 1);
    will_return(__wrap_wdb_remove_agent_db, OS_INVALID);
    expect_string(__wrap__mtdebug1, formatted_msg, "Could not remove the legacy DB of the agent 1.");
    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:database");

    expect_value(__wrap_wdbc_query_ex, *sock, -1);
    expect_string(__wrap_wdbc_query_ex, query, "wazuhdb remove 1");
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, wdb_response);
    will_return(__wrap_wdbc_query_ex, OS_SUCCESS);

    sync_agents_artifacts_with_wdb(keys);

    os_free(dir_ent);
    os_free(keys);
}

void test_sync_agents_artifacts_with_wdb_agent_exists_in_db(void **state) {
    struct dirent *dir_ent = NULL;
    keystore *keys = NULL;
    os_calloc(1, sizeof(struct dirent), dir_ent);
    os_calloc(1, sizeof(keystore), keys);
    strcpy(dir_ent->d_name, "001-centos.db");

    will_return(__wrap_opendir, (DIR *)1);
    will_return(__wrap_readdir, dir_ent);

    char *agent_name = NULL;
    os_strdup("centos", agent_name);
    expect_value(__wrap_wdb_get_agent_name, id, 1);
    will_return(__wrap_wdb_get_agent_name, agent_name);

    will_return(__wrap_readdir, NULL);

    sync_agents_artifacts_with_wdb(keys);

    os_free(dir_ent);
    os_free(keys);
}


int main()
{
    const struct CMUnitTest tests[] = {
        // wm_sync_group_file
        cmocka_unit_test_setup_teardown(test_wm_sync_group_file_error_agent_id, setup_wmdb, teardown_wmdb),
        cmocka_unit_test_setup_teardown(test_wm_sync_group_file_error_opening_file, setup_wmdb, teardown_wmdb),
        cmocka_unit_test_setup_teardown(test_wm_sync_group_file_success_empty_file, setup_wmdb, teardown_wmdb),
        cmocka_unit_test_setup_teardown(test_wm_sync_group_file_success_more_than_max_groups, setup_wmdb, teardown_wmdb),
        cmocka_unit_test_setup_teardown(test_wm_sync_group_file_success_max_groups, setup_wmdb, teardown_wmdb),
        // wm_sync_legacy_groups_files
        cmocka_unit_test_setup_teardown(test_wm_sync_legacy_groups_files_error_opening_groups_dir, setup_wmdb, teardown_wmdb),
        cmocka_unit_test_setup_teardown(test_wm_sync_legacy_groups_files_success_files_worker_error_dir, setup_wmdb, teardown_wmdb),
        cmocka_unit_test_setup_teardown(test_wm_sync_legacy_groups_files_success_files_success_dir, setup_wmdb, teardown_wmdb),
        cmocka_unit_test_setup_teardown(test_wm_sync_legacy_groups_files_error_files, setup_wmdb, teardown_wmdb),
        // sync_agents_artifacts_with_wdb
        cmocka_unit_test_setup_teardown(test_sync_agents_artifacts_with_wdb_opendir_error, setup_wmdb, teardown_wmdb),
        cmocka_unit_test_setup_teardown(test_sync_agents_artifacts_with_wdb_empty_agent_name, setup_wmdb, teardown_wmdb),
        cmocka_unit_test_setup_teardown(test_sync_agents_artifacts_with_wdb_bad_file_name, setup_wmdb, teardown_wmdb),
        cmocka_unit_test_setup_teardown(test_sync_agents_artifacts_with_wdb_bad_file_name2, setup_wmdb, teardown_wmdb),
        cmocka_unit_test_setup_teardown(test_sync_agents_artifacts_with_wdb_agent_exists_in_db, setup_wmdb, teardown_wmdb),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
