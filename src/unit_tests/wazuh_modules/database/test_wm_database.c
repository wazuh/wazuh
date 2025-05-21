/*
 * Copyright (C) 2015, Wazuh Inc.
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
#include "../../wrappers/wazuh/os_crypto/keys_wrappers.h"
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../wrappers/wazuh/shared/file_op_wrappers.h"
#include "../../wrappers/wazuh/shared/rbtree_op_wrappers.h"
#include "../../wrappers/wazuh/shared/validate_op_wrappers.h"
#include "../../wrappers/wazuh/wazuh_db/wdb_global_helpers_wrappers.h"
#include "../../wrappers/wazuh/wazuh_db/wdb_wrappers.h"
#include "../../wrappers/libc/stdio_wrappers.h"
#include "../../wrappers/libc/string_wrappers.h"
#include "../../wrappers/posix/dirent_wrappers.h"
#include "../../wrappers/posix/unistd_wrappers.h"

extern const wm_context WM_DATABASE_CONTEXT;

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

int setup_keys_to_db(void **state) {
    keystore keys = KEYSTORE_INITIALIZER;

    keyentry** keyentries;
    os_calloc(1, sizeof(keyentry*), keyentries);
    keys.keyentries = keyentries;

    keyentry *key = NULL;
    os_calloc(1, sizeof(keyentry), key);
    keys.keyentries[0] = key;

    key->id = strdup("001");
    key->name = strdup("agent1");
    key->ip = (os_ip *)1;
    key->raw_key = strdup("1234567890abcdef");

    os_calloc(1, sizeof(keystore), *state);
    memcpy(*state, &keys, sizeof(keystore));

    test_mode = 1;
    return OS_SUCCESS;
}

int teardown_keys_to_db(void **state) {
    keystore * keys = (keystore *)*state;

    os_free(keys->keyentries[0]->id);
    os_free(keys->keyentries[0]->name);
    os_free(keys->keyentries[0]->raw_key);
    os_free(keys->keyentries[0]);
    os_free(keys->keyentries);
    os_free(keys);

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
    expect_string(__wrap_wfopen, path, group_file_path);
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, NULL);
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
    expect_string(__wrap_wfopen, path, group_file_path);
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, fp_group_file);
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
    expect_string(__wrap_wfopen, path, group_file_path);
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, fp_group_file);
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
    expect_string(__wrap_wfopen, path, group_file_path);
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, fp_group_file);
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
    expect_string(__wrap_wfopen, path, group_file_path);
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, fp_group_file);
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
    expect_string(__wrap_wfopen, path, group_file_path);
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, NULL);
    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:database");
    expect_string(__wrap__mtdebug1, formatted_msg, "Groups file 'queue/agent-groups/001' could not be opened for syncronization.");

    // Logging result and finalizing the dir iteration
    expect_string(__wrap__merror, formatted_msg, "Failed during the groups file 'queue/agent-groups/001' syncronization.");
    will_return(__wrap_readdir, NULL);

    wm_sync_legacy_groups_files();

    os_free(dir_ent);
}

/* Tests sync_keys_with_wdb */

void test_sync_keys_with_wdb_insert(void **state) {
    keystore keys = *((keystore *)*state);
    keys.keysize = 1;

    rb_tree *tree = NULL;
    os_calloc(1, sizeof(rb_tree), tree);

    char *test_ip = "1.1.1.1";

    char **ids = NULL;
    ids = os_AddStrArray("001", ids);

    expect_value(__wrap_wdb_get_all_agents_rbtree, include_manager, 0);
    will_return(__wrap_wdb_get_all_agents_rbtree, tree);

    expect_value(__wrap_rbtree_get, tree, tree);
    expect_string(__wrap_rbtree_get, key, keys.keyentries[0]->id);
    will_return(__wrap_rbtree_get, NULL);

    expect_string(__wrap__mtdebug2, tag, "wazuh-modulesd:database");
    expect_string(__wrap__mtdebug2, formatted_msg, "Synchronizing agent 001 'agent1'.");

    expect_any(__wrap_OS_CIDRtoStr, ip);
    expect_value(__wrap_OS_CIDRtoStr, size, IPSIZE);
    will_return(__wrap_OS_CIDRtoStr, test_ip);
    will_return(__wrap_OS_CIDRtoStr, 0);

    expect_value(__wrap_wdb_insert_agent, id, 1);
    expect_string(__wrap_wdb_insert_agent, name, keys.keyentries[0]->name);
    expect_string(__wrap_wdb_insert_agent, register_ip, test_ip);
    expect_string(__wrap_wdb_insert_agent, internal_key, keys.keyentries[0]->raw_key);
    expect_value(__wrap_wdb_insert_agent, keep_date, 1);
    will_return(__wrap_wdb_insert_agent, 1);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:database");
    expect_string(__wrap__mtdebug1, formatted_msg, "Couldn't insert agent '001' in the database.");

    will_return(__wrap_rbtree_keys, ids);

    expect_string(__wrap_OS_IsAllowedID, id, keys.keyentries[0]->id);
    will_return(__wrap_OS_IsAllowedID, 0);

    sync_keys_with_wdb(&keys);
}

void test_sync_keys_with_wdb_delete(void **state) {
    keystore keys = *((keystore *)*state);
    keys.keysize = 1;

    rb_tree *tree = NULL;
    os_calloc(1, sizeof(rb_tree), tree);

    char **ids = NULL;
    ids = os_AddStrArray("001", ids);

    char *test_name = strdup("TESTNAME");

    expect_value(__wrap_wdb_get_all_agents_rbtree, include_manager, 0);
    will_return(__wrap_wdb_get_all_agents_rbtree, tree);

    expect_value(__wrap_rbtree_get, tree, tree);
    expect_string(__wrap_rbtree_get, key, keys.keyentries[0]->id);
    will_return(__wrap_rbtree_get, 1);

    will_return(__wrap_rbtree_keys, ids);

    expect_string(__wrap_OS_IsAllowedID, id, keys.keyentries[0]->id);
    will_return(__wrap_OS_IsAllowedID, -1);

    expect_value(__wrap_wdb_get_agent_name, id, 1);
    will_return(__wrap_wdb_get_agent_name, test_name);

    expect_value(__wrap_wdb_remove_agent, id, 1);
    will_return(__wrap_wdb_remove_agent, -1);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:database");
    expect_string(__wrap__mtdebug1, formatted_msg, "Couldn't remove agent '001' from the database.");

    sync_keys_with_wdb(&keys);
}

void test_sync_keys_with_wdb_insert_delete(void **state) {
    keystore keys = *((keystore *)*state);
    keys.keysize = 1;

    rb_tree *tree = NULL;
    os_calloc(1, sizeof(rb_tree), tree);

    char *test_ip = "1.1.1.1";
    char *test_name = strdup("TESTNAME");

    char **ids = NULL;
    ids = os_AddStrArray("001", ids);

    expect_value(__wrap_wdb_get_all_agents_rbtree, include_manager, 0);
    will_return(__wrap_wdb_get_all_agents_rbtree, tree);

    expect_value(__wrap_rbtree_get, tree, tree);
    expect_string(__wrap_rbtree_get, key, keys.keyentries[0]->id);
    will_return(__wrap_rbtree_get, NULL);

    expect_string(__wrap__mtdebug2, tag, "wazuh-modulesd:database");
    expect_string(__wrap__mtdebug2, formatted_msg, "Synchronizing agent 001 'agent1'.");

    expect_any(__wrap_OS_CIDRtoStr, ip);
    expect_value(__wrap_OS_CIDRtoStr, size, IPSIZE);
    will_return(__wrap_OS_CIDRtoStr, test_ip);
    will_return(__wrap_OS_CIDRtoStr, 0);

    expect_value(__wrap_wdb_insert_agent, id, 1);
    expect_string(__wrap_wdb_insert_agent, name, keys.keyentries[0]->name);
    expect_string(__wrap_wdb_insert_agent, register_ip, test_ip);
    expect_string(__wrap_wdb_insert_agent, internal_key, keys.keyentries[0]->raw_key);
    expect_value(__wrap_wdb_insert_agent, keep_date, 1);
    will_return(__wrap_wdb_insert_agent, 0);

    will_return(__wrap_rbtree_keys, ids);

    expect_string(__wrap_OS_IsAllowedID, id, keys.keyentries[0]->id);
    will_return(__wrap_OS_IsAllowedID, -1);

    expect_value(__wrap_wdb_get_agent_name, id, 1);
    will_return(__wrap_wdb_get_agent_name, test_name);

    expect_value(__wrap_wdb_remove_agent, id, 1);
    will_return(__wrap_wdb_remove_agent, 0);

    expect_value(__wrap_wdbc_query_ex, *sock, -1);
    expect_string(__wrap_wdbc_query_ex, query, "wazuhdb remove 1");
    expect_value(__wrap_wdbc_query_ex, len, OS_SIZE_1024);
    will_return(__wrap_wdbc_query_ex, "ok");
    will_return(__wrap_wdbc_query_ex, -1);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:database");
    expect_string(__wrap__mtdebug1, formatted_msg, "Could not remove the wazuh-db DB of the agent 1.");

    expect_string(__wrap_rmdir_ex, name, "queue/diff/TESTNAME");
    will_return(__wrap_rmdir_ex, 0);

    expect_string(__wrap_unlink, file, "queue/rids/001");
    will_return(__wrap_unlink, 0);

    expect_string(__wrap_wfopen, path, "queue/agents-timestamp");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, NULL);

    sync_keys_with_wdb(&keys);
}

void test_sync_keys_with_wdb_null(void **state) {
    keystore keys = *((keystore *)*state);
    keys.keysize = 1;

    expect_value(__wrap_wdb_get_all_agents_rbtree, include_manager, 0);
    will_return(__wrap_wdb_get_all_agents_rbtree, NULL);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:database");
    expect_string(__wrap__mterror, formatted_msg, "Couldn't synchronize the keystore with the DB.");

    sync_keys_with_wdb(&keys);
}

// Test wm_database_query

int setup_query(void **state) {
    return 0;
}

int teardown_query(void **state) {
    return 0;
}

void test_query_unknown(void **state) {
    char *query = "unknown";
    char *output = NULL;
    size_t ret;

    ret = WM_DATABASE_CONTEXT.query(NULL, query, &output);

    assert_non_null(output);
    assert_string_equal(output, "err {\"error\":12,\"message\":\"Query not supported\"}");
    assert_int_equal(ret, strlen(output));

    free(output);
}

void test_query_sync_agents(void **state) {
    char *query = "sync_agents";
    char *output = NULL;
    size_t ret;

    rb_tree *tree = NULL;
    os_calloc(1, sizeof(rb_tree), tree);

    is_worker = 1;

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:database");
    expect_string(__wrap__mtdebug1, formatted_msg, "Synchronizing agents.");
    expect_string(__wrap__mdebug1, formatted_msg, "(1402): Authentication key file 'etc/client.keys' not found.");
    expect_string(__wrap__mdebug1, formatted_msg, "(1751): File client.keys not found or empty.");

    expect_value(__wrap_wdb_get_all_agents_rbtree, include_manager, 0);
    will_return(__wrap_wdb_get_all_agents_rbtree, tree);
    will_return(__wrap_rbtree_keys, calloc(1, sizeof(char*)));

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:database");
    expect_string(__wrap__mtdebug1, formatted_msg, "Agents synchronization completed.");
    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:database");
    expect_any(__wrap__mtdebug1, formatted_msg);

    ret = WM_DATABASE_CONTEXT.query(NULL, query, &output);

    assert_non_null(output);
    assert_string_equal(output, "ok");
    assert_int_equal(ret, strlen(output));

    free(output);
}

void test_query_sync_agents_master(void **state) {
    char *query = "sync_agents";
    char *output = NULL;
    size_t ret;

    is_worker = 0;
    ret = WM_DATABASE_CONTEXT.query(NULL, query, &output);

    assert_non_null(output);
    assert_string_equal(output, "err {\"error\":11,\"message\":\"Node is not a worker\"}");
    assert_int_equal(ret, strlen(output));

    free(output);
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
        // sync_keys_with_wdb
        cmocka_unit_test_setup_teardown(test_sync_keys_with_wdb_insert, setup_keys_to_db, teardown_keys_to_db),
        cmocka_unit_test_setup_teardown(test_sync_keys_with_wdb_delete, setup_keys_to_db, teardown_keys_to_db),
        cmocka_unit_test_setup_teardown(test_sync_keys_with_wdb_insert_delete, setup_keys_to_db, teardown_keys_to_db),
        cmocka_unit_test_setup_teardown(test_sync_keys_with_wdb_null, setup_keys_to_db, teardown_keys_to_db),
        cmocka_unit_test(test_query_unknown),
        cmocka_unit_test_setup_teardown(test_query_sync_agents, setup_query, teardown_query),
        cmocka_unit_test(test_query_sync_agents_master),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
