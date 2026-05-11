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
#include "wmodules_def.h"
#include "wm_database.h"

#include "../../wrappers/common.h"
#include "../../wrappers/wazuh/os_crypto/keys_wrappers.h"
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../wrappers/wazuh/shared/file_op_wrappers.h"
#include "../../wrappers/wazuh/shared/rbtree_op_wrappers.h"
#include "../../wrappers/wazuh/shared/validate_op_wrappers.h"
#include "../../wrappers/wazuh/shared/wazuhdb_queries_op_wrappers.h"
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

/* Tests sync_keys_with_wdb */

void test_sync_keys_with_wdb_insert(void **state) {
    keystore keys = *((keystore *)*state);
    keys.keysize = 1;

    rb_tree *tree = NULL;
    os_calloc(1, sizeof(rb_tree), tree);

    char *test_ip = "1.1.1.1";

    char **ids = NULL;
    ids = os_AddStrArray("001", ids);

    will_return(__wrap_wdb_get_all_agents_rbtree, tree);

    expect_value(__wrap_rbtree_get, tree, tree);
    expect_string(__wrap_rbtree_get, key, keys.keyentries[0]->id);
    will_return(__wrap_rbtree_get, NULL);

    expect_string(__wrap__mtdebug2, tag, "wazuh-manager-modulesd:database");
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

    expect_string(__wrap__mtdebug1, tag, "wazuh-manager-modulesd:database");
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

    expect_string(__wrap__mtdebug1, tag, "wazuh-manager-modulesd:database");
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

    will_return(__wrap_wdb_get_all_agents_rbtree, tree);

    expect_value(__wrap_rbtree_get, tree, tree);
    expect_string(__wrap_rbtree_get, key, keys.keyentries[0]->id);
    will_return(__wrap_rbtree_get, NULL);

    expect_string(__wrap__mtdebug2, tag, "wazuh-manager-modulesd:database");
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

    expect_string(__wrap_rmdir_ex, name, "queue/diff/TESTNAME");
    will_return(__wrap_rmdir_ex, 0);

    expect_string(__wrap_unlink, file, "queue/rids/001");
    will_return(__wrap_unlink, 0);

    expect_string(__wrap_wfopen, path, "queue/agents-timestamp");
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, NULL);

    // Mock for initialize_router_functions() - router module not available in tests
    expect_string(__wrap_so_get_module_handle, so, "router");
    will_return(__wrap_so_get_module_handle, NULL);

    expect_string(__wrap__mtdebug2, tag, "wazuh-manager-modulesd:database");
    expect_string(__wrap__mtdebug2, formatted_msg, "Unable to load router module.");

    sync_keys_with_wdb(&keys);
}

void test_sync_keys_with_wdb_null(void **state) {
    keystore keys = *((keystore *)*state);
    keys.keysize = 1;

    will_return(__wrap_wdb_get_all_agents_rbtree, NULL);

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:database");
    expect_string(__wrap__mterror, formatted_msg, "Couldn't synchronize the keystore with the DB.");

    sync_keys_with_wdb(&keys);
}

int main()
{
    const struct CMUnitTest tests[] = {
        // sync_keys_with_wdb
        cmocka_unit_test_setup_teardown(test_sync_keys_with_wdb_insert, setup_keys_to_db, teardown_keys_to_db),
        cmocka_unit_test_setup_teardown(test_sync_keys_with_wdb_delete, setup_keys_to_db, teardown_keys_to_db),
        cmocka_unit_test_setup_teardown(test_sync_keys_with_wdb_insert_delete, setup_keys_to_db, teardown_keys_to_db),
        cmocka_unit_test_setup_teardown(test_sync_keys_with_wdb_null, setup_keys_to_db, teardown_keys_to_db),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
