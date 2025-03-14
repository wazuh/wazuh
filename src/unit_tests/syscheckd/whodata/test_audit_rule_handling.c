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

#include "../../wrappers/common.h"
#include "../../../syscheckd/include/syscheck.h"
#include "../../../syscheckd/src/whodata/syscheck_audit.h"


#include "wrappers/externals/audit/libaudit_wrappers.h"
#include "wrappers/externals/procpc/readproc_wrappers.h"
#include "wrappers/libc/stdio_wrappers.h"
#include "wrappers/libc/stdlib_wrappers.h"
#include "wrappers/posix/unistd_wrappers.h"
#include "wrappers/wazuh/shared/audit_op_wrappers.h"
#include "wrappers/wazuh/shared/debug_op_wrappers.h"
#include "wrappers/wazuh/shared/file_op_wrappers.h"
#include "wrappers/wazuh/syscheckd/audit_parse_wrappers.h"


#define PERMS (AUDIT_PERM_WRITE | AUDIT_PERM_ATTR)
#define CHECK_ALL                                                                                           \
    (CHECK_MD5SUM | CHECK_SHA1SUM | CHECK_SHA256SUM | CHECK_PERM | CHECK_SIZE | CHECK_OWNER | CHECK_GROUP | \
     CHECK_MTIME | CHECK_INODE)

extern OSList *whodata_directories;
OSList *GENERAL_CONFIG;
OSList *RELOAD_CONFIG;

extern int audit_rule_manipulation;

extern atomic_int_t audit_thread_active;

/* setup/teardown */
static int setup_group(void **state) {

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);

    directory_t *directory0 = fim_create_directory("/testdir0", CHECK_ALL | AUDIT_DRIVER | WHODATA_ACTIVE, NULL, 512, NULL, 1024, 0);
    directory_t *directory1 = fim_create_directory("/testdir1", CHECK_ALL | AUDIT_DRIVER | WHODATA_ACTIVE, NULL, 512, NULL, 1024, 0);
    directory_t *directory2 = fim_create_directory("/testdir2", CHECK_ALL | AUDIT_DRIVER | WHODATA_ACTIVE, NULL, 512, NULL, 1024, 0);
    directory_t *directory3 = fim_create_directory("/testdir3", CHECK_ALL | AUDIT_DRIVER | WHODATA_ACTIVE, NULL, 512, NULL, 1024, 0);
    directory_t *directory4 = fim_create_directory("/testdir4", CHECK_ALL | AUDIT_DRIVER | WHODATA_ACTIVE, NULL, 512, NULL, 1024, 0);
    directory_t *directory5 = fim_create_directory("/testdir5", CHECK_ALL | AUDIT_DRIVER | WHODATA_ACTIVE, NULL, 512, NULL, 1024, 0);
    directory_t *directory6 = fim_create_directory("/etc", CHECK_ALL | AUDIT_DRIVER | WHODATA_ACTIVE, NULL, 512, NULL, 1024, 0);

    directory_t *general_directory0 = fim_copy_directory(directory0);
    directory_t *general_directory1 = fim_copy_directory(directory1);
    directory_t *general_directory2 = fim_copy_directory(directory2);
    directory_t *general_directory3 = fim_copy_directory(directory3);
    directory_t *general_directory4 = fim_copy_directory(directory4);

    // Initialize directories list
    GENERAL_CONFIG = OSList_Create();
    RELOAD_CONFIG = OSList_Create();
    if (GENERAL_CONFIG == NULL || RELOAD_CONFIG == NULL) {
        return -1;
    }

    OSList_InsertData(GENERAL_CONFIG, NULL, general_directory0);
    OSList_InsertData(GENERAL_CONFIG, NULL, general_directory1);
    OSList_InsertData(GENERAL_CONFIG, NULL, general_directory2);
    OSList_InsertData(GENERAL_CONFIG, NULL, general_directory3);
    OSList_InsertData(GENERAL_CONFIG, NULL, general_directory4);

    OSList_InsertData(RELOAD_CONFIG, NULL, directory0);
    OSList_InsertData(RELOAD_CONFIG, NULL, directory1);
    OSList_InsertData(RELOAD_CONFIG, NULL, directory2);
    OSList_InsertData(RELOAD_CONFIG, NULL, directory3);
    OSList_InsertData(RELOAD_CONFIG, NULL, directory4);
    OSList_InsertData(RELOAD_CONFIG, NULL, directory5);
    OSList_InsertData(RELOAD_CONFIG, NULL, directory6);

    syscheck.directories = GENERAL_CONFIG;

    // The basic list needs to be created, we won't test this function.
    fim_audit_rules_init();

    return 0;
}

static int teardown_group(void **state) {
    OSListNode *node_it;

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);

    if (GENERAL_CONFIG) {
        OSList_foreach(node_it, GENERAL_CONFIG) {
            free_directory(node_it->data);
            node_it->data = NULL;
        }
        OSList_Destroy(GENERAL_CONFIG);
        GENERAL_CONFIG = NULL;
    }

    if (RELOAD_CONFIG) {
        OSList_foreach(node_it, RELOAD_CONFIG) {
            free_directory(node_it->data);
            node_it->data = NULL;
        }
        OSList_Destroy(RELOAD_CONFIG);
        RELOAD_CONFIG = NULL;
    }

    return 0;
}

static int teardown_clean_rules_list(void **state) {
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);

    OSList_CleanNodes(whodata_directories);

    return 0;
}

static int setup_add_directories_to_whodata_list(void **state) {
    directory_t *dir_it;
    OSListNode *node_it;

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);

    syscheck.directories = RELOAD_CONFIG;

    OSList_foreach(node_it, syscheck.directories) {
        dir_it = node_it->data;
        whodata_directory_t *dir = calloc(1, sizeof(whodata_directory_t));

        if (dir == NULL) {
            return -1;
        }

        dir->path = strdup(dir_it->path);

        if (dir->path == NULL) {
            return -1;
        }

        OSList_AddData(whodata_directories, dir);
    }

    syscheck.max_audit_entries = whodata_directories->currently_size;

    return 0;
}

static int teardown_reload_rules(void **state) {
    syscheck.directories = GENERAL_CONFIG;

    syscheck.max_audit_entries = 256;

    teardown_clean_rules_list(state);

    return 0;
}

static void test_add_whodata_directory(void **state) {
    const char *test_string = "/some/path";
    whodata_directory_t *probe;

    assert_int_equal(whodata_directories->currently_size, 0);

    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);

    add_whodata_directory(test_string);

    assert_int_equal(whodata_directories->currently_size, 1);

    probe = whodata_directories->first_node->data;
    assert_string_equal(probe->path, test_string);

    probe->pending_removal = 1;

    add_whodata_directory(test_string);

    assert_ptr_equal(probe, whodata_directories->first_node->data);
    assert_int_equal(probe->pending_removal, 0);
}

static void test_remove_audit_rule_syscheck(void **state) {
    whodata_directory_t *dir = calloc(1, sizeof(whodata_directory_t));

    if (dir == NULL) {
        fail_msg("Failed to allocate memory for whodata_directory_t");
    }

    dir->pending_removal = 0;
    dir->path = strdup("/some/path");

    if (dir->path == NULL) {
        fail_msg("Failed to allocate memory for path");
    }

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);

    if (OSList_AddData(whodata_directories, dir) == NULL) {
        fail_msg("Failed to add directory to the whodata rules list");
    }

    remove_audit_rule_syscheck("/some/path");

    assert_int_equal(dir->pending_removal, 1);
}

static void test_fim_manipulated_audit_rules(void **state) {
    audit_rule_manipulation = 2;

    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);

    assert_int_equal(fim_manipulated_audit_rules(), 2);
    assert_int_equal(fim_manipulated_audit_rules(), 1);
    assert_int_equal(fim_manipulated_audit_rules(), 0);
    assert_int_equal(fim_manipulated_audit_rules(), 0);
}

void test_rules_initial_load_new_rules(void **state) {
    char log_messages[5][OS_SIZE_512];
    int total_rules;

    syscheck.max_audit_entries = 256; // Default value

    will_return(__wrap_audit_open, 1);
    will_return(__wrap_audit_get_rule_list, 1);
    will_return(__wrap_audit_close, 1);

    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);

    // First directory will be added
    will_return(__wrap_search_audit_rule, 0);
    will_return(__wrap_audit_add_rule, 15);

    snprintf(log_messages[0], OS_SIZE_512, FIM_AUDIT_NEWRULE, ((directory_t *)OSList_GetDataFromIndex(GENERAL_CONFIG, 0))->path);
    expect_string(__wrap__mdebug2, formatted_msg, log_messages[0]);

    // Second directory will have the rule already configured
    will_return(__wrap_search_audit_rule, 0);
    will_return(__wrap_audit_add_rule, -EEXIST);

    snprintf(log_messages[1], OS_SIZE_512, FIM_AUDIT_ALREADY_ADDED, ((directory_t *)OSList_GetDataFromIndex(GENERAL_CONFIG, 1))->path);
    expect_string(__wrap__mdebug2, formatted_msg, log_messages[1]);

    // Third directory will encounter an error
    will_return(__wrap_search_audit_rule, 0);
    will_return(__wrap_audit_add_rule, -1);
    snprintf(log_messages[2], OS_SIZE_512, FIM_WARN_WHODATA_ADD_RULE, ((directory_t *)OSList_GetDataFromIndex(GENERAL_CONFIG, 2))->path);
    expect_string(__wrap__mwarn, formatted_msg, log_messages[2]);

    // Fourth directory will be duplicated on the audit_op list
    will_return(__wrap_search_audit_rule, 1);

    snprintf(log_messages[3], OS_SIZE_512, FIM_AUDIT_RULEDUP, ((directory_t *)OSList_GetDataFromIndex(GENERAL_CONFIG, 3))->path);
    expect_string(__wrap__mdebug2, formatted_msg, log_messages[3]);

    // Fifth directory will encounter an error
    will_return(__wrap_search_audit_rule, -1);
    expect_string(__wrap__merror, formatted_msg, FIM_ERROR_WHODATA_CHECK_RULE);

    total_rules = fim_rules_initial_load();

    assert_int_equal(total_rules, 1);
}

void test_rules_initial_load_max_audit_entries(void **state) {
    char log_messages[2][OS_SIZE_512];
    int total_rules;

    syscheck.max_audit_entries = 1;

    will_return(__wrap_audit_open, 1);
    will_return(__wrap_audit_get_rule_list, 1);
    will_return(__wrap_audit_close, 1);

    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);

    // First directory will be added
    will_return(__wrap_search_audit_rule, 0);
    will_return(__wrap_audit_add_rule, 15);

    snprintf(log_messages[0], OS_SIZE_512, FIM_AUDIT_NEWRULE, ((directory_t *)OSList_GetDataFromIndex(GENERAL_CONFIG, 0))->path);
    expect_string(__wrap__mdebug2, formatted_msg, log_messages[0]);

    // Second directory will be ignored, since we have room for 1 entry
    snprintf(log_messages[1], OS_SIZE_512, FIM_ERROR_WHODATA_MAXNUM_WATCHES, ((directory_t *)OSList_GetDataFromIndex(GENERAL_CONFIG, 1))->path,
             syscheck.max_audit_entries);
    expect_string(__wrap__merror, formatted_msg, log_messages[1]);

    total_rules = fim_rules_initial_load();

    assert_int_equal(total_rules, 1);
}

static void test_clean_rules(void **state) {
    // Ensure there are rules loaded prior to trying to delete them
    assert_int_not_equal(whodata_directories->currently_size, 0);

    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);

    expect_string(__wrap__mdebug2, formatted_msg, FIM_AUDIT_DELETE_RULE);

    expect_value(__wrap_atomic_int_set, atomic, &audit_thread_active);
    will_return(__wrap_atomic_int_set, 0);

    expect_any_count(__wrap_audit_delete_rule, path, whodata_directories->currently_size);
    expect_any_count(__wrap_audit_delete_rule, perms, whodata_directories->currently_size);
    expect_any_count(__wrap_audit_delete_rule, key, whodata_directories->currently_size);
    will_return_count(__wrap_audit_delete_rule, 1, whodata_directories->currently_size);

    clean_rules();

    assert_int_equal(whodata_directories->currently_size, 0);
}

static void test_fim_audit_reload_rules(void **state) {
    char log_messages[7][OS_SIZE_512];
    int initial_rules = whodata_directories->currently_size;
    whodata_directory_t *probe;

    assert_int_not_equal(initial_rules, 0);

    // We will mark the first and third entry for removal.
    probe = whodata_directories->first_node->data;
    probe->pending_removal = 1;

    probe = whodata_directories->first_node->next->next->data;
    probe->pending_removal = 1;

    expect_string(__wrap__mdebug1, formatted_msg, FIM_AUDIT_RELOADING_RULES);

    will_return(__wrap_audit_open, 1);
    will_return(__wrap_audit_get_rule_list, 1);
    will_return(__wrap_audit_close, 1);

    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_wrlock);

    // First directory won't have a configured rule
    will_return(__wrap_search_audit_rule, 0);

    // Second directory will be added to audit
    will_return(__wrap_search_audit_rule, 0);
    will_return(__wrap_audit_add_rule, 15);

    snprintf(log_messages[1], OS_SIZE_512, FIM_AUDIT_NEWRULE, ((directory_t *)OSList_GetDataFromIndex(RELOAD_CONFIG, 1))->path);
    expect_string(__wrap__mdebug2, formatted_msg, log_messages[1]);

    // Third directory will be removed from audit
    will_return(__wrap_search_audit_rule, 1);
    expect_string(__wrap_audit_delete_rule, path, ((directory_t *)OSList_GetDataFromIndex(RELOAD_CONFIG, 2))->path);
    expect_value(__wrap_audit_delete_rule, perms, PERMS);
    expect_string(__wrap_audit_delete_rule, key, AUDIT_KEY);
    will_return(__wrap_audit_delete_rule, 1);

    // Fourth directory will be a rule that is already added to audit
    will_return(__wrap_search_audit_rule, 1);

    snprintf(log_messages[3], OS_SIZE_512, FIM_AUDIT_RULEDUP, ((directory_t *)OSList_GetDataFromIndex(RELOAD_CONFIG, 3))->path);
    expect_string(__wrap__mdebug2, formatted_msg, log_messages[3]);

    // Fifth directory will fail to be added
    will_return(__wrap_search_audit_rule, 0);
    will_return(__wrap_audit_add_rule, -1);
    snprintf(log_messages[4], OS_SIZE_512, FIM_WARN_WHODATA_ADD_RULE, ((directory_t *)OSList_GetDataFromIndex(RELOAD_CONFIG, 4))->path);
    expect_string(__wrap__mdebug1, formatted_msg, log_messages[4]);

    // Sixth directory will attempt to be added, but find it's duplicated
    will_return(__wrap_search_audit_rule, 0);
    will_return(__wrap_audit_add_rule, -EEXIST);

    snprintf(log_messages[5], OS_SIZE_512, FIM_AUDIT_ALREADY_ADDED, ((directory_t *)OSList_GetDataFromIndex(RELOAD_CONFIG, 5))->path);
    expect_string(__wrap__mdebug2, formatted_msg, log_messages[5]);

    // Seventh directory will encounter an error when searching the rule
    will_return(__wrap_search_audit_rule, -1);
    expect_string(__wrap__merror, formatted_msg, FIM_ERROR_WHODATA_CHECK_RULE);

    expect_any(__wrap__mdebug1, formatted_msg);

    fim_audit_reload_rules();

    assert_int_equal(whodata_directories->currently_size, initial_rules - 2);
    assert_int_equal(audit_rule_manipulation, 1);
}

static void test_fim_audit_reload_rules_full(void **state) {
    char log_messages[7][OS_SIZE_512];
    int initial_rules = whodata_directories->currently_size;
    int i = 0;
    OSListNode *node_it;
    directory_t *dir_it;

    // We trick fim_audit_reload_rules() into thinking it already has added all possible rules.
    syscheck.max_audit_entries = 0;

    assert_int_not_equal(initial_rules, 0);

    expect_string(__wrap__mdebug1, formatted_msg, FIM_AUDIT_RELOADING_RULES);

    will_return(__wrap_audit_open, 1);
    will_return(__wrap_audit_get_rule_list, 1);
    will_return(__wrap_audit_close, 1);

    expect_function_call_any(__wrap_pthread_rwlock_wrlock);
    expect_function_call_any(__wrap_pthread_rwlock_unlock);
    expect_function_call_any(__wrap_pthread_rwlock_rdlock);
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);

    will_return_always(__wrap_search_audit_rule, 0);

    OSList_foreach(node_it, RELOAD_CONFIG) {
        dir_it = node_it->data;
        snprintf(log_messages[i], OS_SIZE_512, FIM_ERROR_WHODATA_MAXNUM_WATCHES, dir_it->path, 0);
        if (i == 0) {
            // First directory will cause an error message
            expect_string(__wrap__merror, formatted_msg, log_messages[i]);
        } else {
            // The rest of them will trigger debug messages
            expect_string(__wrap__mdebug2, formatted_msg, log_messages[i]);
        }
        i++;
    }

    expect_any(__wrap__mdebug1, formatted_msg);

    fim_audit_reload_rules();
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_teardown(test_add_whodata_directory, teardown_clean_rules_list),
        cmocka_unit_test_teardown(test_remove_audit_rule_syscheck, teardown_clean_rules_list),
        cmocka_unit_test(test_fim_manipulated_audit_rules),

        // fim_rules_initial_load
        cmocka_unit_test_teardown(test_rules_initial_load_new_rules, teardown_clean_rules_list),
        cmocka_unit_test(test_rules_initial_load_max_audit_entries),

        cmocka_unit_test_setup(test_clean_rules, setup_add_directories_to_whodata_list),

        cmocka_unit_test_setup_teardown(test_fim_audit_reload_rules, setup_add_directories_to_whodata_list,
                                        teardown_reload_rules),
        cmocka_unit_test_setup_teardown(test_fim_audit_reload_rules_full, setup_add_directories_to_whodata_list,
                                        teardown_reload_rules),
    };

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
