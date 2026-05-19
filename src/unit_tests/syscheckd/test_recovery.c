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
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#include "../wrappers/common.h"
#include "../../syscheckd/src/recovery/recovery.h"
#include "../../syscheckd/src/db/include/db.h"
#include "../../syscheckd/src/file/file.h"
#include "../../shared_modules/sync_protocol/include/agent_sync_protocol_c_interface.h"
#include "syscheck-config.h"
#include "../wrappers/wazuh/shared_modules/agent_sync_protocol_wrappers.h"
#include "../wrappers/wazuh/shared_modules/schema_validator_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/posix/time_wrappers.h"

int64_t __wrap_fim_db_get_last_sync_time(const char* table_name);
void __wrap_fim_db_update_last_sync_time_value(const char* table_name, int64_t timestamp);
char* __wrap_fim_db_calculate_table_checksum(const char* table_name);
cJSON* __wrap_build_stateful_event_file(const char* path, const char* sha1_hash, const uint64_t document_version, const cJSON *dbsync_event, const fim_file_data *file_data);
// __wrap_fim_configuration_directory is provided by create_db_wrappers.c (shared wrapper).

#ifdef WIN32
cJSON* __wrap_build_stateful_event_registry_key(const char* path, const char* sha1_hash, const uint64_t document_version, int arch, const cJSON *dbsync_event, fim_registry_key *data);
cJSON* __wrap_build_stateful_event_registry_value(const char* path, const char* value, const char* sha1_hash, const uint64_t document_version, int arch, const cJSON *dbsync_event, fim_registry_value_data *registry_data);
#endif

// Mock directories list for tests
static OSList mock_directories = {0};

// Stand-in directory_t pointer for tests that only need a non-NULL "config exists" signal
static directory_t mock_directory_config = {0};

// Mock implementations
int64_t __wrap_fim_db_get_last_sync_time(const char* table_name) {
    check_expected(table_name);
    return mock_type(int64_t);
}

void __wrap_fim_db_update_last_sync_time_value(const char* table_name, int64_t timestamp) {
    check_expected(table_name);
    check_expected(timestamp);
}

char* __wrap_fim_db_calculate_table_checksum(const char* table_name) {
    check_expected(table_name);
    return mock_ptr_type(char*);
}

cJSON* __wrap_build_stateful_event_file(const char* path, const char* sha1_hash, const uint64_t document_version, const cJSON *dbsync_event, const fim_file_data *data) {
    check_expected_ptr(path);
    return mock_ptr_type(cJSON*);
}

#ifdef WIN32
cJSON* __wrap_build_stateful_event_registry_key(const char* path, const char* sha1_hash, const uint64_t document_version, int arch, const cJSON *dbsync_event, fim_registry_key *data) {
    check_expected_ptr(path);
    return mock_ptr_type(cJSON*);
}

cJSON* __wrap_build_stateful_event_registry_value(const char* path, const char* value, const char* sha1_hash, const uint64_t document_version, int arch, const cJSON *dbsync_event, fim_registry_value_data *registry_data) {
    check_expected_ptr(path);
    return mock_ptr_type(cJSON*);
}
#endif

// Test: first time integrity check (last sync time is 0)
static void test_fim_recovery_integrity_interval_has_elapsed_first_time(void **state) {
    (void) state;
    const int64_t integrity_interval = 86400; // 24 hours in seconds
    int64_t current_time = 1000000; // Fixed test time

#ifdef TEST_WINAGENT
    time_mock_value = current_time;
#else
    will_return(__wrap_time, current_time);
#endif

    expect_string(__wrap_fim_db_get_last_sync_time, table_name, FIMDB_FILE_TABLE_NAME);
    will_return(__wrap_fim_db_get_last_sync_time, 0);

    expect_string(__wrap_fim_db_update_last_sync_time_value, table_name, FIMDB_FILE_TABLE_NAME);
    expect_value(__wrap_fim_db_update_last_sync_time_value, timestamp, current_time);

    bool result = fim_recovery_integrity_interval_has_elapsed(FIMDB_FILE_TABLE_NAME, integrity_interval);

    assert_false(result);
}

// Test: integrity_interval has NOT elapsed (last sync recent)
static void test_fim_recovery_integrity_interval_has_elapsed_not_elapsed(void **state) {
    (void) state;
    const int64_t integrity_interval = 86400; // 24 hours in seconds
    int64_t current_time = 1000000; // Fixed test time

#ifdef TEST_WINAGENT
    time_mock_value = current_time;
#else
    will_return(__wrap_time, current_time);
#endif

    expect_string(__wrap_fim_db_get_last_sync_time, table_name, FIMDB_FILE_TABLE_NAME);
    will_return(__wrap_fim_db_get_last_sync_time, current_time);

    bool result = fim_recovery_integrity_interval_has_elapsed(FIMDB_FILE_TABLE_NAME, integrity_interval);

    assert_false(result);
}

// Test: integrity_interval HAS elapsed (last sync was long ago)
static void test_fim_recovery_integrity_interval_has_elapsed_elapsed(void **state) {
    (void) state;
    const int64_t integrity_interval = 86400; // 24 hours in seconds
    int64_t current_time = 1000000; // Fixed test time
    int64_t old_sync_time = current_time - (2 * integrity_interval); // 48 hours ago

#ifdef TEST_WINAGENT
    time_mock_value = current_time;
#else
    will_return(__wrap_time, current_time);
#endif

    expect_string(__wrap_fim_db_get_last_sync_time, table_name, FIMDB_FILE_TABLE_NAME);
    will_return(__wrap_fim_db_get_last_sync_time, old_sync_time);

    bool result = fim_recovery_integrity_interval_has_elapsed(FIMDB_FILE_TABLE_NAME, integrity_interval);

    assert_true(result);
}

// Test: Persist and resync with successful synchronization
static void test_fim_recovery_persist_table_and_resync_success(void **state) {
    (void) state;
    AgentSyncProtocolHandle* handle = (AgentSyncProtocolHandle*)0x1234; // Mock handle

    expect_any_always(__wrap__mdebug1, formatted_msg);

    // Create test data - simple file entry
    cJSON* test_items = cJSON_CreateArray();
    cJSON* item = cJSON_CreateObject();
    cJSON_AddStringToObject(item, "path", "/tmp/test.txt");
    cJSON_AddStringToObject(item, "checksum", "abc123");
    cJSON_AddNumberToObject(item, "version", 1);
    cJSON_AddNumberToObject(item, "inode", 12345);
    cJSON_AddItemToArray(test_items, item);

    // Expect fim_db_increase_each_entry_version call (called first)
    expect_string(__wrap_fim_db_increase_each_entry_version, table_name, FIMDB_FILE_TABLE_NAME);
    will_return(__wrap_fim_db_increase_each_entry_version, 0);

    // Expect fim_db_get_every_element to return our test items
    expect_string(__wrap_fim_db_get_every_element, table_name, FIMDB_FILE_TABLE_NAME);
    expect_string(__wrap_fim_db_get_every_element, row_filter, "WHERE sync=1");
    will_return(__wrap_fim_db_get_every_element, test_items);

    // Expect asp_clear_in_memory_data call
    expect_value(__wrap_asp_clear_in_memory_data, handle, handle);

    // Orphan guard: path must still resolve to a config
    expect_string(__wrap_fim_configuration_directory, path, "/tmp/test.txt");
    will_return(__wrap_fim_configuration_directory, &mock_directory_config);

    // Expect build_stateful_event_file to be called for our test item
    expect_string(__wrap_build_stateful_event_file, path, "/tmp/test.txt");
    // Return a mock stateful event
    cJSON* mock_event = cJSON_CreateObject();
    cJSON_AddStringToObject(mock_event, "type", "file");
    will_return(__wrap_build_stateful_event_file, mock_event);

    // Schema validator is not initialized (no validation)
    will_return(__wrap_schema_validator_is_initialized, false);

    // Expect asp_persist_diff_in_memory call - validate all parameters
    expect_value(__wrap_asp_persist_diff_in_memory, handle, handle);
    expect_any(__wrap_asp_persist_diff_in_memory, id);
    expect_value(__wrap_asp_persist_diff_in_memory, operation, OPERATION_CREATE);
    expect_string(__wrap_asp_persist_diff_in_memory, index, FIM_FILES_SYNC_INDEX);
    expect_any(__wrap_asp_persist_diff_in_memory, data);

    // Expect asp_sync_module call - return success
    expect_value(__wrap_asp_sync_module, handle, handle);
    expect_value(__wrap_asp_sync_module, mode, MODE_FULL);
    will_return(__wrap_asp_sync_module, true);

    // Call the function
    fim_recovery_persist_table_and_resync(FIMDB_FILE_TABLE_NAME, handle, &mock_directories);

    // The function should complete successfully
    // Note: test_items is freed by the function, so don't free it here
}

// Test: Persist and resync with failed synchronization
static void test_fim_recovery_persist_table_and_resync_failure(void **state) {
    (void) state;
    AgentSyncProtocolHandle* handle = (AgentSyncProtocolHandle*)0x1234; // Mock handle

    expect_any_always(__wrap__mdebug1, formatted_msg);

    // Create test data - simple file entry
    cJSON* test_items = cJSON_CreateArray();
    cJSON* item = cJSON_CreateObject();
    cJSON_AddStringToObject(item, "path", "/tmp/test2.txt");
    cJSON_AddStringToObject(item, "checksum", "def456");
    cJSON_AddNumberToObject(item, "version", 1);
    cJSON_AddNumberToObject(item, "inode", 67890);
    cJSON_AddItemToArray(test_items, item);

    // Expect fim_db_increase_each_entry_version call (called first)
    expect_string(__wrap_fim_db_increase_each_entry_version, table_name, FIMDB_FILE_TABLE_NAME);
    will_return(__wrap_fim_db_increase_each_entry_version, 0);

    // Expect fim_db_get_every_element to return our test items
    expect_string(__wrap_fim_db_get_every_element, table_name, FIMDB_FILE_TABLE_NAME);
    expect_string(__wrap_fim_db_get_every_element, row_filter, "WHERE sync=1");
    will_return(__wrap_fim_db_get_every_element, test_items);

    // Expect asp_clear_in_memory_data call
    expect_value(__wrap_asp_clear_in_memory_data, handle, handle);

    // Orphan guard: path must still resolve to a config
    expect_string(__wrap_fim_configuration_directory, path, "/tmp/test2.txt");
    will_return(__wrap_fim_configuration_directory, &mock_directory_config);

    // Expect build_stateful_event_file to be called for our test item
    expect_string(__wrap_build_stateful_event_file, path, "/tmp/test2.txt");
    // Return a mock stateful event
    cJSON* mock_event = cJSON_CreateObject();
    cJSON_AddStringToObject(mock_event, "type", "file");
    will_return(__wrap_build_stateful_event_file, mock_event);

    // Schema validator is not initialized (no validation)
    will_return(__wrap_schema_validator_is_initialized, false);

    // Expect asp_persist_diff_in_memory call - validate all parameters
    expect_value(__wrap_asp_persist_diff_in_memory, handle, handle);
    expect_any(__wrap_asp_persist_diff_in_memory, id);
    expect_value(__wrap_asp_persist_diff_in_memory, operation, OPERATION_CREATE);
    expect_string(__wrap_asp_persist_diff_in_memory, index, FIM_FILES_SYNC_INDEX);
    expect_any(__wrap_asp_persist_diff_in_memory, data);

    // Expect asp_sync_module call - return failure
    expect_value(__wrap_asp_sync_module, handle, handle);
    expect_value(__wrap_asp_sync_module, mode, MODE_FULL);
    will_return(__wrap_asp_sync_module, false);

    // Call the function
    fim_recovery_persist_table_and_resync(FIMDB_FILE_TABLE_NAME, handle, &mock_directories);

    // The function should complete (even though sync failed)
    // Note: test_items is freed by the function, so don't free it here
}

// Test: Persist and resync with version increase failure
static void test_fim_recovery_persist_table_and_resync_version_increase_failure(void **state) {
    (void) state;
    AgentSyncProtocolHandle* handle = (AgentSyncProtocolHandle*)0x1234; // Mock handle

    // Expect fim_db_increase_each_entry_version to fail
    expect_string(__wrap_fim_db_increase_each_entry_version, table_name, FIMDB_FILE_TABLE_NAME);
    will_return(__wrap_fim_db_increase_each_entry_version, -1);

    // Expect one merror call when version increase fails
    expect_any(__wrap__merror, formatted_msg);

    // Call the function - should return early without calling other functions
    fim_recovery_persist_table_and_resync(FIMDB_FILE_TABLE_NAME, handle, &mock_directories);

    // Function should return early without crashing
}

// Test: Persist and resync with NULL items (error case)
static void test_fim_recovery_persist_table_and_resync_null_items(void **state) {
    (void) state;
    AgentSyncProtocolHandle* handle = (AgentSyncProtocolHandle*)0x1234; // Mock handle

    // Expect fim_db_increase_each_entry_version call (called first)
    expect_string(__wrap_fim_db_increase_each_entry_version, table_name, FIMDB_FILE_TABLE_NAME);
    will_return(__wrap_fim_db_increase_each_entry_version, 0);

    // Expect fim_db_get_every_element to return NULL (error case)
    expect_string(__wrap_fim_db_get_every_element, table_name, FIMDB_FILE_TABLE_NAME);
    expect_string(__wrap_fim_db_get_every_element, row_filter, "WHERE sync=1");
    will_return(__wrap_fim_db_get_every_element, NULL);

    // Expect one merror call when items is NULL
    expect_any(__wrap__merror, formatted_msg);

    // Call the function - should handle NULL gracefully (no sync call expected)
    fim_recovery_persist_table_and_resync(FIMDB_FILE_TABLE_NAME, handle, &mock_directories);

    // Function should return early without crashing
}

// Test: Check if full sync required - checksum mismatch
static void test_fim_recovery_check_if_full_sync_required_mismatch(void **state) {
    (void) state;
    AgentSyncProtocolHandle* handle = (AgentSyncProtocolHandle*)0x1234; // Mock handle
    char* test_checksum = strdup("test_checksum_123");

    expect_any_always(__wrap__mdebug1, formatted_msg);

    // Expect fim_db_calculate_table_checksum call
    expect_string(__wrap_fim_db_calculate_table_checksum, table_name, FIMDB_FILE_TABLE_NAME);
    will_return(__wrap_fim_db_calculate_table_checksum, test_checksum);

    // Expect asp_requires_full_sync call - return true (mismatch)
    expect_value(__wrap_asp_requires_full_sync, handle, handle);
    expect_string(__wrap_asp_requires_full_sync, index, FIM_FILES_SYNC_INDEX);
    expect_string(__wrap_asp_requires_full_sync, checksum, test_checksum);
    will_return(__wrap_asp_requires_full_sync, true);

    bool result = fim_recovery_check_if_full_sync_required(FIMDB_FILE_TABLE_NAME, handle);

    // Should return true (full sync required)
    assert_true(result);
}

// Test: Check if full sync required - checksum match
static void test_fim_recovery_check_if_full_sync_required_match(void **state) {
    (void) state;
    AgentSyncProtocolHandle* handle = (AgentSyncProtocolHandle*)0x1234; // Mock handle
    char* test_checksum = strdup("test_checksum_456");

    expect_any_always(__wrap__mdebug1, formatted_msg);

    // Expect fim_db_calculate_table_checksum call
    expect_string(__wrap_fim_db_calculate_table_checksum, table_name, FIMDB_FILE_TABLE_NAME);
    will_return(__wrap_fim_db_calculate_table_checksum, test_checksum);

    // Expect asp_requires_full_sync call - return false (match)
    expect_value(__wrap_asp_requires_full_sync, handle, handle);
    expect_string(__wrap_asp_requires_full_sync, index, FIM_FILES_SYNC_INDEX);
    expect_string(__wrap_asp_requires_full_sync, checksum, test_checksum);
    will_return(__wrap_asp_requires_full_sync, false);

    bool result = fim_recovery_check_if_full_sync_required(FIMDB_FILE_TABLE_NAME, handle);

    // Should return false (delta sync sufficient)
    assert_false(result);
}

// Test: Check if full sync required - NULL checksum (error)
static void test_fim_recovery_check_if_full_sync_required_null_checksum(void **state) {
    (void) state;
    AgentSyncProtocolHandle* handle = (AgentSyncProtocolHandle*)0x1234; // Mock handle

    expect_any_always(__wrap__merror, formatted_msg);
    expect_any_always(__wrap__mdebug1, formatted_msg);

    // Expect fim_db_calculate_table_checksum to return NULL (error)
    expect_string(__wrap_fim_db_calculate_table_checksum, table_name, FIMDB_FILE_TABLE_NAME);
    will_return(__wrap_fim_db_calculate_table_checksum, NULL);

    bool result = fim_recovery_check_if_full_sync_required(FIMDB_FILE_TABLE_NAME, handle);

    // Should return false on error
    assert_false(result);
}

// Test (#36134): Persist and resync skips rows whose path is no longer in the configuration.
// Two items are returned by the DB; the first is "orphaned" (config lookup returns NULL) and
// must be skipped silently; the second still has a config and must follow the normal path.
static void test_fim_recovery_persist_table_and_resync_skips_orphan_paths(void **state) {
    (void) state;
    AgentSyncProtocolHandle* handle = (AgentSyncProtocolHandle*)0x1234;

    expect_any_always(__wrap__mdebug1, formatted_msg);
    expect_any_always(__wrap__mdebug2, formatted_msg);

    cJSON* test_items = cJSON_CreateArray();

    cJSON* orphan_item = cJSON_CreateObject();
    cJSON_AddStringToObject(orphan_item, "path", "/home/vagrant/orphan.txt");
    cJSON_AddStringToObject(orphan_item, "checksum", "orphan-sha");
    cJSON_AddNumberToObject(orphan_item, "version", 1);
    cJSON_AddNumberToObject(orphan_item, "inode", 11111);
    cJSON_AddItemToArray(test_items, orphan_item);

    cJSON* live_item = cJSON_CreateObject();
    cJSON_AddStringToObject(live_item, "path", "/etc/passwd");
    cJSON_AddStringToObject(live_item, "checksum", "live-sha");
    cJSON_AddNumberToObject(live_item, "version", 1);
    cJSON_AddNumberToObject(live_item, "inode", 22222);
    cJSON_AddItemToArray(test_items, live_item);

    expect_string(__wrap_fim_db_increase_each_entry_version, table_name, FIMDB_FILE_TABLE_NAME);
    will_return(__wrap_fim_db_increase_each_entry_version, 0);

    expect_string(__wrap_fim_db_get_every_element, table_name, FIMDB_FILE_TABLE_NAME);
    expect_string(__wrap_fim_db_get_every_element, row_filter, "WHERE sync=1");
    will_return(__wrap_fim_db_get_every_element, test_items);

    expect_value(__wrap_asp_clear_in_memory_data, handle, handle);

    // Orphaned path: config lookup returns NULL -> row is skipped entirely.
    expect_string(__wrap_fim_configuration_directory, path, "/home/vagrant/orphan.txt");
    will_return(__wrap_fim_configuration_directory, NULL);
    // No build_stateful_event_file / asp_persist_diff_in_memory expectations for the orphan row.

    // Live path: config lookup returns non-NULL -> normal pipeline.
    expect_string(__wrap_fim_configuration_directory, path, "/etc/passwd");
    will_return(__wrap_fim_configuration_directory, &mock_directory_config);

    expect_string(__wrap_build_stateful_event_file, path, "/etc/passwd");
    cJSON* mock_event = cJSON_CreateObject();
    cJSON_AddStringToObject(mock_event, "type", "file");
    will_return(__wrap_build_stateful_event_file, mock_event);

    will_return(__wrap_schema_validator_is_initialized, false);

    expect_value(__wrap_asp_persist_diff_in_memory, handle, handle);
    expect_any(__wrap_asp_persist_diff_in_memory, id);
    expect_value(__wrap_asp_persist_diff_in_memory, operation, OPERATION_CREATE);
    expect_string(__wrap_asp_persist_diff_in_memory, index, FIM_FILES_SYNC_INDEX);
    expect_any(__wrap_asp_persist_diff_in_memory, data);

    expect_value(__wrap_asp_sync_module, handle, handle);
    expect_value(__wrap_asp_sync_module, mode, MODE_FULL);
    will_return(__wrap_asp_sync_module, true);

    fim_recovery_persist_table_and_resync(FIMDB_FILE_TABLE_NAME, handle, &mock_directories);

    // test_items is freed by the function.
}

// Test: buildFileStatefulEvent with valid data
static void test_buildFileStatefulEvent_success(void **state) {
    (void) state;

    // Create test file_data
    cJSON* file_data = cJSON_CreateObject();
    cJSON_AddStringToObject(file_data, "path", "/tmp/test.txt");
    cJSON_AddNumberToObject(file_data, "inode", 12345);
    cJSON_AddNumberToObject(file_data, "size", 1024);

    // Expect build_stateful_event_file to be called
    expect_string(__wrap_build_stateful_event_file, path, "/tmp/test.txt");
    cJSON* mock_result = cJSON_CreateObject();
    cJSON_AddStringToObject(mock_result, "type", "file");
    will_return(__wrap_build_stateful_event_file, mock_result);

    cJSON* result = buildFileStatefulEvent("/tmp/test.txt", file_data, "abc123", 1, &mock_directories);

    assert_non_null(result);
    // Verify inode was converted to string
    cJSON* inode_item = cJSON_GetObjectItem(file_data, "inode");
    assert_non_null(inode_item);
    assert_true(cJSON_IsString(inode_item));
    assert_string_equal(inode_item->valuestring, "12345");

    cJSON_Delete(file_data);
    cJSON_Delete(result);
}

#ifdef WIN32
// Test: buildRegistryKeyStatefulEvent with valid data
static void test_buildRegistryKeyStatefulEvent_success(void **state) {
    (void) state;

    cJSON* key_data = cJSON_CreateObject();
    cJSON_AddStringToObject(key_data, "path", "HKEY_LOCAL_MACHINE\\Software\\Test");

    // Expect build_stateful_event_registry_key to be called
    expect_string(__wrap_build_stateful_event_registry_key, path, "HKEY_LOCAL_MACHINE\\Software\\Test");
    cJSON* mock_result = cJSON_CreateObject();
    cJSON_AddStringToObject(mock_result, "type", "registry_key");
    will_return(__wrap_build_stateful_event_registry_key, mock_result);

    cJSON* result = buildRegistryKeyStatefulEvent("HKEY_LOCAL_MACHINE\\Software\\Test", key_data, "def456", 1, ARCH_64BIT);

    assert_non_null(result);

    cJSON_Delete(key_data);
    cJSON_Delete(result);
}

// Test: buildRegistryValueStatefulEvent with valid data
static void test_buildRegistryValueStatefulEvent_success(void **state) {
    (void) state;

    cJSON* value_data = cJSON_CreateObject();
    cJSON_AddStringToObject(value_data, "path", "HKEY_LOCAL_MACHINE\\Software\\Test");
    cJSON_AddStringToObject(value_data, "value", "TestValue");

    // Expect build_stateful_event_registry_value to be called
    expect_string(__wrap_build_stateful_event_registry_value, path, "HKEY_LOCAL_MACHINE\\Software\\Test");
    cJSON* mock_result = cJSON_CreateObject();
    cJSON_AddStringToObject(mock_result, "type", "registry_value");
    will_return(__wrap_build_stateful_event_registry_value, mock_result);

    cJSON* result = buildRegistryValueStatefulEvent("HKEY_LOCAL_MACHINE\\Software\\Test", "TestValue", value_data, "ghi789", 1, ARCH_32BIT);

    assert_non_null(result);

    cJSON_Delete(value_data);
    cJSON_Delete(result);
}
#endif // WIN32

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_fim_recovery_integrity_interval_has_elapsed_first_time),
        cmocka_unit_test(test_fim_recovery_integrity_interval_has_elapsed_not_elapsed),
        cmocka_unit_test(test_fim_recovery_integrity_interval_has_elapsed_elapsed),
        cmocka_unit_test(test_fim_recovery_persist_table_and_resync_success),
        cmocka_unit_test(test_fim_recovery_persist_table_and_resync_failure),
        cmocka_unit_test(test_fim_recovery_persist_table_and_resync_version_increase_failure),
        cmocka_unit_test(test_fim_recovery_persist_table_and_resync_null_items),
        cmocka_unit_test(test_fim_recovery_persist_table_and_resync_skips_orphan_paths),
        cmocka_unit_test(test_fim_recovery_check_if_full_sync_required_mismatch),
        cmocka_unit_test(test_fim_recovery_check_if_full_sync_required_match),
        cmocka_unit_test(test_fim_recovery_check_if_full_sync_required_null_checksum),
        cmocka_unit_test(test_buildFileStatefulEvent_success),
#ifdef WIN32
        cmocka_unit_test(test_buildRegistryKeyStatefulEvent_success),
        cmocka_unit_test(test_buildRegistryValueStatefulEvent_success),
#endif
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
