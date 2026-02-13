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
#include "../wrappers/wazuh/syscheckd/fim_db_wrappers.h"

#include "syscheck.h"
#include "cJSON.h"

// External function declarations from syscheck.c
extern void persist_sync_documents(char* table_name, cJSON* docs, Operation_t operation);
extern void add_pending_sync_item(OSList *pending_items, const cJSON *json, int sync_value);
extern void process_pending_sync_updates(char* table_name, OSList *pending_items);
extern cJSON* extract_primary_keys(const char* table_name, const cJSON* full_doc);

// Local wrapper declarations (defined per-test-file like test_recovery.c)
cJSON* __wrap_build_stateful_event_file(const char* path, const char* sha1_hash,
                                        const uint64_t document_version, const cJSON *dbsync_event,
                                        const fim_file_data *file_data, OSList* directories);

bool __wrap_validate_and_persist_fim_event(const cJSON* stateful_event, const char* id,
                                           Operation_t operation, const char* index,
                                           uint64_t document_version, const char* item_description,
                                           bool mark_for_deletion, OSList* failed_list,
                                           void* failed_item_data, int sync_flag);

#ifdef WIN32
cJSON* __wrap_build_stateful_event_registry_key(const char* path, const char* sha1_hash,
                                                 const uint64_t document_version, int arch,
                                                 const cJSON *dbsync_event, void* data);

cJSON* __wrap_build_stateful_event_registry_value(const char* path, const char* value,
                                                   const char* sha1_hash, const uint64_t document_version,
                                                   int arch, const cJSON *dbsync_event, void* data);
#endif

// Wrapper implementations for build_stateful_event_* (local to this test file)
cJSON* __wrap_build_stateful_event_file(const char* path, const char* sha1_hash,
                                        const uint64_t document_version,
                                        __attribute__((unused)) const cJSON *dbsync_event,
                                        __attribute__((unused)) const fim_file_data *file_data,
                                        __attribute__((unused)) OSList* directories) {
    check_expected(path);
    check_expected_ptr(sha1_hash);
    check_expected(document_version);
    return mock_ptr_type(cJSON*);
}

bool __wrap_validate_and_persist_fim_event(
    __attribute__((unused)) const cJSON* stateful_event,
    __attribute__((unused)) const char* id,
    Operation_t operation,
    const char* index,
    uint64_t document_version,
    const char* item_description,
    bool mark_for_deletion,
    __attribute__((unused)) OSList* failed_list,
    __attribute__((unused)) void* failed_item_data,
    int sync_flag) {
    check_expected(operation);
    check_expected(index);
    check_expected(document_version);
    check_expected(item_description);
    check_expected(mark_for_deletion);
    check_expected(sync_flag);
    return mock_type(bool);
}

#ifdef WIN32
cJSON* __wrap_build_stateful_event_registry_key(const char* path, const char* sha1_hash,
                                                 const uint64_t document_version, int arch,
                                                 __attribute__((unused)) const cJSON *dbsync_event,
                                                 __attribute__((unused)) void* data) {
    check_expected(path);
    check_expected_ptr(sha1_hash);
    check_expected(document_version);
    check_expected(arch);
    return mock_ptr_type(cJSON*);
}

cJSON* __wrap_build_stateful_event_registry_value(const char* path, const char* value,
                                                   const char* sha1_hash, const uint64_t document_version,
                                                   int arch,
                                                   __attribute__((unused)) const cJSON *dbsync_event,
                                                   __attribute__((unused)) void* data) {
    check_expected(path);
    check_expected(value);
    check_expected_ptr(sha1_hash);
    check_expected(document_version);
    check_expected(arch);
    return mock_ptr_type(cJSON*);
}
#endif

/* Setup and teardown functions */

static int setup_group(void **state) {
    syscheck.directories = NULL;
    return 0;
}

static int teardown_group(void **state) {
    return 0;
}

/* Helper function to create test document */
static cJSON* create_file_doc(const char* path, const char* checksum, uint64_t version) {
    cJSON* doc = cJSON_CreateObject();
    cJSON_AddStringToObject(doc, "path", path);
    cJSON_AddStringToObject(doc, "checksum", checksum);
    cJSON_AddNumberToObject(doc, "version", (double)version);
    return doc;
}

#ifdef WIN32
static cJSON* create_registry_key_doc(const char* path, const char* checksum,
                                       uint64_t version, const char* arch) {
    cJSON* doc = cJSON_CreateObject();
    cJSON_AddStringToObject(doc, "path", path);
    cJSON_AddStringToObject(doc, "checksum", checksum);
    cJSON_AddNumberToObject(doc, "version", (double)version);
    cJSON_AddStringToObject(doc, "architecture", arch);
    return doc;
}

static cJSON* create_registry_value_doc(const char* path, const char* value,
                                         const char* checksum, uint64_t version,
                                         const char* arch) {
    cJSON* doc = cJSON_CreateObject();
    cJSON_AddStringToObject(doc, "path", path);
    cJSON_AddStringToObject(doc, "value", value);
    cJSON_AddStringToObject(doc, "checksum", checksum);
    cJSON_AddNumberToObject(doc, "version", (double)version);
    cJSON_AddStringToObject(doc, "architecture", arch);
    return doc;
}
#endif

/* Tests for persist_sync_documents() */

static void test_persist_sync_documents_promote_files_success(void **state) {
    (void) state;

    // Create test documents array
    cJSON* docs = cJSON_CreateArray();
    cJSON* doc1 = create_file_doc("/tmp/test1.txt", "abc123", 1);
    cJSON* doc2 = create_file_doc("/tmp/test2.txt", "def456", 2);
    cJSON_AddItemToArray(docs, doc1);
    cJSON_AddItemToArray(docs, doc2);

    // Expect build_stateful_event_file for first document
    expect_string(__wrap_build_stateful_event_file, path, "/tmp/test1.txt");
    expect_string(__wrap_build_stateful_event_file, sha1_hash, "abc123");
    expect_value(__wrap_build_stateful_event_file, document_version, 1);
    cJSON* event1 = cJSON_CreateObject();
    cJSON_AddStringToObject(event1, "type", "event");
    will_return(__wrap_build_stateful_event_file, event1);

    // Expect validate_and_persist_fim_event for first document
    expect_value(__wrap_validate_and_persist_fim_event, operation, OPERATION_CREATE);
    expect_string(__wrap_validate_and_persist_fim_event, index, FIM_FILES_SYNC_INDEX);
    expect_value(__wrap_validate_and_persist_fim_event, document_version, 1);
    expect_string(__wrap_validate_and_persist_fim_event, item_description, "file /tmp/test1.txt");
    expect_value(__wrap_validate_and_persist_fim_event, mark_for_deletion, false);
    expect_value(__wrap_validate_and_persist_fim_event, sync_flag, 1);
    will_return(__wrap_validate_and_persist_fim_event, true);

    // Expect build_stateful_event_file for second document
    expect_string(__wrap_build_stateful_event_file, path, "/tmp/test2.txt");
    expect_string(__wrap_build_stateful_event_file, sha1_hash, "def456");
    expect_value(__wrap_build_stateful_event_file, document_version, 2);
    cJSON* event2 = cJSON_CreateObject();
    cJSON_AddStringToObject(event2, "type", "event");
    will_return(__wrap_build_stateful_event_file, event2);

    // Expect validate_and_persist_fim_event for second document
    expect_value(__wrap_validate_and_persist_fim_event, operation, OPERATION_CREATE);
    expect_string(__wrap_validate_and_persist_fim_event, index, FIM_FILES_SYNC_INDEX);
    expect_value(__wrap_validate_and_persist_fim_event, document_version, 2);
    expect_string(__wrap_validate_and_persist_fim_event, item_description, "file /tmp/test2.txt");
    expect_value(__wrap_validate_and_persist_fim_event, mark_for_deletion, false);
    expect_value(__wrap_validate_and_persist_fim_event, sync_flag, 1);
    will_return(__wrap_validate_and_persist_fim_event, true);

    // Expect mdebug1 with count
    expect_string(__wrap__mdebug1, formatted_msg, "Sent 2 promoted documents to persistent queue for table file_entry");

    // Call function
    persist_sync_documents(FIMDB_FILE_TABLE_NAME, docs, OPERATION_CREATE);

    // Clean up (event1 and event2 are freed by persist_sync_documents)
    cJSON_Delete(docs);
}

static void test_persist_sync_documents_demote_files_success(void **state) {
    (void) state;

    // Create test documents array (demoted docs don't have checksum)
    cJSON* docs = cJSON_CreateArray();
    cJSON* doc1 = cJSON_CreateObject();
    cJSON_AddStringToObject(doc1, "path", "/tmp/test1.txt");
    cJSON_AddNumberToObject(doc1, "version", 1);
    cJSON_AddItemToArray(docs, doc1);

    // Expect validate_and_persist_fim_event with DELETE operation
    expect_value(__wrap_validate_and_persist_fim_event, operation, OPERATION_DELETE);
    expect_string(__wrap_validate_and_persist_fim_event, index, FIM_FILES_SYNC_INDEX);
    expect_value(__wrap_validate_and_persist_fim_event, document_version, 1);
    expect_string(__wrap_validate_and_persist_fim_event, item_description, "file /tmp/test1.txt");
    expect_value(__wrap_validate_and_persist_fim_event, mark_for_deletion, false);
    expect_value(__wrap_validate_and_persist_fim_event, sync_flag, 1);
    will_return(__wrap_validate_and_persist_fim_event, true);

    // Expect mdebug1 with count
    expect_string(__wrap__mdebug1, formatted_msg, "Sent 1 demoted documents to persistent queue for table file_entry");

    // Call function
    persist_sync_documents(FIMDB_FILE_TABLE_NAME, docs, OPERATION_DELETE);

    cJSON_Delete(docs);
}

static void test_persist_sync_documents_null_docs(void **state) {
    (void) state;

    // Should return immediately without any calls
    persist_sync_documents(FIMDB_FILE_TABLE_NAME, NULL, OPERATION_CREATE);
}

static void test_persist_sync_documents_invalid_array(void **state) {
    (void) state;

    // Create non-array JSON
    cJSON* not_array = cJSON_CreateObject();

    // Should return immediately without any calls
    persist_sync_documents(FIMDB_FILE_TABLE_NAME, not_array, OPERATION_CREATE);

    cJSON_Delete(not_array);
}

static void test_persist_sync_documents_missing_required_fields(void **state) {
    (void) state;

    // Create document missing required fields
    cJSON* docs = cJSON_CreateArray();
    cJSON* doc1 = cJSON_CreateObject();
    cJSON_AddStringToObject(doc1, "path", "/tmp/test.txt");
    // Missing version field
    cJSON_AddItemToArray(docs, doc1);

    // Expect warning about missing fields
    expect_string(__wrap__mwarn, formatted_msg, "Skipping promoted document with missing required fields");

    // Expect mdebug1 with count 0
    expect_string(__wrap__mdebug1, formatted_msg, "Sent 0 promoted documents to persistent queue for table file_entry");

    // Call function
    persist_sync_documents(FIMDB_FILE_TABLE_NAME, docs, OPERATION_CREATE);

    cJSON_Delete(docs);
}

static void test_persist_sync_documents_missing_checksum_on_create(void **state) {
    (void) state;

    // Create document missing checksum for CREATE operation
    cJSON* docs = cJSON_CreateArray();
    cJSON* doc1 = cJSON_CreateObject();
    cJSON_AddStringToObject(doc1, "path", "/tmp/test.txt");
    cJSON_AddNumberToObject(doc1, "version", 1);
    // Missing checksum field for OPERATION_CREATE
    cJSON_AddItemToArray(docs, doc1);

    // Expect warning about missing checksum
    expect_string(__wrap__mwarn, formatted_msg, "Skipping promoted document with missing checksum");

    // Expect mdebug1 with count 0
    expect_string(__wrap__mdebug1, formatted_msg, "Sent 0 promoted documents to persistent queue for table file_entry");

    // Call function
    persist_sync_documents(FIMDB_FILE_TABLE_NAME, docs, OPERATION_CREATE);

    cJSON_Delete(docs);
}

#ifdef WIN32
static void test_persist_sync_documents_promote_registry_keys_success(void **state) {
    (void) state;

    // Create test registry key document
    cJSON* docs = cJSON_CreateArray();
    cJSON* doc1 = create_registry_key_doc("HKEY_LOCAL_MACHINE\\Software\\Test", "abc123", 1, "[x32]");
    cJSON_AddItemToArray(docs, doc1);

    // Expect build_stateful_event_registry_key
    expect_string(__wrap_build_stateful_event_registry_key, path, "HKEY_LOCAL_MACHINE\\Software\\Test");
    expect_string(__wrap_build_stateful_event_registry_key, sha1_hash, "abc123");
    expect_value(__wrap_build_stateful_event_registry_key, document_version, 1);
    expect_value(__wrap_build_stateful_event_registry_key, arch, ARCH_32BIT);
    cJSON* event1 = cJSON_CreateObject();
    will_return(__wrap_build_stateful_event_registry_key, event1);

    // Expect validate_and_persist_fim_event
    expect_value(__wrap_validate_and_persist_fim_event, operation, OPERATION_CREATE);
    expect_string(__wrap_validate_and_persist_fim_event, index, FIM_REGISTRY_KEYS_SYNC_INDEX);
    expect_value(__wrap_validate_and_persist_fim_event, document_version, 1);
    expect_string(__wrap_validate_and_persist_fim_event, item_description, "registry key HKEY_LOCAL_MACHINE\\Software\\Test");
    expect_value(__wrap_validate_and_persist_fim_event, mark_for_deletion, false);
    expect_value(__wrap_validate_and_persist_fim_event, sync_flag, 1);
    will_return(__wrap_validate_and_persist_fim_event, true);

    // Expect mdebug1
    expect_string(__wrap__mdebug1, formatted_msg, "Sent 1 promoted documents to persistent queue for table registry_key");

    persist_sync_documents(FIMDB_REGISTRY_KEY_TABLENAME, docs, OPERATION_CREATE);

    // Clean up (event1 is freed by persist_sync_documents)
    cJSON_Delete(docs);
}

static void test_persist_sync_documents_demote_registry_values_success(void **state) {
    (void) state;

    // Create test registry value document (without checksum for DELETE)
    cJSON* docs = cJSON_CreateArray();
    cJSON* doc1 = cJSON_CreateObject();
    cJSON_AddStringToObject(doc1, "path", "HKEY_LOCAL_MACHINE\\Software\\Test");
    cJSON_AddStringToObject(doc1, "value", "TestValue");
    cJSON_AddStringToObject(doc1, "architecture", "[x64]");
    cJSON_AddNumberToObject(doc1, "version", 1);
    cJSON_AddItemToArray(docs, doc1);

    // Expect validate_and_persist_fim_event with DELETE
    expect_value(__wrap_validate_and_persist_fim_event, operation, OPERATION_DELETE);
    expect_string(__wrap_validate_and_persist_fim_event, index, FIM_REGISTRY_VALUES_SYNC_INDEX);
    expect_value(__wrap_validate_and_persist_fim_event, document_version, 1);
    expect_string(__wrap_validate_and_persist_fim_event, item_description, "registry value HKEY_LOCAL_MACHINE\\Software\\Test:TestValue");
    expect_value(__wrap_validate_and_persist_fim_event, mark_for_deletion, false);
    expect_value(__wrap_validate_and_persist_fim_event, sync_flag, 1);
    will_return(__wrap_validate_and_persist_fim_event, true);

    // Expect mdebug1
    expect_string(__wrap__mdebug1, formatted_msg, "Sent 1 demoted documents to persistent queue for table registry_data");

    persist_sync_documents(FIMDB_REGISTRY_VALUE_TABLENAME, docs, OPERATION_DELETE);

    cJSON_Delete(docs);
}
#endif

/* Tests for extract_primary_keys() */

static void test_extract_primary_keys_file(void **state) {
    (void) state;

    // Create full file document
    cJSON* full_doc = cJSON_CreateObject();
    cJSON_AddStringToObject(full_doc, "path", "/tmp/test.txt");
    cJSON_AddStringToObject(full_doc, "checksum", "abc123");
    cJSON_AddNumberToObject(full_doc, "version", 5);
    cJSON_AddNumberToObject(full_doc, "inode", 12345);
    cJSON_AddNumberToObject(full_doc, "size", 1024);

    // Extract primary keys
    cJSON* keys = extract_primary_keys(FIMDB_FILE_TABLE_NAME, full_doc);

    // Verify only path and version are extracted
    assert_non_null(keys);
    assert_non_null(cJSON_GetObjectItem(keys, "path"));
    assert_non_null(cJSON_GetObjectItem(keys, "version"));
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(keys, "path")), "/tmp/test.txt");
    assert_int_equal(cJSON_GetNumberValue(cJSON_GetObjectItem(keys, "version")), 5);

    // Verify other fields are NOT included
    assert_null(cJSON_GetObjectItem(keys, "checksum"));
    assert_null(cJSON_GetObjectItem(keys, "inode"));
    assert_null(cJSON_GetObjectItem(keys, "size"));

    cJSON_Delete(full_doc);
    cJSON_Delete(keys);
}

#ifdef WIN32
static void test_extract_primary_keys_registry_key(void **state) {
    (void) state;

    // Create full registry key document
    cJSON* full_doc = cJSON_CreateObject();
    cJSON_AddStringToObject(full_doc, "path", "HKEY_LOCAL_MACHINE\\Software\\Test");
    cJSON_AddStringToObject(full_doc, "architecture", "[x32]");
    cJSON_AddStringToObject(full_doc, "checksum", "abc123");
    cJSON_AddNumberToObject(full_doc, "version", 3);
    cJSON_AddNumberToObject(full_doc, "mtime", 1234567890);

    // Extract primary keys
    cJSON* keys = extract_primary_keys(FIMDB_REGISTRY_KEY_TABLENAME, full_doc);

    // Verify path, architecture, and version are extracted
    assert_non_null(keys);
    assert_non_null(cJSON_GetObjectItem(keys, "path"));
    assert_non_null(cJSON_GetObjectItem(keys, "architecture"));
    assert_non_null(cJSON_GetObjectItem(keys, "version"));
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(keys, "path")), "HKEY_LOCAL_MACHINE\\Software\\Test");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(keys, "architecture")), "[x32]");
    assert_int_equal(cJSON_GetNumberValue(cJSON_GetObjectItem(keys, "version")), 3);

    // Verify other fields are NOT included
    assert_null(cJSON_GetObjectItem(keys, "checksum"));
    assert_null(cJSON_GetObjectItem(keys, "mtime"));

    cJSON_Delete(full_doc);
    cJSON_Delete(keys);
}

static void test_extract_primary_keys_registry_value(void **state) {
    (void) state;

    // Create full registry value document
    cJSON* full_doc = cJSON_CreateObject();
    cJSON_AddStringToObject(full_doc, "path", "HKEY_LOCAL_MACHINE\\Software\\Test");
    cJSON_AddStringToObject(full_doc, "architecture", "[x64]");
    cJSON_AddStringToObject(full_doc, "value", "TestValue");
    cJSON_AddStringToObject(full_doc, "checksum", "def456");
    cJSON_AddNumberToObject(full_doc, "version", 7);
    cJSON_AddNumberToObject(full_doc, "type", 1);
    cJSON_AddNumberToObject(full_doc, "size", 512);

    // Extract primary keys
    cJSON* keys = extract_primary_keys(FIMDB_REGISTRY_VALUE_TABLENAME, full_doc);

    // Verify path, architecture, value, and version are extracted
    assert_non_null(keys);
    assert_non_null(cJSON_GetObjectItem(keys, "path"));
    assert_non_null(cJSON_GetObjectItem(keys, "architecture"));
    assert_non_null(cJSON_GetObjectItem(keys, "value"));
    assert_non_null(cJSON_GetObjectItem(keys, "version"));
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(keys, "path")), "HKEY_LOCAL_MACHINE\\Software\\Test");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(keys, "architecture")), "[x64]");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(keys, "value")), "TestValue");
    assert_int_equal(cJSON_GetNumberValue(cJSON_GetObjectItem(keys, "version")), 7);

    // Verify other fields are NOT included
    assert_null(cJSON_GetObjectItem(keys, "checksum"));
    assert_null(cJSON_GetObjectItem(keys, "type"));
    assert_null(cJSON_GetObjectItem(keys, "size"));

    cJSON_Delete(full_doc);
    cJSON_Delete(keys);
}
#endif

/* Tests for add_pending_sync_item() and process_pending_sync_updates() */

static void test_add_pending_sync_item_success(void **state) {
    (void) state;

    // Create pending list
    OSList* pending = OSList_Create();
    OSList_SetFreeDataPointer(pending, free_pending_sync_item);

    // Create test item
    cJSON* item = cJSON_CreateObject();
    cJSON_AddStringToObject(item, "path", "/tmp/test.txt");
    cJSON_AddNumberToObject(item, "version", 1);

    // Expect mdebug2 with count
    expect_string(__wrap__mdebug2, formatted_msg, "Added item to pending sync list: /tmp/test.txt (version: 1, sync: 1)");

    // Add to pending list
    add_pending_sync_item(pending, item, 1);

    // Verify item was added
    assert_int_equal(pending->currently_size, 1);

    // Clean up
    cJSON_Delete(item);
    OSList_Destroy(pending);
}

static void test_process_pending_sync_updates_files(void **state) {
    (void) state;

    // Create pending list with items
    OSList* pending = OSList_Create();
    OSList_SetFreeDataPointer(pending, free_pending_sync_item);

    // Add test items
    cJSON* item1 = cJSON_CreateObject();
    cJSON_AddStringToObject(item1, "path", "/tmp/test1.txt");
    cJSON_AddNumberToObject(item1, "version", 1);
    expect_string(__wrap__mdebug2, formatted_msg, "Added item to pending sync list: /tmp/test1.txt (version: 1, sync: 1)");
    add_pending_sync_item(pending, item1, 1);

    cJSON* item2 = cJSON_CreateObject();
    cJSON_AddStringToObject(item2, "path", "/tmp/test2.txt");
    cJSON_AddNumberToObject(item2, "version", 2);
    expect_string(__wrap__mdebug2, formatted_msg, "Added item to pending sync list: /tmp/test2.txt (version: 2, sync: 1)");
    add_pending_sync_item(pending, item2, 1);

    // Expect fim_db_set_sync_flag calls
    expect_string(__wrap_fim_db_set_sync_flag, table_name, FIMDB_FILE_TABLE_NAME);
    expect_any(__wrap_fim_db_set_sync_flag, item);
    expect_value(__wrap_fim_db_set_sync_flag, sync_value, 1);
    will_return(__wrap_fim_db_set_sync_flag, 0);

    expect_string(__wrap_fim_db_set_sync_flag, table_name, FIMDB_FILE_TABLE_NAME);
    expect_any(__wrap_fim_db_set_sync_flag, item);
    expect_value(__wrap_fim_db_set_sync_flag, sync_value, 1);
    will_return(__wrap_fim_db_set_sync_flag, 0);

    // Process updates
    expect_string(__wrap__mdebug2, formatted_msg, "Setting sync=1 for path: /tmp/test1.txt");
    expect_string(__wrap__mdebug2, formatted_msg, "Setting sync=1 for path: /tmp/test2.txt");
    expect_string(__wrap__mdebug1, formatted_msg, "Processed 2 pending sync flag updates");
    process_pending_sync_updates(FIMDB_FILE_TABLE_NAME, pending);

    // Clean up
    cJSON_Delete(item1);
    cJSON_Delete(item2);
    OSList_Destroy(pending);
}

/* Main test runner */

int main(void) {
    const struct CMUnitTest tests[] = {
        // persist_sync_documents tests
        cmocka_unit_test(test_persist_sync_documents_promote_files_success),
        cmocka_unit_test(test_persist_sync_documents_demote_files_success),
        cmocka_unit_test(test_persist_sync_documents_null_docs),
        cmocka_unit_test(test_persist_sync_documents_invalid_array),
        cmocka_unit_test(test_persist_sync_documents_missing_required_fields),
        cmocka_unit_test(test_persist_sync_documents_missing_checksum_on_create),
#ifdef WIN32
        cmocka_unit_test(test_persist_sync_documents_promote_registry_keys_success),
        cmocka_unit_test(test_persist_sync_documents_demote_registry_values_success),
#endif
        // extract_primary_keys tests
        cmocka_unit_test(test_extract_primary_keys_file),
#ifdef WIN32
        cmocka_unit_test(test_extract_primary_keys_registry_key),
        cmocka_unit_test(test_extract_primary_keys_registry_value),
#endif
        // Helper function tests
        cmocka_unit_test(test_add_pending_sync_item_success),
        cmocka_unit_test(test_process_pending_sync_updates_files),
    };

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
