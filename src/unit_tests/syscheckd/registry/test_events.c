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
#include "syscheckd/include/syscheck.h"
#include "syscheckd/src/registry/registry.h"
#include "test_fim.h"

#define CHECK_REGISTRY_ALL                                                                             \
    CHECK_SIZE | CHECK_PERM | CHECK_OWNER | CHECK_GROUP | CHECK_MTIME | CHECK_MD5SUM | CHECK_SHA1SUM | \
    CHECK_SHA256SUM | CHECK_SEECHANGES | CHECK_TYPE

typedef struct fim_key_txn_context_s {
    event_data_t *evt_data;
    fim_registry_key *key;
} fim_key_txn_context_t;

typedef struct fim_val_txn_context_s {
    event_data_t *evt_data;
    fim_registry_value_data *data;
    char* diff;
} fim_val_txn_context_t;

static int teardown_cjson_object(void **state) {
    cJSON *object = *state;

    cJSON_Delete(object);

    return 0;
}

cJSON* fim_dbsync_registry_key_json_event(const cJSON* dbsync_event,
                                          const fim_registry_key* key,
                                          const registry_t* configuration,
                                          const event_data_t* evt_data);
cJSON* fim_dbsync_registry_value_json_event(const cJSON* dbsync_event,
                                            const fim_registry_value_data *value,
                                            const registry_t *configuration,
                                            fim_event_mode mode,
                                            const event_data_t *evt_data,
                                            __attribute__((unused)) whodata_evt *w_evt,
                                            const char* diff);
cJSON* fim_registry_compare_key_attrs(const fim_registry_key *new_data,
                               const fim_registry_key *old_data,
                               const registry_t *configuration);
cJSON* fim_registry_compare_value_attrs(const fim_registry_value_data *new_data,
                                        const fim_registry_value_data *old_data,
                                        const registry_t *configuration);

static void test_fim_dbsync_registry_key_json_event_key_not_null(void **state) {
    cJSON *dbsync_event = NULL;
    cJSON *permissions = create_win_permissions_object();
    cJSON *data = NULL;
    fim_registry_key new_key = { .id = 3,
                                 .path = "HKEY_LOCAL_MACHINE\\Software\\prueba\\key2",
                                 .perm_json = permissions,
                                 .perm = cJSON_PrintUnformatted(permissions),
                                 .uid = "0",
                                 .gid = "0",
                                 .user_name = "Administrators",
                                 .group_name = "group_name",
                                 .mtime = 1642007903,
                                 .arch = ARCH_64BIT,
                                 .scanned = 0,
                                 .last_event = 1234,
                                 .checksum = "75d3de895d77868e60a97ffb9ec96df0a9001835" };
    registry_t configuration = { "HKEY_USERS\\Some", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL, "tag"};
    event_data_t evt_data_registry_key = { .report_event = true, .mode = FIM_SCHEDULED, .w_evt = NULL };

    cJSON* ret = fim_dbsync_registry_key_json_event(dbsync_event, &new_key, &configuration, &evt_data_registry_key);

    *state = ret;

    assert_non_null(ret);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(ret, "type")), "event");

    data = cJSON_GetObjectItem(ret, "data");
    assert_non_null(data);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "path")), "HKEY_LOCAL_MACHINE\\Software\\prueba\\key2");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "mode")), "scheduled");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "type")), "added");
    assert_int_equal(cJSON_GetObjectItem(data, "version")->valueint, 2.0);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "arch")), "[x64]");

    cJSON *attributes = cJSON_GetObjectItem(data, "attributes");
    assert_non_null(attributes);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "type")), "registry_key");
    assert_int_equal(cJSON_GetObjectItem(attributes, "uid")->valueint, 0);
    assert_int_equal(cJSON_GetObjectItem(attributes, "gid")->valueint, 0);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "user_name")), "Administrators");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "group_name")), "group_name");
    assert_int_equal(cJSON_GetObjectItem(attributes, "mtime")->valueint, 1642007903);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "checksum")),
                        "75d3de895d77868e60a97ffb9ec96df0a9001835");
    assert_string_equal(cJSON_PrintUnformatted(cJSON_GetObjectItem(attributes, "perm")),
                        cJSON_PrintUnformatted(permissions));

    free(new_key.perm);
    cJSON_Delete(new_key.perm_json);
}


static void test_fim_dbsync_registry_key_json_event_key_null(void **state) {
    const char *dbsync_json_string = "{\"arch\":\"[x64]\",\"checksum\":\"75d3de895d77868e60a97ffb9ec96df0a9001835\",\"gid\":0,\"group_name\":\"group_name\",\"last_event\":0,\"mtime\":1642007903,\"path\":\"HKEY_LOCAL_MACHINE\\\\Software\\\\prueba\\\\key2\",\"perm\":{\"S-1-5-32-636\":{\"name\":\"Users\",\"allowed\":[\"delete\",\"read_control\",\"write_dac\",\"write_owner\",\"synchronize\",\"read_data\",\"write_data\",\"append_data\",\"read_ea\",\"write_ea\",\"execute\",\"read_attributes\",\"write_attributes\"],\"denied\":[\"read_control\",\"synchronize\",\"read_data\",\"read_ea\",\"execute\",\"read_attributes\"]}},\"scanned\":0,\"uid\":0,\"user_name\":\"Administrators\"}";
    cJSON *dbsync_event = cJSON_Parse(dbsync_json_string);
    cJSON *data = NULL;
    cJSON* attributes = NULL;
    fim_registry_key* new_key = NULL;
    registry_t configuration = { "HKEY_USERS\\Some", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL, NULL };
    event_data_t evt_data_registry_key = { .report_event = true, .mode = FIM_SCHEDULED, .w_evt = NULL };

    cJSON* ret = fim_dbsync_registry_key_json_event(dbsync_event, new_key, &configuration, &evt_data_registry_key);

    *state = ret;

    assert_non_null(ret);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(ret, "type")), "event");

    data = cJSON_GetObjectItem(ret, "data");
    assert_non_null(data);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "path")), "HKEY_LOCAL_MACHINE\\Software\\prueba\\key2");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "mode")), "scheduled");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "type")), "added");
    assert_int_equal(cJSON_GetObjectItem(data, "version")->valueint, 2.0);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "arch")), "[x64]");

    attributes = cJSON_GetObjectItem(data, "attributes");
    assert_non_null(attributes);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "type")), "registry_key");
    assert_int_equal(cJSON_GetObjectItem(attributes, "uid")->valueint, 0);
    assert_int_equal(cJSON_GetObjectItem(attributes, "gid")->valueint, 0);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "user_name")), "Administrators");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "group_name")), "group_name");
    assert_int_equal(cJSON_GetObjectItem(attributes, "mtime")->valueint, 1642007903);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "checksum")),
                        "75d3de895d77868e60a97ffb9ec96df0a9001835");

    assert_string_equal(cJSON_PrintUnformatted(cJSON_GetObjectItem(attributes, "perm")),
                        "{\"S-1-5-32-636\":{\"name\":\"Users\",\"allowed\":[\"delete\",\"read_control\",\"write_dac\",\"write_owner\",\"synchronize\",\"read_data\",\"write_data\",\"append_data\",\"read_ea\",\"write_ea\",\"execute\",\"read_attributes\",\"write_attributes\"],\"denied\":[\"read_control\",\"synchronize\",\"read_data\",\"read_ea\",\"execute\",\"read_attributes\"]}}");

}

static void test_fim_dbsync_registry_value_json_event_value_not_null(void **state) {
    cJSON *dbsync_event = NULL;
    cJSON *data = NULL;
    char* diff = "aaaaaaaaaaaa - bbbbbbbbbbb";
    fim_registry_value_data new_data = {.path = "HKEY_LOCAL_MACHINE\\Software\\prueba",
                                        .arch = ARCH_64BIT,
                                        .name = "value_prueba",
                                        .type = 1,
                                        .size = 1,
                                        .hash_md5 = "d41d8cd98f00b204e9800998ecf8427e",
                                        .hash_sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                                        .hash_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                                        .scanned = 0,
                                        .last_event = 1234,
                                        .checksum = "4ca7b88b201728c31afb691707c41d35a984317d"};

    registry_t configuration = { "HKEY_USERS\\Some", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL, "tag"};
    event_data_t evt_data_registry_data = { .report_event = true, .mode = FIM_SCHEDULED, .w_evt = NULL };
    fim_event_mode mode = FIM_SCHEDULED;
    cJSON* ret = fim_dbsync_registry_value_json_event(dbsync_event, &new_data, &configuration, mode, &evt_data_registry_data, NULL,
                                                      diff);

    *state = ret;

    assert_non_null(ret);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(ret, "type")), "event");

    data = cJSON_GetObjectItem(ret, "data");
    assert_non_null(data);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "path")), "HKEY_LOCAL_MACHINE\\Software\\prueba");
    assert_int_equal(cJSON_GetObjectItem(data, "version")->valueint, 2.0);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "mode")), "scheduled");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "type")), "added");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "arch")), "[x64]");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "value_name")), "value_prueba");

    cJSON *attributes = cJSON_GetObjectItem(data, "attributes");
    assert_non_null(attributes);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "type")), "registry_value");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "value_type")), "REG_SZ");
    assert_int_equal(cJSON_GetObjectItem(attributes, "size")->valueint, 1);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "hash_md5")), "d41d8cd98f00b204e9800998ecf8427e");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "hash_sha256")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "hash_sha1")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "checksum")),
                        "4ca7b88b201728c31afb691707c41d35a984317d");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "content_changes")),
                        diff);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "tags")),
                        configuration.tag);

}

static void test_fim_dbsync_registry_value_json_event_value_null(void **state) {
    const char *dbsync_event_string = "{\"arch\":\"[x64]\",\"checksum\":\"4ca7b88b201728c31afb691707c41d35a984317d\",\"hash_md5\":\"d41d8cd98f00b204e9800998ecf8427e\",\"hash_sha1\":\"da39a3ee5e6b4b0d3255bfef95601890afd80709\",\"hash_sha256\":\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",\"last_event\":0,\"name\":\"value_prueba\",\"path\":\"HKEY_LOCAL_MACHINE\\\\Software\\\\prueba\",\"scanned\":0,\"size\":1,\"type\":1}";
    cJSON *dbsync_event = cJSON_Parse(dbsync_event_string);
    fim_registry_value_data* new_data = NULL;
    cJSON *data = NULL;
    char* diff = "aaaaaaaaaaaa - bbbbbbbbbbb";

    registry_t configuration = { "HKEY_USERS\\Some", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL, "tag"};
    event_data_t evt_data_registry_data = { .report_event = true, .mode = FIM_SCHEDULED, .w_evt = NULL };
    fim_event_mode mode = FIM_SCHEDULED;

    cJSON* ret = fim_dbsync_registry_value_json_event(dbsync_event, new_data, &configuration, mode, &evt_data_registry_data, NULL,
                                                      diff);

    *state = ret;

    assert_non_null(ret);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(ret, "type")), "event");

    data = cJSON_GetObjectItem(ret, "data");
    assert_non_null(data);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "path")), "HKEY_LOCAL_MACHINE\\Software\\prueba");
    assert_int_equal(cJSON_GetObjectItem(data, "version")->valueint, 2.0);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "mode")), "scheduled");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "type")), "added");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "arch")), "[x64]");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "value_name")), "value_prueba");

    cJSON *attributes = cJSON_GetObjectItem(data, "attributes");
    assert_non_null(attributes);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "type")), "registry_value");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "value_type")), "REG_SZ");
    assert_int_equal(cJSON_GetObjectItem(attributes, "size")->valueint, 1);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "hash_md5")), "d41d8cd98f00b204e9800998ecf8427e");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "hash_sha256")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "hash_sha1")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "checksum")),
                        "4ca7b88b201728c31afb691707c41d35a984317d");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "content_changes")),
                        diff);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "tags")),
                        configuration.tag);

    cJSON_Delete(dbsync_event);
}

static void test_fim_registry_compare_key_attrs(void **state){
    cJSON *permissions = create_win_permissions_object();
    fim_registry_key new_key = { .id = 3,
                                 .path = "HKEY_USERS\\Some\\random\\key",
                                 .perm_json = permissions,
                                 .perm = cJSON_PrintUnformatted(permissions),
                                 .uid = "100",
                                 .gid = "200",
                                 .user_name = "user_name",
                                 .group_name = "group_name",
                                 .mtime = 1000,
                                 .arch = ARCH_64BIT,
                                 .scanned = 0,
                                 .last_event = 1234,
                                 .checksum = "1234567890ABCDEF1234567890ABCDEF12345678" };
    cJSON *saved_permissions = cJSON_CreateObject();
    fim_registry_key saved_key = { .id = 3,
                                 .path = "HKEY_USERS\\Some\\random\\key",
                                 .perm_json = saved_permissions,
                                 .perm = cJSON_PrintUnformatted(saved_permissions),
                                 .uid = "110",
                                 .gid = "220",
                                 .user_name = "user_old_name",
                                 .group_name = "group_old_name",
                                 .mtime = 1100,
                                 .arch = ARCH_64BIT,
                                 .scanned = 0,
                                 .last_event = 1234,
                                 .checksum = "234567890ABCDEF1234567890ABCDEF123456789" };
    registry_t configuration = { "HKEY_USERS\\Some", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL };
    cJSON *ret, *it;
    char *changed_attributes[] = { "permission", "uid", "user_name", "gid", "group_name", "mtime" };
    int attributes_it = 0;


    ret = fim_registry_compare_key_attrs(&new_key, &saved_key, &configuration);

    *state = ret;

    cJSON_ArrayForEach(it, ret) {
        assert_string_equal(cJSON_GetStringValue(it), changed_attributes[attributes_it++]);
    }

    free(new_key.perm);
    free(saved_key.perm);
    cJSON_Delete(permissions);
    cJSON_Delete(saved_permissions);
}

static void test_fim_registry_compare_value_attrs(void **state){
    fim_registry_value_data new_value = { 3,
                                          "key\\path",
                                          ARCH_64BIT,
                                          "the\\value",
                                          REG_SZ,
                                          50,
                                          "1234567890ABCDEF1234567890ABCDEF",
                                          "1234567890ABCDEF1234567890ABCDEF12345678",
                                          "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF",
                                          0,
                                          10000,
                                          "1234567890ABCDEF1234567890ABCDEF12345678",
                                          FIM_MODIFICATION };

    fim_registry_value_data saved_value = { 3,
                                          "key\\path",
                                          ARCH_64BIT,
                                          "the\\value",
                                          REG_DWORD,
                                          49,
                                          "234567890ABCDEF1234567890ABCDEF1",
                                          "234567890ABCDEF1234567890ABCDEF123456789",
                                          "234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1",
                                          0,
                                          11000,
                                          "234567890ABCDEF1234567890ABCDEF123456789",
                                          FIM_MODIFICATION };
    registry_t configuration = { "HKEY_USERS\\Some", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL };
    cJSON *ret, *it;
    char *changed_attributes[] = { "size", "type", "md5", "sha1", "sha256", "last_event", "checksum" };
    int attributes_it = 0;

    ret = fim_registry_compare_value_attrs(&new_value, &saved_value, &configuration);

    *state = ret;

    cJSON_ArrayForEach(it, ret) {
        assert_string_equal(cJSON_GetStringValue(it), changed_attributes[attributes_it++]);
    }
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // tests registry key transaction callback
        cmocka_unit_test_teardown(test_fim_dbsync_registry_key_json_event_key_not_null, teardown_cjson_object),
        cmocka_unit_test_teardown(test_fim_dbsync_registry_key_json_event_key_null, teardown_cjson_object),
        cmocka_unit_test_teardown(test_fim_dbsync_registry_value_json_event_value_not_null, teardown_cjson_object),
        cmocka_unit_test_teardown(test_fim_dbsync_registry_value_json_event_value_null, teardown_cjson_object),
        cmocka_unit_test_teardown(test_fim_registry_compare_key_attrs,teardown_cjson_object),
        cmocka_unit_test_teardown(test_fim_registry_compare_value_attrs,teardown_cjson_object),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
