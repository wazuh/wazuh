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
#include "../../../syscheckd/include/syscheck.h"
#include "../../../syscheckd/src/registry/registry.h"
#include "test_fim.h"

#define CHECK_REGISTRY_ALL                                                                             \
    CHECK_SIZE | CHECK_PERM | CHECK_OWNER | CHECK_GROUP | CHECK_MTIME | CHECK_MD5SUM | CHECK_SHA1SUM | \
    CHECK_SHA256SUM | CHECK_SEECHANGES | CHECK_TYPE

fim_registry_key DEFAULT_REGISTRY_KEY = { .id = 3, .path = "HKEY_USERS\\Some\\random\\key", .perm_json = NULL, .perm = "", .uid = "110", .gid = "220", .user_name = "user_old_name", .group_name = "group_old_name", .mtime = 1100, .arch = ARCH_64BIT, .scanned = 0, .last_event = 1234, .checksum = "234567890ABCDEF1234567890ABCDEF123456789", .hash_full_path = "234567890ABCDEF1234567890ABCDEF123456111"};
fim_registry_value_data DEFAULT_REGISTRY_VALUE = { .id = 3, .path = "key\\path", .hash_full_path = "234567890ABCDEF1234567890ABCDEF123456111", .arch = ARCH_64BIT, .name = "the\\value", .type = REG_SZ, .size = 50, .hash_md5 = "1234567890ABCDEF1234567890ABCDEF", . hash_sha1 = "1234567890ABCDEF1234567890ABCDEF12345678", .hash_sha256 = "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF", .scanned = 0, .last_event = 10000, .checksum = "1234567890ABCDEF1234567890ABCDEF12345678", .mode = FIM_MODIFICATION };
typedef struct fim_key_txn_context_s {
    event_data_t *evt_data;
    fim_registry_key *key;
} fim_key_txn_context_t;

typedef struct fim_val_txn_context_s {
    event_data_t *evt_data;
    fim_registry_value_data *data;
    char* diff;
} fim_val_txn_context_t;

typedef struct key_difference_s {
    cJSON *old_data;
    cJSON *changed_attributes;
    cJSON *old_attributes;
} key_difference_t;

typedef struct json_data_s {
    cJSON *data1;
    cJSON *data2;
} json_data_t;

static int setup_dbsync_difference(void **state) {
    key_difference_t *data = calloc(1, sizeof(key_difference_t));
    if (data == NULL) {
        return 1;
    }

    data->old_data = cJSON_CreateObject();

    if (data->old_data == NULL) {
        return 1;
    }

    data->changed_attributes = cJSON_CreateArray();
    if (data->changed_attributes == NULL) {
        return 1;
    }

    data->old_attributes = cJSON_CreateObject();
    if (data->old_attributes == NULL) {
        return 1;
    }
    *state = data;
    return 0;
}

static int teardown_dbsync_difference(void **state) {
    key_difference_t * data = (key_difference_t*) *state;

    cJSON_Delete(data->changed_attributes);
    cJSON_Delete(data->old_attributes);
    cJSON_Delete(data->old_data);

    free(data);
    return 0;
}

static int teardown_cjson_object(void **state) {
    cJSON *object = *state;

    cJSON_Delete(object);

    return 0;
}

static int teardown_cjson_data(void **state) {
    json_data_t *data = *state;

    cJSON_Delete(data->data2);
    free(data);

    return 0;
}

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
                                          "234567890ABCDEF1234567890ABCDEF123456111",
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
                                          "234567890ABCDEF1234567890ABCDEF123456111",
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

void test_calculate_dbsync_difference_key_perm_change(void **state) {

    key_difference_t *data = (key_difference_t *) *state;
    registry_t configuration = { "HKEY_USERS\\Some", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL };
    const char* old_entry_str = "{\"type\":\"registry_key\",\"perm\":{\"S-1-5-32-545\":{\"name\":\"Users\",\"allowed\":[\"read_control\",\"read_data\",\"read_ea\",\"write_ea\"]},\"S-1-5-32-544\":{\"name\":\"Administrators\",\"allowed\":[\"delete\",\"read_control\",\"write_dac\",\"write_owner\",\"read_data\",\"write_data\",\"append_data\",\"read_ea\",\"write_ea\",\"execute\"]},\"S-1-5-18\":{\"name\":\"SYSTEM\",\"allowed\":[\"delete\",\"read_control\",\"write_dac\",\"write_owner\",\"read_data\",\"write_data\",\"append_data\",\"read_ea\",\"write_ea\",\"execute\"]},\"S-1-3-0\":{\"name\":\"CREATOR OWNER\",\"allowed\":[\"delete\",\"read_control\",\"write_dac\",\"write_owner\",\"read_data\",\"write_data\",\"append_data\",\"read_ea\",\"write_ea\",\"execute\"]},\"S-1-15-2-1\":{\"name\":\"ALL APPLICATION PACKAGES\",\"allowed\":[\"read_control\",\"read_data\",\"read_ea\",\"write_ea\"]}},\"uid\":\"110\",\"user_name\":\"user_old_name\",\"gid\":\"110\",\"group_name\":\"group_old_name\",\"mtime\":1100,\"checksum\":\"234567890ABCDEF1234567890ABCDEF123456789\"}";
    cJSON *old_data = data->old_data;
    cJSON *changed_attributes = data->changed_attributes;
    cJSON *old_attributes = data->old_attributes;

    char *perm_string = "{\"S-1-5-32-545\":{\"name\":\"Users\",\"allowed\":[\"read_control\",\"read_data\",\"read_ea\",\"write_ea\"]},\"S-1-5-32-544\":{\"name\":\"Administrators\",\"allowed\":[\"delete\",\"read_control\",\"write_dac\",\"write_owner\",\"read_data\",\"write_data\",\"append_data\",\"read_ea\",\"write_ea\",\"execute\"]},\"S-1-5-18\":{\"name\":\"SYSTEM\",\"allowed\":[\"delete\",\"read_control\",\"write_dac\",\"write_owner\",\"read_data\",\"write_data\",\"append_data\",\"read_ea\",\"write_ea\",\"execute\"]},\"S-1-3-0\":{\"name\":\"CREATOR OWNER\",\"allowed\":[\"delete\",\"read_control\",\"write_dac\",\"write_owner\",\"read_data\",\"write_data\",\"append_data\",\"read_ea\",\"write_ea\",\"execute\"]},\"S-1-15-2-1\":{\"name\":\"ALL APPLICATION PACKAGES\",\"allowed\":[\"read_control\",\"read_data\",\"read_ea\",\"write_ea\"]}}";
    cJSON_AddItemToObject(old_data, "perm", cJSON_CreateString(perm_string));

    fim_registry_key registry_data =  DEFAULT_REGISTRY_KEY;

    fim_calculate_dbsync_difference_key(&registry_data, &configuration, old_data, changed_attributes, old_attributes);
    assert_string_equal(cJSON_PrintUnformatted(changed_attributes), "[\"permission\"]");
    assert_string_equal(cJSON_PrintUnformatted(old_attributes), old_entry_str);
}

void test_calculate_dbsync_difference_key_no_change(void **state) {

    key_difference_t *data = (key_difference_t *) *state;
    registry_t configuration = { "HKEY_USERS\\Some", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL };
    cJSON *old_data = data->old_data;
    cJSON *changed_attributes = data->changed_attributes;
    cJSON *old_attributes = data->old_attributes;

    fim_registry_key registry_data =  DEFAULT_REGISTRY_KEY;

    fim_calculate_dbsync_difference_key(&registry_data, &configuration, old_data, changed_attributes, old_attributes);
    assert_string_equal(cJSON_PrintUnformatted(changed_attributes), "[]");
}

void test_calculate_dbsync_difference_key_uid_change(void **state) {

    key_difference_t *data = (key_difference_t *) *state;
    registry_t configuration = { "HKEY_USERS\\Some", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL };
    const char *old_attributes_str = "{\"type\":\"registry_key\",\"uid\":\"210\",\"user_name\":\"user_old_name\",\"gid\":\"110\",\"group_name\":\"group_old_name\",\"mtime\":1100,\"checksum\":\"234567890ABCDEF1234567890ABCDEF123456789\"}";
    cJSON *old_data = data->old_data;
    cJSON *changed_attributes = data->changed_attributes;
    cJSON *old_attributes = data->old_attributes;

    cJSON_AddStringToObject(old_data, "uid", "210");

    fim_registry_key registry_data = DEFAULT_REGISTRY_KEY;
    fim_calculate_dbsync_difference_key(&registry_data, &configuration, old_data, changed_attributes, old_attributes);

    assert_string_equal(cJSON_PrintUnformatted(changed_attributes), "[\"uid\"]");
    assert_string_equal(cJSON_PrintUnformatted(old_attributes), old_attributes_str);
}

void test_calculate_dbsync_difference_key_username_change(void **state) {
    key_difference_t *data = (key_difference_t *) *state;
    registry_t configuration = { "HKEY_USERS\\Some", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL };
    const char* old_attributes_str = "{\"type\":\"registry_key\",\"uid\":\"110\",\"user_name\":\"previous_username\",\"gid\":\"110\",\"group_name\":\"group_old_name\",\"mtime\":1100,\"checksum\":\"234567890ABCDEF1234567890ABCDEF123456789\"}";
    cJSON *old_data = data->old_data;
    cJSON *changed_attributes = data->changed_attributes;
    cJSON *old_attributes = data->old_attributes;

    cJSON_AddStringToObject(old_data, "user_name", "previous_username");

    fim_registry_key registry_data =  DEFAULT_REGISTRY_KEY;
    fim_calculate_dbsync_difference_key(&registry_data, &configuration, old_data, changed_attributes, old_attributes);
    assert_string_equal(cJSON_PrintUnformatted(changed_attributes), "[\"user_name\"]");
    assert_string_equal(cJSON_PrintUnformatted(old_attributes), old_attributes_str);
}

void test_calculate_dbsync_difference_key_username_no_change_empty(void **state) {
    key_difference_t *data = (key_difference_t *) *state;
    registry_t configuration = { "HKEY_USERS\\Some", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL };
    cJSON *old_data = data->old_data;
    cJSON *changed_attributes = data->changed_attributes;
    cJSON *old_attributes = data->old_attributes;
    cJSON_AddStringToObject(old_data, "user_name", "");

    fim_registry_key registry_data = DEFAULT_REGISTRY_KEY;
    fim_calculate_dbsync_difference_key(&registry_data, &configuration, old_data, changed_attributes, old_attributes);
    assert_string_equal(cJSON_PrintUnformatted(changed_attributes), "[]");
}


void test_calculate_dbsync_difference_key_gid_change(void **state) {

    key_difference_t *data = (key_difference_t *) *state;
    registry_t configuration = { "HKEY_USERS\\Some", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL };
    const char *old_attributes_str = "{\"type\":\"registry_key\",\"uid\":\"110\",\"user_name\":\"user_old_name\",\"gid\":\"210\",\"group_name\":\"group_old_name\",\"mtime\":1100,\"checksum\":\"234567890ABCDEF1234567890ABCDEF123456789\"}";

    cJSON *old_data = data->old_data;
    cJSON *changed_attributes = data->changed_attributes;
    cJSON *old_attributes = data->old_attributes;

    cJSON_AddStringToObject(old_data, "gid", "210");

    fim_registry_key registry_data = DEFAULT_REGISTRY_KEY;
    fim_calculate_dbsync_difference_key(&registry_data, &configuration, old_data, changed_attributes, old_attributes);
    assert_string_equal(cJSON_PrintUnformatted(changed_attributes), "[\"gid\"]");
    assert_string_equal(cJSON_PrintUnformatted(old_attributes), old_attributes_str);
}

void test_calculate_dbsync_difference_key_groupname_change(void **state) {
    key_difference_t *data = (key_difference_t *) *state;
    registry_t configuration = { "HKEY_USERS\\Some", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL };
    const char* old_attributes_str = "{\"type\":\"registry_key\",\"uid\":\"110\",\"user_name\":\"user_old_name\",\"gid\":\"110\",\"group_name\":\"previous_groupname\",\"mtime\":1100,\"checksum\":\"234567890ABCDEF1234567890ABCDEF123456789\"}";
    cJSON *old_data = data->old_data;
    cJSON *changed_attributes = data->changed_attributes;
    cJSON *old_attributes = data->old_attributes;

    cJSON_AddStringToObject(old_data, "group_name", "previous_groupname");

    fim_registry_key registry_data = DEFAULT_REGISTRY_KEY;
    fim_calculate_dbsync_difference_key(&registry_data, &configuration, old_data, changed_attributes, old_attributes);
    assert_string_equal(cJSON_PrintUnformatted(changed_attributes), "[\"group_name\"]");
    assert_string_equal(cJSON_PrintUnformatted(old_attributes), old_attributes_str);
}

void test_calculate_dbsync_difference_key_mtime_change(void **state) {
    key_difference_t *data = (key_difference_t *) *state;
    const char* old_attributes_str = "{\"type\":\"registry_key\",\"uid\":\"110\",\"user_name\":\"user_old_name\",\"gid\":\"110\",\"group_name\":\"group_old_name\",\"mtime\":98765432,\"checksum\":\"234567890ABCDEF1234567890ABCDEF123456789\"}";
    registry_t configuration = { "HKEY_USERS\\Some", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL };
    cJSON *old_data = data->old_data;
    cJSON *changed_attributes = data->changed_attributes;
    cJSON *old_attributes = data->old_attributes;

    cJSON_AddNumberToObject(old_data, "mtime", 98765432);

    fim_registry_key registry_data = DEFAULT_REGISTRY_KEY;
    fim_calculate_dbsync_difference_key(&registry_data, &configuration, old_data, changed_attributes, old_attributes);
    assert_string_equal(cJSON_PrintUnformatted(changed_attributes), "[\"mtime\"]");
    assert_string_equal(cJSON_PrintUnformatted(old_attributes), old_attributes_str);
}

void test_calculate_dbsync_difference_value_size_change(void **state) {
    key_difference_t *data = (key_difference_t *) *state;
    const char *old_attributes_str = "{\"type\":\"registry_value\",\"size\":98765432,\"value_type\":\"REG_SZ\",\"hash_md5\":\"1234567890ABCDEF1234567890ABCDEF\",\"hash_sha1\":\"1234567890ABCDEF1234567890ABCDEF12345678\",\"hash_sha256\":\"1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF\"}";
    registry_t configuration = { "HKEY_USERS\\Some", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL };
    cJSON *old_data = data->old_data;
    cJSON *changed_attributes = data->changed_attributes;
    cJSON *old_attributes = data->old_attributes;

    cJSON_AddNumberToObject(old_data, "size", 98765432);

    fim_registry_value_data registry_data = DEFAULT_REGISTRY_VALUE;

    fim_calculate_dbsync_difference_value(&registry_data, &configuration, old_data, changed_attributes, old_attributes);
    assert_string_equal(cJSON_PrintUnformatted(changed_attributes), "[\"size\"]");
    assert_string_equal(cJSON_PrintUnformatted(old_attributes), old_attributes_str);

}

void test_calculate_dbsync_difference_value_type_change(void **state) {
    key_difference_t *data = (key_difference_t *) *state;
    const char *old_attributes_str = "{\"type\":\"registry_value\",\"size\":50,\"value_type\":\"REG_EXPAND_SZ\",\"hash_md5\":\"1234567890ABCDEF1234567890ABCDEF\",\"hash_sha1\":\"1234567890ABCDEF1234567890ABCDEF12345678\",\"hash_sha256\":\"1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF\"}";
    registry_t configuration = { "HKEY_USERS\\Some", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL };
    cJSON *old_data = data->old_data;
    cJSON *changed_attributes = data->changed_attributes;
    cJSON *old_attributes = data->old_attributes;

    cJSON_AddNumberToObject(old_data, "value_type", 2);
    fim_registry_value_data registry_data = DEFAULT_REGISTRY_VALUE;

    fim_calculate_dbsync_difference_value(&registry_data, &configuration, old_data, changed_attributes, old_attributes);
    assert_string_equal(cJSON_PrintUnformatted(changed_attributes), "[\"value_type\"]");
    assert_string_equal(cJSON_PrintUnformatted(old_attributes), old_attributes_str);
}

void test_calculate_dbsync_difference_value_md5_change(void **state) {
    key_difference_t *data = (key_difference_t *) *state;
    const char *old_attributes_str = "{\"type\":\"registry_value\",\"size\":50,\"value_type\":\"REG_SZ\",\"hash_md5\":\"FEDCBA0987654321FEDCBA0987654321\",\"hash_sha1\":\"1234567890ABCDEF1234567890ABCDEF12345678\",\"hash_sha256\":\"1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF\"}";
    registry_t configuration = { "HKEY_USERS\\Some", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL };
    cJSON *old_data = data->old_data;
    cJSON *changed_attributes = data->changed_attributes;
    cJSON *old_attributes = data->old_attributes;

    cJSON_AddStringToObject(old_data, "hash_md5", "FEDCBA0987654321FEDCBA0987654321");

    fim_registry_value_data registry_data = DEFAULT_REGISTRY_VALUE;

    fim_calculate_dbsync_difference_value(&registry_data, &configuration, old_data, changed_attributes, old_attributes);
    assert_string_equal(cJSON_PrintUnformatted(changed_attributes), "[\"md5\"]");
    assert_string_equal(cJSON_PrintUnformatted(old_attributes), old_attributes_str);
}

void test_calculate_dbsync_difference_value_sha1_change(void **state) {
    key_difference_t *data = (key_difference_t *) *state;
    const char *old_attributes_str = "{\"type\":\"registry_value\",\"size\":50,\"value_type\":\"REG_SZ\",\"hash_md5\":\"1234567890ABCDEF1234567890ABCDEF\",\"hash_sha1\":\"FEDCBA0987654321FEDCBA0987654321FEDCBA09\",\"hash_sha256\":\"1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF\"}";
    registry_t configuration = { "HKEY_USERS\\Some", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL };
    cJSON *old_data = data->old_data;
    cJSON *changed_attributes = data->changed_attributes;
    cJSON *old_attributes = data->old_attributes;

    cJSON_AddStringToObject(old_data, "hash_sha1", "FEDCBA0987654321FEDCBA0987654321FEDCBA09");

    fim_registry_value_data registry_data = DEFAULT_REGISTRY_VALUE;

    fim_calculate_dbsync_difference_value(&registry_data, &configuration, old_data, changed_attributes, old_attributes);
    assert_string_equal(cJSON_PrintUnformatted(changed_attributes), "[\"sha1\"]");
    assert_string_equal(cJSON_PrintUnformatted(old_attributes), old_attributes_str);
}


void test_calculate_dbsync_difference_value_sha256_change(void **state) {
    key_difference_t *data = (key_difference_t *) *state;
    const char *old_attributes_str = "{\"type\":\"registry_value\",\"size\":50,\"value_type\":\"REG_SZ\",\"hash_md5\":\"1234567890ABCDEF1234567890ABCDEF\",\"hash_sha1\":\"1234567890ABCDEF1234567890ABCDEF12345678\",\"hash_sha256\":\"FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321\"}";

    registry_t configuration = { "HKEY_USERS\\Some", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL };
    cJSON *old_data = data->old_data;
    cJSON *changed_attributes = data->changed_attributes;
    cJSON *old_attributes = data->old_attributes;

    cJSON_AddStringToObject(old_data, "hash_sha256", "FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321");

    fim_registry_value_data registry_data = DEFAULT_REGISTRY_VALUE;

    fim_calculate_dbsync_difference_value(&registry_data, &configuration, old_data, changed_attributes, old_attributes);
    assert_string_equal(cJSON_PrintUnformatted(changed_attributes), "[\"sha256\"]");
    assert_string_equal(cJSON_PrintUnformatted(old_attributes), old_attributes_str);
}

void test_calculate_dbsync_difference_value_no_change(void **state) {
    key_difference_t *data = (key_difference_t *) *state;
    registry_t configuration = { "HKEY_USERS\\Some", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL };
    cJSON *old_data = data->old_data;
    cJSON *changed_attributes = data->changed_attributes;
    cJSON *old_attributes = data->old_attributes;

    fim_registry_value_data registry_data = DEFAULT_REGISTRY_VALUE;

    fim_calculate_dbsync_difference_value(&registry_data, &configuration, old_data, changed_attributes, old_attributes);
    assert_string_equal(cJSON_PrintUnformatted(changed_attributes), "[]");
}

void test_registry_key_attributes_json_entry(void **state) {
    json_data_t *data = calloc(1, sizeof(json_data_t));
    char perm_data[OS_MAXSTR] = "{\"S-1-5-32-545\":{\"name\":\"Users\",\"allowed\":[\"read_control\",\"read_data\",\"read_ea\",\"write_ea\"]},\"S-1-5-32-544\":{\"name\":\"Administrators\",\"allowed\":[\"delete\",\"read_control\",\"write_dac\",\"write_owner\",\"read_data\",\"write_data\",\"append_data\",\"read_ea\",\"write_ea\",\"execute\"]},\"S-1-5-18\":{\"name\":\"SYSTEM\",\"allowed\":[\"delete\",\"read_control\",\"write_dac\",\"write_owner\",\"read_data\",\"write_data\",\"append_data\",\"read_ea\",\"write_ea\",\"execute\"]},\"S-1-3-0\":{\"name\":\"CREATOR OWNER\",\"allowed\":[\"delete\",\"read_control\",\"write_dac\",\"write_owner\",\"read_data\",\"write_data\",\"append_data\",\"read_ea\",\"write_ea\",\"execute\"]},\"S-1-15-2-1\":{\"name\":\"ALL APPLICATION PACKAGES\",\"allowed\":[\"read_control\",\"read_data\",\"read_ea\",\"write_ea\"]}}";

    const char* event_str = "{\"type\":\"registry_key\",\"perm\":{\"S-1-5-32-545\":{\"name\":\"Users\",\"allowed\":[\"read_control\",\"read_data\",\"read_ea\",\"write_ea\"]},\"S-1-5-32-544\":{\"name\":\"Administrators\",\"allowed\":[\"delete\",\"read_control\",\"write_dac\",\"write_owner\",\"read_data\",\"write_data\",\"append_data\",\"read_ea\",\"write_ea\",\"execute\"]},\"S-1-5-18\":{\"name\":\"SYSTEM\",\"allowed\":[\"delete\",\"read_control\",\"write_dac\",\"write_owner\",\"read_data\",\"write_data\",\"append_data\",\"read_ea\",\"write_ea\",\"execute\"]},\"S-1-3-0\":{\"name\":\"CREATOR OWNER\",\"allowed\":[\"delete\",\"read_control\",\"write_dac\",\"write_owner\",\"read_data\",\"write_data\",\"append_data\",\"read_ea\",\"write_ea\",\"execute\"]},\"S-1-15-2-1\":{\"name\":\"ALL APPLICATION PACKAGES\",\"allowed\":[\"read_control\",\"read_data\",\"read_ea\",\"write_ea\"]}},\"uid\":\"110\",\"user_name\":\"user_old_name\",\"gid\":\"220\",\"group_name\":\"group_old_name\",\"mtime\":1100,\"checksum\":\"234567890ABCDEF1234567890ABCDEF123456789\"}";
    fim_registry_key registry_data = DEFAULT_REGISTRY_KEY;
    registry_t configuration = { "HKEY_USERS\\Some", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL };

    registry_data.perm = perm_data;

    cJSON *event = fim_registry_key_attributes_json(NULL, &registry_data, &configuration);

    data->data2 = event;
    *state = data;

    assert_string_equal(event_str, cJSON_PrintUnformatted(event));
}

void test_registry_key_attributes_json_dbsync(void **state) {
    json_data_t *data = calloc(1, sizeof(json_data_t));
    cJSON *dbsync_event = cJSON_Parse("{\"perm\":\"{\\\"S-1-5-32-545\\\":{\\\"name\\\":\\\"Users\\\",\\\"allowed\\\":[\\\"read_control\\\",\\\"read_data\\\",\\\"read_ea\\\",\\\"write_ea\\\"]},\\\"S-1-5-32-544\\\":{\\\"name\\\":\\\"Administrators\\\",\\\"allowed\\\":[\\\"delete\\\",\\\"read_control\\\",\\\"write_dac\\\",\\\"write_owner\\\",\\\"read_data\\\",\\\"write_data\\\",\\\"append_data\\\",\\\"read_ea\\\",\\\"write_ea\\\",\\\"execute\\\"]},\\\"S-1-5-18\\\":{\\\"name\\\":\\\"SYSTEM\\\",\\\"allowed\\\":[\\\"delete\\\",\\\"read_control\\\",\\\"write_dac\\\",\\\"write_owner\\\",\\\"read_data\\\",\\\"write_data\\\",\\\"append_data\\\",\\\"read_ea\\\",\\\"write_ea\\\",\\\"execute\\\"]},\\\"S-1-3-0\\\":{\\\"name\\\":\\\"CREATOR OWNER\\\",\\\"allowed\\\":[\\\"delete\\\",\\\"read_control\\\",\\\"write_dac\\\",\\\"write_owner\\\",\\\"read_data\\\",\\\"write_data\\\",\\\"append_data\\\",\\\"read_ea\\\",\\\"write_ea\\\",\\\"execute\\\"]},\\\"S-1-15-2-1\\\":{\\\"name\\\":\\\"ALL APPLICATION PACKAGES\\\",\\\"allowed\\\":[\\\"read_control\\\",\\\"read_data\\\",\\\"read_ea\\\",\\\"write_ea\\\"]}}\",\"uid\":\"110\",\"user_name\":\"user_old_name\",\"gid\":\"220\",\"group_name\":\"group_old_name\",\"mtime\":1100,\"checksum\":\"234567890ABCDEF1234567890ABCDEF123456789\"}");
    const char* event_str = "{\"type\":\"registry_key\",\"perm\":{\"S-1-5-32-545\":{\"name\":\"Users\",\"allowed\":[\"read_control\",\"read_data\",\"read_ea\",\"write_ea\"]},\"S-1-5-32-544\":{\"name\":\"Administrators\",\"allowed\":[\"delete\",\"read_control\",\"write_dac\",\"write_owner\",\"read_data\",\"write_data\",\"append_data\",\"read_ea\",\"write_ea\",\"execute\"]},\"S-1-5-18\":{\"name\":\"SYSTEM\",\"allowed\":[\"delete\",\"read_control\",\"write_dac\",\"write_owner\",\"read_data\",\"write_data\",\"append_data\",\"read_ea\",\"write_ea\",\"execute\"]},\"S-1-3-0\":{\"name\":\"CREATOR OWNER\",\"allowed\":[\"delete\",\"read_control\",\"write_dac\",\"write_owner\",\"read_data\",\"write_data\",\"append_data\",\"read_ea\",\"write_ea\",\"execute\"]},\"S-1-15-2-1\":{\"name\":\"ALL APPLICATION PACKAGES\",\"allowed\":[\"read_control\",\"read_data\",\"read_ea\",\"write_ea\"]}},\"uid\":\"110\",\"user_name\":\"user_old_name\",\"gid\":\"220\",\"group_name\":\"group_old_name\",\"mtime\":1100,\"checksum\":\"234567890ABCDEF1234567890ABCDEF123456789\"}";
    registry_t configuration = { "HKEY_USERS\\Some", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL };

    cJSON *event = fim_registry_key_attributes_json(dbsync_event, NULL, &configuration);

    data->data1 = dbsync_event;
    data->data2 = event;
    *state = data;
    assert_string_equal(event_str, cJSON_PrintUnformatted(event));
}


void test_registry_value_attributes_json_entry(void **state) {
    json_data_t *data = calloc(1, sizeof(json_data_t));
    const char* event_str = "{\"type\":\"registry_value\",\"value_type\":\"REG_SZ\",\"size\":50,\"hash_md5\":\"1234567890ABCDEF1234567890ABCDEF\",\"hash_sha1\":\"1234567890ABCDEF1234567890ABCDEF12345678\",\"hash_sha256\":\"1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF\",\"checksum\":\"1234567890ABCDEF1234567890ABCDEF12345678\"}";
    fim_registry_value_data registry_data = DEFAULT_REGISTRY_VALUE;
    registry_t configuration = { "HKEY_USERS\\Some", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL };

    cJSON *event = fim_registry_value_attributes_json(NULL, &registry_data, &configuration);

    data->data1 = event;
    *state = data;

    assert_string_equal(event_str, cJSON_PrintUnformatted(event));
}

void test_registry_value_attributes_json_dbsync(void **state) {
    json_data_t *data = calloc(1, sizeof(json_data_t));
    const char* event_str = "{\"type\":\"registry_value\",\"value_type\":\"REG_SZ\",\"size\":50,\"hash_md5\":\"1234567890ABCDEF1234567890ABCDEF\",\"hash_sha1\":\"1234567890ABCDEF1234567890ABCDEF12345678\",\"hash_sha256\":\"1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF\",\"checksum\":\"1234567890ABCDEF1234567890ABCDEF12345678\"}";
    cJSON *dbsync_event = cJSON_Parse("{\"arch\":\"[x64]\",\"checksum\":\"1234567890ABCDEF1234567890ABCDEF12345678\",\"hash_md5\":\"1234567890ABCDEF1234567890ABCDEF\",\"hash_sha1\":\"1234567890ABCDEF1234567890ABCDEF12345678\",\"hash_sha256\":\"1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF\",\"last_event\":1645700674,\"name\":\"New Value 1\",\"path\":\"HKEY_USERS\\\\Some\",\"scanned\":0,\"size\":50,\"type\":1}");
    registry_t configuration = { "HKEY_USERS\\Some", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL };


    cJSON *event = fim_registry_value_attributes_json(dbsync_event, NULL, &configuration);
    data->data1 = dbsync_event;
    data->data2 = event;
    *state = data;

    assert_string_equal(event_str, cJSON_PrintUnformatted(event));
}


int main(void) {
    const struct CMUnitTest tests[] = {
        // tests registry key transaction callback
        cmocka_unit_test_teardown(test_fim_registry_compare_key_attrs, teardown_cjson_object),
        cmocka_unit_test_teardown(test_fim_registry_compare_value_attrs, teardown_cjson_object),
        cmocka_unit_test_setup_teardown(test_calculate_dbsync_difference_key_perm_change, setup_dbsync_difference, teardown_dbsync_difference),
        cmocka_unit_test_setup_teardown(test_calculate_dbsync_difference_key_no_change, setup_dbsync_difference, teardown_dbsync_difference),
        cmocka_unit_test_setup_teardown(test_calculate_dbsync_difference_key_uid_change, setup_dbsync_difference, teardown_dbsync_difference),
        cmocka_unit_test_setup_teardown(test_calculate_dbsync_difference_key_username_change, setup_dbsync_difference, teardown_dbsync_difference),
        cmocka_unit_test_setup_teardown(test_calculate_dbsync_difference_key_username_no_change_empty, setup_dbsync_difference, teardown_dbsync_difference),
        cmocka_unit_test_setup_teardown(test_calculate_dbsync_difference_key_gid_change, setup_dbsync_difference, teardown_dbsync_difference),
        cmocka_unit_test_setup_teardown(test_calculate_dbsync_difference_key_groupname_change, setup_dbsync_difference, teardown_dbsync_difference),
        cmocka_unit_test_setup_teardown(test_calculate_dbsync_difference_key_mtime_change, setup_dbsync_difference, teardown_dbsync_difference),
        cmocka_unit_test_setup_teardown(test_calculate_dbsync_difference_value_size_change, setup_dbsync_difference, teardown_dbsync_difference),
        cmocka_unit_test_setup_teardown(test_calculate_dbsync_difference_value_type_change, setup_dbsync_difference, teardown_dbsync_difference),
        cmocka_unit_test_setup_teardown(test_calculate_dbsync_difference_value_md5_change, setup_dbsync_difference, teardown_dbsync_difference),
        cmocka_unit_test_setup_teardown(test_calculate_dbsync_difference_value_sha1_change, setup_dbsync_difference, teardown_dbsync_difference),
        cmocka_unit_test_setup_teardown(test_calculate_dbsync_difference_value_sha256_change, setup_dbsync_difference, teardown_dbsync_difference),
        cmocka_unit_test_setup_teardown(test_calculate_dbsync_difference_value_no_change, setup_dbsync_difference, teardown_dbsync_difference),
        cmocka_unit_test_teardown(test_registry_key_attributes_json_entry, teardown_cjson_data),
        cmocka_unit_test_teardown(test_registry_key_attributes_json_dbsync, teardown_cjson_data),
        cmocka_unit_test_teardown(test_registry_value_attributes_json_entry, teardown_cjson_data),
        cmocka_unit_test_teardown(test_registry_value_attributes_json_dbsync, teardown_cjson_data),

    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
