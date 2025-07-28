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

fim_registry_key DEFAULT_REGISTRY_KEY = { .path = "HKEY_USERS\\Some\\random\\key", .perm_json = NULL, .permissions = "", .uid = "110", .gid = "220", .owner = "user_old_name", .group = "group_old_name", .mtime = 1100, .architecture = ARCH_64BIT, .checksum = "234567890ABCDEF1234567890ABCDEF123456789"};
fim_registry_value_data DEFAULT_REGISTRY_VALUE = { .path = "key\\path", .architecture = ARCH_64BIT, .value = "the\\value", .type = REG_SZ, .size = 50, .hash_md5 = "1234567890ABCDEF1234567890ABCDEF", .hash_sha1 = "1234567890ABCDEF1234567890ABCDEF12345678", .hash_sha256 = "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF", .checksum = "1234567890ABCDEF1234567890ABCDEF12345678" };

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

static int teardown_cjson_data(void **state) {
    json_data_t *data = *state;

    cJSON_Delete(data->data2);
    free(data);

    return 0;
}


void test_calculate_dbsync_difference_key_perm_change(void **state) {

    key_difference_t *data = (key_difference_t *) *state;
    registry_t configuration = { "HKEY_USERS\\Some", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL };
    const char* old_entry_str = "{\"permissions\":{\"S-1-5-32-545\":{\"value\":\"Users\",\"allowed\":[\"read_control\",\"read_data\",\"read_ea\",\"write_ea\"]},\"S-1-5-32-544\":{\"value\":\"Administrators\",\"allowed\":[\"delete\",\"read_control\",\"write_dac\",\"write_owner\",\"read_data\",\"write_data\",\"append_data\",\"read_ea\",\"write_ea\",\"execute\"]},\"S-1-5-18\":{\"value\":\"SYSTEM\",\"allowed\":[\"delete\",\"read_control\",\"write_dac\",\"write_owner\",\"read_data\",\"write_data\",\"append_data\",\"read_ea\",\"write_ea\",\"execute\"]},\"S-1-3-0\":{\"value\":\"CREATOR OWNER\",\"allowed\":[\"delete\",\"read_control\",\"write_dac\",\"write_owner\",\"read_data\",\"write_data\",\"append_data\",\"read_ea\",\"write_ea\",\"execute\"]},\"S-1-15-2-1\":{\"value\":\"ALL APPLICATION PACKAGES\",\"allowed\":[\"read_control\",\"read_data\",\"read_ea\",\"write_ea\"]}}}";
    cJSON *old_data = data->old_data;
    cJSON *changed_attributes = data->changed_attributes;
    cJSON *old_attributes = data->old_attributes;

    char *perm_string = "{\"S-1-5-32-545\":{\"value\":\"Users\",\"allowed\":[\"read_control\",\"read_data\",\"read_ea\",\"write_ea\"]},\"S-1-5-32-544\":{\"value\":\"Administrators\",\"allowed\":[\"delete\",\"read_control\",\"write_dac\",\"write_owner\",\"read_data\",\"write_data\",\"append_data\",\"read_ea\",\"write_ea\",\"execute\"]},\"S-1-5-18\":{\"value\":\"SYSTEM\",\"allowed\":[\"delete\",\"read_control\",\"write_dac\",\"write_owner\",\"read_data\",\"write_data\",\"append_data\",\"read_ea\",\"write_ea\",\"execute\"]},\"S-1-3-0\":{\"value\":\"CREATOR OWNER\",\"allowed\":[\"delete\",\"read_control\",\"write_dac\",\"write_owner\",\"read_data\",\"write_data\",\"append_data\",\"read_ea\",\"write_ea\",\"execute\"]},\"S-1-15-2-1\":{\"value\":\"ALL APPLICATION PACKAGES\",\"allowed\":[\"read_control\",\"read_data\",\"read_ea\",\"write_ea\"]}}";
    cJSON_AddItemToObject(old_data, "permissions", cJSON_CreateString(perm_string));

    fim_registry_key registry_data =  DEFAULT_REGISTRY_KEY;

    fim_calculate_dbsync_difference_key(&registry_data, &configuration, old_data, changed_attributes, old_attributes);
    assert_string_equal(cJSON_PrintUnformatted(changed_attributes), "[\"registry.permissions\"]");
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
    const char *old_attributes_str = "{\"uid\":\"210\"}";
    cJSON *old_data = data->old_data;
    cJSON *changed_attributes = data->changed_attributes;
    cJSON *old_attributes = data->old_attributes;

    cJSON_AddStringToObject(old_data, "uid", "210");

    fim_registry_key registry_data = DEFAULT_REGISTRY_KEY;
    fim_calculate_dbsync_difference_key(&registry_data, &configuration, old_data, changed_attributes, old_attributes);

    assert_string_equal(cJSON_PrintUnformatted(changed_attributes), "[\"registry.uid\"]");
    assert_string_equal(cJSON_PrintUnformatted(old_attributes), old_attributes_str);
}

void test_calculate_dbsync_difference_key_username_change(void **state) {
    key_difference_t *data = (key_difference_t *) *state;
    registry_t configuration = { "HKEY_USERS\\Some", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL };
    const char* old_attributes_str = "{\"owner\":\"previous_username\"}";
    cJSON *old_data = data->old_data;
    cJSON *changed_attributes = data->changed_attributes;
    cJSON *old_attributes = data->old_attributes;

    cJSON_AddStringToObject(old_data, "owner", "previous_username");

    fim_registry_key registry_data =  DEFAULT_REGISTRY_KEY;
    fim_calculate_dbsync_difference_key(&registry_data, &configuration, old_data, changed_attributes, old_attributes);
    assert_string_equal(cJSON_PrintUnformatted(changed_attributes), "[\"registry.owner\"]");
    assert_string_equal(cJSON_PrintUnformatted(old_attributes), old_attributes_str);
}

void test_calculate_dbsync_difference_key_username_no_change_empty(void **state) {
    key_difference_t *data = (key_difference_t *) *state;
    registry_t configuration = { "HKEY_USERS\\Some", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL };
    cJSON *old_data = data->old_data;
    cJSON *changed_attributes = data->changed_attributes;
    cJSON *old_attributes = data->old_attributes;
    cJSON_AddStringToObject(old_data, "owner", "");

    fim_registry_key registry_data = DEFAULT_REGISTRY_KEY;
    fim_calculate_dbsync_difference_key(&registry_data, &configuration, old_data, changed_attributes, old_attributes);
    assert_string_equal(cJSON_PrintUnformatted(changed_attributes), "[]");
}


void test_calculate_dbsync_difference_key_gid_change(void **state) {

    key_difference_t *data = (key_difference_t *) *state;
    registry_t configuration = { "HKEY_USERS\\Some", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL };
    const char *old_attributes_str = "{\"gid\":\"210\"}";

    cJSON *old_data = data->old_data;
    cJSON *changed_attributes = data->changed_attributes;
    cJSON *old_attributes = data->old_attributes;

    cJSON_AddStringToObject(old_data, "gid", "210");

    fim_registry_key registry_data = DEFAULT_REGISTRY_KEY;
    fim_calculate_dbsync_difference_key(&registry_data, &configuration, old_data, changed_attributes, old_attributes);
    assert_string_equal(cJSON_PrintUnformatted(changed_attributes), "[\"registry.gid\"]");
    assert_string_equal(cJSON_PrintUnformatted(old_attributes), old_attributes_str);
}

void test_calculate_dbsync_difference_key_groupname_change(void **state) {
    key_difference_t *data = (key_difference_t *) *state;
    registry_t configuration = { "HKEY_USERS\\Some", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL };
    const char* old_attributes_str = "{\"group\":\"previous_groupname\"}";
    cJSON *old_data = data->old_data;
    cJSON *changed_attributes = data->changed_attributes;
    cJSON *old_attributes = data->old_attributes;

    cJSON_AddStringToObject(old_data, "group_", "previous_groupname");

    fim_registry_key registry_data = DEFAULT_REGISTRY_KEY;
    fim_calculate_dbsync_difference_key(&registry_data, &configuration, old_data, changed_attributes, old_attributes);
    assert_string_equal(cJSON_PrintUnformatted(changed_attributes), "[\"registry.group\"]");
    assert_string_equal(cJSON_PrintUnformatted(old_attributes), old_attributes_str);
}

void test_calculate_dbsync_difference_key_mtime_change(void **state) {
    key_difference_t *data = (key_difference_t *) *state;
    const char* old_attributes_str = "{\"mtime\":98765432}";
    registry_t configuration = { "HKEY_USERS\\Some", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL };
    cJSON *old_data = data->old_data;
    cJSON *changed_attributes = data->changed_attributes;
    cJSON *old_attributes = data->old_attributes;

    cJSON_AddNumberToObject(old_data, "mtime", 98765432);

    fim_registry_key registry_data = DEFAULT_REGISTRY_KEY;
    fim_calculate_dbsync_difference_key(&registry_data, &configuration, old_data, changed_attributes, old_attributes);
    assert_string_equal(cJSON_PrintUnformatted(changed_attributes), "[\"registry.mtime\"]");
    assert_string_equal(cJSON_PrintUnformatted(old_attributes), old_attributes_str);
}

void test_calculate_dbsync_difference_value_size_change(void **state) {
    key_difference_t *data = (key_difference_t *) *state;
    const char *old_attributes_str = "{\"size\":98765432}";
    registry_t configuration = { "HKEY_USERS\\Some", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL };
    cJSON *old_data = data->old_data;
    cJSON *changed_attributes = data->changed_attributes;
    cJSON *old_attributes = data->old_attributes;

    cJSON_AddNumberToObject(old_data, "size", 98765432);

    fim_registry_value_data registry_data = DEFAULT_REGISTRY_VALUE;

    fim_calculate_dbsync_difference_value(&registry_data, &configuration, old_data, changed_attributes, old_attributes);
    assert_string_equal(cJSON_PrintUnformatted(changed_attributes), "[\"registry.size\"]");
    assert_string_equal(cJSON_PrintUnformatted(old_attributes), old_attributes_str);

}

void test_calculate_dbsync_difference_value_type_change(void **state) {
    key_difference_t *data = (key_difference_t *) *state;
    const char *old_attributes_str = "{\"data\":{\"type\":\"REG_EXPAND_SZ\"}}";
    registry_t configuration = { "HKEY_USERS\\Some", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL };
    cJSON *old_data = data->old_data;
    cJSON *changed_attributes = data->changed_attributes;
    cJSON *old_attributes = data->old_attributes;

    cJSON_AddNumberToObject(old_data, "type", 2);
    fim_registry_value_data registry_data = DEFAULT_REGISTRY_VALUE;

    fim_calculate_dbsync_difference_value(&registry_data, &configuration, old_data, changed_attributes, old_attributes);
    assert_string_equal(cJSON_PrintUnformatted(changed_attributes), "[\"registry.data.type\"]");
    assert_string_equal(cJSON_PrintUnformatted(old_attributes), old_attributes_str);
}

void test_calculate_dbsync_difference_value_md5_change(void **state) {
    key_difference_t *data = (key_difference_t *) *state;
    const char *old_attributes_str = "{\"data\":{\"hash\":{\"md5\":\"FEDCBA0987654321FEDCBA0987654321\"}}}";
    registry_t configuration = { "HKEY_USERS\\Some", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL };
    cJSON *old_data = data->old_data;
    cJSON *changed_attributes = data->changed_attributes;
    cJSON *old_attributes = data->old_attributes;

    cJSON_AddStringToObject(old_data, "hash_md5", "FEDCBA0987654321FEDCBA0987654321");

    fim_registry_value_data registry_data = DEFAULT_REGISTRY_VALUE;

    fim_calculate_dbsync_difference_value(&registry_data, &configuration, old_data, changed_attributes, old_attributes);
    assert_string_equal(cJSON_PrintUnformatted(changed_attributes), "[\"registry.data.hash.md5\"]");
    assert_string_equal(cJSON_PrintUnformatted(old_attributes), old_attributes_str);
}

void test_calculate_dbsync_difference_value_sha1_change(void **state) {
    key_difference_t *data = (key_difference_t *) *state;
    const char *old_attributes_str = "{\"data\":{\"hash\":{\"sha1\":\"FEDCBA0987654321FEDCBA0987654321FEDCBA09\"}}}";
    registry_t configuration = { "HKEY_USERS\\Some", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL };
    cJSON *old_data = data->old_data;
    cJSON *changed_attributes = data->changed_attributes;
    cJSON *old_attributes = data->old_attributes;

    cJSON_AddStringToObject(old_data, "hash_sha1", "FEDCBA0987654321FEDCBA0987654321FEDCBA09");

    fim_registry_value_data registry_data = DEFAULT_REGISTRY_VALUE;

    fim_calculate_dbsync_difference_value(&registry_data, &configuration, old_data, changed_attributes, old_attributes);
    assert_string_equal(cJSON_PrintUnformatted(changed_attributes), "[\"registry.data.hash.sha1\"]");
    assert_string_equal(cJSON_PrintUnformatted(old_attributes), old_attributes_str);
}


void test_calculate_dbsync_difference_value_sha256_change(void **state) {
    key_difference_t *data = (key_difference_t *) *state;
    const char *old_attributes_str = "{\"data\":{\"hash\":{\"sha256\":\"FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321\"}}}";

    registry_t configuration = { "HKEY_USERS\\Some", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL };
    cJSON *old_data = data->old_data;
    cJSON *changed_attributes = data->changed_attributes;
    cJSON *old_attributes = data->old_attributes;

    cJSON_AddStringToObject(old_data, "hash_sha256", "FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321");

    fim_registry_value_data registry_data = DEFAULT_REGISTRY_VALUE;

    fim_calculate_dbsync_difference_value(&registry_data, &configuration, old_data, changed_attributes, old_attributes);
    assert_string_equal(cJSON_PrintUnformatted(changed_attributes), "[\"registry.data.hash.sha256\"]");
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
    char perm_data[OS_MAXSTR] = "{\"S-1-5-32-545\":{\"value\":\"Users\",\"allowed\":[\"read_control\",\"read_data\",\"read_ea\",\"write_ea\"]},\"S-1-5-32-544\":{\"value\":\"Administrators\",\"allowed\":[\"delete\",\"read_control\",\"write_dac\",\"write_owner\",\"read_data\",\"write_data\",\"append_data\",\"read_ea\",\"write_ea\",\"execute\"]},\"S-1-5-18\":{\"value\":\"SYSTEM\",\"allowed\":[\"delete\",\"read_control\",\"write_dac\",\"write_owner\",\"read_data\",\"write_data\",\"append_data\",\"read_ea\",\"write_ea\",\"execute\"]},\"S-1-3-0\":{\"value\":\"CREATOR OWNER\",\"allowed\":[\"delete\",\"read_control\",\"write_dac\",\"write_owner\",\"read_data\",\"write_data\",\"append_data\",\"read_ea\",\"write_ea\",\"execute\"]},\"S-1-15-2-1\":{\"value\":\"ALL APPLICATION PACKAGES\",\"allowed\":[\"read_control\",\"read_data\",\"read_ea\",\"write_ea\"]}}";

    const char* event_str = "{\"permissions\":{\"S-1-5-32-545\":{\"value\":\"Users\",\"allowed\":[\"read_control\",\"read_data\",\"read_ea\",\"write_ea\"]},\"S-1-5-32-544\":{\"value\":\"Administrators\",\"allowed\":[\"delete\",\"read_control\",\"write_dac\",\"write_owner\",\"read_data\",\"write_data\",\"append_data\",\"read_ea\",\"write_ea\",\"execute\"]},\"S-1-5-18\":{\"value\":\"SYSTEM\",\"allowed\":[\"delete\",\"read_control\",\"write_dac\",\"write_owner\",\"read_data\",\"write_data\",\"append_data\",\"read_ea\",\"write_ea\",\"execute\"]},\"S-1-3-0\":{\"value\":\"CREATOR OWNER\",\"allowed\":[\"delete\",\"read_control\",\"write_dac\",\"write_owner\",\"read_data\",\"write_data\",\"append_data\",\"read_ea\",\"write_ea\",\"execute\"]},\"S-1-15-2-1\":{\"value\":\"ALL APPLICATION PACKAGES\",\"allowed\":[\"read_control\",\"read_data\",\"read_ea\",\"write_ea\"]}},\"uid\":\"110\",\"owner\":\"user_old_name\",\"gid\":\"220\",\"group\":\"group_old_name\",\"mtime\":1100}";
    fim_registry_key registry_data = DEFAULT_REGISTRY_KEY;
    registry_t configuration = { "HKEY_USERS\\Some", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL };

    registry_data.permissions = perm_data;

    cJSON *event = fim_registry_key_attributes_json(NULL, &registry_data, &configuration);

    data->data2 = event;
    *state = data;

    assert_string_equal(event_str, cJSON_PrintUnformatted(event));
}

void test_registry_key_attributes_json_dbsync(void **state) {
    json_data_t *data = calloc(1, sizeof(json_data_t));
    cJSON *dbsync_event = cJSON_Parse("{\"permissions\":\"{\\\"S-1-5-32-545\\\":{\\\"value\\\":\\\"Users\\\",\\\"allowed\\\":[\\\"read_control\\\",\\\"read_data\\\",\\\"read_ea\\\",\\\"write_ea\\\"]},\\\"S-1-5-32-544\\\":{\\\"value\\\":\\\"Administrators\\\",\\\"allowed\\\":[\\\"delete\\\",\\\"read_control\\\",\\\"write_dac\\\",\\\"write_owner\\\",\\\"read_data\\\",\\\"write_data\\\",\\\"append_data\\\",\\\"read_ea\\\",\\\"write_ea\\\",\\\"execute\\\"]},\\\"S-1-5-18\\\":{\\\"value\\\":\\\"SYSTEM\\\",\\\"allowed\\\":[\\\"delete\\\",\\\"read_control\\\",\\\"write_dac\\\",\\\"write_owner\\\",\\\"read_data\\\",\\\"write_data\\\",\\\"append_data\\\",\\\"read_ea\\\",\\\"write_ea\\\",\\\"execute\\\"]},\\\"S-1-3-0\\\":{\\\"value\\\":\\\"CREATOR OWNER\\\",\\\"allowed\\\":[\\\"delete\\\",\\\"read_control\\\",\\\"write_dac\\\",\\\"write_owner\\\",\\\"read_data\\\",\\\"write_data\\\",\\\"append_data\\\",\\\"read_ea\\\",\\\"write_ea\\\",\\\"execute\\\"]},\\\"S-1-15-2-1\\\":{\\\"value\\\":\\\"ALL APPLICATION PACKAGES\\\",\\\"allowed\\\":[\\\"read_control\\\",\\\"read_data\\\",\\\"read_ea\\\",\\\"write_ea\\\"]}}\",\"uid\":\"110\",\"owner\":\"user_old_name\",\"gid\":\"220\",\"group_\":\"group_old_name\",\"mtime\":1100,\"checksum\":\"234567890ABCDEF1234567890ABCDEF123456789\"}");
    const char* event_str = "{\"permissions\":{\"S-1-5-32-545\":{\"value\":\"Users\",\"allowed\":[\"read_control\",\"read_data\",\"read_ea\",\"write_ea\"]},\"S-1-5-32-544\":{\"value\":\"Administrators\",\"allowed\":[\"delete\",\"read_control\",\"write_dac\",\"write_owner\",\"read_data\",\"write_data\",\"append_data\",\"read_ea\",\"write_ea\",\"execute\"]},\"S-1-5-18\":{\"value\":\"SYSTEM\",\"allowed\":[\"delete\",\"read_control\",\"write_dac\",\"write_owner\",\"read_data\",\"write_data\",\"append_data\",\"read_ea\",\"write_ea\",\"execute\"]},\"S-1-3-0\":{\"value\":\"CREATOR OWNER\",\"allowed\":[\"delete\",\"read_control\",\"write_dac\",\"write_owner\",\"read_data\",\"write_data\",\"append_data\",\"read_ea\",\"write_ea\",\"execute\"]},\"S-1-15-2-1\":{\"value\":\"ALL APPLICATION PACKAGES\",\"allowed\":[\"read_control\",\"read_data\",\"read_ea\",\"write_ea\"]}},\"uid\":\"110\",\"owner\":\"user_old_name\",\"gid\":\"220\",\"group\":\"group_old_name\",\"mtime\":1100}";
    registry_t configuration = { "HKEY_USERS\\Some", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL };

    cJSON *event = fim_registry_key_attributes_json(dbsync_event, NULL, &configuration);

    data->data1 = dbsync_event;
    data->data2 = event;
    *state = data;
    assert_string_equal(event_str, cJSON_PrintUnformatted(event));
}


void test_registry_value_attributes_json_entry(void **state) {
    json_data_t *data = calloc(1, sizeof(json_data_t));
    const char* event_str = "{\"size\":50,\"data\":{\"type\":\"REG_SZ\",\"hash\":{\"md5\":\"1234567890ABCDEF1234567890ABCDEF\",\"sha1\":\"1234567890ABCDEF1234567890ABCDEF12345678\",\"sha256\":\"1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF\"}}}";
    fim_registry_value_data registry_data = DEFAULT_REGISTRY_VALUE;
    registry_t configuration = { "HKEY_USERS\\Some", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL };

    cJSON *event = fim_registry_value_attributes_json(NULL, &registry_data, &configuration);

    data->data1 = event;
    *state = data;

    assert_string_equal(event_str, cJSON_PrintUnformatted(event));
}

void test_registry_value_attributes_json_dbsync(void **state) {
    json_data_t *data = calloc(1, sizeof(json_data_t));
    const char* event_str = "{\"size\":50,\"data\":{\"type\":\"REG_SZ\",\"hash\":{\"md5\":\"1234567890ABCDEF1234567890ABCDEF\",\"sha1\":\"1234567890ABCDEF1234567890ABCDEF12345678\",\"sha256\":\"1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF\"}}}";
    cJSON *dbsync_event = cJSON_Parse("{\"architecture\":\"[x64]\",\"checksum\":\"1234567890ABCDEF1234567890ABCDEF12345678\",\"hash_md5\":\"1234567890ABCDEF1234567890ABCDEF\",\"hash_sha1\":\"1234567890ABCDEF1234567890ABCDEF12345678\",\"hash_sha256\":\"1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF\",\"value\":\"New Value 1\",\"path\":\"HKEY_USERS\\\\Some\",\"size\":50,\"type\":1}");
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
