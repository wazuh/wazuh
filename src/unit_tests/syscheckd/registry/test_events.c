/*
 * Copyright (C) 2015-2021, Wazuh Inc.
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
#include "syscheck.h"
#include "registry/registry.h"

#define CHECK_REGISTRY_ALL                                                                             \
    CHECK_SIZE | CHECK_PERM | CHECK_OWNER | CHECK_GROUP | CHECK_MTIME | CHECK_MD5SUM | CHECK_SHA1SUM | \
    CHECK_SHA256SUM | CHECK_SEECHANGES | CHECK_TYPE

static int teardown_cjson_object(void **state) {
    cJSON *object = *state;

    cJSON_Delete(object);

    return 0;
}

static void test_fim_registry_event_null_new_data(void **state) {
    fim_entry saved;
    registry configuration;
    cJSON *ret;

    expect_string(__wrap__mwarn, formatted_msg, FIM_REGISTRY_EVENT_NULL_ENTRY);

    ret = fim_registry_event(NULL, &saved, &configuration, FIM_SCHEDULED, FIM_ADDED, NULL, NULL);

    assert_null(ret);
}

static void test_fim_registry_event_null_new_key(void **state) {
    fim_entry new;
    fim_entry saved;
    registry configuration;
    cJSON *ret;

    new.type = FIM_TYPE_REGISTRY;
    new.registry_entry.key = NULL;
    new.registry_entry.value = NULL;

    expect_string(__wrap__mwarn, formatted_msg, FIM_REGISTRY_EVENT_NULL_ENTRY_KEY);

    ret = fim_registry_event(&new, &saved, &configuration, FIM_SCHEDULED, FIM_ADDED, NULL, NULL);

    assert_null(ret);
}

static void test_fim_registry_event_invalid_new_entry_type(void **state) {
    fim_entry new;
    fim_registry_key new_key;
    fim_entry saved;
    registry configuration;
    cJSON *ret;

    new.type = FIM_TYPE_FILE;
    new.registry_entry.key = &new_key;
    new.registry_entry.value = NULL;

    saved.type = FIM_TYPE_REGISTRY;

    expect_string(__wrap__mwarn, formatted_msg, FIM_REGISTRY_EVENT_WRONG_ENTRY_TYPE);

    ret = fim_registry_event(&new, &saved, &configuration, FIM_SCHEDULED, FIM_ADDED, NULL, NULL);

    assert_null(ret);
}

static void test_fim_registry_event_invalid_new_entry_type_null_saved_entry(void **state) {
    fim_entry new;
    fim_registry_key new_key;
    registry configuration;
    cJSON *ret;

    new.type = FIM_TYPE_FILE;
    new.registry_entry.key = &new_key;
    new.registry_entry.value = NULL;

    expect_string(__wrap__mwarn, formatted_msg, FIM_REGISTRY_EVENT_WRONG_ENTRY_TYPE);

    ret = fim_registry_event(&new, NULL, &configuration, FIM_SCHEDULED, FIM_ADDED, NULL, NULL);

    assert_null(ret);
}

static void test_fim_registry_event_invalid_saved_entry_type(void **state) {
    fim_entry new;
    fim_registry_key new_key;
    fim_entry saved;
    fim_registry_key saved_key;
    registry configuration;
    cJSON *ret;

    new.type = FIM_TYPE_REGISTRY;
    new.registry_entry.key = &new_key;
    new.registry_entry.value = NULL;

    saved.type = FIM_TYPE_FILE;
    saved.registry_entry.key = &saved_key;
    saved.registry_entry.value = NULL;

    expect_string(__wrap__mwarn, formatted_msg, FIM_REGISTRY_EVENT_WRONG_SAVED_TYPE);

    ret = fim_registry_event(&new, &saved, &configuration, FIM_SCHEDULED, FIM_ADDED, NULL, NULL);

    assert_null(ret);
}

static void test_fim_registry_event_added_key_event(void **state) {
    fim_entry new;
    fim_registry_key new_key = {
        3, "HKEY_USERS\\Some\\random\\key", "windows-permission", "100", "200", "user_name", "group_name", 1000, ARCH_64BIT, 0, 1234, "1234567890ABCDEF1234567890ABCDEF12345678"
    };
    registry configuration = { "HKEY_USERS\\Some", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL, NULL };
    cJSON *ret, *data, *attributes;

    new.type = FIM_TYPE_REGISTRY;
    new.registry_entry.key = &new_key;
    new.registry_entry.value = NULL;

    ret = fim_registry_event(&new, NULL, &configuration, FIM_SCHEDULED, FIM_ADDED, NULL, NULL);

    *state = ret;

    assert_non_null(ret);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(ret, "type")), "event");

    data = cJSON_GetObjectItem(ret, "data");
    assert_non_null(data);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "path")), "HKEY_USERS\\Some\\random\\key");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "mode")), "scheduled");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "type")), "added");

    attributes = cJSON_GetObjectItem(data, "attributes");
    assert_non_null(attributes);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "type")), "registry_key");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "uid")), "100");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "gid")), "200");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "user_name")), "user_name");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "group_name")), "group_name");
    assert_int_equal(cJSON_GetObjectItem(attributes, "mtime")->valueint, 1000);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "checksum")),
                        "1234567890ABCDEF1234567890ABCDEF12345678");
}

static void test_fim_registry_event_added_key_event_attributes_disabled(void **state) {
    fim_entry new;
    fim_registry_key new_key = {
        3, "HKEY_USERS\\Some\\random\\key", "windows-permission", "100", "200", "user_name", "group_name", 1000, ARCH_64BIT, 0, 1234, "1234567890ABCDEF1234567890ABCDEF12345678"
    };
    registry configuration = { "HKEY_USERS\\Some", ARCH_64BIT, 0, 320, 0, NULL, NULL };
    cJSON *ret, *data, *attributes;

    new.type = FIM_TYPE_REGISTRY;
    new.registry_entry.key = &new_key;
    new.registry_entry.value = NULL;

    ret = fim_registry_event(&new, NULL, &configuration, FIM_SCHEDULED, FIM_ADDED, NULL, NULL);

    *state = ret;

    assert_non_null(ret);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(ret, "type")), "event");

    data = cJSON_GetObjectItem(ret, "data");
    assert_non_null(data);

    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "path")), "HKEY_USERS\\Some\\random\\key");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "mode")), "scheduled");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "type")), "added");

    attributes = cJSON_GetObjectItem(data, "attributes");
    assert_non_null(attributes);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "type")), "registry_key");
    assert_null(cJSON_GetObjectItem(attributes, "uid"));
    assert_null(cJSON_GetObjectItem(attributes, "gid"));
    assert_null(cJSON_GetObjectItem(attributes, "user_name"));
    assert_null(cJSON_GetObjectItem(attributes, "group_name"));
    assert_null(cJSON_GetObjectItem(attributes, "mtime"));
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "checksum")),
                        "1234567890ABCDEF1234567890ABCDEF12345678");
}

static void test_fim_registry_event_modified_key_event(void **state) {
    fim_entry new, saved;
    fim_registry_key new_key = {
        3, "HKEY_USERS\\Some\\random\\key", "windows-permission", "100", "200", "user_name", "group_name", 1000, ARCH_64BIT, 0, 1234, "1234567890ABCDEF1234567890ABCDEF12345678"
    };
    fim_registry_key saved_key = {
        3, "HKEY_USERS\\Some\\random\\key", "windows-old-permission", "110", "220", "user_old_name", "group_old_name", 1100, ARCH_64BIT, 0, 1234, "234567890ABCDEF1234567890ABCDEF123456789"
    };
    registry configuration = { "HKEY_USERS\\Some", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL };
    cJSON *ret, *data, *attributes, *old_attributes, *it;
    char *changed_attributes[] = { "permission", "uid", "user_name", "gid", "group_name", "mtime" };
    int attributes_it = 0;

    new.type = FIM_TYPE_REGISTRY;
    new.registry_entry.key = &new_key;
    new.registry_entry.value = NULL;

    saved.type = FIM_TYPE_REGISTRY;
    saved.registry_entry.key = &saved_key;
    saved.registry_entry.value = NULL;

    ret = fim_registry_event(&new, &saved, &configuration, FIM_SCHEDULED, FIM_MODIFICATION, NULL, NULL);

    *state = ret;

    assert_non_null(ret);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(ret, "type")), "event");

    data = cJSON_GetObjectItem(ret, "data");
    assert_non_null(data);

    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "path")), "HKEY_USERS\\Some\\random\\key");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "mode")), "scheduled");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "type")), "modified");
    cJSON_ArrayForEach(it, cJSON_GetObjectItem(data, "changed_attributes")) {
        assert_string_equal(cJSON_GetStringValue(it), changed_attributes[attributes_it++]);
    }

    attributes = cJSON_GetObjectItem(data, "attributes");
    assert_non_null(attributes);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "type")), "registry_key");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "uid")), "100");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "gid")), "200");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "user_name")), "user_name");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "group_name")), "group_name");
    assert_int_equal(cJSON_GetObjectItem(attributes, "mtime")->valueint, 1000);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "checksum")),
                        "1234567890ABCDEF1234567890ABCDEF12345678");

    old_attributes = cJSON_GetObjectItem(data, "old_attributes");
    assert_non_null(old_attributes);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(old_attributes, "type")), "registry_key");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(old_attributes, "uid")), "110");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(old_attributes, "gid")), "220");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(old_attributes, "user_name")), "user_old_name");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(old_attributes, "group_name")), "group_old_name");
    assert_int_equal(cJSON_GetObjectItem(old_attributes, "mtime")->valueint, 1100);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(old_attributes, "checksum")),
                        "234567890ABCDEF1234567890ABCDEF123456789");
}

static void test_fim_registry_event_modified_key_event_attributes_disabled(void **state) {
    fim_entry new, saved;
    fim_registry_key new_key = {
        3, "HKEY_USERS\\Some\\random\\key", "windows-permission", "100", "200", "user_name", "group_name", 1000, ARCH_64BIT, 0, 1234, "1234567890ABCDEF1234567890ABCDEF12345678"
    };
    fim_registry_key saved_key = {
        3, "HKEY_USERS\\Some\\random\\key", "windows-old-permission", "110", "220", "user_old_name", "group_old_name", 1100, ARCH_64BIT, 0, 1234, "234567890ABCDEF1234567890ABCDEF123456789"
    };
    registry configuration = { "HKEY_USERS\\Some", ARCH_64BIT, 0, 320, 0, NULL, NULL };
    cJSON *ret;

    new.type = FIM_TYPE_REGISTRY;
    new.registry_entry.key = &new_key;
    new.registry_entry.value = NULL;

    saved.type = FIM_TYPE_REGISTRY;
    saved.registry_entry.key = &saved_key;
    saved.registry_entry.value = NULL;

    ret = fim_registry_event(&new, &saved, &configuration, FIM_SCHEDULED, FIM_MODIFICATION, NULL, NULL);

    assert_null(ret);
}

static void test_fim_registry_event_deleted_key_event(void **state) {
    fim_entry new;
    fim_registry_key new_key = {
        3, "HKEY_USERS\\Some\\random\\key", "windows-permission", "100", "200", "user_name", "group_name", 1000, ARCH_64BIT, 0, 1234, "1234567890ABCDEF1234567890ABCDEF12345678"
    };
    registry configuration = { "HKEY_USERS\\Some", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL };
    cJSON *ret, *data, *attributes;

    new.type = FIM_TYPE_REGISTRY;
    new.registry_entry.key = &new_key;
    new.registry_entry.value = NULL;

    ret = fim_registry_event(&new, NULL, &configuration, FIM_SCHEDULED, FIM_DELETE, NULL, NULL);

    *state = ret;

    assert_non_null(ret);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(ret, "type")), "event");

    data = cJSON_GetObjectItem(ret, "data");
    assert_non_null(data);

    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "path")), "HKEY_USERS\\Some\\random\\key");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "mode")), "scheduled");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "type")), "deleted");

    attributes = cJSON_GetObjectItem(data, "attributes");
    assert_non_null(attributes);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "type")), "registry_key");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "uid")), "100");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "gid")), "200");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "user_name")), "user_name");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "group_name")), "group_name");
    assert_int_equal(cJSON_GetObjectItem(attributes, "mtime")->valueint, 1000);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "checksum")),
                        "1234567890ABCDEF1234567890ABCDEF12345678");
}

static void test_fim_registry_event_deleted_key_event_attributes_disabled(void **state) {
    fim_entry new;
    fim_registry_key new_key = {
        3, "HKEY_USERS\\Some\\random\\key", "windows-permission", "100", "200", "user_name", "group_name", 1000, ARCH_64BIT, 0, 1234, "1234567890ABCDEF1234567890ABCDEF12345678"
    };
    registry configuration = { "HKEY_USERS\\Some", ARCH_64BIT, 0, 320, 0, NULL, NULL };
    cJSON *ret, *data, *attributes;

    new.type = FIM_TYPE_REGISTRY;
    new.registry_entry.key = &new_key;
    new.registry_entry.value = NULL;

    ret = fim_registry_event(&new, NULL, &configuration, FIM_SCHEDULED, FIM_DELETE, NULL, NULL);

    *state = ret;

    assert_non_null(ret);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(ret, "type")), "event");

    data = cJSON_GetObjectItem(ret, "data");
    assert_non_null(data);

    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "path")), "HKEY_USERS\\Some\\random\\key");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "mode")), "scheduled");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "type")), "deleted");

    attributes = cJSON_GetObjectItem(data, "attributes");
    assert_non_null(attributes);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "type")), "registry_key");
    assert_null(cJSON_GetObjectItem(attributes, "uid"));
    assert_null(cJSON_GetObjectItem(attributes, "gid"));
    assert_null(cJSON_GetObjectItem(attributes, "user_name"));
    assert_null(cJSON_GetObjectItem(attributes, "group_name"));
    assert_null(cJSON_GetObjectItem(attributes, "mtime"));
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "checksum")),
                        "1234567890ABCDEF1234567890ABCDEF12345678");
}

static void test_fim_registry_event_added_value_event(void **state) {
    fim_entry new;
    fim_registry_key new_key = {
        3, "HKEY_USERS\\Some\\random\\key", "windows-permission", "100", "200", "user_name", "group_name", 1000, ARCH_64BIT, 0, 1234, "1234567890ABCDEF1234567890ABCDEF12345678"
    };
    fim_registry_value_data new_value = { 3,
                                          "the\\value",
                                          REG_SZ,
                                          50,
                                          "1234567890ABCDEF1234567890ABCDEF",
                                          "1234567890ABCDEF1234567890ABCDEF12345678",
                                          "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF",
                                          0,
                                          10000,
                                          "1234567890ABCDEF1234567890ABCDEF12345678",
                                          FIM_ADDED };
    registry configuration = { "HKEY_USERS\\Some", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL };
    cJSON *ret, *data, *attributes;

    new.type = FIM_TYPE_REGISTRY;
    new.registry_entry.key = &new_key;
    new.registry_entry.value = &new_value;

    ret = fim_registry_event(&new, NULL, &configuration, FIM_SCHEDULED, FIM_ADDED, NULL, NULL);

    *state = ret;

    assert_non_null(ret);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(ret, "type")), "event");

    data = cJSON_GetObjectItem(ret, "data");
    assert_non_null(data);

    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "path")),
                        "HKEY_USERS\\Some\\random\\key");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "mode")), "scheduled");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "type")), "added");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "value_name")), "the\\value");

    attributes = cJSON_GetObjectItem(data, "attributes");

    assert_non_null(attributes);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "type")), "registry_value");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "value_type")), "REG_SZ");
    assert_int_equal(cJSON_GetObjectItem(attributes, "size")->valueint, 50);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "hash_md5")),
                        "1234567890ABCDEF1234567890ABCDEF");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "hash_sha1")),
                        "1234567890ABCDEF1234567890ABCDEF12345678");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "hash_sha256")),
                        "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "checksum")),
                        "1234567890ABCDEF1234567890ABCDEF12345678");
}

static void test_fim_registry_event_added_value_event_attributes_disabled(void **state) {
    fim_entry new;
    fim_registry_key new_key = {
        3, "HKEY_USERS\\Some\\random\\key", "windows-permission", "100", "200", "user_name", "group_name", 1000, ARCH_64BIT, 0, 1234, "1234567890ABCDEF1234567890ABCDEF12345678"
    };
    fim_registry_value_data new_value = { 3,
                                          "the\\value",
                                          REG_SZ,
                                          50,
                                          "1234567890ABCDEF1234567890ABCDEF",
                                          "1234567890ABCDEF1234567890ABCDEF12345678",
                                          "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF",
                                          0,
                                          10000,
                                          "1234567890ABCDEF1234567890ABCDEF12345678",
                                          FIM_ADDED };
    registry configuration = { "HKEY_USERS\\Some", ARCH_64BIT, 0, 320, 0, NULL, NULL };
    cJSON *ret, *data, *attributes;

    new.type = FIM_TYPE_REGISTRY;
    new.registry_entry.key = &new_key;
    new.registry_entry.value = &new_value;

    ret = fim_registry_event(&new, NULL, &configuration, FIM_SCHEDULED, FIM_ADDED, NULL, NULL);

    *state = ret;

    assert_non_null(ret);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(ret, "type")), "event");

    data = cJSON_GetObjectItem(ret, "data");
    assert_non_null(data);

    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "path")),
                        "HKEY_USERS\\Some\\random\\key");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "mode")), "scheduled");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "type")), "added");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "value_name")), "the\\value");

    attributes = cJSON_GetObjectItem(data, "attributes");
    assert_non_null(attributes);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "type")), "registry_value");
    assert_null(cJSON_GetObjectItem(attributes, "value_type"));
    assert_null(cJSON_GetObjectItem(attributes, "size"));
    assert_null(cJSON_GetObjectItem(attributes, "hash_md5"));
    assert_null(cJSON_GetObjectItem(attributes, "hash_sha1"));
    assert_null(cJSON_GetObjectItem(attributes, "hash_sha256"));
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "checksum")),
                        "1234567890ABCDEF1234567890ABCDEF12345678");
}

static void test_fim_registry_event_modified_value_event(void **state) {
    fim_entry new, saved;
    fim_registry_key new_key = {
        3, "HKEY_USERS\\Some\\random\\key", "windows-permission", "100", "200", "user_name", "group_name", 1000, ARCH_64BIT, 0, 1234, "1234567890ABCDEF1234567890ABCDEF12345678"
    };
    fim_registry_value_data new_value = { 3,
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
    fim_registry_key saved_key = {
        3, "HKEY_USERS\\Some\\random\\key", "windows-permission", "100", "200", "user_name", "group_name", 1000, ARCH_64BIT, 0, 1234, "1234567890ABCDEF1234567890ABCDEF12345678"
    };
    fim_registry_value_data saved_value = { 3,
                                          "the\\value",
                                          REG_SZ,
                                          500,
                                          "234567890ABCDEF1234567890ABCDEF1",
                                          "234567890ABCDEF1234567890ABCDEF123456789",
                                          "234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1",
                                          0,
                                          11000,
                                          "234567890ABCDEF1234567890ABCDEF123456789",
                                          FIM_MODIFICATION };
    registry configuration = { "HKEY_USERS\\Some", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL };
    cJSON *ret, *data, *attributes, *old_attributes, *it;
    char *changed_attributes[] = { "size", "md5", "sha1", "sha256", "last_event", "checksum" };
    int attributes_it = 0;

    new.type = FIM_TYPE_REGISTRY;
    new.registry_entry.key = &new_key;
    new.registry_entry.value = &new_value;

    saved.type = FIM_TYPE_REGISTRY;
    saved.registry_entry.key = &saved_key;
    saved.registry_entry.value = &saved_value;

    ret = fim_registry_event(&new, &saved, &configuration, FIM_SCHEDULED, FIM_MODIFICATION, NULL, NULL);

    *state = ret;

    assert_non_null(ret);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(ret, "type")), "event");

    data = cJSON_GetObjectItem(ret, "data");
    assert_non_null(data);

    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "path")),
                        "HKEY_USERS\\Some\\random\\key");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "mode")), "scheduled");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "type")), "modified");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "value_name")), "the\\value");
    cJSON_ArrayForEach(it, cJSON_GetObjectItem(data, "changed_attributes")) {
        assert_string_equal(cJSON_GetStringValue(it), changed_attributes[attributes_it++]);
    }

    attributes = cJSON_GetObjectItem(data, "attributes");
    assert_non_null(attributes);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "type")), "registry_value");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "value_type")), "REG_SZ");
    assert_int_equal(cJSON_GetObjectItem(attributes, "size")->valueint, 50);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "hash_md5")),
                        "1234567890ABCDEF1234567890ABCDEF");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "hash_sha1")),
                        "1234567890ABCDEF1234567890ABCDEF12345678");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "hash_sha256")),
                        "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "checksum")),
                        "1234567890ABCDEF1234567890ABCDEF12345678");

    old_attributes = cJSON_GetObjectItem(data, "old_attributes");
    assert_non_null(old_attributes);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(old_attributes, "type")), "registry_value");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(old_attributes, "value_type")), "REG_SZ");
    assert_int_equal(cJSON_GetObjectItem(old_attributes, "size")->valueint, 500);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(old_attributes, "hash_md5")),
                        "234567890ABCDEF1234567890ABCDEF1");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(old_attributes, "hash_sha1")),
                        "234567890ABCDEF1234567890ABCDEF123456789");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(old_attributes, "hash_sha256")),
                        "234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(old_attributes, "checksum")),
                        "234567890ABCDEF1234567890ABCDEF123456789");
}

static void test_fim_registry_event_modified_value_event_attributes_disabled(void **state) {
    fim_entry new, saved;
    fim_registry_key new_key = {
        3, "HKEY_USERS\\Some\\random\\key", "windows-permission", "100", "200", "user_name", "group_name", 1000, ARCH_64BIT, 0, 1234, "1234567890ABCDEF1234567890ABCDEF12345678"
    };
    fim_registry_value_data new_value = { 3,
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
    fim_registry_key saved_key = {
        3, "HKEY_USERS\\Some\\random\\key", "windows-permission", "100", "200", "user_name", "group_name", 1000, ARCH_64BIT, 0, 1234, "1234567890ABCDEF1234567890ABCDEF12345678"
    };
    fim_registry_value_data saved_value = { 3,
                                          "the\\value",
                                          REG_SZ,
                                          500,
                                          "234567890ABCDEF1234567890ABCDEF1",
                                          "234567890ABCDEF1234567890ABCDEF123456789",
                                          "234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1",
                                          0,
                                          11000,
                                          "234567890ABCDEF1234567890ABCDEF123456789",
                                          FIM_MODIFICATION };
    registry configuration = { "HKEY_USERS\\Some", ARCH_64BIT, 0, 320, 0, NULL, NULL };
    cJSON *ret;

    new.type = FIM_TYPE_REGISTRY;
    new.registry_entry.key = &new_key;
    new.registry_entry.value = &new_value;

    saved.type = FIM_TYPE_REGISTRY;
    saved.registry_entry.key = &saved_key;
    saved.registry_entry.value = &saved_value;

    ret = fim_registry_event(&new, &saved, &configuration, FIM_SCHEDULED, FIM_MODIFICATION, NULL, NULL);

    *state = ret;

    assert_null(ret);
}

static void test_fim_registry_event_deleted_value_event(void **state) {
    fim_entry new;
    fim_registry_key new_key = {
        3, "HKEY_USERS\\Some\\random\\key", "windows-permission", "100", "200", "user_name", "group_name", 1000, ARCH_64BIT, 0, 1234, "1234567890ABCDEF1234567890ABCDEF12345678"
    };
    fim_registry_value_data new_value = { 3,
                                          "the\\value",
                                          REG_SZ,
                                          50,
                                          "1234567890ABCDEF1234567890ABCDEF",
                                          "1234567890ABCDEF1234567890ABCDEF12345678",
                                          "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF",
                                          0,
                                          10000,
                                          "1234567890ABCDEF1234567890ABCDEF12345678",
                                          FIM_ADDED };
    registry configuration = { "HKEY_USERS\\Some", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL };
    cJSON *ret, *data, *attributes;

    new.type = FIM_TYPE_REGISTRY;
    new.registry_entry.key = &new_key;
    new.registry_entry.value = &new_value;

    ret = fim_registry_event(&new, NULL, &configuration, FIM_SCHEDULED, FIM_DELETE, NULL, NULL);

    *state = ret;

    assert_non_null(ret);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(ret, "type")), "event");

    data = cJSON_GetObjectItem(ret, "data");
    assert_non_null(data);

    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "path")),
                        "HKEY_USERS\\Some\\random\\key");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "mode")), "scheduled");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "type")), "deleted");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "value_name")), "the\\value");

    attributes = cJSON_GetObjectItem(data, "attributes");
    assert_non_null(attributes);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "type")), "registry_value");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "value_type")), "REG_SZ");
    assert_int_equal(cJSON_GetObjectItem(attributes, "size")->valueint, 50);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "hash_md5")),
                        "1234567890ABCDEF1234567890ABCDEF");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "hash_sha1")),
                        "1234567890ABCDEF1234567890ABCDEF12345678");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "hash_sha256")),
                        "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "checksum")),
                        "1234567890ABCDEF1234567890ABCDEF12345678");
}

static void test_fim_registry_event_deleted_value_event_attributes_disabled(void **state) {
    fim_entry new;
    fim_registry_key new_key = {
        3, "HKEY_USERS\\Some\\random\\key", "windows-permission", "100", "200", "user_name", "group_name", 1000, ARCH_64BIT, 0, 1234, "1234567890ABCDEF1234567890ABCDEF12345678"
    };
    fim_registry_value_data new_value = { 3,
                                          "the\\value",
                                          REG_SZ,
                                          50,
                                          "1234567890ABCDEF1234567890ABCDEF",
                                          "1234567890ABCDEF1234567890ABCDEF12345678",
                                          "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF",
                                          0,
                                          10000,
                                          "1234567890ABCDEF1234567890ABCDEF12345678",
                                          FIM_DELETE };
    registry configuration = { "HKEY_USERS\\Some", ARCH_64BIT, 0, 320, 0, NULL, NULL };
    cJSON *ret, *data, *attributes;

    new.type = FIM_TYPE_REGISTRY;
    new.registry_entry.key = &new_key;
    new.registry_entry.value = &new_value;

    ret = fim_registry_event(&new, NULL, &configuration, FIM_SCHEDULED, FIM_DELETE, NULL, NULL);

    *state = ret;

    assert_non_null(ret);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(ret, "type")), "event");

    data = cJSON_GetObjectItem(ret, "data");
    assert_non_null(data);

    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "path")),
                        "HKEY_USERS\\Some\\random\\key");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "mode")), "scheduled");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "type")), "deleted");
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(data, "value_name")), "the\\value");

    attributes = cJSON_GetObjectItem(data, "attributes");
    assert_non_null(attributes);
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "type")), "registry_value");
    assert_null(cJSON_GetObjectItem(attributes, "value_type"));
    assert_null(cJSON_GetObjectItem(attributes, "size"));
    assert_null(cJSON_GetObjectItem(attributes, "hash_md5"));
    assert_null(cJSON_GetObjectItem(attributes, "hash_sha1"));
    assert_null(cJSON_GetObjectItem(attributes, "hash_sha256"));
    assert_string_equal(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "checksum")),
                        "1234567890ABCDEF1234567890ABCDEF12345678");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_fim_registry_event_null_new_data),
        cmocka_unit_test(test_fim_registry_event_null_new_key),
        cmocka_unit_test(test_fim_registry_event_invalid_new_entry_type),
        cmocka_unit_test(test_fim_registry_event_invalid_new_entry_type_null_saved_entry),
        cmocka_unit_test(test_fim_registry_event_invalid_saved_entry_type),
        cmocka_unit_test_teardown(test_fim_registry_event_added_key_event, teardown_cjson_object),
        cmocka_unit_test_teardown(test_fim_registry_event_added_key_event_attributes_disabled, teardown_cjson_object),
        cmocka_unit_test_teardown(test_fim_registry_event_modified_key_event, teardown_cjson_object),
        cmocka_unit_test(test_fim_registry_event_modified_key_event_attributes_disabled),
        cmocka_unit_test_teardown(test_fim_registry_event_deleted_key_event, teardown_cjson_object),
        cmocka_unit_test_teardown(test_fim_registry_event_deleted_key_event_attributes_disabled, teardown_cjson_object),
        cmocka_unit_test_teardown(test_fim_registry_event_added_value_event, teardown_cjson_object),
        cmocka_unit_test_teardown(test_fim_registry_event_added_value_event_attributes_disabled, teardown_cjson_object),
        cmocka_unit_test_teardown(test_fim_registry_event_modified_value_event, teardown_cjson_object),
        cmocka_unit_test(test_fim_registry_event_modified_value_event_attributes_disabled),
        cmocka_unit_test_teardown(test_fim_registry_event_deleted_value_event, teardown_cjson_object),
        cmocka_unit_test_teardown(test_fim_registry_event_deleted_value_event_attributes_disabled, teardown_cjson_object),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
