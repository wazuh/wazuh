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
        cmocka_unit_test_teardown(test_fim_registry_compare_key_attrs,teardown_cjson_object),
        cmocka_unit_test_teardown(test_fim_registry_compare_value_attrs,teardown_cjson_object),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
