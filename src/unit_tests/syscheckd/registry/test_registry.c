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
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include "syscheck.h"
#include "registry/registry.h"

#include "../../wrappers/common.h"
#include "../../wrappers/windows/sddl_wrappers.h"
#include "../../wrappers/windows/aclapi_wrappers.h"
#include "../../wrappers/windows/winreg_wrappers.h"
#include "../../wrappers/windows/winbase_wrappers.h"
#include "../../wrappers/windows/securitybaseapi_wrappers.h"
#include "../../wrappers/wazuh/syscheckd/fim_db_wrappers.h"
#include "../../wrappers/wazuh/shared/syscheck_op_wrappers.h"
#include "../../wrappers/wazuh/syscheckd/fim_diff_changes_wrappers.h"
#include "../../wrappers/wazuh/shared/utf8_winapi_wrapper_wrappers.h"
#include "../../wrappers/wazuh/shared_modules/schema_validator_wrappers.h"
#include "../../wrappers/wazuh/shared_modules/agent_sync_protocol_wrappers.h"

#include "test_fim.h"

#define CHECK_REGISTRY_ALL                                                                             \
    CHECK_SIZE | CHECK_PERM | CHECK_OWNER | CHECK_GROUP | CHECK_MTIME | CHECK_MD5SUM | CHECK_SHA1SUM | \
    CHECK_SHA256SUM | CHECK_SEECHANGES | CHECK_TYPE

char inv_hKey[50];

static registry_t default_config[] = {
    { "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL, NULL },
    { "HKEY_LOCAL_MACHINE\\Software\\RecursionLevel0", ARCH_64BIT, CHECK_REGISTRY_ALL, 0, 0, NULL, NULL, NULL },
    { "HKEY_LOCAL_MACHINE\\Software\\Ignore", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL, NULL },
    { inv_hKey, ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL, NULL },
    { "HKEY_LOCAL_MACHINE\\Software\\FailToInsert", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL, NULL },
    { NULL, 0, 0, 320, 0, NULL, NULL, NULL }
};

static registry_t one_entry_config[] = {
    { "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL, NULL },
    { NULL, 0, 0, 320, 0, NULL, NULL, NULL }
};

static registry_ignore default_ignore[] = { { "HKEY_LOCAL_MACHINE\\Software\\Ignore", ARCH_32BIT},
                                            { "HKEY_LOCAL_MACHINE\\Software\\Ignore", ARCH_64BIT},
                                            { NULL, 0} };

static char *default_ignore_regex_patterns[] = { "IgnoreRegex", "IgnoreRegex", NULL };

static registry_ignore_regex default_ignore_regex[] = { { NULL, ARCH_32BIT }, { NULL, ARCH_64BIT }, { NULL, 0 } };

typedef struct tmp_file_entry_s {
    fim_tmp_file *file;
    fim_entry *entry;
} tmp_file_entry_t;

void registry_key_transaction_callback(ReturnTypeCallback resultType, const cJSON* result_json, void* user_data);
void registry_value_transaction_callback(ReturnTypeCallback resultType, const cJSON* result_json, void* user_data);
int fim_set_root_key(HKEY *root_key_handle, const char *full_key, const char **sub_key);
registry_t *fim_registry_configuration(const char *key, int architecture);
int fim_registry_validate_recursion_level(const char *key_path, const registry_t *configuration);
int fim_registry_validate_ignore(const char *entry, const registry_t *configuration, int key);
void fim_registry_free_entry(fim_entry *entry);
void fim_registry_free_key(fim_registry_key *key);
void fim_registry_free_value_data(fim_registry_value_data *data);
fim_registry_key *fim_registry_get_key_data(HKEY key_handle, const char *path, const registry_t *configuration);
void fim_registry_calculate_hashes(fim_entry *entry, registry_t *configuration, BYTE *data_buffer);
void expect_SendMSG_call(const char *message_expected, const char *locmsg_expected, char loc_expected, int ret){
    expect_string(__wrap_SendMSG, message, message_expected);
    expect_string(__wrap_SendMSG, locmsg, locmsg_expected);
    expect_value(__wrap_SendMSG, loc, loc_expected);
    will_return(__wrap_SendMSG, ret);
}

void expect_fim_registry_get_key_data_call(LPSTR usid,
                                           LPSTR gsid,
                                           char *uname,
                                           char *gname,
                                           const char *permissions,
                                           FILETIME last_write_time) {
    expect_GetSecurityInfo_call((PSID) "userid", NULL, ERROR_SUCCESS);
    expect_ConvertSidToStringSid_call(usid, 1);
    expect_utf8_LookupAccountSid_call((PSID)uname, "domain", 1);

    expect_GetSecurityInfo_call(NULL, (PSID) "groupid", ERROR_SUCCESS);
    expect_ConvertSidToStringSid_call(gsid, 1);
    expect_utf8_LookupAccountSid_call((PSID)gname, "domain", 1);

    expect_get_registry_permissions(create_win_permissions_object(), ERROR_SUCCESS);

    expect_any(__wrap_decode_win_acl_json, perms);

    expect_RegQueryInfoKeyA_call(&last_write_time, ERROR_SUCCESS);
}

fim_registry_key *create_reg_key(const char *path, int architecture, const char *permissions, const char *uid, const char *gid, const char *owner,
                                 const char *group) {
    fim_registry_key *ret;

    os_calloc(1, sizeof(fim_registry_key), ret);

    os_strdup(path, ret->path);
    ret->architecture = architecture;
    os_strdup(permissions, ret->permissions);
    os_strdup(uid, ret->uid);
    os_strdup(gid, ret->gid);
    os_strdup(owner, ret->owner);
    os_strdup(group, ret->group);

    return ret;
}

fim_registry_value_data *create_reg_value_data(char *value, unsigned int type, unsigned int size) {
    fim_registry_value_data *ret;

    os_calloc(1, sizeof(fim_registry_value_data), ret);

    os_strdup(value, ret->value);
    ret->type = type;
    ret->size = size;

    return ret;
}

int delete_tables(){
    char *err_msg = NULL;
    // DELETE TABLES
    sqlite3_exec(syscheck.database->db, "DELETE FROM registry_data;", NULL, NULL, &err_msg);
    if (err_msg) {
        fail_msg("%s", err_msg);
        sqlite3_free(err_msg);

        return -1;
    }
    sqlite3_exec(syscheck.database->db, "DELETE FROM registry_key;", NULL, NULL, &err_msg);
    if (err_msg) {
        fail_msg("%s", err_msg);
        sqlite3_free(err_msg);

        return -1;
    }
    return 0;
}

static int setup_group(void **state) {
    int i;
    time_mock_value = 9999999;
    strcpy(inv_hKey, "HKEY_LOCAL_MACHINE_Invalid_key\\Software\\Ignore");

    syscheck.registry = default_config;
    syscheck.key_ignore = default_ignore;
    syscheck.enable_synchronization = 1;  // Enable synchronization for tests

    // Initialize sync limits (0 = no limit)
    syscheck.file_limit = 0;
    syscheck.registry_key_limit = 0;
    syscheck.registry_value_limit = 0;

    for (i = 0; default_ignore_regex_patterns[i]; i++) {
        default_ignore_regex[i].regex = calloc(1, sizeof(OSMatch));

        if (default_ignore_regex[i].regex == NULL) {
            return -1;
        }

        if (!OSMatch_Compile(default_ignore_regex_patterns[i], default_ignore_regex[i].regex, 0)) {
            return -1;
        }
    }

    syscheck.key_ignore_regex = default_ignore_regex;

    return 0;
}

static int teardown_group(void **state) {
    int i;

    syscheck.registry = NULL;
    syscheck.key_ignore = NULL;
    syscheck.value_ignore = NULL;

    for (i = 0; syscheck.key_ignore_regex[i].regex; i++) {
        OSMatch_FreePattern(syscheck.key_ignore_regex[i].regex);
    }
    syscheck.key_ignore_regex = NULL;

    return 0;
}

static int setup_test_hashes(void **state) {
    syscheck.registry = default_config;

    fim_entry *entry;
    os_calloc(1, sizeof(fim_entry), entry);

    fim_registry_key *key;
    os_calloc(1, sizeof(fim_registry_key), key);
    os_strdup("HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile", key->path);
    os_strdup("sid (allowed): delete|write_dac|write_data|append_data|write_attributes", key->permissions);
    os_strdup("100", key->uid);
    os_strdup("200", key->gid);
    os_strdup("username", key->owner);
    os_strdup("groupname", key->group);
    key->architecture = 1;

    fim_registry_value_data *value;
    os_calloc(1, sizeof(fim_registry_value_data), value);
    os_strdup("valuename", value->value);
    strcpy(value->hash_md5, "1234567890ABCDEF1234567890ABCDEF");
    strcpy(value->hash_sha1, "1234567890ABCDEF1234567890ABCDEF12345678");
    strcpy(value->hash_sha256, "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF");
    strcpy(value->checksum, "1234567890ABCDEF1234567890ABCDEF12345678");

    entry->type = FIM_TYPE_REGISTRY;
    entry->registry_entry.key = key;
    entry->registry_entry.value = value;

    *state = entry;
    return 0;
}

static int teardown_test_hashes(void **state) {
    fim_entry *entry = *state;

    if (entry){
        fim_registry_free_key(entry->registry_entry.key);
        fim_registry_free_value_data(entry->registry_entry.value);
        free(entry);
    }

    return 0;
}

// TESTS

static void test_fim_set_root_key_null_root_key(void **state) {
    int ret;
    char *full_key = NULL;
    const char *sub_key;

    ret = fim_set_root_key(NULL, full_key, &sub_key);

    assert_int_equal(ret, -1);
}

static void test_fim_set_root_key_null_full_key(void **state) {
    int ret;
    HKEY root_key;
    const char *sub_key;

    ret = fim_set_root_key(&root_key, NULL, &sub_key);

    assert_int_equal(ret, -1);
}

static void test_fim_set_root_key_null_sub_key(void **state) {
    int ret;
    HKEY root_key;
    char *full_key = NULL;

    ret = fim_set_root_key(&root_key, full_key, NULL);

    assert_int_equal(ret, -1);
}

static void test_fim_set_root_key_invalid_key(void **state) {
    int ret;
    HKEY root_key;
    char *full_key = "This wont match to any root key";
    const char *sub_key;

    ret = fim_set_root_key(&root_key, full_key, &sub_key);

    assert_int_equal(ret, -1);
    assert_null(root_key);
}

static void test_fim_set_root_key_invalid_root_key(void **state) {
    int ret;
    HKEY root_key;
    char *full_key = "HKEY_LOCAL_MACHINE_This_is_almost_valid\\but\\not\\quite\\valid";
    const char *sub_key;

    ret = fim_set_root_key(&root_key, full_key, &sub_key);

    assert_int_equal(ret, -1);
    assert_null(root_key);
}

static void test_fim_set_root_key_valid_HKEY_LOCAL_MACHINE_key(void **state) {
    int ret;
    HKEY root_key;
    char *full_key = "HKEY_LOCAL_MACHINE\\This\\is_a_valid\\key";
    const char *sub_key;

    ret = fim_set_root_key(&root_key, full_key, &sub_key);

    assert_int_equal(ret, 0);
    assert_ptr_equal(root_key, HKEY_LOCAL_MACHINE);
    assert_ptr_equal(sub_key, full_key + 19);
}

static void test_fim_set_root_key_valid_HKEY_CLASSES_ROOT_key(void **state) {
    int ret;
    HKEY root_key;
    char *full_key = "HKEY_CLASSES_ROOT\\This\\is_a_valid\\key";
    const char *sub_key;

    ret = fim_set_root_key(&root_key, full_key, &sub_key);

    assert_int_equal(ret, 0);
    assert_ptr_equal(root_key, HKEY_CLASSES_ROOT);
    assert_ptr_equal(sub_key, full_key + 18);
}

static void test_fim_set_root_key_valid_HKEY_CURRENT_CONFIG_key(void **state) {
    int ret;
    HKEY root_key;
    char *full_key = "HKEY_CURRENT_CONFIG\\This\\is_a_valid\\key";
    const char *sub_key;

    ret = fim_set_root_key(&root_key, full_key, &sub_key);

    assert_int_equal(ret, 0);
    assert_ptr_equal(root_key, HKEY_CURRENT_CONFIG);
    assert_ptr_equal(sub_key, full_key + 20);
}

static void test_fim_set_root_key_valid_HKEY_USERS_key(void **state) {
    int ret;
    HKEY root_key;
    char *full_key = "HKEY_USERS\\This\\is_a_valid\\key";
    const char *sub_key;

    ret = fim_set_root_key(&root_key, full_key, &sub_key);

    assert_int_equal(ret, 0);
    assert_ptr_equal(root_key, HKEY_USERS);
    assert_ptr_equal(sub_key, full_key + 11);
}

static void test_fim_registry_configuration_registry_found(void **state) {
    registry_t *configuration;

    configuration = fim_registry_configuration("HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile\\something", ARCH_64BIT);
    assert_non_null(configuration);
    assert_string_equal(configuration->entry, "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile");
    assert_int_equal(configuration->arch, ARCH_64BIT);
}

static void test_fim_registry_configuration_registry_not_found_arch_does_not_match(void **state) {
    registry_t *configuration;

    expect_any_always(__wrap__mdebug2, formatted_msg);

    configuration = fim_registry_configuration("HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile\\something", ARCH_32BIT);
    assert_null(configuration);
}

static void test_fim_registry_configuration_registry_not_found_path_does_not_match(void **state) {
    registry_t *configuration;

    expect_any_always(__wrap__mdebug2, formatted_msg);

    configuration = fim_registry_configuration("HKEY_LOCAL_MACHINE\\Software\\Classes\\something", ARCH_64BIT);
    assert_null(configuration);
}

static void test_fim_registry_configuration_null_key(void **state) {
    registry_t *configuration;

    expect_any_always(__wrap__mdebug2, formatted_msg);

    configuration = fim_registry_configuration(NULL, ARCH_64BIT);
    assert_null(configuration);
}

static void test_fim_registry_validate_recursion_level_null_configuration(void **state) {
    char *path = "HKEY_LOCAL_MACHINE\\Software\\Classes\\something";
    int ret;

    ret = fim_registry_validate_recursion_level(path, NULL);

    assert_int_equal(ret, -1);
}

static void test_fim_registry_validate_recursion_level_null_entry_path(void **state) {
    registry_t *configuration = &syscheck.registry[0];
    int ret;

    ret = fim_registry_validate_recursion_level(NULL, configuration);

    assert_int_equal(ret, -1);
}

static void test_fim_registry_validate_recursion_level_valid_entry_path(void **state) {
    char *path = "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile\\Some\\valid\\path";
    registry_t *configuration = &syscheck.registry[0];
    int ret;

    ret = fim_registry_validate_recursion_level(path, configuration);

    assert_int_equal(ret, 0);
}

static void test_fim_registry_validate_recursion_level_invalid_recursion_level(void **state) {
    char *path = "HKEY_LOCAL_MACHINE\\Software\\RecursionLevel0\\This\\must\\fail";
    registry_t *configuration = &syscheck.registry[1];
    int ret;
    expect_string(__wrap__mdebug2, formatted_msg,
                  "(6217): Maximum level of recursion reached. Depth:3 recursion_level:0 "
                  "'HKEY_LOCAL_MACHINE\\Software\\RecursionLevel0\\This\\must\\fail'");

    ret = fim_registry_validate_recursion_level(path, configuration);

    assert_int_equal(ret, -1);
}

static void test_fim_registry_validate_ignore_null_configuration(void **state) {
    char *path = "HKEY_LOCAL_MACHINE\\Software\\Classes\\something";
    int ret;

    ret = fim_registry_validate_ignore(path, NULL, 1);

    assert_int_equal(ret, -1);
}

static void test_fim_registry_validate_ignore_null_entry_path(void **state) {
    registry_t *configuration = &syscheck.registry[0];
    int ret;

    ret = fim_registry_validate_ignore(NULL, configuration, 1);

    assert_int_equal(ret, -1);
}

static void test_fim_registry_validate_ignore_valid_entry_path(void **state) {
    char *path = "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile\\Some\\valid\\path";
    registry_t *configuration = &syscheck.registry[0];
    int ret;

    ret = fim_registry_validate_ignore(path, configuration, 1);

    assert_int_equal(ret, 0);
}

static void test_fim_registry_validate_ignore_ignore_entry(void **state) {
    char *path = "HKEY_LOCAL_MACHINE\\Software\\Ignore";
    registry_t *configuration = &syscheck.registry[2];
    int ret;

    expect_string(__wrap__mdebug2, formatted_msg,
                  "(6260): Ignoring 'registry' '[x64] HKEY_LOCAL_MACHINE\\Software\\Ignore' due to "
                  "'HKEY_LOCAL_MACHINE\\Software\\Ignore'");

    ret = fim_registry_validate_ignore(path, configuration, 1);

    assert_int_equal(ret, -1);
}

static void test_fim_registry_validate_ignore_regex_ignore_entry(void **state) {
    char *path = "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile\\IgnoreRegex\\This\\must\\fail";
    registry_t *configuration = &syscheck.registry[0];
    int ret;

    expect_string(__wrap__mdebug2, formatted_msg,
                  "(6259): Ignoring 'registry' '[x64] "
                  "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile\\IgnoreRegex\\This\\must\\fail' due to sregex "
                  "'IgnoreRegex'");

    ret = fim_registry_validate_ignore(path, configuration, 1);

    assert_int_equal(ret, -1);
}

static void test_fim_registry_get_key_data_check_owner(void **state) {
    char *path = "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile";
    syscheck.registry = one_entry_config;
    registry_t *configuration = &syscheck.registry[0];
    configuration->opts = CHECK_OWNER;
    HKEY key_handle = HKEY_LOCAL_MACHINE;
    fim_registry_key *ret_key;

    expect_GetSecurityInfo_call((PSID)"userid", NULL, ERROR_SUCCESS);
    expect_ConvertSidToStringSid_call((LPSTR)"userid", 1);
    expect_utf8_LookupAccountSid_call((PSID)"username", "domain", 1);

    ret_key = fim_registry_get_key_data(key_handle, path, configuration);

    assert_string_equal(ret_key->uid, "userid");
    assert_string_equal(ret_key->owner, "username");
    assert_null(ret_key->gid);
    assert_null(ret_key->group);
    assert_null(ret_key->permissions);
    assert_null(ret_key->mtime);
}

static void test_fim_registry_get_key_data_check_group(void **state) {
    char *path = "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile";
    syscheck.registry = one_entry_config;
    registry_t *configuration = &syscheck.registry[0];
    configuration->opts = CHECK_GROUP;
    HKEY key_handle = HKEY_LOCAL_MACHINE;
    fim_registry_key *ret_key;

    expect_GetSecurityInfo_call((PSID)"groupid", NULL, ERROR_SUCCESS);
    expect_ConvertSidToStringSid_call((LPSTR)"groupid", 1);
    expect_utf8_LookupAccountSid_call((PSID)"groupname", "domain", 1);

    ret_key = fim_registry_get_key_data(key_handle, path, configuration);

    assert_null(ret_key->uid);
    assert_null(ret_key->owner);
    assert_string_equal(ret_key->gid, "groupid");
    assert_string_equal(ret_key->group, "groupname");
    assert_null(ret_key->permissions);
    assert_null(ret_key->mtime);
}

static void test_fim_registry_get_key_data_check_perm(void **state) {
    char *path = "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile";
    syscheck.registry = one_entry_config;
    registry_t *configuration = &syscheck.registry[0];
    configuration->opts = CHECK_PERM;
    HKEY key_handle = HKEY_LOCAL_MACHINE;
    fim_registry_key *ret_key;
    cJSON *permissions = create_win_permissions_object();

    expect_get_registry_permissions(permissions, ERROR_SUCCESS);

    expect_string(__wrap_decode_win_acl_json, perms, permissions);

    ret_key = fim_registry_get_key_data(key_handle, path, configuration);

    assert_null(ret_key->uid);
    assert_null(ret_key->owner);
    assert_null(ret_key->gid);
    assert_null(ret_key->group);
    assert_non_null(ret_key->permissions);
    assert_non_null(ret_key->perm_json);
    assert_null(ret_key->mtime);
}

static void test_fim_registry_get_key_data_check_mtime(void **state) {
    char *path = "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile";
    syscheck.registry = one_entry_config;
    registry_t *configuration = &syscheck.registry[0];
    configuration->opts = CHECK_MTIME;
    HKEY key_handle = HKEY_LOCAL_MACHINE;
    fim_registry_key *ret_key;
    FILETIME last_write_time = { 0, 1000 };

    expect_RegQueryInfoKeyA_call(&last_write_time, ERROR_SUCCESS);

    ret_key = fim_registry_get_key_data(key_handle, path, configuration);

    assert_null(ret_key->uid);
    assert_null(ret_key->owner);
    assert_null(ret_key->gid);
    assert_null(ret_key->group);
    assert_null(ret_key->permissions);
    assert_int_equal(ret_key->mtime, 1240857784);
}

static void test_fim_registry_calculate_hashes_CHECK_MD5SUM(void **state) {
    fim_entry *entry = *state;

    syscheck.registry = one_entry_config;
    registry_t *configuration = &syscheck.registry[0];
    configuration->opts = CHECK_MD5SUM;
    WCHAR data_buffer[] = L"value_data";
    entry->registry_entry.value->type = REG_EXPAND_SZ;

    fim_registry_calculate_hashes(entry, configuration, (BYTE *)data_buffer);

    assert_string_equal(entry->registry_entry.value->hash_md5, "51718cc02664f7b131b76f8b53918927");
    assert_string_equal(entry->registry_entry.value->hash_sha1, "");
    assert_string_equal(entry->registry_entry.value->hash_sha256, "");
    assert_string_equal(entry->registry_entry.value->checksum, "1234567890ABCDEF1234567890ABCDEF12345678");
}

static void test_fim_registry_calculate_hashes_CHECK_SHA1SUM(void **state) {
    fim_entry *entry = *state;

    syscheck.registry = one_entry_config;
    registry_t *configuration = &syscheck.registry[0];
    configuration->opts = CHECK_SHA1SUM;
    WCHAR data_buffer[] = L"value_data\0\0";
    entry->registry_entry.value->type = REG_MULTI_SZ;

    fim_registry_calculate_hashes(entry, configuration, (BYTE *)data_buffer);

    assert_string_equal(entry->registry_entry.value->hash_md5, "");
    assert_string_equal(entry->registry_entry.value->hash_sha1, "ee6cf811813827f6e18d07f0fb7e22a43337d63c");
    assert_string_equal(entry->registry_entry.value->hash_sha256, "");
    assert_string_equal(entry->registry_entry.value->checksum, "1234567890ABCDEF1234567890ABCDEF12345678");
}

static void test_fim_registry_calculate_hashes_CHECK_SHA256SUM(void **state) {
    fim_entry *entry = *state;

    syscheck.registry = one_entry_config;
    registry_t *configuration = &syscheck.registry[0];
    configuration->opts = CHECK_SHA256SUM;
    BYTE *data_buffer = (unsigned char *)"value_data";
    entry->registry_entry.value->type = REG_DWORD;

    fim_registry_calculate_hashes(entry, configuration, data_buffer);


    assert_string_equal(entry->registry_entry.value->hash_md5, "");
    assert_string_equal(entry->registry_entry.value->hash_sha1, "");
    assert_string_equal(entry->registry_entry.value->hash_sha256, "482e0d08067b0965649aba1eef95350f71f60ba9079c7096f2f4e4b018f4cc09");
    assert_string_equal(entry->registry_entry.value->checksum, "1234567890ABCDEF1234567890ABCDEF12345678");
}

static void test_fim_registry_calculate_hashes_default_type(void **state) {
    fim_entry *entry = *state;

    syscheck.registry = one_entry_config;
    registry_t *configuration = &syscheck.registry[0];
    configuration->opts = CHECK_REGISTRY_ALL;
    BYTE *data_buffer = (unsigned char *)"value_data";
    entry->registry_entry.value->type = -1;

    fim_registry_calculate_hashes(entry, configuration, data_buffer);


    assert_string_equal(entry->registry_entry.value->hash_md5, "d41d8cd98f00b204e9800998ecf8427e");
    assert_string_equal(entry->registry_entry.value->hash_sha1, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    assert_string_equal(entry->registry_entry.value->hash_sha256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert_string_equal(entry->registry_entry.value->checksum, "1234567890ABCDEF1234567890ABCDEF12345678");
}

static void test_fim_registry_calculate_hashes_no_config(void **state) {
    fim_entry *entry = *state;

    syscheck.registry = one_entry_config;
    registry_t *configuration = &syscheck.registry[0];
    configuration->opts = 0;
    BYTE *data_buffer = (unsigned char *)"value_data";
    entry->registry_entry.value->type = -1;

    fim_registry_calculate_hashes(entry, configuration, data_buffer);

    assert_string_equal(entry->registry_entry.value->hash_md5, "");
    assert_string_equal(entry->registry_entry.value->hash_sha1, "");
    assert_string_equal(entry->registry_entry.value->hash_sha256, "");
    assert_string_equal(entry->registry_entry.value->checksum, "1234567890ABCDEF1234567890ABCDEF12345678");
}

static void test_fim_registry_calculate_hashes_utf16_conversion(void **state) {
    fim_entry *entry = *state;

    syscheck.registry = one_entry_config;
    registry_t *configuration = &syscheck.registry[0];
    configuration->opts = CHECK_MD5SUM;

    WCHAR utf16_data[] = L"cmd";
    entry->registry_entry.value->type = REG_SZ;

    fim_registry_calculate_hashes(entry, configuration, (BYTE *)utf16_data);

    // Using MD5 hash of "cmd" (without null character)
    assert_string_equal(entry->registry_entry.value->hash_md5, "dfff0a7fa1a55c8c1a4966c19f6da452");
    assert_string_equal(entry->registry_entry.value->hash_sha1, "");
    assert_string_equal(entry->registry_entry.value->hash_sha256, "");
    assert_string_equal(entry->registry_entry.value->checksum, "1234567890ABCDEF1234567890ABCDEF12345678");
}

static void test_fim_registry_calculate_hashes_utf16_multi_sz(void **state) {
    fim_entry *entry = *state;

    syscheck.registry = one_entry_config;
    registry_t *configuration = &syscheck.registry[0];
    configuration->opts = CHECK_MD5SUM;

    // REG_MULTI_SZ is expected to have double null termination:
    // https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types
    WCHAR utf16_multi_data[] = L"A\0B\0\0";
    entry->registry_entry.value->type = REG_MULTI_SZ;

    fim_registry_calculate_hashes(entry, configuration, (BYTE *)utf16_multi_data);

    // Using MD5 hash of "AB" (without null characters)
    assert_string_equal(entry->registry_entry.value->hash_md5, "b86fc6b051f63d73de262d4c34e3a0a9");
    assert_string_equal(entry->registry_entry.value->hash_sha1, "");
    assert_string_equal(entry->registry_entry.value->hash_sha256, "");
    assert_string_equal(entry->registry_entry.value->checksum, "1234567890ABCDEF1234567890ABCDEF12345678");
}

static void test_fim_registry_calculate_hashes_utf16_conversion_fail_reg_sz(void **state) {
    fim_entry *entry = *state;

    syscheck.registry = one_entry_config;
    registry_t *configuration = &syscheck.registry[0];
    configuration->opts = CHECK_MD5SUM;

    WCHAR utf16_data[] = L"test";
    entry->registry_entry.value->type = REG_SZ;

    expect_string(__wrap__mdebug1, formatted_msg, "Error converting registry value data to UTF-8.");

    fim_registry_calculate_hashes(entry, configuration, (BYTE *)utf16_data);

    assert_string_equal(entry->registry_entry.value->hash_md5, "");
    assert_string_equal(entry->registry_entry.value->hash_sha1, "");
    assert_string_equal(entry->registry_entry.value->hash_sha256, "");
}

static void test_fim_registry_calculate_hashes_utf16_conversion_fail_reg_expand_sz(void **state) {
    fim_entry *entry = *state;

    syscheck.registry = one_entry_config;
    registry_t *configuration = &syscheck.registry[0];
    configuration->opts = CHECK_SHA1SUM;

    WCHAR utf16_data[] = L"%USERPROFILE%\\test";
    entry->registry_entry.value->type = REG_EXPAND_SZ;

    expect_string(__wrap__mdebug1, formatted_msg, "Error converting registry value data to UTF-8.");

    fim_registry_calculate_hashes(entry, configuration, (BYTE *)utf16_data);

    assert_string_equal(entry->registry_entry.value->hash_md5, "");
    assert_string_equal(entry->registry_entry.value->hash_sha1, "");
    assert_string_equal(entry->registry_entry.value->hash_sha256, "");
}

static void test_fim_registry_calculate_hashes_utf16_multi_sz_conversion_fail_first(void **state) {
    fim_entry *entry = *state;

    syscheck.registry = one_entry_config;
    registry_t *configuration = &syscheck.registry[0];
    configuration->opts = CHECK_SHA256SUM;

    WCHAR utf16_multi_data[] = L"A\0B\0\0";
    entry->registry_entry.value->type = REG_MULTI_SZ;

    expect_string(__wrap__mdebug1, formatted_msg, "Error converting registry value data to UTF-8.");

    fim_registry_calculate_hashes(entry, configuration, (BYTE *)utf16_multi_data);

    assert_string_equal(entry->registry_entry.value->hash_md5, "");
    assert_string_equal(entry->registry_entry.value->hash_sha1, "");
    assert_string_equal(entry->registry_entry.value->hash_sha256, "");
}

static void test_fim_registry_calculate_hashes_utf16_multi_sz_conversion_fail_second(void **state) {
    fim_entry *entry = *state;

    syscheck.registry = one_entry_config;
    registry_t *configuration = &syscheck.registry[0];
    configuration->opts = CHECK_MD5SUM | CHECK_SHA1SUM;

    WCHAR utf16_multi_data[] = L"A\0B\0\0";
    entry->registry_entry.value->type = REG_MULTI_SZ;
    expect_string(__wrap__mdebug1, formatted_msg, "Error converting registry value data to UTF-8.");

    fim_registry_calculate_hashes(entry, configuration, (BYTE *)utf16_multi_data);

    assert_string_equal(entry->registry_entry.value->hash_md5, "");
    assert_string_equal(entry->registry_entry.value->hash_sha1, "");
    assert_string_equal(entry->registry_entry.value->hash_sha256, "");
}

static void test_fim_registry_convert_value_for_diff_reg_sz_success(void **state) {
    WCHAR utf16_data[] = L"TestValue";
    char *expected_result = "TestValue";

    char *result = fim_registry_convert_value_for_diff((BYTE *)utf16_data, REG_SZ);

    assert_non_null(result);
    assert_string_equal(result, expected_result);
    free(result);
}

static void test_fim_registry_convert_value_for_diff_reg_sz_fail(void **state) {
    WCHAR utf16_data[] = L"TestValue";
    char *result = fim_registry_convert_value_for_diff((BYTE *)utf16_data, REG_SZ);

    assert_null(result);
}

static void test_fim_registry_convert_value_for_diff_reg_expand_sz_success(void **state) {
    WCHAR utf16_data[] = L"%USERPROFILE%\\test";
    char *expected_result = "%USERPROFILE%\\test";
    char *result = fim_registry_convert_value_for_diff((BYTE *)utf16_data, REG_EXPAND_SZ);

    assert_non_null(result);
    assert_string_equal(result, expected_result);
    free(result);
}

static void test_fim_registry_convert_value_for_diff_reg_expand_sz_fail(void **state) {
    WCHAR utf16_data[] = L"%USERPROFILE%\\test";
    char *result = fim_registry_convert_value_for_diff((BYTE *)utf16_data, REG_EXPAND_SZ);

    assert_null(result);
}

static void test_fim_registry_convert_value_for_diff_reg_multi_sz_success(void **state) {
    WCHAR utf16_multi_data[] = L"Value1\0Value2\0Value3\0\0";
    char *result = fim_registry_convert_value_for_diff((BYTE *)utf16_multi_data, REG_MULTI_SZ);

    assert_non_null(result);
    assert_string_equal(result, "Value1");
    assert_string_equal(result + 7, "Value2");
    assert_string_equal(result + 14, "Value3");
    free(result);
}

static void test_fim_registry_convert_value_for_diff_reg_multi_sz_fail_first_loop(void **state) {
    WCHAR utf16_multi_data[] = L"Value1\0Value2\0\0";
    char *result = fim_registry_convert_value_for_diff((BYTE *)utf16_multi_data, REG_MULTI_SZ);

    assert_null(result);
}

static void test_fim_registry_convert_value_for_diff_reg_multi_sz_fail_second_loop(void **state) {
    WCHAR utf16_multi_data[] = L"Value1\0Value2\0\0";
    char *result = fim_registry_convert_value_for_diff((BYTE *)utf16_multi_data, REG_MULTI_SZ);

    assert_null(result);
}

static void test_fim_registry_convert_value_for_diff_reg_dword(void **state) {
    DWORD dword_value = 12345678;
    BYTE *data_buffer = (BYTE *)&dword_value;

    char *result = fim_registry_convert_value_for_diff(data_buffer, REG_DWORD);

    assert_ptr_equal(result, (char *)data_buffer);
}

static void test_fim_registry_scan_base_line_generation(void **state) {
    syscheck.registry = one_entry_config;
    syscheck.registry[0].opts = CHECK_REGISTRY_ALL;

    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);

    // Set value of FirstSubKey
    wchar_t *value_name = L"test_value";
    unsigned int value_type = REG_DWORD;
    unsigned int value_size = 4;
    DWORD value_data = 123456;
    TXN_HANDLE mock_handle;

    LPSTR usid = "userid";
    LPSTR gsid = "groupid";
    FILETIME last_write_time = { 0, 1000 };

    will_return(__wrap_fim_db_transaction_start, mock_handle);
    will_return(__wrap_fim_db_transaction_start, mock_handle);
    expect_string(__wrap__mdebug1, formatted_msg, FIM_WINREGISTRY_START);
    expect_any_always(__wrap__mdebug2, formatted_msg);

    // Scan a subkey of batfile
    expect_RegOpenKeyExW_call(HKEY_LOCAL_MACHINE, L"Software\\Classes\\batfile", 0, KEY_READ | KEY_WOW64_64KEY, NULL,
                             ERROR_SUCCESS);
    expect_RegQueryInfoKey_call(1, 0, &last_write_time, ERROR_SUCCESS);
    expect_RegEnumKeyExW_call(L"FirstSubKey", ERROR_SUCCESS);

    // Scan a value of FirstSubKey
    expect_RegOpenKeyExW_call(HKEY_LOCAL_MACHINE, L"Software\\Classes\\batfile\\FirstSubKey", 0,
                             KEY_READ | KEY_WOW64_64KEY, NULL, ERROR_SUCCESS);
    expect_RegQueryInfoKey_call(0, 1, &last_write_time, ERROR_SUCCESS);

    // Inside fim_registry_get_key_data
    expect_fim_registry_get_key_data_call(usid, gsid, "username", "groupname",
                                          "sid (allowed): delete|write_dac|write_data|append_data|write_attributes",
                                          last_write_time);
    will_return(__wrap_fim_db_transaction_sync_row, -1);
    expect_string(__wrap__merror, formatted_msg, "Dbsync registry transaction failed due to -1");
    will_return(__wrap_fim_db_transaction_sync_row, -1);
    expect_RegEnumValueW_call(value_name, value_type, (LPBYTE)&value_data, value_size, ERROR_SUCCESS);

    expect_fim_registry_value_diff("HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile\\FirstSubKey", "test_value",
                                   (const char *)&value_data, 4, REG_DWORD, NULL);



    // Inside fim_registry_get_key_data
    expect_fim_registry_get_key_data_call(usid, gsid, "username", "groupname",
                                          "sid (allowed): delete|write_dac|write_data|append_data|write_attributes",
                                          last_write_time);

    will_return(__wrap_fim_db_transaction_sync_row, 0);

    expect_function_call(__wrap_fim_db_transaction_deleted_rows);
    expect_function_call(__wrap_fim_db_transaction_deleted_rows);

    // process_pending_sync_updates is called twice: once for keys, once for values
    expect_string(__wrap__mdebug1, formatted_msg, "Processed 0 pending sync flag updates");
    expect_string(__wrap__mdebug1, formatted_msg, "Processed 0 pending sync flag updates");
    expect_string(__wrap__mdebug1, formatted_msg, FIM_WINREGISTRY_ENDED);

    // Test
    fim_registry_scan();
}

static void test_fim_registry_scan_regular_scan(void **state) {
    syscheck.registry = default_config;

    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);

    // Set value of FirstSubKey
    wchar_t *value_name = L"test_value";
    unsigned int value_type = REG_DWORD;
    unsigned int value_size = 4;
    DWORD value_data = 123456;
    TXN_HANDLE mock_handle;

    LPSTR usid = "userid";
    LPSTR gsid = "groupid";
    FILETIME last_write_time = { 0, 1000 };

    will_return(__wrap_fim_db_transaction_start, &mock_handle);
    will_return(__wrap_fim_db_transaction_start, &mock_handle);
    expect_string(__wrap__mdebug1, formatted_msg, FIM_WINREGISTRY_START);
    expect_string(__wrap__mdebug1, formatted_msg, "(6919): Invalid syscheck registry entry: 'HKEY_LOCAL_MACHINE_Invalid_key\\Software\\Ignore' arch: '[x64] '.");
    expect_any_always(__wrap__mdebug2, formatted_msg);
    expect_any_always(__wrap__merror, formatted_msg);

    // Scan a subkey of batfile
    expect_RegOpenKeyExW_call(HKEY_LOCAL_MACHINE, L"Software\\Classes\\batfile", 0,
                             KEY_READ | KEY_WOW64_64KEY, NULL, ERROR_SUCCESS);
    expect_RegQueryInfoKey_call(1, 0, &last_write_time, ERROR_SUCCESS);
    expect_RegEnumKeyExW_call(L"FirstSubKey", ERROR_SUCCESS);

    expect_RegOpenKeyExW_call(HKEY_LOCAL_MACHINE, L"Software\\Classes\\batfile\\FirstSubKey", 0,
                             KEY_READ | KEY_WOW64_64KEY, NULL, ERROR_SUCCESS);
    expect_RegQueryInfoKey_call(0, 1, &last_write_time, ERROR_SUCCESS);

    // Inside fim_registry_get_key_data
    expect_fim_registry_get_key_data_call(usid, gsid, "username", "groupname",
                                          "sid (allowed): delete|write_dac|write_data|append_data|write_attributes",
                                          last_write_time);

    will_return(__wrap_fim_db_transaction_sync_row, -1);
    will_return(__wrap_fim_db_transaction_sync_row, -1);

    expect_RegEnumValueW_call(value_name, value_type, (LPBYTE)&value_data, value_size, ERROR_SUCCESS);


    expect_fim_registry_value_diff("HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile\\FirstSubKey", "test_value",
                                   (const char *)&value_data, 4, REG_DWORD, NULL);

    // Inside fim_registry_get_key_data
    expect_fim_registry_get_key_data_call(usid, gsid, "username", "groupname",
                                          "sid (allowed): delete|write_dac|write_data|append_data|write_attributes",
                                          last_write_time);

    will_return(__wrap_fim_db_transaction_sync_row, -1);
    will_return(__wrap_fim_db_transaction_sync_row, -1);

    // Scan a subkey of RecursionLevel0
    expect_RegOpenKeyExW_call(HKEY_LOCAL_MACHINE, L"Software\\RecursionLevel0", 0, KEY_READ | KEY_WOW64_64KEY, NULL, ERROR_SUCCESS);
    expect_RegQueryInfoKey_call(1, 0, &last_write_time, ERROR_SUCCESS);
    expect_RegEnumKeyExW_call(L"depth0", ERROR_SUCCESS);

    // Inside fim_registry_get_key_data
    expect_fim_registry_get_key_data_call(usid, gsid, "username2", "groupname2",
                                          "sid (allowed): delete|write_dac|write_data|append_data|write_attributes",
                                          last_write_time);

    will_return(__wrap_fim_db_transaction_sync_row, -1);

    expect_RegOpenKeyExW_call(HKEY_LOCAL_MACHINE, L"Software\\FailToInsert", 0,
                             KEY_READ | KEY_WOW64_64KEY, NULL, ERROR_SUCCESS);
    expect_RegQueryInfoKey_call(0, 0, &last_write_time, ERROR_SUCCESS);


    // Inside fim_registry_get_key_data
    expect_fim_registry_get_key_data_call(usid, gsid, "username2", "groupname2",
                                          "sid (allowed): delete|write_dac|write_data|append_data|write_attributes",
                                          last_write_time);

    expect_function_call(__wrap_fim_db_transaction_deleted_rows);
    expect_function_call(__wrap_fim_db_transaction_deleted_rows);

    // process_pending_sync_updates is called twice: once for keys, once for values
    expect_string(__wrap__mdebug1, formatted_msg, "Processed 0 pending sync flag updates");
    expect_string(__wrap__mdebug1, formatted_msg, "Processed 0 pending sync flag updates");
    expect_string(__wrap__mdebug1, formatted_msg, FIM_WINREGISTRY_ENDED);

    // Test
    fim_registry_scan();
}

static void test_fim_registry_scan_RegOpenKeyExW_fail(void **state) {
    syscheck.registry = one_entry_config;
    syscheck.registry[0].opts = CHECK_REGISTRY_ALL;
    TXN_HANDLE mock_handle;

    will_return(__wrap_fim_db_transaction_start, mock_handle);
    will_return(__wrap_fim_db_transaction_start, mock_handle);
    expect_string(__wrap__mdebug1, formatted_msg, FIM_WINREGISTRY_START);
    expect_string(__wrap__mdebug1, formatted_msg, "(6920): Failed to open registry key: 'Software\\Classes\\batfile' (arch: '[x64]'). Error code: -1.");
    // process_pending_sync_updates is called twice: once for keys, once for values
    expect_string(__wrap__mdebug1, formatted_msg, "Processed 0 pending sync flag updates");
    expect_string(__wrap__mdebug1, formatted_msg, "Processed 0 pending sync flag updates");
    expect_string(__wrap__mdebug1, formatted_msg, FIM_WINREGISTRY_ENDED);
    expect_any_always(__wrap__mdebug2, formatted_msg);

    // Scan a subkey of batfile
    expect_RegOpenKeyExW_call(HKEY_LOCAL_MACHINE, L"Software\\Classes\\batfile", 0,
                             KEY_READ | KEY_WOW64_64KEY, NULL, -1);

    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);

    expect_function_call(__wrap_fim_db_transaction_deleted_rows);
    expect_function_call(__wrap_fim_db_transaction_deleted_rows);

    // Test

    fim_registry_scan();
}

static void test_fim_registry_scan_RegQueryInfoKey_fail(void **state) {
    FILETIME last_write_time = { 0, 1000 };

    syscheck.registry = one_entry_config;
    syscheck.registry[0].opts = CHECK_REGISTRY_ALL;
    TXN_HANDLE mock_handle;

    will_return(__wrap_fim_db_transaction_start, mock_handle);
    will_return(__wrap_fim_db_transaction_start, mock_handle);
    expect_string(__wrap__mdebug1, formatted_msg, FIM_WINREGISTRY_START);
    // process_pending_sync_updates is called twice: once for keys, once for values
    expect_string(__wrap__mdebug1, formatted_msg, "Processed 0 pending sync flag updates");
    expect_string(__wrap__mdebug1, formatted_msg, "Processed 0 pending sync flag updates");
    expect_string(__wrap__mdebug1, formatted_msg, FIM_WINREGISTRY_ENDED);
    expect_any_always(__wrap__mdebug2, formatted_msg);

    // Scan a subkey of batfile

    expect_RegOpenKeyExW_call(HKEY_LOCAL_MACHINE, L"Software\\Classes\\batfile", 0,
                             KEY_READ | KEY_WOW64_64KEY, NULL, ERROR_SUCCESS);
    expect_RegQueryInfoKey_call(1, 0, &last_write_time, -1);

    // Expect pthread calls from C++ singletons and syscheck mutexes
    expect_function_call_any(__wrap_pthread_mutex_lock);
    expect_function_call_any(__wrap_pthread_mutex_unlock);

    expect_function_call(__wrap_fim_db_transaction_deleted_rows);
    expect_function_call(__wrap_fim_db_transaction_deleted_rows);

    // Test
    fim_registry_scan();
}

static void test_fim_registry_key_transaction_callback_empty_changed_attributes(){
    notify_scan = 1;
    event_data_t event_data = {.mode = FIM_SCHEDULED, .report_event = true};
    fim_registry_key key = {
        .path = "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile",
        .architecture = ARCH_64BIT,
    };
    ReturnTypeCallback resultType = MODIFIED;
    const cJSON *result_json = cJSON_Parse("{\"new\":{\"path\":\"HKEY_LOCAL_MACHINE\\\\Software\\\\Classes\\\\batfile\",\"architecture\":\"[x64]\",\"version\":2},\"old\":{\"path\":\"HKEY_LOCAL_MACHINE\\\\Software\\\\Classes\\\\batfile\", \"architecture\":\"[x64]\",\"version\":1}}");
    fim_key_txn_context_t user_data = {
        .evt_data = &event_data,
        .config = NULL,
        .key = &key,
        .failed_keys = NULL,
        .pending_sync_updates = NULL
    };

    expect_string(__wrap__mdebug2, formatted_msg, "(6954): Entry 'HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile' does not have any modified fields. No event will be generated.");

    registry_key_transaction_callback(resultType, result_json, &user_data);
}

static void test_fim_registry_key_transaction_callback_base_line(){
    notify_scan = 0;
    ReturnTypeCallback resultType = INSERTED;
    const cJSON* result_json = NULL;
    fim_key_txn_context_t user_data = {
        .evt_data = NULL,
        .config = NULL,
        .key = NULL,
        .failed_keys = NULL,
        .pending_sync_updates = NULL
    };

    registry_key_transaction_callback(resultType, result_json, &user_data);
}

static void test_fim_registry_key_transaction_callback_empty_json_array(){
    notify_scan = 1;
    ReturnTypeCallback resultType = INSERTED;
    const char* json_string = "{}";
    const cJSON* result_json = cJSON_Parse(json_string);
    fim_key_txn_context_t user_data = {
        .evt_data = NULL,
        .config = NULL,
        .key = NULL,
        .failed_keys = NULL,
        .pending_sync_updates = NULL
    };

    registry_key_transaction_callback(resultType, result_json, &user_data);
}

static void test_fim_registry_key_transaction_callback_null_configuration(){
    notify_scan = 1;
    event_data_t event_data;
    ReturnTypeCallback resultType = INSERTED;
    const char* json_string = "{\"path\":\"HKEY_LOCAL_MACHINE\\\\Software\\\\Classes\\\\batfile\", \"architecture\":\"[x32]\"}";
    const cJSON* result_json = cJSON_Parse(json_string);
    fim_key_txn_context_t user_data = {
        .evt_data = &event_data,
        .config = NULL,
        .key = NULL,
        .failed_keys = NULL,
        .pending_sync_updates = NULL
    };

    // fim_registry_configuration
    expect_any_always(__wrap__mdebug2, formatted_msg);

    registry_key_transaction_callback(resultType, result_json, &user_data);
}

static void test_fim_registry_key_transaction_callback_insert(){
    notify_scan = 1;
    event_data_t event_data = {.mode = FIM_SCHEDULED, .report_event = true};
    ReturnTypeCallback resultType = INSERTED;
    const char* json_string = "{\"path\":\"HKEY_LOCAL_MACHINE\\\\Software\\\\Classes\\\\batfile\", \"architecture\":\"[x64]\", \"checksum\":\"d0e2e27875639745261c5d1365eb6c9fb7319247\", \"version\":1}";
    const cJSON* result_json = cJSON_Parse(json_string);
    fim_key_txn_context_t user_data = {
        .evt_data = &event_data,
        .config = NULL,
        .key = NULL,
        .failed_keys = NULL,
        .pending_sync_updates = NULL
    };

    expect_function_call(__wrap_send_syscheck_msg);

    // validate_and_persist_fim_event wrapper returns validation success
    will_return(__wrap_validate_and_persist_fim_event, true);

    registry_key_transaction_callback(resultType, result_json, &user_data);
}

static void test_fim_registry_key_transaction_callback_modify(){
    notify_scan = 1;
    event_data_t event_data = {.mode = FIM_SCHEDULED, .report_event = true};
    ReturnTypeCallback resultType = MODIFIED;
    const char* json_string = "{\"path\":\"HKEY_LOCAL_MACHINE\\\\Software\\\\Classes\\\\batfile\", \"architecture\":\"[x64]\", \"checksum\":\"d0e2e27875639745261c5d1365eb6c9fb7319247\", \"version\":1}";
    const cJSON* result_json = cJSON_Parse(json_string);
    fim_key_txn_context_t user_data = {
        .evt_data = &event_data,
        .config = NULL,
        .key = NULL,
        .failed_keys = NULL,
        .pending_sync_updates = NULL
    };

    expect_function_call(__wrap_send_syscheck_msg);

    // validate_and_persist_fim_event wrapper returns validation success
    will_return(__wrap_validate_and_persist_fim_event, true);

    registry_key_transaction_callback(resultType, result_json, &user_data);
}

static void test_fim_registry_key_transaction_callback_delete(){
    notify_scan = 1;
    event_data_t event_data = {.mode = FIM_SCHEDULED, .report_event = true};
    ReturnTypeCallback resultType = DELETED;
    const char* json_string = "{\"path\":\"HKEY_LOCAL_MACHINE\\\\Software\\\\Classes\\\\batfile\", \"architecture\":\"[x64]\", \"checksum\":\"d0e2e27875639745261c5d1365eb6c9fb7319247\", \"version\":1}";
    const cJSON* result_json = cJSON_Parse(json_string);
    fim_key_txn_context_t user_data = {
        .evt_data = &event_data,
        .config = NULL,
        .key = NULL,
        .failed_keys = NULL,
        .pending_sync_updates = NULL
    };

    expect_function_call(__wrap_send_syscheck_msg);

    // validate_and_persist_fim_event wrapper returns validation success
    will_return(__wrap_validate_and_persist_fim_event, true);

    registry_key_transaction_callback(resultType, result_json, &user_data);
}

static void test_fim_registry_key_transaction_callback_max_rows(){
    notify_scan = 1;
    event_data_t event_data;
    fim_registry_key key;
    key.path = "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile";
    key.architecture = ARCH_64BIT;
    ReturnTypeCallback resultType = MAX_ROWS;
    const char* json_string = "{\"path\":\"HKEY_LOCAL_MACHINE\\\\Software\\\\Classes\\\\batfile\", \"architecture\":\"[x64]\"}";
    const cJSON* result_json = cJSON_Parse(json_string);
    fim_key_txn_context_t user_data = {
        .evt_data = &event_data,
        .config = NULL,
        .key = &key,
        .failed_keys = NULL,
        .pending_sync_updates = NULL
    };

    expect_string(__wrap__mdebug1, formatted_msg, "Couldn't insert 'HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile' entry into DB. The DB is full, please check your configuration.");

    registry_key_transaction_callback(resultType, result_json, &user_data);
}

static void test_fim_registry_value_transaction_callback_empty_changed_attributes(){
    notify_scan = 1;
    event_data_t event_data = {.mode = FIM_SCHEDULED, .report_event = true};
    fim_registry_value_data value;
    memset(&value, 0, sizeof(fim_registry_value_data));
    value.path = "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile";
    value.architecture = ARCH_64BIT;
    value.value = "mock_value_name";
    ReturnTypeCallback resultType = MODIFIED;
    const cJSON *result_json = cJSON_Parse("{\"new\":{\"path\":\"HKEY_LOCAL_MACHINE\\\\Software\\\\Classes\\\\batfile\",\"architecture\":\"[x64]\",\"value\":\"mock_name_value\",\"version\":2},\"old\":{\"path\":\"HKEY_LOCAL_MACHINE\\\\Software\\\\Classes\\\\batfile\", \"architecture\":\"[x64]\",\"value\":\"mock_name_value\",\"version\":1}}");
    fim_val_txn_context_t user_data = {
        .data = &value,
        .evt_data = &event_data,
        .diff = NULL,
        .config = NULL,
        .failed_values = NULL,
        .pending_sync_updates = NULL
    };

    expect_string(__wrap__mdebug2, formatted_msg, "(6954): Entry 'HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile' does not have any modified fields. No event will be generated.");

    registry_value_transaction_callback(resultType, result_json, &user_data);
}

static void test_fim_registry_value_transaction_callback_base_line(){
    notify_scan = 0;
    event_data_t event_data;
    ReturnTypeCallback resultType = INSERTED;
    const cJSON* result_json = NULL;
    fim_val_txn_context_t user_data = {
        .data = NULL,
        .evt_data = &event_data,
        .diff = NULL,
        .config = NULL,
        .failed_values = NULL,
        .pending_sync_updates = NULL
    };

    registry_value_transaction_callback(resultType, result_json, &user_data);
}

static void test_fim_registry_value_transaction_callback_empty_json_array(){
    notify_scan = 1;
    ReturnTypeCallback resultType = INSERTED;
    const char* json_string = "{}";
    const cJSON* result_json = cJSON_Parse(json_string);
    fim_val_txn_context_t user_data = {
        .data = NULL,
        .evt_data = NULL,
        .diff = NULL,
        .config = NULL,
        .failed_values = NULL,
        .pending_sync_updates = NULL
    };

    registry_value_transaction_callback(resultType, result_json, &user_data);
}

static void test_fim_registry_value_transaction_callback_null_configuration(){
    notify_scan = 1;
    event_data_t event_data;
    ReturnTypeCallback resultType = INSERTED;
    const char* json_string = "{\"path\":\"HKEY_LOCAL_MACHINE\\\\Software\\\\Classes\\\\batfile\", \"architecture\":\"[x32]\", \"value\":\"mock_name_value\"}";
    const cJSON* result_json = cJSON_Parse(json_string);
    fim_val_txn_context_t user_data = {
        .data = NULL,
        .evt_data = &event_data,
        .diff = NULL,
        .config = NULL,
        .failed_values = NULL,
        .pending_sync_updates = NULL
    };

    // fim_registry_configuration
    expect_any_always(__wrap__mdebug2, formatted_msg);

    registry_value_transaction_callback(resultType, result_json, &user_data);
}

static void test_fim_registry_value_transaction_callback_insert(){
    notify_scan = 1;
    event_data_t event_data = {.mode = FIM_SCHEDULED, .report_event = true};
    ReturnTypeCallback resultType = INSERTED;
    const char* json_string = "{\"path\":\"HKEY_LOCAL_MACHINE\\\\Software\\\\Classes\\\\batfile\",\"architecture\":\"[x64]\",\"value\":\"mock_name_value\",\"checksum\":\"d0e2e27875639745261c5d1365eb6c9fb7319247\",\"version\":1}";
    const cJSON* result_json = cJSON_Parse(json_string);
    fim_val_txn_context_t user_data = {
        .data = NULL,
        .evt_data = &event_data,
        .diff = NULL,
        .config = NULL,
        .failed_values = NULL,
        .pending_sync_updates = NULL
    };

    expect_function_call(__wrap_send_syscheck_msg);

    // validate_and_persist_fim_event wrapper returns validation success
    will_return(__wrap_validate_and_persist_fim_event, true);

    registry_value_transaction_callback(resultType, result_json, &user_data);
}

static void test_fim_registry_value_transaction_callback_modify(){
    notify_scan = 1;
    event_data_t event_data = {.mode = FIM_SCHEDULED, .report_event = true};
    ReturnTypeCallback resultType = MODIFIED;
    const char* json_string = "{\"path\":\"HKEY_LOCAL_MACHINE\\\\Software\\\\Classes\\\\batfile\",\"architecture\":\"[x64]\",\"value\":\"mock_name_value\",\"checksum\":\"d0e2e27875639745261c5d1365eb6c9fb7319247\",\"version\":1}";
    const cJSON* result_json = cJSON_Parse(json_string);
    fim_val_txn_context_t user_data = {
        .data = NULL,
        .evt_data = &event_data,
        .diff = NULL,
        .config = NULL,
        .failed_values = NULL,
        .pending_sync_updates = NULL
    };

    expect_function_call(__wrap_send_syscheck_msg);

    // validate_and_persist_fim_event wrapper returns validation success
    will_return(__wrap_validate_and_persist_fim_event, true);

    registry_value_transaction_callback(resultType, result_json, &user_data);
}

static void test_fim_registry_value_transaction_callback_modify_with_diff(){
    notify_scan = 1;
    event_data_t event_data = {.mode = FIM_SCHEDULED, .report_event = true};
    ReturnTypeCallback resultType = MODIFIED;
    const char* json_string = "{\"path\":\"HKEY_LOCAL_MACHINE\\\\Software\\\\Classes\\\\batfile\",\"architecture\":\"[x64]\",\"value\":\"mock_name_value\",\"checksum\":\"d0e2e27875639745261c5d1365eb6c9fb7319247\",\"version\":1}";
    const cJSON* result_json = cJSON_Parse(json_string);
    fim_val_txn_context_t user_data = {
        .data = NULL,
        .evt_data = &event_data,
        .diff = "test diff string",
        .config = NULL,
        .failed_values = NULL,
        .pending_sync_updates = NULL
    };

    expect_function_call(__wrap_send_syscheck_msg);

    // validate_and_persist_fim_event wrapper returns validation success
    will_return(__wrap_validate_and_persist_fim_event, true);

    registry_value_transaction_callback(resultType, result_json, &user_data);
}

static void test_fim_registry_value_transaction_callback_delete(){
    notify_scan = 1;
    event_data_t event_data = {.mode = FIM_SCHEDULED, .report_event = true};
    ReturnTypeCallback resultType = DELETED;
    const char* json_string = "{\"path\":\"HKEY_LOCAL_MACHINE\\\\Software\\\\Classes\\\\batfile\",\"architecture\":\"[x64]\",\"value\":\"mock_name_value\",\"checksum\":\"d0e2e27875639745261c5d1365eb6c9fb7319247\",\"version\":1}";
    const cJSON* result_json = cJSON_Parse(json_string);
    fim_val_txn_context_t user_data = {
        .data = NULL,
        .evt_data = &event_data,
        .diff = NULL,
        .config = NULL,
        .failed_values = NULL,
        .pending_sync_updates = NULL
    };

    expect_function_call(__wrap_send_syscheck_msg);

    // validate_and_persist_fim_event wrapper returns validation success
    will_return(__wrap_validate_and_persist_fim_event, true);

    expect_string(__wrap__mdebug2, formatted_msg, "(6355): Can't remove folder 'queue/diff/registry/[x64] b9b175e8810d3475f15976dd3b5f9210f3af6604/6797a8200934259ad5d56d1eb8dd24afc4f7ae2e', it does not exist.");

    registry_value_transaction_callback(resultType, result_json, &user_data);
}

static void test_fim_registry_value_transaction_callback_max_rows(){
    notify_scan = 1;
    event_data_t event_data = {.mode = FIM_SCHEDULED, .report_event = true};
    fim_registry_value_data value;
    memset(&value, 0, sizeof(fim_registry_value_data));
    value.path = "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile";
    value.architecture = ARCH_64BIT;
    value.value = "mock_value_name";
    ReturnTypeCallback resultType = MAX_ROWS;
    const char* json_string = "{\"path\":\"HKEY_LOCAL_MACHINE\\\\Software\\\\Classes\\\\batfile\", \"architecture\":\"[x64]\", \"value\":\"mock_name_value\"}";
    const cJSON* result_json = cJSON_Parse(json_string);
    fim_val_txn_context_t user_data = {
        .data = &value,
        .evt_data = &event_data,
        .diff = NULL,
        .config = NULL,
        .failed_values = NULL,
        .pending_sync_updates = NULL
    };

    expect_string(__wrap__mdebug1, formatted_msg, "Couldn't insert 'HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile' entry into DB. The DB is full, please check your configuration.");

    registry_value_transaction_callback(resultType, result_json, &user_data);
}

static void test_fim_registry_free_entry(){
    fim_entry *entry;
    os_calloc(1, sizeof(fim_entry), entry);

    fim_registry_key *key;
    os_calloc(1, sizeof(fim_registry_key), key);
    os_strdup("HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile", key->path);
    os_strdup("sid (allowed): delete|write_dac|write_data|append_data|write_attributes", key->permissions);
    os_strdup("100", key->uid);
    os_strdup("200", key->gid);
    os_strdup("username", key->owner);
    os_strdup("groupname", key->group);
    key->architecture = 1;

    fim_registry_value_data *value;
    os_calloc(1, sizeof(fim_registry_value_data), value);
    os_strdup("valuename", value->value);
    strcpy(value->hash_md5, "1234567890ABCDEF1234567890ABCDEF");
    strcpy(value->hash_sha1, "1234567890ABCDEF1234567890ABCDEF12345678");
    strcpy(value->hash_sha256, "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF");
    strcpy(value->checksum, "1234567890ABCDEF1234567890ABCDEF12345678");

    entry->type = FIM_TYPE_REGISTRY;
    entry->registry_entry.key = key;
    entry->registry_entry.value = value;

    fim_registry_free_entry(entry);
}

static void test_fim_read_values_single_dword_value(void **state) {
    HKEY key_handle = (HKEY)123;
    TXN_HANDLE mock_txn_handler = (TXN_HANDLE)456;
    char *path = "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile";
    int arch = ARCH_64BIT;
    DWORD value_count = 1;
    DWORD max_value_length = 256;
    DWORD max_value_data_length = 256;
    event_data_t event_data = {.mode = FIM_SCHEDULED};
    fim_val_txn_context_t txn_ctx = {
        .data = NULL,
        .evt_data = &event_data,
        .diff = NULL,
        .config = NULL,
        .failed_values = NULL,
        .pending_sync_updates = NULL
    };

    syscheck.registry = one_entry_config;
    syscheck.registry[0].opts = CHECK_MD5SUM | CHECK_SHA1SUM | CHECK_SHA256SUM;

    wchar_t *value_name = L"TestValue";
    DWORD value_data = 12345;
    DWORD value_type = REG_DWORD;
    DWORD value_size = sizeof(DWORD);

    expect_RegEnumValueW_call(value_name, value_type, (LPBYTE)&value_data, value_size, ERROR_SUCCESS);

    will_return(__wrap_fim_db_transaction_sync_row, 0);

    fim_read_values(key_handle, path, arch, value_count, max_value_length, max_value_data_length,
                    mock_txn_handler, &txn_ctx);

    // Note: We don't verify txn_ctx.data here because it points to freed stack memory (dangling pointer).
    // The actual data verification happens in the callback in production code.
}

static void test_fim_read_values_single_string_value(void **state) {
    HKEY key_handle = (HKEY)123;
    TXN_HANDLE mock_txn_handler = (TXN_HANDLE)456;
    char *path = "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile";
    int arch = ARCH_64BIT;
    DWORD value_count = 1;
    DWORD max_value_length = 256;
    DWORD max_value_data_length = 256;
    event_data_t event_data = {.mode = FIM_SCHEDULED};
    fim_val_txn_context_t txn_ctx = {
        .data = NULL,
        .evt_data = &event_data,
        .diff = NULL,
        .config = NULL,
        .failed_values = NULL,
        .pending_sync_updates = NULL
    };

    syscheck.registry = one_entry_config;
    syscheck.registry[0].opts = CHECK_MD5SUM;

    wchar_t *value_name = L"StringValue";
    WCHAR value_data[] = L"test_string_data";
    DWORD value_type = REG_SZ;
    DWORD value_size = sizeof(value_data);

    expect_RegEnumValueW_call(value_name, value_type, (LPBYTE)value_data, value_size, ERROR_SUCCESS);

    will_return(__wrap_fim_db_transaction_sync_row, 0);

    fim_read_values(key_handle, path, arch, value_count, max_value_length, max_value_data_length,
                    mock_txn_handler, &txn_ctx);

    // Data verification omitted - txn_ctx.data points to freed stack memory
}

static void test_fim_read_values_unterminated_string_value(void **state) {
    HKEY key_handle = (HKEY)123;
    TXN_HANDLE mock_txn_handler = (TXN_HANDLE)456;
    char *path = "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile";
    int arch = ARCH_64BIT;
    DWORD value_count = 1;
    DWORD max_value_length = 256;
    DWORD max_value_data_length = 256;
    event_data_t event_data = {.mode = FIM_SCHEDULED};
    fim_val_txn_context_t txn_ctx = {
        .data = NULL,
        .evt_data = &event_data,
        .diff = NULL,
        .config = NULL,
        .failed_values = NULL,
        .pending_sync_updates = NULL
    };

    syscheck.registry = one_entry_config;
    syscheck.registry[0].opts = CHECK_MD5SUM;

    wchar_t *value_name = L"UnterminatedString";
    /* Simulate the case where RegEnumValueW writes a string without null terminator */
    WCHAR value_data[256];
    const WCHAR *test_str = L"test_unterminated";
    size_t str_len = wcslen(test_str);
    memcpy(value_data, test_str, str_len * sizeof(WCHAR));
    /* Do not add null terminator, leaving garbage data after the string */
    memset(value_data + str_len, 0xFF, sizeof(value_data) - (str_len * sizeof(WCHAR)));

    DWORD value_type = REG_SZ;
    /* value_size indicates only the useful bytes, without counting the null terminator */
    DWORD value_size = str_len * sizeof(WCHAR);

    expect_RegEnumValueW_call(value_name, value_type, (LPBYTE)value_data, value_size, ERROR_SUCCESS);

    will_return(__wrap_fim_db_transaction_sync_row, 0);

    fim_read_values(key_handle, path, arch, value_count, max_value_length, max_value_data_length,
                    mock_txn_handler, &txn_ctx);

    // Data verification omitted - txn_ctx.data points to freed stack memory
}

static void test_fim_read_values_unterminated_multi_string_value(void **state) {
    HKEY key_handle = (HKEY)123;
    TXN_HANDLE mock_txn_handler = (TXN_HANDLE)456;
    char *path = "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile";
    int arch = ARCH_64BIT;
    DWORD value_count = 1;
    DWORD max_value_length = 256;
    DWORD max_value_data_length = 256;
    event_data_t event_data = {.mode = FIM_SCHEDULED};
    fim_val_txn_context_t txn_ctx = {
        .data = NULL,
        .evt_data = &event_data,
        .diff = NULL,
        .config = NULL,
        .failed_values = NULL,
        .pending_sync_updates = NULL
    };

    syscheck.registry = one_entry_config;
    syscheck.registry[0].opts = CHECK_MD5SUM;

    wchar_t *value_name = L"UnterminatedMultiString";
    /* Simulate REG_MULTI_SZ where the last string in the list lacks null terminator
     * Format should be: "String1\0String2\0\0" but RegEnumValueW may write "String1\0String2" */
    WCHAR value_data[256];
    const WCHAR *first_str = L"FirstValue";
    const WCHAR *second_str = L"SecondValue";
    size_t first_len = wcslen(first_str);
    size_t second_len = wcslen(second_str);

    /* Copy first string with null terminator */
    memcpy(value_data, first_str, first_len * sizeof(WCHAR));
    value_data[first_len] = L'\0';

    /* Copy second string WITHOUT null terminator */
    memcpy(value_data + first_len + 1, second_str, second_len * sizeof(WCHAR));

    /* Fill remaining buffer with garbage */
    memset((BYTE *)(value_data + first_len + 1 + second_len), 0xFF,
           sizeof(value_data) - ((first_len + 1 + second_len) * sizeof(WCHAR)));

    DWORD value_type = REG_MULTI_SZ;
    /* value_size includes first string with null, second string without null, but not final \0 */
    DWORD value_size = (first_len + 1 + second_len) * sizeof(WCHAR);

    expect_RegEnumValueW_call(value_name, value_type, (LPBYTE)value_data, value_size, ERROR_SUCCESS);

    will_return(__wrap_fim_db_transaction_sync_row, 0);

    fim_read_values(key_handle, path, arch, value_count, max_value_length, max_value_data_length,
                    mock_txn_handler, &txn_ctx);

    // Data verification omitted - txn_ctx.data points to freed stack memory
}

static void test_fim_read_values_multiple_values(void **state) {
    HKEY key_handle = (HKEY)123;
    char *path = "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile";
    int arch = ARCH_64BIT;
    DWORD value_count = 2;
    DWORD max_value_length = 256;
    DWORD max_value_data_length = 256;
    TXN_HANDLE mock_txn_handler = (TXN_HANDLE)456;
    event_data_t event_data = {.mode = FIM_SCHEDULED};
    fim_val_txn_context_t txn_ctx = {
        .data = NULL,
        .evt_data = &event_data,
        .diff = NULL,
        .config = NULL,
        .failed_values = NULL,
        .pending_sync_updates = NULL
    };

    syscheck.registry = one_entry_config;
    syscheck.registry[0].opts = CHECK_MD5SUM;

    wchar_t *value_name1 = L"Value1";
    DWORD value_data1 = 100;
    wchar_t *value_name2 = L"Value2";
    DWORD value_data2 = 200;

    expect_RegEnumValueW_call(value_name1, REG_DWORD, (LPBYTE)&value_data1, sizeof(DWORD), ERROR_SUCCESS);
    will_return(__wrap_fim_db_transaction_sync_row, 0);

    expect_RegEnumValueW_call(value_name2, REG_DWORD, (LPBYTE)&value_data2, sizeof(DWORD), ERROR_SUCCESS);
    will_return(__wrap_fim_db_transaction_sync_row, 0);

    fim_read_values(key_handle, path, arch, value_count, max_value_length, max_value_data_length,
                    mock_txn_handler, &txn_ctx);

    // Data verification omitted - txn_ctx.data points to freed stack memory
}

static void test_fim_read_values_zero_value_count(void **state) {
    HKEY key_handle = (HKEY)123;
    char *path = "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile";
    int arch = ARCH_64BIT;
    DWORD value_count = 0;
    DWORD max_value_length = 256;
    DWORD max_value_data_length = 256;
    TXN_HANDLE mock_txn_handler = (TXN_HANDLE)456;
    event_data_t event_data = {.mode = FIM_SCHEDULED};
    fim_val_txn_context_t txn_ctx = {
        .data = NULL,
        .evt_data = &event_data,
        .diff = NULL,
        .config = NULL,
        .failed_values = NULL,
        .pending_sync_updates = NULL
    };

    syscheck.registry = one_entry_config;

    fim_read_values(key_handle, path, arch, value_count, max_value_length, max_value_data_length,
                    mock_txn_handler, &txn_ctx);

    assert_null(txn_ctx.data);
}

static void test_fim_read_values_RegEnumValueW_fail(void **state) {
    HKEY key_handle = (HKEY)123;
    char *path = "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile";
    int arch = ARCH_64BIT;
    DWORD value_count = 1;
    DWORD max_value_length = 256;
    DWORD max_value_data_length = 256;
    TXN_HANDLE mock_txn_handler = (TXN_HANDLE)456;
    event_data_t event_data = {.mode = FIM_SCHEDULED};
    fim_val_txn_context_t txn_ctx = {
        .data = NULL,
        .evt_data = &event_data,
        .diff = NULL,
        .config = NULL,
        .failed_values = NULL,
        .pending_sync_updates = NULL
    };

    syscheck.registry = one_entry_config;

    wchar_t *value_name = L"FailedValue";
    DWORD value_data = 0;

    expect_RegEnumValueW_call(value_name, REG_DWORD, (LPBYTE)&value_data, sizeof(DWORD), ERROR_NO_MORE_ITEMS);

    fim_read_values(key_handle, path, arch, value_count, max_value_length, max_value_data_length,
                    mock_txn_handler, &txn_ctx);

    assert_null(txn_ctx.data);
}

static void test_fim_read_values_null_configuration(void **state) {
    HKEY key_handle = (HKEY)123;
    char *path = "HKEY_LOCAL_MACHINE\\Software\\Unknown\\Path";
    int arch = ARCH_64BIT;
    DWORD value_count = 1;
    DWORD max_value_length = 256;
    DWORD max_value_data_length = 256;
    TXN_HANDLE mock_txn_handler = (TXN_HANDLE)456;
    event_data_t event_data = {.mode = FIM_SCHEDULED};
    fim_val_txn_context_t txn_ctx = {
        .data = NULL,
        .evt_data = &event_data,
        .diff = NULL,
        .config = NULL,
        .failed_values = NULL,
        .pending_sync_updates = NULL
    };

    syscheck.registry = one_entry_config;

    expect_any_always(__wrap__mdebug2, formatted_msg);

    fim_read_values(key_handle, path, arch, value_count, max_value_length, max_value_data_length,
                    mock_txn_handler, &txn_ctx);

    assert_null(txn_ctx.data);
}

static void test_fim_read_values_arch_32bit(void **state) {
    HKEY key_handle = (HKEY)123;
    char *path = "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile";
    int arch = ARCH_32BIT;
    DWORD value_count = 1;
    DWORD max_value_length = 256;
    DWORD max_value_data_length = 256;
    TXN_HANDLE mock_txn_handler = (TXN_HANDLE)456;
    event_data_t event_data = {.mode = FIM_SCHEDULED};
    fim_val_txn_context_t txn_ctx = {
        .data = NULL,
        .evt_data = &event_data,
        .diff = NULL,
        .config = NULL,
        .failed_values = NULL,
        .pending_sync_updates = NULL
    };

    syscheck.registry = default_config;
    syscheck.registry[0].arch = ARCH_32BIT;
    syscheck.registry[0].opts = CHECK_MD5SUM;

    wchar_t *value_name = L"TestValue32";
    DWORD value_data = 32;

    expect_RegEnumValueW_call(value_name, REG_DWORD, (LPBYTE)&value_data, sizeof(DWORD), ERROR_SUCCESS);
    will_return(__wrap_fim_db_transaction_sync_row, 0);

    fim_read_values(key_handle, path, arch, value_count, max_value_length, max_value_data_length,
                    mock_txn_handler, &txn_ctx);

    // Data verification omitted - txn_ctx.data points to freed stack memory

    syscheck.registry[0].arch = ARCH_64BIT;
}

static void test_fim_read_values_with_seechanges(void **state) {
    HKEY key_handle = (HKEY)123;
    char *path = "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile";
    int arch = ARCH_64BIT;
    DWORD value_count = 1;
    DWORD max_value_length = 256;
    DWORD max_value_data_length = 256;
    TXN_HANDLE mock_txn_handler = (TXN_HANDLE)456;
    event_data_t event_data = {.mode = FIM_SCHEDULED};
    fim_val_txn_context_t txn_ctx = {
        .data = NULL,
        .evt_data = &event_data,
        .diff = NULL,
        .config = NULL,
        .failed_values = NULL,
        .pending_sync_updates = NULL
    };

    syscheck.registry = one_entry_config;
    syscheck.registry[0].opts = CHECK_MD5SUM | CHECK_SEECHANGES;

    wchar_t *value_name = L"DiffValue";
    DWORD value_data = 999;
    DWORD value_type = REG_DWORD;
    DWORD value_size = sizeof(DWORD);

    expect_RegEnumValueW_call(value_name, value_type, (LPBYTE)&value_data, value_size, ERROR_SUCCESS);

    expect_fim_registry_value_diff(path, "DiffValue", (const char *)&value_data, value_size, value_type, NULL);

    will_return(__wrap_fim_db_transaction_sync_row, 0);

    fim_read_values(key_handle, path, arch, value_count, max_value_length, max_value_data_length,
                    mock_txn_handler, &txn_ctx);

    // Data verification omitted - txn_ctx.data points to freed stack memory
}

static void test_fim_read_values_db_sync_fail(void **state) {
    HKEY key_handle = (HKEY)123;
    char *path = "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile";
    int arch = ARCH_64BIT;
    DWORD value_count = 1;
    DWORD max_value_length = 256;
    DWORD max_value_data_length = 256;
    TXN_HANDLE mock_txn_handler = (TXN_HANDLE)456;
    event_data_t event_data = {.mode = FIM_SCHEDULED};
    fim_val_txn_context_t txn_ctx = {
        .data = NULL,
        .evt_data = &event_data,
        .diff = NULL,
        .config = NULL,
        .failed_values = NULL,
        .pending_sync_updates = NULL
    };

    syscheck.registry = one_entry_config;
    syscheck.registry[0].opts = CHECK_MD5SUM;

    wchar_t *value_name = L"SyncFailValue";
    DWORD value_data = 500;

    expect_RegEnumValueW_call(value_name, REG_DWORD, (LPBYTE)&value_data, sizeof(DWORD), ERROR_SUCCESS);

    will_return(__wrap_fim_db_transaction_sync_row, -1);
    expect_any(__wrap__mdebug2, formatted_msg);

    fim_read_values(key_handle, path, arch, value_count, max_value_length, max_value_data_length,
                    mock_txn_handler, &txn_ctx);

    // Data verification omitted - txn_ctx.data points to freed stack memory
}

static void test_fim_read_values_ignored_value(void **state) {
    HKEY key_handle = (HKEY)123;
    char *path = "HKEY_LOCAL_MACHINE\\Software\\Ignore";
    int arch = ARCH_64BIT;
    DWORD value_count = 1;
    DWORD max_value_length = 256;
    DWORD max_value_data_length = 256;
    TXN_HANDLE mock_txn_handler = (TXN_HANDLE)456;
    event_data_t event_data = {.mode = FIM_SCHEDULED};
    fim_val_txn_context_t txn_ctx = {
        .data = NULL,
        .evt_data = &event_data,
        .diff = NULL,
        .config = NULL,
        .failed_values = NULL,
        .pending_sync_updates = NULL
    };

    static registry_ignore value_ignore_config[] = {
        { "HKEY_LOCAL_MACHINE\\Software\\Ignore", ARCH_64BIT },
        { NULL, 0 }
    };
    registry_ignore *saved_value_ignore = syscheck.value_ignore;
    syscheck.value_ignore = value_ignore_config;

    syscheck.registry = default_config;
    syscheck.registry[2].opts = CHECK_MD5SUM;

    wchar_t *value_name = L"IgnoredValue";
    DWORD value_data = 123;

    expect_RegEnumValueW_call(value_name, REG_DWORD, (LPBYTE)&value_data, sizeof(DWORD), ERROR_SUCCESS);

    expect_any(__wrap__mdebug2, formatted_msg);

    fim_read_values(key_handle, path, arch, value_count, max_value_length, max_value_data_length,
                    mock_txn_handler, &txn_ctx);

    assert_null(txn_ctx.data);
    syscheck.value_ignore = saved_value_ignore;
}

static void test_fim_read_values_reg_qword(void **state) {
    HKEY key_handle = (HKEY)123;
    char *path = "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile";
    int arch = ARCH_64BIT;
    DWORD value_count = 1;
    DWORD max_value_length = 256;
    DWORD max_value_data_length = 256;
    TXN_HANDLE mock_txn_handler = (TXN_HANDLE)456;
    event_data_t event_data = {.mode = FIM_SCHEDULED};
    fim_val_txn_context_t txn_ctx = {
        .data = NULL,
        .evt_data = &event_data,
        .diff = NULL,
        .config = NULL,
        .failed_values = NULL,
        .pending_sync_updates = NULL
    };

    syscheck.registry = one_entry_config;
    syscheck.registry[0].opts = CHECK_MD5SUM | CHECK_SHA256SUM;

    wchar_t *value_name = L"QwordValue";
    unsigned long long value_data = 0x123456789ABCDEF0ULL;

    expect_RegEnumValueW_call(value_name, REG_QWORD, (LPBYTE)&value_data, sizeof(unsigned long long), ERROR_SUCCESS);
    will_return(__wrap_fim_db_transaction_sync_row, 0);

    fim_read_values(key_handle, path, arch, value_count, max_value_length, max_value_data_length,
                    mock_txn_handler, &txn_ctx);

    // Data verification omitted - txn_ctx.data points to freed stack memory
}

static void test_fim_read_values_unknown_type(void **state) {
    HKEY key_handle = (HKEY)123;
    char *path = "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile";
    int arch = ARCH_64BIT;
    DWORD value_count = 1;
    DWORD max_value_length = 256;
    DWORD max_value_data_length = 256;
    TXN_HANDLE mock_txn_handler = (TXN_HANDLE)456;
    event_data_t event_data = {.mode = FIM_SCHEDULED};
    fim_val_txn_context_t txn_ctx = {
        .data = NULL,
        .evt_data = &event_data,
        .diff = NULL,
        .config = NULL,
        .failed_values = NULL,
        .pending_sync_updates = NULL
    };

    syscheck.registry = one_entry_config;
    syscheck.registry[0].opts = CHECK_MD5SUM;

    wchar_t *value_name = L"UnknownTypeValue";
    DWORD value_data = 0;
    DWORD unknown_type = 100;

    expect_RegEnumValueW_call(value_name, unknown_type, (LPBYTE)&value_data, sizeof(DWORD), ERROR_SUCCESS);
    will_return(__wrap_fim_db_transaction_sync_row, 0);

    fim_read_values(key_handle, path, arch, value_count, max_value_length, max_value_data_length,
                    mock_txn_handler, &txn_ctx);

    // Data verification omitted - txn_ctx.data points to freed stack memory
}

int main(void) {
    const struct CMUnitTest tests[] = {
        /* fim_set_root_key test */
        cmocka_unit_test(test_fim_set_root_key_null_root_key),
        cmocka_unit_test(test_fim_set_root_key_null_full_key),
        cmocka_unit_test(test_fim_set_root_key_null_sub_key),
        cmocka_unit_test(test_fim_set_root_key_invalid_key),
        cmocka_unit_test(test_fim_set_root_key_invalid_root_key),
        cmocka_unit_test(test_fim_set_root_key_valid_HKEY_LOCAL_MACHINE_key),
        cmocka_unit_test(test_fim_set_root_key_valid_HKEY_CLASSES_ROOT_key),
        cmocka_unit_test(test_fim_set_root_key_valid_HKEY_CURRENT_CONFIG_key),
        cmocka_unit_test(test_fim_set_root_key_valid_HKEY_USERS_key),

        /* fim_registry_configuration tests */
        cmocka_unit_test(test_fim_registry_configuration_registry_found),
        cmocka_unit_test(test_fim_registry_configuration_registry_not_found_arch_does_not_match),
        cmocka_unit_test(test_fim_registry_configuration_registry_not_found_path_does_not_match),
        cmocka_unit_test(test_fim_registry_configuration_null_key),

        /* fim_registry_validate_recursion_level tests */
        cmocka_unit_test(test_fim_registry_validate_recursion_level_null_configuration),
        cmocka_unit_test(test_fim_registry_validate_recursion_level_null_entry_path),
        cmocka_unit_test(test_fim_registry_validate_recursion_level_valid_entry_path),
        cmocka_unit_test(test_fim_registry_validate_recursion_level_invalid_recursion_level),

        /* fim_registry_validate_ignore tests */
        cmocka_unit_test(test_fim_registry_validate_ignore_null_configuration),
        cmocka_unit_test(test_fim_registry_validate_ignore_null_entry_path),
        cmocka_unit_test(test_fim_registry_validate_ignore_valid_entry_path),
        cmocka_unit_test(test_fim_registry_validate_ignore_ignore_entry),
        cmocka_unit_test(test_fim_registry_validate_ignore_regex_ignore_entry),

        /* fim_registry_get_key_data tests */
        cmocka_unit_test(test_fim_registry_get_key_data_check_owner),
        cmocka_unit_test(test_fim_registry_get_key_data_check_group),
        cmocka_unit_test(test_fim_registry_get_key_data_check_perm),
        cmocka_unit_test(test_fim_registry_get_key_data_check_mtime),

        /* fim_registry_calculate_hashes tests */
        cmocka_unit_test_setup_teardown(test_fim_registry_calculate_hashes_CHECK_MD5SUM, setup_test_hashes, teardown_test_hashes),
        cmocka_unit_test_setup_teardown(test_fim_registry_calculate_hashes_CHECK_SHA1SUM, setup_test_hashes, teardown_test_hashes),
        cmocka_unit_test_setup_teardown(test_fim_registry_calculate_hashes_CHECK_SHA256SUM, setup_test_hashes, teardown_test_hashes),
        cmocka_unit_test_setup_teardown(test_fim_registry_calculate_hashes_default_type, setup_test_hashes, teardown_test_hashes),
        cmocka_unit_test_setup_teardown(test_fim_registry_calculate_hashes_no_config, setup_test_hashes, teardown_test_hashes),

        /* UTF-16 to UTF-8 conversion tests for Issue #33371 */
        cmocka_unit_test_setup_teardown(test_fim_registry_calculate_hashes_utf16_conversion, setup_test_hashes, teardown_test_hashes),
        cmocka_unit_test_setup_teardown(test_fim_registry_calculate_hashes_utf16_multi_sz, setup_test_hashes, teardown_test_hashes),
        cmocka_unit_test(test_fim_registry_convert_value_for_diff_reg_sz_success),
        cmocka_unit_test(test_fim_registry_convert_value_for_diff_reg_expand_sz_success),
        cmocka_unit_test(test_fim_registry_convert_value_for_diff_reg_multi_sz_success),
        cmocka_unit_test(test_fim_registry_convert_value_for_diff_reg_dword),

        /* fim_registry_scan tests */
        cmocka_unit_test(test_fim_registry_scan_base_line_generation),
        cmocka_unit_test(test_fim_registry_scan_regular_scan),
        cmocka_unit_test(test_fim_registry_scan_RegOpenKeyExW_fail),
        cmocka_unit_test(test_fim_registry_scan_RegQueryInfoKey_fail),

        /* fim registry key transaction callback tests */
        cmocka_unit_test(test_fim_registry_key_transaction_callback_empty_changed_attributes),
        cmocka_unit_test(test_fim_registry_key_transaction_callback_empty_json_array),
        cmocka_unit_test(test_fim_registry_key_transaction_callback_base_line),
        cmocka_unit_test(test_fim_registry_key_transaction_callback_null_configuration),
        cmocka_unit_test(test_fim_registry_key_transaction_callback_insert),
        cmocka_unit_test(test_fim_registry_key_transaction_callback_modify),
        cmocka_unit_test(test_fim_registry_key_transaction_callback_delete),
        cmocka_unit_test(test_fim_registry_key_transaction_callback_max_rows),

        /* fim registry value transaction callback tests */
        cmocka_unit_test(test_fim_registry_value_transaction_callback_empty_changed_attributes),
        cmocka_unit_test(test_fim_registry_value_transaction_callback_empty_json_array),
        cmocka_unit_test(test_fim_registry_value_transaction_callback_base_line),
        cmocka_unit_test(test_fim_registry_value_transaction_callback_null_configuration),
        cmocka_unit_test(test_fim_registry_value_transaction_callback_insert),
        cmocka_unit_test(test_fim_registry_value_transaction_callback_modify),
        cmocka_unit_test(test_fim_registry_value_transaction_callback_modify_with_diff),
        cmocka_unit_test(test_fim_registry_value_transaction_callback_delete),
        cmocka_unit_test(test_fim_registry_value_transaction_callback_max_rows),

        /* fim_registry_free_entry */
        cmocka_unit_test(test_fim_registry_free_entry),

        /* fim_read_values tests */
        cmocka_unit_test(test_fim_read_values_single_dword_value),
        cmocka_unit_test(test_fim_read_values_single_string_value),
        cmocka_unit_test(test_fim_read_values_unterminated_string_value),
        cmocka_unit_test(test_fim_read_values_unterminated_multi_string_value),
        cmocka_unit_test(test_fim_read_values_multiple_values),
        cmocka_unit_test(test_fim_read_values_zero_value_count),
        cmocka_unit_test(test_fim_read_values_RegEnumValueW_fail),
        cmocka_unit_test(test_fim_read_values_null_configuration),
        cmocka_unit_test(test_fim_read_values_arch_32bit),
        cmocka_unit_test(test_fim_read_values_with_seechanges),
        cmocka_unit_test(test_fim_read_values_db_sync_fail),
        cmocka_unit_test(test_fim_read_values_ignored_value),
        cmocka_unit_test(test_fim_read_values_reg_qword),
        cmocka_unit_test(test_fim_read_values_unknown_type)
    };

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
