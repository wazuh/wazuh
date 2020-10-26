/*
 * Copyright (C) 2015-2020, Wazuh Inc.
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
#include "../syscheckd/syscheck.h"
#include "../syscheckd/registry/registry.h"
#include "../syscheckd/db/fim_db.h"
#include "../../wrappers/common.h"

#define CHECK_REGISTRY_ALL                                                                             \
    CHECK_SIZE | CHECK_PERM | CHECK_OWNER | CHECK_GROUP | CHECK_MTIME | CHECK_MD5SUM | CHECK_SHA1SUM | \
    CHECK_SHA256SUM | CHECK_SEECHANGES | CHECK_TYPE

char inv_hKey[50];

static registry default_config[] = {
    { "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL, NULL },
    { "HKEY_LOCAL_MACHINE\\Software\\RecursionLevel0", ARCH_64BIT, CHECK_REGISTRY_ALL, 0, 0, NULL, NULL, NULL },
    { "HKEY_LOCAL_MACHINE\\Software\\Ignore", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL, NULL },
    { inv_hKey, ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL, NULL },
    { NULL, 0, 0, 320, 0, NULL, NULL, NULL }
};

static registry one_entry_config[] = {
    { "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile", ARCH_64BIT, CHECK_REGISTRY_ALL, 320, 0, NULL, NULL, NULL }
};

static registry_ignore default_ignore[] = { { "HKEY_LOCAL_MACHINE\\Software\\Ignore", ARCH_32BIT},
                                            { "HKEY_LOCAL_MACHINE\\Software\\Ignore", ARCH_64BIT},
                                            { NULL, 0} };

static char *default_ignore_regex_patterns[] = { "IgnoreRegex", "IgnoreRegex", NULL };

static registry_ignore_regex default_ignore_regex[] = { { NULL, ARCH_32BIT }, { NULL, ARCH_64BIT }, { NULL, 0 } };

static registry empty_config[] = { { NULL, 0, 0, 320, 0, NULL, NULL, NULL } };

extern int _base_line;

int fim_set_root_key(HKEY *root_key_handle, const char *full_key, const char **sub_key);
registry *fim_registry_configuration(const char *key, int arch);
int fim_registry_validate_recursion_level(const char *key_path, const registry *configuration);
int fim_registry_validate_ignore(const char *entry, const registry *configuration, int key);
void fim_registry_free_key(fim_registry_key *key);
void fim_registry_free_value_data(fim_registry_value_data *data);
fim_registry_key *fim_registry_get_key_data(HKEY key_handle, const char *path, const registry *configuration);
void fim_registry_calculate_hashes(fim_entry *entry, registry *configuration, BYTE *data_buffer);

void expect_RegOpenKeyEx_call(HKEY hKey, LPCSTR sub_key, DWORD options, REGSAM sam, PHKEY result, LONG return_value) {
    expect_value(wrap_RegOpenKeyEx, hKey, hKey);
    expect_string(wrap_RegOpenKeyEx, lpSubKey, sub_key);
    expect_value(wrap_RegOpenKeyEx, ulOptions, options);
    expect_value(wrap_RegOpenKeyEx, samDesired, sam);
    will_return(wrap_RegOpenKeyEx, result);
    will_return(wrap_RegOpenKeyEx, return_value);
}

void expect_RegQueryInfoKey_call(DWORD sub_keys, DWORD values, PFILETIME last_write_time, LONG return_value) {
    will_return(wrap_RegQueryInfoKey, sub_keys);
    will_return(wrap_RegQueryInfoKey, values);
    will_return(wrap_RegQueryInfoKey, last_write_time);
    will_return(wrap_RegQueryInfoKey, return_value);
}

void expect_RegQueryInfoKeyA_call(PFILETIME last_write_time, LONG return_value) {
    will_return(wrap_RegQueryInfoKeyA, last_write_time);
    will_return(wrap_RegQueryInfoKeyA, return_value);
}

void expect_RegEnumKeyEx_call(LPSTR name, DWORD name_length, LONG return_value) {
    will_return(wrap_RegEnumKeyEx, name);
    will_return(wrap_RegEnumKeyEx, name_length);
    will_return(wrap_RegEnumKeyEx, return_value);
}

void expect_RegEnumValue_call(LPSTR value_name, DWORD type, LPBYTE data, DWORD data_length, LONG return_value) {
    will_return(wrap_RegEnumValue, value_name);
    will_return(wrap_RegEnumValue, strlen(value_name));
    will_return(wrap_RegEnumValue, type);
    will_return(wrap_RegEnumValue, data_length);
    will_return(wrap_RegEnumValue, data);
    will_return(wrap_RegEnumValue, return_value);
}

void expect_SendMSG_call(const char *message_expected, const char *locmsg_expected, char loc_expected, int ret){
    expect_string(__wrap_SendMSG, message, message_expected);
    expect_string(__wrap_SendMSG, locmsg, locmsg_expected);
    expect_value(__wrap_SendMSG, loc, loc_expected);
    will_return(__wrap_SendMSG, ret);
}

void expect_GetSecurityInfo_call(PSID ppsidOwner, PSID pSidGroup, DWORD ret_value){
    if (ppsidOwner) will_return(wrap_GetSecurityInfo, ppsidOwner);
    if (pSidGroup) will_return(wrap_GetSecurityInfo, pSidGroup);
    will_return(wrap_GetSecurityInfo, ret_value);
}

void expect_ConvertSidToStringSid_call(LPSTR StringSid, int ret_value){
    will_return(wrap_ConvertSidToStringSid, StringSid);
    will_return(wrap_ConvertSidToStringSid, ret_value);
}

void expect_LookupAccountSid_call(char *name, char *DomainName, int ret_value){
    will_return(wrap_LookupAccountSid, name);
    will_return(wrap_LookupAccountSid, DomainName);
    will_return(wrap_LookupAccountSid, ret_value);
}

void expect_RegGetKeySecurity_call(LPDWORD lpcbSecurityDescriptor, int ret_value){
    will_return(wrap_RegGetKeySecurity, lpcbSecurityDescriptor);
    will_return(wrap_RegGetKeySecurity, ret_value);
}

void expect_GetSecurityDescriptorDacl_call(int fDaclPresent, PACL *pDacl, int ret_value){
    will_return(wrap_GetSecurityDescriptorDacl, fDaclPresent);
    will_return(wrap_GetSecurityDescriptorDacl, pDacl);
    will_return(wrap_GetSecurityDescriptorDacl, ret_value);
}

void expect_GetAclInformation_call(LPVOID pAclInformation, int ret_value){
    will_return(wrap_GetAclInformation, pAclInformation);
    will_return(wrap_GetAclInformation, ret_value);
}

void expect_GetAce_call(LPVOID *pAce, int ret_value){
    will_return(wrap_GetAce, pAce);
    will_return(wrap_GetAce, ret_value);
}

void expect_fim_registry_get_key_data_call(LPSTR usid, LPSTR gsid, char *uname, char *gname,
                                           ACL_SIZE_INFORMATION acl_size, ACCESS_ALLOWED_ACE ace,
                                           FILETIME last_write_time) {
    expect_GetSecurityInfo_call((PSID)"userid", NULL, ERROR_SUCCESS);
    expect_ConvertSidToStringSid_call(usid, 1);
    expect_LookupAccountSid_call((PSID)uname, "domain", 1);

    expect_GetSecurityInfo_call(NULL, (PSID)"groupid", ERROR_SUCCESS);
    expect_ConvertSidToStringSid_call(gsid, 1);
    expect_LookupAccountSid_call((PSID)gname, "domain", 1);

    expect_RegGetKeySecurity_call((LPDWORD)120, ERROR_INSUFFICIENT_BUFFER);
    expect_RegGetKeySecurity_call((LPDWORD)120, ERROR_SUCCESS);

    expect_GetSecurityDescriptorDacl_call(TRUE, (PACL*)123456, TRUE);

    expect_GetAclInformation_call(&acl_size, TRUE);

    expect_GetAce_call((LPVOID)&ace, TRUE);

    expect_LookupAccountSid_call((PSID)"sid", "domain", 1);
    expect_LookupAccountSid_call((PSID)"sid", "domain", 1);

    will_return(wrap_IsValidSid, 1);

    expect_RegQueryInfoKeyA_call(&last_write_time, ERROR_SUCCESS);
}

int check_fim_db_reg_key(fim_registry_key *key_to_check){
    fim_registry_key *key_saved = fim_db_get_registry_key(syscheck.database, key_to_check->path, key_to_check->arch);
    if(!key_saved){
        return -1;
    }

    assert_string_equal(key_saved->perm, key_to_check->perm);
    assert_string_equal(key_saved->uid, key_to_check->uid);
    assert_string_equal(key_saved->gid, key_to_check->gid);
    assert_string_equal(key_saved->user_name, key_to_check->user_name);
    assert_string_equal(key_saved->group_name, key_to_check->group_name);

    fim_registry_free_key(key_saved);

    return 0;
}

int check_fim_db_reg_value_data(const char *data_name, unsigned int type, unsigned int size, const char *key_name, int key_arch){
    fim_registry_key *reg_key = fim_db_get_registry_key(syscheck.database, key_name, key_arch);
    assert_non_null(reg_key);

    fim_registry_value_data *value_saved = fim_db_get_registry_data(syscheck.database, reg_key->id, data_name);
    if(!value_saved){
        fim_registry_free_key(reg_key);
        return -1;
    }

    assert_string_equal(value_saved->name, data_name);
    assert_int_equal(value_saved->type, type);
    assert_int_equal(value_saved->size, size);

    fim_registry_free_key(reg_key);
    fim_registry_free_value_data(value_saved);

    return 0;
}

fim_registry_key *create_reg_key(const char *path, int arch, const char *perm, const char *uid, const char *gid, const char *user_name,
                                 const char *group_name) {
    fim_registry_key *ret;

    os_calloc(1, sizeof(fim_registry_key), ret);

    ret->id = 0;
    os_strdup(path, ret->path);
    ret->arch = arch;
    os_strdup(perm, ret->perm);
    os_strdup(uid, ret->uid);
    os_strdup(gid, ret->gid);
    os_strdup(user_name, ret->user_name);
    os_strdup(group_name, ret->group_name);

    return ret;
}

static int setup_group(void **state) {
    int i;
    time_mock_value = 12345;
    strcpy(inv_hKey, "HKEY_LOCAL_MACHINE_Invalid_key\\Software\\Ignore");

    syscheck.registry = default_config;
    syscheck.key_ignore = default_ignore;

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

    // Init database
    syscheck.database = fim_db_init(0);

    return 0;
}

static int teardown_group(void **state) {
    int i;

    syscheck.registry = NULL;
    syscheck.key_ignore = NULL;

    for (i = 0; syscheck.key_ignore_regex[i].regex; i++) {
        OSMatch_FreePattern(syscheck.key_ignore_regex[i].regex);
    }
    syscheck.key_ignore_regex = NULL;

    // Close database
    expect_string(__wrap__mdebug1, formatted_msg, "Database transaction completed.");
    fim_db_close(syscheck.database);
    fim_db_clean();

    return 0;
}

static int setup_remove_entries(void **state) {
    syscheck.registry = empty_config;

    return 0;
}

static int teardown_restore_scan(void **state) {
    syscheck.registry = default_config;

    _base_line = 0;

    return 0;
}

static int setup_base_line(void **state) {
    syscheck.registry = one_entry_config;
    syscheck.registry[0].opts = CHECK_REGISTRY_ALL;

    fim_registry_key **keys_array = calloc(3, sizeof(fim_registry_key*));
    if(keys_array == NULL)
        return -1;

    keys_array[0] = create_reg_key("HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile", 1,
                                   "sid (allowed): delete|write_dac|write_data|append_data|write_attributes",
                                   "userid", "groupid", "username", "groupname");
    keys_array[1] = create_reg_key("HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile\\FirstSubKey", 1,
                                   "sid (allowed): delete|write_dac|write_data|append_data|write_attributes",
                                   "userid", "groupid", "username", "groupname");
    keys_array[2] = NULL;

    _base_line = 0;
    *state = keys_array;
    return 0;
}

static int teardown_clean_db_and_state(void **state) {
    char *err_msg = NULL;
    fim_registry_key **keys_array = *state;

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

    // Free state
    if (keys_array){
        // Temporary
        for (int i = 0; keys_array[i]; ++i) {
            fim_registry_free_key(keys_array[i]);
            free(keys_array[i]);
        }
        free(keys_array);
        keys_array = NULL;
    }

    return 0;
}

static int setup_regular_scan(void **state) {
    syscheck.registry = default_config;

    fim_registry_key **keys_array = calloc(5, sizeof(fim_registry_key*));
    if(keys_array == NULL)
        return -1;

    keys_array[0] = create_reg_key("HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile", 1,
                                   "sid (allowed): delete|write_dac|write_data|append_data|write_attributes",
                                   "userid", "groupid", "username", "groupname");
    keys_array[1] = create_reg_key("HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile\\FirstSubKey", 1,
                                   "sid (allowed): delete|write_dac|write_data|append_data|write_attributes",
                                   "userid", "groupid", "username", "groupname");
    keys_array[2] = create_reg_key("HKEY_LOCAL_MACHINE\\Software\\RecursionLevel0", 1,
                                   "sid (allowed): delete|write_dac|write_data|append_data|write_attributes",
                                   "userid", "groupid", "username2", "groupname2");
    keys_array[3] = create_reg_key("HKEY_LOCAL_MACHINE\\Software\\RecursionLevel0\\depth0", 1,
                                   "sid (allowed): delete|write_dac|write_data|append_data|write_attributes",
                                   "userid", "groupid", "username2", "groupname2");
    keys_array[4] = NULL;

    _base_line = 1;
    *state = keys_array;
    return 0;
}

static int setup_test_hashes(void **state) {
    syscheck.registry = default_config;

    fim_entry *entry;
    os_calloc(1, sizeof(fim_entry), entry);

    fim_registry_key *key;
    os_calloc(1, sizeof(fim_registry_key), key);
    key->id = 3;
    os_strdup("HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile", key->path);
    os_strdup("sid (allowed): delete|write_dac|write_data|append_data|write_attributes", key->perm);
    os_strdup("100", key->uid);
    os_strdup("200", key->gid);
    os_strdup("username", key->user_name);
    os_strdup("groupname", key->group_name);
    key->arch = 1;

    fim_registry_value_data *value;
    os_calloc(1, sizeof(fim_registry_value_data), value);
    value->id = 3;
    os_strdup("valuename", value->name);
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
    registry *configuration;

    configuration = fim_registry_configuration("HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile\\something", ARCH_64BIT);
    assert_non_null(configuration);
    assert_string_equal(configuration->entry, "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile");
    assert_int_equal(configuration->arch, ARCH_64BIT);
}

static void test_fim_registry_configuration_registry_not_found_arch_does_not_match(void **state) {
    registry *configuration;

    expect_any_always(__wrap__mdebug2, formatted_msg);

    configuration = fim_registry_configuration("HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile\\something", ARCH_32BIT);
    assert_null(configuration);
}

static void test_fim_registry_configuration_registry_not_found_path_does_not_match(void **state) {
    registry *configuration;

    expect_any_always(__wrap__mdebug2, formatted_msg);

    configuration = fim_registry_configuration("HKEY_LOCAL_MACHINE\\Software\\Classes\\something", ARCH_64BIT);
    assert_null(configuration);
}

static void test_fim_registry_configuration_null_key(void **state) {
    registry *configuration;

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
    registry *configuration = &syscheck.registry[0];
    int ret;

    ret = fim_registry_validate_recursion_level(NULL, configuration);

    assert_int_equal(ret, -1);
}

static void test_fim_registry_validate_recursion_level_valid_entry_path(void **state) {
    char *path = "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile\\Some\\valid\\path";
    registry *configuration = &syscheck.registry[0];
    int ret;

    ret = fim_registry_validate_recursion_level(path, configuration);

    assert_int_equal(ret, 0);
}

static void test_fim_registry_validate_recursion_level_invalid_recursion_level(void **state) {
    char *path = "HKEY_LOCAL_MACHINE\\Software\\RecursionLevel0\\This\\must\\fail";
    registry *configuration = &syscheck.registry[1];
    int ret;
    expect_string(__wrap__mdebug2, formatted_msg, "(6217): Maximum level of recursion reached. Depth:2 recursion_level:0 'HKEY_LOCAL_MACHINE\\Software\\RecursionLevel0\\This\\must\\fail'");

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
    registry *configuration = &syscheck.registry[0];
    int ret;

    ret = fim_registry_validate_ignore(NULL, configuration, 1);

    assert_int_equal(ret, -1);
}

static void test_fim_registry_validate_ignore_valid_entry_path(void **state) {
    char *path = "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile\\Some\\valid\\path";
    registry *configuration = &syscheck.registry[0];
    int ret;

    ret = fim_registry_validate_ignore(path, configuration, 1);

    assert_int_equal(ret, 0);
}

static void test_fim_registry_validate_ignore_ignore_entry(void **state) {
    char *path = "HKEY_LOCAL_MACHINE\\Software\\Ignore";
    registry *configuration = &syscheck.registry[2];
    int ret;

    expect_string(__wrap__mdebug2, formatted_msg, "(6204): Ignoring 'registry' 'HKEY_LOCAL_MACHINE\\Software\\Ignore' due to 'HKEY_LOCAL_MACHINE\\Software\\Ignore'");

    ret = fim_registry_validate_ignore(path, configuration, 1);

    assert_int_equal(ret, -1);
}

static void test_fim_registry_validate_ignore_regex_ignore_entry(void **state) {
    char *path = "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile\\IgnoreRegex\\This\\must\\fail";
    registry *configuration = &syscheck.registry[0];
    int ret;

    expect_string(__wrap__mdebug2, formatted_msg, "(6205): Ignoring 'registry' 'HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile\\IgnoreRegex\\This\\must\\fail' due to sregex 'IgnoreRegex'");

    ret = fim_registry_validate_ignore(path, configuration, 1);

    assert_int_equal(ret, -1);
}

static void test_fim_registry_get_key_data_check_owner(void **state) {
    char *path = "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile";
    syscheck.registry = one_entry_config;
    registry *configuration = &syscheck.registry[0];
    configuration->opts = CHECK_OWNER;
    HKEY key_handle = HKEY_LOCAL_MACHINE;
    fim_registry_key *ret_key;

    expect_GetSecurityInfo_call((PSID)"userid", NULL, ERROR_SUCCESS);
    expect_ConvertSidToStringSid_call((LPSTR)"userid", 1);
    expect_LookupAccountSid_call((PSID)"username", "domain", 1);

    ret_key = fim_registry_get_key_data(key_handle, path, configuration);

    assert_string_equal(ret_key->uid, "userid");
    assert_string_equal(ret_key->user_name, "username");
    assert_null(ret_key->gid);
    assert_null(ret_key->group_name);
    assert_null(ret_key->perm);
    assert_null(ret_key->mtime);
}

static void test_fim_registry_get_key_data_check_group(void **state) {
    char *path = "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile";
    syscheck.registry = one_entry_config;
    registry *configuration = &syscheck.registry[0];
    configuration->opts = CHECK_GROUP;
    HKEY key_handle = HKEY_LOCAL_MACHINE;
    fim_registry_key *ret_key;

    expect_GetSecurityInfo_call((PSID)"groupid", NULL, ERROR_SUCCESS);
    expect_ConvertSidToStringSid_call((LPSTR)"groupid", 1);
    expect_LookupAccountSid_call((PSID)"groupname", "domain", 1);

    ret_key = fim_registry_get_key_data(key_handle, path, configuration);

    assert_null(ret_key->uid);
    assert_null(ret_key->user_name);
    assert_string_equal(ret_key->gid, "groupid");
    assert_string_equal(ret_key->group_name, "groupname");
    assert_null(ret_key->perm);
    assert_null(ret_key->mtime);
}

static void test_fim_registry_get_key_data_check_perm(void **state) {
    char *path = "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile";
    syscheck.registry = one_entry_config;
    registry *configuration = &syscheck.registry[0];
    configuration->opts = CHECK_PERM;
    HKEY key_handle = HKEY_LOCAL_MACHINE;
    fim_registry_key *ret_key;
    ACL_SIZE_INFORMATION acl_size = { .AceCount = 1 };

    // Set the ACE data
    ACCESS_ALLOWED_ACE ace;
    ace.Header.AceType = ACCESS_ALLOWED_ACE_TYPE;
    ace.Header.AceFlags = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE | SUCCESSFUL_ACCESS_ACE_FLAG;
    ace.Mask = FILE_WRITE_DATA | WRITE_DAC | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | DELETE;

    expect_RegGetKeySecurity_call((LPDWORD)120, ERROR_INSUFFICIENT_BUFFER);
    expect_RegGetKeySecurity_call((LPDWORD)120, ERROR_SUCCESS);

    expect_GetSecurityDescriptorDacl_call(TRUE, (PACL*)123456, TRUE);

    expect_GetAclInformation_call(&acl_size, TRUE);

    expect_GetAce_call((LPVOID)&ace, TRUE);

    expect_LookupAccountSid_call((PSID)"sid", "domain", 1);
    expect_LookupAccountSid_call((PSID)"sid", "domain", 1);

    will_return(wrap_IsValidSid, 1);

    ret_key = fim_registry_get_key_data(key_handle, path, configuration);

    assert_null(ret_key->uid);
    assert_null(ret_key->user_name);
    assert_null(ret_key->gid);
    assert_null(ret_key->group_name);
    assert_string_equal(ret_key->perm, "sid (allowed): delete|write_dac|write_data|append_data|write_attributes");
    assert_null(ret_key->mtime);
}

static void test_fim_registry_get_key_data_check_mtime(void **state) {
    char *path = "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile";
    syscheck.registry = one_entry_config;
    registry *configuration = &syscheck.registry[0];
    configuration->opts = CHECK_MTIME;
    HKEY key_handle = HKEY_LOCAL_MACHINE;
    fim_registry_key *ret_key;
    FILETIME last_write_time = { 0, 1000 };

    expect_RegQueryInfoKeyA_call(&last_write_time, ERROR_SUCCESS);

    ret_key = fim_registry_get_key_data(key_handle, path, configuration);

    assert_null(ret_key->uid);
    assert_null(ret_key->user_name);
    assert_null(ret_key->gid);
    assert_null(ret_key->group_name);
    assert_null(ret_key->perm);
    assert_int_equal(ret_key->mtime, 1240857784);
}

static void test_fim_registry_calculate_hashes_CHECK_MD5SUM(void **state) {
    fim_entry *entry = *state;

    syscheck.registry = one_entry_config;
    registry *configuration = &syscheck.registry[0];
    configuration->opts = CHECK_MD5SUM;
    BYTE *data_buffer = (unsigned char *)"value_data";
    entry->registry_entry.value->type = REG_EXPAND_SZ;

    fim_registry_calculate_hashes(entry, configuration, data_buffer);

    assert_string_equal(entry->registry_entry.value->hash_md5, "51718cc02664f7b131b76f8b53918927");
    assert_string_equal(entry->registry_entry.value->hash_sha1, "");
    assert_string_equal(entry->registry_entry.value->hash_sha256, "");
    assert_string_equal(entry->registry_entry.value->checksum, "1234567890ABCDEF1234567890ABCDEF12345678");
}

static void test_fim_registry_calculate_hashes_CHECK_SHA1SUM(void **state) {
    fim_entry *entry = *state;

    syscheck.registry = one_entry_config;
    registry *configuration = &syscheck.registry[0];
    configuration->opts = CHECK_SHA1SUM;
    BYTE *data_buffer = (unsigned char *)"value_data";
    entry->registry_entry.value->type = REG_MULTI_SZ;

    fim_registry_calculate_hashes(entry, configuration, data_buffer);


    assert_string_equal(entry->registry_entry.value->hash_md5, "");
    assert_string_equal(entry->registry_entry.value->hash_sha1, "ee6cf811813827f6e18d07f0fb7e22a43337d63c");
    assert_string_equal(entry->registry_entry.value->hash_sha256, "");
    assert_string_equal(entry->registry_entry.value->checksum, "1234567890ABCDEF1234567890ABCDEF12345678");
}

static void test_fim_registry_calculate_hashes_CHECK_SHA256SUM(void **state) {
    fim_entry *entry = *state;

    syscheck.registry = one_entry_config;
    registry *configuration = &syscheck.registry[0];
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
    registry *configuration = &syscheck.registry[0];
    configuration->opts = CHECK_REGISTRY_ALL;
    BYTE *data_buffer = (unsigned char *)"value_data";
    entry->registry_entry.value->type = -1;

    fim_registry_calculate_hashes(entry, configuration, data_buffer);


    assert_string_equal(entry->registry_entry.value->hash_md5, "d41d8cd98f00b204e9800998ecf8427e");
    assert_string_equal(entry->registry_entry.value->hash_sha1, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    assert_string_equal(entry->registry_entry.value->hash_sha256, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert_string_equal(entry->registry_entry.value->checksum, "1234567890ABCDEF1234567890ABCDEF12345678");
}

static void test_fim_registry_scan_no_entries_configured(void **state) {
    expect_string(__wrap__mdebug1, formatted_msg, FIM_WINREGISTRY_START);
    expect_string(__wrap__mdebug1, formatted_msg, FIM_WINREGISTRY_ENDED);

    fim_registry_scan();

    assert_int_equal(_base_line, 1);
}

static void test_fim_registry_scan_base_line_generation(void **state) {
    fim_registry_key **keys_array = *state;
    int ret = 0;
    ACL_SIZE_INFORMATION acl_size = { .AceCount = 1 };
    ACCESS_ALLOWED_ACE ace;

    // Set the ACE data
    ace.Header.AceType = ACCESS_ALLOWED_ACE_TYPE;
    ace.Header.AceFlags = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE | SUCCESSFUL_ACCESS_ACE_FLAG;
    ace.Mask = FILE_WRITE_DATA | WRITE_DAC | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | DELETE;

    // Set value of FirstSubKey
    char value_name[10] = "valuename";
    unsigned int value_type = REG_DWORD;
    unsigned int value_size = 4;
    DWORD value_data = 123456;

    LPSTR usid = "userid";
    LPSTR gsid = "groupid";
    FILETIME last_write_time = { 0, 1000 };

    expect_string(__wrap__mdebug1, formatted_msg, FIM_WINREGISTRY_START);
    expect_string(__wrap__mdebug1, formatted_msg, FIM_WINREGISTRY_ENDED);
    expect_any_always(__wrap__mdebug2, formatted_msg);

    // Scan a subkey of batfile
    expect_RegOpenKeyEx_call(HKEY_LOCAL_MACHINE, "Software\\Classes\\batfile", 0,
                             KEY_READ | KEY_WOW64_64KEY, NULL, ERROR_SUCCESS);
    expect_RegQueryInfoKey_call(1, 0, &last_write_time, ERROR_SUCCESS);
    expect_RegEnumKeyEx_call("FirstSubKey", 12, ERROR_SUCCESS);

    // Inside fim_registry_get_key_data
    expect_fim_registry_get_key_data_call(usid, gsid, "username", "groupname", acl_size, ace, last_write_time);

    // Scan a value of FirstSubKey
    expect_RegOpenKeyEx_call(HKEY_LOCAL_MACHINE, "Software\\Classes\\batfile\\FirstSubKey", 0,
                             KEY_READ | KEY_WOW64_64KEY, NULL, ERROR_SUCCESS);
    expect_RegQueryInfoKey_call(0, 1, &last_write_time, ERROR_SUCCESS);
    expect_RegEnumValue_call(value_name, value_type, (LPBYTE)&value_data, value_size, ERROR_SUCCESS);

    // Inside fim_registry_get_key_data
    expect_fim_registry_get_key_data_call(usid, gsid, "username", "groupname", acl_size, ace, last_write_time);

    // Test
    fim_registry_scan();
    assert_int_equal(_base_line, 1);

    // Database check
    ret = check_fim_db_reg_key(keys_array[0]);
    assert_int_equal(ret, 0);
    ret = check_fim_db_reg_key(keys_array[1]);
    assert_int_equal(ret, 0);
    ret = check_fim_db_reg_value_data("valuename", REG_DWORD, 4, keys_array[1]->path, keys_array[1]->arch);
    assert_int_equal(ret, 0);
}

static void test_fim_registry_scan_regular_scan(void **state) {
    fim_registry_key **keys_array = *state;
    int ret = 0;
    ACL_SIZE_INFORMATION acl_size = { .AceCount = 1 };
    ACCESS_ALLOWED_ACE ace;

    // Set the ACE data
    ace.Header.AceType = ACCESS_ALLOWED_ACE_TYPE;
    ace.Header.AceFlags = CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE | SUCCESSFUL_ACCESS_ACE_FLAG;
    ace.Mask = FILE_WRITE_DATA | WRITE_DAC | FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | DELETE;

    // Set value of FirstSubKey
    char value_name[10] = "valuename";
    unsigned int value_type = REG_DWORD;
    unsigned int value_size = 4;
    DWORD value_data = 123456;

    LPSTR usid = "userid";
    LPSTR gsid = "groupid";
    FILETIME last_write_time = { 0, 1000 };

    expect_string(__wrap__mdebug1, formatted_msg, FIM_WINREGISTRY_START);
    expect_string(__wrap__mdebug1, formatted_msg, "(6919): Invalid syscheck registry entry: 'HKEY_LOCAL_MACHINE_Invalid_key\\Software\\Ignore' arch: '[x64] '.");
    expect_string(__wrap__mdebug1, formatted_msg, FIM_WINREGISTRY_ENDED);
    expect_any_always(__wrap__mdebug2, formatted_msg);

    // Scan a subkey of batfile
    expect_RegOpenKeyEx_call(HKEY_LOCAL_MACHINE, "Software\\Classes\\batfile", 0,
                             KEY_READ | KEY_WOW64_64KEY, NULL, ERROR_SUCCESS);
    expect_RegQueryInfoKey_call(1, 0, &last_write_time, ERROR_SUCCESS);
    expect_RegEnumKeyEx_call("FirstSubKey", 12, ERROR_SUCCESS);

    // Inside fim_registry_get_key_data
    expect_fim_registry_get_key_data_call(usid, gsid, "username", "groupname", acl_size, ace, last_write_time);

    // Scan a value of FirstSubKey
    expect_RegOpenKeyEx_call(HKEY_LOCAL_MACHINE, "Software\\Classes\\batfile\\FirstSubKey", 0,
                             KEY_READ | KEY_WOW64_64KEY, NULL, ERROR_SUCCESS);
    expect_RegQueryInfoKey_call(0, 1, &last_write_time, ERROR_SUCCESS);
    expect_RegEnumValue_call(value_name, value_type, (LPBYTE)&value_data, value_size, ERROR_SUCCESS);

    // Inside fim_registry_get_key_data
    expect_fim_registry_get_key_data_call(usid, gsid, "username", "groupname", acl_size, ace, last_write_time);

    // Scan a subkey of RecursionLevel0
    expect_RegOpenKeyEx_call(HKEY_LOCAL_MACHINE, "Software\\RecursionLevel0", 0, KEY_READ | KEY_WOW64_64KEY, NULL, ERROR_SUCCESS);
    expect_RegQueryInfoKey_call(1, 0, &last_write_time, ERROR_SUCCESS);

    expect_RegEnumKeyEx_call("depth0", 7, ERROR_SUCCESS);

    // Inside fim_registry_get_key_data
    expect_fim_registry_get_key_data_call(usid, gsid, "username2", "groupname2", acl_size, ace, last_write_time);

    // Scan a subkey of depth0
    expect_RegOpenKeyEx_call(HKEY_LOCAL_MACHINE, "Software\\RecursionLevel0\\depth0", 0,
                             KEY_READ | KEY_WOW64_64KEY, NULL, ERROR_SUCCESS);
    expect_RegQueryInfoKey_call(1, 0, &last_write_time, ERROR_SUCCESS);

    expect_RegEnumKeyEx_call("depth1", 7, ERROR_SUCCESS);

    // Inside fim_registry_get_key_data
    expect_fim_registry_get_key_data_call(usid, gsid, "username2", "groupname2", acl_size, ace, last_write_time);

    // Test
    fim_registry_scan();

    // Database check
    ret = check_fim_db_reg_key(keys_array[0]);
    assert_int_equal(ret, 0);
    ret = check_fim_db_reg_key(keys_array[1]);
    assert_int_equal(ret, 0);
    ret = check_fim_db_reg_value_data("valuename", REG_DWORD, 4, keys_array[1]->path, keys_array[1]->arch);
    assert_int_equal(ret, 0);
    ret = check_fim_db_reg_key(keys_array[2]);
    assert_int_equal(ret, 0);
    ret = check_fim_db_reg_key(keys_array[3]);
    assert_int_equal(ret, 0);
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

        /* fim_registry_scan tests */
        cmocka_unit_test_setup_teardown(test_fim_registry_scan_no_entries_configured, setup_remove_entries, teardown_restore_scan),
        cmocka_unit_test_setup_teardown(test_fim_registry_scan_base_line_generation, setup_base_line, teardown_clean_db_and_state),
        cmocka_unit_test_setup_teardown(test_fim_registry_scan_regular_scan, setup_regular_scan, teardown_clean_db_and_state),
    };

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
