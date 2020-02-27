/*
 * Copyright (C) 2015-2019, Wazuh Inc.
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

#include <winsock2.h>
#include <windows.h>
#include <wtypes.h> /* HKEY */
#include<libloaderapi.h>
#include <openssl/evp.h>

#include "syscheckd/syscheck.h"

extern char *os_winreg_sethkey(char *reg_entry);
void os_winreg_querykey(HKEY hKey, char *p_key, char *full_key_name, int pos);

/**************************************************************************/
/*************************WRAPS - GROUP SETUP******************************/
int test_group_setup(void **state) {
    int ret;
    ret = Read_Syscheck_Config("test_syscheck.conf");
    return ret;
}


void __wrap__mdebug2(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

int __wrap_fim_registry_event(char *key, fim_entry_data *data, int pos) {
    return mock();
}

int __wrap_EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *data, size_t count)
{
   check_expected(data);
   check_expected(count);
   return mock();
}
/**************************************************************************/
/*************************os_winreg_sethkey********************************/
void test_os_winreg_sethkek_invalid_subtree(void **state) {
    char* entry = strdup("WRONG_SUBTREE\\Software\\Classes\\batfile");
    const char* ret = (const char *)os_winreg_sethkey(entry);
    assert_null(ret);
}

void test_os_winreg_sethkek_no_path(void **state) {
    char* entry = strdup("HKEY_LOCAL_MACHINE\\");
    const char* ret = (const char *)os_winreg_sethkey(entry);
    assert_null(ret);
}

void test_os_winreg_sethkek_valid_local_machine(void **state) {
    char* entry = strdup("HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile");
    const char* ret = (const char *)os_winreg_sethkey(entry);
    assert_string_equal(ret, "Software\\Classes\\batfile");
}

void test_os_winreg_sethkek_valid_classes_root(void **state) {
    char* entry = strdup("HKEY_CLASSES_ROOT\\Software\\Classes\\batfile");
    const char* ret = (const char *) os_winreg_sethkey(entry);
    assert_string_equal(ret, "Software\\Classes\\batfile");
}

void test_os_winreg_sethkek_valid_current_config(void **state) {
    char* entry = strdup("HKEY_CURRENT_CONFIG\\Software\\Classes\\batfile");
    const char* ret = (const char *) os_winreg_sethkey(entry);
    assert_string_equal(ret, "Software\\Classes\\batfile");
}
void test_os_winreg_sethkek_valid_users(void **state) {
    char* entry = strdup("HKEY_USERS\\Software\\Classes\\batfile");
    const char* ret = (const char *) os_winreg_sethkey(entry);
    assert_string_equal(ret, "Software\\Classes\\batfile");
}
/**************************************************************************/
/*************************os_winreg_querykey*******************************/
void test_os_winreg_querykey_invalid_query(void **state) {
    HKEY oshkey;
    char *subkey = strdup("command");
    char *fullname = strdup("HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile\\shell\\open\\command");
    int pos = 0;

    will_return_count(wrap_RegQueryInfoKey, NULL, 5);
    will_return(wrap_RegQueryInfoKey,-1);
    os_winreg_querykey(oshkey, subkey, fullname, pos);
}

void test_os_winreg_querykey_success_no_subkey(void **state) {
    HKEY oshkey;
    char *subkey = strdup("command");
    char *fullname = strdup("HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile\\shell\\open\\command");
    int pos = 0;

    will_return(wrap_RegQueryInfoKey, NULL); // class_name_b
    will_return(wrap_RegQueryInfoKey, NULL); // class_name_s
    will_return(wrap_RegQueryInfoKey, 0); // subkey_count 
    will_return(wrap_RegQueryInfoKey, 0); // value_count
    will_return(wrap_RegQueryInfoKey, 0); // file_time 
    will_return(wrap_RegQueryInfoKey,ERROR_SUCCESS);
    os_winreg_querykey(oshkey, subkey, fullname, pos);
}

void test_os_winreg_querykey_success_subkey_p_key(void **state) {
    HKEY oshkey;
    char *subkey = strdup("command");
    char *fullname = strdup("HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile\\shell\\open\\command");
    int pos = 0;

    will_return(wrap_RegQueryInfoKey, NULL); // class_name_b
    will_return(wrap_RegQueryInfoKey, NULL); // class_name_s
    will_return(wrap_RegQueryInfoKey, 1); // subkey_count 
    will_return(wrap_RegQueryInfoKey, 0); // value_count
    will_return(wrap_RegQueryInfoKey, 0); // file_time 
    will_return(wrap_RegQueryInfoKey,ERROR_SUCCESS);

    will_return(wrap_RegEnumKeyEx, "SUBKEY_NAME");
    will_return(wrap_RegEnumKeyEx, strlen("SUBKEY_NAME"));
    will_return(wrap_RegEnumKeyEx, ERROR_SUCCESS);

    // Shutdown os_winreg_open_key
    will_return(wrap_RegOpenKeyEx, -1);

    os_winreg_querykey(oshkey, subkey, fullname, pos);
}

void test_os_winreg_querykey_ignored_registry(void **state) {
    HKEY oshkey;
    int pos = 0;
    char *subkey = strdup("command");
    char *fullname = syscheck.registry_ignore[pos].entry;

    will_return(wrap_RegQueryInfoKey, NULL); // class_name_b
    will_return(wrap_RegQueryInfoKey, NULL); // class_name_s
    will_return(wrap_RegQueryInfoKey, 0); // subkey_count 
    will_return(wrap_RegQueryInfoKey, 0); // value_count
    will_return(wrap_RegQueryInfoKey, 0); // file_time 
    will_return(wrap_RegQueryInfoKey,ERROR_SUCCESS);

    char debug_msg[OS_MAXSTR];
    snprintf(debug_msg, OS_MAXSTR, "(6204): Ignoring 'registry' '%s' due to '%s'", fullname, fullname);
    expect_string(__wrap__mdebug2, formatted_msg, debug_msg);
    os_winreg_querykey(oshkey, subkey, fullname, pos);
}

void test_os_winreg_querykey_ignored_regex(void **state) {
    HKEY oshkey;
    int pos = 0;
    char *subkey = strdup("command");
    char *fullname = strdup("HKEY_LOCAL_MACHINE\\Security\\Enum"); // <registry_ignore type="sregex">\Enum$</registry_ignore>

    will_return(wrap_RegQueryInfoKey, NULL); // class_name_b
    will_return(wrap_RegQueryInfoKey, NULL); // class_name_s
    will_return(wrap_RegQueryInfoKey, 0); // subkey_count 
    will_return(wrap_RegQueryInfoKey, 0); // value_count
    will_return(wrap_RegQueryInfoKey, 0); // file_time 
    will_return(wrap_RegQueryInfoKey,ERROR_SUCCESS);

    char debug_msg[OS_MAXSTR];
    snprintf(debug_msg, OS_MAXSTR,"(6205): Ignoring 'registry' '%s' due to sregex '\\Enum$'", fullname, fullname);
    expect_string(__wrap__mdebug2, formatted_msg, debug_msg);
    os_winreg_querykey(oshkey, subkey, fullname, pos);
}

void test_os_winreg_querykey_values_string(void **state) {
    HKEY oshkey;
    int pos = 0;
    char *subkey = strdup("command");
    char *fullname = strdup("HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile\\shell\\open\\command"); // <registry_ignore type="sregex">\Enum$</registry_ignore>

    will_return(wrap_RegQueryInfoKey, NULL); // class_name_b
    will_return(wrap_RegQueryInfoKey, NULL); // class_name_s
    will_return(wrap_RegQueryInfoKey, 0); // subkey_count 
    will_return(wrap_RegQueryInfoKey, 1); // value_count
    will_return(wrap_RegQueryInfoKey, 0); // file_time 
    will_return(wrap_RegQueryInfoKey,ERROR_SUCCESS);

    will_return(wrap_RegEnumValue, "REG_VALUE");
    will_return(wrap_RegEnumValue, strlen("REG_VALUE"));
    will_return(wrap_RegEnumValue, REG_SZ);
    will_return(wrap_RegEnumValue, strlen("REG_DATA"));
    will_return(wrap_RegEnumValue, "REG_DATA");
    will_return(wrap_RegEnumValue, ERROR_SUCCESS);

    expect_string(__wrap_EVP_DigestUpdate, data, "REG_VALUE");
    expect_value(__wrap_EVP_DigestUpdate, count, strlen("REG_VALUE"));
    will_return(__wrap_EVP_DigestUpdate, 0);

    expect_string(__wrap_EVP_DigestUpdate, data, "REG_DATA");
    expect_value(__wrap_EVP_DigestUpdate, count, strlen("REG_DATA"));
    will_return(__wrap_EVP_DigestUpdate, 0);

    will_return(__wrap_fim_registry_event, 0);

    os_winreg_querykey(oshkey, subkey, fullname, pos);
}

void test_os_winreg_querykey_values_multi_string(void **state) {
    HKEY oshkey;
    int pos = 0;
    char *subkey = strdup("command");
    char *fullname = strdup("HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile\\shell\\open\\command"); // <registry_ignore type="sregex">\Enum$</registry_ignore>

    will_return(wrap_RegQueryInfoKey, NULL); // class_name_b
    will_return(wrap_RegQueryInfoKey, NULL); // class_name_s
    will_return(wrap_RegQueryInfoKey, 0); // subkey_count 
    will_return(wrap_RegQueryInfoKey, 1); // value_count
    will_return(wrap_RegQueryInfoKey, 0); // file_time 
    will_return(wrap_RegQueryInfoKey,ERROR_SUCCESS);

    will_return(wrap_RegEnumValue, "REG_VALUE");
    will_return(wrap_RegEnumValue, strlen("REG_VALUE"));
    will_return(wrap_RegEnumValue, REG_MULTI_SZ);
    will_return(wrap_RegEnumValue, (strlen("REG_DATA_1")*3)+3);
    will_return(wrap_RegEnumValue, "REG_DATA_1\0REG_DATA_2\0REG_DATA_3\0");
    will_return(wrap_RegEnumValue, ERROR_SUCCESS);

    expect_string(__wrap_EVP_DigestUpdate, data, "REG_VALUE");
    expect_value(__wrap_EVP_DigestUpdate, count, strlen("REG_VALUE"));
    will_return(__wrap_EVP_DigestUpdate, 0);

    expect_string(__wrap_EVP_DigestUpdate, data, "REG_DATA_1");
    expect_value(__wrap_EVP_DigestUpdate, count, strlen("REG_DATA_1"));
    will_return(__wrap_EVP_DigestUpdate, 0);
    expect_string(__wrap_EVP_DigestUpdate, data, "REG_DATA_2");
    expect_value(__wrap_EVP_DigestUpdate, count, strlen("REG_DATA_2"));
    will_return(__wrap_EVP_DigestUpdate, 0);
    expect_string(__wrap_EVP_DigestUpdate, data, "REG_DATA_3");
    expect_value(__wrap_EVP_DigestUpdate, count, strlen("REG_DATA_3"));
    will_return(__wrap_EVP_DigestUpdate, 0);

    will_return(__wrap_fim_registry_event, 0);

    os_winreg_querykey(oshkey, subkey, fullname, pos);
}
/**************************************************************************/
/*************************os_winreg_check()*******************************/
int setup_winreg_check_invalid_subtree(void **state) {
    // Store initial registry pointer
    *state = syscheck.registry; 
    registry **reg_array_ptr;
    reg_array_ptr = (registry **) calloc(2, sizeof(registry*));
    registry *new_reg_ptr = reg_array_ptr[0];
    new_reg_ptr = (registry*) malloc(sizeof(registry));
    new_reg_ptr->entry = strdup("WRONG_SUBTREE\\Software\\Classes\\batfile");
    new_reg_ptr->arch = syscheck.registry[0].arch;
    syscheck.registry = reg_array_ptr[0];
    return 0;
}

int teardown_winreg_check_invalid_subtree(void **state){
    // free new_reg
    free(syscheck.registry->entry);
    free(syscheck.registry);
    // Restore registry
    syscheck.registry = *state;
    return 0;
}

void test_os_winreg_check_invalid_subtree(void **state) {
    
}

int main(void) {
    const struct CMUnitTest tests[] = {
        /* os_winreg_sethkek */
        cmocka_unit_test(test_os_winreg_sethkek_invalid_subtree),
        cmocka_unit_test(test_os_winreg_sethkek_no_path),
        cmocka_unit_test(test_os_winreg_sethkek_valid_local_machine),
        cmocka_unit_test(test_os_winreg_sethkek_valid_classes_root),
        cmocka_unit_test(test_os_winreg_sethkek_valid_current_config),
        cmocka_unit_test(test_os_winreg_sethkek_valid_users),
        /* os_winreg_querykey */
        cmocka_unit_test(test_os_winreg_querykey_invalid_query),
        cmocka_unit_test(test_os_winreg_querykey_success_no_subkey),
        cmocka_unit_test(test_os_winreg_querykey_success_subkey_p_key),
        cmocka_unit_test(test_os_winreg_querykey_ignored_registry),
        cmocka_unit_test(test_os_winreg_querykey_ignored_regex),
        cmocka_unit_test(test_os_winreg_querykey_values_string),
        cmocka_unit_test(test_os_winreg_querykey_values_multi_string),
        /* os_winreg_check */
        //cmocka_unit_test_setup_teardown(test_os_winreg_check_invalid_subtree, setup_winreg_check_invalid_subtree, teardown_winreg_check_invalid_subtree)
    };

    return cmocka_run_group_tests(tests, test_group_setup, NULL);
}