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
/**************************************************************************/
/*************************os_winreg_check()*******************************/
int setup_winreg_check_invalid_subtree(void **state){
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
        /* os_winreg_check */
        //cmocka_unit_test_setup_teardown(test_os_winreg_check_invalid_subtree, setup_winreg_check_invalid_subtree, teardown_winreg_check_invalid_subtree)
    };

    return cmocka_run_group_tests(tests, test_group_setup, NULL);
}