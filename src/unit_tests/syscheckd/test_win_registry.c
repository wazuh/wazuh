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
/*******************************WRAPS**************************************/

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
int setup_os_winreg_querykey(void **state){
    int ret = Read_Syscheck_Config("test_syscheck.conf");
    return ret;
}

void test_os_winreg_querykey_invalid_query(void **state) {
    HKEY oshkey;
    char *subkey = strdup("command");
    char *fullname = strdup("HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile\\shell\\open\\command");
    int pos = 0;

    //will_return_count(__wrap_RegQueryInfoKeyA, NULL, 5);
    //will_return(__wrap_RegQueryInfoKeyA,__real_RegQueryInfoKeyA);
    os_winreg_querykey(oshkey, subkey, fullname, pos);
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
        cmocka_unit_test(test_os_winreg_querykey_invalid_query)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}