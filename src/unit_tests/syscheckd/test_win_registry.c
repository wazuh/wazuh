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

#include <winsock2.h>
#include <windows.h>
#include <wtypes.h> /* HKEY */
#include<libloaderapi.h>
#include <openssl/evp.h>

#include "../wrappers/common.h"
#include "../wrappers/externals/openssl/digest_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/syscheckd/create_db_wrappers.h"
#include "syscheckd/syscheck.h"

extern char *os_winreg_sethkey(char *reg_entry);
extern void os_winreg_querykey(HKEY hKey, char *p_key, char *full_key_name, int pos);
extern void os_winreg_open_key(char *subkey, char *fullkey_name, int pos);

static int test_has_started = 0;
/**************************************************************************/
/*************************WRAPS - GROUP SETUP******************************/
int test_group_setup(void **state) {
    int ret;
    expect_any_always(__wrap__mdebug1, formatted_msg);
    ret = Read_Syscheck_Config("test_syscheck.conf");
    test_has_started = 1;
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
    HKEY oshkey = NULL;
    char *subkey = strdup("command");
    char *fullname = strdup("HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile\\shell\\open\\command");
    int pos = 0;
    FILETIME ft;

    will_return_count(wrap_RegQueryInfoKey, NULL, 4);
    will_return(wrap_RegQueryInfoKey, &ft);
    will_return(wrap_RegQueryInfoKey, -1);
    os_winreg_querykey(oshkey, subkey, fullname, pos);
}

void test_os_winreg_querykey_success_no_subkey(void **state) {
    HKEY oshkey = NULL;
    char *subkey = strdup("command");
    char *fullname = strdup("HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile\\shell\\open\\command");
    int pos = 0;
    FILETIME ft;

    will_return(wrap_RegQueryInfoKey, NULL); // class_name_b
    will_return(wrap_RegQueryInfoKey, NULL); // class_name_s
    will_return(wrap_RegQueryInfoKey, 0); // subkey_count
    will_return(wrap_RegQueryInfoKey, 0); // value_count
    will_return(wrap_RegQueryInfoKey, &ft); // file_time
    will_return(wrap_RegQueryInfoKey, ERROR_SUCCESS);
    os_winreg_querykey(oshkey, subkey, fullname, pos);
}

void test_os_winreg_querykey_success_subkey_p_key(void **state) {
    HKEY oshkey = NULL;
    char *subkey = strdup("command");
    char *fullname = strdup("HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile\\shell\\open\\command");
    int pos = 0;
    FILETIME ft;

    will_return(wrap_RegQueryInfoKey, NULL); // class_name_b
    will_return(wrap_RegQueryInfoKey, NULL); // class_name_s
    will_return(wrap_RegQueryInfoKey, 1); // subkey_count
    will_return(wrap_RegQueryInfoKey, 0); // value_count
    will_return(wrap_RegQueryInfoKey, &ft); // file_time
    will_return(wrap_RegQueryInfoKey, ERROR_SUCCESS);

    will_return(wrap_RegEnumKeyEx, "SUBKEY_NAME");
    will_return(wrap_RegEnumKeyEx, strlen("SUBKEY_NAME"));
    will_return(wrap_RegEnumKeyEx, ERROR_SUCCESS);

    // Shutdown os_winreg_open_key
    // Inside RegOpenKeyEx
    expect_value(wrap_RegOpenKeyEx, hKey, HKEY_USERS);
    expect_string(wrap_RegOpenKeyEx, lpSubKey, "command\\SUBKEY_NAME");
    expect_value(wrap_RegOpenKeyEx, ulOptions, 0);
    expect_value(wrap_RegOpenKeyEx, samDesired, KEY_READ | (syscheck.registry[pos].arch == ARCH_32BIT ? KEY_WOW64_32KEY : KEY_WOW64_64KEY));
    will_return(wrap_RegOpenKeyEx, NULL);
    will_return(wrap_RegOpenKeyEx, ERROR_ACCESS_DENIED);

    expect_string(__wrap__mdebug1, formatted_msg, "(6920): Unable to open registry key: 'command\\SUBKEY_NAME' arch: '[x32]'.");
    os_winreg_querykey(oshkey, subkey, fullname, pos);
}

void test_os_winreg_querykey_ignored_registry(void **state) {
    HKEY oshkey = NULL;
    int pos = 0;
    char *subkey = strdup("command");
    char *fullname = syscheck.registry_ignore[pos].entry;
    FILETIME ft;

    will_return(wrap_RegQueryInfoKey, NULL); // class_name_b
    will_return(wrap_RegQueryInfoKey, NULL); // class_name_s
    will_return(wrap_RegQueryInfoKey, 0); // subkey_count
    will_return(wrap_RegQueryInfoKey, 0); // value_count
    will_return(wrap_RegQueryInfoKey, &ft); // file_time
    will_return(wrap_RegQueryInfoKey, ERROR_SUCCESS);

    char debug_msg[OS_MAXSTR];
    snprintf(debug_msg, OS_MAXSTR, "(6204): Ignoring 'registry' '%s' due to '%s'", fullname, fullname);
    expect_string(__wrap__mdebug2, formatted_msg, debug_msg);
    os_winreg_querykey(oshkey, subkey, fullname, pos);
}

void test_os_winreg_querykey_ignored_regex(void **state) {
    HKEY oshkey = NULL;
    int pos = 0;
    char *subkey = strdup("command");
    char *fullname = strdup("HKEY_LOCAL_MACHINE\\Security\\Enum"); // <registry_ignore type="sregex">\Enum$</registry_ignore>
    FILETIME ft;

    will_return(wrap_RegQueryInfoKey, NULL); // class_name_b
    will_return(wrap_RegQueryInfoKey, NULL); // class_name_s
    will_return(wrap_RegQueryInfoKey, 0); // subkey_count
    will_return(wrap_RegQueryInfoKey, 0); // value_count
    will_return(wrap_RegQueryInfoKey, &ft); // file_time
    will_return(wrap_RegQueryInfoKey, ERROR_SUCCESS);

    char debug_msg[OS_MAXSTR];
    snprintf(debug_msg, OS_MAXSTR,"(6205): Ignoring 'registry' '%s' due to sregex '\\Enum$'", fullname);
    expect_string(__wrap__mdebug2, formatted_msg, debug_msg);
    os_winreg_querykey(oshkey, subkey, fullname, pos);
}

void test_os_winreg_querykey_values_string(void **state) {
    HKEY oshkey = NULL;
    int pos = 0;
    char *subkey = strdup("command");
    char *fullname = strdup("HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile\\shell\\open\\command"); // <registry_ignore type="sregex">\Enum$</registry_ignore>
    FILETIME ft;

    will_return(wrap_RegQueryInfoKey, NULL); // class_name_b
    will_return(wrap_RegQueryInfoKey, NULL); // class_name_s
    will_return(wrap_RegQueryInfoKey, 0); // subkey_count
    will_return(wrap_RegQueryInfoKey, 1); // value_count
    will_return(wrap_RegQueryInfoKey, &ft); // file_time
    will_return(wrap_RegQueryInfoKey, ERROR_SUCCESS);

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
    HKEY oshkey = NULL;
    int pos = 0;
    char *subkey = strdup("command");
    char *fullname = strdup("HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile\\shell\\open\\command"); // <registry_ignore type="sregex">\Enum$</registry_ignore>
    FILETIME ft;

    will_return(wrap_RegQueryInfoKey, NULL); // class_name_b
    will_return(wrap_RegQueryInfoKey, NULL); // class_name_s
    will_return(wrap_RegQueryInfoKey, 0); // subkey_count
    will_return(wrap_RegQueryInfoKey, 1); // value_count
    will_return(wrap_RegQueryInfoKey, &ft); // file_time
    will_return(wrap_RegQueryInfoKey, ERROR_SUCCESS);

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

void test_os_winreg_querykey_values_number(void **state) {
    /**
     * Case DWORD is not working. Proposed changes:
     case REG_DWORD:
        snprintf(buffer, OS_SIZE_2048, "%08x", (unsigned int)*data_buffer);
        EVP_DigestUpdate(ctx, buffer, strlen(buffer));
        buffer[0] = '\0';
        break;
     * */
    HKEY oshkey = NULL;
    int pos = 0;
    char *subkey = strdup("command");
    char *fullname = strdup("HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile\\shell\\open\\command"); // <registry_ignore type="sregex">\Enum$</registry_ignore>
    FILETIME ft;

    will_return(wrap_RegQueryInfoKey, NULL); // class_name_b
    will_return(wrap_RegQueryInfoKey, NULL); // class_name_s
    will_return(wrap_RegQueryInfoKey, 0); // subkey_count
    will_return(wrap_RegQueryInfoKey, 1); // value_count
    will_return(wrap_RegQueryInfoKey,&ft); // file_time
    will_return(wrap_RegQueryInfoKey, ERROR_SUCCESS);

    will_return(wrap_RegEnumValue, "REG_VALUE");
    will_return(wrap_RegEnumValue, strlen("REG_VALUE"));
    will_return(wrap_RegEnumValue, REG_DWORD);
    will_return(wrap_RegEnumValue, 4); // 32 bits number -> 4 * sizeof(char)
    unsigned int value = 1000;
    will_return(wrap_RegEnumValue, &value);
    will_return(wrap_RegEnumValue, ERROR_SUCCESS);


    expect_string(__wrap_EVP_DigestUpdate, data, "REG_VALUE");
    expect_value(__wrap_EVP_DigestUpdate, count, strlen("REG_VALUE"));
    will_return(__wrap_EVP_DigestUpdate, 0);

    expect_string(__wrap_EVP_DigestUpdate, data, "000003e8");
    expect_value(__wrap_EVP_DigestUpdate, count, 8);
    will_return(__wrap_EVP_DigestUpdate, 0);

    will_return(__wrap_fim_registry_event, 0);

    os_winreg_querykey(oshkey, subkey, fullname, pos);
}

void test_os_winreg_querykey_values_binary(void **state) {
    /**
     * Default case is not working. Proposed fix:
    default:
        ptr = &data_buffer[0];
        for (j = 0; j < data_size; j++) {
            snprintf(buffer, 3, "%02x", *((unsigned int*)ptr) & 0xFF);
            EVP_DigestUpdate(ctx, buffer, strlen(buffer));
            buffer[0] = '\0';
            ptr++;
        }
        break;
     * */
    HKEY oshkey = NULL;
    int pos = 0;
    char *subkey = strdup("command");
    char *fullname = strdup("HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile\\shell\\open\\command"); // <registry_ignore type="sregex">\Enum$</registry_ignore>
    FILETIME ft;

    will_return(wrap_RegQueryInfoKey, NULL); // class_name_b
    will_return(wrap_RegQueryInfoKey, NULL); // class_name_s
    will_return(wrap_RegQueryInfoKey, 0); // subkey_count
    will_return(wrap_RegQueryInfoKey, 1); // value_count
    will_return(wrap_RegQueryInfoKey, &ft); // file_time
    will_return(wrap_RegQueryInfoKey, ERROR_SUCCESS);

    will_return(wrap_RegEnumValue, "REG_VALUE");
    will_return(wrap_RegEnumValue, strlen("REG_VALUE"));
    will_return(wrap_RegEnumValue, REG_BINARY);
    will_return(wrap_RegEnumValue, 4); // 32 bits number -> 4 * sizeof(char)
    unsigned int value = 0x2AFE80DC;
    will_return(wrap_RegEnumValue, &value);
    will_return(wrap_RegEnumValue, ERROR_SUCCESS);


    expect_string(__wrap_EVP_DigestUpdate, data, "REG_VALUE");
    expect_value(__wrap_EVP_DigestUpdate, count, strlen("REG_VALUE"));
    will_return(__wrap_EVP_DigestUpdate, 0);

    expect_string(__wrap_EVP_DigestUpdate, data, "dc");
    expect_value(__wrap_EVP_DigestUpdate, count, 2);
    will_return(__wrap_EVP_DigestUpdate, 0);
    expect_string(__wrap_EVP_DigestUpdate, data, "80");
    expect_value(__wrap_EVP_DigestUpdate, count, 2);
    will_return(__wrap_EVP_DigestUpdate, 0);
    expect_string(__wrap_EVP_DigestUpdate, data, "fe");
    expect_value(__wrap_EVP_DigestUpdate, count, 2);
    will_return(__wrap_EVP_DigestUpdate, 0);
    expect_string(__wrap_EVP_DigestUpdate, data, "2a");
    expect_value(__wrap_EVP_DigestUpdate, count, 2);
    will_return(__wrap_EVP_DigestUpdate, 0);

    will_return(__wrap_fim_registry_event, 0);

    os_winreg_querykey(oshkey, subkey, fullname, pos);
}

void test_os_winreg_querykey_values_none(void **state) {
    HKEY oshkey = NULL;
    int pos = 0;
    char *subkey = strdup("command");
    char *fullname = strdup("HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile\\shell\\open\\command"); // <registry_ignore type="sregex">\Enum$</registry_ignore>
    FILETIME ft;

    will_return(wrap_RegQueryInfoKey, NULL); // class_name_b
    will_return(wrap_RegQueryInfoKey, NULL); // class_name_s
    will_return(wrap_RegQueryInfoKey, 0); // subkey_count
    will_return(wrap_RegQueryInfoKey, 1); // value_count
    will_return(wrap_RegQueryInfoKey, &ft); // file_time
    will_return(wrap_RegQueryInfoKey, ERROR_SUCCESS);

    will_return(wrap_RegEnumValue, "REG_VALUE");
    will_return(wrap_RegEnumValue, strlen("REG_VALUE"));
    will_return(wrap_RegEnumValue, REG_NONE);
    will_return(wrap_RegEnumValue, NULL);
    will_return(wrap_RegEnumValue, 0);
    will_return(wrap_RegEnumValue, ERROR_SUCCESS);

    expect_string(__wrap_EVP_DigestUpdate, data, "REG_VALUE");
    expect_value(__wrap_EVP_DigestUpdate, count, strlen("REG_VALUE"));
    will_return(__wrap_EVP_DigestUpdate, 0);

    will_return(__wrap_fim_registry_event, 0);

    os_winreg_querykey(oshkey, subkey, fullname, pos);
}

void test_os_winreg_querykey_registry_event_fail(void **state) {
    HKEY oshkey = NULL;
    int pos = 0;
    char *subkey = strdup("command");
    char *fullname = strdup("HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile\\shell\\open\\command"); // <registry_ignore type="sregex">\Enum$</registry_ignore>
    FILETIME ft;

    will_return(wrap_RegQueryInfoKey, NULL); // class_name_b
    will_return(wrap_RegQueryInfoKey, NULL); // class_name_s
    will_return(wrap_RegQueryInfoKey, 0); // subkey_count
    will_return(wrap_RegQueryInfoKey, 1); // value_count
    will_return(wrap_RegQueryInfoKey, &ft); // file_time
    will_return(wrap_RegQueryInfoKey, ERROR_SUCCESS);

    will_return(wrap_RegEnumValue, "REG_VALUE");
    will_return(wrap_RegEnumValue, strlen("REG_VALUE"));
    will_return(wrap_RegEnumValue, REG_NONE);
    will_return(wrap_RegEnumValue, NULL);
    will_return(wrap_RegEnumValue, 0);
    will_return(wrap_RegEnumValue, ERROR_SUCCESS);

    expect_string(__wrap_EVP_DigestUpdate, data, "REG_VALUE");
    expect_value(__wrap_EVP_DigestUpdate, count, strlen("REG_VALUE"));
    will_return(__wrap_EVP_DigestUpdate, 0);

    will_return(__wrap_fim_registry_event, OS_INVALID);
    char debug_msg[OS_MAXSTR];
    snprintf(debug_msg, OS_MAXSTR, "(6329): Unable to save registry key: '[x32] %s'", fullname);
    expect_string(__wrap__mdebug1, formatted_msg, debug_msg);

    os_winreg_querykey(oshkey, subkey, fullname, pos);
}
/**************************************************************************/
/*************************os_winreg_check()*******************************/
int setup_winreg_check_invalid_subtree(void **state) {
    // Store initial registry pointer
    *state = syscheck.registry;
    registry *reg_array_ptr;
    reg_array_ptr = (registry *) calloc(2, sizeof(registry));
    reg_array_ptr->entry = strdup("WRONG_SUBTREE\\Software\\Classes\\batfile");
    reg_array_ptr->arch = syscheck.registry[0].arch;
    syscheck.registry = reg_array_ptr;
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

int setup_winreg_check_valid_subtree(void **state) {
    // Store initial registry pointer
    *state = syscheck.registry;
    registry *reg_array_ptr;
    reg_array_ptr = (registry *) calloc(2, sizeof(registry));
    reg_array_ptr->entry = strdup("HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile");
    reg_array_ptr->arch = syscheck.registry[0].arch;
    syscheck.registry = reg_array_ptr;
    return 0;
}

int teardown_winreg_check_valid_subtree(void **state){
    // free new_reg
    free(syscheck.registry->entry);
    free(syscheck.registry);
    // Restore registry
    syscheck.registry = *state;
    return 0;
}


void test_os_winreg_check_invalid_subtree(void **state) {
    expect_string(__wrap__mdebug1, formatted_msg, FIM_WINREGISTRY_START);
    char debug_msg[OS_MAXSTR];
    snprintf(debug_msg, OS_MAXSTR, FIM_READING_REGISTRY, syscheck.registry[0].arch == ARCH_64BIT ? "[x64] " : "[x32] ", syscheck.registry[0].entry);
    expect_string(__wrap__mdebug2, formatted_msg, debug_msg);
    char warn_msg[OS_MAXSTR];
    snprintf(warn_msg, OS_MAXSTR, "(6919): Invalid syscheck registry entry: '%s' arch: '%s'.", syscheck.registry[0].entry, syscheck.registry[0].arch == ARCH_64BIT ? "[x64]" : "[x32]");
    expect_string(__wrap__mdebug1, formatted_msg, warn_msg);
    expect_string(__wrap__mdebug1, formatted_msg, FIM_WINREGISTRY_ENDED);
    os_winreg_check();
}

void test_os_winreg_check_valid_subtree(void **state) {
    expect_string(__wrap__mdebug1, formatted_msg, FIM_WINREGISTRY_START);
    char debug_msg[OS_MAXSTR];
    snprintf(debug_msg, OS_MAXSTR, FIM_READING_REGISTRY, syscheck.registry[0].arch == ARCH_64BIT ? "[x64] " : "[x32] ", syscheck.registry[0].entry);
    expect_string(__wrap__mdebug2, formatted_msg, debug_msg);
    int pos = 0;

    // If os_winreg check tries to call os_winreg_open_key then subtree is valid
    // Inside RegOpenKeyEx
    expect_value(wrap_RegOpenKeyEx, hKey, HKEY_LOCAL_MACHINE);
    expect_string(wrap_RegOpenKeyEx, lpSubKey, "Software\\Classes\\batfile");
    expect_value(wrap_RegOpenKeyEx, ulOptions, 0);
    expect_value(wrap_RegOpenKeyEx, samDesired, KEY_READ | (syscheck.registry[pos].arch == ARCH_32BIT ? KEY_WOW64_32KEY : KEY_WOW64_64KEY));
    will_return(wrap_RegOpenKeyEx, NULL);
    will_return(wrap_RegOpenKeyEx, ERROR_ACCESS_DENIED);
    char debug_msg2[OS_MAXSTR];
    snprintf(debug_msg2, OS_MAXSTR, "(6920): Unable to open registry key: 'Software\\Classes\\batfile' arch: '%s'.", syscheck.registry[0].arch == ARCH_64BIT ? "[x64]" : "[x32]");
    expect_string(__wrap__mdebug1, formatted_msg, debug_msg2);

    expect_string(__wrap__mdebug1, formatted_msg, FIM_WINREGISTRY_ENDED);
    os_winreg_check();
}
/**************************************************************************/
/*************************os_winreg_open()*******************************/
void test_os_winreg_open_fail(void **state) {
    int pos = 0;

    // Inside RegOpenKeyEx
    expect_value(wrap_RegOpenKeyEx, hKey, HKEY_LOCAL_MACHINE);
    expect_string(wrap_RegOpenKeyEx, lpSubKey, "Software\\Classes\\batfile");
    expect_value(wrap_RegOpenKeyEx, ulOptions, 0);
    expect_value(wrap_RegOpenKeyEx, samDesired, KEY_READ | (syscheck.registry[pos].arch == ARCH_32BIT ? KEY_WOW64_32KEY : KEY_WOW64_64KEY));
    will_return(wrap_RegOpenKeyEx, NULL);
    will_return(wrap_RegOpenKeyEx, ERROR_ACCESS_DENIED);
    char debug_msg2[OS_MAXSTR];
    snprintf(debug_msg2, OS_MAXSTR, "(6920): Unable to open registry key: 'Software\\Classes\\batfile' arch: '%s'.", syscheck.registry[0].arch == ARCH_64BIT ? "[x64]" : "[x32]");
    expect_string(__wrap__mdebug1, formatted_msg, debug_msg2);
    os_winreg_open_key("Software\\Classes\\batfile", "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile", 0);
}

void test_os_winreg_open_success(void **state) {
    int pos = 0;
    FILETIME ft;

    // Inside RegOpenKeyEx
    expect_value(wrap_RegOpenKeyEx, hKey, HKEY_LOCAL_MACHINE);
    expect_string(wrap_RegOpenKeyEx, lpSubKey,
        "Software\\Classes\\batfile");
    expect_value(wrap_RegOpenKeyEx, ulOptions, 0);
    expect_value(wrap_RegOpenKeyEx, samDesired, KEY_READ | (syscheck.registry[pos].arch == ARCH_32BIT ? KEY_WOW64_32KEY : KEY_WOW64_64KEY));
    will_return(wrap_RegOpenKeyEx, NULL);
    will_return(wrap_RegOpenKeyEx, ERROR_SUCCESS);
    // Promptly exit from os_winreg_querykey
    will_return_count(wrap_RegQueryInfoKey, NULL, 4);
    will_return(wrap_RegQueryInfoKey, &ft);
    will_return(wrap_RegQueryInfoKey, -1);

    os_winreg_open_key("Software\\Classes\\batfile", "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile", 0);
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
        cmocka_unit_test(test_os_winreg_querykey_values_number),
        cmocka_unit_test(test_os_winreg_querykey_values_binary),
        cmocka_unit_test(test_os_winreg_querykey_values_none),
        cmocka_unit_test(test_os_winreg_querykey_registry_event_fail),
        /* os_winreg_check */
        cmocka_unit_test_setup_teardown(test_os_winreg_check_invalid_subtree, setup_winreg_check_invalid_subtree, teardown_winreg_check_invalid_subtree),
        cmocka_unit_test_setup_teardown(test_os_winreg_check_valid_subtree, setup_winreg_check_valid_subtree, teardown_winreg_check_valid_subtree),
        /* os_winreg_open */
        cmocka_unit_test(test_os_winreg_open_fail),
        cmocka_unit_test(test_os_winreg_open_success),
    };

    return cmocka_run_group_tests(tests, test_group_setup, NULL);
}
