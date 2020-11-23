/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Test corresponding to the syscollector capacities
 * for BSD and MAC
 * */


#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/proc_info.h>

#include "shared.h"
#include "headers/defs.h"
#include "../../wrappers/common.h"
#include "../../wrappers/macos/libc/stdio_wrappers.h"
#include "../../wrappers/macos/posix/dirent_wrappers.h"
#include "../../wrappers/macos/libplist_wrappers.h"
#include "../../wrappers/macos/libwazuh_wrappers.h"
#include "../../../wazuh_modules/syscollector/syscollector.h"
#include "../../wazuh_modules/wmodules.h"

int extern test_mode;

bool sys_convert_bin_plist(FILE **fp, char *magic_bytes, char *filepath);
int sys_read_apps(const char * app_folder, const char * timestamp, int random_id, int queue_fd, const char* LOCATION);
int sys_read_homebrew_apps(const char * app_folder, const char * timestamp, int random_id, int queue_fd, const char* LOCATION);
cJSON* sys_parse_pkg(const char * app_folder);

static int setup_wrappers(void **state) {
    test_mode = 1;
    return 0;
}

static int teardown_wrappers(void **state) {
    test_mode = 0;
    return 0;
}

static int setup_max_eps(void **state) {
    wm_max_eps = 1000000;
    return 0;
}

// sys_convert_bin_plist

void test_sys_convert_bin_plist_failed_stat(void **state)
{
    int stat_size = 20;
    FILE *fp = (void *)1;

    will_return(wrap_fileno, 3);

    will_return(wrap_fstat, stat_size);
    will_return(wrap_fstat, -1);

    expect_string(wrap_mterror, tag, "wazuh-modulesd:syscollector");
    expect_string(wrap_mterror, formatted_msg, "Failed to stat file 'prueba': No such process");

    bool ret = sys_convert_bin_plist(&fp, NULL, "prueba");
    assert_int_equal(ret, false);
}

void test_sys_convert_bin_plist_failed_mmap(void **state)
{
    int stat_size = 20;
    FILE *fp = (void *)1;

    will_return(wrap_fileno, 3);

    will_return(wrap_fstat, stat_size);
    will_return(wrap_fstat, 1);

    expect_value(wrap_mmap, fd, 3);
    will_return(wrap_mmap, MAP_FAILED);

    expect_string(wrap_mterror, tag, "wazuh-modulesd:syscollector");
    expect_string(wrap_mterror, formatted_msg, "Failed to mmap file 'prueba': No such process");

    bool ret = sys_convert_bin_plist(&fp, NULL, "prueba");
    assert_int_equal(ret, false);
}

void test_sys_convert_bin_plist_empty_node(void **state)
{
    int stat_size = 20;
    FILE *fp = (void *)1;

    will_return(wrap_fileno, 3);

    will_return(wrap_fstat, stat_size);
    will_return(wrap_fstat, 1);

    expect_value(wrap_mmap, fd, 3);
    will_return(wrap_mmap, (void *)1);

    expect_value(wrap_plist_from_bin, bin, (void *)1);
    will_return(wrap_plist_from_bin, (void *)0);

    expect_value(wrap_munmap, mem, (void *)1);

    bool ret = sys_convert_bin_plist(&fp, NULL, NULL);
    assert_int_equal(ret, false);
}

void test_sys_convert_bin_plist_failed_xml(void **state)
{
    int stat_size = 20;
    FILE *fp = (void *)1;

    will_return(wrap_fileno, 3);

    will_return(wrap_fstat, stat_size);
    will_return(wrap_fstat, 1);

    expect_value(wrap_mmap, fd, 3);
    will_return(wrap_mmap, (void *)1);

    expect_value(wrap_plist_from_bin, bin, (void *)1);
    will_return(wrap_plist_from_bin, (void *)1);

    expect_value(wrap_plist_to_xml, node, (void *)1);
    will_return(wrap_plist_to_xml, (void *)0);
    will_return(wrap_plist_to_xml, stat_size);

    expect_value(wrap_plist_free, node, (plist_t)1);
    expect_value(wrap_munmap, mem, (void *)1);

    bool ret = sys_convert_bin_plist(&fp, NULL, NULL);
    assert_int_equal(ret, false);
}

void test_sys_convert_bin_plist_failed_tmpfile(void **state)
{
    int stat_size = 20;
    FILE *fp = (void *)1;

    will_return(wrap_fileno, 3);

    will_return(wrap_fstat, stat_size);
    will_return(wrap_fstat, 1);

    expect_value(wrap_mmap, fd, 3);
    will_return(wrap_mmap, (void *)1);

    expect_value(wrap_plist_from_bin, bin, (void *)1);
    will_return(wrap_plist_from_bin, (void *)1);

    expect_value(wrap_plist_to_xml, node, (void *)1);
    will_return(wrap_plist_to_xml, "test");
    will_return(wrap_plist_to_xml, stat_size);

    expect_value(wrap_fclose, fp, (void *)1);
    will_return(wrap_fclose, 0);

    will_return(wrap_tmpfile, NULL);

    expect_string(wrap_mterror, tag, "wazuh-modulesd:syscollector");
    expect_string(wrap_mterror, formatted_msg, "Failed to open tmpfile: No such process");

    expect_value(wrap_plist_free, node, (plist_t)1);
    expect_value(wrap_munmap, mem, (void *)1);

    bool ret = sys_convert_bin_plist(&fp, NULL, NULL);
    assert_int_equal(ret, false);
}

void test_sys_convert_bin_plist_ok(void **state)
{
    int stat_size = 20;
    FILE *fp = (void *)1;
    char buffer[OS_MAXSTR];
    memset(buffer, 0, OS_MAXSTR);

    will_return(wrap_fileno, 3);

    will_return(wrap_fstat, stat_size);
    will_return(wrap_fstat, 1);

    expect_value(wrap_mmap, fd, 3);
    will_return(wrap_mmap, (void *)1);

    expect_value(wrap_plist_from_bin, bin, (void *)1);
    will_return(wrap_plist_from_bin, (void *)1);

    expect_value(wrap_plist_to_xml, node, (void *)1);
    will_return(wrap_plist_to_xml, "<?xml");
    will_return(wrap_plist_to_xml, stat_size);

    expect_value(wrap_fclose, fp, (void *)1);
    will_return(wrap_fclose, 0);

    will_return(wrap_tmpfile, (void *)1);

    expect_string(wrap_fwrite, src, "<?xml");
    will_return(wrap_fwrite, 1);

    expect_value(wrap_fseek, fp, (FILE *)1);

    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, "<?xml");

    expect_value(wrap_plist_free, node, (plist_t)1);
    expect_value(wrap_munmap, mem, (void *)1);

    bool ret = sys_convert_bin_plist(&fp, (char *)buffer, NULL);
    assert_int_equal(ret, true);
}

// normalize_mac_package

static void test_normalize_mac_package_name(void **state) {
    int ret;
    int i;
    char * vendor = NULL;
    char * package = NULL;
    char * source_package[18][3] = {
        {"Microsoft Word", "Microsoft", "Word"},
        {"Microsoft Excel", "Microsoft", "Excel"},
        {"VMware Fusion", "VMware", "Fusion"},
        {"VMware Horizon Client", "VMware", "Horizon Client"},
        {"1Password 7", NULL, "1Password"},
        {"zoom.us", NULL, "zoom"},
        {"TotalDefenseAntivirusforMac", "TotalDefense", "Anti-Virus"},
        {"TotalDefenseInternetSecurityforMac", "TotalDefense", "InternetSecurity"},
        {"AVGAntivirus", "AVG", "Anti-Virus"},
        {"AVGInternetSecurity", "AVG", "InternetSecurity"},
        {"AntivirusforMac", NULL, "Antivirus"},
        {"Kaspersky Anti-Virus For Mac", NULL, "Kaspersky Anti-Virus"},
        {"Symantec Endpoint Protection", "Symantec", "Endpoint Protection"},
        {"McAfee Endpoint Security for Mac", "McAfee", "Endpoint Security"},
        {"Quick Heal Total Security", "Quick Heal", "Total Security"},
        {"QuickHeal Total Security", "QuickHeal", "Total Security"},
        {"Foxit Reader", NULL, NULL},
        {NULL, NULL, NULL},
    };

    for (i = 0; i < 18; i++) {
        ret = normalize_mac_package_name(source_package[i][0], &vendor, &package);
        if (i < 16) {
            assert_int_equal(ret, 1);
            if (source_package[i][1]) {
                assert_string_equal(vendor, source_package[i][1]);
                os_free(vendor);
            }
            assert_string_equal(package, source_package[i][2]);
            os_free(package);
        } else {
            assert_int_equal(ret, 0);
            assert_null(package);
            assert_null(vendor);
        }
    }
}

// sys_parse_pkg

void test_sys_parse_pkg_fopen_error(void **state) {

    const char * app_folder = "/test.app";
    cJSON * object = NULL;

    expect_string(wrap_snprintf, s, "/test.app/Contents/Info.plist");
    will_return(wrap_snprintf, 24);

    expect_string(wrap_fopen, path, "/test.app/Contents/Info.plist");
    expect_string(wrap_fopen, mode, "rb");
    will_return(wrap_fopen, NULL);

    expect_string(wrap_mtdebug1, tag, "wazuh-modulesd:syscollector");
    expect_string(wrap_mtdebug1, formatted_msg, "Unable to open '/test.app/Contents/Info.plist' due to 'No such process'");

    object = sys_parse_pkg(app_folder);
    assert_null(object);
}

void test_sys_parse_pkg_fgets_null(void **state) {

    const char * app_folder = "/test.app";
    cJSON * object = NULL;

    expect_string(wrap_snprintf, s, "/test.app/Contents/Info.plist");
    will_return(wrap_snprintf, 24);

    expect_string(wrap_fopen, path, "/test.app/Contents/Info.plist");
    expect_string(wrap_fopen, mode, "rb");
    will_return(wrap_fopen, 1);

    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, NULL);

    expect_string(wrap_mtwarn, tag, "wazuh-modulesd:syscollector");
    expect_string(wrap_mtwarn, formatted_msg, "Unable to read file '/test.app/Contents/Info.plist'");

    expect_value(wrap_fclose, fp, (void *)1);
    will_return(wrap_fclose, 0);

    object = sys_parse_pkg(app_folder);

    // Check result
    cJSON * package = cJSON_GetObjectItem(object, "program");
    cJSON * name = cJSON_GetObjectItem(package, "name");
    assert_string_equal(name->valuestring, "test");
    cJSON_Delete(object);
}

void test_sys_parse_pkg_unknown_format(void **state) {

    const char * app_folder = "/test.app";
    cJSON * object = NULL;

    expect_string(wrap_snprintf, s, "/test.app/Contents/Info.plist");
    will_return(wrap_snprintf, 24);

    expect_string(wrap_fopen, path, "/test.app/Contents/Info.plist");
    expect_string(wrap_fopen, mode, "rb");
    will_return(wrap_fopen, 1);

    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, "bplist00");

    // sys_convert_bin_plist (doesn't matter the result value)

    int stat_size = 20;
    FILE *fp = (void *)1;

    will_return(wrap_fileno, 3);
    will_return(wrap_fstat, stat_size);
    will_return(wrap_fstat, 1);
    expect_value(wrap_mmap, fd, 3);
    will_return(wrap_mmap, (void *)1);
    expect_value(wrap_plist_from_bin, bin, (void *)1);
    will_return(wrap_plist_from_bin, (void *)0);
    expect_value(wrap_munmap, mem, (void *)1);

    expect_string(wrap_mtwarn, tag, "wazuh-modulesd:syscollector");
    expect_string(wrap_mtwarn, formatted_msg, "Unable to read package information from '/test.app/Contents/Info.plist' (invalid format)");

    expect_value(wrap_fclose, fp, (void *)1);
    will_return(wrap_fclose, 0);

    object = sys_parse_pkg(app_folder);

    // Check result
    cJSON * package = cJSON_GetObjectItem(object, "program");
    cJSON * name = cJSON_GetObjectItem(package, "name");
    assert_string_equal(name->valuestring, "test");
    cJSON_Delete(object);
}

void test_sys_parse_pkg_name_same_line(void **state) {

    const char * app_folder = "/test.app";
    cJSON * object = NULL;

    expect_string(wrap_snprintf, s, "/test.app/Contents/Info.plist");
    will_return(wrap_snprintf, 24);

    expect_string(wrap_fopen, path, "/test.app/Contents/Info.plist");
    expect_string(wrap_fopen, mode, "rb");
    will_return(wrap_fopen, 1);

    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, "<?xml");

    // now it doesn't go through sys_convert_bin_plist

    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, "<key>CFBundleName</key><string>test_name</string>");

    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, NULL);

    expect_value(wrap_fclose, fp, (void *)1);
    will_return(wrap_fclose, 0);

    object = sys_parse_pkg(app_folder);

    // Check result
    cJSON * package = cJSON_GetObjectItem(object, "program");
    cJSON * name = cJSON_GetObjectItem(package, "name");
    cJSON * vendor = cJSON_GetObjectItem(package, "vendor");
    assert_string_equal(name->valuestring, "test_name");
    assert_null(vendor);
    cJSON_Delete(object);
}

void test_sys_parse_pkg_name_vendor_same_line(void **state) {

    const char * app_folder = "/Microsoft Test.app";
    cJSON * object = NULL;

    expect_string(wrap_snprintf, s, "/Microsoft Test.app/Contents/Info.plist");
    will_return(wrap_snprintf, 24);

    expect_string(wrap_fopen, path, "/Microsoft Test.app/Contents/Info.plist");
    expect_string(wrap_fopen, mode, "rb");
    will_return(wrap_fopen, 1);

    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, "<?xml");

    // now it doesn't go through sys_convert_bin_plist

    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, "<key>CFBundleName</key><string>Microsoft Test</string>");

    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, NULL);

    expect_value(wrap_fclose, fp, (void *)1);
    will_return(wrap_fclose, 0);

    object = sys_parse_pkg(app_folder);

    // Check result
    cJSON * package = cJSON_GetObjectItem(object, "program");
    cJSON * name = cJSON_GetObjectItem(package, "name");
    cJSON * vendor = cJSON_GetObjectItem(package, "vendor");
    assert_string_equal(name->valuestring, "Test");
    assert_string_equal(vendor->valuestring, "Microsoft");
    cJSON_Delete(object);
}

void test_sys_parse_pkg_name(void **state) {

    const char * app_folder = "/test.app";
    cJSON * object = NULL;

    expect_string(wrap_snprintf, s, "/test.app/Contents/Info.plist");
    will_return(wrap_snprintf, 24);

    expect_string(wrap_fopen, path, "/test.app/Contents/Info.plist");
    expect_string(wrap_fopen, mode, "rb");
    will_return(wrap_fopen, 1);

    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, "<?xml");

    // now it doesn't go through sys_convert_bin_plist

    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, "<key>CFBundleName</key>");

    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, "<string>test_name</string>");

    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, NULL);

    expect_value(wrap_fclose, fp, (void *)1);
    will_return(wrap_fclose, 0);

    object = sys_parse_pkg(app_folder);

    // Check result
    cJSON * package = cJSON_GetObjectItem(object, "program");
    cJSON * name = cJSON_GetObjectItem(package, "name");
    cJSON * vendor = cJSON_GetObjectItem(package, "vendor");
    assert_string_equal(name->valuestring, "test_name");
    assert_null(vendor);
    cJSON_Delete(object);
}

void test_sys_parse_pkg_name_vendor(void **state) {

    const char * app_folder = "/Microsoft Test.app";
    cJSON * object = NULL;

    expect_string(wrap_snprintf, s, "/Microsoft Test.app/Contents/Info.plist");
    will_return(wrap_snprintf, 24);

    expect_string(wrap_fopen, path, "/Microsoft Test.app/Contents/Info.plist");
    expect_string(wrap_fopen, mode, "rb");
    will_return(wrap_fopen, 1);

    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, "<?xml");

    // now it doesn't go through sys_convert_bin_plist

    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, "<key>CFBundleName</key><string>Microsoft Test</string>");

    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, "<string>Microsoft Test</string>");

    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, NULL);

    expect_value(wrap_fclose, fp, (void *)1);
    will_return(wrap_fclose, 0);

    object = sys_parse_pkg(app_folder);

    // Check result
    cJSON * package = cJSON_GetObjectItem(object, "program");
    cJSON * name = cJSON_GetObjectItem(package, "name");
    cJSON * vendor = cJSON_GetObjectItem(package, "vendor");
    assert_string_equal(name->valuestring, "Test");
    assert_string_equal(vendor->valuestring, "Microsoft");
    cJSON_Delete(object);
}

void test_sys_parse_pkg_version_same_line(void **state) {

    const char * app_folder = "/test.app";
    cJSON * object = NULL;

    expect_string(wrap_snprintf, s, "/test.app/Contents/Info.plist");
    will_return(wrap_snprintf, 24);

    expect_string(wrap_fopen, path, "/test.app/Contents/Info.plist");
    expect_string(wrap_fopen, mode, "rb");
    will_return(wrap_fopen, 1);

    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, "<?xml");

    // now it doesn't go through sys_convert_bin_plist

    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, "<key>CFBundleShortVersionString</key><string>4.5.1</string>");

    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, NULL);

    expect_value(wrap_fclose, fp, (void *)1);
    will_return(wrap_fclose, 0);

    object = sys_parse_pkg(app_folder);

    // Check result
    cJSON * package = cJSON_GetObjectItem(object, "program");
    cJSON * name = cJSON_GetObjectItem(package, "name");
    cJSON * version = cJSON_GetObjectItem(package, "version");
    assert_string_equal(name->valuestring, "test");
    assert_string_equal(version->valuestring, "4.5.1");
    cJSON_Delete(object);
}

void test_sys_parse_pkg_version(void **state) {

    const char * app_folder = "/test.app";
    cJSON * object = NULL;

    expect_string(wrap_snprintf, s, "/test.app/Contents/Info.plist");
    will_return(wrap_snprintf, 24);

    expect_string(wrap_fopen, path, "/test.app/Contents/Info.plist");
    expect_string(wrap_fopen, mode, "rb");
    will_return(wrap_fopen, 1);

    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, "<?xml");

    // now it doesn't go through sys_convert_bin_plist

    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, "<key>CFBundleShortVersionString</key>");

    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, "<string>4.5.1</string>");

    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, NULL);

    expect_value(wrap_fclose, fp, (void *)1);
    will_return(wrap_fclose, 0);

    object = sys_parse_pkg(app_folder);

    // Check result
    cJSON * package = cJSON_GetObjectItem(object, "program");
    cJSON * name = cJSON_GetObjectItem(package, "name");
    cJSON * version = cJSON_GetObjectItem(package, "version");
    assert_string_equal(name->valuestring, "test");
    assert_string_equal(version->valuestring, "4.5.1");
    cJSON_Delete(object);
}

void test_sys_parse_pkg_custom_version_key(void **state) {

    const char * app_folder = "/test.app";
    cJSON * object = NULL;

    expect_string(wrap_snprintf, s, "/test.app/Contents/Info.plist");
    will_return(wrap_snprintf, 24);

    expect_string(wrap_fopen, path, "/test.app/Contents/Info.plist");
    expect_string(wrap_fopen, mode, "rb");
    will_return(wrap_fopen, 1);

    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, "<?xml");

    // now it doesn't go through sys_convert_bin_plist

    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, "<key>CFBundleShortVersionString</key><string>4.5.1</string>");
    
    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, "<key>CliVersion</key><string>5.5.1</string>");

    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, NULL);

    expect_value(wrap_fclose, fp, (void *)1);
    will_return(wrap_fclose, 0);

    object = sys_parse_pkg(app_folder);

    // Check result
    cJSON * package = cJSON_GetObjectItem(object, "program");
    cJSON * name = cJSON_GetObjectItem(package, "name");
    cJSON * version = cJSON_GetObjectItem(package, "version");
    assert_string_equal(name->valuestring, "test");
    assert_string_equal(version->valuestring, "5.5.1");
    cJSON_Delete(object);
}

void test_sys_parse_pkg_group_same_line(void **state) {

    const char * app_folder = "/test.app";
    cJSON * object = NULL;

    expect_string(wrap_snprintf, s, "/test.app/Contents/Info.plist");
    will_return(wrap_snprintf, 24);

    expect_string(wrap_fopen, path, "/test.app/Contents/Info.plist");
    expect_string(wrap_fopen, mode, "rb");
    will_return(wrap_fopen, 1);

    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, "<?xml");

    // now it doesn't go through sys_convert_bin_plist

    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, "<key>LSApplicationCategoryType</key><string>public.app-category.developer-tools</string>");

    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, NULL);

    expect_value(wrap_fclose, fp, (void *)1);
    will_return(wrap_fclose, 0);

    object = sys_parse_pkg(app_folder);

    // Check result
    cJSON * package = cJSON_GetObjectItem(object, "program");
    cJSON * name = cJSON_GetObjectItem(package, "name");
    cJSON * group = cJSON_GetObjectItem(package, "group");
    assert_string_equal(name->valuestring, "test");
    assert_string_equal(group->valuestring, "public.app-category.developer-tools");
    cJSON_Delete(object);
}

void test_sys_parse_pkg_group(void **state) {

    const char * app_folder = "/test.app";
    cJSON * object = NULL;

    expect_string(wrap_snprintf, s, "/test.app/Contents/Info.plist");
    will_return(wrap_snprintf, 24);

    expect_string(wrap_fopen, path, "/test.app/Contents/Info.plist");
    expect_string(wrap_fopen, mode, "rb");
    will_return(wrap_fopen, 1);

    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, "<?xml");

    // now it doesn't go through sys_convert_bin_plist

    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, "<key>LSApplicationCategoryType</key>");

    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, "<string>public.app-category.developer-tools</string>");

    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, NULL);

    expect_value(wrap_fclose, fp, (void *)1);
    will_return(wrap_fclose, 0);

    object = sys_parse_pkg(app_folder);

    // Check result
    cJSON * package = cJSON_GetObjectItem(object, "program");
    cJSON * name = cJSON_GetObjectItem(package, "name");
    cJSON * group = cJSON_GetObjectItem(package, "group");
    assert_string_equal(name->valuestring, "test");
    assert_string_equal(group->valuestring, "public.app-category.developer-tools");
    cJSON_Delete(object);
}

void test_sys_parse_pkg_description_same_line(void **state) {

    const char * app_folder = "/test.app";
    cJSON * object = NULL;

    expect_string(wrap_snprintf, s, "/test.app/Contents/Info.plist");
    will_return(wrap_snprintf, 24);

    expect_string(wrap_fopen, path, "/test.app/Contents/Info.plist");
    expect_string(wrap_fopen, mode, "rb");
    will_return(wrap_fopen, 1);

    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, "<?xml");

    // now it doesn't go through sys_convert_bin_plist

    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, "<key>CFBundleIdentifier</key><string>com.apple.Safari</string>");

    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, NULL);

    expect_value(wrap_fclose, fp, (void *)1);
    will_return(wrap_fclose, 0);

    object = sys_parse_pkg(app_folder);

    // Check result
    cJSON * package = cJSON_GetObjectItem(object, "program");
    cJSON * name = cJSON_GetObjectItem(package, "name");
    cJSON * description = cJSON_GetObjectItem(package, "description");
    assert_string_equal(name->valuestring, "test");
    assert_string_equal(description->valuestring, "com.apple.Safari");
    cJSON_Delete(object);
}

void test_sys_parse_pkg_description(void **state) {

    const char * app_folder = "/test.app";
    cJSON * object = NULL;

    expect_string(wrap_snprintf, s, "/test.app/Contents/Info.plist");
    will_return(wrap_snprintf, 24);

    expect_string(wrap_fopen, path, "/test.app/Contents/Info.plist");
    expect_string(wrap_fopen, mode, "rb");
    will_return(wrap_fopen, 1);

    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, "<?xml");

    // now it doesn't go through sys_convert_bin_plist

    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, "<key>CFBundleIdentifier</key>");

    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, "<string>com.apple.Safari</string>");

    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, NULL);

    expect_value(wrap_fclose, fp, (void *)1);
    will_return(wrap_fclose, 0);

    object = sys_parse_pkg(app_folder);

    // Check result
    cJSON * package = cJSON_GetObjectItem(object, "program");
    cJSON * name = cJSON_GetObjectItem(package, "name");
    cJSON * description = cJSON_GetObjectItem(package, "description");
    assert_string_equal(name->valuestring, "test");
    assert_string_equal(description->valuestring, "com.apple.Safari");
    cJSON_Delete(object);
}

// sys_read_apps

void test_sys_read_apps_dir_null(void **state) {

    const char * app_folder = "/Applications";
    int ret;

    expect_string(wrap_opendir, filename, "/Applications");
    will_return(wrap_opendir, NULL);

    expect_string(wrap_mterror, tag, "wazuh-modulesd:syscollector");
    expect_string(wrap_mterror, formatted_msg, "Unable to open '/Applications' directory due to 'No such process'");

    ret = sys_read_apps(app_folder, NULL, 0, 0, NULL);
    assert_int_equal(ret, 1);
}

void test_sys_read_apps_skip_file(void **state) {

    const char * app_folder = "/Applications";
    int ret;

    struct dirent *de = NULL;
    os_calloc(1, sizeof(struct dirent), de);
    strncpy(de->d_name, ".hidden_file", 12);

    expect_string(wrap_opendir, filename, "/Applications");
    will_return(wrap_opendir, 1);

    will_return(wrap_readdir, de);

    expect_string(wrap_snprintf, s, "/Applications/.hidden_file");
    will_return(wrap_snprintf, 26);

    will_return(wrap_readdir, NULL);

    expect_value(wrap_closedir, dirp, 1);
    will_return(wrap_closedir, 0);

    ret = sys_read_apps(app_folder, NULL, 0, 0, NULL);
    assert_int_equal(ret, 0);


    os_free(de);
}

void test_sys_read_apps_no_object(void **state) {

    const char * app_folder = "/Applications";
    int ret;

    struct dirent *de = NULL;
    os_calloc(1, sizeof(struct dirent), de);
    strncpy(de->d_name, "Test.app", 12);

    expect_string(wrap_opendir, filename, "/Applications");
    will_return(wrap_opendir, 1);

    will_return(wrap_readdir, de);

    expect_string(wrap_snprintf, s, "/Applications/Test.app");
    will_return(wrap_snprintf, 22);

    // sys_parse_pkg

    expect_string(wrap_snprintf, s, "/Applications/Test.app/Contents/Info.plist");
    will_return(wrap_snprintf, 42);
    expect_string(wrap_fopen, path, "/Applications/Test.app/Contents/Info.plist");
    expect_string(wrap_fopen, mode, "rb");
    will_return(wrap_fopen, NULL);
    expect_string(wrap_mtdebug1, tag, "wazuh-modulesd:syscollector");
    expect_string(wrap_mtdebug1, formatted_msg, "Unable to open '/Applications/Test.app/Contents/Info.plist' due to 'No such process'");

    expect_string(wrap_mtdebug1, tag, "wazuh-modulesd:syscollector");
    expect_string(wrap_mtdebug1, formatted_msg, "Unable to get package information for 'Test.app'");

    will_return(wrap_readdir, NULL);

    expect_value(wrap_closedir, dirp, 1);
    will_return(wrap_closedir, 0);

    ret = sys_read_apps(app_folder, NULL, 0, 0, NULL);
    assert_int_equal(ret, 0);


    os_free(de);
}

void test_sys_read_apps_skip_package(void **state) {

    const char * app_folder = "/Applications";
    int ret;

    struct dirent *de = NULL;
    os_calloc(1, sizeof(struct dirent), de);
    strncpy(de->d_name, "Test.app", 12);

    expect_string(wrap_opendir, filename, "/Applications");
    will_return(wrap_opendir, 1);

    will_return(wrap_readdir, de);

    expect_string(wrap_snprintf, s, "/Applications/Test.app");
    will_return(wrap_snprintf, 22);

    // sys_parse_pkg

    expect_string(wrap_snprintf, s, "/Applications/Test.app/Contents/Info.plist");
    will_return(wrap_snprintf, 42);
    expect_string(wrap_fopen, path, "/Applications/Test.app/Contents/Info.plist");
    expect_string(wrap_fopen, mode, "rb");
    will_return(wrap_fopen, 1);
    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, "<?xml");
    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, "<key>CFBundleName</key>");
    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, "<string>icloud</string>");
    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, NULL);
    expect_value(wrap_fclose, fp, (void *)1);
    will_return(wrap_fclose, 0);

    expect_string(wrap_mtdebug2, tag, "wazuh-modulesd:syscollector");
    expect_string(wrap_mtdebug2, formatted_msg, "Skipping package 'icloud' since it belongs the OS.");

    will_return(wrap_readdir, NULL);

    expect_value(wrap_closedir, dirp, 1);
    will_return(wrap_closedir, 0);

    ret = sys_read_apps(app_folder, NULL, 0, 0, NULL);
    assert_int_equal(ret, 0);


    os_free(de);
}

void test_sys_read_apps_success(void **state) {

    const char * app_folder = "/Applications";
    const char * timestamp = "2020/10/21 18:00:00";
    const char * LOCATION = "loc";
    int random_id = 123456789;
    int queue_fd = 1;
    int ret;

    struct dirent *de = NULL;
    os_calloc(1, sizeof(struct dirent), de);
    strncpy(de->d_name, "Test.app", 12);

    expect_string(wrap_opendir, filename, "/Applications");
    will_return(wrap_opendir, 1);

    will_return(wrap_readdir, de);

    expect_string(wrap_snprintf, s, "/Applications/Test.app");
    will_return(wrap_snprintf, 22);

    // sys_parse_pkg

    expect_string(wrap_snprintf, s, "/Applications/Test.app/Contents/Info.plist");
    will_return(wrap_snprintf, 42);
    expect_string(wrap_fopen, path, "/Applications/Test.app/Contents/Info.plist");
    expect_string(wrap_fopen, mode, "rb");
    will_return(wrap_fopen, 1);
    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, "<?xml");
    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, "<key>CFBundleName</key>");
    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, "<string>ProgramName</string>");
    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, NULL);
    expect_value(wrap_fclose, fp, (void *)1);
    will_return(wrap_fclose, 0);

    expect_string(wrap_mtdebug2, tag, "wazuh-modulesd:syscollector");
    expect_string(wrap_mtdebug2, formatted_msg, "Sending '{\"type\":\"program\",\"program\":{\"format\":\"pkg\",\"name\":\"ProgramName\",\"location\":\"/Applications/Test.app\"},\"ID\":123456789,\"timestamp\":\"2020/10/21 18:00:00\"}'");
    will_return(wrap_wm_sendmsg, 0);

    will_return(wrap_readdir, NULL);

    expect_value(wrap_closedir, dirp, 1);
    will_return(wrap_closedir, 0);

    ret = sys_read_apps(app_folder, timestamp, random_id, queue_fd, LOCATION);
    assert_int_equal(ret, 0);


    os_free(de);
}

// sys_read_homebrew_apps

void test_sys_read_homebrew_apps_dir_null(void **state) {

    const char * app_folder = "/usr/local/Cellar";
    int ret;

    expect_string(wrap_opendir, filename, "/usr/local/Cellar");
    will_return(wrap_opendir, NULL);

    expect_string(wrap_mtdebug1, tag, "wazuh-modulesd:syscollector");
    expect_string(wrap_mtdebug1, formatted_msg, "No homebrew applications found in '/usr/local/Cellar'");

    ret = sys_read_homebrew_apps(app_folder, NULL, 0, 0, NULL);
    assert_int_equal(ret, 1);
}

void test_sys_read_homebrew_apps_skip_file(void **state) {

    const char * app_folder = "/usr/local/Cellar";
    int ret;

    struct dirent *de = NULL;
    os_calloc(1, sizeof(struct dirent), de);
    strncpy(de->d_name, ".hidden_file", 12);

    expect_string(wrap_opendir, filename, "/usr/local/Cellar");
    will_return(wrap_opendir, 1);

    will_return(wrap_readdir, de);

    will_return(wrap_readdir, NULL);

    expect_value(wrap_closedir, dirp, 1);
    will_return(wrap_closedir, 0);

    ret = sys_read_homebrew_apps(app_folder, NULL, 0, 0, NULL);
    assert_int_equal(ret, 0);

    os_free(de);
}

void test_sys_read_homebrew_apps_skip_version(void **state) {

    const char * app_folder = "/usr/local/Cellar";
    const char * timestamp = "2020/10/21 18:00:00";
    const char * LOCATION = "loc";
    int random_id = 123456789;
    int queue_fd = 1;
    int ret;

    struct dirent *de = NULL;
    os_calloc(1, sizeof(struct dirent), de);
    strncpy(de->d_name, "test", 4);

    struct dirent *version = NULL;
    os_calloc(1, sizeof(struct dirent), version);
    strncpy(version->d_name, ".hidden_file", 12);

    expect_string(wrap_opendir, filename, "/usr/local/Cellar");
    will_return(wrap_opendir, 1);
    will_return(wrap_readdir, de);

    expect_string(wrap_snprintf, s, "/usr/local/Cellar/test");
    will_return(wrap_snprintf, 20);

    expect_string(wrap_opendir, filename, "/usr/local/Cellar/test");
    will_return(wrap_opendir, 2);
    will_return(wrap_readdir, version);

    will_return(wrap_readdir, NULL);

    expect_value(wrap_closedir, dirp, 2);
    will_return(wrap_closedir, 0);

    expect_string(wrap_mtdebug2, tag, "wazuh-modulesd:syscollector");
    expect_string(wrap_mtdebug2, formatted_msg, "Sending '{\"type\":\"program\",\"ID\":123456789,\"timestamp\":\"2020/10/21 18:00:00\",\"program\":{\"format\":\"pkg\",\"name\":\"test\",\"location\":\"/usr/local/Cellar/test\"}}'");
    will_return(wrap_wm_sendmsg, 0);

    will_return(wrap_readdir, NULL);

    expect_value(wrap_closedir, dirp, 1);
    will_return(wrap_closedir, 0);

    ret = sys_read_homebrew_apps(app_folder, timestamp, random_id, queue_fd, LOCATION);
    assert_int_equal(ret, 0);


    os_free(version);
    os_free(de);
}

void test_sys_read_homebrew_apps_success(void **state) {

    const char * app_folder = "/usr/local/Cellar";
    const char * timestamp = "2020/10/21 18:00:00";
    const char * LOCATION = "loc";
    int random_id = 123456789;
    int queue_fd = 1;
    int ret;

    struct dirent *de = NULL;
    os_calloc(1, sizeof(struct dirent), de);
    strncpy(de->d_name, "test@1.0_1", 10);

    struct dirent *version = NULL;
    os_calloc(1, sizeof(struct dirent), version);
    strncpy(version->d_name, "1.0_1", 5);

    expect_string(wrap_opendir, filename, "/usr/local/Cellar");
    will_return(wrap_opendir, 1);
    will_return(wrap_readdir, de);

    expect_string(wrap_snprintf, s, "/usr/local/Cellar/test@1.0_1");
    will_return(wrap_snprintf, 26);

    expect_string(wrap_opendir, filename, "/usr/local/Cellar/test@1.0_1");
    will_return(wrap_opendir, 2);
    will_return(wrap_readdir, version);

    expect_string(wrap_snprintf, s, "/usr/local/Cellar/test@1.0_1/1.0_1/.brew/test@1.0_1.rb");
    will_return(wrap_snprintf, 52);

    expect_string(wrap_fopen, path, "/usr/local/Cellar/test@1.0_1/1.0_1/.brew/test@1.0_1.rb");
    expect_string(wrap_fopen, mode, "r");
    will_return(wrap_fopen, 3);

    expect_value(wrap_fgets, __stream, (FILE *)3);
    will_return(wrap_fgets, "desc \"This is the description\"");

    expect_value(wrap_fclose, fp, (void *)3);
    will_return(wrap_fclose, 0);

    will_return(wrap_readdir, NULL);

    expect_value(wrap_closedir, dirp, 2);
    will_return(wrap_closedir, 0);

    expect_string(wrap_mtdebug2, tag, "wazuh-modulesd:syscollector");
    expect_string(wrap_mtdebug2, formatted_msg, "Sending '{\"type\":\"program\",\"ID\":123456789,\"timestamp\":\"2020/10/21 18:00:00\",\"program\":{\"format\":\"pkg\",\"name\":\"test\",\"location\":\"/usr/local/Cellar/test@1.0_1\",\"version\":\"1.0\",\"description\":\"This is the description\"}}'");
    will_return(wrap_wm_sendmsg, 0);

    will_return(wrap_readdir, NULL);

    expect_value(wrap_closedir, dirp, 1);
    will_return(wrap_closedir, 0);

    ret = sys_read_homebrew_apps(app_folder, timestamp, random_id, queue_fd, LOCATION);
    assert_int_equal(ret, 0);

    os_free(version);
    os_free(de);
}

void test_get_vendor_mac(void **state) {
    int i;
    char * vendor = NULL;
    char * vendors[18][2] = {
        {"com.google.Chrome", "Google"},
        {"com.apple.Safari", "Apple"},
        {"com.microsoft.to-do-mac", "Microsoft"},
        {"com.adobe.Reader", "Adobe"},
        {"com.atlassian.trello", "Atlassian"},
        {"com.oracle.java.8u171.jdk", "Oracle"},
        {"com.sophos.sav", "Sophos"},
        {"com.symantec.endpointprotection", "Symantec"},
        {"com.kaspersky.kav", "Kaspersky"},
        {"com.mcafee.console", "Mcafee"},
        {"com.bitdefender.antivirusformac", "Bitdefender"},
        {"com.k7computing.AntiVirus", "K7computing"},
        {"com.avg.antivirus", "Avg"},
        {"com.avast.antivirus", "Avast"},
        {"com.simplexsolutionsinc.vpnguardMac", "Simplexsolutionsinc"},
        {"com.liquid.reader.osx", "Liquid"},
        {"com.foxit-software.Foxit Reader", "Foxitsoftware"},
        {"org.audacityteam.audacity", NULL},
    };

    for (i = 0; i < 18; i++) {
        vendor = get_vendor_mac(vendors[i][0]);
        if (i < 17) {
            assert_string_equal(vendor, vendors[i][1]);
            os_free(vendor);
        } else {
            assert_null(vendor);
        }
    }
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_sys_convert_bin_plist_failed_stat),
        cmocka_unit_test(test_sys_convert_bin_plist_failed_mmap),
        cmocka_unit_test(test_sys_convert_bin_plist_empty_node),
        cmocka_unit_test(test_sys_convert_bin_plist_failed_xml),
        cmocka_unit_test(test_sys_convert_bin_plist_failed_tmpfile),
        cmocka_unit_test(test_sys_convert_bin_plist_ok),
        cmocka_unit_test(test_normalize_mac_package_name),
        cmocka_unit_test(test_sys_parse_pkg_fopen_error),
        cmocka_unit_test(test_sys_parse_pkg_fgets_null),
        cmocka_unit_test(test_sys_parse_pkg_unknown_format),
        cmocka_unit_test(test_sys_parse_pkg_name_same_line),
        cmocka_unit_test(test_sys_parse_pkg_name_vendor_same_line),
        cmocka_unit_test(test_sys_parse_pkg_name),
        cmocka_unit_test(test_sys_parse_pkg_name_vendor),
        cmocka_unit_test(test_sys_parse_pkg_version_same_line),
        cmocka_unit_test(test_sys_parse_pkg_version),
        cmocka_unit_test(test_sys_parse_pkg_custom_version_key),
        cmocka_unit_test(test_sys_parse_pkg_group_same_line),
        cmocka_unit_test(test_sys_parse_pkg_group),
        cmocka_unit_test(test_sys_parse_pkg_description_same_line),
        cmocka_unit_test(test_sys_parse_pkg_description),
        cmocka_unit_test(test_get_vendor_mac),
        cmocka_unit_test_setup(test_sys_read_apps_dir_null, setup_max_eps),
        cmocka_unit_test_setup(test_sys_read_apps_skip_file, setup_max_eps),
        cmocka_unit_test_setup(test_sys_read_apps_no_object, setup_max_eps),
        cmocka_unit_test_setup(test_sys_read_apps_skip_package, setup_max_eps),
        cmocka_unit_test_setup(test_sys_read_apps_success, setup_max_eps),
        cmocka_unit_test_setup(test_sys_read_homebrew_apps_dir_null, setup_max_eps),
        cmocka_unit_test_setup(test_sys_read_homebrew_apps_skip_file, setup_max_eps),
        cmocka_unit_test_setup(test_sys_read_homebrew_apps_skip_version, setup_max_eps),
        cmocka_unit_test_setup(test_sys_read_homebrew_apps_success, setup_max_eps),
    };
    return cmocka_run_group_tests(tests, setup_wrappers, teardown_wrappers);
}
