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
#include "../../wrappers/macos/libplist_wrappers.h"
#include "../../wrappers/macos/libwazuh_wrappers.h"
#include "../../../wazuh_modules/syscollector/syscollector.h"
#include "../../wazuh_modules/wmodules.h"

int extern test_mode;

bool sys_convert_bin_plist(FILE **fp, char *magic_bytes, char *filepath);

static int setup_wrappers(void **state) {
    test_mode = 1;
    return 0;
}

static int teardown_wrappers(void **state) {
    test_mode = 0;
    return 0;
}

void test_sys_convert_bin_plist_failed_stat(void **state) 
{
    int stat_size = 20;
    FILE *fp = (void *)1;

    will_return(wrap_fileno, 3);

    will_return(wrap_fstat, stat_size);
    will_return(wrap_fstat, -1);

    expect_string(wrap_mterror, tag, "wazuh-modulesd:syscollector");
    expect_string(wrap_mterror, formatted_msg, "Failed to stat file 'prueba': Undefined error: 0");    

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
    expect_string(wrap_mterror, formatted_msg, "Failed to mmap file 'prueba': Undefined error: 0");    

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
    will_return(wrap_plist_to_xml, (void *)1);
    will_return(wrap_plist_to_xml, stat_size);
    
    expect_value(wrap_fclose, fp, (void *)1);
    will_return(wrap_fclose, 1);

    will_return(wrap_tmpfile, NULL);

    expect_string(wrap_mterror, tag, "wazuh-modulesd:syscollector");
    expect_string(wrap_mterror, formatted_msg, "Failed to open tmpfile: Undefined error: 0");

    expect_value(wrap_plist_free, node, (plist_t)1);
    expect_value(wrap_munmap, mem, (void *)1);

    bool ret = sys_convert_bin_plist(&fp, NULL, NULL);
    assert_int_equal(ret, false);
}

void test_sys_convert_bin_plist_ok(void **state) 
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
    will_return(wrap_plist_to_xml, (void *)1);
    will_return(wrap_plist_to_xml, stat_size);
    
    expect_value(wrap_fclose, fp, (void *)1);
    will_return(wrap_fclose, 1);

    will_return(wrap_tmpfile, (void *)1);

    expect_value(wrap_fwrite, src, (char *)1);
    will_return(wrap_fwrite, 1);

    expect_value(wrap_fseek, fp, (FILE *)1);

    expect_value(wrap_fgets, __stream, (FILE *)1);
    will_return(wrap_fgets, "<?xml");

    expect_value(wrap_plist_free, node, (plist_t)1);
    expect_value(wrap_munmap, mem, (void *)1);

    bool ret = sys_convert_bin_plist(&fp, NULL, NULL);
    assert_int_equal(ret, true);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_sys_convert_bin_plist_failed_stat, setup_wrappers, teardown_wrappers),
        cmocka_unit_test_setup_teardown(test_sys_convert_bin_plist_failed_mmap, setup_wrappers, teardown_wrappers),
        cmocka_unit_test_setup_teardown(test_sys_convert_bin_plist_empty_node, setup_wrappers, teardown_wrappers),
        cmocka_unit_test_setup_teardown(test_sys_convert_bin_plist_failed_xml, setup_wrappers, teardown_wrappers),
        cmocka_unit_test_setup_teardown(test_sys_convert_bin_plist_failed_tmpfile, setup_wrappers, teardown_wrappers),
        cmocka_unit_test_setup_teardown(test_sys_convert_bin_plist_ok, setup_wrappers, teardown_wrappers)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
