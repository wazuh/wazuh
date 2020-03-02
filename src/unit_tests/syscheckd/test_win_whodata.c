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

#define WIN_WHODATA 1
#include "syscheckd/syscheck.h"

extern int set_winsacl(const char *dir, int position);
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

void __wrap__merror(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}
/**************************************************************************/
/***************************set_winsacl************************************/
void test_set_winsacl_opened_failed(void **state) {
    char debug_msg[OS_MAXSTR];
    snprintf(debug_msg, OS_MAXSTR, FIM_SACL_CONFIGURE, syscheck.dir[0]);
    expect_string(__wrap__mdebug2, formatted_msg, debug_msg);

    expect_value(wrap_OpenProcessToken, DesiredAccess, TOKEN_ADJUST_PRIVILEGES);
    will_return(wrap_OpenProcessToken, 0); 

    will_return(wrap_GetLastError, (unsigned int) 500);
    expect_string(__wrap__merror, formatted_msg, "(6648): OpenProcessToken() failed. Error '500'.");

    set_winsacl(syscheck.dir[0], 0);
}
/**************************************************************************/
int main(void) {
    const struct CMUnitTest tests[] = {
        /* set_winsacl */
        cmocka_unit_test(test_set_winsacl_opened_failed),
    };

    return cmocka_run_group_tests(tests, test_group_setup, NULL);
}