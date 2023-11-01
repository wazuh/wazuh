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
#include <stdio.h>

#include "../../../wazuh_modules/wmodules.h"

#define COMMAND u8"Powershell -c \"@{ winCounter = (Get-Counter '\\mémoire\\mégaoctets disponibles').CounterSamples[0] } | ConvertTo-Json -compress\""
#define COMMAND2 u8"Powershell -c \"@{ winCounter = (Get-Counter '\\processeur(_total)\\% temps processeur').CounterSamples[0] } | ConvertTo-Json -compress\""

static void test_wm_exec_accented_command(void ** state) {
#ifdef WIN32
    size_t size = mbstowcs(NULL, COMMAND, 0);
    wchar_t *wcommand = calloc(size, sizeof(wchar_t));
    mbstowcs(wcommand, COMMAND, size);

    expect_any(__wrap__mdebug2, formatted_msg);
    expect_string(wrap_CreateProcessW, lpCommandLine, wcommand);
    will_return(wrap_CreateProcessW, TRUE);
    expect_any(wrap_WaitForSingleObject, hMutex);
    expect_any(wrap_WaitForSingleObject, value);
    will_return(wrap_WaitForSingleObject, 0);
    expect_any(wrap_CloseHandle, hObject);
    will_return(wrap_CloseHandle, FALSE);
    expect_any(wrap_CloseHandle, hObject);
    will_return(wrap_CloseHandle, FALSE);
    assert_int_equal(0, wm_exec(COMMAND, NULL, NULL, 0, NULL));

    free(wcommand);
#else
    printf("not implemented yet!\n");
#endif
}

static void test_wm_exec_not_accented_command(void ** state) {
#ifdef WIN32
    size_t size = mbstowcs(NULL, COMMAND2, 0);
    wchar_t *wcommand = calloc(size, sizeof(wchar_t));
    mbstowcs(wcommand, COMMAND2, size);

    expect_any(__wrap__mdebug2, formatted_msg);
    expect_string(wrap_CreateProcessW, lpCommandLine, wcommand);
    will_return(wrap_CreateProcessW, TRUE);
    expect_any(wrap_WaitForSingleObject, hMutex);
    expect_any(wrap_WaitForSingleObject, value);
    will_return(wrap_WaitForSingleObject, 0);
    expect_any(wrap_CloseHandle, hObject);
    will_return(wrap_CloseHandle, FALSE);
    expect_any(wrap_CloseHandle, hObject);
    will_return(wrap_CloseHandle, FALSE);
    assert_int_equal(0, wm_exec(COMMAND2, NULL, NULL, 0, NULL));

    free(wcommand);
#else
    printf("not implemented yet!\n");
#endif
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_wm_exec_accented_command),
        cmocka_unit_test(test_wm_exec_not_accented_command)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
