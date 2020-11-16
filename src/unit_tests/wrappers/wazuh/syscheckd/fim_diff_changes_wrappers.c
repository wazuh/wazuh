/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "fim_diff_changes_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

char *__wrap_fim_file_diff(const char *filename) {
    check_expected(filename);

    return mock_type(char *);
}

char *__wrap_fim_diff_process_delete_file(const char *filename) {
    check_expected(filename);

    return mock_type(char *);
}

void expect_fim_file_diff(const char *filename, char *ret) {
    expect_string(__wrap_fim_file_diff, filename, filename);
    will_return(__wrap_fim_file_diff, ret);
}

void expect_fim_diff_process_delete_file(const char *filename, char *ret) {
    expect_string(__wrap_fim_diff_process_delete_file, filename, filename);
    will_return(__wrap_fim_diff_process_delete_file, ret);
}
