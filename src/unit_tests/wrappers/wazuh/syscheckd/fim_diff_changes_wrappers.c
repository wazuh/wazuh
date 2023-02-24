/* Copyright (C) 2015, Wazuh Inc.
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

int __wrap_fim_diff_process_delete_file(const char *filename) {
    check_expected(filename);

    return mock();
}

void expect_fim_file_diff(const char *filename, char *ret) {
    expect_string(__wrap_fim_file_diff, filename, filename);
    will_return(__wrap_fim_file_diff, ret);
}

void expect_fim_diff_process_delete_file(const char *filename, int ret) {
    expect_string(__wrap_fim_diff_process_delete_file, filename, filename);
    will_return(__wrap_fim_diff_process_delete_file, ret);
}

#ifdef WIN32
char *__wrap_fim_registry_value_diff(const char *key_name,
                                     const char *value_name,
                                     const char *value_data,
                                     DWORD data_type,
                                     __attribute__((unused)) const registry_t *configuration) {
    check_expected(key_name);
    check_expected(value_name);
    check_expected(value_data);
    check_expected(data_type);

    return mock_type(char *);
}

void expect_fim_registry_value_diff(const char *key_name,
                                    const char *value_name,
                                    const char *value_data,
                                    DWORD data_size,
                                    DWORD data_type,
                                    char *ret) {
    expect_string(__wrap_fim_registry_value_diff, key_name, key_name);
    expect_string(__wrap_fim_registry_value_diff, value_name, value_name);
    expect_memory(__wrap_fim_registry_value_diff, value_data, value_data, data_size);
    expect_value(__wrap_fim_registry_value_diff, data_type, data_type);
    will_return(__wrap_fim_registry_value_diff, ret);
}
#endif
