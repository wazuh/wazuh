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

#include "test_fim_db.h"

void expect_fim_db_bind_insert_data(int text_count) {
    expect_any_count(__wrap_sqlite3_bind_int, index, 3);
    expect_any_count(__wrap_sqlite3_bind_int, value, 3);
    will_return_count(__wrap_sqlite3_bind_int, 0, 3);
#ifndef TEST_WINAGENT
    expect_any(__wrap_sqlite3_bind_int64, index);
    expect_any(__wrap_sqlite3_bind_int64, value);
    will_return(__wrap_sqlite3_bind_int64, 0);
#endif
    expect_any_count(__wrap_sqlite3_bind_text, pos, 9);
    expect_any_count(__wrap_sqlite3_bind_text, buffer, text_count);
    will_return_count(__wrap_sqlite3_bind_text, 0, 9);
}

void expect_fim_db_bind_update_data(int text_count) {
    expect_any_count(__wrap_sqlite3_bind_int, index, 3);
    expect_any_count(__wrap_sqlite3_bind_int, value, 3);
    will_return_count(__wrap_sqlite3_bind_int, 0, 3);

    expect_any_count(__wrap_sqlite3_bind_text, pos, 9);
    expect_any_count(__wrap_sqlite3_bind_text, buffer, text_count);
    will_return_count(__wrap_sqlite3_bind_text, 0, 9);
}

void expect_fim_db_bind_replace_path(int text_count) {
    expect_any_count(__wrap_sqlite3_bind_int, index, 5);
    expect_any_count(__wrap_sqlite3_bind_int, value, 5);
    will_return_count(__wrap_sqlite3_bind_int, 0, 5);

    expect_any_count(__wrap_sqlite3_bind_text, pos, 2);
    expect_any_count(__wrap_sqlite3_bind_text, buffer, text_count);
    will_return_count(__wrap_sqlite3_bind_text, 0, 2);
}

void expect_fim_db_bind_delete_data_id(int row) {
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, row);
    will_return(__wrap_sqlite3_bind_int, 0);
}

void expect_fim_db_bind_get_inode() {
    expect_any(__wrap_sqlite3_bind_int64, index);
    expect_any(__wrap_sqlite3_bind_int64, value);
    will_return(__wrap_sqlite3_bind_int64, 0);

    expect_any(__wrap_sqlite3_bind_int, index);
    expect_any(__wrap_sqlite3_bind_int, value);
    will_return(__wrap_sqlite3_bind_int, 0);
}

void expect_fim_db_insert_path_success() {
    expect_fim_db_clean_stmt();

    expect_fim_db_bind_replace_path(2);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);
}

void expect_fim_db_insert_data_success(int row_id) {
    expect_fim_db_clean_stmt();

    if (row_id == 0) {
        expect_fim_db_bind_insert_data(3);
    } else {
        expect_fim_db_bind_update_data(3);
    }

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_DONE);

    if (row_id == 0) {
        will_return(__wrap_sqlite3_last_insert_rowid, 1);
    }
}

void expect_fim_db_bind_path(const char *path) {
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, path);
    will_return(__wrap_sqlite3_bind_text, 0);
}
