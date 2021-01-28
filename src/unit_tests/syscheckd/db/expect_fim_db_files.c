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
#ifndef TEST_WINAGENT
    expect_any_count(__wrap_sqlite3_bind_int, index, 3);
    expect_any_count(__wrap_sqlite3_bind_int, value, 3);
    will_return_count(__wrap_sqlite3_bind_int, 0, 3);

    expect_any(__wrap_sqlite3_bind_int64, index);
    expect_any(__wrap_sqlite3_bind_int64, value);
    will_return(__wrap_sqlite3_bind_int64, 0);
#else
    expect_any_count(__wrap_sqlite3_bind_int, index, 2);
    expect_any_count(__wrap_sqlite3_bind_int, value, 2);
    will_return_count(__wrap_sqlite3_bind_int, 0, 2);
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

void expect_fim_db_get_paths_from_inode(char **paths) {
    expect_fim_db_clean_stmt(/*FIMDB_STMT_GET_PATHS_INODE*/);
    expect_fim_db_clean_stmt(/*FIMDB_STMT_GET_PATHS_INODE_COUNT*/);

    expect_fim_db_bind_get_inode();

    will_return(__wrap_sqlite3_step, 0);
    if (paths == NULL) {
        will_return(__wrap_sqlite3_step, SQLITE_DONE);
    } else {
        // TODO: Get length of paths by scanning to the final NULL, add sqlite3_column_text will_returns for each string
    }
    expect_fim_db_check_transaction();
}

/**
 * Successfully wrappes a fim_db_decode_full_row() call
 * */
void expect_fim_db_decode_full_row() {
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "/some/random/path"); // path
    expect_value(__wrap_sqlite3_column_int, iCol, 2);
    will_return(__wrap_sqlite3_column_int, 1); // mode
    expect_value(__wrap_sqlite3_column_int, iCol, 3);
    will_return(__wrap_sqlite3_column_int, 1000000); // last_event
    expect_value(__wrap_sqlite3_column_int, iCol, 4);
    will_return(__wrap_sqlite3_column_int, 1000001); // scanned
    expect_value(__wrap_sqlite3_column_int, iCol, 5);
    will_return(__wrap_sqlite3_column_int, 1000002); // options
    expect_value(__wrap_sqlite3_column_text, iCol, 6);
    will_return(__wrap_sqlite3_column_text, "checksum"); // checksum
    expect_value(__wrap_sqlite3_column_int, iCol, 7);
    will_return(__wrap_sqlite3_column_int, 111); // dev
    expect_value(__wrap_sqlite3_column_int64, iCol, 8);
    will_return(__wrap_sqlite3_column_int64, 1024); // inode
    expect_value(__wrap_sqlite3_column_int, iCol, 9);
    will_return(__wrap_sqlite3_column_int, 4096); // size
    expect_value_count(__wrap_sqlite3_column_text, iCol, 10, 2);
    will_return_count(__wrap_sqlite3_column_text, "perm", 2); // perm
    expect_value_count(__wrap_sqlite3_column_text, iCol, 11, 2);
    will_return_count(__wrap_sqlite3_column_text, "attributes", 2); // attributes
    expect_value_count(__wrap_sqlite3_column_text, iCol, 12, 2);
    will_return_count(__wrap_sqlite3_column_text, "uid", 2); // uid
    expect_value_count(__wrap_sqlite3_column_text, iCol, 13, 2);
    will_return_count(__wrap_sqlite3_column_text, "gid", 2); // gid
    expect_value_count(__wrap_sqlite3_column_text, iCol, 14, 2);
    will_return_count(__wrap_sqlite3_column_text, "user_name", 2); // user_name
    expect_value_count(__wrap_sqlite3_column_text, iCol, 15, 2);
    will_return_count(__wrap_sqlite3_column_text, "group_name", 2); // group_name
    expect_value(__wrap_sqlite3_column_text, iCol, 16);
    will_return(__wrap_sqlite3_column_text, "hash_md5"); // hash_md5
    expect_value(__wrap_sqlite3_column_text, iCol, 17);
    will_return(__wrap_sqlite3_column_text, "hash_sha1"); // hash_sha1
    expect_value(__wrap_sqlite3_column_text, iCol, 18);
    will_return(__wrap_sqlite3_column_text, "hash_sha256"); // hash_sha256
    expect_value(__wrap_sqlite3_column_int, iCol, 19);
    will_return(__wrap_sqlite3_column_int, 12345678); // mtime
}

void expect_fim_db_decode_full_row_from_entry(const fim_entry *entry) {
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, entry->file_entry.path);

    expect_value(__wrap_sqlite3_column_int, iCol, 2);
    will_return(__wrap_sqlite3_column_int, entry->file_entry.data->mode);

    expect_value(__wrap_sqlite3_column_int, iCol, 3);
    will_return(__wrap_sqlite3_column_int, entry->file_entry.data->last_event);

    expect_value(__wrap_sqlite3_column_int, iCol, 4);
    will_return(__wrap_sqlite3_column_int, entry->file_entry.data->scanned);

    expect_value(__wrap_sqlite3_column_int, iCol, 5);
    will_return(__wrap_sqlite3_column_int, entry->file_entry.data->options);

    expect_value(__wrap_sqlite3_column_text, iCol, 6);
    will_return(__wrap_sqlite3_column_text, entry->file_entry.data->checksum);

    expect_value(__wrap_sqlite3_column_int, iCol, 7);
    will_return(__wrap_sqlite3_column_int, entry->file_entry.data->dev);

    expect_value(__wrap_sqlite3_column_int64, iCol, 8);
    will_return(__wrap_sqlite3_column_int64, entry->file_entry.data->inode);

    expect_value(__wrap_sqlite3_column_int, iCol, 9);
    will_return(__wrap_sqlite3_column_int, entry->file_entry.data->size);

    expect_value_count(__wrap_sqlite3_column_text, iCol, 10, entry->file_entry.data->perm ? 2 : 1);
    will_return_count(__wrap_sqlite3_column_text, entry->file_entry.data->perm, entry->file_entry.data->perm ? 2 : 1);

    expect_value_count(__wrap_sqlite3_column_text, iCol, 11, entry->file_entry.data->attributes ? 2 : 1);
    will_return_count(__wrap_sqlite3_column_text, entry->file_entry.data->attributes,
                      entry->file_entry.data->attributes ? 2 : 1);

    expect_value_count(__wrap_sqlite3_column_text, iCol, 12, entry->file_entry.data->uid ? 2 : 1);
    will_return_count(__wrap_sqlite3_column_text, entry->file_entry.data->uid, entry->file_entry.data->uid ? 2 : 1);

    expect_value_count(__wrap_sqlite3_column_text, iCol, 13, entry->file_entry.data->gid ? 2 : 1);
    will_return_count(__wrap_sqlite3_column_text, entry->file_entry.data->gid, entry->file_entry.data->gid ? 2 : 1);

    expect_value_count(__wrap_sqlite3_column_text, iCol, 14, entry->file_entry.data->user_name ? 2 : 1);
    will_return_count(__wrap_sqlite3_column_text, entry->file_entry.data->user_name,
                      entry->file_entry.data->user_name ? 2 : 1);

    expect_value_count(__wrap_sqlite3_column_text, iCol, 15, entry->file_entry.data->group_name ? 2 : 1);
    will_return_count(__wrap_sqlite3_column_text, entry->file_entry.data->group_name,
                      entry->file_entry.data->group_name ? 2 : 1);

    expect_value(__wrap_sqlite3_column_text, iCol, 16);
    will_return(__wrap_sqlite3_column_text, entry->file_entry.data->hash_md5);

    expect_value(__wrap_sqlite3_column_text, iCol, 17);
    will_return(__wrap_sqlite3_column_text, entry->file_entry.data->hash_sha1);

    expect_value(__wrap_sqlite3_column_text, iCol, 18);
    will_return(__wrap_sqlite3_column_text, entry->file_entry.data->hash_sha256);

    expect_value(__wrap_sqlite3_column_int, iCol, 19);
    will_return(__wrap_sqlite3_column_int, entry->file_entry.data->mtime);
}
