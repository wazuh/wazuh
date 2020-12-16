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

extern const char *registry_arch[];

void expect_fim_db_decode_registry_key(const fim_registry_key *key) {
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, key->id);

    expect_value_count(__wrap_sqlite3_column_text, iCol, 1, key->path ? 2 : 1);
    will_return_count(__wrap_sqlite3_column_text, key->path, key->path ? 2 : 1);

    expect_value_count(__wrap_sqlite3_column_text, iCol, 2, key->perm ? 2 : 1);
    will_return_count(__wrap_sqlite3_column_text, key->perm, key->perm ? 2 : 1);

    expect_value_count(__wrap_sqlite3_column_text, iCol, 3, key->uid ? 2 : 1);
    will_return_count(__wrap_sqlite3_column_text, key->uid, key->uid ? 2 : 1);

    expect_value_count(__wrap_sqlite3_column_text, iCol, 4, key->gid ? 2 : 1);
    will_return_count(__wrap_sqlite3_column_text, key->gid, key->gid ? 2 : 1);

    expect_value_count(__wrap_sqlite3_column_text, iCol, 5, key->user_name ? 2 : 1);
    will_return_count(__wrap_sqlite3_column_text, key->user_name, key->user_name ? 2 : 1);

    expect_value_count(__wrap_sqlite3_column_text, iCol, 6, key->group_name ? 2 : 1);
    will_return_count(__wrap_sqlite3_column_text, key->group_name, key->group_name ? 2 : 1);

    expect_value(__wrap_sqlite3_column_int, iCol, 7);
    will_return(__wrap_sqlite3_column_int, key->mtime);

    expect_value(__wrap_sqlite3_column_text, iCol, 8);
    will_return(__wrap_sqlite3_column_text, registry_arch[key->arch]);

    expect_value(__wrap_sqlite3_column_int, iCol, 9);
    will_return(__wrap_sqlite3_column_int, key->scanned);

    expect_value(__wrap_sqlite3_column_int, iCol, 10);
    will_return(__wrap_sqlite3_column_int, key->last_event);

    expect_value(__wrap_sqlite3_column_text, iCol, 11);
    will_return(__wrap_sqlite3_column_text, key->checksum);
}

void expect_fim_db_decode_registry_value(const fim_registry_value_data *data) {
    expect_value(__wrap_sqlite3_column_int, iCol, 0);
    will_return(__wrap_sqlite3_column_int, data->id);

    expect_value_count(__wrap_sqlite3_column_text, iCol, 1, data->name ? 2 : 1);
    will_return_count(__wrap_sqlite3_column_text, data->name, data->name ? 2 : 1);

    expect_value(__wrap_sqlite3_column_int, iCol, 2);
    will_return(__wrap_sqlite3_column_int, data->type);

    expect_value(__wrap_sqlite3_column_int, iCol, 3);
    will_return(__wrap_sqlite3_column_int, data->size);

    expect_value(__wrap_sqlite3_column_text, iCol, 4);
    will_return(__wrap_sqlite3_column_text, data->hash_md5);

    expect_value(__wrap_sqlite3_column_text, iCol, 5);
    will_return(__wrap_sqlite3_column_text, data->hash_sha1);

    expect_value(__wrap_sqlite3_column_text, iCol, 6);
    will_return(__wrap_sqlite3_column_text, data->hash_sha256);

    expect_value(__wrap_sqlite3_column_int, iCol, 7);
    will_return(__wrap_sqlite3_column_int, data->scanned);

    expect_value(__wrap_sqlite3_column_int, iCol, 8);
    will_return(__wrap_sqlite3_column_int, data->last_event);

    expect_value(__wrap_sqlite3_column_text, iCol, 9);
    will_return(__wrap_sqlite3_column_text, data->checksum);
}

void expect_fim_db_bind_registry_path(const char *path, unsigned int arch) {
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, path);
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, arch == ARCH_32BIT ? "[x32]" : "[x64]");
    will_return(__wrap_sqlite3_bind_text, 0);
}

void expect_fim_db_get_registry_key(const fim_registry_key *key) {
    expect_fim_db_clean_stmt();
    expect_fim_db_bind_registry_path(key->path, key->arch);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_fim_db_decode_registry_key(key);
}

void expect_fim_db_get_registry_key_fail(const fim_registry_key *key) {
    expect_fim_db_clean_stmt();
    expect_fim_db_bind_registry_path(key->path, key->arch);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
}

void expect_fim_db_bind_registry_data_name_key_id(const char *name, int key_id) {
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, name);
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, key_id);
    will_return(__wrap_sqlite3_bind_int, 0);
}

void expect_fim_db_get_registry_data_fail(const char *name, int key_id) {
    expect_fim_db_clean_stmt();
    expect_fim_db_bind_registry_data_name_key_id(name, key_id);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
}

void expect_fim_db_get_registry_data(const char *name, int key_id, const fim_registry_value_data *data) {
    expect_fim_db_clean_stmt();
    expect_fim_db_bind_registry_data_name_key_id(name, key_id);

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ROW);

    expect_fim_db_decode_registry_value(data);
}
