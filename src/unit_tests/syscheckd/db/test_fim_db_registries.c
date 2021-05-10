/*
 * Copyright (C) 2015-2021, Wazuh Inc.
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
#include "../../../syscheckd/db/fim_db.h"

extern int _base_line;

void fim_registry_free_key(fim_registry_key *key);
void fim_registry_free_value_data(fim_registry_value_data *data);

static const char *default_key_query = "INSERT INTO registry_key VALUES(1, \"HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile\", \"permissions\", \"userid\", \"groupid\", \"username\", \"groupname\", 1234, \'[x32]\', 0, 1234, \"checksum1\");";

int check_fim_db_reg_key(fim_registry_key *key_to_check){
    fim_registry_key *key_saved = fim_db_get_registry_key(syscheck.database, key_to_check->path, key_to_check->arch);
    if(!key_saved){
        return -1;
    }

    assert_string_equal(key_saved->perm, key_to_check->perm);
    assert_string_equal(key_saved->uid, key_to_check->uid);
    assert_string_equal(key_saved->gid, key_to_check->gid);
    assert_string_equal(key_saved->user_name, key_to_check->user_name);
    assert_string_equal(key_saved->group_name, key_to_check->group_name);

    fim_registry_free_key(key_saved);

    return 0;
}

int check_fim_db_reg_value_data(fim_registry_value_data *value_to_check, int id){

    fim_registry_value_data *value_saved = fim_db_get_registry_data(syscheck.database, id, value_to_check->name);
    if(!value_saved){
        return -1;
    }

    assert_string_equal(value_saved->name, value_to_check->name);
    assert_int_equal(value_saved->type, value_to_check->type);
    assert_int_equal(value_saved->size, value_to_check->size);

    fim_registry_free_value_data(value_saved);

    return 0;
}

fim_registry_key *create_reg_key(int id, const char *path, const char *perm, const char *uid, const char *gid,
                                 const char *user_name, const char *group_name) {
    fim_registry_key *ret;

    os_calloc(1, sizeof(fim_registry_key), ret);

    ret->id = id;
    os_strdup(path, ret->path);
    os_strdup(perm, ret->perm);
    os_strdup(uid, ret->uid);
    os_strdup(gid, ret->gid);
    os_strdup(user_name, ret->user_name);
    os_strdup(group_name, ret->group_name);

    return ret;
}

fim_registry_value_data *create_reg_value_data(int id, char *name, unsigned int type, unsigned int size) {
    fim_registry_value_data *ret;

    os_calloc(1, sizeof(fim_registry_value_data), ret);

    os_strdup(name, ret->name);
    ret->id = id;
    ret->type = type;
    ret->size = size;

    return ret;
}

void execute_query(const char *query) {
    char *err_msg = NULL;
    sqlite3_exec(syscheck.database->db, query, NULL, NULL, &err_msg);
    if (err_msg) {
        sqlite3_free(err_msg);
        fail_msg("%s", err_msg);
    }
}

static int setup_group(void **state) {

#ifdef TEST_WINAGENT
    time_mock_value = 192837465;
#endif

    will_return_always(__wrap_sqlite3_step, 1);

    // Init database
    syscheck.database = fim_db_init(0);

    return 0;
}

static int teardown_group(void **state) {
    // Close database

    expect_string(__wrap__mdebug1, formatted_msg, "Database transaction completed.");
    fim_db_close(syscheck.database);
    fim_db_clean();

    return 0;
}

static int teardown_delete_tables(void **state) {
    // DELETE TABLES
    execute_query("DELETE FROM registry_data;");
    execute_query("DELETE FROM registry_key;");

    return 0;
}

static int teardown_delete_tables_and_file(void **state) {
    fim_tmp_file *file = *state;

    if (file) {
        fim_db_clean_file(&file, FIM_DB_MEMORY);
    }

    teardown_delete_tables(state);

    return 0;
}

static int setup_registry_entry(void **state) {
    fim_registry_key *key = create_reg_key(1, "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile", "permissions", "userid", "groupid",
                                           "username", "groupname");
    fim_registry_value_data *value = create_reg_value_data(1, "valuename", REG_DWORD, 4);
    fim_entry *entry = NULL;
    os_calloc(1, sizeof(fim_entry), entry);
    entry->type = FIM_TYPE_REGISTRY;
    entry->registry_entry.key = key;
    entry->registry_entry.value = value;

    *state = entry;

    return 0;
}

static int teardown_registry_entry(void **state) {
    fim_entry *entry = *state;

    if (entry){
        fim_registry_free_key(entry->registry_entry.key);
        fim_registry_free_value_data(entry->registry_entry.value);
        free(entry);
    }

    if(teardown_delete_tables(state))
        return -1;

    return 0;
}

static int n_scanned_callback(void *param, int argc, char **argv, char **azColName){
    int *n_scanned = (int *)param;
    (*n_scanned)++;

    return 0;
}

int count_scanned(int type) {
    int n_scanned = 0;
    char *err_msg = NULL;

    if (type == 0){
        sqlite3_exec(syscheck.database->db, "SELECT * FROM registry_key WHERE scanned = 1", n_scanned_callback,
                     &n_scanned, &err_msg);
    } else if (type == 1){
        sqlite3_exec(syscheck.database->db, "SELECT * FROM registry_data WHERE scanned = 1", n_scanned_callback,
                     &n_scanned, &err_msg);
    }

    if (err_msg) {
        fail_msg("%s", err_msg);
        sqlite3_free(err_msg);

        return -1;
    }

    return n_scanned;
}

// Tests

static void test_fim_db_get_registry_key(void **state) {
    int ret;
    fim_registry_key *key = NULL;

    will_return_always(__wrap_sqlite3_step, 1);

    execute_query(default_key_query);

    // Get
    key = fim_db_get_registry_key(syscheck.database, "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile", 0);
    assert_non_null(key);
    ret = check_fim_db_reg_key(key);
    assert_int_equal(ret, 0);
}

static void test_fim_db_get_registry_key_using_id(void **state) {
    int ret;
    fim_registry_key *key = NULL;

    will_return_always(__wrap_sqlite3_step, 1);

    execute_query(default_key_query);

    // Get
    key = fim_db_get_registry_key_using_id(syscheck.database, 1);
    assert_non_null(key);
    ret = check_fim_db_reg_key(key);
    assert_int_equal(ret, 0);
}

static void test_fim_db_get_registry_data(void **state) {
    int ret;
    fim_registry_value_data *value = NULL;

    will_return_always(__wrap_sqlite3_step, 1);

    execute_query(default_key_query);
    execute_query("INSERT INTO registry_data VALUES(1, \"valuename\", 4, 4, \"hash1\", \"hash2\", \"hash3\", 0, 1234, \"checksum2\");");

    // Get
    value = fim_db_get_registry_data(syscheck.database, 1, "valuename");
    assert_non_null(value);
    ret = check_fim_db_reg_value_data(value, 1);
    assert_int_equal(ret, 0);
}

static void test_fim_db_get_registry_key_db_error(void **state) {
    fim_registry_key *key = NULL;

    will_return_always(__wrap_sqlite3_step, 1);

    execute_query(default_key_query);

    // Get
    key = fim_db_get_registry_key(syscheck.database, "nonexist", 0);
    assert_null(key);
}

static void test_fim_db_get_registry_key_using_id_db_error(void **state) {
    fim_registry_key *key = NULL;

    will_return_always(__wrap_sqlite3_step, 1);

    execute_query(default_key_query);

    // Get
    key = fim_db_get_registry_key_using_id(syscheck.database, 3);
    assert_null(key);
}

static void test_fim_db_get_registry_data_db_error(void **state) {
    fim_registry_value_data *value = NULL;

    will_return_always(__wrap_sqlite3_step, 1);

    execute_query(default_key_query);
    execute_query("INSERT INTO registry_data VALUES(1, \"valuename\", 4, 4, \"hash1\", \"hash2\", \"hash3\", 0, 1234, \"checksum2\");");

    // Get
    value = fim_db_get_registry_data(syscheck.database, 1, "nonexist");
    assert_null(value);
}

static void test_fim_db_insert_registry(void **state) {
    int ret;
    fim_entry *entry = *state;

    will_return_always(__wrap_sqlite3_step, 1);

    // Insert entry
    ret = fim_db_insert_registry(syscheck.database, entry);
    assert_int_equal(ret, FIMDB_OK);
    ret = check_fim_db_reg_key(entry->registry_entry.key);
    assert_int_equal(ret, 0);
    ret = check_fim_db_reg_value_data(entry->registry_entry.value, entry->registry_entry.value->id);
    assert_int_equal(ret, 0);
}

static void test_fim_db_insert_registry_db_error(void **state) {
    int ret;
    fim_entry *entry = *state;

    for (int i = 0; i < 5; i++){
        will_return(__wrap_sqlite3_step, 0);
        will_return(__wrap_sqlite3_step, FIMDB_ERR);
    }

    expect_string(__wrap__merror, formatted_msg, "Step error replacing registry key 'HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile': not an error");
    expect_string(__wrap__merror, formatted_msg, "Step error getting registry rowid HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile: not an error");
    expect_string(__wrap__merror, formatted_msg, "Step error replacing registry data '1': not an error");

    // Insert entry
    ret = fim_db_insert_registry(syscheck.database, entry);
    assert_int_not_equal(ret, 0);
    ret = check_fim_db_reg_key(entry->registry_entry.key);
    assert_int_equal(ret, -1);
    ret = check_fim_db_reg_value_data(entry->registry_entry.value, entry->registry_entry.value->id);
    assert_int_equal(ret, -1);
}

static void test_fim_db_insert_registry_key(void **state) {
    int ret;
    fim_entry *entry = *state;

    will_return_always(__wrap_sqlite3_step, 1);

    // Insert key
    ret = fim_db_insert_registry_key(syscheck.database, entry->registry_entry.key, entry->registry_entry.key->id);
    assert_int_equal(ret, FIMDB_OK);
    ret = check_fim_db_reg_key(entry->registry_entry.key);
    assert_int_equal(ret, 0);
}

static void test_fim_db_insert_registry_data(void **state) {
    int ret;
    fim_entry *entry = *state;

    will_return_always(__wrap_sqlite3_step, 1);

    execute_query(default_key_query);

    // Insert value
    ret = fim_db_insert_registry_data(syscheck.database, entry->registry_entry.value, entry->registry_entry.key->id, 1);
    assert_int_equal(ret, FIMDB_OK);
    ret = check_fim_db_reg_value_data(entry->registry_entry.value, entry->registry_entry.value->id);
    assert_int_equal(ret, 0);
}

static void test_fim_db_insert_registry_key_db_error(void **state) {
    int ret;
    fim_entry *entry = *state;

    expect_string(__wrap__merror, formatted_msg, "Step error replacing registry key 'HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile': not an error");
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_step, 1);

    // Insert key
    ret = fim_db_insert_registry_key(syscheck.database, entry->registry_entry.key, entry->registry_entry.key->id);
    assert_int_equal(ret, FIMDB_ERR);
    ret = check_fim_db_reg_key(entry->registry_entry.key);
    assert_int_equal(ret, -1);
}

static void test_fim_db_insert_registry_data_db_error(void **state) {
    int ret;
    fim_entry *entry = *state;

    expect_string(__wrap__merror, formatted_msg, "Step error replacing registry data \'1\': not an error");
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_step, 1);

    execute_query(default_key_query);

    // Insert value
    ret = fim_db_insert_registry_data(syscheck.database, entry->registry_entry.value, entry->registry_entry.key->id, 1);
    assert_int_equal(ret, FIMDB_ERR);
    ret = check_fim_db_reg_value_data(entry->registry_entry.value, entry->registry_entry.value->id);
    assert_int_equal(ret, -1);
}

static void test_fim_db_remove_registry_key(void **state) {
    int ret;
    fim_entry *entry = *state;

    will_return_always(__wrap_sqlite3_step, 1);

    execute_query(default_key_query);

    // Remove
    ret = fim_db_remove_registry_key(syscheck.database, entry);
    assert_int_equal(ret, FIMDB_OK);
    ret = check_fim_db_reg_key(entry->registry_entry.key);
    assert_int_equal(ret, -1);
}

static void test_fim_db_remove_registry_data(void **state) {
    int ret;
    fim_entry *entry = *state;

    will_return_always(__wrap_sqlite3_step, 1);

    execute_query(default_key_query);

    execute_query("INSERT INTO registry_data VALUES(1, \"valuename\", 4, 4, \"hash1\", \"hash2\", \"hash3\", 0, 1234, \"checksum2\");");

    entry->registry_entry.value->id = 1;

    // Remove
    ret = fim_db_remove_registry_value_data(syscheck.database, entry->registry_entry.value);
    assert_int_equal(ret, FIMDB_OK);
    ret = check_fim_db_reg_value_data(entry->registry_entry.value, entry->registry_entry.value->id);
    assert_int_equal(ret, -1);
}

static void test_fim_db_remove_registry_key_db_error(void **state) {
    int ret;
    fim_entry *entry = *state;

    expect_string(__wrap__merror, formatted_msg, "Step error deleting data value from key 'HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile': not an error");
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_step, 1);

    execute_query(default_key_query);

    // Remove
    ret = fim_db_remove_registry_key(syscheck.database, entry);
    assert_int_equal(ret, FIMDB_ERR);
    ret = check_fim_db_reg_key(entry->registry_entry.key);
    assert_int_equal(ret, 0);
}

static void test_fim_db_remove_registry_data_db_error(void **state) {
    int ret;
    fim_entry *entry = *state;

    expect_string(__wrap__merror, formatted_msg, "Step error deleting entry name 'valuename': not an error");
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_step, 1);

    execute_query(default_key_query);
    execute_query("INSERT INTO registry_data VALUES(1, \"valuename\", 4, 4, \"hash1\", \"hash2\", \"hash3\", 0, 1234, \"checksum2\");");

    entry->registry_entry.value->id = 1;

    // Remove
    ret = fim_db_remove_registry_value_data(syscheck.database, entry->registry_entry.value);
    assert_int_equal(ret, FIMDB_ERR);
    ret = check_fim_db_reg_value_data(entry->registry_entry.value, entry->registry_entry.value->id);
    assert_int_equal(ret, 0);
}

static void test_fim_db_set_all_registry_key_unscanned(void **state) {
    int ret;

    execute_query("INSERT INTO registry_key VALUES(1, \"HKEY_LOCAL_MACHINE\\Software\\Classes\\testkey1\", \"permissions1\", \"userid1\", \"groupid1\", \"username1\", \"groupname1\", 1234, \'[x32]\', 1, 1234, \"checksum1\");");
    execute_query("INSERT INTO registry_key VALUES(2, \"HKEY_LOCAL_MACHINE\\Software\\Classes\\testkey2\", \"permissions2\", \"userid2\", \"groupid2\", \"username2\", \"groupname2\", 1234, \'[x32]\', 0, 1234, \"checksum2\");");
    execute_query("INSERT INTO registry_key VALUES(3, \"HKEY_LOCAL_MACHINE\\Software\\Classes\\testkey3\", \"permissions3\", \"userid3\", \"groupid3\", \"username3\", \"groupname3\", 1234, \'[x32]\', 1, 1234, \"checksum3\");");

    ret = fim_db_set_all_registry_key_unscanned(syscheck.database);
    assert_int_equal(ret, FIMDB_OK);

    ret = count_scanned(0);
    assert_int_equal(ret, 0);
}

static void test_fim_db_set_all_registry_data_unscanned(void **state) {
    int ret;

    execute_query("INSERT INTO registry_key VALUES(1, \"HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile1\",  \"permissions\", \"userid\", \"groupid\", \"username\", \"groupname\", 1234, \'[x32]\', 0, 1234, \"checksum1\");");
    execute_query("INSERT INTO registry_data VALUES(1, \"valuename1\", 4, 4, \"hash1\", \"hash2\", \"hash3\", 1, 1234, \"checksum2\");");
    execute_query("INSERT INTO registry_key VALUES(2, \"HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile2\",  \"permissions\", \"userid\", \"groupid\", \"username\", \"groupname\", 1234, \'[x32]\', 0, 1234, \"checksum1\");");
    execute_query("INSERT INTO registry_data VALUES(2, \"valuename2\", 4, 4, \"hash1\", \"hash2\", \"hash3\", 0, 1234, \"checksum2\");");
    execute_query("INSERT INTO registry_key VALUES(3, \"HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile3\",  \"permissions\", \"userid\", \"groupid\", \"username\", \"groupname\", 1234, \'[x32]\', 0, 1234, \"checksum1\");");
    execute_query("INSERT INTO registry_data VALUES(3, \"valuename3\", 4, 4, \"hash1\", \"hash2\", \"hash3\", 1, 1234, \"checksum2\");");

    ret = fim_db_set_all_registry_data_unscanned(syscheck.database);
    assert_int_equal(ret, FIMDB_OK);

    ret = count_scanned(1);
    assert_int_equal(ret, 0);
}

static void test_fim_db_set_registry_key_scanned(void **state) {
    int ret;

    will_return_always(__wrap_sqlite3_step, 1);

    execute_query(default_key_query);

    ret = fim_db_set_registry_key_scanned(syscheck.database, "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile", 0);
    assert_int_equal(ret, FIMDB_OK);

    ret = count_scanned(0);
    assert_int_equal(ret, 1);
}

static void test_fim_db_set_registry_key_scanned_error(void **state) {
    int ret;

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, FIMDB_ERR);
    expect_string(__wrap__merror, formatted_msg, "Step error setting scanned key path 'HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile': not an error");

    execute_query(default_key_query);

    ret = fim_db_set_registry_key_scanned(syscheck.database, "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile", 0);
    assert_int_equal(ret, FIMDB_ERR);

    ret = count_scanned(0);
    assert_int_equal(ret, 0);
}

static void test_fim_db_set_registry_data_scanned(void **state) {
    int ret;

    will_return_always(__wrap_sqlite3_step, 1);

    execute_query(default_key_query);
    execute_query("INSERT INTO registry_data VALUES(1, \"valuename\", 4, 4, \"hash1\", \"hash2\", \"hash3\", 0, 1234, \"checksum2\");");

    ret = fim_db_set_registry_data_scanned(syscheck.database, "valuename", 1);
    assert_int_equal(ret, FIMDB_OK);

    ret = count_scanned(1);
    assert_int_equal(ret, 1);
}

static void test_fim_db_set_registry_data_scanned_error(void **state) {
    int ret;

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, FIMDB_ERR);
    expect_string(__wrap__merror, formatted_msg, "Step error setting scanned data name 'valuename': not an error");

    execute_query(default_key_query);
    execute_query("INSERT INTO registry_data VALUES(1, \"valuename\", 4, 4, \"hash1\", \"hash2\", \"hash3\", 0, 1234, \"checksum2\");");

    ret = fim_db_set_registry_data_scanned(syscheck.database, "valuename", 1);
    assert_int_equal(ret, FIMDB_ERR);

    ret = count_scanned(1);
    assert_int_equal(ret, 0);
}

static void test_fim_db_get_registry_keys_not_scanned(void **state) {
    int ret;
    fim_tmp_file *file = NULL;

    will_return_always(__wrap_sqlite3_step, 1);

    execute_query("INSERT INTO registry_key VALUES(1, \"HKEY_LOCAL_MACHINE\\Software\\Classes\\testkey1\", \"permissions1\", \"userid1\", \"groupid1\", \"username1\", \"groupname1\", 1234, \'[x32]\', 0, 1234, \"checksum1\");");
    execute_query("INSERT INTO registry_key VALUES(2, \"HKEY_LOCAL_MACHINE\\Software\\Classes\\testkey2\", \"permissions2\", \"userid2\", \"groupid2\", \"username2\", \"groupname2\", 1234, \'[x32]\', 1, 1234, \"checksum2\");");
    execute_query("INSERT INTO registry_key VALUES(3, \"HKEY_LOCAL_MACHINE\\Software\\Classes\\testkey3\", \"permissions3\", \"userid3\", \"groupid3\", \"username3\", \"groupname3\", 1234, \'[x32]\', 0, 1234, \"checksum3\");");

    // Check keys not scanned
    char namekey1[60] = "0 HKEY_LOCAL_MACHINE\\Software\\Classes\\testkey1";
    char namekey3[60] = "0 HKEY_LOCAL_MACHINE\\Software\\Classes\\testkey3";

    ret = fim_db_get_registry_keys_not_scanned(syscheck.database, &file, FIM_DB_MEMORY);
    assert_int_equal(ret, FIMDB_OK);
    assert_int_equal(2, file->elements);
    assert_string_equal(namekey1, wstr_unescape_json((char *) W_Vector_get(file->list, 0)));
    assert_string_equal(namekey3, wstr_unescape_json((char *) W_Vector_get(file->list, 1)));

    *state = file;
}

static void test_fim_db_get_registry_keys_not_scanned_error(void **state) {
    int ret;
    fim_tmp_file *file = NULL;

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, FIMDB_ERR);

    execute_query("INSERT INTO registry_key VALUES(1, \"HKEY_LOCAL_MACHINE\\Software\\Classes\\testkey1\", \"permissions1\", \"userid1\", \"groupid1\", \"username1\", \"groupname1\", 1234, \'[x32]\', 0, 1234, \"checksum1\");");
    execute_query("INSERT INTO registry_key VALUES(2, \"HKEY_LOCAL_MACHINE\\Software\\Classes\\testkey2\", \"permissions2\", \"userid2\", \"groupid2\", \"username2\", \"groupname2\", 1234, \'[x32]\', 1, 1234, \"checksum2\");");
    execute_query("INSERT INTO registry_key VALUES(3, \"HKEY_LOCAL_MACHINE\\Software\\Classes\\testkey3\", \"permissions3\", \"userid3\", \"groupid3\", \"username3\", \"groupname3\", 1234, \'[x32]\', 0, 1234, \"checksum3\");");

    ret = fim_db_get_registry_keys_not_scanned(syscheck.database, &file, FIM_DB_MEMORY);
    assert_int_equal(ret, FIMDB_ERR);
    assert_null(file);

    *state = file;
}

static void test_fim_db_get_registry_data_not_scanned(void **state) {
    int ret;
    fim_tmp_file *file;

    will_return_always(__wrap_sqlite3_step, 1);

    execute_query("INSERT INTO registry_key VALUES(1, \"HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile1\",  \"permissions\", \"userid\", \"groupid\", \"username\", \"groupname\", 1234, \'[x32]\', 0, 1234, \"checksum1\");");
    execute_query("INSERT INTO registry_data VALUES(1, \"valuename1\", 4, 4, \"hash1\", \"hash2\", \"hash3\", 0, 1234, \"checksum2\");");
    execute_query("INSERT INTO registry_key VALUES(2, \"HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile2\",  \"permissions\", \"userid\", \"groupid\", \"username\", \"groupname\", 1234, \'[x32]\', 0, 1234, \"checksum1\");");
    execute_query("INSERT INTO registry_data VALUES(2, \"valuename2\", 4, 4, \"hash1\", \"hash2\", \"hash3\", 1, 1234, \"checksum2\");");
    execute_query("INSERT INTO registry_key VALUES(3, \"HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile3\",  \"permissions\", \"userid\", \"groupid\", \"username\", \"groupname\", 1234, \'[x32]\', 0, 1234, \"checksum1\");");
    execute_query("INSERT INTO registry_data VALUES(3, \"valuename3\", 4, 4, \"hash1\", \"hash2\", \"hash3\", 0, 1234, \"checksum2\");");

    ret = fim_db_get_registry_data_not_scanned(syscheck.database, &file, FIM_DB_MEMORY);
    assert_int_equal(ret, FIMDB_OK);
    assert_int_equal(2, file->elements);
    assert_string_equal("1 valuename1", wstr_unescape_json((char *) W_Vector_get(file->list, 0)));
    assert_string_equal("3 valuename3", wstr_unescape_json((char *) W_Vector_get(file->list, 1)));

    *state = file;
}

static void test_fim_db_get_registry_data_not_scanned_error(void **state) {
    int ret;
    fim_tmp_file *file;

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, FIMDB_ERR);

    execute_query("INSERT INTO registry_key VALUES(1, \"HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile1\",  \"permissions\", \"userid\", \"groupid\", \"username\", \"groupname\", 1234, \'[x32]\', 0, 1234, \"checksum1\");");
    execute_query("INSERT INTO registry_data VALUES(1, \"valuename1\", 4, 4, \"hash1\", \"hash2\", \"hash3\", 0, 1234, \"checksum2\");");
    execute_query("INSERT INTO registry_key VALUES(2, \"HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile2\",  \"permissions\", \"userid\", \"groupid\", \"username\", \"groupname\", 1234, \'[x32]\', 0, 1234, \"checksum1\");");
    execute_query("INSERT INTO registry_data VALUES(2, \"valuename2\", 4, 4, \"hash1\", \"hash2\", \"hash3\", 1, 1234, \"checksum2\");");
    execute_query("INSERT INTO registry_key VALUES(3, \"HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile3\",  \"permissions\", \"userid\", \"groupid\", \"username\", \"groupname\", 1234, \'[x32]\', 0, 1234, \"checksum1\");");
    execute_query("INSERT INTO registry_data VALUES(3, \"valuename3\", 4, 4, \"hash1\", \"hash2\", \"hash3\", 0, 1234, \"checksum2\");");

    ret = fim_db_get_registry_data_not_scanned(syscheck.database, &file, FIM_DB_MEMORY);
    assert_int_equal(ret, FIMDB_ERR);
    assert_null(file);

    *state = file;
}

static void test_fim_db_get_count_registry_key(void **state) {
    int ret;

    will_return_always(__wrap_sqlite3_step, 1);

    execute_query("INSERT INTO registry_key VALUES(1, \"HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile1\",  \"permissions\", \"userid\", \"groupid\", \"username\", \"groupname\", 1234, \'[x32]\', 0, 1234, \"checksum1\");");
    execute_query("INSERT INTO registry_key VALUES(2, \"HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile2\",  \"permissions\", \"userid\", \"groupid\", \"username\", \"groupname\", 1234, \'[x32]\', 0, 1234, \"checksum1\");");
    execute_query("INSERT INTO registry_key VALUES(3, \"HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile3\",  \"permissions\", \"userid\", \"groupid\", \"username\", \"groupname\", 1234, \'[x32]\', 0, 1234, \"checksum1\");");

    ret = fim_db_get_count_registry_key(syscheck.database);
    assert_int_equal(ret, 3);
}

static void test_fim_db_get_count_registry_data(void **state) {
    int ret;

    will_return_always(__wrap_sqlite3_step, 1);

    execute_query("INSERT INTO registry_key VALUES(1, \"HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile1\",  \"permissions\", \"userid\", \"groupid\", \"username\", \"groupname\", 1234, \'[x32]\', 0, 1234, \"checksum1\");");
    execute_query("INSERT INTO registry_data VALUES(1, \"valuename1\", 4, 4, \"hash1\", \"hash2\", \"hash3\", 0, 1234, \"checksum2\");");
    execute_query("INSERT INTO registry_key VALUES(2, \"HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile2\",  \"permissions\", \"userid\", \"groupid\", \"username\", \"groupname\", 1234, \'[x32]\', 0, 1234, \"checksum1\");");
    execute_query("INSERT INTO registry_data VALUES(2, \"valuename2\", 4, 4, \"hash1\", \"hash2\", \"hash3\", 1, 1234, \"checksum2\");");
    execute_query("INSERT INTO registry_key VALUES(3, \"HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile3\",  \"permissions\", \"userid\", \"groupid\", \"username\", \"groupname\", 1234, \'[x32]\', 0, 1234, \"checksum1\");");
    execute_query("INSERT INTO registry_data VALUES(3, \"valuename3\", 4, 4, \"hash1\", \"hash2\", \"hash3\", 0, 1234, \"checksum2\");");

    ret = fim_db_get_count_registry_data(syscheck.database);
    assert_int_equal(ret, 3);
}

static void test_fim_db_get_values_from_registry_key(void **state) {
    int ret;
    fim_tmp_file *file;

    will_return_always(__wrap_sqlite3_step, 1);

    execute_query("INSERT INTO registry_key VALUES(1, \"HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile1\",  \"permissions\", \"userid\", \"groupid\", \"username\", \"groupname\", 1234, \'[x32]\', 0, 1234, \"checksum1\");");
    execute_query("INSERT INTO registry_data VALUES(1, \"valuename1\", 4, 4, \"hash1\", \"hash2\", \"hash3\", 0, 1234, \"checksum2\");");
    execute_query("INSERT INTO registry_data VALUES(1, \"valuename2\", 4, 4, \"hash1\", \"hash2\", \"hash3\", 1, 1234, \"checksum2\");");
    execute_query("INSERT INTO registry_data VALUES(1, \"valuename3\", 4, 4, \"hash1\", \"hash2\", \"hash3\", 0, 1234, \"checksum2\");");

    ret = fim_db_get_values_from_registry_key(syscheck.database, &file, FIM_DB_MEMORY, 1);
    assert_int_equal(ret, FIMDB_OK);
    assert_int_equal(3, file->elements);
    assert_string_equal("1 valuename1", wstr_unescape_json((char *) W_Vector_get(file->list, 0)));
    assert_string_equal("1 valuename2", wstr_unescape_json((char *) W_Vector_get(file->list, 1)));
    assert_string_equal("1 valuename3", wstr_unescape_json((char *) W_Vector_get(file->list, 2)));

    *state = file;
}

static void test_fim_db_get_values_from_registry_key_error(void **state) {
    int ret;
    fim_tmp_file *file;

    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, FIMDB_ERR);

    execute_query("INSERT INTO registry_key VALUES(1, \"HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile1\",  \"permissions\", \"userid\", \"groupid\", \"username\", \"groupname\", 1234, \'[x32]\', 0, 1234, \"checksum1\");");
    execute_query("INSERT INTO registry_data VALUES(1, \"valuename1\", 4, 4, \"hash1\", \"hash2\", \"hash3\", 0, 1234, \"checksum2\");");
    execute_query("INSERT INTO registry_data VALUES(1, \"valuename2\", 4, 4, \"hash1\", \"hash2\", \"hash3\", 1, 1234, \"checksum2\");");
    execute_query("INSERT INTO registry_data VALUES(1, \"valuename3\", 4, 4, \"hash1\", \"hash2\", \"hash3\", 0, 1234, \"checksum2\");");

    ret = fim_db_get_values_from_registry_key(syscheck.database, &file, FIM_DB_MEMORY, 2);
    assert_int_equal(ret, FIMDB_ERR);
    assert_null(file);

    *state = file;
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_teardown(test_fim_db_get_registry_key, teardown_delete_tables),
        cmocka_unit_test_teardown(test_fim_db_get_registry_key_using_id, teardown_delete_tables),
        cmocka_unit_test_teardown(test_fim_db_get_registry_data, teardown_delete_tables),
        cmocka_unit_test_teardown(test_fim_db_get_registry_key_db_error, teardown_delete_tables),
        cmocka_unit_test_teardown(test_fim_db_get_registry_key_using_id_db_error, teardown_delete_tables),
        cmocka_unit_test_teardown(test_fim_db_get_registry_data_db_error, teardown_delete_tables),
        cmocka_unit_test_setup_teardown(test_fim_db_insert_registry, setup_registry_entry, teardown_registry_entry),
        cmocka_unit_test_setup_teardown(test_fim_db_insert_registry_db_error, setup_registry_entry, teardown_registry_entry),
        cmocka_unit_test_setup_teardown(test_fim_db_insert_registry_key, setup_registry_entry, teardown_registry_entry),
        cmocka_unit_test_setup_teardown(test_fim_db_insert_registry_data, setup_registry_entry, teardown_registry_entry),
        cmocka_unit_test_setup_teardown(test_fim_db_insert_registry_key_db_error, setup_registry_entry, teardown_registry_entry),
        cmocka_unit_test_setup_teardown(test_fim_db_insert_registry_data_db_error, setup_registry_entry, teardown_registry_entry),
        cmocka_unit_test_setup_teardown(test_fim_db_remove_registry_key, setup_registry_entry, teardown_registry_entry),
        cmocka_unit_test_setup_teardown(test_fim_db_remove_registry_data, setup_registry_entry, teardown_registry_entry),
        cmocka_unit_test_setup_teardown(test_fim_db_remove_registry_key_db_error, setup_registry_entry, teardown_registry_entry),
        cmocka_unit_test_setup_teardown(test_fim_db_remove_registry_data_db_error, setup_registry_entry, teardown_registry_entry),
        cmocka_unit_test_teardown(test_fim_db_set_all_registry_key_unscanned, teardown_delete_tables),
        cmocka_unit_test_teardown(test_fim_db_set_all_registry_data_unscanned, teardown_delete_tables),
        cmocka_unit_test_teardown(test_fim_db_set_registry_key_scanned, teardown_delete_tables),
        cmocka_unit_test_teardown(test_fim_db_set_registry_key_scanned_error, teardown_delete_tables),
        cmocka_unit_test_teardown(test_fim_db_set_registry_data_scanned, teardown_delete_tables),
        cmocka_unit_test_teardown(test_fim_db_set_registry_data_scanned_error, teardown_delete_tables),
        cmocka_unit_test_teardown(test_fim_db_get_registry_keys_not_scanned, teardown_delete_tables_and_file),
        cmocka_unit_test_teardown(test_fim_db_get_registry_keys_not_scanned_error, teardown_delete_tables_and_file),
        cmocka_unit_test_teardown(test_fim_db_get_registry_data_not_scanned, teardown_delete_tables_and_file),
        cmocka_unit_test_teardown(test_fim_db_get_registry_data_not_scanned_error, teardown_delete_tables_and_file),
        cmocka_unit_test_teardown(test_fim_db_get_count_registry_key, teardown_delete_tables),
        cmocka_unit_test_teardown(test_fim_db_get_count_registry_data, teardown_delete_tables),
        cmocka_unit_test_teardown(test_fim_db_get_values_from_registry_key, teardown_delete_tables),
        cmocka_unit_test_teardown(test_fim_db_get_values_from_registry_key_error, teardown_delete_tables),
    };

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
