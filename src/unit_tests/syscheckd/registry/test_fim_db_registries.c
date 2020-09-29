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
#include "../../../syscheckd/db/fim_db.h"

extern int _base_line;

int check_fim_db_reg_key(fim_registry_key *key_to_check){
    fim_registry_key *key_saved = fim_db_get_registry_key(syscheck.database, key_to_check->path);
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

fim_registry_key *create_reg_key(const char *path, const char *perm, const char *uid, const char *gid, const char *user_name,
                                 const char *group_name) {
    fim_registry_key *ret;

    os_calloc(1, sizeof(fim_registry_key), ret);

    ret->id = 0;
    os_strdup(path, ret->path);
    os_strdup(perm, ret->perm);
    os_strdup(uid, ret->uid);
    os_strdup(gid, ret->gid);
    os_strdup(user_name, ret->user_name);
    os_strdup(group_name, ret->group_name);

    return ret;
}

fim_registry_value_data *create_reg_value_data(char *name, unsigned int type, unsigned int size) {
    fim_registry_value_data *ret;

    os_calloc(1, sizeof(fim_registry_value_data), ret);

    os_strdup(name, ret->name);
    ret->type = type;
    ret->size = size;

    return ret;
}

static int setup_group(void **state) {
    int i;

    time_mock_value = 19283746500;

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
    char *err_msg = NULL;

    // DELETE TABLES
    sqlite3_exec(syscheck.database->db, "DELETE FROM registry_data;", NULL, NULL, &err_msg);
    if (err_msg) {
        fail_msg("%s", err_msg);
        sqlite3_free(err_msg);

        return -1;
    }
    sqlite3_exec(syscheck.database->db, "DELETE FROM registry_key;", NULL, NULL, &err_msg);
    if (err_msg) {
        fail_msg("%s", err_msg);
        sqlite3_free(err_msg);

        return -1;
    }

    return 0;
}

static int setup_registry_entry(void **state) {
    fim_registry_key *key = create_reg_key("HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile", "permissions", "userid", "groupid",
                                           "username", "groupname");
    fim_registry_value_data *value = create_reg_value_data("valuename", REG_DWORD, 4);
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
    n_scanned[0]++;

    return 0;
}

int count_scanned(int type) {
    int *n_scanned = 0;
    char *err_msg = NULL;

    if (type == 0){
        sqlite3_exec(syscheck.database->db, "SELECT * FROM registry_key WHERE scanned = 1", n_scanned_callback, &n_scanned, &err_msg);
    } else if (type == 1){
        sqlite3_exec(syscheck.database->db, "SELECT * FROM registry_data WHERE scanned = 1", n_scanned_callback, &n_scanned, &err_msg);
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
    char *err_msg = NULL;

    will_return_always(__wrap_sqlite3_step, 1);

    sqlite3_exec(syscheck.database->db, "INSERT INTO registry_key VALUES(1, \"HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile\",  \"permissions\", \"userid\", \"groupid\", \"username\", \"groupname\", 1234, 0, 0, \"checksum1\");", NULL, NULL, &err_msg);
    if (err_msg) {
        fail_msg("%s", err_msg);
        sqlite3_free(err_msg);

        return -1;
    }

    // Get
    key = fim_db_get_registry_key(syscheck.database, "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile");
    assert_non_null(key);
    ret = check_fim_db_reg_key(key);
    assert_int_equal(ret, 0);
}

static void test_fim_db_get_registry_data(void **state) {
    int ret;
    fim_registry_value_data *value = NULL;
    char *err_msg = NULL;

    will_return_always(__wrap_sqlite3_step, 1);

    sqlite3_exec(syscheck.database->db, "INSERT INTO registry_data VALUES(1, \"valuename\", 4, 4, \"hash1\", \"hash2\", \"hash3\", 0, 1234, \"checksum2\");", NULL, NULL, &err_msg);
    if (err_msg) {
        fail_msg("%s", err_msg);
        sqlite3_free(err_msg);

        return -1;
    }

    // Get
    value = fim_db_get_registry_data(syscheck.database, 1, "valuename");
    assert_non_null(value);
    ret = check_fim_db_reg_value_data(value, 1);
    assert_int_equal(ret, 0);
}

static void test_fim_db_get_registry_key_db_error(void **state) {
    int ret;
    fim_registry_key *key = NULL;
    char *err_msg = NULL;

    will_return_always(__wrap_sqlite3_step, 1);

    sqlite3_exec(syscheck.database->db, "INSERT INTO registry_key VALUES(1, \"HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile\",  \"permissions\", \"userid\", \"groupid\", \"username\", \"groupname\", 1234, 0, 0, \"checksum1\");", NULL, NULL, &err_msg);
    if (err_msg) {
        fail_msg("%s", err_msg);
        sqlite3_free(err_msg);

        return -1;
    }

    // Get
    key = fim_db_get_registry_key(syscheck.database, "nonexist");
    assert_null(key);
}

static void test_fim_db_get_registry_data_db_error(void **state) {
    int ret;
    fim_registry_value_data *value = NULL;
    char *err_msg = NULL;

    will_return_always(__wrap_sqlite3_step, 1);

    sqlite3_exec(syscheck.database->db, "INSERT INTO registry_data VALUES(1, \"valuename\", 4, 4, \"hash1\", \"hash2\", \"hash3\", 0, 1234, \"checksum2\");", NULL, NULL, &err_msg);
    if (err_msg) {
        fail_msg("%s", err_msg);
        sqlite3_free(err_msg);

        return -1;
    }

    // Get
    value = fim_db_get_registry_data(syscheck.database, 1, "nonexist");
    assert_null(value);
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

    // Insert value
    ret = fim_db_insert_registry_data(syscheck.database, entry->registry_entry.value, entry->registry_entry.key->id);
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

    expect_string(__wrap__merror, formatted_msg, "Step error replacing registry data \'0\': not an error");
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_step, 1);

    // Insert value
    ret = fim_db_insert_registry_data(syscheck.database, entry->registry_entry.value, entry->registry_entry.key->id);
    assert_int_equal(ret, FIMDB_ERR);
    ret = check_fim_db_reg_value_data(entry->registry_entry.value, entry->registry_entry.value->id);
    assert_int_equal(ret, -1);
}

static void test_fim_db_remove_registry_key(void **state) {
    int ret;
    char *err_msg = NULL;
    fim_entry *entry = *state;

    will_return_always(__wrap_sqlite3_step, 1);

    sqlite3_exec(syscheck.database->db, "INSERT INTO registry_key VALUES(1, \"HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile\",  \"permissions\", \"userid\", \"groupid\", \"username\", \"groupname\", 1234, 0, 0, \"checksum1\");", NULL, NULL, &err_msg);
    if (err_msg) {
        fail_msg("%s", err_msg);
        sqlite3_free(err_msg);

        return -1;
    }

    // Remove
    ret = fim_db_remove_registry_key(syscheck.database, entry);
    assert_int_equal(ret, FIMDB_OK);
    ret = check_fim_db_reg_key(entry->registry_entry.key);
    assert_int_equal(ret, -1);
}

static void test_fim_db_remove_registry_data(void **state) {
    int ret;
    char *err_msg = NULL;
    fim_entry *entry = *state;

    will_return_always(__wrap_sqlite3_step, 1);

    sqlite3_exec(syscheck.database->db, "INSERT INTO registry_data VALUES(1, \"valuename\", 4, 4, \"hash1\", \"hash2\", \"hash3\", 0, 1234, \"checksum2\");", NULL, NULL, &err_msg);
    if (err_msg) {
        fail_msg("%s", err_msg);
        sqlite3_free(err_msg);

        return -1;
    }

    entry->registry_entry.value->id = 1;

    // Remove
    ret = fim_db_remove_registry_value_data(syscheck.database, entry->registry_entry.value);
    assert_int_equal(ret, FIMDB_OK);
    ret = check_fim_db_reg_value_data(entry->registry_entry.value, entry->registry_entry.value->id);
    assert_int_equal(ret, -1);
}

static void test_fim_db_remove_registry_key_db_error(void **state) {
    int ret;
    char *err_msg = NULL;
    fim_entry *entry = *state;

    expect_string(__wrap__merror, formatted_msg, "Step error deleting data value from key 'HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile': not an error");
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_step, 1);

    sqlite3_exec(syscheck.database->db, "INSERT INTO registry_key VALUES(1, \"HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile\",  \"permissions\", \"userid\", \"groupid\", \"username\", \"groupname\", 1234, 0, 0, \"checksum1\");", NULL, NULL, &err_msg);
    if (err_msg) {
        fail_msg("%s", err_msg);
        sqlite3_free(err_msg);

        return -1;
    }

    // Remove
    ret = fim_db_remove_registry_key(syscheck.database, entry);
    assert_int_equal(ret, FIMDB_ERR);
    ret = check_fim_db_reg_key(entry->registry_entry.key);
    assert_int_equal(ret, 0);
}

static void test_fim_db_remove_registry_data_db_error(void **state) {
    int ret;
    char *err_msg = NULL;
    fim_entry *entry = *state;

    expect_string(__wrap__merror, formatted_msg, "Step error deleting entry name 'valuename': not an error");
    will_return(__wrap_sqlite3_step, 0);
    will_return(__wrap_sqlite3_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_step, 1);

    sqlite3_exec(syscheck.database->db, "INSERT INTO registry_data VALUES(1, \"valuename\", 4, 4, \"hash1\", \"hash2\", \"hash3\", 0, 1234, \"checksum2\");", NULL, NULL, &err_msg);
    if (err_msg) {
        fail_msg("%s", err_msg);
        sqlite3_free(err_msg);

        return -1;
    }

    entry->registry_entry.value->id = 1;

    // Remove
    ret = fim_db_remove_registry_value_data(syscheck.database, entry->registry_entry.value);
    assert_int_equal(ret, FIMDB_ERR);
    ret = check_fim_db_reg_value_data(entry->registry_entry.value, entry->registry_entry.value->id);
    assert_int_equal(ret, 0);
}

static void test_fim_db_set_all_registry_key_unscanned(void **state) {
    int ret;
    char *err_msg = NULL;

    sqlite3_exec(syscheck.database->db, "INSERT INTO registry_key VALUES(1, \"HKEY_LOCAL_MACHINE\\Software\\Classes\\testkey1\",  \"permissions1\", \"userid1\", \"groupid1\", \"username1\", \"groupname1\", 1234, 0, 1, \"checksum1\");", NULL, NULL, &err_msg);
    if (err_msg) {
        fail_msg("%s", err_msg);
        sqlite3_free(err_msg);

        return -1;
    }
    sqlite3_exec(syscheck.database->db, "INSERT INTO registry_key VALUES(2, \"HKEY_LOCAL_MACHINE\\Software\\Classes\\testkey2\",  \"permissions2\", \"userid2\", \"groupid2\", \"username2\", \"groupname2\", 1234, 0, 0, \"checksum2\");", NULL, NULL, &err_msg);
    if (err_msg) {
        fail_msg("%s", err_msg);
        sqlite3_free(err_msg);

        return -1;
    }
    sqlite3_exec(syscheck.database->db, "INSERT INTO registry_key VALUES(3, \"HKEY_LOCAL_MACHINE\\Software\\Classes\\testkey3\",  \"permissions3\", \"userid3\", \"groupid3\", \"username3\", \"groupname3\", 1234, 0, 1, \"checksum3\");", NULL, NULL, &err_msg);
    if (err_msg) {
        fail_msg("%s", err_msg);
        sqlite3_free(err_msg);

        return -1;
    }

    ret = fim_db_set_all_registry_key_unscanned(syscheck.database);
    assert_int_equal(ret, FIMDB_OK);

    ret = count_scanned(0);
    assert_int_equal(ret, 0);
}

static void test_fim_db_set_all_registry_data_unscanned(void **state) {
    int ret;
    char *err_msg = NULL;

    sqlite3_exec(syscheck.database->db, "INSERT INTO registry_data VALUES(1, \"valuename\", 4, 4, \"hash1\", \"hash2\", \"hash3\", 1, 1234, \"checksum2\");", NULL, NULL, &err_msg);
    if (err_msg) {
        fail_msg("%s", err_msg);
        sqlite3_free(err_msg);

        return -1;
    }
    sqlite3_exec(syscheck.database->db, "INSERT INTO registry_data VALUES(2, \"valuename\", 4, 4, \"hash1\", \"hash2\", \"hash3\", 0, 1234, \"checksum2\");", NULL, NULL, &err_msg);
    if (err_msg) {
        fail_msg("%s", err_msg);
        sqlite3_free(err_msg);

        return -1;
    }
    sqlite3_exec(syscheck.database->db, "INSERT INTO registry_data VALUES(3, \"valuename\", 4, 4, \"hash1\", \"hash2\", \"hash3\", 1, 1234, \"checksum2\");", NULL, NULL, &err_msg);
    if (err_msg) {
        fail_msg("%s", err_msg);
        sqlite3_free(err_msg);

        return -1;
    }

    ret = fim_db_set_all_registry_data_unscanned(syscheck.database);
    assert_int_equal(ret, FIMDB_OK);

    ret = count_scanned(1);
    assert_int_equal(ret, 0);
}

static void test_fim_db_set_registry_key_scanned(void **state) {
    int ret;
    char *err_msg = NULL;

    will_return_always(__wrap_sqlite3_step, 1);

    sqlite3_exec(syscheck.database->db, "INSERT INTO registry_key VALUES(1, \"HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile\",  \"permissions\", \"userid\", \"groupid\", \"username\", \"groupname\", 1234, 0, 0, \"checksum1\");", NULL, NULL, &err_msg);
    if (err_msg) {
        fail_msg("%s", err_msg);
        sqlite3_free(err_msg);

        return -1;
    }

    ret = fim_db_set_registry_key_scanned(syscheck.database, "HKEY_LOCAL_MACHINE\\Software\\Classes\\batfile");
    assert_int_equal(ret, FIMDB_OK);

    ret = count_scanned(0);
    assert_int_equal(ret, 1);
}

static void test_fim_db_set_registry_data_scanned(void **state) {
    int ret;
    char *err_msg = NULL;

    will_return_always(__wrap_sqlite3_step, 1);

    sqlite3_exec(syscheck.database->db, "INSERT INTO registry_data VALUES(1, \"valuename\", 4, 4, \"hash1\", \"hash2\", \"hash3\", 0, 1234, \"checksum2\");", NULL, NULL, &err_msg);
    if (err_msg) {
        fail_msg("%s", err_msg);
        sqlite3_free(err_msg);

        return -1;
    }

    ret = fim_db_set_registry_data_scanned(syscheck.database, "valuename", 1);
    assert_int_equal(ret, FIMDB_OK);

    ret = count_scanned(1);
    assert_int_equal(ret, 1);
}

static void test_fim_db_get_registry_keys_not_scanned(void **state) {
    int ret;
    char *err_msg = NULL;
    fim_tmp_file *file;

    sqlite3_exec(syscheck.database->db, "INSERT INTO registry_key VALUES(1, \"HKEY_LOCAL_MACHINE\\Software\\Classes\\testkey1\",  \"permissions1\", \"userid1\", \"groupid1\", \"username1\", \"groupname1\", 1234, 0, 0, \"checksum1\");", NULL, NULL, &err_msg);
    if (err_msg) {
        fail_msg("%s", err_msg);
        sqlite3_free(err_msg);

        return -1;
    }
    sqlite3_exec(syscheck.database->db, "INSERT INTO registry_key VALUES(2, \"HKEY_LOCAL_MACHINE\\Software\\Classes\\testkey2\",  \"permissions2\", \"userid2\", \"groupid2\", \"username2\", \"groupname2\", 1234, 0, 1, \"checksum2\");", NULL, NULL, &err_msg);
    if (err_msg) {
        fail_msg("%s", err_msg);
        sqlite3_free(err_msg);

        return -1;
    }
    sqlite3_exec(syscheck.database->db, "INSERT INTO registry_key VALUES(3, \"HKEY_LOCAL_MACHINE\\Software\\Classes\\testkey3\",  \"permissions3\", \"userid3\", \"groupid3\", \"username3\", \"groupname3\", 1234, 0, 0, \"checksum3\");", NULL, NULL, &err_msg);
    if (err_msg) {
        fail_msg("%s", err_msg);
        sqlite3_free(err_msg);

        return -1;
    }


    ret = fim_db_get_registry_keys_not_scanned(syscheck.database, &file, FIM_DB_DISK);
    assert_int_equal(ret, FIMDB_OK);

    if (file && file->elements) {
        // check not scanned
    } else {
        return -1;
    }
}

static void test_fim_db_get_registry_data_not_scanned(void **state) {
    int ret;
    char *err_msg = NULL;
    fim_tmp_file *file;

    sqlite3_exec(syscheck.database->db, "INSERT INTO registry_data VALUES(1, \"valuename\", 4, 4, \"hash1\", \"hash2\", \"hash3\", 0, 1234, \"checksum2\");", NULL, NULL, &err_msg);
    if (err_msg) {
        fail_msg("%s", err_msg);
        sqlite3_free(err_msg);

        return -1;
    }
    sqlite3_exec(syscheck.database->db, "INSERT INTO registry_data VALUES(2, \"valuename\", 4, 4, \"hash1\", \"hash2\", \"hash3\", 1, 1234, \"checksum2\");", NULL, NULL, &err_msg);
    if (err_msg) {
        fail_msg("%s", err_msg);
        sqlite3_free(err_msg);

        return -1;
    }
    sqlite3_exec(syscheck.database->db, "INSERT INTO registry_data VALUES(3, \"valuename\", 4, 4, \"hash1\", \"hash2\", \"hash3\", 0, 1234, \"checksum2\");", NULL, NULL, &err_msg);
    if (err_msg) {
        fail_msg("%s", err_msg);
        sqlite3_free(err_msg);

        return -1;
    }

    ret = fim_db_get_registry_data_not_scanned(syscheck.database, &file, FIM_DB_DISK);
    assert_int_equal(ret, FIMDB_OK);

    if (file && file->elements) {
        // check not scanned
    } else {
        return -1;
    }
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_teardown(test_fim_db_get_registry_key, teardown_delete_tables),
        cmocka_unit_test_teardown(test_fim_db_get_registry_data, teardown_delete_tables),
        cmocka_unit_test_teardown(test_fim_db_get_registry_key_db_error, teardown_delete_tables),
        cmocka_unit_test_teardown(test_fim_db_get_registry_data_db_error, teardown_delete_tables),
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
        cmocka_unit_test_teardown(test_fim_db_set_registry_data_scanned, teardown_delete_tables),
        //cmocka_unit_test_teardown(test_fim_db_get_registry_keys_not_scanned, teardown_delete_tables),
        //cmocka_unit_test_teardown(test_fim_db_get_registry_data_not_scanned, teardown_delete_tables),

    };

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
