/*
 * Copyright (C) 2015, Wazuh Inc.
 * May 2, 2024.
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
#include <string.h>
#include <stdlib.h>

#include "../wazuh_db/wdb.h"
#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/file_op_wrappers.h"
#include "../wrappers/libc/stdio_wrappers.h"

int setup(__attribute__((unused)) void ** state) {
    test_mode = 1;
    return 0;
}

int teardown(__attribute__((unused)) void ** state) {
    test_mode = 0;
    return 0;
}

void test_wdb_create_agent_db2_ok(void ** state) {
    expect_wfopen(WDB2_DIR "/" WDB_PROF_NAME, "r", (void *)1);
    expect_wfopen(WDB2_DIR "/000.db.new", "w", (void *)2);
    expect_fread("", 0);
    expect_fclose((void *)1, 0);
    expect_fclose((void *)2, 0);
    expect_string(__wrap_chmod, path, WDB2_DIR "/000.db.new");
    will_return(__wrap_chmod, 0);
    expect_string(__wrap_OS_MoveFile, src, WDB2_DIR "/000.db.new");
    expect_string(__wrap_OS_MoveFile, dst, WDB2_DIR "/000.db");
    will_return(__wrap_OS_MoveFile, 0);

    int result = wdb_create_agent_db2("000");
    assert_int_equal(result, 0);
}

void test_wdb_create_agent_db2_wfopen_error(void ** state) {
    expect_wfopen(WDB2_DIR "/" WDB_PROF_NAME, "r", (void *)1);
    expect_wfopen(WDB2_DIR "/000.db.new", "w", NULL);
    expect_string(__wrap__merror, formatted_msg, "Couldn't create database 'queue/db/000.db': Success (0)");
    expect_fclose((void *)1, 0);

    errno = 0;
    int result = wdb_create_agent_db2("000");
    assert_int_equal(result, -1);
}

void test_wdb_create_agent_db2_fwrite_error(void ** state) {
    expect_wfopen(WDB2_DIR "/" WDB_PROF_NAME, "r", (void *)1);
    expect_wfopen(WDB2_DIR "/000.db.new", "w", (void *)2);
    expect_fread("Hello", 5);
    will_return(__wrap_fwrite, 0);
    expect_fclose((void *)1, 0);
    expect_fclose((void *)2, 0);

    int result = wdb_create_agent_db2("000");
    assert_int_equal(result, -1);
}

void test_wdb_create_agent_db2_fclose_error(void ** state) {
    expect_wfopen(WDB2_DIR "/" WDB_PROF_NAME, "r", (void *)1);
    expect_wfopen(WDB2_DIR "/000.db.new", "w", (void *)2);
    expect_fread("", 0);
    expect_fclose((void *)1, 0);
    expect_fclose((void *)2, -1);
    expect_string(__wrap__merror, formatted_msg, "Couldn't create file queue/db/000.db.new completely");

    int result = wdb_create_agent_db2("000");
    assert_int_equal(result, -1);
}

void test_wdb_create_agent_db2_chmod_error(void ** state) {
    expect_wfopen(WDB2_DIR "/" WDB_PROF_NAME, "r", (void *)1);
    expect_wfopen(WDB2_DIR "/000.db.new", "w", (void *)2);
    expect_fread("", 0);
    expect_fclose((void *)1, 0);
    expect_fclose((void *)2, 0);
    expect_string(__wrap_chmod, path, WDB2_DIR "/000.db.new");
    will_return(__wrap_chmod, -1);
    expect_string(__wrap__merror, formatted_msg, "(1127): Could not chmod object 'queue/db/000.db.new' due to [(0)-(Success)].");

    errno = 0;
    int result = wdb_create_agent_db2("000");
    assert_int_equal(result, -1);
}

void test_wdb_create_agent_db2_rename_error(void ** state) {
    expect_wfopen(WDB2_DIR "/" WDB_PROF_NAME, "r", (void *)1);
    expect_wfopen(WDB2_DIR "/000.db.new", "w", (void *)2);
    expect_fread("", 0);
    expect_fclose((void *)1, 0);
    expect_fclose((void *)2, 0);
    expect_string(__wrap_chmod, path, WDB2_DIR "/000.db.new");
    will_return(__wrap_chmod, 0);
    expect_string(__wrap_OS_MoveFile, src, WDB2_DIR "/000.db.new");
    expect_string(__wrap_OS_MoveFile, dst, WDB2_DIR "/000.db");
    will_return(__wrap_OS_MoveFile, -1);

    expect_string(__wrap__merror, formatted_msg, "(1124): Could not rename file 'queue/db/000.db.new' to 'queue/db/000.db' due to [(0)-(Success)].");

    errno = 0;
    int result = wdb_create_agent_db2("000");
    assert_int_equal(result, -1);
}

int main() {
    test_mode = 1;

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_wdb_create_agent_db2_ok),
        cmocka_unit_test(test_wdb_create_agent_db2_wfopen_error),
        cmocka_unit_test(test_wdb_create_agent_db2_fwrite_error),
        cmocka_unit_test(test_wdb_create_agent_db2_fclose_error),
        cmocka_unit_test(test_wdb_create_agent_db2_chmod_error),
        cmocka_unit_test(test_wdb_create_agent_db2_rename_error),
    };

    return cmocka_run_group_tests(tests, setup, teardown);
}
