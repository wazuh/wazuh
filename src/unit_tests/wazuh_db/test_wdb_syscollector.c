/*
 * Wazuh SQLite integration
 * Copyright (C) 2015, Wazuh Inc.
 * July 4, 2022.
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
#include <stdbool.h>
#include <string.h>

#include "../wazuh_db/wdb.h"
#include "../external/sqlite/sqlite3.h"
#include "../wrappers/wazuh/wazuh_db/wdb_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/externals/sqlite/sqlite3_wrappers.h"
#include "../wrappers/externals/cJSON/cJSON_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_agents_wrappers.h"
#include "../headers/os_err.h"

static int test_setup(void **state) {
    wdb_t *data = NULL;

    os_calloc(1, sizeof(wdb_t), data);
    *state = data;
    return 0;
}

static int test_teardown(void **state) {
    wdb_t *data  = (wdb_t *)*state;
    os_free(data);
    return 0;
}

#define ALLOW_ZERO      true
#define NOT_ALLOW_ZERO  false
#define ALLOW_OVER_ONEHUNDRED true
#define NOT_ALLOW_OVER_ONEHUNDRED false

typedef struct test_struct {
    wdb_t *wdb;
    char *output;
} test_struct_t;

/* setup/teardown */
int setup_wdb(void **state) {
    test_struct_t *init_data = NULL;
    os_calloc(1,sizeof(test_struct_t),init_data);
    os_calloc(1,sizeof(wdb_t),init_data->wdb);
    os_strdup("000",init_data->wdb->id);
    os_calloc(256,sizeof(char),init_data->output);
    os_calloc(1,sizeof(sqlite3 *),init_data->wdb->db);
    init_data->wdb->stmt[0] = (sqlite3_stmt*)1;
    init_data->wdb->transaction = 0;
    *state = init_data;
    return 0;
}

int teardown_wdb(void **state) {
    test_struct_t *data  = (test_struct_t *)*state;
    os_free(data->output);
    os_free(data->wdb->id);
    os_free(data->wdb->db);
    os_free(data->wdb);
    os_free(data);
    return 0;
}

static void wdb_syscollector_processes_save2_fail(void) {
    int i = 0;

    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetStringValue, "scan_time");
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetStringValue, "1");
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetStringValue, "1");
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetStringValue, "name");
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetStringValue, "state");
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetStringValue, "cmd");
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetStringValue, "argvs");
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetStringValue, "euser");
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetStringValue, "ruser");
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetStringValue, "suser");
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetStringValue, "egroup");
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetStringValue, "rgroup");
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetStringValue, "sgroup");
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetStringValue, "fgroup");
    for (i = 0; i < 13; i++) {
        will_return(__wrap_cJSON_GetObjectItem, NULL);
    }
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetStringValue, "checksum");


    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_process_save(): cannot begin transaction");
}

static void  wdb_syscollector_processes_save2_fail_2(cJSON *attribute) {
    int i = 0;

    for (i = 0; i < 4; i++) {
        will_return(__wrap_cJSON_GetObjectItem, NULL);
    }

    for (i = 0; i < 3; i++) {
        will_return(__wrap_cJSON_GetObjectItem, 1);
        will_return(__wrap_cJSON_GetObjectItem, attribute);
    }

    for (i = 0; i < 9; i++) {
        will_return(__wrap_cJSON_GetObjectItem, NULL);
    }

    for (i = 0; i < 13; i++) {
        will_return(__wrap_cJSON_GetObjectItem, 1);
        will_return(__wrap_cJSON_GetObjectItem, attribute);
    }

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetStringValue, "scan_time");
    will_return(__wrap_cJSON_GetStringValue, NULL);
    will_return(__wrap_cJSON_GetStringValue, "name");
    will_return(__wrap_cJSON_GetStringValue, "state");
    will_return(__wrap_cJSON_GetStringValue, "cmd");
    will_return(__wrap_cJSON_GetStringValue, "argvs");
    will_return(__wrap_cJSON_GetStringValue, "euser");
    will_return(__wrap_cJSON_GetStringValue, "ruser");
    will_return(__wrap_cJSON_GetStringValue, "suser");
    will_return(__wrap_cJSON_GetStringValue, "egroup");
    will_return(__wrap_cJSON_GetStringValue, "rgroup");
    will_return(__wrap_cJSON_GetStringValue, "sgroup");
    will_return(__wrap_cJSON_GetStringValue, "fgroup");
    will_return(__wrap_cJSON_GetStringValue, "checksum");

    will_return(__wrap_wdb_begin2, 0);
}

static void  wdb_syscollector_processes_save2_success(cJSON *attribute) {
    int i = 0;

    for (i = 0; i < 5; i++) {
        will_return(__wrap_cJSON_GetObjectItem, NULL);
    }

    for (i = 0; i < 3; i++) {
        will_return(__wrap_cJSON_GetObjectItem, 1);
        will_return(__wrap_cJSON_GetObjectItem, attribute);
    }

    for (i = 0; i < 9; i++) {
        will_return(__wrap_cJSON_GetObjectItem, NULL);
    }

    for (i = 0; i < 13; i++) {
        will_return(__wrap_cJSON_GetObjectItem, 1);
        will_return(__wrap_cJSON_GetObjectItem, attribute);
    }

    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetStringValue, "scan_time");
    will_return(__wrap_cJSON_GetStringValue, "1");
    will_return(__wrap_cJSON_GetStringValue, "1");
    will_return(__wrap_cJSON_GetStringValue, "name");
    will_return(__wrap_cJSON_GetStringValue, "state");
    will_return(__wrap_cJSON_GetStringValue, "cmd");
    will_return(__wrap_cJSON_GetStringValue, "argvs");
    will_return(__wrap_cJSON_GetStringValue, "euser");
    will_return(__wrap_cJSON_GetStringValue, "ruser");
    will_return(__wrap_cJSON_GetStringValue, "suser");
    will_return(__wrap_cJSON_GetStringValue, "egroup");
    will_return(__wrap_cJSON_GetStringValue, "rgroup");
    will_return(__wrap_cJSON_GetStringValue, "sgroup");
    will_return(__wrap_cJSON_GetStringValue, "fgroup");
    will_return(__wrap_cJSON_GetStringValue, "checksum");

    will_return(__wrap_wdb_begin2, 0);

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "0");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_time");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 3);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "name");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_string(__wrap_sqlite3_bind_text, buffer, "state");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 6);
    expect_value(__wrap_sqlite3_bind_int, value, 123);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 7);
    expect_value(__wrap_sqlite3_bind_int, value, 123);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 8);
    expect_value(__wrap_sqlite3_bind_int, value, 123);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 9);
    expect_string(__wrap_sqlite3_bind_text, buffer, "cmd");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 10);
    expect_string(__wrap_sqlite3_bind_text, buffer, "argvs");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 11);
    expect_string(__wrap_sqlite3_bind_text, buffer, "euser");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 12);
    expect_string(__wrap_sqlite3_bind_text, buffer, "ruser");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 13);
    expect_string(__wrap_sqlite3_bind_text, buffer, "suser");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 14);
    expect_string(__wrap_sqlite3_bind_text, buffer, "egroup");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 15);
    expect_string(__wrap_sqlite3_bind_text, buffer, "rgroup");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 16);
    expect_string(__wrap_sqlite3_bind_text, buffer, "sgroup");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 17);
    expect_string(__wrap_sqlite3_bind_text, buffer, "fgroup");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 18);
    expect_value(__wrap_sqlite3_bind_int, value, 123);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 19);
    expect_value(__wrap_sqlite3_bind_int, value, 123);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 20);
    expect_value(__wrap_sqlite3_bind_int, value, 123);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 21);
    expect_value(__wrap_sqlite3_bind_int, value, 123);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 22);
    expect_value(__wrap_sqlite3_bind_int, value, 123);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 23);
    expect_value(__wrap_sqlite3_bind_int, value, 123);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 24);
    expect_value(__wrap_sqlite3_bind_int64, value, 5294967296);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 25);
    expect_value(__wrap_sqlite3_bind_int, value, 123);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 26);
    expect_value(__wrap_sqlite3_bind_int, value, 123);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 27);
    expect_value(__wrap_sqlite3_bind_int, value, 123);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 28);
    expect_value(__wrap_sqlite3_bind_int, value, 123);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 29);
    expect_value(__wrap_sqlite3_bind_int, value, 123);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 30);
    expect_value(__wrap_sqlite3_bind_int, value, 123);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 31);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_wdb_step, SQLITE_DONE);
}

static void wdb_syscollector_package_save2_fail() {
    int i = 0;

    for (i = 0; i < 16; i++) {
        will_return(__wrap_cJSON_GetObjectItem, NULL);
    }

    will_return(__wrap_cJSON_GetStringValue, "scan_time");
    will_return(__wrap_cJSON_GetStringValue, "format");
    will_return(__wrap_cJSON_GetStringValue, "name");
    will_return(__wrap_cJSON_GetStringValue, "priority");
    will_return(__wrap_cJSON_GetStringValue, "groups");
    will_return(__wrap_cJSON_GetStringValue, "vendor");
    will_return(__wrap_cJSON_GetStringValue, "install_time");
    will_return(__wrap_cJSON_GetStringValue, "version");
    will_return(__wrap_cJSON_GetStringValue, "architecture");
    will_return(__wrap_cJSON_GetStringValue, "multiarch");
    will_return(__wrap_cJSON_GetStringValue, "source");
    will_return(__wrap_cJSON_GetStringValue, "description");
    will_return(__wrap_cJSON_GetStringValue, "location");
    will_return(__wrap_cJSON_GetStringValue, "checksum");
    will_return(__wrap_cJSON_GetStringValue, "item_id");

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_package_save(): cannot begin transaction");
}

static void wdb_syscollector_package_save2_success(cJSON *attribute) {
    int i = 0;

    for (i = 0; i < 5; i++) {
        will_return(__wrap_cJSON_GetObjectItem, NULL);
    }

    will_return(__wrap_cJSON_GetObjectItem, 1);
    will_return(__wrap_cJSON_GetObjectItem, attribute);

    for (i = 0; i < 10; i++) {
        will_return(__wrap_cJSON_GetObjectItem, NULL);
    }

    will_return(__wrap_cJSON_GetStringValue, "scan_time");
    will_return(__wrap_cJSON_GetStringValue, "format");
    will_return(__wrap_cJSON_GetStringValue, "name");
    will_return(__wrap_cJSON_GetStringValue, "priority");
    will_return(__wrap_cJSON_GetStringValue, "groups");
    will_return(__wrap_cJSON_GetStringValue, "vendor");
    will_return(__wrap_cJSON_GetStringValue, "install_time");
    will_return(__wrap_cJSON_GetStringValue, "version");
    will_return(__wrap_cJSON_GetStringValue, "architecture");
    will_return(__wrap_cJSON_GetStringValue, "multiarch");
    will_return(__wrap_cJSON_GetStringValue, "source");
    will_return(__wrap_cJSON_GetStringValue, "description");
    will_return(__wrap_cJSON_GetStringValue, "location");
    will_return(__wrap_cJSON_GetStringValue, "checksum");
    will_return(__wrap_cJSON_GetStringValue, "item_id");

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "0");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_time");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "format");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "name");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_string(__wrap_sqlite3_bind_text, buffer, "priority");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_string(__wrap_sqlite3_bind_text, buffer, "groups");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 7);
    expect_value(__wrap_sqlite3_bind_int64, value, 987);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_string(__wrap_sqlite3_bind_text, buffer, "vendor");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 9);
    expect_string(__wrap_sqlite3_bind_text, buffer, "install_time");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 10);
    expect_string(__wrap_sqlite3_bind_text, buffer, "version");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 11);
    expect_string(__wrap_sqlite3_bind_text, buffer, "architecture");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 12);
    expect_string(__wrap_sqlite3_bind_text, buffer, "multiarch");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 13);
    expect_string(__wrap_sqlite3_bind_text, buffer, "source");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 14);
    expect_string(__wrap_sqlite3_bind_text, buffer, "description");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 15);
    expect_string(__wrap_sqlite3_bind_text, buffer, "location");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 16);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 17);
    expect_string(__wrap_sqlite3_bind_text, buffer, "item_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_wdb_step, SQLITE_DONE);
}

static void wdb_syscollector_hotfix_save2_fail(void) {
    int i = 0;

    for (i = 0; i < 3; i++) {
        will_return(__wrap_cJSON_GetObjectItem, NULL);
    }

    will_return(__wrap_cJSON_GetStringValue, "scan_time");
    will_return(__wrap_cJSON_GetStringValue, "hotfix");
    will_return(__wrap_cJSON_GetStringValue, "checksum");

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_hotfix_save(): cannot begin transaction");
}

static void wdb_syscollector_hotfix_save2_success(void) {
    int i = 0;

    for (i = 0; i < 3; i++) {
        will_return(__wrap_cJSON_GetObjectItem, NULL);
    }

    will_return(__wrap_cJSON_GetStringValue, "scan_time");
    will_return(__wrap_cJSON_GetStringValue, "hotfix");
    will_return(__wrap_cJSON_GetStringValue, "checksum");

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "0");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_time");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "hotfix");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_wdb_step, SQLITE_DONE);
}

static void wdb_syscollector_port_save2_fail(void) {
    int i = 0;

    for (i = 0; i < 14; i++) {
        will_return(__wrap_cJSON_GetObjectItem, NULL);
    }

    will_return(__wrap_cJSON_GetStringValue, "scan_time");
    will_return(__wrap_cJSON_GetStringValue, "protocol");
    will_return(__wrap_cJSON_GetStringValue, "local_ip");
    will_return(__wrap_cJSON_GetStringValue, "remote_ip");
    will_return(__wrap_cJSON_GetStringValue, "state");
    will_return(__wrap_cJSON_GetStringValue, "process");
    will_return(__wrap_cJSON_GetStringValue, "checksum");
    will_return(__wrap_cJSON_GetStringValue, "item_id");

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_port_save(): cannot begin transaction");
}

static void wdb_syscollector_port_save2_success(cJSON *attribute) {
    int i = 0;

    for (i = 0; i < 3; i++) {
        will_return(__wrap_cJSON_GetObjectItem, NULL);
    }

    will_return(__wrap_cJSON_GetObjectItem, 1);
    will_return(__wrap_cJSON_GetObjectItem, attribute);
    will_return(__wrap_cJSON_GetObjectItem, NULL);

    for (i = 0; i < 4; i++) {
        will_return(__wrap_cJSON_GetObjectItem, 1);
        will_return(__wrap_cJSON_GetObjectItem, attribute);
    }

    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetObjectItem, 1);
    will_return(__wrap_cJSON_GetObjectItem, attribute);

    for (i = 0; i < 3; i++) {
        will_return(__wrap_cJSON_GetObjectItem, NULL);
    }

    will_return(__wrap_cJSON_GetStringValue, "scan_time");
    will_return(__wrap_cJSON_GetStringValue, "protocol");
    will_return(__wrap_cJSON_GetStringValue, "local_ip");
    will_return(__wrap_cJSON_GetStringValue, "remote_ip");
    will_return(__wrap_cJSON_GetStringValue, "state");
    will_return(__wrap_cJSON_GetStringValue, "process");
    will_return(__wrap_cJSON_GetStringValue, "checksum");
    will_return(__wrap_cJSON_GetStringValue, "item_id");

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "0");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_time");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "protocol");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "local_ip");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 5);
    expect_value(__wrap_sqlite3_bind_int, value, 541);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_string(__wrap_sqlite3_bind_text, buffer, "remote_ip");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 7);
    expect_value(__wrap_sqlite3_bind_int, value, 541);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 8);
    expect_value(__wrap_sqlite3_bind_int, value, 541);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 9);
    expect_value(__wrap_sqlite3_bind_int, value, 541);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 10);
    expect_value(__wrap_sqlite3_bind_int64, value, 5294967296);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 11);
    expect_string(__wrap_sqlite3_bind_text, buffer, "state");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 12);
    expect_value(__wrap_sqlite3_bind_int, value, 541);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 13);
    expect_string(__wrap_sqlite3_bind_text, buffer, "process");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 14);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 15);
    expect_string(__wrap_sqlite3_bind_text, buffer, "item_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_wdb_step, SQLITE_DONE);
}

static void wdb_syscollector_netproto_save2_fail(void) {
    int i = 0;

    for (i = 0; i < 7;i++) {
        will_return(__wrap_cJSON_GetObjectItem, NULL);
    }

    will_return(__wrap_cJSON_GetStringValue, "iface");
    will_return(__wrap_cJSON_GetStringValue, "gateway");
    will_return(__wrap_cJSON_GetStringValue, "type");
    will_return(__wrap_cJSON_GetStringValue, "dhcp");
    will_return(__wrap_cJSON_GetStringValue, "checksum");
    will_return(__wrap_cJSON_GetStringValue, "item_id");

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_netproto_save(): cannot begin transaction");
}

static void wdb_syscollector_netproto_save2_success(cJSON *attribute) {
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetObjectItem, 1);
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetObjectItem, 1);
    will_return(__wrap_cJSON_GetObjectItem, attribute);
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetStringValue, "iface");
    will_return(__wrap_cJSON_GetStringValue, "ipv6");
    will_return(__wrap_cJSON_GetStringValue, "gateway");
    will_return(__wrap_cJSON_GetStringValue, "dhcp");
    will_return(__wrap_cJSON_GetStringValue, "checksum");
    will_return(__wrap_cJSON_GetStringValue, "item_id");

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "0");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "iface");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "ipv6");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "gateway");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_string(__wrap_sqlite3_bind_text, buffer, "dhcp");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 6);
    expect_value(__wrap_sqlite3_bind_int64, value, 654);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_string(__wrap_sqlite3_bind_text, buffer, "item_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_wdb_step, SQLITE_DONE);
}

static void wdb_syscollector_netaddr_save2_fail(void) {
    int i = 0;

    for (i = 0; i < 7; i++) {
        will_return(__wrap_cJSON_GetObjectItem, NULL);
    }

    will_return(__wrap_cJSON_GetStringValue, "iface");
    will_return(__wrap_cJSON_GetStringValue, "address");
    will_return(__wrap_cJSON_GetStringValue, "netmask");
    will_return(__wrap_cJSON_GetStringValue, "broadcast");
    will_return(__wrap_cJSON_GetStringValue, "checksum");
    will_return(__wrap_cJSON_GetStringValue, "item_id");

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_netaddr_save(): cannot begin transaction");
}

static void wdb_syscollector_netaddr_save2_success(cJSON *attribute) {
    int i = 0;

    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetObjectItem, 1);
    will_return(__wrap_cJSON_GetObjectItem, attribute);

    for (i = 0; i < 5; i++) {
        will_return(__wrap_cJSON_GetObjectItem, NULL);
    }

    will_return(__wrap_cJSON_GetStringValue, "iface");
    will_return(__wrap_cJSON_GetStringValue, "address");
    will_return(__wrap_cJSON_GetStringValue, "netmask");
    will_return(__wrap_cJSON_GetStringValue, "broadcast");
    will_return(__wrap_cJSON_GetStringValue, "checksum");
    will_return(__wrap_cJSON_GetStringValue, "item_id");

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "0");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "iface");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "ipv6");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "address");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_string(__wrap_sqlite3_bind_text, buffer, "netmask");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_string(__wrap_sqlite3_bind_text, buffer, "broadcast");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_string(__wrap_sqlite3_bind_text, buffer, "item_id");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_wdb_step, SQLITE_DONE);

}

static void wdb_syscollector_netinfo_save2_fail(void) {
    int i = 0;

    for (i = 0; i < 17; i++) {
        will_return(__wrap_cJSON_GetObjectItem, NULL);
    }

    will_return(__wrap_cJSON_GetStringValue, "scan_time");
    will_return(__wrap_cJSON_GetStringValue, "name");
    will_return(__wrap_cJSON_GetStringValue, "adapter");
    will_return(__wrap_cJSON_GetStringValue, "type");
    will_return(__wrap_cJSON_GetStringValue, "state");
    will_return(__wrap_cJSON_GetStringValue, "mac");
    will_return(__wrap_cJSON_GetStringValue, "checksum");
    will_return(__wrap_cJSON_GetStringValue, "item_id");

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_netinfo_save(): cannot begin transaction");
}

static void wdb_syscollector_netinfo_save2_success(cJSON *attribute) {
    int i = 0;

    for (i = 0; i < 5; i++) {
        will_return(__wrap_cJSON_GetObjectItem, NULL);
    }

    will_return(__wrap_cJSON_GetObjectItem, 1);
    will_return(__wrap_cJSON_GetObjectItem, attribute);
    will_return(__wrap_cJSON_GetObjectItem, NULL);

    for (i = 0; i < 8; i++) {
        will_return(__wrap_cJSON_GetObjectItem, 1);
        will_return(__wrap_cJSON_GetObjectItem, attribute);
    }

    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetStringValue, "scan_time");
    will_return(__wrap_cJSON_GetStringValue, "name");
    will_return(__wrap_cJSON_GetStringValue, "adapter");
    will_return(__wrap_cJSON_GetStringValue, "type");
    will_return(__wrap_cJSON_GetStringValue, "state");
    will_return(__wrap_cJSON_GetStringValue, "mac");
    will_return(__wrap_cJSON_GetStringValue, "checksum");
    will_return(__wrap_cJSON_GetStringValue, "item_id");

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "0");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_time");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "name");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "adapter");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_string(__wrap_sqlite3_bind_text, buffer, "type");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_string(__wrap_sqlite3_bind_text, buffer, "state");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 7);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_string(__wrap_sqlite3_bind_text, buffer, "mac");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 9);
    expect_value(__wrap_sqlite3_bind_int64, value, 1);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 10);
    expect_value(__wrap_sqlite3_bind_int64, value, 1);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 11);
    expect_value(__wrap_sqlite3_bind_int64, value, 1);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 12);
    expect_value(__wrap_sqlite3_bind_int64, value, 1);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 13);
    expect_value(__wrap_sqlite3_bind_int64, value, 1);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 14);
    expect_value(__wrap_sqlite3_bind_int64, value, 1);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 15);
    expect_value(__wrap_sqlite3_bind_int64, value, 1);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 16);
    expect_value(__wrap_sqlite3_bind_int64, value, 1);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 17);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 18);
    expect_string(__wrap_sqlite3_bind_text, buffer, "item_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_wdb_step, SQLITE_DONE);
}

static void wdb_syscollector_hwinfo_save2_fail(void) {
     int i = 0;

     for (i = 0; i < 9; i++) {
        will_return(__wrap_cJSON_GetObjectItem, NULL);
     }

     will_return(__wrap_cJSON_GetStringValue, "scan_time");
     will_return(__wrap_cJSON_GetStringValue, "board_serial");
     will_return(__wrap_cJSON_GetStringValue, "cpu_name");
     will_return(__wrap_cJSON_GetStringValue, "checksum");

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_hardware_save(): cannot begin transaction");
}

static void wdb_syscollector_hwinfo_save2_success(cJSON *attribute) {
    int i = 0;

     for (i = 0; i < 3; i++) {
        will_return(__wrap_cJSON_GetObjectItem, NULL);
     }

     for (i = 0; i < 5; i++) {
        will_return(__wrap_cJSON_GetObjectItem, 1);
        will_return(__wrap_cJSON_GetObjectItem, attribute);
     }

     will_return(__wrap_cJSON_GetObjectItem, NULL);

     will_return(__wrap_cJSON_GetStringValue, "scan_time");
     will_return(__wrap_cJSON_GetStringValue, "board_serial");
     will_return(__wrap_cJSON_GetStringValue, "cpu_name");
     will_return(__wrap_cJSON_GetStringValue, "checksum");

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "0");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_time");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "board_serial");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "cpu_name");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 5);
    expect_value(__wrap_sqlite3_bind_int, value, 7);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_double, index, 6);
    expect_value(__wrap_sqlite3_bind_double, value, 1.5);
    will_return(__wrap_sqlite3_bind_double, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 7);
    expect_value(__wrap_sqlite3_bind_int64, value, 7);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 8);
    expect_value(__wrap_sqlite3_bind_int64, value, 7);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 9);
    expect_value(__wrap_sqlite3_bind_int, value, 7);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 10);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_wdb_step, SQLITE_DONE);
}

static void wdb_syscollector_osinfo_save2_fail(void) {
    int i = 0;

    for (i = 0; i < 17; i++) {
        will_return(__wrap_cJSON_GetObjectItem, NULL);
    }

    will_return(__wrap_cJSON_GetStringValue, "scan_time");
    will_return(__wrap_cJSON_GetStringValue, "hostname");
    will_return(__wrap_cJSON_GetStringValue, "architecture");
    will_return(__wrap_cJSON_GetStringValue, "os_name");
    will_return(__wrap_cJSON_GetStringValue, "os_version");
    will_return(__wrap_cJSON_GetStringValue, "os_codename");
    will_return(__wrap_cJSON_GetStringValue, "os_major");
    will_return(__wrap_cJSON_GetStringValue, "os_minor");
    will_return(__wrap_cJSON_GetStringValue, "os_patch");
    will_return(__wrap_cJSON_GetStringValue, "os_build");
    will_return(__wrap_cJSON_GetStringValue, "os_platform");
    will_return(__wrap_cJSON_GetStringValue, "sysname");
    will_return(__wrap_cJSON_GetStringValue, "release");
    will_return(__wrap_cJSON_GetStringValue, "version");
    will_return(__wrap_cJSON_GetStringValue, "os_release");
    will_return(__wrap_cJSON_GetStringValue, "os_display_version");
    will_return(__wrap_cJSON_GetStringValue, "checksum");

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_osinfo_save(): cannot begin transaction");
}

void test_wdb_netinfo_save_insertion_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_netinfo_insert(): cannot cache statement");

    output = wdb_netinfo_save(data, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, 0, 0, 0, 0, 0, 0, 0, 0, NULL, NULL, false);
    assert_int_equal(output, -1);
}

/* Tests wdb_netinfo_insert */
void test_wdb_netinfo_insert_cache_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_netinfo_insert(): cannot cache statement");

    output = wdb_netinfo_insert(data, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, 0, 0, 0, 0, 0, 0, 0, 0, NULL, NULL, false);
    assert_int_equal(output, -1);
}

void test_wdb_netinfo_insert_default_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_time");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "name");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "adapter");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_string(__wrap_sqlite3_bind_text, buffer, "type");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_string(__wrap_sqlite3_bind_text, buffer, "state");
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_value(__wrap_sqlite3_bind_int, index, 7);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_string(__wrap_sqlite3_bind_text, buffer, "mac");
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_value(__wrap_sqlite3_bind_int64, index, 9);
    expect_value(__wrap_sqlite3_bind_int64, value, 2);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 10);
    expect_value(__wrap_sqlite3_bind_int64, value, 3);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 11);
    expect_value(__wrap_sqlite3_bind_int64, value, 4);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 12);
    expect_value(__wrap_sqlite3_bind_int64, value, 5);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 13);
    expect_value(__wrap_sqlite3_bind_int64, value, 6);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 14);
    expect_value(__wrap_sqlite3_bind_int64, value, 7);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 15);
    expect_value(__wrap_sqlite3_bind_int64, value, 8);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 16);
    expect_value(__wrap_sqlite3_bind_int64, value, 9);
    will_return(__wrap_sqlite3_bind_int64, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 17);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 18);
    expect_string(__wrap_sqlite3_bind_text, buffer, "item_id");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_wdb_step, 1);
    will_return(__wrap_sqlite3_errmsg, "ERROR");
    expect_string(__wrap__merror, formatted_msg, "SQLite: ERROR");

    output = wdb_netinfo_insert(data, "scan_id", "scan_time", "name", "adapter", "type", "state", 1, "mac", 2, 3, 4, 5, 6, 7, 8, 9, "checksum", "item_id", false);
    assert_int_equal(output, -1);
}

void test_wdb_netinfo_insert_sql_constraint_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_time");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "name");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "adapter");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_string(__wrap_sqlite3_bind_text, buffer, "type");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_string(__wrap_sqlite3_bind_text, buffer, "state");
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_value(__wrap_sqlite3_bind_int, index, 7);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_string(__wrap_sqlite3_bind_text, buffer, "mac");
    will_return(__wrap_sqlite3_bind_text, 0);


    expect_value(__wrap_sqlite3_bind_int64, index, 9);
    expect_value(__wrap_sqlite3_bind_int64, value, 2);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 10);
    expect_value(__wrap_sqlite3_bind_int64, value, 3);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 11);
    expect_value(__wrap_sqlite3_bind_int64, value, 4);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 12);
    expect_value(__wrap_sqlite3_bind_int64, value, 5);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 13);
    expect_value(__wrap_sqlite3_bind_int64, value, 6);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 14);
    expect_value(__wrap_sqlite3_bind_int64, value, 7);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 15);
    expect_value(__wrap_sqlite3_bind_int64, value, 8);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 16);
    expect_value(__wrap_sqlite3_bind_int64, value, 9);
    will_return(__wrap_sqlite3_bind_int64, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 17);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 18);
    expect_string(__wrap_sqlite3_bind_text, buffer, "item_id");
    will_return(__wrap_sqlite3_bind_text, 0);

   // expect_sqlite3_step_call(SQLITE_CONSTRAINT);
    will_return(__wrap_wdb_step, SQLITE_CONSTRAINT);
    will_return(__wrap_sqlite3_errmsg, "DUPLICATE");
    will_return(__wrap_sqlite3_errmsg, "DUPLICATE");
    expect_string(__wrap__merror, formatted_msg, "SQLite: DUPLICATE");

    output = wdb_netinfo_insert(data, "scan_id", "scan_time", "name", "adapter", "type", "state", 1, "mac", 2, 3, 4, 5, 6, 7, 8, 9, "checksum", "item_id", false);
    assert_int_equal(output, -1);
}

void test_wdb_netinfo_insert_sql_constraint_success(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_time");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "name");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "adapter");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_string(__wrap_sqlite3_bind_text, buffer, "type");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_string(__wrap_sqlite3_bind_text, buffer, "state");
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_value(__wrap_sqlite3_bind_int, index, 7);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_string(__wrap_sqlite3_bind_text, buffer, "mac");
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_value(__wrap_sqlite3_bind_int64, index, 9);
    expect_value(__wrap_sqlite3_bind_int64, value, 2);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 10);
    expect_value(__wrap_sqlite3_bind_int64, value, 3);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 11);
    expect_value(__wrap_sqlite3_bind_int64, value, 4);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 12);
    expect_value(__wrap_sqlite3_bind_int64, value, 5);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 13);
    expect_value(__wrap_sqlite3_bind_int64, value, 6);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 14);
    expect_value(__wrap_sqlite3_bind_int64, value, 7);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 15);
    expect_value(__wrap_sqlite3_bind_int64, value, 8);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 16);
    expect_value(__wrap_sqlite3_bind_int64, value, 9);
    will_return(__wrap_sqlite3_bind_int64, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 17);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 18);
    expect_string(__wrap_sqlite3_bind_text, buffer, "item_id");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_wdb_step, SQLITE_CONSTRAINT);
    will_return(__wrap_sqlite3_errmsg, "UNIQUE");
    will_return(__wrap_sqlite3_errmsg, "UNIQUE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: UNIQUE");

    output = wdb_netinfo_insert(data, "scan_id", "scan_time", "name", "adapter", "type", "state", 1, "mac", 2, 3, 4, 5, 6, 7, 8, 9, "checksum", "item_id", false);
    assert_int_equal(output, 0);
}

void test_wdb_netinfo_insert_sql_success(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_time");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "name");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "adapter");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_string(__wrap_sqlite3_bind_text, buffer, "type");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_string(__wrap_sqlite3_bind_text, buffer, "state");
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_value(__wrap_sqlite3_bind_int, index, 7);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_string(__wrap_sqlite3_bind_text, buffer, "mac");
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_value(__wrap_sqlite3_bind_int64, index, 9);
    expect_value(__wrap_sqlite3_bind_int64, value, 2);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 10);
    expect_value(__wrap_sqlite3_bind_int64, value, 3);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 11);
    expect_value(__wrap_sqlite3_bind_int64, value, 4);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 12);
    expect_value(__wrap_sqlite3_bind_int64, value, 5);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 13);
    expect_value(__wrap_sqlite3_bind_int64, value, 6);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 14);
    expect_value(__wrap_sqlite3_bind_int64, value, 7);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 15);
    expect_value(__wrap_sqlite3_bind_int64, value, 8);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 16);
    expect_value(__wrap_sqlite3_bind_int64, value, 9);
    will_return(__wrap_sqlite3_bind_int64, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 17);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 18);
    expect_string(__wrap_sqlite3_bind_text, buffer, "item_id");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_wdb_step, SQLITE_DONE);

    output = wdb_netinfo_insert(data, "scan_id", "scan_time", "name", "adapter", "type", "state", 1, "mac", 2, 3, 4, 5, 6, 7, 8, 9, "checksum", "item_id", false);
    assert_int_equal(output, 0);
}

/* Test wdb_netproto_insert */
void test_wdb_netproto_insert_cache_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_netproto_insert(): cannot cache statement");

    output = wdb_netproto_insert(data, NULL, NULL, 0, NULL, NULL, 0, NULL, NULL, false);
    assert_int_equal(output, -1);
}

void test_wdb_netproto_insert_default_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_stmt_cache, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "iface");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "ipv4");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "gateway");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_string(__wrap_sqlite3_bind_text, buffer, "dhcp");
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_value(__wrap_sqlite3_bind_int64, index, 6);
    expect_value(__wrap_sqlite3_bind_int64, value, 6);
    will_return(__wrap_sqlite3_bind_int64, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_string(__wrap_sqlite3_bind_text, buffer, "item_id");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_wdb_step, 1);
    will_return(__wrap_sqlite3_errmsg, "ERROR");
    expect_string(__wrap__merror, formatted_msg, "SQLite: ERROR");

    output = wdb_netproto_insert(data, "scan_id", "iface", WDB_NETADDR_IPV4, "gateway", "dhcp", 6, "checksum", "item_id", false);
    assert_int_equal(output, -1);
}

void test_wdb_netproto_insert_sql_constraint_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_stmt_cache, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "iface");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "ipv4");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "gateway");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_string(__wrap_sqlite3_bind_text, buffer, "dhcp");
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_value(__wrap_sqlite3_bind_int64, index, 6);
    expect_value(__wrap_sqlite3_bind_int64, value, 6);
    will_return(__wrap_sqlite3_bind_int64, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_string(__wrap_sqlite3_bind_text, buffer, "item_id");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_wdb_step, SQLITE_CONSTRAINT);
    will_return(__wrap_sqlite3_errmsg, "DUPLICATED");
    will_return(__wrap_sqlite3_errmsg, "DUPLICATED");
    expect_string(__wrap__merror, formatted_msg, "SQLite: DUPLICATED");

    output = wdb_netproto_insert(data, "scan_id", "iface", WDB_NETADDR_IPV4, "gateway", "dhcp", 6, "checksum", "item_id", false);
    assert_int_equal(output, -1);
}

void test_wdb_netproto_insert_sql_constraint_success(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_stmt_cache, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "iface");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "ipv4");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "gateway");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_string(__wrap_sqlite3_bind_text, buffer, "dhcp");
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_value(__wrap_sqlite3_bind_int64, index, 6);
    expect_value(__wrap_sqlite3_bind_int64, value, 6);
    will_return(__wrap_sqlite3_bind_int64, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_string(__wrap_sqlite3_bind_text, buffer, "item_id");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_wdb_step, SQLITE_CONSTRAINT);
    will_return(__wrap_sqlite3_errmsg, "UNIQUE");
    will_return(__wrap_sqlite3_errmsg, "UNIQUE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: UNIQUE");

    output = wdb_netproto_insert(data, "scan_id", "iface", WDB_NETADDR_IPV4, "gateway", "dhcp", 6, "checksum", "item_id", false);
    assert_int_equal(output, 0);
}

void test_wdb_netproto_insert_sql_success(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_stmt_cache, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "iface");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "ipv4");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "gateway");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_string(__wrap_sqlite3_bind_text, buffer, "dhcp");
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_value(__wrap_sqlite3_bind_int64, index, 6);
    expect_value(__wrap_sqlite3_bind_int64, value, 6);
    will_return(__wrap_sqlite3_bind_int64, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_string(__wrap_sqlite3_bind_text, buffer, "item_id");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_wdb_step, SQLITE_DONE);

    output = wdb_netproto_insert(data, "scan_id", "iface", WDB_NETADDR_IPV4, "gateway", "dhcp", 6, "checksum", "item_id", false);
    assert_int_equal(output, 0);
}

/* Test wdb_netaddr_save */
void test_wdb_netaddr_save_transaction_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 0;
    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_netaddr_save(): cannot begin transaction");

    output = wdb_netaddr_save(data, NULL, NULL, 0, NULL, NULL, NULL, NULL, NULL, false);
    assert_int_equal(output, -1);
}

void test_wdb_netaddr_save_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 1;
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_netaddr_insert(): cannot cache statement");

    output = wdb_netaddr_save(data, NULL, NULL, 0, NULL, NULL, NULL, NULL, NULL, false);
    assert_int_equal(output, -1);
}

void test_wdb_netaddr_save_success(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "iface");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "ipv6");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "address");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_string(__wrap_sqlite3_bind_text, buffer, "netmask");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_string(__wrap_sqlite3_bind_text, buffer, "broadcast");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_string(__wrap_sqlite3_bind_text, buffer, "item_id");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_wdb_step, SQLITE_DONE);

    output = wdb_netaddr_save(data, "scan_id", "iface", 1, "address", "netmask", "broadcast", "checksum", "item_id", true);
    assert_int_equal(output, 0);
}

/* Test wdb_netaddr_insert */
void test_wdb_netaddr_insert_cache_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_netaddr_insert(): cannot cache statement");

    output = wdb_netaddr_insert(data, NULL, NULL, 0, NULL, NULL, NULL, NULL, NULL, false);
    assert_int_equal(output, -1);
}

void test_wdb_netaddr_insert_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_stmt_cache, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "iface");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "ipv4");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "address");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_string(__wrap_sqlite3_bind_text, buffer, "netmask");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_string(__wrap_sqlite3_bind_text, buffer, "broadcast");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_string(__wrap_sqlite3_bind_text, buffer, "item_id");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_wdb_step, 1);
    will_return(__wrap_sqlite3_errmsg, "ERROR");
    expect_string(__wrap__merror, formatted_msg, "SQLite: ERROR");

    output = wdb_netaddr_insert(data, "scan_id", "iface", WDB_NETADDR_IPV4, "address", "netmask", "broadcast", "checksum", "item_id", false);
    assert_int_equal(output, -1);
}

/* Test wdb_netinfo_delete */
void test_wdb_netinfo_delete_transaction_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 0;
    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_netinfo_delete(): cannot begin transaction");

    output = wdb_netinfo_delete(data, "scan_id");
    assert_int_equal(output, -1);
}

void test_wdb_netinfo_delete_sys_netiface_cache_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 1;

    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_netinfo_delete(): cannot cache statement");

    output = wdb_netinfo_delete(data, "scan_id");
    assert_int_equal(output, -1);
}

void test_wdb_netinfo_delete_sys_netiface_sql_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_begin2, 0);

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_wdb_step, 1);
    will_return(__wrap_sqlite3_errmsg, "ERROR");
    expect_string(__wrap__merror, formatted_msg, "Deleting old information from 'sys_netiface' table: ERROR");

    output = wdb_netinfo_delete(data, "scan_id");
    assert_int_equal(output, -1);
}

void test_wdb_netinfo_delete_sys_netproto_cache_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_begin2, 0);

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_wdb_step, SQLITE_DONE);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_netinfo_delete(): cannot cache statement");

    output = wdb_netinfo_delete(data, "scan_id");
    assert_int_equal(output, -1);
}

void test_wdb_netinfo_delete_sys_netproto_sql_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_begin2, 0);

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_wdb_step, SQLITE_DONE);


    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_wdb_step, 1);
    will_return(__wrap_sqlite3_errmsg, "ERROR");
    expect_string(__wrap__merror, formatted_msg, "Deleting old information from 'sys_netproto' table: ERROR");

    output = wdb_netinfo_delete(data, "scan_id");
    assert_int_equal(output, -1);
}

void test_wdb_netinfo_delete_sys_netaddr_cache_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_begin2, 0);

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_wdb_step, SQLITE_DONE);


    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_netinfo_delete(): cannot cache statement");

    output = wdb_netinfo_delete(data, "scan_id");
    assert_int_equal(output, -1);
}

void test_wdb_netinfo_delete_sys_netaddr_sql_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_begin2, 0);

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_wdb_step, SQLITE_DONE);


    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_wdb_step, 1);
    will_return(__wrap_sqlite3_errmsg, "ERROR");
    expect_string(__wrap__merror, formatted_msg, "Deleting old information from 'sys_netaddr' table: ERROR");

    output = wdb_netinfo_delete(data, "scan_id");
    assert_int_equal(output, -1);
}

void test_wdb_netinfo_delete_success(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_begin2, 0);

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_wdb_step, SQLITE_DONE);


    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    output = wdb_netinfo_delete(data, "scan_id");
    assert_int_equal(output, 0);
}

/* Test wdb_hotfix_delete */
void test_wdb_hotfix_delete_transaction_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 0;
    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_hotfix_delete(): cannot begin transaction");

    output = wdb_hotfix_delete(data, "scan_id");
    assert_int_equal(output, -1);
}

void test_wdb_hotfix_delete_cache_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 1;
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_hotfix_delete(): cannot cache statement");

    output = wdb_hotfix_delete(data, "scan_id");
    assert_int_equal(output, -1);
}

void test_wdb_hotfix_delete_sql_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_wdb_step, 1);
    will_return(__wrap_sqlite3_errmsg, "ERROR");
    expect_string(__wrap__merror, formatted_msg, "Deleting old information from 'sys_hotfixes' table: ERROR");

    output = wdb_hotfix_delete(data, "scan_id");
    assert_int_equal(output, -1);
}

void test_wdb_hotfix_delete_success(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    output = wdb_hotfix_delete(data, "scan_id");
    assert_int_equal(output, 0);
}

/* Test wdb_osinfo_save */
void test_wdb_osinfo_save_transaction_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 0;
    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_osinfo_save(): cannot begin transaction");

    output = wdb_osinfo_save(data, "scan_id", "scan_time", "hostname", "architecture", "os_name", "os_version", "os_codename", "os_major", "os_minor", "os_patch", "os_build", "os_platform", "sysname", "release", "version", "os_release", "os_display_version", "checksum", false);
    assert_int_equal(output, -1);
}


void test_wdb_osinfo_save_retrieve_osinfo_type_reference_fail(void ** state) {
    int output = 0;
    wdb_t * data = (wdb_t *) *state;

    will_return(__wrap_wdb_begin2, 0);

    will_return(__wrap_wdb_stmt_cache, 0);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_time");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "hostname");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "architecture");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_string(__wrap_sqlite3_bind_text, buffer, "os_name");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_string(__wrap_sqlite3_bind_text, buffer, "os_version");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_string(__wrap_sqlite3_bind_text, buffer, "os_codename");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_string(__wrap_sqlite3_bind_text, buffer, "os_major");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 9);
    expect_string(__wrap_sqlite3_bind_text, buffer, "os_minor");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 10);
    expect_string(__wrap_sqlite3_bind_text, buffer, "os_patch");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 11);
    expect_string(__wrap_sqlite3_bind_text, buffer, "os_build");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 12);
    expect_string(__wrap_sqlite3_bind_text, buffer, "os_platform");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 13);
    expect_string(__wrap_sqlite3_bind_text, buffer, "sysname");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 14);
    expect_string(__wrap_sqlite3_bind_text, buffer, "release");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 15);
    expect_string(__wrap_sqlite3_bind_text, buffer, "version");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 16);
    expect_string(__wrap_sqlite3_bind_text, buffer, "os_release");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 17);
    expect_string(__wrap_sqlite3_bind_text, buffer, "os_display_version");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 18);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 19);
    expect_any(__wrap_sqlite3_bind_text, buffer);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_wdb_step, SQLITE_DONE);

    output = wdb_osinfo_save(data, "scan_id", "scan_time", "hostname", "architecture", "os_name", "os_version",
                             "os_codename", "os_major", "os_minor", "os_patch", "os_build", "os_platform", "sysname",
                             "release", "version", "os_release", "os_display_version", "checksum", false);
    assert_int_equal(output, 0);
}

void test_wdb_osinfo_save_retrieve_osinfo_ok(void ** state) {
    int output = 0;
    wdb_t * data = (wdb_t *) *state;

    will_return(__wrap_wdb_begin2, 0);


    will_return(__wrap_wdb_stmt_cache, 0);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_time");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "hostname");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "architecture");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_string(__wrap_sqlite3_bind_text, buffer, "os_name");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_string(__wrap_sqlite3_bind_text, buffer, "os_version");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_string(__wrap_sqlite3_bind_text, buffer, "os_codename");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_string(__wrap_sqlite3_bind_text, buffer, "os_major");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 9);
    expect_string(__wrap_sqlite3_bind_text, buffer, "os_minor");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 10);
    expect_string(__wrap_sqlite3_bind_text, buffer, "os_patch");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 11);
    expect_string(__wrap_sqlite3_bind_text, buffer, "os_build");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 12);
    expect_string(__wrap_sqlite3_bind_text, buffer, "os_platform");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 13);
    expect_string(__wrap_sqlite3_bind_text, buffer, "sysname");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 14);
    expect_string(__wrap_sqlite3_bind_text, buffer, "release");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 15);
    expect_string(__wrap_sqlite3_bind_text, buffer, "version");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 16);
    expect_string(__wrap_sqlite3_bind_text, buffer, "os_release");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 17);
    expect_string(__wrap_sqlite3_bind_text, buffer, "os_display_version");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 18);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 19);
    expect_any(__wrap_sqlite3_bind_text, buffer);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_wdb_step, SQLITE_DONE);

    output = wdb_osinfo_save(data, "scan_id", "scan_time", "hostname", "architecture", "os_name", "os_version",
                             "os_codename", "os_major", "os_minor", "os_patch", "os_build", "os_platform", "sysname",
                             "release", "version", "os_release", "os_display_version", "checksum", false);
    assert_int_equal(output, 0);
}

void test_wdb_osinfo_save_cache_fail(void ** state) {
    int output = 0;
    wdb_t * data = (wdb_t *) *state;
    char debug_msg[OS_SIZE_512] = {0};

    will_return(__wrap_wdb_begin2, 0);

    will_return(__wrap_wdb_stmt_cache, -1);
    snprintf(debug_msg, OS_SIZE_512, "at wdb_osinfo_save(): cannot cache statement (%d)", WDB_STMT_OSINFO_DEL);
    expect_string(__wrap__mdebug1, formatted_msg, debug_msg);

    output = wdb_osinfo_save(data, "scan_id", "scan_time", "hostname", "architecture", "os_name", "os_version",
                             "os_codename", "os_major", "os_minor", "os_patch", "os_build", "os_platform", "sysname",
                             "release", "version", "os_release", "os_display_version", "checksum", false);
    assert_int_equal(output, -1);
}

void test_wdb_osinfo_save_sql_fail(void ** state) {
    int output = 0;
    wdb_t * data = (wdb_t *) *state;

    will_return(__wrap_wdb_begin2, 0);

    will_return(__wrap_wdb_stmt_cache, 0);
    will_return(__wrap_wdb_step, SQLITE_ERROR);
    will_return(__wrap_sqlite3_errmsg, "ERROR");
    expect_string(__wrap__merror, formatted_msg, "Deleting old information from 'sys_osinfo' table: ERROR");

    output = wdb_osinfo_save(data, "scan_id", "scan_time", "hostname", "architecture", "os_name", "os_version",
                             "os_codename", "os_major", "os_minor", "os_patch", "os_build", "os_platform", "sysname",
                             "release", "version", "os_release", "os_display_version", "checksum", false);
    assert_int_equal(output, -1);
}

void test_wdb_osinfo_save_insert_fail(void ** state) {
    int output = 0;
    wdb_t * data = (wdb_t *) *state;

    will_return(__wrap_wdb_begin2, 0);


    will_return(__wrap_wdb_stmt_cache, 0);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_osinfo_insert(): cannot cache statement");

    output = wdb_osinfo_save(data, "scan_id", "scan_time", "hostname", "architecture", "os_name", "os_version",
                             "os_codename", "os_major", "os_minor", "os_patch", "os_build", "os_platform", "sysname",
                             "release", "version", "os_release", "os_display_version", "checksum", false);
    assert_int_equal(output, -1);
}

/* Test wdb_osinfo_insert */
void test_wdb_osinfo_insert_cache_fail(void ** state) {
    int output = 0;
    wdb_t * data = (wdb_t *) *state;

    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_osinfo_insert(): cannot cache statement");

    os_sha1 digest = "hexdigest";
    output =
        wdb_osinfo_insert(data, "scan_id", "scan_time", "hostname", "architecture", "os_name", "os_version",
                          "os_codename", "os_major", "os_minor", "os_patch", "os_build", "os_platform", "sysname",
                          "release", "version", "os_release", "os_display_version", "checksum", false, digest);
    assert_int_equal(output, -1);
}

void test_wdb_osinfo_insert_sql_fail(void ** state) {
    int output = 0;
    wdb_t * data = (wdb_t *) *state;
    os_sha1 digest = "hexdigest";


    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_time");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "hostname");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "architecture");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_string(__wrap_sqlite3_bind_text, buffer, "os_name");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_string(__wrap_sqlite3_bind_text, buffer, "os_version");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_string(__wrap_sqlite3_bind_text, buffer, "os_codename");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_string(__wrap_sqlite3_bind_text, buffer, "os_major");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 9);
    expect_string(__wrap_sqlite3_bind_text, buffer, "os_minor");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 10);
    expect_string(__wrap_sqlite3_bind_text, buffer, "os_patch");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 11);
    expect_string(__wrap_sqlite3_bind_text, buffer, "os_build");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 12);
    expect_string(__wrap_sqlite3_bind_text, buffer, "os_platform");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 13);
    expect_string(__wrap_sqlite3_bind_text, buffer, "sysname");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 14);
    expect_string(__wrap_sqlite3_bind_text, buffer, "release");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 15);
    expect_string(__wrap_sqlite3_bind_text, buffer, "version");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 16);
    expect_string(__wrap_sqlite3_bind_text, buffer, "os_release");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 17);
    expect_string(__wrap_sqlite3_bind_text, buffer, "os_display_version");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 18);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 19);
    expect_string(__wrap_sqlite3_bind_text, buffer, digest);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_wdb_step, 1);
    will_return(__wrap_sqlite3_errmsg, "ERROR");
    expect_string(__wrap__merror, formatted_msg, "SQLite: ERROR");

    output =
        wdb_osinfo_insert(data, "scan_id", "scan_time", "hostname", "architecture", "os_name", "os_version",
                          "os_codename", "os_major", "os_minor", "os_patch", "os_build", "os_platform", "sysname",
                          "release", "version", "os_release", "os_display_version", "checksum", false, digest);
    assert_int_equal(output, -1);
}

/* Test wdb_package_save */
void test_wdb_package_save_transaction_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 0;
    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_package_save(): cannot begin transaction");

    output = wdb_package_save(data, "scan_id", "scan_time", "format", "name", "priority", "section", 0, "vendor", "install_time", "version", "architecture", "multiarch", "source", "description", "location", "checksum", "item_id", false);
    assert_int_equal(output, -1);
}

void test_wdb_package_save_insert_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 1;
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_package_insert(): cannot cache statement");

    output = wdb_package_save(data, "scan_id", "scan_time", "format", "name", "priority", "section", 0, "vendor", "install_time", "version", "architecture", "multiarch", "source", "description", "location", "checksum", "item_id", false);
    assert_int_equal(output, -1);
}

void test_wdb_package_save_success(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 0;
    will_return(__wrap_wdb_begin2, 0);

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_time");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "format");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "name");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_string(__wrap_sqlite3_bind_text, buffer, "priority");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_string(__wrap_sqlite3_bind_text, buffer, "section");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_null, index, 7);
    will_return(__wrap_sqlite3_bind_null, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_string(__wrap_sqlite3_bind_text, buffer, "vendor");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 9);
    expect_string(__wrap_sqlite3_bind_text, buffer, "install_time");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 10);
    expect_string(__wrap_sqlite3_bind_text, buffer, "version");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 11);
    expect_string(__wrap_sqlite3_bind_text, buffer, "architecture");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 12);
    expect_string(__wrap_sqlite3_bind_text, buffer, "multiarch");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 13);
    expect_string(__wrap_sqlite3_bind_text, buffer, "source");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 14);
    expect_string(__wrap_sqlite3_bind_text, buffer, "description");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 15);
    expect_string(__wrap_sqlite3_bind_text, buffer, "location");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 16);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 17);
    expect_string(__wrap_sqlite3_bind_text, buffer, "item_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    output = wdb_package_save(data, "scan_id", "scan_time", "format", "name", "priority", "section", -1, "vendor", "install_time", "version", "architecture", "multiarch", "source", "description", "location", "checksum", "item_id", false);
    assert_int_equal(output, 0);
}

/* Test wdb_package_insert */
void test_wdb_package_insert_cache_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_package_insert(): cannot cache statement");

    output = wdb_package_insert(data, "scan_id", "scan_time", "format", "name", "priority", "section", 0, "vendor", "install_time", "version", "architecture", "multiarch", "source", "description", "location", "checksum", "item_id", false);
    assert_int_equal(output, -1);
}

void test_wdb_package_insert_default_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_time");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "format");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "name");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_string(__wrap_sqlite3_bind_text, buffer, "priority");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_string(__wrap_sqlite3_bind_text, buffer, "section");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 7);
    expect_value(__wrap_sqlite3_bind_int64, value, 0);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_string(__wrap_sqlite3_bind_text, buffer, "vendor");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 9);
    expect_string(__wrap_sqlite3_bind_text, buffer, "install_time");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 10);
    expect_string(__wrap_sqlite3_bind_text, buffer, "version");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 11);
    expect_string(__wrap_sqlite3_bind_text, buffer, "architecture");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 12);
    expect_string(__wrap_sqlite3_bind_text, buffer, "multiarch");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 13);
    expect_string(__wrap_sqlite3_bind_text, buffer, "source");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 14);
    expect_string(__wrap_sqlite3_bind_text, buffer, "description");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 15);
    expect_string(__wrap_sqlite3_bind_text, buffer, "location");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 16);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 17);
    expect_string(__wrap_sqlite3_bind_text, buffer, "item_id");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_wdb_step, 1);
    will_return(__wrap_sqlite3_errmsg, "ERROR");
    expect_string(__wrap__merror, formatted_msg, "SQLite: ERROR");


    output = wdb_package_insert(data, "scan_id", "scan_time", "format", "name", "priority", "section", 0, "vendor", "install_time", "version", "architecture", "multiarch", "source", "description", "location", "checksum", "item_id", false);
    assert_int_equal(output, -1);
}

void test_wdb_package_insert_sql_constraint_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_time");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "format");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "name");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_string(__wrap_sqlite3_bind_text, buffer, "priority");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_string(__wrap_sqlite3_bind_text, buffer, "section");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 7);
    expect_value(__wrap_sqlite3_bind_int64, value, 0);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_string(__wrap_sqlite3_bind_text, buffer, "vendor");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 9);
    expect_string(__wrap_sqlite3_bind_text, buffer, "install_time");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 10);
    expect_string(__wrap_sqlite3_bind_text, buffer, "version");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 11);
    expect_string(__wrap_sqlite3_bind_text, buffer, "architecture");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 12);
    expect_string(__wrap_sqlite3_bind_text, buffer, "multiarch");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 13);
    expect_string(__wrap_sqlite3_bind_text, buffer, "source");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 14);
    expect_string(__wrap_sqlite3_bind_text, buffer, "description");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 15);
    expect_string(__wrap_sqlite3_bind_text, buffer, "location");
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 16);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 17);
    expect_string(__wrap_sqlite3_bind_text, buffer, "item_id");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_wdb_step, SQLITE_CONSTRAINT);
    will_return(__wrap_sqlite3_errmsg, "DUPLICATED");
    will_return(__wrap_sqlite3_errmsg, "DUPLICATED");
    expect_string(__wrap__merror, formatted_msg, "SQLite: DUPLICATED");

    output = wdb_package_insert(data, "scan_id", "scan_time", "format", "name", "priority", "section", 0, "vendor", "install_time", "version", "architecture", "multiarch", "source", "description", "location", "checksum", "item_id", false);
    assert_int_equal(output, -1);
}

void test_wdb_package_insert_sql_constraint_success(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_time");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "format");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "name");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_string(__wrap_sqlite3_bind_text, buffer, "priority");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_string(__wrap_sqlite3_bind_text, buffer, "section");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 7);
    expect_value(__wrap_sqlite3_bind_int64, value, 0);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_string(__wrap_sqlite3_bind_text, buffer, "vendor");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 9);
    expect_string(__wrap_sqlite3_bind_text, buffer, "install_time");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 10);
    expect_string(__wrap_sqlite3_bind_text, buffer, "version");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 11);
    expect_string(__wrap_sqlite3_bind_text, buffer, "architecture");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 12);
    expect_string(__wrap_sqlite3_bind_text, buffer, "multiarch");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 13);
    expect_string(__wrap_sqlite3_bind_text, buffer, "source");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 14);
    expect_string(__wrap_sqlite3_bind_text, buffer, "description");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 15);
    expect_string(__wrap_sqlite3_bind_text, buffer, "location");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 16);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 17);
    expect_string(__wrap_sqlite3_bind_text, buffer, "item_id");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_wdb_step, SQLITE_CONSTRAINT);
    will_return(__wrap_sqlite3_errmsg, "UNIQUE");
    will_return(__wrap_sqlite3_errmsg, "UNIQUE");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: UNIQUE");

    output = wdb_package_insert(data, "scan_id", "scan_time", "format", "name", "priority", "section", 0, "vendor", "install_time", "version", "architecture", "multiarch", "source", "description", "location", "checksum", "item_id", false);
    assert_int_equal(output, 0);
}

void test_wdb_package_insert_sql_success(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_time");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "format");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "name");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_string(__wrap_sqlite3_bind_text, buffer, "priority");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_string(__wrap_sqlite3_bind_text, buffer, "section");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 7);
    expect_value(__wrap_sqlite3_bind_int64, value, 0);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_string(__wrap_sqlite3_bind_text, buffer, "vendor");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 9);
    expect_string(__wrap_sqlite3_bind_text, buffer, "install_time");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 10);
    expect_string(__wrap_sqlite3_bind_text, buffer, "version");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 11);
    expect_string(__wrap_sqlite3_bind_text, buffer, "architecture");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 12);
    expect_string(__wrap_sqlite3_bind_text, buffer, "multiarch");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 13);
    expect_string(__wrap_sqlite3_bind_text, buffer, "source");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 14);
    expect_string(__wrap_sqlite3_bind_text, buffer, "description");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 15);
    expect_string(__wrap_sqlite3_bind_text, buffer, "location");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 16);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 17);
    expect_string(__wrap_sqlite3_bind_text, buffer, "item_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    output = wdb_package_insert(data, "scan_id", "scan_time", "format", "name", "priority", "section", 0, "vendor", "install_time", "version", "architecture", "multiarch", "source", "description", "location", "checksum", "item_id", false);
    assert_int_equal(output, 0);
}

/* Test wdb_hotfix_save */
void test_wdb_hotfix_save_transaction_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 0;
    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_hotfix_save(): cannot begin transaction");

    output = wdb_hotfix_save(data, "scan_id", "scan_time", "hotfix", "checksum", false);
    assert_int_equal(output, -1);
}

void test_wdb_hotfix_save_insert_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 1;

    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_hotfix_insert(): cannot cache statement");

    output = wdb_hotfix_save(data, "scan_id", "scan_time", "hotfix", "checksum", false);
    assert_int_equal(output, -1);
}

void test_wdb_hotfix_save_success(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 0;
    will_return(__wrap_wdb_begin2, 0);

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_time");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "hotfix");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    output = wdb_hotfix_save(data, "scan_id", "scan_time", "hotfix", "checksum", false);
    assert_int_equal(output, 0);
}

/* Test wdb_package_update */
void test_wdb_package_update_transaction_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 0;
    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_package_update(): cannot begin transaction");

    output = wdb_package_update(data, "scan_id");
    assert_int_equal(output, -1);
}

void test_wdb_package_update_cache_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 1;
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_package_update(): cannot cache get statement");

    output = wdb_package_update(data, "scan_id");
    assert_int_equal(output, -1);
}

void test_wdb_package_update_sql_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 0;
    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);
    will_return(__wrap_wdb_step, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);



    will_return(__wrap_sqlite3_errmsg, "ERROR");
    expect_string(__wrap__merror, formatted_msg, "Unable to update the 'sys_programs' table: ERROR");


    output = wdb_package_update(data, "scan_id");
    assert_int_equal(output, -1);
}

void test_wdb_package_update_loop_cache_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "cpe");
    expect_value(__wrap_sqlite3_column_text, iCol, 1);
    will_return(__wrap_sqlite3_column_text, "msu_name");
    expect_value(__wrap_sqlite3_column_text, iCol, 2);
    will_return(__wrap_sqlite3_column_text, "format");
    expect_value(__wrap_sqlite3_column_text, iCol, 3);
    will_return(__wrap_sqlite3_column_text, "name");
    expect_value(__wrap_sqlite3_column_text, iCol, 4);
    will_return(__wrap_sqlite3_column_text, "vendor");
    expect_value(__wrap_sqlite3_column_text, iCol, 5);
    will_return(__wrap_sqlite3_column_text, "version");
    expect_value(__wrap_sqlite3_column_text, iCol, 6);
    will_return(__wrap_sqlite3_column_text, "arch");

    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_package_update(): cannot cache update statement");

    output = wdb_package_update(data, "scan_id");
    assert_int_equal(output, -1);
}

void test_wdb_package_update_loop_sql_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "cpe");
    expect_value(__wrap_sqlite3_column_text, iCol, 1);
    will_return(__wrap_sqlite3_column_text, "msu_name");
    expect_value(__wrap_sqlite3_column_text, iCol, 2);
    will_return(__wrap_sqlite3_column_text, "format");
    expect_value(__wrap_sqlite3_column_text, iCol, 3);
    will_return(__wrap_sqlite3_column_text, "name");
    expect_value(__wrap_sqlite3_column_text, iCol, 4);
    will_return(__wrap_sqlite3_column_text, "vendor");
    expect_value(__wrap_sqlite3_column_text, iCol, 5);
    will_return(__wrap_sqlite3_column_text, "version");
    expect_value(__wrap_sqlite3_column_text, iCol, 6);
    will_return(__wrap_sqlite3_column_text, "arch");

    will_return(__wrap_wdb_stmt_cache, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "cpe");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "msu_name");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "format");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_string(__wrap_sqlite3_bind_text, buffer, "name");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_string(__wrap_sqlite3_bind_text, buffer, "vendor");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_string(__wrap_sqlite3_bind_text, buffer, "version");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_string(__wrap_sqlite3_bind_text, buffer, "arch");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_wdb_step, 1);

    will_return(__wrap_sqlite3_errmsg, "ERROR");
    expect_string(__wrap__merror, formatted_msg, "Unable to update the 'sys_programs' table: ERROR");

    output = wdb_package_update(data, "scan_id");
    assert_int_equal(output, -1);
}

void test_wdb_package_update_success(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_wdb_step, SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "cpe");
    expect_value(__wrap_sqlite3_column_text, iCol, 1);
    will_return(__wrap_sqlite3_column_text, "msu_name");
    expect_value(__wrap_sqlite3_column_text, iCol, 2);
    will_return(__wrap_sqlite3_column_text, "format");
    expect_value(__wrap_sqlite3_column_text, iCol, 3);
    will_return(__wrap_sqlite3_column_text, "name");
    expect_value(__wrap_sqlite3_column_text, iCol, 4);
    will_return(__wrap_sqlite3_column_text, "vendor");
    expect_value(__wrap_sqlite3_column_text, iCol, 5);
    will_return(__wrap_sqlite3_column_text, "version");
    expect_value(__wrap_sqlite3_column_text, iCol, 6);
    will_return(__wrap_sqlite3_column_text, "arch");

    will_return(__wrap_wdb_stmt_cache, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "cpe");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "msu_name");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "format");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_string(__wrap_sqlite3_bind_text, buffer, "name");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_string(__wrap_sqlite3_bind_text, buffer, "vendor");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_string(__wrap_sqlite3_bind_text, buffer, "version");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_string(__wrap_sqlite3_bind_text, buffer, "arch");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_wdb_step, SQLITE_DONE);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    output = wdb_package_update(data, "scan_id");
    assert_int_equal(output, 0);
}

/* Test wdb_package_delete */
void test_wdb_package_delete_transaction_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 0;
    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_package_delete(): cannot begin transaction");

    output = wdb_package_delete(data, "scan_id");
    assert_int_equal(output, -1);
}

void test_wdb_package_delete_cache_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 1;
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_package_delete(): cannot cache statement");

    output = wdb_package_delete(data, "scan_id");
    assert_int_equal(output, -1);
}

void test_wdb_package_delete_sql_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 0;
    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_wdb_step, 1);
    will_return(__wrap_sqlite3_errmsg, "ERROR");
    expect_string(__wrap__merror, formatted_msg, "Deleting old information from 'sys_programs' table: ERROR");

    output = wdb_package_delete(data, "scan_id");
    assert_int_equal(output, -1);
}

void test_wdb_package_delete_success(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_wdb_step, SQLITE_DONE);

    output = wdb_package_delete(data, "scan_id");
    assert_int_equal(output, 0);
}

/* Test wdb_hardware_save */
void test_wdb_hardware_save_transaction_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 0;
    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_hardware_save(): cannot begin transaction");

    output = wdb_hardware_save(data, "scan_id", "scan_time", "serial", "cpu_name", 4, 2900, 8192, 6144, 2048, "checksum", false);
    assert_int_equal(output, -1);
}

void test_wdb_hardware_save_cache_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 1;
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_hardware_save(): cannot cache statement");

    output = wdb_hardware_save(data, "scan_id", "scan_time", "serial", "cpu_name", 4, 2900, 8192, 6144, 2048, "checksum", false);
    assert_int_equal(output, -1);
}

void test_wdb_hardware_save_sql_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 0;
    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);

    will_return(__wrap_wdb_step, 1);
    will_return(__wrap_sqlite3_errmsg, "ERROR");
    expect_string(__wrap__merror, formatted_msg, "Deleting old information from 'sys_hwinfo' table: ERROR");

    output = wdb_hardware_save(data, "scan_id", "scan_time", "serial", "cpu_name", 4, 2900, 8192, 6144, 2048, "checksum", false);
    assert_int_equal(output, -1);
}

void test_wdb_hardware_save_insert_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 0;
    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_hardware_insert(): cannot cache statement");

    output = wdb_hardware_save(data, "scan_id", "scan_time", "serial", "cpu_name", 4, 2900, 8192, 6144, 2048, "checksum", false);
    assert_int_equal(output, -1);
}

void test_wdb_hardware_save_success(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 0;
    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_time");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "serial");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "cpu_name");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_null, index, 5);
    will_return(__wrap_sqlite3_bind_null, 0);
    expect_value(__wrap_sqlite3_bind_null, index, 6);
    will_return(__wrap_sqlite3_bind_null, 0);
    expect_value(__wrap_sqlite3_bind_null, index, 7);
    will_return(__wrap_sqlite3_bind_null, 0);
    expect_value(__wrap_sqlite3_bind_null, index, 8);
    will_return(__wrap_sqlite3_bind_null, 0);
    expect_value(__wrap_sqlite3_bind_null, index, 9);
    will_return(__wrap_sqlite3_bind_null, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 10);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_wdb_step, SQLITE_DONE);

    output = wdb_hardware_save(data, "scan_id", "scan_time", "serial", "cpu_name", 0, 0, 0, 0, 0, "checksum", false);
    assert_int_equal(output, 0);
}

/* Test wdb_hardware_insert */
void test_wdb_hardware_insert_cache_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_hardware_insert(): cannot cache statement");

    output = wdb_hardware_insert(data, "scan_id", "scan_time", "serial", "cpu_name", 4, 2900, 8192, 6144, 2048, "checksum", false);
    assert_int_equal(output, -1);
}

void test_wdb_hardware_insert_sql_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_stmt_cache, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_time");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "serial");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "cpu_name");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 5);
    expect_value(__wrap_sqlite3_bind_int, value, 4);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_double, index, 6);
    expect_value(__wrap_sqlite3_bind_double, value, 2900);
    will_return(__wrap_sqlite3_bind_double, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 7);
    expect_value(__wrap_sqlite3_bind_int64, value, 8192);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 8);
    expect_value(__wrap_sqlite3_bind_int64, value, 6144);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 9);
    expect_value(__wrap_sqlite3_bind_int, value, 100);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 10);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_wdb_step, 1);
    will_return(__wrap_sqlite3_errmsg, "ERROR");
    expect_string(__wrap__merror, formatted_msg, "SQLite: ERROR");

    output = wdb_hardware_insert(data, "scan_id", "scan_time", "serial", "cpu_name", 4, 2900, 8192, 6144, 100, "checksum", false);
    assert_int_equal(output, -1);
}

/* Test wdb_port_save */
void test_wdb_port_save_transaction_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 0;
    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_port_save(): cannot begin transaction");

    output = wdb_port_save(data, "scan_id", "scan_time", "protocol", "local_ip", 541, "remote_ip", 541, 10, 10, 1, "state", 32545, "process", "checksum", "item_id", false);
    assert_int_equal(output, -1);
}

void test_wdb_port_save_insert_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 1;

    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_port_insert(): cannot cache statement");

    output = wdb_port_save(data, "scan_id", "scan_time", "protocol", "local_ip", 541, "remote_ip", 541, 10, 10, 1, "state", 32545, "process", "checksum", "item_id", false);
    assert_int_equal(output, -1);
}

void test_wdb_port_save_success(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 0;
    will_return(__wrap_wdb_begin2, 0);

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_time");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "protocol");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "local_ip");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 5);
    expect_value(__wrap_sqlite3_bind_int, value, 541);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_string(__wrap_sqlite3_bind_text, buffer, "remote_ip");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 7);
    expect_value(__wrap_sqlite3_bind_int, value, 541);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 8);
    expect_value(__wrap_sqlite3_bind_int, value, 10);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 9);
    expect_value(__wrap_sqlite3_bind_int, value, 10);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 10);
    expect_value(__wrap_sqlite3_bind_int64, value, 5294967296);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 11);
    expect_string(__wrap_sqlite3_bind_text, buffer, "state");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 12);
    expect_value(__wrap_sqlite3_bind_int, value, 32545);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 13);
    expect_string(__wrap_sqlite3_bind_text, buffer, "process");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 14);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 15);
    expect_string(__wrap_sqlite3_bind_text, buffer, "item_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    output = wdb_port_save(data, "scan_id", "scan_time", "protocol", "local_ip", 541, "remote_ip", 541, 10, 10, 5294967296, "state", 32545, "process", "checksum", "item_id", false);
    assert_int_equal(output, 0);
}

/* Test wdb_port_insert */
void test_wdb_port_insert_cache_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_port_insert(): cannot cache statement");

    output = wdb_port_insert(data, "scan_id", "scan_time", "protocol", "local_ip", 1, "remote_ip", 1, 1, 1, 1, "state", 1, "process", "checksum", "item_id", false);
    assert_int_equal(output, -1);
}

void test_wdb_port_insert_sql_fail(void **state) {
   int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_stmt_cache, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_time");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "protocol");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "local_ip");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 5);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_string(__wrap_sqlite3_bind_text, buffer, "remote_ip");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_null, index, 7);
    will_return(__wrap_sqlite3_bind_null, 0);
    expect_value(__wrap_sqlite3_bind_null, index, 8);
    will_return(__wrap_sqlite3_bind_null, 0);
    expect_value(__wrap_sqlite3_bind_null, index, 9);
    will_return(__wrap_sqlite3_bind_null, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 10);
    expect_value(__wrap_sqlite3_bind_int64, value, 1);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 11);
    expect_string(__wrap_sqlite3_bind_text, buffer, "state");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_null, index, 12);
    will_return(__wrap_sqlite3_bind_null, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 13);
    expect_string(__wrap_sqlite3_bind_text, buffer, "process");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 14);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 15);
    expect_string(__wrap_sqlite3_bind_text, buffer, "item_id");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_wdb_step, 1);
    will_return(__wrap_sqlite3_errmsg, "ERROR");
    expect_string(__wrap__merror, formatted_msg, "SQLite: ERROR");

    output = wdb_port_insert(data, "scan_id", "scan_time", "protocol", "local_ip", 1, "remote_ip", -1, -1, -1, 1, "state", -1, "process", "checksum", "item_id", false);
    assert_int_equal(output, -1);
}

/* Test wdb_port_delete */
void test_wdb_port_delete_transaction_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 0;
    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_port_delete(): cannot begin transaction");

    output = wdb_port_delete(data, "scan_id");
    assert_int_equal(output, -1);
}

void test_wdb_port_delete_cache_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 1;
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_port_delete(): cannot cache statement");

    output = wdb_port_delete(data, "scan_id");
    assert_int_equal(output, -1);
}

void test_wdb_port_delete_sql_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 0;
    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_wdb_step, 1);
    will_return(__wrap_sqlite3_errmsg, "ERROR");
    expect_string(__wrap__merror, formatted_msg, "Deleting old information from 'sys_ports' table: ERROR");

    output = wdb_port_delete(data, "scan_id");
    assert_int_equal(output, -1);
}

void test_wdb_port_delete_success(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 0;
    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_wdb_step, SQLITE_DONE);

    output = wdb_port_delete(data, "scan_id");
    assert_int_equal(output, 0);
}

/* Test wdb_process_save */
void test_wdb_process_save_transaction_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 0;
    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_process_save(): cannot begin transaction");

    output = wdb_process_save(data, "scan_id", "scan_time", 1, "name", "state", 1, 1, 1, "cmd", "argvs", "euser", "ruser", "suser", "egroup", "rgroup", "sgroup", "fgroup", 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 65, 2, 2, "checksum", false);
    assert_int_equal(output, -1);
}

void test_wdb_process_save_insert_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 1;

    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_process_insert(): cannot cache statement");

    output = wdb_process_save(data, "scan_id", "scan_time", 1, "name", "state", 1, 1, 1, "cmd", "argvs", "euser", "ruser", "suser", "egroup", "rgroup", "sgroup", "fgroup", 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 65, 2, 2, "checksum", false);
    assert_int_equal(output, -1);
}

void test_wdb_process_save_success(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 0;
    will_return(__wrap_wdb_begin2, 0);

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_time");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 3);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "name");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_string(__wrap_sqlite3_bind_text, buffer, "state");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 6);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 7);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 8);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 9);
    expect_string(__wrap_sqlite3_bind_text, buffer, "cmd");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 10);
    expect_string(__wrap_sqlite3_bind_text, buffer, "argvs");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 11);
    expect_string(__wrap_sqlite3_bind_text, buffer, "euser");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 12);
    expect_string(__wrap_sqlite3_bind_text, buffer, "ruser");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 13);
    expect_string(__wrap_sqlite3_bind_text, buffer, "suser");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 14);
    expect_string(__wrap_sqlite3_bind_text, buffer, "egroup");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 15);
    expect_string(__wrap_sqlite3_bind_text, buffer, "rgroup");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 16);
    expect_string(__wrap_sqlite3_bind_text, buffer, "sgroup");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 17);
    expect_string(__wrap_sqlite3_bind_text, buffer, "fgroup");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 18);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 19);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 20);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 21);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 22);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 23);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 24);
    expect_value(__wrap_sqlite3_bind_int64, value, 5294967296);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 25);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 26);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 27);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 28);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 29);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 30);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 31);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    output = wdb_process_save(data, "scan_id", "scan_time", 1, "name", "state", 1, 1, 1, "cmd", "argvs", "euser", "ruser", "suser", "egroup", "rgroup", "sgroup", "fgroup", 1, 1, 1, 1, 1, 1, 5294967296, 1, 1, 1, 1, 1, 1, "checksum", false);
    assert_int_equal(output, 0);
}

void test_wdb_process_insert_sql_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_stmt_cache, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_time");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 3);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "name");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_string(__wrap_sqlite3_bind_text, buffer, "state");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_null, index, 6);
    will_return(__wrap_sqlite3_bind_null, 0);
    expect_value(__wrap_sqlite3_bind_null, index, 7);
    will_return(__wrap_sqlite3_bind_null, 0);
    expect_value(__wrap_sqlite3_bind_null, index, 8);
    will_return(__wrap_sqlite3_bind_null, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 9);
    expect_string(__wrap_sqlite3_bind_text, buffer, "cmd");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 10);
    expect_string(__wrap_sqlite3_bind_text, buffer, "argvs");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 11);
    expect_string(__wrap_sqlite3_bind_text, buffer, "euser");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 12);
    expect_string(__wrap_sqlite3_bind_text, buffer, "ruser");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 13);
    expect_string(__wrap_sqlite3_bind_text, buffer, "suser");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 14);
    expect_string(__wrap_sqlite3_bind_text, buffer, "egroup");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 15);
    expect_string(__wrap_sqlite3_bind_text, buffer, "rgroup");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 16);
    expect_string(__wrap_sqlite3_bind_text, buffer, "sgroup");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 17);
    expect_string(__wrap_sqlite3_bind_text, buffer, "fgroup");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_null, index, 18);
    will_return(__wrap_sqlite3_bind_null, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 19);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_null, index, 20);
    will_return(__wrap_sqlite3_bind_null, 0);
    expect_value(__wrap_sqlite3_bind_null, index, 21);
    will_return(__wrap_sqlite3_bind_null, 0);
    expect_value(__wrap_sqlite3_bind_null, index, 22);
    will_return(__wrap_sqlite3_bind_null, 0);
    expect_value(__wrap_sqlite3_bind_null, index, 23);
    will_return(__wrap_sqlite3_bind_null, 0);
    expect_value(__wrap_sqlite3_bind_null, index, 24);
    will_return(__wrap_sqlite3_bind_null, 0);
    expect_value(__wrap_sqlite3_bind_null, index, 25);
    will_return(__wrap_sqlite3_bind_null, 0);
    expect_value(__wrap_sqlite3_bind_null, index, 26);
    will_return(__wrap_sqlite3_bind_null, 0);
    expect_value(__wrap_sqlite3_bind_null, index, 27);
    will_return(__wrap_sqlite3_bind_null, 0);
    expect_value(__wrap_sqlite3_bind_null, index, 28);
    will_return(__wrap_sqlite3_bind_null, 0);
    expect_value(__wrap_sqlite3_bind_null, index, 29);
    will_return(__wrap_sqlite3_bind_null, 0);
    expect_value(__wrap_sqlite3_bind_null, index, 30);
    will_return(__wrap_sqlite3_bind_null, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 31);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_wdb_step, 1);
    will_return(__wrap_sqlite3_errmsg, "ERROR");
    expect_string(__wrap__merror, formatted_msg, "SQLite: ERROR");

    output = wdb_process_insert(data, "scan_id", "scan_time", 1, "name", "state", -1, -1, -1, "cmd", "argvs", "euser", "ruser", "suser", "egroup", "rgroup", "sgroup", "fgroup", -1, 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, "checksum", false);
    assert_int_equal(output, -1);
}

/* Test wdb_process_delete */
void test_wdb_process_delete_transaction_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 0;
    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_process_delete(): cannot begin transaction");

    output = wdb_process_delete(data, "scan_id");
    assert_int_equal(output, -1);
}

void test_wdb_process_delete_cache_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 1;
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_process_delete(): cannot cache statement");

    output = wdb_process_delete(data, "scan_id");
    assert_int_equal(output, -1);
}

void test_wdb_process_delete_sql_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 0;
    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_wdb_step, 1);
    will_return(__wrap_sqlite3_errmsg, "ERROR");
    expect_string(__wrap__merror, formatted_msg, "Deleting old information from 'sys_processes' table: ERROR");

    output = wdb_process_delete(data, "scan_id");
    assert_int_equal(output, -1);
}

void test_wdb_process_delete_success(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 0;
    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_wdb_step, SQLITE_DONE);

    output = wdb_process_delete(data, "scan_id");
    assert_int_equal(output, 0);
}

/* Test wdb_users_save */
void test_wdb_users_save_transaction_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 0;
    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_users_save(): cannot begin transaction");

    output = wdb_users_save(data, "scan_id", "scan_time", "name", "full_name", "home", 1, 1, "uuid", "groups", 1, 1, 1.0, 1,
                            "shell", "type", true, false, 1, 1, 1.0, 1.0, 1, "hash", 1, 1, 1, 1, "status", 1, 1, "ip", true, 
                            "type", "tty", "checksum", false);
    assert_int_equal(output, -1);
}

void test_wdb_users_save_insert_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 1;

    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_users_insert(): cannot cache statement");

    output = wdb_users_save(data, "scan_id", "scan_time", "name", "full_name", "home", 1, 1, "uuid", "groups", 1, 1, 1.0, 1,
                            "shell", "type", true, false, 1, 1, 1.0, 1.0, 1, "hash", 1, 1, 1, 1, "status", 1, 1, "ip", true, 
                            "type", "tty", "checksum", false);    
    assert_int_equal(output, -1);
}

void test_wdb_users_save_success(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 0;
    will_return(__wrap_wdb_begin2, 0);

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_time");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "name");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "full_name");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_string(__wrap_sqlite3_bind_text, buffer, "home");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 6);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 7);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_string(__wrap_sqlite3_bind_text, buffer, "uuid");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 9);
    expect_string(__wrap_sqlite3_bind_text, buffer, "groups");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 10);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 11);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_double, index, 12);
    expect_value(__wrap_sqlite3_bind_double, value, 1.0);
    will_return(__wrap_sqlite3_bind_double, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 13);
    expect_value(__wrap_sqlite3_bind_text, buffer, "sudo");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 14);
    expect_string(__wrap_sqlite3_bind_text, buffer, "shell");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 15);
    expect_string(__wrap_sqlite3_bind_text, buffer, "type");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 16);
    expect_value(__wrap_sqlite3_bind_int, value, true);
    will_return(__wrap_sqlite3_bind_int, 0);    
    expect_value(__wrap_sqlite3_bind_int, index, 17);
    expect_value(__wrap_sqlite3_bind_int, value, false);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 18);
    expect_value(__wrap_sqlite3_bind_int64, value, 1);
    will_return(__wrap_sqlite3_bind_int64, 0);  
    expect_value(__wrap_sqlite3_bind_int, index, 19);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, 0); 
    expect_value(__wrap_sqlite3_bind_double, index, 20);
    expect_value(__wrap_sqlite3_bind_double, value, 1.0);
    will_return(__wrap_sqlite3_bind_double, 0);
    expect_value(__wrap_sqlite3_bind_double, index, 21);
    expect_value(__wrap_sqlite3_bind_double, value, 1.0);
    will_return(__wrap_sqlite3_bind_double, 0);    
    expect_value(__wrap_sqlite3_bind_int, index, 22);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 23);
    expect_string(__wrap_sqlite3_bind_text, buffer, "hash");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 24);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, 0);    
    expect_value(__wrap_sqlite3_bind_int, index, 25);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, 0);    
    expect_value(__wrap_sqlite3_bind_int, index, 26);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, 0);    
    expect_value(__wrap_sqlite3_bind_int, index, 27);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 28);
    expect_string(__wrap_sqlite3_bind_text, buffer, "status");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 29);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 30);
    expect_value(__wrap_sqlite3_bind_int64, value, 1);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 31);
    expect_string(__wrap_sqlite3_bind_text, buffer, "ip");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 32);
    expect_value(__wrap_sqlite3_bind_int, value, true);
    will_return(__wrap_sqlite3_bind_int, 0);  
    expect_value(__wrap_sqlite3_bind_text, pos, 33);
    expect_string(__wrap_sqlite3_bind_text, buffer, "type");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 34);
    expect_string(__wrap_sqlite3_bind_text, buffer, "tty");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 35);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    output = wdb_users_save(data, "scan_id", "scan_time", "name", "full_name", "home", 1, 1, "uuid", "groups", 1, 1, 1.0, "sudo",
                            "shell", "type", true, false, 1, 1, 1.0, 1.0, 1, "hash", 1, 1, 1, 1, "status", 1, 1, "ip", true, 
                            "type", "tty", "checksum", false);    
    assert_int_equal(output, 0);
}

/* wdb_users_insert */
void test_wdb_users_insert_sql_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_time");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "name");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "full_name");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_string(__wrap_sqlite3_bind_text, buffer, "home");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 6);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 7);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_string(__wrap_sqlite3_bind_text, buffer, "uuid");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 9);
    expect_string(__wrap_sqlite3_bind_text, buffer, "groups");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 10);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 11);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_double, index, 12);
    expect_value(__wrap_sqlite3_bind_double, value, 1.0);
    will_return(__wrap_sqlite3_bind_double, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 13);
    expect_value(__wrap_sqlite3_bind_text, buffer, "sudo");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 14);
    expect_string(__wrap_sqlite3_bind_text, buffer, "shell");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 15);
    expect_string(__wrap_sqlite3_bind_text, buffer, "type");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 16);
    expect_value(__wrap_sqlite3_bind_int, value, true);
    will_return(__wrap_sqlite3_bind_int, 0);    
    expect_value(__wrap_sqlite3_bind_int, index, 17);
    expect_value(__wrap_sqlite3_bind_int, value, false);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 18);
    expect_value(__wrap_sqlite3_bind_int64, value, 1);
    will_return(__wrap_sqlite3_bind_int64, 0);  
    expect_value(__wrap_sqlite3_bind_int, index, 19);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, 0); 
    expect_value(__wrap_sqlite3_bind_double, index, 20);
    expect_value(__wrap_sqlite3_bind_double, value, 1.0);
    will_return(__wrap_sqlite3_bind_double, 0);
    expect_value(__wrap_sqlite3_bind_double, index, 21);
    expect_value(__wrap_sqlite3_bind_double, value, 1.0);
    will_return(__wrap_sqlite3_bind_double, 0);    
    expect_value(__wrap_sqlite3_bind_int, index, 22);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 23);
    expect_string(__wrap_sqlite3_bind_text, buffer, "hash");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 24);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, 0);    
    expect_value(__wrap_sqlite3_bind_int, index, 25);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, 0);    
    expect_value(__wrap_sqlite3_bind_int, index, 26);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, 0);    
    expect_value(__wrap_sqlite3_bind_int, index, 27);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 28);
    expect_string(__wrap_sqlite3_bind_text, buffer, "status");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 29);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 30);
    expect_value(__wrap_sqlite3_bind_int64, value, 1);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 31);
    expect_string(__wrap_sqlite3_bind_text, buffer, "ip");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 32);
    expect_value(__wrap_sqlite3_bind_int, value, true);
    will_return(__wrap_sqlite3_bind_int, 0);  
    expect_value(__wrap_sqlite3_bind_text, pos, 33);
    expect_string(__wrap_sqlite3_bind_text, buffer, "type");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 34);
    expect_string(__wrap_sqlite3_bind_text, buffer, "tty");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 35);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_wdb_step, 1);
    will_return(__wrap_sqlite3_errmsg, "ERROR");
    expect_string(__wrap__merror, formatted_msg, "SQLite: ERROR");

    output = wdb_users_insert(data, "scan_id", "scan_time", "name", "full_name", "home", 1, 1, "uuid", "groups", 1, 1, 1.0, "sudo",
                            "shell", "type", true, false, 1, 1, 1.0, 1.0, 1, "hash", 1, 1, 1, 1, "status", 1, 1, "ip", true, 
                            "type", "tty", "checksum", false);    
    assert_int_equal(output, -1);
}

/* Test wdb_groups_save */
void test_wdb_groups_save_transaction_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 0;
    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_groups_save(): cannot begin transaction");

    output = wdb_groups_save(data, "scan_id", "scan_time", 1, "name", "description", 1, "uuid", true, "users", "checksum", false);
    assert_int_equal(output, -1);
}

void test_wdb_groups_save_insert_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 1;

    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_groups_insert(): cannot cache statement");

    output = wdb_groups_save(data, "scan_id", "scan_time", 1, "name", "description", 1, "uuid", true, "users", "checksum", false);
    assert_int_equal(output, -1);
}

void test_wdb_groups_save_success(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 0;
    will_return(__wrap_wdb_begin2, 0);

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_time");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 3);
    expect_value(__wrap_sqlite3_bind_int64, value, 1);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "name");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_string(__wrap_sqlite3_bind_text, buffer, "description");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 6);
    expect_value(__wrap_sqlite3_bind_int64, value, 1);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_string(__wrap_sqlite3_bind_text, buffer, "uuid");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 8);
    expect_value(__wrap_sqlite3_bind_int, value, true);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 9);
    expect_string(__wrap_sqlite3_bind_text, buffer, "users");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 10);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    output = wdb_groups_save(data, "scan_id", "scan_time", 1, "name", "description", 1, "uuid", true, "users", "checksum", false);
    assert_int_equal(output, 0);
}

/* wdb_groups_insert */
void test_wdb_groups_insert_sql_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_time");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 3);
    expect_value(__wrap_sqlite3_bind_int64, value, 1);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "name");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_string(__wrap_sqlite3_bind_text, buffer, "description");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_int64, index, 6);
    expect_value(__wrap_sqlite3_bind_int64, value, 1);
    will_return(__wrap_sqlite3_bind_int64, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_string(__wrap_sqlite3_bind_text, buffer, "uuid");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 8);
    expect_value(__wrap_sqlite3_bind_int, value, true);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 9);
    expect_string(__wrap_sqlite3_bind_text, buffer, "users");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 10);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_wdb_step, 1);
    will_return(__wrap_sqlite3_errmsg, "ERROR");
    expect_string(__wrap__merror, formatted_msg, "SQLite: ERROR");

    output = wdb_groups_insert(data, "scan_id", "scan_time", 1, "name", "description", 1, "uuid", true, "users", "checksum", false);
    assert_int_equal(output, -1);
}

/* Test wdb_syscollector_save2 */
void test_wdb_syscollector_save2_parser_json_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_cJSON_Parse, NULL);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_syscollector_save2(): no payload");

    output = wdb_syscollector_save2(data, WDB_SYSCOLLECTOR_PROCESSES, NULL);
    assert_int_equal(output, -1);
}

void test_wdb_syscollector_save2_get_attributes_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_cJSON_Parse, 1);
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    expect_function_call(__wrap_cJSON_Delete);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_syscollector_save2(): no attributes");

    output = wdb_syscollector_save2(data, WDB_SYSCOLLECTOR_PROCESSES, NULL);
    assert_int_equal(output, -1);
}

void test_wdb_syscollector_save2_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_cJSON_Parse, 1);
    will_return(__wrap_cJSON_GetObjectItem, 1);
    expect_function_call(__wrap_cJSON_Delete);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_syscollector_save2(): Invalid component.");
    
    output = wdb_syscollector_save2(data, 0, NULL);
    assert_int_equal(output, -1);
}

void test_wdb_syscollector_save2_processes_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_cJSON_Parse, 1);
    will_return(__wrap_cJSON_GetObjectItem, 1);

    data->transaction = 0;
    wdb_syscollector_processes_save2_fail();
    expect_function_call(__wrap_cJSON_Delete);

    output = wdb_syscollector_save2(data, WDB_SYSCOLLECTOR_PROCESSES, NULL);
    assert_int_equal(output, -1);
}

void test_wdb_syscollector_save2_processes_fail_2(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;
    cJSON attribute = {0};

    attribute.valueint = 123;
    attribute.valuedouble = 5294967296;

    will_return(__wrap_cJSON_Parse, 1);
    will_return(__wrap_cJSON_GetObjectItem, 1);

    data->transaction = 0;
    wdb_syscollector_processes_save2_fail_2(&attribute);
    expect_function_call(__wrap_cJSON_Delete);

    output = wdb_syscollector_save2(data, WDB_SYSCOLLECTOR_PROCESSES, NULL);
    assert_int_equal(output, OS_INVALID);
}

void test_wdb_syscollector_save2_processes_success(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;
    cJSON attribute = {0};

    attribute.valueint = 123;
    attribute.valuedouble = 5294967296;

    will_return(__wrap_cJSON_Parse, 1);
    will_return(__wrap_cJSON_GetObjectItem, 1);

    data->transaction = 0;
    wdb_syscollector_processes_save2_success(&attribute);
    expect_function_call(__wrap_cJSON_Delete);

    output = wdb_syscollector_save2(data, WDB_SYSCOLLECTOR_PROCESSES, NULL);
    assert_int_equal(output, 0);
}

void test_wdb_syscollector_save2_package_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_cJSON_Parse, 1);
    will_return(__wrap_cJSON_GetObjectItem, 1);

    data->transaction = 0;
    wdb_syscollector_package_save2_fail();
    expect_function_call(__wrap_cJSON_Delete);

    output = wdb_syscollector_save2(data, WDB_SYSCOLLECTOR_PACKAGES, NULL);
    assert_int_equal(output, -1);
}

void test_wdb_syscollector_save2_package_success(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;
    cJSON attribute = {0};

    attribute.valueint = 987;

    will_return(__wrap_cJSON_Parse, 1);
    will_return(__wrap_cJSON_GetObjectItem, 1);

    data->transaction = 0;
    wdb_syscollector_package_save2_success(&attribute);
    expect_function_call(__wrap_cJSON_Delete);

    output = wdb_syscollector_save2(data, WDB_SYSCOLLECTOR_PACKAGES, NULL);
    assert_int_equal(output, 0);
}

void test_wdb_syscollector_save2_hotfix_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_cJSON_Parse, 1);
    will_return(__wrap_cJSON_GetObjectItem, 1);

    data->transaction = 0;
    wdb_syscollector_hotfix_save2_fail();
    expect_function_call(__wrap_cJSON_Delete);

    output = wdb_syscollector_save2(data, WDB_SYSCOLLECTOR_HOTFIXES, NULL);
    assert_int_equal(output, -1);
}

void test_wdb_syscollector_save2_hotfix_success(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_cJSON_Parse, 1);
    will_return(__wrap_cJSON_GetObjectItem, 1);

    data->transaction = 0;
    wdb_syscollector_hotfix_save2_success();
    expect_function_call(__wrap_cJSON_Delete);

    output = wdb_syscollector_save2(data, WDB_SYSCOLLECTOR_HOTFIXES, NULL);
    assert_int_equal(output, 0);
}

void test_wdb_syscollector_save2_port_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_cJSON_Parse, 1);
    will_return(__wrap_cJSON_GetObjectItem, 1);

    data->transaction = 0;
    wdb_syscollector_port_save2_fail();
    expect_function_call(__wrap_cJSON_Delete);

    output = wdb_syscollector_save2(data, WDB_SYSCOLLECTOR_PORTS, NULL);
    assert_int_equal(output, -1);
}

void test_wdb_syscollector_save2_port_success(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;
    cJSON attribute = {0};

    attribute.valueint = 541;
    attribute.valuedouble = 5294967296;

    will_return(__wrap_cJSON_Parse, 1);
    will_return(__wrap_cJSON_GetObjectItem, 1);

    data->transaction = 0;
    wdb_syscollector_port_save2_success(&attribute);
    expect_function_call(__wrap_cJSON_Delete);

    output = wdb_syscollector_save2(data, WDB_SYSCOLLECTOR_PORTS, NULL);
    assert_int_equal(output, 0);
}

void test_wdb_syscollector_save2_netproto_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_cJSON_Parse, 1);
    will_return(__wrap_cJSON_GetObjectItem, 1);

    data->transaction = 0;
    wdb_syscollector_netproto_save2_fail();
    expect_function_call(__wrap_cJSON_Delete);

    output = wdb_syscollector_save2(data, WDB_SYSCOLLECTOR_NETPROTO, NULL);
    assert_int_equal(output, -1);
}

void test_wdb_syscollector_save2_netproto_success(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;
    cJSON attribute = {0};

    attribute.valueint = 654;
    will_return(__wrap_cJSON_Parse, 1);
    will_return(__wrap_cJSON_GetObjectItem, 1);

    data->transaction = 0;
    wdb_syscollector_netproto_save2_success(&attribute);
    expect_function_call(__wrap_cJSON_Delete);

    output = wdb_syscollector_save2(data, WDB_SYSCOLLECTOR_NETPROTO, NULL);
    assert_int_equal(output, 0);
}

void test_wdb_syscollector_save2_netaddr_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_cJSON_Parse, 1);
    will_return(__wrap_cJSON_GetObjectItem, 1);

    data->transaction = 0;
    wdb_syscollector_netaddr_save2_fail();
    expect_function_call(__wrap_cJSON_Delete);

    output = wdb_syscollector_save2(data, WDB_SYSCOLLECTOR_NETADDRESS, NULL);
    assert_int_equal(output, -1);
}

void test_wdb_syscollector_save2_netaddr_success(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;
    cJSON attribute = {0};

    attribute.valueint = 1;
    will_return(__wrap_cJSON_Parse, 1);
    will_return(__wrap_cJSON_GetObjectItem, 1);

    data->transaction = 0;
    wdb_syscollector_netaddr_save2_success(&attribute);
    expect_function_call(__wrap_cJSON_Delete);

    output = wdb_syscollector_save2(data, WDB_SYSCOLLECTOR_NETADDRESS, NULL);
    assert_int_equal(output, 0);
}

void test_wdb_syscollector_save2_netinfo_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_cJSON_Parse, 1);
    will_return(__wrap_cJSON_GetObjectItem, 1);

    data->transaction = 0;
    wdb_syscollector_netinfo_save2_fail();
    expect_function_call(__wrap_cJSON_Delete);

    output = wdb_syscollector_save2(data, WDB_SYSCOLLECTOR_NETINFO, NULL);
    assert_int_equal(output, -1);
}

void test_wdb_syscollector_save2_netinfo_success(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;
    cJSON attribute = {0};

    attribute.valueint = 1;
    will_return(__wrap_cJSON_Parse, 1);
    will_return(__wrap_cJSON_GetObjectItem, 1);

    data->transaction = 0;
    wdb_syscollector_netinfo_save2_success(&attribute);
    expect_function_call(__wrap_cJSON_Delete);

    output = wdb_syscollector_save2(data, WDB_SYSCOLLECTOR_NETINFO, NULL);
    assert_int_equal(output, 0);
}

void test_wdb_syscollector_save2_hwinfo_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_cJSON_Parse, 1);
    will_return(__wrap_cJSON_GetObjectItem, 1);

    data->transaction = 0;
    wdb_syscollector_hwinfo_save2_fail();
    expect_function_call(__wrap_cJSON_Delete);

    output = wdb_syscollector_save2(data, WDB_SYSCOLLECTOR_HWINFO, NULL);
    assert_int_equal(output, -1);
}

void test_wdb_syscollector_save2_hwinfo_success(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;
    cJSON attribute = {0};

    attribute.valueint = 7;
    attribute.valuedouble = 1.5;
    will_return(__wrap_cJSON_Parse, 1);
    will_return(__wrap_cJSON_GetObjectItem, 1);

    data->transaction = 0;
    wdb_syscollector_hwinfo_save2_success(&attribute);
    expect_function_call(__wrap_cJSON_Delete);

    output = wdb_syscollector_save2(data, WDB_SYSCOLLECTOR_HWINFO, NULL);
    assert_int_equal(output, 0);
}

void test_wdb_syscollector_save2_osinfo_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_cJSON_Parse, 1);
    will_return(__wrap_cJSON_GetObjectItem, 1);

    data->transaction = 0;
    wdb_syscollector_osinfo_save2_fail();
    expect_function_call(__wrap_cJSON_Delete);

    output = wdb_syscollector_save2(data, WDB_SYSCOLLECTOR_OSINFO, NULL);
    assert_int_equal(output, -1);
}

void test_wdb_syscollector_save2_osinfo_success(void ** state) {
    int output = 0;
    wdb_t * data = (wdb_t *) *state;

    data->transaction = 0;

    will_return(__wrap_cJSON_Parse, 1);
    will_return(__wrap_cJSON_GetObjectItem, 1);

    for (int i = 0; i < 17; i++) {
        will_return(__wrap_cJSON_GetObjectItem, NULL);
    }

    will_return(__wrap_cJSON_GetStringValue, "scan_time");
    will_return(__wrap_cJSON_GetStringValue, "hostname");
    will_return(__wrap_cJSON_GetStringValue, "architecture");
    will_return(__wrap_cJSON_GetStringValue, "os_name");
    will_return(__wrap_cJSON_GetStringValue, "os_version");
    will_return(__wrap_cJSON_GetStringValue, "os_codename");
    will_return(__wrap_cJSON_GetStringValue, "os_major");
    will_return(__wrap_cJSON_GetStringValue, "os_minor");
    will_return(__wrap_cJSON_GetStringValue, "os_patch");
    will_return(__wrap_cJSON_GetStringValue, "os_build");
    will_return(__wrap_cJSON_GetStringValue, "os_platform");
    will_return(__wrap_cJSON_GetStringValue, "sysname");
    will_return(__wrap_cJSON_GetStringValue, "release");
    will_return(__wrap_cJSON_GetStringValue, "version");
    will_return(__wrap_cJSON_GetStringValue, "os_release");
    will_return(__wrap_cJSON_GetStringValue, "os_display_version");
    will_return(__wrap_cJSON_GetStringValue, "checksum");

    will_return(__wrap_wdb_begin2, 0);

    will_return(__wrap_wdb_stmt_cache, 0);
    will_return(__wrap_wdb_step, SQLITE_DONE);

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "0");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_time");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "hostname");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "architecture");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_string(__wrap_sqlite3_bind_text, buffer, "os_name");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_string(__wrap_sqlite3_bind_text, buffer, "os_version");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_string(__wrap_sqlite3_bind_text, buffer, "os_codename");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_string(__wrap_sqlite3_bind_text, buffer, "os_major");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 9);
    expect_string(__wrap_sqlite3_bind_text, buffer, "os_minor");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 10);
    expect_string(__wrap_sqlite3_bind_text, buffer, "os_patch");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 11);
    expect_string(__wrap_sqlite3_bind_text, buffer, "os_build");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 12);
    expect_string(__wrap_sqlite3_bind_text, buffer, "os_platform");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 13);
    expect_string(__wrap_sqlite3_bind_text, buffer, "sysname");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 14);
    expect_string(__wrap_sqlite3_bind_text, buffer, "release");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 15);
    expect_string(__wrap_sqlite3_bind_text, buffer, "version");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 16);
    expect_string(__wrap_sqlite3_bind_text, buffer, "os_release");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 17);
    expect_string(__wrap_sqlite3_bind_text, buffer, "os_display_version");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 18);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 19);
    expect_any(__wrap_sqlite3_bind_text, buffer);
    will_return(__wrap_sqlite3_bind_text, 0);

    will_return(__wrap_wdb_step, SQLITE_DONE);

    expect_function_call(__wrap_cJSON_Delete);

    output = wdb_syscollector_save2(data, WDB_SYSCOLLECTOR_OSINFO, NULL);
    assert_int_equal(output, 0);
}

/* test objects */

// sys_netinfo
typedef struct netinfo_object {
    char *scan_id;
    char *scan_time;
    char *name;
    char *adapter;
    char *type;
    char *_state;
    int mtu;
    char *mac;
    long tx_packets;
    long rx_packets;
    long tx_bytes;
    long rx_bytes;
    long tx_errors;
    long rx_errors;
    long tx_dropped;
    long rx_dropped;
    char *checksum;
    char *item_id;
    bool replace;
} netinfo_object;

netinfo_object netinfo = {
    .scan_id = "0",
    .scan_time = "2022/06/29 15:29:45",
    .name = "Ethernet 2",
    .adapter = "Intel(R) PRO/1000 MT Desktop Adapter #2",
    .type = "ethernet",
    ._state = "up",
    .mtu = 1500,
    .mac = "08:00:27:4c:3d:35:",
    .tx_packets = 40041,
    .rx_packets = 38305,
    .tx_bytes = 17929845,
    .rx_bytes = 3332226,
    .tx_errors = 0,
    .rx_errors = 0,
    .tx_dropped = 0,
    .rx_dropped = 0,
    .checksum = "cabec688e047879b0efbf902b2cf6a8f256f5908",
    .item_id = "b6add5e98952c1216b6e189197de17c6962ccc74",
    .replace = TRUE
};

// sys_netproto
typedef struct netproto_object {
    char *scan_id;
    char *iface;
    int type;
    char *gateway;
    char *dhcp;
    int metric;
    char *checksum;
    char *item_id;
    bool replace;
} netproto_object;

netproto_object netproto = {
    .scan_id = "0",
    .iface = "Loopback Pseudo-Interface 1",
    .type = WDB_NETADDR_IPV4,
    .gateway = " ",
    .dhcp = "disabled",
    .metric = 75,
    .checksum = "c8e2003d6e3992ca9900667faa094ae195fbb98f",
    .item_id = "e6db7b9f540419ba6258e01fbadd8336d35c8c0a",
    .replace = TRUE
};

// sys_netaddr
typedef struct netaddr_object {
    char *scan_id;
    char *iface;
    int proto;
    char *address;
    char *netmask;
    char *broadcast;
    char *checksum;
    char *item_id;
    bool replace;
} netaddr_object;

netaddr_object netaddr = {
    .scan_id = "0",
    .iface = "Ethernet 2",
    .proto = 0,
    .address = "192.168.33.210",
    .netmask = "255.255.255.0",
    .broadcast = "192.168.33.255",
    .checksum = "57f25994f150743a56c87cefe773f30b92b351cf",
    .item_id = "9a6a01ef2bc8991938550cf826482d78c39050ee",
    .replace = TRUE
};

// sys_osinfo
typedef struct osinfo_object {
    char *scan_id;
    char *scan_time;
    char *hostname;
    char *architecture;
    char *os_name;
    char *os_version;
    char *os_codename;
    char *os_major;
    char *os_minor;
    char *os_patch;
    char *os_build;
    char *os_platform;
    char *sysname;
    char *release;
    char *version;
    char *os_release;
    char *os_display_version;
    char *checksum;
    bool replace;
    char *reference;
} osinfo_object;

osinfo_object osinfo = {
    .scan_id = "0",
    .scan_time = "2022/06/29 14:58:29",
    .hostname = "DESKTOP-8NH6TAI",
    .architecture = "x86_64",
    .os_name = "Microsoft Windows 11 Enterprise Evaluation",
    .os_version = "10.0.22000",
    .os_codename = " ",
    .os_major = "10",
    .os_minor = "0",
    .os_patch = " ",
    .os_build = "22000",
    .os_platform = " ",
    .sysname = " ",
    .release = " ",
    .version = " ",
    .os_release = "2009",
    .os_display_version = "21H2",
    .checksum = "1656514705657068700",
    .replace = TRUE,
    .reference = "eed7ce92814a61931ff8698ef3e8dea984df7635",
};

// sys_package
typedef struct package_object {
    char *scan_id;
    char *scan_time;
    char *format;
    char *name;
    char *priority;
    char * section;
    long size;
    char *vendor;
    char *install_time;
    char *version;
    char *architecture;
    char *multiarch;
    char *source;
    char *description;
    char *location;
    char *checksum;
    char *item_id;
    bool replace;
} package_object;

package_object package = {
    .scan_id = "0",
    .scan_time = "2022/06/22 21:20:36",
    .format = "win",
    .name = "Microsoft SQL Server 2014 (64-bit)",
    .priority = " ",
    .section = " ",
    .size = 12342356,
    .vendor = "Microsoft Corporation",
    .install_time = " ",
    .version = "12",
    .architecture = "x86_64",
    .multiarch = " ",
    .source = " ",
    .description = " ",
    .location = " ",
    .checksum = "2d4009216d12de6cd8c724ee7ea7ac26c9c9a248",
    .item_id = "8f5ddd79108614",
    .replace = TRUE
};

// sys_hotfix
typedef struct hotfix_object {
    char *scan_id;
    char *scan_time;
    char *hotfix;
    char *checksum;
    bool replace;
} hotfix_object;

hotfix_object hotfix = {
    .scan_id = "0",
    .scan_time = "2022/06/29 15:29:45",
    .hotfix = "KB982573",
    .checksum = "62a01d14af223e0ddeb5a5182e101ebfe1b12007",
    .replace = TRUE
};

// sys_hardware
typedef struct hardware_object {
    char *scan_id;
    char *scan_time;
    char *serial;
    char *cpu_name;
    int cpu_cores;
    double cpu_mhz;
    uint64_t ram_total;
    uint64_t ram_free;
    int ram_usage;
    char *checksum;
    bool replace;
} hardware_object;

hardware_object hardware = {
    .scan_id = "0",
    .scan_time = "2022/06/29 15:29:43",
    .serial = "0",
    .cpu_name = "Intel(R) Core(TM) i7-10750H CPU @ 2.60GHz",
    .cpu_cores = 2,
    .cpu_mhz = 2592,
    .ram_total = 4181100,
    .ram_free = 2311016,
    .ram_usage = 44,
    .checksum = "f3f06f3756c908eee3bbc36391371c7a5fff4f33",
    .replace = TRUE
};

// sys_port
typedef struct port_object {
    char *scan_id;
    char *scan_time;
    char *protocol;
    char *local_ip;
    int local_port;
    char *remote_ip;
    int remote_port;
    int tx_queue;
    int rx_queue;
    long long inode;
    char *state;
    int pid;
    char *process;
    char *checksum;
    char *item_id;
    bool replace;
} port_object;

port_object port = {
    .scan_id = "0",
    .scan_time = "2022/06/29 15:26:03",
    .protocol = "udp6",
    .local_ip = "::",
    .local_port = 54958,
    .remote_ip = NULL,
    .remote_port = 0,
    .tx_queue = 0,
    .rx_queue = 0,
    .inode = 0,
    .state = " ",
    .pid = 1744,
    .process = "svchost.exe",
    .checksum = "24641b98af84f613faf490b219daa8eb0afb11d7",
    .item_id = "9ec3a0047af3ebeaa72c9501fa09a3ccf53a69a3",
    .replace = TRUE,
};

// process
typedef struct process_object {
    char *scan_id;
    char *scan_time;
    int pid;
    char *name;
    char *state;
    int ppid;
    int utime;
    int stime;
    char *cmd;
    char *argvs;
    char *euser;
    char *ruser;
    char *suser;
    char *egroup;
    char *rgroup;
    char *sgroup;
    char *fgroup;
    int priority;
    int nice;
    int size;
    int vm_size;
    int resident;
    int share;
    int start_time;
    int pgrp;
    int session;
    int nlwp;
    int tgid;
    int tty;
    int processor;
    char *checksum;
    bool replace;
} process_object;

process_object process = {
    .scan_id = "0",
    .scan_time = "2022/07/04 17:14:07",
    .pid = 10480,
    .name = "uhssvc.exe",
    .state = NULL,
    .ppid = 780,
    .utime = 0,
    .stime = 0,
    .cmd = "\\Device\\HarddiskVolume3\\Program Files\\Microsoft Update Health Tools\\uhssvc.exe",
    .argvs = NULL,
    .euser = NULL,
    .ruser = NULL,
    .suser = NULL,
    .egroup = NULL,
    .rgroup = NULL,
    .sgroup = NULL,
    .fgroup = NULL,
    .priority = 8,
    .nice = 0,
    .size = 1355776,
    .vm_size = 7737344,
    .resident = 0,
    .share = 0,
    .start_time = 0,
    .pgrp = 0,
    .session = 0,
    .nlwp = 3,
    .tgid = 0,
    .tty = 0,
    .processor = 0,
    .checksum = "4ef6bc09b0d48caec86533b54d5650a378659663",
    .replace = TRUE
};

/* methods configurations */
void configure_sqlite3_bind_text(int position, const char* string) {
    will_return(__wrap_sqlite3_bind_text, OS_SUCCESS);
    expect_value(__wrap_sqlite3_bind_text, pos, position);
    if (string) {
        expect_string(__wrap_sqlite3_bind_text, buffer, string);
    }
}

void configure_sqlite3_bind_int64(int position, int number, bool allow_zero) {
    if (number > 0 || (0 == number && allow_zero)) {
        will_return(__wrap_sqlite3_bind_int64, OS_SUCCESS);
        expect_value(__wrap_sqlite3_bind_int64, index, position);
        expect_value(__wrap_sqlite3_bind_int64, value, number);
    } else {
        will_return(__wrap_sqlite3_bind_null, OS_SUCCESS);
        expect_value(__wrap_sqlite3_bind_null, index, position);
    }
}

void configure_sqlite3_bind_int(int position, int number, bool allow_zero) {
    if (number > 0 || (0 == number && allow_zero)) {
        will_return(__wrap_sqlite3_bind_int, OS_SUCCESS);
        expect_value(__wrap_sqlite3_bind_int, index, position);
        expect_value(__wrap_sqlite3_bind_int, value, number);
    } else {
        will_return(__wrap_sqlite3_bind_null, OS_SUCCESS);
        expect_value(__wrap_sqlite3_bind_null, index, position);
    }
}

void configure_sqlite3_bind_int_ex(int position, int number, bool allow_zero, bool allow_over_one_hundred) {
    if (!allow_over_one_hundred && number > 100) {
        will_return(__wrap_sqlite3_bind_null, OS_SUCCESS);
        expect_value(__wrap_sqlite3_bind_null, index, position);
    } else {
        configure_sqlite3_bind_int(position, number, allow_zero);
    }
}

void configure_sqlite3_bind_double(int position, double number, bool allow_zero) {
    if (number > 0 || (0 == number && allow_zero)) {
        will_return(__wrap_sqlite3_bind_double, OS_SUCCESS);
        expect_value(__wrap_sqlite3_bind_double, index, position);
        expect_value(__wrap_sqlite3_bind_double, value, number);
    } else {
        will_return(__wrap_sqlite3_bind_null, OS_SUCCESS);
        expect_value(__wrap_sqlite3_bind_null, index, position);
    }
}

// wdb_netinfo_insert
void configure_wdb_netinfo_insert(netinfo_object test_netinfo, int sqlite_code) {
    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);

    configure_sqlite3_bind_text(1, test_netinfo.scan_id);
    configure_sqlite3_bind_text(2, test_netinfo.scan_time);
    configure_sqlite3_bind_text(3, test_netinfo.name);
    configure_sqlite3_bind_text(4, test_netinfo.adapter);
    configure_sqlite3_bind_text(5, test_netinfo.type);
    configure_sqlite3_bind_text(6, test_netinfo._state);
    configure_sqlite3_bind_int(7, test_netinfo.mtu, NOT_ALLOW_ZERO);
    configure_sqlite3_bind_text(8, test_netinfo.mac);
    configure_sqlite3_bind_int64(9, test_netinfo.tx_packets, ALLOW_ZERO);
    configure_sqlite3_bind_int64(10, test_netinfo.rx_packets, ALLOW_ZERO);
    configure_sqlite3_bind_int64(11, test_netinfo.tx_bytes, ALLOW_ZERO);
    configure_sqlite3_bind_int64(12, test_netinfo.rx_bytes, ALLOW_ZERO);
    configure_sqlite3_bind_int64(13, test_netinfo.tx_errors, ALLOW_ZERO);
    configure_sqlite3_bind_int64(14, test_netinfo.rx_errors, ALLOW_ZERO);
    configure_sqlite3_bind_int64(15, test_netinfo.tx_dropped, ALLOW_ZERO);
    configure_sqlite3_bind_int64(16, test_netinfo.rx_dropped, ALLOW_ZERO);
    configure_sqlite3_bind_text(17, test_netinfo.checksum);
    configure_sqlite3_bind_text(18, test_netinfo.item_id);

    will_return(__wrap_wdb_step, sqlite_code);
}

// wdb_netproto_insert
void configure_wdb_netproto_insert(netproto_object test_netproto, int sqlite_code) {
    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);

    configure_sqlite3_bind_text(1, test_netproto.scan_id);
    configure_sqlite3_bind_text(2, test_netproto.iface);
    configure_sqlite3_bind_text(3, test_netproto.type == WDB_NETADDR_IPV4 ? "ipv4" : "ipv6");
    configure_sqlite3_bind_text(4, test_netproto.gateway);
    configure_sqlite3_bind_text(5, test_netproto.dhcp);
    configure_sqlite3_bind_int64(6, test_netproto.metric, ALLOW_ZERO);
    configure_sqlite3_bind_text(7, test_netproto.checksum);
    configure_sqlite3_bind_text(8, test_netproto.item_id);

    will_return(__wrap_wdb_step, sqlite_code);
}

// wdb_netaddr_insert
void configure_wdb_netaddr_insert(netaddr_object test_netaddr, int sqlite_code) {
    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);

    configure_sqlite3_bind_text(1, test_netaddr.scan_id);
    configure_sqlite3_bind_text(2, test_netaddr.iface);
    configure_sqlite3_bind_text(3, test_netaddr.proto == WDB_NETADDR_IPV4 ? "ipv4" : "ipv6");
    configure_sqlite3_bind_text(4, test_netaddr.address);
    configure_sqlite3_bind_text(5, test_netaddr.netmask);
    configure_sqlite3_bind_text(6, test_netaddr.broadcast);
    configure_sqlite3_bind_text(7, test_netaddr.checksum);
    configure_sqlite3_bind_text(8, test_netaddr.item_id);

    will_return(__wrap_wdb_step, sqlite_code);
}

// wdb_osinfo_insert
void configure_wdb_osinfo_insert(osinfo_object test_osinfo, int sqlite_code) {
    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);

    configure_sqlite3_bind_text(1, test_osinfo.scan_id);
    configure_sqlite3_bind_text(2, test_osinfo.scan_time);
    configure_sqlite3_bind_text(3, test_osinfo.hostname);
    configure_sqlite3_bind_text(4, test_osinfo.architecture);
    configure_sqlite3_bind_text(5, test_osinfo.os_name);
    configure_sqlite3_bind_text(6, test_osinfo.os_version);
    configure_sqlite3_bind_text(7, test_osinfo.os_codename);
    configure_sqlite3_bind_text(8, test_osinfo.os_major);
    configure_sqlite3_bind_text(9, test_osinfo.os_minor);
    configure_sqlite3_bind_text(10, test_osinfo.os_patch);
    configure_sqlite3_bind_text(11, test_osinfo.os_build);
    configure_sqlite3_bind_text(12, test_osinfo.os_platform);
    configure_sqlite3_bind_text(13, test_osinfo.sysname);
    configure_sqlite3_bind_text(14, test_osinfo.release);
    configure_sqlite3_bind_text(15, test_osinfo.version);
    configure_sqlite3_bind_text(16, test_osinfo.os_release);
    configure_sqlite3_bind_text(17, test_osinfo.os_display_version);
    configure_sqlite3_bind_text(18, test_osinfo.checksum);
    configure_sqlite3_bind_text(19, test_osinfo.reference);

    will_return(__wrap_wdb_step, sqlite_code);
}

// wdb_package_insert
void configure_wdb_package_insert(package_object test_package, int sqlite_code) {
    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);

    configure_sqlite3_bind_text(1, test_package.scan_id);
    configure_sqlite3_bind_text(2, test_package.scan_time);
    configure_sqlite3_bind_text(3, test_package.format);
    configure_sqlite3_bind_text(4, test_package.name);
    configure_sqlite3_bind_text(5, test_package.priority);
    configure_sqlite3_bind_text(6, test_package.section);
    configure_sqlite3_bind_int64(7, test_package.size, ALLOW_ZERO);
    configure_sqlite3_bind_text(8, test_package.vendor);
    configure_sqlite3_bind_text(9, test_package.install_time);
    configure_sqlite3_bind_text(10, test_package.version);
    configure_sqlite3_bind_text(11, test_package.architecture);
    configure_sqlite3_bind_text(12, test_package.multiarch);
    configure_sqlite3_bind_text(13, test_package.source);
    configure_sqlite3_bind_text(14, test_package.description);
    configure_sqlite3_bind_text(15, test_package.location);
    configure_sqlite3_bind_text(16, test_package.checksum);
    configure_sqlite3_bind_text(17, test_package.item_id);

    will_return(__wrap_wdb_step, sqlite_code);
}

// wdb_hotfix_insert
void configure_wdb_hotfix_insert(hotfix_object test_hotfix, int sqlite_code) {
    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);

    configure_sqlite3_bind_text(1, test_hotfix.scan_id);
    configure_sqlite3_bind_text(2, test_hotfix.scan_time);
    configure_sqlite3_bind_text(3, test_hotfix.hotfix);
    configure_sqlite3_bind_text(4, test_hotfix.checksum);

    will_return(__wrap_wdb_step, sqlite_code);
}

// wdb_hardware_insert
void configure_wdb_hardware_insert(hardware_object test_hardware, int sqlite_code) {
    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);

    configure_sqlite3_bind_text(1, test_hardware.scan_id);
    configure_sqlite3_bind_text(2, test_hardware.scan_time);
    configure_sqlite3_bind_text(3, test_hardware.serial);
    configure_sqlite3_bind_text(4, test_hardware.cpu_name);
    configure_sqlite3_bind_int(5, test_hardware.cpu_cores, NOT_ALLOW_ZERO);
    configure_sqlite3_bind_double(6, test_hardware.cpu_mhz, NOT_ALLOW_ZERO);
    configure_sqlite3_bind_int64(7, test_hardware.ram_total, NOT_ALLOW_ZERO);
    configure_sqlite3_bind_int64(8, test_hardware.ram_free, NOT_ALLOW_ZERO);
    configure_sqlite3_bind_int_ex(9, test_hardware.ram_usage, NOT_ALLOW_ZERO, NOT_ALLOW_OVER_ONEHUNDRED);
    configure_sqlite3_bind_text(10, test_hardware.checksum);

    will_return(__wrap_wdb_step, sqlite_code);
}

// wdb_port_insert
void configure_wdb_port_insert(port_object test_port, int sqlite_code) {
    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);

    configure_sqlite3_bind_text(1, test_port.scan_id);
    configure_sqlite3_bind_text(2, test_port.scan_time);
    configure_sqlite3_bind_text(3, test_port.protocol);
    configure_sqlite3_bind_text(4, test_port.local_ip);
    configure_sqlite3_bind_int(5, test_port.local_port, ALLOW_ZERO);
    configure_sqlite3_bind_text(6, test_port.remote_ip);
    configure_sqlite3_bind_int(7, test_port.remote_port, ALLOW_ZERO);
    configure_sqlite3_bind_int(8, test_port.tx_queue, ALLOW_ZERO);
    configure_sqlite3_bind_int(9, test_port.rx_queue, ALLOW_ZERO);
    configure_sqlite3_bind_int64(10, test_port.inode, ALLOW_ZERO);
    configure_sqlite3_bind_text(11, test_port.state);
    configure_sqlite3_bind_int(12, test_port.pid, ALLOW_ZERO);
    configure_sqlite3_bind_text(13, test_port.process);
    configure_sqlite3_bind_text(14, test_port.checksum);
    configure_sqlite3_bind_text(15, test_port.item_id);

    will_return(__wrap_wdb_step, sqlite_code);
}

// wdb_process_insert
void configure_wdb_process_insert(process_object test_process, int sqlite_code) {
    will_return(__wrap_wdb_stmt_cache, OS_SUCCESS);

    configure_sqlite3_bind_text(1, test_process.scan_id);
    configure_sqlite3_bind_text(2, test_process.scan_time);
    configure_sqlite3_bind_int(3, test_process.pid, ALLOW_ZERO);
    configure_sqlite3_bind_text(4, test_process.name);
    configure_sqlite3_bind_text(5, test_process.state);
    configure_sqlite3_bind_int(6, test_process.ppid, ALLOW_ZERO);
    configure_sqlite3_bind_int(7, test_process.utime, ALLOW_ZERO);
    configure_sqlite3_bind_int(8, test_process.stime, ALLOW_ZERO);
    configure_sqlite3_bind_text(9, test_process.cmd);
    configure_sqlite3_bind_text(10, test_process.argvs);
    configure_sqlite3_bind_text(11, test_process.euser);
    configure_sqlite3_bind_text(12, test_process.ruser);
    configure_sqlite3_bind_text(13, test_process.suser);
    configure_sqlite3_bind_text(14, test_process.egroup);
    configure_sqlite3_bind_text(15, test_process.rgroup);
    configure_sqlite3_bind_text(16, test_process.sgroup);
    configure_sqlite3_bind_text(17, test_process.fgroup);
    configure_sqlite3_bind_int(18, test_process.priority, ALLOW_ZERO);
    configure_sqlite3_bind_int(19, test_process.nice, ALLOW_ZERO);
    configure_sqlite3_bind_int(20, test_process.size, ALLOW_ZERO);
    configure_sqlite3_bind_int(21, test_process.vm_size, ALLOW_ZERO);
    configure_sqlite3_bind_int(22, test_process.resident, ALLOW_ZERO);
    configure_sqlite3_bind_int(23, test_process.share, ALLOW_ZERO);
    configure_sqlite3_bind_int64(24, test_process.start_time, ALLOW_ZERO);
    configure_sqlite3_bind_int(25, test_process.pgrp, ALLOW_ZERO);
    configure_sqlite3_bind_int(26, test_process.session, ALLOW_ZERO);
    configure_sqlite3_bind_int(27, test_process.nlwp, ALLOW_ZERO);
    configure_sqlite3_bind_int(28, test_process.tgid, ALLOW_ZERO);
    configure_sqlite3_bind_int(29, test_process.tty, ALLOW_ZERO);
    configure_sqlite3_bind_int(30, test_process.processor, ALLOW_ZERO);
    configure_sqlite3_bind_text(31, test_process.checksum);

    will_return(__wrap_wdb_step, sqlite_code);
}

/* tests */

// Test wdb_netinfo_save
static void test_wdb_netinfo_save_transaction_fail(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, OS_INVALID);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_netinfo_save(): cannot begin transaction");

    ret = wdb_netinfo_save(data->wdb, netinfo.scan_id, netinfo.scan_time, netinfo.name, netinfo.adapter, netinfo.type,
                           netinfo._state, netinfo.mtu, netinfo.mac, netinfo.tx_packets, netinfo.rx_packets, netinfo.tx_bytes,
                           netinfo.rx_bytes, netinfo.tx_errors, netinfo.rx_errors, netinfo.tx_dropped, netinfo.rx_dropped, netinfo.checksum,
                           netinfo.item_id, netinfo.replace);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wdb_netinfo_save_success(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, OS_SUCCESS);
    configure_wdb_netinfo_insert(netinfo, SQLITE_DONE);

    ret = wdb_netinfo_save(data->wdb, netinfo.scan_id, netinfo.scan_time, netinfo.name, netinfo.adapter, netinfo.type,
                           netinfo._state, netinfo.mtu, netinfo.mac, netinfo.tx_packets, netinfo.rx_packets, netinfo.tx_bytes,
                           netinfo.rx_bytes, netinfo.tx_errors, netinfo.rx_errors, netinfo.tx_dropped, netinfo.rx_dropped, netinfo.checksum,
                           netinfo.item_id, netinfo.replace);

    assert_int_equal(ret, OS_SUCCESS);
}

static void test_wdb_netinfo_save_fail(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, OS_SUCCESS);

    // wdb_netinfo_insert
    will_return(__wrap_wdb_stmt_cache, OS_INVALID);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_netinfo_insert(): cannot cache statement");

    ret = wdb_netinfo_save(data->wdb, netinfo.scan_id, netinfo.scan_time, netinfo.name, netinfo.adapter, netinfo.type,
                           netinfo._state, netinfo.mtu, netinfo.mac, netinfo.tx_packets, netinfo.rx_packets, netinfo.tx_bytes,
                           netinfo.rx_bytes, netinfo.tx_errors, netinfo.rx_errors, netinfo.tx_dropped, netinfo.rx_dropped, netinfo.checksum,
                           netinfo.item_id, netinfo.replace);

    assert_int_equal(ret, OS_INVALID);
}

// Test wdb_netinfo_insert
static void test_wdb_netinfo_insert_stmt_cache_fail(void **state) {
    int ret = OS_INVALID;

    will_return(__wrap_wdb_stmt_cache, OS_INVALID);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_netinfo_insert(): cannot cache statement");

    ret = wdb_netinfo_insert(NULL, netinfo.scan_id, netinfo.scan_time, netinfo.name, netinfo.adapter, netinfo.type,
                             netinfo._state, netinfo.mtu, netinfo.mac, netinfo.tx_packets, netinfo.rx_packets, netinfo.tx_bytes,
                             netinfo.rx_bytes, netinfo.tx_errors, netinfo.rx_errors, netinfo.tx_dropped, netinfo.rx_dropped, netinfo.checksum,
                             netinfo.item_id, netinfo.replace);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wdb_netinfo_insert_success(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;

    configure_wdb_netinfo_insert(netinfo, SQLITE_DONE);

    ret = wdb_netinfo_insert(data->wdb, netinfo.scan_id, netinfo.scan_time, netinfo.name, netinfo.adapter, netinfo.type,
                             netinfo._state, netinfo.mtu, netinfo.mac, netinfo.tx_packets, netinfo.rx_packets, netinfo.tx_bytes,
                             netinfo.rx_bytes, netinfo.tx_errors, netinfo.rx_errors, netinfo.tx_dropped, netinfo.rx_dropped, netinfo.checksum,
                             netinfo.item_id, netinfo.replace);

    assert_int_equal(ret, OS_SUCCESS);
}

static void test_wdb_netinfo_insert_name_null_success(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;
    netinfo_object test_netinfo = netinfo;
    test_netinfo.name = NULL;

    expect_value(__wrap_wdbi_remove_by_pk, component, WDB_SYSCOLLECTOR_NETINFO);
    expect_value(__wrap_wdbi_remove_by_pk, pk_value, test_netinfo.item_id);

    configure_wdb_netinfo_insert(test_netinfo, SQLITE_DONE);

    ret = wdb_netinfo_insert(data->wdb, test_netinfo.scan_id, test_netinfo.scan_time, test_netinfo.name, test_netinfo.adapter, test_netinfo.type,
                             test_netinfo._state, test_netinfo.mtu, test_netinfo.mac, test_netinfo.tx_packets, test_netinfo.rx_packets, test_netinfo.tx_bytes,
                             test_netinfo.rx_bytes, test_netinfo.tx_errors, test_netinfo.rx_errors, test_netinfo.tx_dropped, test_netinfo.rx_dropped, test_netinfo.checksum,
                             test_netinfo.item_id, test_netinfo.replace);

    assert_int_equal(ret, OS_SUCCESS);
}

static void test_wdb_netinfo_insert_negative_values_error(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;
    netinfo_object test_netinfo = netinfo;

    test_netinfo.mtu = OS_INVALID;
    test_netinfo.tx_packets = OS_INVALID;
    test_netinfo.rx_packets = OS_INVALID;
    test_netinfo.tx_bytes = OS_INVALID;
    test_netinfo.rx_bytes = OS_INVALID;
    test_netinfo.tx_errors = OS_INVALID;
    test_netinfo.rx_errors = OS_INVALID;
    test_netinfo.tx_dropped = OS_INVALID;
    test_netinfo.rx_dropped = OS_INVALID;

    configure_wdb_netinfo_insert(test_netinfo, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR_MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "SQLite: ERROR_MESSAGE");

    ret = wdb_netinfo_insert(data->wdb, test_netinfo.scan_id, test_netinfo.scan_time, test_netinfo.name, test_netinfo.adapter, test_netinfo.type,
                             test_netinfo._state, test_netinfo.mtu, test_netinfo.mac, test_netinfo.tx_packets, test_netinfo.rx_packets, test_netinfo.tx_bytes,
                             test_netinfo.rx_bytes, test_netinfo.tx_errors, test_netinfo.rx_errors, test_netinfo.tx_dropped, test_netinfo.rx_dropped, test_netinfo.checksum,
                             test_netinfo.item_id, test_netinfo.replace);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wdb_netinfo_insert_name_constraint_success(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;

    configure_wdb_netinfo_insert(netinfo, SQLITE_CONSTRAINT);

    will_return(__wrap_sqlite3_errmsg, "UNIQUE constraint failed");
    will_return(__wrap_sqlite3_errmsg, "UNIQUE constraint failed");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: UNIQUE constraint failed");


    ret = wdb_netinfo_insert(data->wdb, netinfo.scan_id, netinfo.scan_time, netinfo.name, netinfo.adapter, netinfo.type,
                             netinfo._state, netinfo.mtu, netinfo.mac, netinfo.tx_packets, netinfo.rx_packets, netinfo.tx_bytes,
                             netinfo.rx_bytes, netinfo.tx_errors, netinfo.rx_errors, netinfo.tx_dropped, netinfo.rx_dropped, netinfo.checksum,
                             netinfo.item_id, netinfo.replace);

    assert_int_equal(ret, OS_SUCCESS);
}

static void test_wdb_netinfo_insert_name_constraint_fail(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;

    configure_wdb_netinfo_insert(netinfo, SQLITE_CONSTRAINT);

    will_return(__wrap_sqlite3_errmsg, "ERROR_MESSAGE");
    will_return(__wrap_sqlite3_errmsg, "ERROR_MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "SQLite: ERROR_MESSAGE");


    ret = wdb_netinfo_insert(data->wdb, netinfo.scan_id, netinfo.scan_time, netinfo.name, netinfo.adapter, netinfo.type,
                             netinfo._state, netinfo.mtu, netinfo.mac, netinfo.tx_packets, netinfo.rx_packets, netinfo.tx_bytes,
                             netinfo.rx_bytes, netinfo.tx_errors, netinfo.rx_errors, netinfo.tx_dropped, netinfo.rx_dropped, netinfo.checksum,
                             netinfo.item_id, netinfo.replace);

    assert_int_equal(ret, OS_INVALID);
}

// Test wdb_netproto_save

static void test_wdb_netproto_save_transaction_fail(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, OS_INVALID);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_netproto_save(): cannot begin transaction");

    ret = wdb_netproto_save(data->wdb, netproto.scan_id, netproto.iface, netproto.type, netproto.gateway, netproto.dhcp,
                            netproto.metric, netproto.checksum, netproto.item_id, netproto.replace );

    assert_int_equal(ret, OS_INVALID);
}

static void test_wdb_netproto_save_success(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, OS_SUCCESS);
    configure_wdb_netproto_insert(netproto, SQLITE_DONE);

    ret = wdb_netproto_save(data->wdb, netproto.scan_id, netproto.iface, netproto.type, netproto.gateway, netproto.dhcp,
                            netproto.metric, netproto.checksum, netproto.item_id, netproto.replace );

    assert_int_equal(ret, OS_SUCCESS);
}

static void test_wdb_netproto_save_fail(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_begin2, OS_SUCCESS);
    //wdb_netproto_insert
    will_return(__wrap_wdb_stmt_cache, OS_INVALID);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_netproto_insert(): cannot cache statement");

    ret = wdb_netproto_save(data->wdb, netproto.scan_id, netproto.iface, netproto.type, netproto.gateway, netproto.dhcp,
                            netproto.metric, netproto.checksum, netproto.item_id, netproto.replace );

    assert_int_equal(ret, OS_INVALID);
}

// Test wdb_netproto_insert
static void test_wdb_netproto_insert_stmt_cache_fail(void **state) {
    int ret = OS_INVALID;

    will_return(__wrap_wdb_stmt_cache, OS_INVALID);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_netproto_insert(): cannot cache statement");

    ret = wdb_netproto_insert(NULL, netproto.scan_id, netproto.iface, netproto.type, netproto.gateway, netproto.dhcp,
                              netproto.metric, netproto.checksum, netproto.item_id, netproto.replace );

    assert_int_equal(ret, OS_INVALID);
}

static void test_wdb_netproto_insert_success(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;

    configure_wdb_netproto_insert(netproto, SQLITE_DONE);

    ret = wdb_netproto_insert(data->wdb, netproto.scan_id, netproto.iface, netproto.type, netproto.gateway, netproto.dhcp, netproto.metric,
                              netproto.checksum, netproto.item_id, netproto.replace);

    assert_int_equal(ret, OS_SUCCESS);
}

static void test_wdb_netproto_insert_iface_null(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;
    netproto_object test_netproto = netproto;
    test_netproto.iface = NULL;

    expect_value(__wrap_wdbi_remove_by_pk, component, WDB_SYSCOLLECTOR_NETPROTO);
    expect_value(__wrap_wdbi_remove_by_pk, pk_value, test_netproto.item_id);

    configure_wdb_netproto_insert(test_netproto, SQLITE_DONE);

    ret = wdb_netproto_insert(data->wdb, test_netproto.scan_id, test_netproto.iface, test_netproto.type, test_netproto.gateway, test_netproto.dhcp, test_netproto.metric,
                              test_netproto.checksum, test_netproto.item_id, test_netproto.replace);

    assert_int_equal(ret, OS_SUCCESS);
}

static void test_wdb_netproto_insert_negative_values_error(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;
    netproto_object test_netproto = netproto;
    test_netproto.type = 1;
    test_netproto.metric = OS_INVALID;

    will_return(__wrap_sqlite3_errmsg, "ERROR_MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "SQLite: ERROR_MESSAGE");

    configure_wdb_netproto_insert(test_netproto, SQLITE_ERROR);

    ret = wdb_netproto_insert(data->wdb, test_netproto.scan_id, test_netproto.iface, test_netproto.type, test_netproto.gateway, test_netproto.dhcp, test_netproto.metric,
                              test_netproto.checksum, test_netproto.item_id, test_netproto.replace);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wdb_netproto_insert_name_constraint_success(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;
    netproto_object test_netproto = netproto;

    configure_wdb_netproto_insert(test_netproto, SQLITE_CONSTRAINT);

    will_return(__wrap_sqlite3_errmsg, "UNIQUE constraint failed");
    will_return(__wrap_sqlite3_errmsg, "UNIQUE constraint failed");
    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: UNIQUE constraint failed");

    ret = wdb_netproto_insert(data->wdb, test_netproto.scan_id, test_netproto.iface, test_netproto.type, test_netproto.gateway, test_netproto.dhcp, test_netproto.metric,
                              test_netproto.checksum, test_netproto.item_id, test_netproto.replace);

    assert_int_equal(ret, OS_SUCCESS);
}

static void test_wdb_netproto_insert_name_constraint_fail(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;
    netproto_object test_netproto = netproto;

    configure_wdb_netproto_insert(test_netproto, SQLITE_CONSTRAINT);

    will_return(__wrap_sqlite3_errmsg, "ERROR_MESSAGE");
    will_return(__wrap_sqlite3_errmsg, "ERROR_MESSAGE");
    expect_string(__wrap__merror, formatted_msg, "SQLite: ERROR_MESSAGE");

    ret = wdb_netproto_insert(data->wdb, test_netproto.scan_id, test_netproto.iface, test_netproto.type, test_netproto.gateway, test_netproto.dhcp, test_netproto.metric,
                              test_netproto.checksum, test_netproto.item_id, test_netproto.replace);

    assert_int_equal(ret, OS_INVALID);
}

// Test wdb_netaddr_insert
static void test_wdb_netaddr_insert_stmt_cache_fail(void **state) {
    int ret = OS_INVALID;

    will_return(__wrap_wdb_stmt_cache, OS_INVALID);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_netaddr_insert(): cannot cache statement");

    ret = wdb_netaddr_insert(NULL, netaddr.scan_id, netaddr.iface, netaddr.proto, netaddr.address, netaddr.netmask,
                             netaddr.broadcast, netaddr.checksum, netaddr.item_id, netaddr.replace );

    assert_int_equal(ret, OS_INVALID);
}

static void test_wdb_netaddr_insert_success(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;

    configure_wdb_netaddr_insert(netaddr, SQLITE_DONE);

    ret = wdb_netaddr_insert(data->wdb, netaddr.scan_id, netaddr.iface, netaddr.proto, netaddr.address, netaddr.netmask,
                             netaddr.broadcast, netaddr.checksum, netaddr.item_id, netaddr.replace );

    assert_int_equal(ret, OS_SUCCESS);
}

static void test_wdb_netaddr_insert_null_values_success(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;
    netaddr_object test_netaddr = netaddr;
    test_netaddr.iface = NULL;
    test_netaddr.address = NULL;

    expect_value(__wrap_wdbi_remove_by_pk, component, WDB_SYSCOLLECTOR_NETADDRESS);
    expect_value(__wrap_wdbi_remove_by_pk, pk_value, test_netaddr.item_id);

    configure_wdb_netaddr_insert(test_netaddr, SQLITE_DONE);

    ret = wdb_netaddr_insert(data->wdb, test_netaddr.scan_id, test_netaddr.iface, test_netaddr.proto, test_netaddr.address, test_netaddr.netmask,
                             test_netaddr.broadcast, test_netaddr.checksum, test_netaddr.item_id, test_netaddr.replace );

    assert_int_equal(ret, OS_SUCCESS);
}

// Test wdb_osinfo_insert
static void test_wdb_osinfo_insert_stmt_cache_fail(void **state) {
    int ret = OS_INVALID;

    will_return(__wrap_wdb_stmt_cache, OS_INVALID);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_osinfo_insert(): cannot cache statement");

    ret = wdb_osinfo_insert(NULL, osinfo.scan_id, osinfo.scan_time, osinfo.hostname, osinfo.architecture, osinfo.os_name,
                            osinfo.os_version, osinfo.os_codename, osinfo.os_major, osinfo.os_minor, osinfo.os_patch, osinfo.os_build,
                            osinfo.os_platform, osinfo.sysname, osinfo.release, osinfo.version, osinfo.os_release, osinfo.os_display_version,
                            osinfo.checksum, osinfo.replace, osinfo.reference);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wdb_osinfo_insert_success(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;

    configure_wdb_osinfo_insert(osinfo, SQLITE_DONE);

    ret = wdb_osinfo_insert(data->wdb, osinfo.scan_id, osinfo.scan_time, osinfo.hostname, osinfo.architecture, osinfo.os_name,
                            osinfo.os_version, osinfo.os_codename, osinfo.os_major, osinfo.os_minor, osinfo.os_patch, osinfo.os_build,
                            osinfo.os_platform, osinfo.sysname, osinfo.release, osinfo.version, osinfo.os_release, osinfo.os_display_version,
                            osinfo.checksum, osinfo.replace, osinfo.reference);

    assert_int_equal(ret, OS_SUCCESS);
}

static void test_wdb_osinfo_insert_step_error(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;

    configure_wdb_osinfo_insert(osinfo, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR");
    expect_string(__wrap__merror, formatted_msg, "SQLite: ERROR");

    ret = wdb_osinfo_insert(data->wdb, osinfo.scan_id, osinfo.scan_time, osinfo.hostname, osinfo.architecture, osinfo.os_name,
                            osinfo.os_version, osinfo.os_codename, osinfo.os_major, osinfo.os_minor, osinfo.os_patch, osinfo.os_build,
                            osinfo.os_platform, osinfo.sysname, osinfo.release, osinfo.version, osinfo.os_release, osinfo.os_display_version,
                            osinfo.checksum, osinfo.replace, osinfo.reference);

    assert_int_equal(ret, OS_INVALID);
}

// Test wdb_package_insert
static void test_wdb_package_insert_stmt_cache_fail(void **state) {
    int ret = OS_INVALID;

    will_return(__wrap_wdb_stmt_cache, OS_INVALID);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_package_insert(): cannot cache statement");

    ret = wdb_package_insert(NULL, package.scan_id, package.scan_time, package.format, package.name, package.priority, package.section,
                             package.size, package.vendor, package.install_time, package.version, package.architecture, package.multiarch,
                             package.source, package.description, package.location, package.checksum, package.item_id,
                             package.replace);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wdb_package_insert_success(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;

    configure_wdb_package_insert(package, SQLITE_DONE);

    ret = wdb_package_insert(data->wdb, package.scan_id, package.scan_time, package.format, package.name, package.priority, package.section,
                             package.size, package.vendor, package.install_time, package.version, package.architecture, package.multiarch,
                             package.source, package.description, package.location, package.checksum, package.item_id,
                             package.replace);

    assert_int_equal(ret, OS_SUCCESS);
}

static void test_wdb_package_insert_step_error(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;

    configure_wdb_package_insert(package, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR");
    expect_string(__wrap__merror, formatted_msg, "SQLite: ERROR");

    ret = wdb_package_insert(data->wdb, package.scan_id, package.scan_time, package.format, package.name, package.priority, package.section,
                             package.size, package.vendor, package.install_time, package.version, package.architecture, package.multiarch,
                             package.source, package.description, package.location, package.checksum, package.item_id,
                             package.replace);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wdb_package_insert_architecture_null(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data = (test_struct_t *)*state;
    package_object temp_package = package;
    temp_package.architecture = NULL;

    expect_value(__wrap_wdbi_remove_by_pk, component, WDB_SYSCOLLECTOR_PACKAGES);
    expect_value(__wrap_wdbi_remove_by_pk, pk_value, package.item_id);

    configure_wdb_package_insert(temp_package, SQLITE_DONE);

    ret = wdb_package_insert(data->wdb, temp_package.scan_id, temp_package.scan_time, temp_package.format, temp_package.name, temp_package.priority, temp_package.section,
                             temp_package.size, temp_package.vendor, temp_package.install_time, temp_package.version, temp_package.architecture, temp_package.multiarch,
                             temp_package.source, temp_package.description, temp_package.location, temp_package.checksum, temp_package.item_id,
                             temp_package.replace);

    assert_int_equal(ret, OS_SUCCESS);
}

static void test_wdb_package_insert_size_negative_value(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data = (test_struct_t *)*state;
    package_object temp_package = package;
    temp_package.size = -1;

    configure_wdb_package_insert(temp_package, SQLITE_DONE);

    ret = wdb_package_insert(data->wdb, temp_package.scan_id, temp_package.scan_time, temp_package.format, temp_package.name, temp_package.priority, temp_package.section,
                             temp_package.size, temp_package.vendor, temp_package.install_time, temp_package.version, temp_package.architecture, temp_package.multiarch,
                             temp_package.source, temp_package.description, temp_package.location, temp_package.checksum, temp_package.item_id,
                             temp_package.replace);

    assert_int_equal(ret, OS_SUCCESS);
}

static void test_wdb_package_insert_constraint_success(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data = (test_struct_t *)*state;

    configure_wdb_package_insert(package, SQLITE_CONSTRAINT);

    will_return(__wrap_sqlite3_errmsg, "UNIQUE constraint failed");
    will_return(__wrap_sqlite3_errmsg, "UNIQUE constraint failed");

    expect_string(__wrap__mdebug1, formatted_msg, "SQLite: UNIQUE constraint failed");

    ret = wdb_package_insert(data->wdb, package.scan_id, package.scan_time, package.format, package.name, package.priority, package.section,
                             package.size, package.vendor, package.install_time, package.version, package.architecture, package.multiarch,
                             package.source, package.description, package.location, package.checksum, package.item_id,
                             package.replace);

    assert_int_equal(ret, OS_SUCCESS);
}

static void test_wdb_package_insert_constraint_fail(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data = (test_struct_t *)*state;

    configure_wdb_package_insert(package, SQLITE_CONSTRAINT);

    will_return(__wrap_sqlite3_errmsg, "ERROR");
    will_return(__wrap_sqlite3_errmsg, "ERROR");
    expect_string(__wrap__merror, formatted_msg, "SQLite: ERROR");

    ret = wdb_package_insert(data->wdb, package.scan_id, package.scan_time, package.format, package.name, package.priority, package.section,
                            package.size, package.vendor, package.install_time, package.version, package.architecture, package.multiarch,
                            package.source, package.description, package.location, package.checksum, package.item_id,
                            package.replace);

    assert_int_equal(ret, OS_INVALID);
}

// Test wdb_hotfix_insert
static void test_wdb_hotfix_insert_stmt_cache_fail(void **state) {
    int ret = OS_INVALID;

    will_return(__wrap_wdb_stmt_cache, OS_INVALID);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_hotfix_insert(): cannot cache statement");

    ret = wdb_hotfix_insert(NULL, hotfix.scan_id, hotfix.scan_time, hotfix.hotfix, hotfix.checksum, hotfix.replace);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wdb_hotfix_insert_hotfix_null(void **state) {
    int ret = OS_INVALID;
    hotfix_object temp_hotfix = hotfix;
    temp_hotfix.hotfix = NULL;

    ret = wdb_hotfix_insert(NULL, temp_hotfix.scan_id, temp_hotfix.scan_time, temp_hotfix.hotfix, temp_hotfix.checksum, temp_hotfix.replace);

    assert_int_equal(ret, OS_INVALID);

}

static void test_wdb_hotfix_insert_success(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;

    configure_wdb_hotfix_insert(hotfix, SQLITE_DONE);

    ret = wdb_hotfix_insert(data->wdb, hotfix.scan_id, hotfix.scan_time, hotfix.hotfix, hotfix.checksum, hotfix.replace);

    assert_int_equal(ret, OS_SUCCESS);
}

static void test_wdb_hotfix_insert_step_error(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;

    configure_wdb_hotfix_insert(hotfix, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR");
    expect_string(__wrap__merror, formatted_msg, "SQLite: ERROR");

    ret = wdb_hotfix_insert(data->wdb, hotfix.scan_id, hotfix.scan_time, hotfix.hotfix, hotfix.checksum, hotfix.replace);

    assert_int_equal(ret, OS_INVALID);
}

// Test wdb_hardware_insert
static void test_wdb_hardware_insert_stmt_cache_fail(void **state) {
    int ret = OS_INVALID;

    will_return(__wrap_wdb_stmt_cache, OS_INVALID);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_hardware_insert(): cannot cache statement");

    ret = wdb_hardware_insert(NULL, hardware.scan_id, hardware.scan_time, hardware.serial, hardware.cpu_name, hardware.cpu_cores,
                              hardware.cpu_mhz, hardware.ram_total, hardware.ram_free, hardware.ram_usage, hardware.checksum, hardware.replace);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wdb_hardware_insert_success(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;

    configure_wdb_hardware_insert(hardware, SQLITE_DONE);

    ret = wdb_hardware_insert(data->wdb, hardware.scan_id, hardware.scan_time, hardware.serial, hardware.cpu_name, hardware.cpu_cores,
                              hardware.cpu_mhz, hardware.ram_total, hardware.ram_free, hardware.ram_usage, hardware.checksum, hardware.replace);

    assert_int_equal(ret, OS_SUCCESS);
}

static void test_wdb_hardware_insert_step_error(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;

    configure_wdb_hardware_insert(hardware, SQLITE_ERROR);

    will_return(__wrap_sqlite3_errmsg, "ERROR");
    expect_string(__wrap__merror, formatted_msg, "SQLite: ERROR");

    ret = wdb_hardware_insert(data->wdb, hardware.scan_id, hardware.scan_time, hardware.serial, hardware.cpu_name, hardware.cpu_cores,
                              hardware.cpu_mhz, hardware.ram_total, hardware.ram_free, hardware.ram_usage, hardware.checksum, hardware.replace);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wdb_hardware_insert_success_null_values(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data = (test_struct_t *)*state;
    hardware_object temp_hardware = hardware;
    temp_hardware.cpu_cores = -1;
    temp_hardware.cpu_mhz = -1;
    temp_hardware.ram_usage = 101;
    temp_hardware.ram_total = 0;
    temp_hardware.ram_free = 0;

    configure_wdb_hardware_insert(temp_hardware, SQLITE_DONE);

    ret = wdb_hardware_insert(data->wdb, temp_hardware.scan_id, temp_hardware.scan_time, temp_hardware.serial, temp_hardware.cpu_name,
                              temp_hardware.cpu_cores, temp_hardware.cpu_mhz, temp_hardware.ram_total, temp_hardware.ram_free, temp_hardware.ram_usage,
                              temp_hardware.checksum, temp_hardware.replace);

    assert_int_equal(ret, OS_SUCCESS);
}

// Test wdb_port_insert
static void test_wdb_port_insert_stmt_cache_fail(void **state) {
    int ret = OS_INVALID;

    will_return(__wrap_wdb_stmt_cache, OS_INVALID);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_port_insert(): cannot cache statement");

    ret = wdb_port_insert(NULL, port.scan_id, port.scan_time, port.protocol, port.local_ip, port.local_port, port.remote_ip, port.remote_port,
                          port.tx_queue, port.rx_queue, port.inode, port.state, port.pid, port.process, port.checksum, port.item_id, port.replace);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wdb_port_insert_success(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;

    configure_wdb_port_insert(port, SQLITE_DONE);

    ret = wdb_port_insert(data->wdb, port.scan_id, port.scan_time, port.protocol, port.local_ip, port.local_port, port.remote_ip, port.remote_port,
                          port.tx_queue, port.rx_queue, port.inode, port.state, port.pid, port.process, port.checksum, port.item_id, port.replace);

    assert_int_equal(ret, OS_SUCCESS);
}

static void test_wdb_port_insert_null_values_success(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;
    port_object test_port = port;
    test_port.protocol = NULL;
    test_port.local_ip = NULL;
    test_port.local_port = OS_INVALID;
    test_port.inode = OS_INVALID;

    configure_wdb_port_insert(test_port, SQLITE_DONE);

    expect_value(__wrap_wdbi_remove_by_pk, component, WDB_SYSCOLLECTOR_PORTS);
    expect_value(__wrap_wdbi_remove_by_pk, pk_value, test_port.item_id);

    ret = wdb_port_insert(data->wdb, test_port.scan_id, test_port.scan_time, test_port.protocol, test_port.local_ip, test_port.local_port, test_port.remote_ip, test_port.remote_port,
                          test_port.tx_queue, test_port.rx_queue, test_port.inode, test_port.state, test_port.pid, test_port.process, test_port.checksum, test_port.item_id, test_port.replace);

    assert_int_equal(ret, OS_SUCCESS);
}

// Test wdb_process_insert
static void test_wdb_process_insert_stmt_cache_fail(void **state) {
    int ret = OS_INVALID;

    will_return(__wrap_wdb_stmt_cache, OS_INVALID);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_process_insert(): cannot cache statement");

    ret = wdb_process_insert(NULL, process.scan_id, process.scan_time, process.pid, process.name, process.state, process.ppid, process.utime,
                             process.stime, process.cmd, process.argvs, process.euser, process.ruser, process.suser, process.egroup, process.rgroup,
                             process.sgroup, process.fgroup, process.priority, process.nice, process.size, process.vm_size, process.resident,
                             process.share, process.start_time, process.pgrp, process.session, process.nlwp, process.tgid, process.tty, process.processor,
                             process.checksum, process.replace);

    assert_int_equal(ret, OS_INVALID);
}

static void test_wdb_process_insert_success(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;

    configure_wdb_process_insert(process, SQLITE_DONE);

    ret = wdb_process_insert(data->wdb, process.scan_id, process.scan_time, process.pid, process.name, process.state, process.ppid, process.utime,
                             process.stime, process.cmd, process.argvs, process.euser, process.ruser, process.suser, process.egroup, process.rgroup,
                             process.sgroup, process.fgroup, process.priority, process.nice, process.size, process.vm_size, process.resident,
                             process.share, process.start_time, process.pgrp, process.session, process.nlwp, process.tgid, process.tty, process.processor,
                             process.checksum, process.replace);

    assert_int_equal(ret, OS_SUCCESS);
}

static void test_wdb_process_insert_null_values_fail(void **state) {
    int ret = OS_INVALID;
    test_struct_t *data  = (test_struct_t *)*state;
    process_object test_process = process;
    test_process.pid = OS_INVALID;

    ret = wdb_process_insert(data->wdb, test_process.scan_id, test_process.scan_time, test_process.pid, test_process.name, test_process.state, test_process.ppid, test_process.utime,
                             test_process.stime, test_process.cmd, test_process.argvs, test_process.euser, test_process.ruser, test_process.suser, test_process.egroup, test_process.rgroup,
                             test_process.sgroup, test_process.fgroup, test_process.priority, test_process.nice, test_process.size, test_process.vm_size, test_process.resident,
                             test_process.share, test_process.start_time, test_process.pgrp, test_process.session, test_process.nlwp, test_process.tgid, test_process.tty, test_process.processor,
                             test_process.checksum, test_process.replace);

    assert_int_equal(ret, OS_INVALID);
}

// Main

int main() {

    const struct CMUnitTest tests[] = {
        /* Tests wdb_netinfo_save */
        cmocka_unit_test_setup_teardown(test_wdb_netinfo_save_insertion_fail, test_setup, test_teardown),
        /* Tests wdb_netinfo_insert */
        cmocka_unit_test_setup_teardown(test_wdb_netinfo_insert_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_netinfo_insert_default_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_netinfo_insert_sql_constraint_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_netinfo_insert_sql_constraint_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_netinfo_insert_sql_success, test_setup, test_teardown),
        /* Test wdb_netproto_insert */
        cmocka_unit_test_setup_teardown(test_wdb_netproto_insert_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_netproto_insert_default_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_netproto_insert_sql_constraint_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_netproto_insert_sql_constraint_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_netproto_insert_sql_success, test_setup, test_teardown),
        /* Test wdb_netaddr_save */
        cmocka_unit_test_setup_teardown(test_wdb_netaddr_save_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_netaddr_save_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_netaddr_save_success, test_setup, test_teardown),
        /* Test wdb_netaddr_insert */
        cmocka_unit_test_setup_teardown(test_wdb_netaddr_insert_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_netaddr_insert_fail, test_setup, test_teardown),
        /* Test wdb_netinfo_delete */
        cmocka_unit_test_setup_teardown(test_wdb_netinfo_delete_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_netinfo_delete_sys_netiface_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_netinfo_delete_sys_netiface_sql_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_netinfo_delete_sys_netproto_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_netinfo_delete_sys_netproto_sql_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_netinfo_delete_sys_netaddr_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_netinfo_delete_sys_netaddr_sql_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_netinfo_delete_success, test_setup, test_teardown),
        /* Test wdb_hotfix_delete */
        cmocka_unit_test_setup_teardown(test_wdb_hotfix_delete_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_hotfix_delete_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_hotfix_delete_sql_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_hotfix_delete_success, test_setup, test_teardown),
        /* Test wdb_osinfo_save */
        cmocka_unit_test_setup_teardown(test_wdb_osinfo_save_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_osinfo_save_retrieve_osinfo_type_reference_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_osinfo_save_retrieve_osinfo_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_osinfo_save_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_osinfo_save_sql_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_osinfo_save_insert_fail, test_setup, test_teardown),
        /* Test wdb_osinfo_insert */
        cmocka_unit_test_setup_teardown(test_wdb_osinfo_insert_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_osinfo_insert_sql_fail, test_setup, test_teardown),
        /* Test wdb_package_save */
        cmocka_unit_test_setup_teardown(test_wdb_package_save_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_package_save_insert_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_package_save_success, test_setup, test_teardown),
        /* Test wdb_package_insert */
        cmocka_unit_test_setup_teardown(test_wdb_package_insert_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_package_insert_default_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_package_insert_sql_constraint_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_package_insert_sql_constraint_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_package_insert_sql_success, test_setup, test_teardown),
        /* Test wdb_hotfix_save */
        cmocka_unit_test_setup_teardown(test_wdb_hotfix_save_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_hotfix_save_insert_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_hotfix_save_success, test_setup, test_teardown),
        /* Test wdb_package_update */
        cmocka_unit_test_setup_teardown(test_wdb_package_update_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_package_update_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_package_update_sql_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_package_update_loop_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_package_update_loop_sql_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_package_update_success, test_setup, test_teardown),
        /* Test wdb_package_delete */
        cmocka_unit_test_setup_teardown(test_wdb_package_delete_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_package_delete_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_package_delete_sql_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_package_delete_success, test_setup, test_teardown),
        /* Test wdb_hardware_save */
        cmocka_unit_test_setup_teardown(test_wdb_hardware_save_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_hardware_save_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_hardware_save_sql_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_hardware_save_insert_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_hardware_save_success, test_setup, test_teardown),
        /* Test wdb_hardware_insert */
        cmocka_unit_test_setup_teardown(test_wdb_hardware_insert_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_hardware_insert_sql_fail, test_setup, test_teardown),
        /* Test wdb_port_save */
        cmocka_unit_test_setup_teardown(test_wdb_port_save_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_port_save_insert_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_port_save_success, test_setup, test_teardown),
        /* Test wdb_port_insert */
        cmocka_unit_test_setup_teardown(test_wdb_port_insert_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_port_insert_sql_fail, test_setup, test_teardown),
        /* Test wdb_port_delete */
        cmocka_unit_test_setup_teardown(test_wdb_port_delete_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_port_delete_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_port_delete_sql_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_port_delete_success, test_setup, test_teardown),
        /* Test wdb_process_save */
        cmocka_unit_test_setup_teardown(test_wdb_process_save_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_process_save_insert_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_process_save_success, test_setup, test_teardown),
        /* Test wdb_process_insert */
        cmocka_unit_test_setup_teardown(test_wdb_process_insert_sql_fail, test_setup, test_teardown),
        /* Test wdb_process_delete */
        cmocka_unit_test_setup_teardown(test_wdb_process_delete_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_process_delete_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_process_delete_sql_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_process_delete_success, test_setup, test_teardown),
        /* Test wdb_users_insert */
        cmocka_unit_test_setup_teardown(test_wdb_users_insert_sql_fail, test_setup, test_teardown),
        /* Test wdb_users_save */
        cmocka_unit_test_setup_teardown(test_wdb_users_save_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_users_save_insert_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_users_save_success, test_setup, test_teardown),
        /* Test wdb_groups_insert */
        cmocka_unit_test_setup_teardown(test_wdb_groups_insert_sql_fail, test_setup, test_teardown),
        /* Test wdb_groups_save */
        cmocka_unit_test_setup_teardown(test_wdb_groups_save_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_groups_save_insert_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_groups_save_success, test_setup, test_teardown),
        /* Test wdb_syscollector_save2 */
        cmocka_unit_test_setup_teardown(test_wdb_syscollector_save2_parser_json_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_syscollector_save2_get_attributes_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_syscollector_save2_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_syscollector_save2_processes_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_syscollector_save2_processes_fail_2, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_syscollector_save2_processes_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_syscollector_save2_package_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_syscollector_save2_package_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_syscollector_save2_hotfix_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_syscollector_save2_hotfix_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_syscollector_save2_port_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_syscollector_save2_port_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_syscollector_save2_netproto_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_syscollector_save2_netproto_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_syscollector_save2_netaddr_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_syscollector_save2_netaddr_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_syscollector_save2_netinfo_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_syscollector_save2_netinfo_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_syscollector_save2_hwinfo_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_syscollector_save2_hwinfo_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_syscollector_save2_osinfo_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_syscollector_save2_osinfo_success, test_setup, test_teardown),
        // Test wdb_netinfo_save
        cmocka_unit_test_setup_teardown(test_wdb_netinfo_save_transaction_fail, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_netinfo_save_success, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_netinfo_save_fail, setup_wdb, teardown_wdb),
        // Test wdb_netinfo_insert
        cmocka_unit_test(test_wdb_netinfo_insert_stmt_cache_fail),
        cmocka_unit_test_setup_teardown(test_wdb_netinfo_insert_name_null_success, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_netinfo_insert_success, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_netinfo_insert_negative_values_error, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_netinfo_insert_name_constraint_success, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_netinfo_insert_name_constraint_fail, setup_wdb, teardown_wdb),
        // Test wdb_netproto_save
        cmocka_unit_test_setup_teardown(test_wdb_netproto_save_transaction_fail, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_netproto_save_success, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_netproto_save_fail, setup_wdb, teardown_wdb),
        // Test wdb_netproto_insert
        cmocka_unit_test(test_wdb_netproto_insert_stmt_cache_fail),
        cmocka_unit_test_setup_teardown(test_wdb_netproto_insert_success, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_netproto_insert_iface_null, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_netproto_insert_negative_values_error, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_netproto_insert_name_constraint_success, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_netproto_insert_name_constraint_fail, setup_wdb, teardown_wdb),
        // Test wdb_netaddr_insert
        cmocka_unit_test(test_wdb_netaddr_insert_stmt_cache_fail),
        cmocka_unit_test_setup_teardown(test_wdb_netaddr_insert_success, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_netaddr_insert_null_values_success, setup_wdb, teardown_wdb),
        // Test wdb_osinfo_insert
        cmocka_unit_test(test_wdb_osinfo_insert_stmt_cache_fail),
        cmocka_unit_test_setup_teardown(test_wdb_osinfo_insert_success, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_osinfo_insert_step_error, setup_wdb, teardown_wdb),
        // Test wdb_package_insert
        cmocka_unit_test(test_wdb_package_insert_stmt_cache_fail),
        cmocka_unit_test_setup_teardown(test_wdb_package_insert_success, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_package_insert_step_error, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_package_insert_architecture_null, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_package_insert_size_negative_value, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_package_insert_constraint_success, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_package_insert_constraint_fail, setup_wdb, teardown_wdb),
        // Test wdb_hotfix_insert
        cmocka_unit_test(test_wdb_hotfix_insert_stmt_cache_fail),
        cmocka_unit_test(test_wdb_hotfix_insert_hotfix_null),
        cmocka_unit_test_setup_teardown(test_wdb_hotfix_insert_success, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_hotfix_insert_step_error, setup_wdb, teardown_wdb),
        // Test wdb_hardware_insert
        cmocka_unit_test(test_wdb_hardware_insert_stmt_cache_fail),
        cmocka_unit_test_setup_teardown(test_wdb_hardware_insert_success, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_hardware_insert_step_error, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_hardware_insert_success_null_values, setup_wdb, teardown_wdb),
        // Test wdb_port_insert
        cmocka_unit_test(test_wdb_port_insert_stmt_cache_fail),
        cmocka_unit_test_setup_teardown(test_wdb_port_insert_success, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_port_insert_null_values_success, setup_wdb, teardown_wdb),
        // Test wdb_process_insert
        cmocka_unit_test(test_wdb_process_insert_stmt_cache_fail),
        cmocka_unit_test_setup_teardown(test_wdb_process_insert_success, setup_wdb, teardown_wdb),
        cmocka_unit_test_setup_teardown(test_wdb_process_insert_null_values_fail, setup_wdb, teardown_wdb)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
