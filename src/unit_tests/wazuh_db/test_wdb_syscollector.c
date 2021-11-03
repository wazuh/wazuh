
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include "wazuh_db/wdb.h"
#include "external/sqlite/sqlite3.h"
#include "../wrappers/wazuh/wazuh_db/wdb_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/externals/sqlite/sqlite3_wrappers.h"
#include "../wrappers/externals/cJSON/cJSON_wrappers.h"

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

static void wdb_syscollector_processes_save2_fail(void) {
    int i = 0;

    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetStringValue, "scan_time");
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

static void  wdb_syscollector_processes_save2_success(cJSON *attribute) {
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
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 24);
    expect_value(__wrap_sqlite3_bind_int, value, 123);
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
    expect_sqlite3_step_call(SQLITE_DONE);
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
    expect_value(__wrap_sqlite3_bind_int, index, 16);
    expect_value(__wrap_sqlite3_bind_int, value, 0);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 17);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 18);
    expect_string(__wrap_sqlite3_bind_text, buffer, "item_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_sqlite3_step_call(SQLITE_DONE);
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
    expect_sqlite3_step_call(SQLITE_DONE);
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
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 10);
    expect_value(__wrap_sqlite3_bind_int, value, 541);
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
    expect_sqlite3_step_call(SQLITE_DONE);
}

static void wdb_syscollector_netproto_save2_fail(void) {
    int i = 0;

    for (i = 0; i < 7;i++) {
        will_return(__wrap_cJSON_GetObjectItem, NULL);
    }

    will_return(__wrap_cJSON_GetStringValue, "iface");
    will_return(__wrap_cJSON_GetStringValue, "gateway");
    will_return(__wrap_cJSON_GetStringValue, "dhcp");
    will_return(__wrap_cJSON_GetStringValue, "checksum");
    will_return(__wrap_cJSON_GetStringValue, "item_id");

    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_netproto_save(): cannot begin transaction");
}

static void wdb_syscollector_netproto_save2_success(cJSON *attribute) {
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetObjectItem, 1);
    will_return(__wrap_cJSON_GetObjectItem, attribute);
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetObjectItem, 1);
    will_return(__wrap_cJSON_GetObjectItem, attribute);
    will_return(__wrap_cJSON_GetObjectItem, NULL);
    will_return(__wrap_cJSON_GetObjectItem, NULL);

    will_return(__wrap_cJSON_GetStringValue, "iface");
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
    expect_sqlite3_step_call(SQLITE_DONE);
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

    expect_sqlite3_step_call(SQLITE_DONE);

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
    expect_sqlite3_step_call(SQLITE_DONE);
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
    expect_sqlite3_step_call(SQLITE_DONE);

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
    expect_sqlite3_step_call(SQLITE_DONE);
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

static void wdb_syscollector_osinfo_save2_success(void) {
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

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_sqlite3_step_call(SQLITE_DONE);
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
    expect_sqlite3_step_call(SQLITE_DONE);
}


/* Tests wdb_netinfo_save */
void test_wdb_netinfo_save_transaction_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 0;
    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_netinfo_save(): cannot begin transaction");

    output = wdb_netinfo_save(data, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, 0, 0, 0, 0, 0, 0, 0, 0, NULL, NULL, false);
    assert_int_equal(output, -1);
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

void test_wdb_netinfo_save_success(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 1;

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

    expect_value(__wrap_sqlite3_bind_null, index, 7);
    will_return(__wrap_sqlite3_bind_null, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_string(__wrap_sqlite3_bind_text, buffer, "mac");
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_value(__wrap_sqlite3_bind_null, index, 9);
    will_return(__wrap_sqlite3_bind_null, 0);
    expect_value(__wrap_sqlite3_bind_null, index, 10);
    will_return(__wrap_sqlite3_bind_null, 0);
    expect_value(__wrap_sqlite3_bind_null, index, 11);
    will_return(__wrap_sqlite3_bind_null, 0);
    expect_value(__wrap_sqlite3_bind_null, index, 12);
    will_return(__wrap_sqlite3_bind_null, 0);
    expect_value(__wrap_sqlite3_bind_null, index, 13);
    will_return(__wrap_sqlite3_bind_null, 0);
    expect_value(__wrap_sqlite3_bind_null, index, 14);
    will_return(__wrap_sqlite3_bind_null, 0);
    expect_value(__wrap_sqlite3_bind_null, index, 15);
    will_return(__wrap_sqlite3_bind_null, 0);
    expect_value(__wrap_sqlite3_bind_null, index, 16);
    will_return(__wrap_sqlite3_bind_null, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 17);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 18);
    expect_string(__wrap_sqlite3_bind_text, buffer, "item_id");
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_sqlite3_step_call(SQLITE_DONE);

    output = wdb_netinfo_save(data, "scan_id", "scan_time", "name", "adapter", "type", "state", 0, "mac", -1, -1, -1, -1, -1, -1, -1, -1, "checksum", "item_id", true);
    assert_int_equal(output, 0);
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

    expect_sqlite3_step_call(1);
    will_return(__wrap_sqlite3_errmsg, "ERROR");
    expect_string(__wrap__merror, formatted_msg, "at wdb_package_insert(): sqlite3_step(): ERROR");

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

    expect_sqlite3_step_call(SQLITE_CONSTRAINT);
    will_return(__wrap_sqlite3_errmsg, "DUPLICATE");
    will_return(__wrap_sqlite3_errmsg, "DUPLICATE");
    expect_string(__wrap__merror, formatted_msg, "at wdb_package_insert(): sqlite3_step(): DUPLICATE");

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

    expect_sqlite3_step_call(SQLITE_CONSTRAINT);
    will_return(__wrap_sqlite3_errmsg, "UNIQUE");
    will_return(__wrap_sqlite3_errmsg, "UNIQUE");
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_package_insert(): sqlite3_step(): UNIQUE");
    //expect_string(__wrap__merror, formatted_msg, "at wdb_package_insert(): sqlite3_step(): UNIQUE");

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

    expect_sqlite3_step_call(SQLITE_DONE);

    output = wdb_netinfo_insert(data, "scan_id", "scan_time", "name", "adapter", "type", "state", 1, "mac", 2, 3, 4, 5, 6, 7, 8, 9, "checksum", "item_id", false);
    assert_int_equal(output, 0);
}

/* Test wdb_netproto_save */
void test_wdb_netproto_save_transaction_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 0;
    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_netproto_save(): cannot begin transaction");

    output = wdb_netproto_save(data, NULL, NULL, 0, NULL, NULL, 0, NULL, NULL, false);
    assert_int_equal(output, -1);
}

void test_wdb_netproto_save_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 1;
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_netproto_insert(): cannot cache statement");

    output = wdb_netproto_save(data, NULL, NULL, 0, NULL, NULL, 0, NULL, NULL, false);
    assert_int_equal(output, -1);
}

void test_wdb_netproto_save_success(void **state) {
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
    expect_string(__wrap_sqlite3_bind_text, buffer, "gateway");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_string(__wrap_sqlite3_bind_text, buffer, "dhcp");
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_value(__wrap_sqlite3_bind_null, index, 6);
    will_return(__wrap_sqlite3_bind_null, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_string(__wrap_sqlite3_bind_text, buffer, "item_id");
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_sqlite3_step_call(SQLITE_DONE);

    output = wdb_netproto_save(data, "scan_id", "iface", 1, "gateway", "dhcp", -1, "checksum", "item_id", true);
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

    expect_sqlite3_step_call(1);
    will_return(__wrap_sqlite3_errmsg, "ERROR");
    expect_string(__wrap__merror, formatted_msg, "at wdb_netproto_insert(): sqlite3_step(): ERROR");

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

    expect_sqlite3_step_call(SQLITE_CONSTRAINT);
    will_return(__wrap_sqlite3_errmsg, "DUPLICATED");
    will_return(__wrap_sqlite3_errmsg, "DUPLICATED");
    expect_string(__wrap__merror, formatted_msg, "at wdb_netproto_insert(): sqlite3_step(): DUPLICATED");

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

    expect_sqlite3_step_call(SQLITE_CONSTRAINT);
    will_return(__wrap_sqlite3_errmsg, "UNIQUE");
    will_return(__wrap_sqlite3_errmsg, "UNIQUE");
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_netproto_insert(): sqlite3_step(): UNIQUE");

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

    expect_sqlite3_step_call(SQLITE_DONE);

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

    expect_sqlite3_step_call(SQLITE_DONE);

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

    expect_sqlite3_step_call(1);
    will_return(__wrap_sqlite3_errmsg, "ERROR");
    expect_string(__wrap__merror, formatted_msg, "at wdb_netaddr_insert(): sqlite3_step(): ERROR");

    output = wdb_netaddr_insert(data, "scan_id", "iface", WDB_NETADDR_IPV4, "address", "netmask", "broadcast", "checksum", "item_id", false);
    assert_int_equal(output, -1);
}

void test_wdb_netaddr_insert_success(void **state) {
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

    expect_sqlite3_step_call(SQLITE_DONE);

    output = wdb_netaddr_insert(data, "scan_id", "iface", WDB_NETADDR_IPV4, "address", "netmask", "broadcast", "checksum", "item_id", false);
    assert_int_equal(output, 0);
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
    expect_sqlite3_step_call(1);
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
    expect_sqlite3_step_call(SQLITE_DONE);
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
    expect_sqlite3_step_call(SQLITE_DONE);


    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_sqlite3_step_call(1);
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
    expect_sqlite3_step_call(SQLITE_DONE);


    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_sqlite3_step_call(SQLITE_DONE);

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
    expect_sqlite3_step_call(SQLITE_DONE);


    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_sqlite3_step_call(SQLITE_DONE);

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_sqlite3_step_call(1);
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
    expect_sqlite3_step_call(SQLITE_DONE);


    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_sqlite3_step_call(SQLITE_DONE);

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_sqlite3_step_call(SQLITE_DONE);

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
    expect_sqlite3_step_call(1);
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
    expect_sqlite3_step_call(SQLITE_DONE);

    output = wdb_hotfix_delete(data, "scan_id");
    assert_int_equal(output, 0);
}

/* Test wdb_set_hotfix_metadata */
void test_wdb_set_hotfix_metadata_transaction_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 0;
    will_return(__wrap_wdb_begin2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_set_hotfix_metadata(): cannot begin transaction");

    output = wdb_set_hotfix_metadata(data, "scan_id");
    assert_int_equal(output, -1);
}

void test_wdb_set_hotfix_metadata_cache_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    data->transaction = 1;
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_set_hotfix_metadata(): cannot cache statement");

    output = wdb_set_hotfix_metadata(data, "scan_id");
    assert_int_equal(output, -1);
}

void test_wdb_set_hotfix_metadata_sql_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_sqlite3_step_call(1);
    will_return(__wrap_sqlite3_errmsg, "ERROR");
    expect_string(__wrap__merror, formatted_msg, "Could not set the hotfix metadata: ERROR");

    output = wdb_set_hotfix_metadata(data, "scan_id");
    assert_int_equal(output, -1);
}

void test_wdb_set_hotfix_metadata_success(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_sqlite3_step_call(SQLITE_DONE);

    output = wdb_set_hotfix_metadata(data, "scan_id");
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

void test_wdb_osinfo_save_cache_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_osinfo_save(): cannot cache statement");

    output = wdb_osinfo_save(data, "scan_id", "scan_time", "hostname", "architecture", "os_name", "os_version", "os_codename", "os_major", "os_minor", "os_patch", "os_build", "os_platform", "sysname", "release", "version", "os_release", "os_display_version", "checksum", false);
    assert_int_equal(output, -1);
}

void test_wdb_osinfo_save_sql_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);
    expect_sqlite3_step_call(1);
    will_return(__wrap_sqlite3_errmsg, "ERROR");
    expect_string(__wrap__merror, formatted_msg, "Deleting old information from 'sys_osinfo' table: ERROR");

    output = wdb_osinfo_save(data, "scan_id", "scan_time", "hostname", "architecture", "os_name", "os_version", "os_codename", "os_major", "os_minor", "os_patch", "os_build", "os_platform", "sysname", "release", "version", "os_release", "os_display_version", "checksum", false);
    assert_int_equal(output, -1);
}

void test_wdb_osinfo_save_insert_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);
    expect_sqlite3_step_call(SQLITE_DONE);

    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_osinfo_insert(): cannot cache statement");

    output = wdb_osinfo_save(data, "scan_id", "scan_time", "hostname", "architecture", "os_name", "os_version", "os_codename", "os_major", "os_minor", "os_patch", "os_build", "os_platform", "sysname", "release", "version", "os_release", "os_display_version", "checksum", false);
    assert_int_equal(output, -1);
}

void test_wdb_osinfo_save_success(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_begin2, 0);
    will_return(__wrap_wdb_stmt_cache, 0);
    expect_sqlite3_step_call(SQLITE_DONE);

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
    expect_sqlite3_step_call(SQLITE_DONE);

    output = wdb_osinfo_save(data, "scan_id", "scan_time", "hostname", "architecture", "os_name", "os_version", "os_codename", "os_major", "os_minor", "os_patch", "os_build", "os_platform", "sysname", "release", "version", "os_release", "os_display_version", "checksum", false);
    assert_int_equal(output, 0);
}

/* Test wdb_osinfo_insert */
void test_wdb_osinfo_insert_cache_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_osinfo_insert(): cannot cache statement");

    output = wdb_osinfo_insert(data, "scan_id", "scan_time", "hostname", "architecture", "os_name", "os_version", "os_codename", "os_major", "os_minor", "os_patch", "os_build", "os_platform", "sysname", "release", "version", "os_release", "os_display_version", "checksum", false);
    assert_int_equal(output, -1);
}

void test_wdb_osinfo_insert_sql_fail(void **state) {
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

    expect_sqlite3_step_call(1);
    will_return(__wrap_sqlite3_errmsg, "ERROR");
    expect_string(__wrap__merror, formatted_msg, "at wdb_osinfo_insert(): sqlite3_step(): ERROR");

    output = wdb_osinfo_insert(data, "scan_id", "scan_time", "hostname", "architecture", "os_name", "os_version", "os_codename", "os_major", "os_minor", "os_patch", "os_build", "os_platform", "sysname", "release", "version", "os_release", "os_display_version", "checksum", false);
    assert_int_equal(output, -1);
}

void test_wdb_osinfo_insert_success(void **state) {
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
    expect_sqlite3_step_call(SQLITE_DONE);

    output = wdb_osinfo_insert(data, "scan_id", "scan_time", "hostname", "architecture", "os_name", "os_version", "os_codename", "os_major", "os_minor", "os_patch", "os_build", "os_platform", "sysname", "release", "version", "os_release", "os_display_version", "checksum", false);
    assert_int_equal(output, 0);
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
    expect_value(__wrap_sqlite3_bind_int, index, 16);
    expect_value(__wrap_sqlite3_bind_int, value, 0);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 17);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 18);
    expect_string(__wrap_sqlite3_bind_text, buffer, "item_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_sqlite3_step_call(SQLITE_DONE);

    output = wdb_package_save(data, "scan_id", "scan_time", "format", "name", "priority", "section", -1, "vendor", "install_time", "version", "architecture", "multiarch", "source", "description", "location", "checksum", "item_id", false);
    assert_int_equal(output, 0);
}

/* Test wdb_package_insert */
void test_wdb_package_insert_cache_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_package_insert(): cannot cache statement");

    output = wdb_package_insert(data, "scan_id", "scan_time", "format", "name", "priority", "section", 0, "vendor", "install_time", "version", "architecture", "multiarch", "source", "description", "location", 0, "checksum", "item_id", false);
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
    expect_value(__wrap_sqlite3_bind_int, index, 16);
    expect_value(__wrap_sqlite3_bind_int, value, 0);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 17);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 18);
    expect_string(__wrap_sqlite3_bind_text, buffer, "item_id");
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_sqlite3_step_call(1);
    will_return(__wrap_sqlite3_errmsg, "ERROR");
    expect_string(__wrap__merror, formatted_msg, "at wdb_package_insert(): sqlite3_step(): ERROR");


    output = wdb_package_insert(data, "scan_id", "scan_time", "format", "name", "priority", "section", 0, "vendor", "install_time", "version", "architecture", "multiarch", "source", "description", "location", 0, "checksum", "item_id", false);
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
    expect_value(__wrap_sqlite3_bind_int, index, 16);
    expect_value(__wrap_sqlite3_bind_int, value, 0);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 17);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 18);
    expect_string(__wrap_sqlite3_bind_text, buffer, "item_id");
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_sqlite3_step_call(SQLITE_CONSTRAINT);
    will_return(__wrap_sqlite3_errmsg, "DUPLICATED");
    will_return(__wrap_sqlite3_errmsg, "DUPLICATED");
    expect_string(__wrap__merror, formatted_msg, "at wdb_package_insert(): sqlite3_step(): DUPLICATED");

    output = wdb_package_insert(data, "scan_id", "scan_time", "format", "name", "priority", "section", 0, "vendor", "install_time", "version", "architecture", "multiarch", "source", "description", "location", 0, "checksum", "item_id", false);
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
    expect_value(__wrap_sqlite3_bind_int, index, 16);
    expect_value(__wrap_sqlite3_bind_int, value, 0);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 17);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 18);
    expect_string(__wrap_sqlite3_bind_text, buffer, "item_id");
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_sqlite3_step_call(SQLITE_CONSTRAINT);
    will_return(__wrap_sqlite3_errmsg, "UNIQUE");
    will_return(__wrap_sqlite3_errmsg, "UNIQUE");
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_package_insert(): sqlite3_step(): UNIQUE");

    output = wdb_package_insert(data, "scan_id", "scan_time", "format", "name", "priority", "section", 0, "vendor", "install_time", "version", "architecture", "multiarch", "source", "description", "location", 0, "checksum", "item_id", false);
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
    expect_value(__wrap_sqlite3_bind_int, index, 16);
    expect_value(__wrap_sqlite3_bind_int, value, 0);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 17);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 18);
    expect_string(__wrap_sqlite3_bind_text, buffer, "item_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_sqlite3_step_call(SQLITE_DONE);

    output = wdb_package_insert(data, "scan_id", "scan_time", "format", "name", "priority", "section", 0, "vendor", "install_time", "version", "architecture", "multiarch", "source", "description", "location", 0, "checksum", "item_id", false);
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
    expect_sqlite3_step_call(1);
    will_return(__wrap_sqlite3_errmsg, "ERROR");
    expect_string(__wrap__merror, formatted_msg, "at wdb_hotfix_insert(): sqlite3_step(): ERROR");

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
    expect_sqlite3_step_call(SQLITE_DONE);

    output = wdb_hotfix_save(data, "scan_id", "scan_time", "hotfix", "checksum", false);
    assert_int_equal(output, 0);
}

/* Test wdb_hotfix_insert */
void test_wdb_hotfix_insert_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_hotfix_insert(): cannot cache statement");

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

    expect_sqlite3_step_call(1);
    will_return(__wrap_sqlite3_errmsg, "ERROR");
    expect_string(__wrap__merror, formatted_msg, "at wdb_hotfix_insert(): sqlite3_step(): ERROR");

    output = wdb_hotfix_insert(data, "scan_id", "scan_time", "hotfix", "checksum", false);
    assert_int_equal(output, -1);
}

void test_wdb_hotfix_insert_success(void **state) {
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
    expect_string(__wrap_sqlite3_bind_text, buffer, "hotfix");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_sqlite3_step_call(SQLITE_DONE);

    output = wdb_hotfix_insert(data, "scan_id", "scan_time", "hotfix", "checksum", false);
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

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_sqlite3_step_call(0);
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

    expect_sqlite3_step_call(SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "cpe");
    expect_value(__wrap_sqlite3_column_text, iCol, 1);
    will_return(__wrap_sqlite3_column_text, "msu_name");
    expect_value(__wrap_sqlite3_column_int, iCol, 2);
    will_return(__wrap_sqlite3_column_int, 0);
    expect_value(__wrap_sqlite3_column_text, iCol, 3);
    will_return(__wrap_sqlite3_column_text, "format");
    expect_value(__wrap_sqlite3_column_text, iCol, 4);
    will_return(__wrap_sqlite3_column_text, "name");
    expect_value(__wrap_sqlite3_column_text, iCol, 5);
    will_return(__wrap_sqlite3_column_text, "vendor");
    expect_value(__wrap_sqlite3_column_text, iCol, 6);
    will_return(__wrap_sqlite3_column_text, "version");
    expect_value(__wrap_sqlite3_column_text, iCol, 7);
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

    expect_sqlite3_step_call(SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "cpe");
    expect_value(__wrap_sqlite3_column_text, iCol, 1);
    will_return(__wrap_sqlite3_column_text, "msu_name");
    expect_value(__wrap_sqlite3_column_int, iCol, 2);
    will_return(__wrap_sqlite3_column_int, 0);
    expect_value(__wrap_sqlite3_column_text, iCol, 3);
    will_return(__wrap_sqlite3_column_text, "format");
    expect_value(__wrap_sqlite3_column_text, iCol, 4);
    will_return(__wrap_sqlite3_column_text, "name");
    expect_value(__wrap_sqlite3_column_text, iCol, 5);
    will_return(__wrap_sqlite3_column_text, "vendor");
    expect_value(__wrap_sqlite3_column_text, iCol, 6);
    will_return(__wrap_sqlite3_column_text, "version");
    expect_value(__wrap_sqlite3_column_text, iCol, 7);
    will_return(__wrap_sqlite3_column_text, "arch");

    will_return(__wrap_wdb_stmt_cache, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "cpe");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "msu_name");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 3);
    expect_value(__wrap_sqlite3_bind_int, value, 0);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_string(__wrap_sqlite3_bind_text, buffer, "format");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_string(__wrap_sqlite3_bind_text, buffer, "name");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_string(__wrap_sqlite3_bind_text, buffer, "vendor");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_string(__wrap_sqlite3_bind_text, buffer, "version");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 9);
    expect_string(__wrap_sqlite3_bind_text, buffer, "arch");
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_sqlite3_step_call(1);

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

    expect_sqlite3_step_call(SQLITE_ROW);
    expect_value(__wrap_sqlite3_column_text, iCol, 0);
    will_return(__wrap_sqlite3_column_text, "cpe");
    expect_value(__wrap_sqlite3_column_text, iCol, 1);
    will_return(__wrap_sqlite3_column_text, "msu_name");
    expect_value(__wrap_sqlite3_column_int, iCol, 2);
    will_return(__wrap_sqlite3_column_int, 0);
    expect_value(__wrap_sqlite3_column_text, iCol, 3);
    will_return(__wrap_sqlite3_column_text, "format");
    expect_value(__wrap_sqlite3_column_text, iCol, 4);
    will_return(__wrap_sqlite3_column_text, "name");
    expect_value(__wrap_sqlite3_column_text, iCol, 5);
    will_return(__wrap_sqlite3_column_text, "vendor");
    expect_value(__wrap_sqlite3_column_text, iCol, 6);
    will_return(__wrap_sqlite3_column_text, "version");
    expect_value(__wrap_sqlite3_column_text, iCol, 7);
    will_return(__wrap_sqlite3_column_text, "arch");

    will_return(__wrap_wdb_stmt_cache, 0);

    expect_value(__wrap_sqlite3_bind_text, pos, 1);
    expect_string(__wrap_sqlite3_bind_text, buffer, "cpe");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "msu_name");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 3);
    expect_value(__wrap_sqlite3_bind_int, value, 0);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    expect_string(__wrap_sqlite3_bind_text, buffer, "scan_id");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    expect_string(__wrap_sqlite3_bind_text, buffer, "format");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_string(__wrap_sqlite3_bind_text, buffer, "name");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 7);
    expect_string(__wrap_sqlite3_bind_text, buffer, "vendor");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 8);
    expect_string(__wrap_sqlite3_bind_text, buffer, "version");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 9);
    expect_string(__wrap_sqlite3_bind_text, buffer, "arch");
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_sqlite3_step_call(SQLITE_DONE);
    expect_sqlite3_step_call(SQLITE_DONE);

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

    expect_sqlite3_step_call(1);
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

    expect_sqlite3_step_call(SQLITE_DONE);

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

    expect_sqlite3_step_call(1);
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
    expect_sqlite3_step_call(SQLITE_DONE);

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
    expect_sqlite3_step_call(SQLITE_DONE);

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

    expect_sqlite3_step_call(SQLITE_DONE);

    output = wdb_hardware_save(data, "scan_id", "scan_time", "serial", "cpu_name", -1, -1, 0, 0, -1, "checksum", false);
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
    expect_value(__wrap_sqlite3_bind_int, value, 2048);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 10);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_sqlite3_step_call(1);
    will_return(__wrap_sqlite3_errmsg, "ERROR");
    expect_string(__wrap__merror, formatted_msg, "at wdb_hardware_insert(): sqlite3_step(): ERROR");

    output = wdb_hardware_insert(data, "scan_id", "scan_time", "serial", "cpu_name", 4, 2900, 8192, 6144, 2048, "checksum", false);
    assert_int_equal(output, -1);
}

void test_wdb_hardware_insert_success(void **state) {
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
    expect_value(__wrap_sqlite3_bind_int, value, 2048);
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 10);
    expect_string(__wrap_sqlite3_bind_text, buffer, "checksum");
    will_return(__wrap_sqlite3_bind_text, 0);

    expect_sqlite3_step_call(SQLITE_DONE);

    output = wdb_hardware_insert(data, "scan_id", "scan_time", "serial", "cpu_name", 4, 2900, 8192, 6144, 2048, "checksum", false);
    assert_int_equal(output, 0);
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
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 10);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
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
    expect_sqlite3_step_call(SQLITE_DONE);

    output = wdb_port_save(data, "scan_id", "scan_time", "protocol", "local_ip", 541, "remote_ip", 541, 10, 10, 1, "state", 32545, "process", "checksum", "item_id", false);
    assert_int_equal(output, 0);
}

/* Test wdb_port_insert */
void test_wdb_port_insert_cache_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_port_insert(): cannot cache statement");

    output = wdb_port_insert(data, "scan_id", "scan_time", "protocol", "local_ip", -1, "remote_ip", -1, -1, -1, -1, "state", -1, "process", "checksum", "item_id", false);
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
    expect_value(__wrap_sqlite3_bind_null, index, 5);
    will_return(__wrap_sqlite3_bind_null, 0);
    expect_value(__wrap_sqlite3_bind_text, pos, 6);
    expect_string(__wrap_sqlite3_bind_text, buffer, "remote_ip");
    will_return(__wrap_sqlite3_bind_text, 0);
    expect_value(__wrap_sqlite3_bind_null, index, 7);
    will_return(__wrap_sqlite3_bind_null, 0);
    expect_value(__wrap_sqlite3_bind_null, index, 8);
    will_return(__wrap_sqlite3_bind_null, 0);
    expect_value(__wrap_sqlite3_bind_null, index, 9);
    will_return(__wrap_sqlite3_bind_null, 0);
    expect_value(__wrap_sqlite3_bind_null, index, 10);
    will_return(__wrap_sqlite3_bind_null, 0);
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

    expect_sqlite3_step_call(1);
    will_return(__wrap_sqlite3_errmsg, "ERROR");
    expect_string(__wrap__merror, formatted_msg, "at wdb_port_insert(): sqlite3_step(): ERROR");

    output = wdb_port_insert(data, "scan_id", "scan_time", "protocol", "local_ip", -1, "remote_ip", -1, -1, -1, -1, "state", -1, "process", "checksum", "item_id", false);
    assert_int_equal(output, -1);
}

void test_wdb_port_insert_success(void **state) {
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
    will_return(__wrap_sqlite3_bind_int, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 10);
    expect_value(__wrap_sqlite3_bind_int, value, 1);
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

    expect_sqlite3_step_call(SQLITE_DONE);

    output = wdb_port_insert(data, "scan_id", "scan_time", "protocol", "local_ip", 541, "remote_ip", 541, 10, 10, 1, "state", 32545, "process", "checksum", "item_id", false);
    assert_int_equal(output, 0);
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

    expect_sqlite3_step_call(1);
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

    expect_sqlite3_step_call(SQLITE_DONE);

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
    will_return(__wrap_sqlite3_bind_int, 0);
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
    expect_sqlite3_step_call(SQLITE_DONE);

    output = wdb_process_save(data, "scan_id", "scan_time", 1, "name", "state", 1, 1, 1, "cmd", "argvs", "euser", "ruser", "suser", "egroup", "rgroup", "sgroup", "fgroup", 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, "checksum", false);
    assert_int_equal(output, 0);
}

/* Test wdb_process_insert */
void test_wdb_process_insert_cache_fail(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "at wdb_process_insert(): cannot cache statement");

    output = wdb_process_insert(data, "scan_id", "scan_time", -1, "name", "state", -1, -1, -1, "cmd", "argvs", "euser", "ruser", "suser", "egroup", "rgroup", "sgroup", "fgroup", -1, 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, "checksum", false);
    assert_int_equal(output, -1);
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
    expect_value(__wrap_sqlite3_bind_null, index, 3);
    will_return(__wrap_sqlite3_bind_null, 0);
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

    expect_sqlite3_step_call(1);
    will_return(__wrap_sqlite3_errmsg, "ERROR");
    expect_string(__wrap__merror, formatted_msg, "at wdb_process_insert(): sqlite3_step(): ERROR");

    output = wdb_process_insert(data, "scan_id", "scan_time", -1, "name", "state", -1, -1, -1, "cmd", "argvs", "euser", "ruser", "suser", "egroup", "rgroup", "sgroup", "fgroup", -1, 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, "checksum", false);
    assert_int_equal(output, -1);
}

void test_wdb_process_insert_success(void **state) {
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
    will_return(__wrap_sqlite3_bind_int, 0);
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

    expect_sqlite3_step_call(SQLITE_DONE);

    output = wdb_process_insert(data, "scan_id", "scan_time", 1, "name", "state", 1, 1, 1, "cmd", "argvs", "euser", "ruser", "suser", "egroup", "rgroup", "sgroup", "fgroup", 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, "checksum", false);
    assert_int_equal(output, 0);
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

    expect_sqlite3_step_call(1);
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

    expect_sqlite3_step_call(SQLITE_DONE);

    output = wdb_process_delete(data, "scan_id");
    assert_int_equal(output, 0);
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

void test_wdb_syscollector_save2_processes_success(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;
    cJSON attribute = {0};

    attribute.valueint = 123;

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

void test_wdb_syscollector_save2_osinfo_success(void **state) {
    int output = 0;
    wdb_t *data = (wdb_t *)*state;

    will_return(__wrap_cJSON_Parse, 1);
    will_return(__wrap_cJSON_GetObjectItem, 1);

    data->transaction = 1;
    wdb_syscollector_osinfo_save2_success();
    expect_function_call(__wrap_cJSON_Delete);

    output = wdb_syscollector_save2(data, WDB_SYSCOLLECTOR_OSINFO, NULL);
    assert_int_equal(output, 0);
}

int main() {

    const struct CMUnitTest tests[] = {
        /* Tests wdb_netinfo_save */
        cmocka_unit_test_setup_teardown(test_wdb_netinfo_save_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_netinfo_save_insertion_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_netinfo_save_success, test_setup, test_teardown),
        /* Tests wdb_netinfo_insert */
        cmocka_unit_test_setup_teardown(test_wdb_netinfo_insert_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_netinfo_insert_default_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_netinfo_insert_sql_constraint_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_netinfo_insert_sql_constraint_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_netinfo_insert_sql_success, test_setup, test_teardown),
        /* Test wdb_netproto_save */
        cmocka_unit_test_setup_teardown(test_wdb_netproto_save_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_netproto_save_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_netproto_save_success, test_setup, test_teardown),
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
        cmocka_unit_test_setup_teardown(test_wdb_netaddr_insert_success, test_setup, test_teardown),
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
        /* Test wdb_set_hotfix_metadata */
        cmocka_unit_test_setup_teardown(test_wdb_set_hotfix_metadata_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_set_hotfix_metadata_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_set_hotfix_metadata_sql_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_set_hotfix_metadata_success, test_setup, test_teardown),
        /* Test wdb_osinfo_save */
        cmocka_unit_test_setup_teardown(test_wdb_osinfo_save_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_osinfo_save_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_osinfo_save_sql_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_osinfo_save_insert_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_osinfo_save_success, test_setup, test_teardown),
        /* Test wdb_osinfo_insert */
        cmocka_unit_test_setup_teardown(test_wdb_osinfo_insert_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_osinfo_insert_sql_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_osinfo_insert_success, test_setup, test_teardown),
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
        /* Test wdb_hotfix_insert */
        cmocka_unit_test_setup_teardown(test_wdb_hotfix_insert_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_hotfix_insert_success, test_setup, test_teardown),
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
        cmocka_unit_test_setup_teardown(test_wdb_hardware_insert_success, test_setup, test_teardown),
        /* Test wdb_port_save */
        cmocka_unit_test_setup_teardown(test_wdb_port_save_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_port_save_insert_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_port_save_success, test_setup, test_teardown),
        /* Test wdb_port_insert */
        cmocka_unit_test_setup_teardown(test_wdb_port_insert_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_port_insert_sql_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_port_insert_success, test_setup, test_teardown),
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
        cmocka_unit_test_setup_teardown(test_wdb_process_insert_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_process_insert_sql_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_process_insert_success, test_setup, test_teardown),
        /* Test wdb_process_delete */
        cmocka_unit_test_setup_teardown(test_wdb_process_delete_transaction_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_process_delete_cache_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_process_delete_sql_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_process_delete_success, test_setup, test_teardown),
        /* Test wdb_syscollector_save2 */
        cmocka_unit_test_setup_teardown(test_wdb_syscollector_save2_parser_json_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_syscollector_save2_get_attributes_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_syscollector_save2_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_syscollector_save2_processes_fail, test_setup, test_teardown),
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
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
