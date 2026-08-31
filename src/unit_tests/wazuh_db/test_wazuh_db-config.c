/*
 * Copyright (C) 2015, Wazuh Inc.
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

#include "shared.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "wazuh_db-config.h"
#include "wdb.h"
#include "wazuhdb_op.h"
#include "../../external/cJSON/cJSON.h"

/* setup/teardown */

int wazuh_db_setup() {
    wdb_init_conf();

    return OS_SUCCESS;
}

int  wazuh_db_teardown() {
    wdb_free_conf();

    return OS_SUCCESS;
}

void test_Read_WazuhDB_JSON_effective_defaults(void **state)
{
    cJSON *wdb = cJSON_Parse("{\"backup\":{\"global\":{\"enabled\":true,\"interval\":\"1d\",\"max_files\":3}}}");
    assert_non_null(wdb);

    assert_int_equal(Read_WazuhDB_JSON(wdb), OS_SUCCESS);
    assert_int_equal(wconfig.wdb_backup_settings[WDB_GLOBAL_BACKUP]->enabled, 1);
    assert_int_equal(wconfig.wdb_backup_settings[WDB_GLOBAL_BACKUP]->interval, 86400);
    assert_int_equal(wconfig.wdb_backup_settings[WDB_GLOBAL_BACKUP]->max_files, 3);

    cJSON_Delete(wdb);
}

void test_Read_WazuhDB_JSON_interval_int_and_disabled(void **state)
{
    cJSON *wdb = cJSON_Parse("{\"backup\":{\"global\":{\"enabled\":false,\"interval\":3600,\"max_files\":1}}}");
    assert_non_null(wdb);

    assert_int_equal(Read_WazuhDB_JSON(wdb), OS_SUCCESS);
    assert_int_equal(wconfig.wdb_backup_settings[WDB_GLOBAL_BACKUP]->enabled, 0);
    assert_int_equal(wconfig.wdb_backup_settings[WDB_GLOBAL_BACKUP]->interval, 3600);
    assert_int_equal(wconfig.wdb_backup_settings[WDB_GLOBAL_BACKUP]->max_files, 1);

    cJSON_Delete(wdb);
}

void test_Read_WazuhDB_JSON_absent_keeps_defaults(void **state)
{
    cJSON *empty = cJSON_Parse("{}");

    /* The settings are group-wide: start again from wdb_init_conf() defaults */
    wdb_free_conf();
    wdb_init_conf();

    assert_int_equal(Read_WazuhDB_JSON(NULL), OS_SUCCESS);
    assert_int_equal(Read_WazuhDB_JSON(empty), OS_SUCCESS);
    assert_int_equal(wconfig.wdb_backup_settings[WDB_GLOBAL_BACKUP]->enabled, 1);
    assert_int_equal(wconfig.wdb_backup_settings[WDB_GLOBAL_BACKUP]->interval, 86400);
    assert_int_equal(wconfig.wdb_backup_settings[WDB_GLOBAL_BACKUP]->max_files, 3);

    cJSON_Delete(empty);
}

void test_Read_WazuhDB_JSON_null_section_keeps_defaults(void **state)
{
    int enabled = wconfig.wdb_backup_settings[WDB_GLOBAL_BACKUP]->enabled;
    time_t interval = wconfig.wdb_backup_settings[WDB_GLOBAL_BACKUP]->interval;
    int max_files = wconfig.wdb_backup_settings[WDB_GLOBAL_BACKUP]->max_files;

    assert_int_equal(Read_WazuhDB_JSON(NULL), OS_SUCCESS);
    assert_int_equal(wconfig.wdb_backup_settings[WDB_GLOBAL_BACKUP]->enabled, enabled);
    assert_int_equal(wconfig.wdb_backup_settings[WDB_GLOBAL_BACKUP]->interval, interval);
    assert_int_equal(wconfig.wdb_backup_settings[WDB_GLOBAL_BACKUP]->max_files, max_files);
}

void test_Read_WazuhDB_JSON_rejects_zero_interval_and_max_files(void **state)
{
    cJSON *interval = cJSON_Parse("{\"backup\":{\"global\":{\"interval\":0}}}");
    cJSON *max_files = cJSON_Parse("{\"backup\":{\"global\":{\"max_files\":0}}}");

    expect_string(__wrap__merror, formatted_msg, "(1235): Invalid value for element 'interval': 0.");
    assert_int_equal(Read_WazuhDB_JSON(interval), OS_INVALID);

    expect_string(__wrap__merror, formatted_msg, "(1235): Invalid value for element 'max_files': 0.");
    assert_int_equal(Read_WazuhDB_JSON(max_files), OS_INVALID);

    cJSON_Delete(interval);
    cJSON_Delete(max_files);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        // Tests Read_WazuhDB_JSON (etc/wazuh-manager.yml)
        cmocka_unit_test(test_Read_WazuhDB_JSON_effective_defaults),
        cmocka_unit_test(test_Read_WazuhDB_JSON_interval_int_and_disabled),
        cmocka_unit_test(test_Read_WazuhDB_JSON_absent_keeps_defaults),
        cmocka_unit_test(test_Read_WazuhDB_JSON_null_section_keeps_defaults),
        cmocka_unit_test(test_Read_WazuhDB_JSON_rejects_zero_interval_and_max_files),
    };

    return cmocka_run_group_tests(tests, wazuh_db_setup, wazuh_db_teardown);
}
