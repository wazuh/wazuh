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

#include "../../config/global-config.h"
#include "../../analysisd/eventinfo.h"

#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_wrappers.h"

#include "../headers/wazuhdb_op.h"

extern int DecodeSyscollector(Eventinfo *lf, int *socket);
extern _Config Config;

/* setup / teardown */
int test_setup_global(void **state)
{
    expect_string(__wrap__mdebug1, formatted_msg, "SyscollectorInit completed.");
    Config.decoder_order_size = 32;
    SyscollectorInit();
    return 0;
}

int test_setup_invalid_location(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    os_strdup("{'type'='dbsync_processes'}", lf->log);
    os_strdup("s>syscollector", lf->location);
    *state = lf;
    return 0;
}

int test_setup_invalid_json(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    os_strdup("_INVALIDJSON_", lf->log);
    os_strdup("(>syscollector", lf->location);
    *state = lf;
    return 0;
}

int test_setup_invalid_msgtype(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    const char *plain_event = "{\"type\":\"_dbsync_processes\"}";

    if (lf->log = strdup(plain_event), lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    *state = lf;
    return 0;
}

int test_setup_invalid_msgtype2(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    const char *plain_event = "{\"type\":\"dbsync_processes\"}";

    if (lf->log = strdup(plain_event), lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    *state = lf;
    return 0;
}

int test_cleanup(void **state)
{
    Eventinfo *lf = *state;
    os_free(lf->log);
    w_free_event_info(lf);
    return 0;
}

/* tests */
void test_syscollector_dbsync_invalid_location(void **state)
{
    Eventinfo *lf = *state;
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid received event. (Location)");
    int ret = DecodeSyscollector(lf, 0);

    assert_int_equal(ret, 0);
}

void test_syscollector_dbsync_invalid_json(void **state)
{
    Eventinfo *lf = *state;
    expect_string(__wrap__mdebug1, formatted_msg, "Error parsing JSON event.");
    expect_any(__wrap__mdebug2, formatted_msg);
    int ret = DecodeSyscollector(lf, 0);

    assert_int_equal(ret, 0);
}

void test_syscollector_dbsync_invalid_msgtype(void **state)
{
    Eventinfo *lf = *state;
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid message type: _dbsync_processes.");
    int ret = DecodeSyscollector(lf, 0);

    assert_int_equal(ret, 0);
}

void test_syscollector_dbsync_invalid_msgtype2(void **state)
{
    Eventinfo *lf = *state;
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid message type: dbsync_processes.");
    int ret = DecodeSyscollector(lf, 0);

    assert_int_equal(ret, 0);
}

int main()
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_invalid_location, test_setup_invalid_location, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_invalid_json, test_setup_invalid_json, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_invalid_msgtype, test_setup_invalid_msgtype, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_invalid_msgtype2, test_setup_invalid_msgtype2, test_cleanup)
    };
    return cmocka_run_group_tests(tests, test_setup_global, NULL);
}
