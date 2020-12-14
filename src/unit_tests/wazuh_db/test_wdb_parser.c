/*
 * Copyright (C) 2015-2019, Wazuh Inc.
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
#include <string.h>
#include <stdlib.h>

#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/wazuh_db/wdb_wrappers.h"

wdb_t * __wrap_wdb_open_agent2(int agent_id)
{
    wdb_t * wdb = NULL;
    if (mock()) {
        char sagent_id[64];
        snprintf(sagent_id, sizeof(sagent_id), "%03d", agent_id);
        os_calloc(1, sizeof(wdb_t), wdb);
        w_mutex_init(&wdb->mutex, NULL);
        wdb->id = strdup(sagent_id);
    }
    return wdb;
}

int __wrap_wdb_inventory_save_hw(wdb_t * wdb, const char * payload)
{
    check_expected(payload);
    return mock();
}

int __wrap_wdb_inventory_save_os(wdb_t * wdb, const char * payload)
{
    check_expected(payload);
    return mock();
}

int __wrap_wdb_inventory_save_network(wdb_t * wdb, const char * payload)
{
    check_expected(payload);
    return mock();
}

int __wrap_wdb_inventory_delete_network(wdb_t * wdb, const char * payload)
{
    check_expected(payload);
    return mock();
}

int __wrap_wdb_inventory_save_program(wdb_t * wdb, const char * payload)
{
    check_expected(payload);
    return mock();
}

int __wrap_wdb_inventory_delete_program(wdb_t * wdb, const char * payload)
{
    check_expected(payload);
    return mock();
}

int __wrap_wdb_inventory_save_hotfix(wdb_t * wdb, const char * payload)
{
    check_expected(payload);
    return mock();
}

int __wrap_wdb_inventory_delete_hotfix(wdb_t * wdb, const char * payload)
{
    check_expected(payload);
    return mock();
}

int __wrap_wdb_inventory_save_port(wdb_t * wdb, const char * payload)
{
    check_expected(payload);
    return mock();
}

int __wrap_wdb_inventory_delete_port(wdb_t * wdb, const char * payload)
{
    check_expected(payload);
    return mock();
}

int __wrap_wdb_inventory_save_process(wdb_t * wdb, const char * payload)
{
    check_expected(payload);
    return mock();
}

int __wrap_wdb_inventory_delete_process(wdb_t * wdb, const char * payload)
{
    check_expected(payload);
    return mock();
}

int __wrap_wdb_inventory_save_scan_info(wdb_t * wdb, const char * inventory, const char * payload)
{
    check_expected(inventory);
    check_expected(payload);
    return mock();
}

typedef struct test_struct {
    wdb_t *wdb;
    char *output;
} test_struct_t;

static int test_setup(void **state) {
    test_struct_t *init_data;
    init_data = malloc(sizeof(test_struct_t));
    init_data->wdb = malloc(sizeof(wdb_t));
    init_data->wdb->id = strdup("000");
    init_data->output = malloc(256*sizeof(char));
    *state = init_data;
    return 0;
}

static int test_teardown(void **state){
    test_struct_t *data  = (test_struct_t *)*state;
    free(data->output);
    free(data->wdb->id);
    free(data->wdb);
    free(data);
    return 0;
}

void test_wdb_parse_syscheck_no_space(void **state)
{
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    expect_string(__wrap__mdebug2, formatted_msg, "DB(000) Invalid FIM query syntax: badquery_nospace");
    ret = wdb_parse_syscheck(data->wdb, "badquery_nospace", data->output);

    assert_string_equal(data->output, "err Invalid FIM query syntax, near \'badquery_nospace\'");
    assert_int_equal(ret, -1);
}

void test_scan_info_error(void **state)
{
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    will_return(__wrap_wdb_scan_info_get, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Cannot get FIM scan info.");
    char *query = strdup("scan_info_get ");
    ret = wdb_parse_syscheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Cannot get fim scan info.");
    assert_int_equal(ret, -1);
    os_free(query);
}

void test_scan_info_ok(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_scan_info_get, 1);
    char *query = strdup("scan_info_get ");
    ret = wdb_parse_syscheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok 0");
    assert_int_equal(ret, 1);

    os_free(query);
}


void test_update_info_error(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_fim_update_date_entry, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Cannot update fim date field.");
    char *query = strdup("updatedate ");
    ret = wdb_parse_syscheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Cannot update fim date field.");
    assert_int_equal(ret, -1);

    os_free(query);
}

void test_update_info_ok(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_fim_update_date_entry, 1);
    char *query = strdup("updatedate ");
    ret = wdb_parse_syscheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, 1);

    os_free(query);
}


void test_clean_old_entries_error(void **state)
{
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    will_return(__wrap_wdb_fim_clean_old_entries, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Cannot clean fim database.");
    char *query = strdup("cleandb ");
    ret = wdb_parse_syscheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Cannot clean fim database.");
    assert_int_equal(ret, -1);

    os_free(query);
}

void test_clean_old_entries_ok(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;

    will_return(__wrap_wdb_fim_clean_old_entries, 1);
    char *query = strdup("cleandb ");
    ret = wdb_parse_syscheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, 1);

    os_free(query);
}



void test_scan_info_update_noarg(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid scan_info fim query syntax.");
    char *query = strdup("scan_info_update ");
    ret = wdb_parse_syscheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid Syscheck query syntax, near \'\'");
    assert_int_equal(ret, -1);

    os_free(query);
}

void test_scan_info_update_error(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;
    will_return(__wrap_wdb_scan_info_update, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Cannot save fim control message.");
    char *query = strdup("scan_info_update \"191919\" ");
    ret = wdb_parse_syscheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Cannot save fim control message");
    assert_int_equal(ret, -1);

    os_free(query);
}

void test_scan_info_update_ok(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;
    will_return(__wrap_wdb_scan_info_update, 1);
    char *query = strdup("scan_info_update \"191919\" ");
    ret = wdb_parse_syscheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, 1);

    os_free(query);
}



void test_scan_info_fim_check_control_error(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;
    will_return(__wrap_wdb_scan_info_fim_checks_control, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Cannot save fim check_control message.");
    char *query = strdup("control ");
    ret = wdb_parse_syscheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Cannot save fim control message");
    assert_int_equal(ret, -1);

    os_free(query);
}

void test_scan_info_fim_check_control_ok(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;
    will_return(__wrap_wdb_scan_info_fim_checks_control, 1);
    char *query = strdup("control ");
    ret = wdb_parse_syscheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, 1);

    os_free(query);
}

void test_syscheck_load_error(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;
    will_return(__wrap_wdb_syscheck_load, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Cannot load FIM.");
    char *query = strdup("load ");
    ret = wdb_parse_syscheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Cannot load Syscheck");
    assert_int_equal(ret, -1);

    os_free(query);
}

void test_syscheck_load_ok(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;
    will_return(__wrap_wdb_syscheck_load, 1);
    char *query = strdup("load ");
    ret = wdb_parse_syscheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok TEST STRING");
    assert_int_equal(ret, 1);

    os_free(query);
}

void test_fim_delete_error(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;
    will_return(__wrap_wdb_fim_delete, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Cannot delete FIM entry.");
    char *query = strdup("delete ");
    ret = wdb_parse_syscheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Cannot delete Syscheck");
    assert_int_equal(ret, -1);

    os_free(query);
}

void test_fim_delete_ok(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;
    will_return(__wrap_wdb_fim_delete, 1);
    char *query = strdup("delete ");
    ret = wdb_parse_syscheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, 1);

    os_free(query);
}

void test_syscheck_save_noarg(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid FIM query syntax.");
    char *query = strdup("save ");
    expect_string(__wrap__mdebug2, formatted_msg, "DB(000) FIM query: ");
    ret = wdb_parse_syscheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid Syscheck query syntax, near \'\'");
    assert_int_equal(ret, -1);

    os_free(query);
}

void test_syscheck_save_invalid_type(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid FIM query syntax.");
    char *query = strdup("save invalid_type ");
    expect_string(__wrap__mdebug2, formatted_msg, "DB(000) FIM query: invalid_type");
    ret = wdb_parse_syscheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid Syscheck query syntax, near \'invalid_type\'");
    assert_int_equal(ret, -1);

    os_free(query);
}

void test_syscheck_save_file_type_error(void **state)
{
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("save file 1212121 ");
    will_return(__wrap_wdb_syscheck_save, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Cannot save FIM.");
    ret = wdb_parse_syscheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Cannot save Syscheck");
    assert_int_equal(ret, -1);

    os_free(query);
}

void test_syscheck_save_file_nospace(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid FIM query syntax.");
    char *query = strdup("save file ");
    expect_string(__wrap__mdebug2, formatted_msg, "FIM query: ");
    ret = wdb_parse_syscheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid Syscheck query syntax, near \'\'");
    assert_int_equal(ret, -1);

    os_free(query);
}

void test_syscheck_save_file_type_ok(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("save file !1212121 ");
    will_return(__wrap_wdb_syscheck_save, 1);
    ret = wdb_parse_syscheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, 1);

    os_free(query);
}

void test_syscheck_save_registry_type_error(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("save registry 1212121 ");
    will_return(__wrap_wdb_syscheck_save, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Cannot save FIM.");
    ret = wdb_parse_syscheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Cannot save Syscheck");
    assert_int_equal(ret, -1);

    os_free(query);
}

void test_syscheck_save_registry_type_ok(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("save registry !1212121 ");
    will_return(__wrap_wdb_syscheck_save, 1);
    ret = wdb_parse_syscheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, 1);

    os_free(query);
}

void test_syscheck_save2_error(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("save2 ");
    will_return(__wrap_wdb_syscheck_save2, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Cannot save FIM.");
    ret = wdb_parse_syscheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Cannot save Syscheck");
    assert_int_equal(ret, -1);

    os_free(query);
}

void test_syscheck_save2_ok(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("save2 ");
    will_return(__wrap_wdb_syscheck_save2, 1);
    ret = wdb_parse_syscheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok");
    assert_int_equal(ret, 0);

    os_free(query);
}

void test_integrity_check_error(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("integrity_check_ ");
    will_return(__wrap_wdbi_query_checksum, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Cannot query FIM range checksum.");
    ret = wdb_parse_syscheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Cannot perform range checksum");
    assert_int_equal(ret, -1);

    os_free(query);
}

void test_integrity_check_no_data(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("integrity_check_ ");
    will_return(__wrap_wdbi_query_checksum, 0);
    ret = wdb_parse_syscheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok no_data");
    assert_int_equal(ret, 0);

    os_free(query);
}

void test_integrity_check_checksum_fail(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("integrity_check_ ");
    will_return(__wrap_wdbi_query_checksum, 1);
    ret = wdb_parse_syscheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok checksum_fail");
    assert_int_equal(ret, 0);

    os_free(query);
}

void test_integrity_check_ok(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("integrity_check_ ");
    will_return(__wrap_wdbi_query_checksum, 2);
    ret = wdb_parse_syscheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok ");
    assert_int_equal(ret, 0);

    os_free(query);
}

void test_integrity_clear_error(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("integrity_clear ");
    will_return(__wrap_wdbi_query_clear, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Cannot query FIM range checksum.");
    ret = wdb_parse_syscheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Cannot perform range checksum");
    assert_int_equal(ret, -1);

    os_free(query);
}

void test_integrity_clear_ok(void **state)
{
    int ret;

    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("integrity_clear ");
    will_return(__wrap_wdbi_query_clear, 2);
    ret = wdb_parse_syscheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok ");
    assert_int_equal(ret, 0);

    os_free(query);
}


void test_invalid_command(void **state){
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid FIM query syntax.");
    char *query = strdup("wrong_command ");
    expect_string(__wrap__mdebug2, formatted_msg, "DB query error near: wrong_command");
    ret = wdb_parse_syscheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid Syscheck query syntax, near 'wrong_command'");
    assert_int_equal(ret, -1);

    os_free(query);
}

void test_parse_no_input(void **state)
{
    (void) state;

    char output[OS_MAXSTR + 1];
    *output = '\0';

    expect_string(__wrap__mdebug1, formatted_msg, "Empty input query.");

    int ret = wdb_parse(NULL, output);

    assert_int_equal(ret, -1);
    assert_null(*output);
}

void test_parse_invalid_actor(void **state)
{
    (void) state;

    char * input1 = strdup("abcdef");
    char * output1 = calloc(1, OS_MAXSTR + 1);
    *output1 = '\0';

    expect_string(__wrap__mdebug2, formatted_msg, "DB query: abcdef");
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid DB query syntax.");

    int ret = wdb_parse(input1, output1);

    assert_int_equal(ret, -1);
    assert_string_equal(output1, "err Invalid DB query syntax, near 'abcdef'");

    free(input1);
    free(output1);

    char * input2 = strdup("manager 000");
    char * output2 = calloc(1, OS_MAXSTR + 1);
    *output2 = '\0';

    expect_string(__wrap__mdebug1, formatted_msg, "DB() Invalid DB query actor: manager");

    ret = wdb_parse(input2, output2);

    assert_int_equal(ret, -1);
    assert_string_equal(output2, "err Invalid DB query actor: 'manager'");

    free(input2);
    free(output2);
}

void test_parse_invalid_agent_id(void **state)
{
    (void) state;

    char * input1 = strdup("agent 000");
    char * output1 = calloc(1, OS_MAXSTR + 1);
    *output1 = '\0';

    expect_string(__wrap__mdebug1, formatted_msg, "Invalid DB query syntax.");
    expect_string(__wrap__mdebug2, formatted_msg, "DB query error near: 000");

    int ret = wdb_parse(input1, output1);

    assert_int_equal(ret, -1);
    assert_string_equal(output1, "err Invalid DB query syntax, near '000'");

    free(input1);
    free(output1);

    char * input2 = strdup("agent abc test");
    char * output2 = calloc(1, OS_MAXSTR + 1);
    *output2 = '\0';

    expect_string(__wrap__mdebug1, formatted_msg, "Invalid agent ID 'abc'");

    ret = wdb_parse(input2, output2);

    assert_int_equal(ret, -1);
    assert_string_equal(output2, "err Invalid agent ID 'abc'");

    free(input2);
    free(output2);

    char * input3 = strdup("agent 000 test");
    char * output3 = calloc(1, OS_MAXSTR + 1);
    *output3 = '\0';

    will_return(__wrap_wdb_open_agent2, 0);

    expect_string(__wrap__merror, formatted_msg, "Couldn't open DB for agent '000'");

    ret = wdb_parse(input3, output3);

    assert_int_equal(ret, -1);
    assert_string_equal(output3, "err Couldn't open DB for agent 0");

    free(input3);
    free(output3);
}

void test_parse_inventory_invalid_type(void **state)
{
    (void) state;

    char * input1 = strdup("agent 000 inventory");
    char * output1 = calloc(1, OS_MAXSTR + 1);
    *output1 = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid inventory query syntax.");
    expect_string(__wrap__mdebug2, formatted_msg, "DB(000) query error near: inventory");

    int ret = wdb_parse(input1, output1);

    assert_int_equal(ret, -1);
    assert_string_equal(output1, "err Invalid inventory query syntax, near 'inventory'");

    free(input1);
    free(output1);

    char * input2 = strdup("agent 000 inventory drivers");
    char * output2 = calloc(1, OS_MAXSTR + 1);
    *output2 = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory drivers");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid inventory query syntax: drivers");

    ret = wdb_parse(input2, output2);

    assert_int_equal(ret, -1);
    assert_string_equal(output2, "err Invalid inventory query syntax, near 'drivers'");

    free(input2);
    free(output2);
}

void test_parse_inventory_network_invalid_query(void **state)
{
    (void) state;

    char * input1 = strdup("agent 000 inventory network");
    char * output1 = calloc(1, OS_MAXSTR + 1);
    *output1 = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory network");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid inventory query syntax: network");

    int ret = wdb_parse(input1, output1);

    assert_int_equal(ret, -1);
    assert_string_equal(output1, "err Invalid inventory query syntax, near 'network'");

    free(input1);
    free(output1);

    char * input2 = strdup("agent 000 inventory network save");
    char * output2 = calloc(1, OS_MAXSTR + 1);
    *output2 = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory network save");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid inventory query syntax: save");

    ret = wdb_parse(input2, output2);

    assert_int_equal(ret, -1);
    assert_string_equal(output2, "err Invalid inventory query syntax, near 'save'");

    free(input2);
    free(output2);

    char * input3 = strdup("agent 000 inventory network create {}");
    char * output3 = calloc(1, OS_MAXSTR + 1);
    *output3 = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory network create {}");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid inventory query syntax: create");

    ret = wdb_parse(input3, output3);

    assert_int_equal(ret, -1);
    assert_string_equal(output3, "err Invalid inventory query syntax, near 'create'");

    free(input3);
    free(output3);
}

void test_parse_inventory_network_save(void **state)
{
    (void) state;

    char * input = strdup("agent 000 inventory network save {\"type\":\"added\"}");
    char * output = calloc(1, OS_MAXSTR + 1);
    *output = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory network save {\"type\":\"added\"}");

    expect_string(__wrap_wdb_inventory_save_network, payload, "{\"type\":\"added\"}");
    will_return(__wrap_wdb_inventory_save_network, 0);

    int ret = wdb_parse(input, output);

    assert_int_equal(ret, 0);
    assert_string_equal(output, "ok");

    free(input);
    free(output);
}

void test_parse_inventory_network_save_error(void **state)
{
    (void) state;

    char * input = strdup("agent 000 inventory network save {\"type\":\"added\"}");
    char * output = calloc(1, OS_MAXSTR + 1);
    *output = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap_wdb_inventory_save_network, payload, "{\"type\":\"added\"}");
    will_return(__wrap_wdb_inventory_save_network, -1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory network save {\"type\":\"added\"}");
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot save network information.");

    int ret = wdb_parse(input, output);

    assert_int_equal(ret, -1);
    assert_string_equal(output, "err Cannot save network information.");

    free(input);
    free(output);
}

void test_parse_inventory_network_delete(void **state)
{
    (void) state;

    char * input = strdup("agent 000 inventory network delete {\"type\":\"deleted\"}");
    char * output = calloc(1, OS_MAXSTR + 1);
    *output = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory network delete {\"type\":\"deleted\"}");

    expect_string(__wrap_wdb_inventory_delete_network, payload, "{\"type\":\"deleted\"}");
    will_return(__wrap_wdb_inventory_delete_network, 0);

    int ret = wdb_parse(input, output);

    assert_int_equal(ret, 0);
    assert_string_equal(output, "ok");

    free(input);
    free(output);
}

void test_parse_inventory_network_delete_error(void **state)
{
    (void) state;

    char * input = strdup("agent 000 inventory network delete {\"type\":\"deleted\"}");
    char * output = calloc(1, OS_MAXSTR + 1);
    *output = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap_wdb_inventory_delete_network, payload, "{\"type\":\"deleted\"}");
    will_return(__wrap_wdb_inventory_delete_network, -1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory network delete {\"type\":\"deleted\"}");
    expect_string(__wrap__mdebug1, formatted_msg, "Cannot delete old network information.");

    int ret = wdb_parse(input, output);

    assert_int_equal(ret, -1);
    assert_string_equal(output, "err Cannot delete old network information.");

    free(input);
    free(output);
}

void test_parse_inventory_os_invalid_query(void **state)
{
    (void) state;

    char * input1 = strdup("agent 000 inventory OS");
    char * output1 = calloc(1, OS_MAXSTR + 1);
    *output1 = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory OS");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid inventory query syntax: OS");

    int ret = wdb_parse(input1, output1);

    assert_int_equal(ret, -1);
    assert_string_equal(output1, "err Invalid inventory query syntax, near 'OS'");

    free(input1);
    free(output1);

    char * input2 = strdup("agent 000 inventory OS save");
    char * output2 = calloc(1, OS_MAXSTR + 1);
    *output2 = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory OS save");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid inventory query syntax: save");

    ret = wdb_parse(input2, output2);

    assert_int_equal(ret, -1);
    assert_string_equal(output2, "err Invalid inventory query syntax, near 'save'");

    free(input2);
    free(output2);

    char * input3 = strdup("agent 000 inventory OS install {}");
    char * output3 = calloc(1, OS_MAXSTR + 1);
    *output3 = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory OS install {}");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid inventory query syntax: install");

    ret = wdb_parse(input3, output3);

    assert_int_equal(ret, -1);
    assert_string_equal(output3, "err Invalid inventory query syntax, near 'install'");

    free(input3);
    free(output3);
}

void test_parse_inventory_os_save(void **state)
{
    (void) state;

    char * input = strdup("agent 000 inventory OS save {\"type\":\"modified\"}");
    char * output = calloc(1, OS_MAXSTR + 1);
    *output = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory OS save {\"type\":\"modified\"}");

    expect_string(__wrap_wdb_inventory_save_os, payload, "{\"type\":\"modified\"}");
    will_return(__wrap_wdb_inventory_save_os, 0);

    int ret = wdb_parse(input, output);

    assert_int_equal(ret, 0);
    assert_string_equal(output, "ok");

    free(input);
    free(output);
}

void test_parse_inventory_os_save_error(void **state)
{
    (void) state;

    char * input = strdup("agent 000 inventory OS save {\"type\":\"modified\"}");
    char * output = calloc(1, OS_MAXSTR + 1);
    *output = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory OS save {\"type\":\"modified\"}");

    expect_string(__wrap_wdb_inventory_save_os, payload, "{\"type\":\"modified\"}");
    will_return(__wrap_wdb_inventory_save_os, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Cannot save OS information.");

    int ret = wdb_parse(input, output);

    assert_int_equal(ret, -1);
    assert_string_equal(output, "err Cannot save OS information.");

    free(input);
    free(output);
}

void test_parse_inventory_hw_invalid_query(void **state)
{
    (void) state;

    char * input1 = strdup("agent 000 inventory hardware");
    char * output1 = calloc(1, OS_MAXSTR + 1);
    *output1 = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory hardware");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid inventory query syntax: hardware");

    int ret = wdb_parse(input1, output1);

    assert_int_equal(ret, -1);
    assert_string_equal(output1, "err Invalid inventory query syntax, near 'hardware'");

    free(input1);
    free(output1);

    char * input2 = strdup("agent 000 inventory hardware save");
    char * output2 = calloc(1, OS_MAXSTR + 1);
    *output2 = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory hardware save");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid inventory query syntax: save");

    ret = wdb_parse(input2, output2);

    assert_int_equal(ret, -1);
    assert_string_equal(output2, "err Invalid inventory query syntax, near 'save'");

    free(input2);
    free(output2);

    char * input3 = strdup("agent 000 inventory hardware add {}");
    char * output3 = calloc(1, OS_MAXSTR + 1);
    *output3 = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory hardware add {}");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid inventory query syntax: add");

    ret = wdb_parse(input3, output3);

    assert_int_equal(ret, -1);
    assert_string_equal(output3, "err Invalid inventory query syntax, near 'add'");

    free(input3);
    free(output3);
}

void test_parse_inventory_hw_save(void **state)
{
    (void) state;

    char * input = strdup("agent 000 inventory hardware save {\"type\":\"added\"}");
    char * output = calloc(1, OS_MAXSTR + 1);
    *output = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory hardware save {\"type\":\"added\"}");

    expect_string(__wrap_wdb_inventory_save_hw, payload, "{\"type\":\"added\"}");
    will_return(__wrap_wdb_inventory_save_hw, 0);

    int ret = wdb_parse(input, output);

    assert_int_equal(ret, 0);
    assert_string_equal(output, "ok");

    free(input);
    free(output);
}

void test_parse_inventory_hw_save_error(void **state)
{
    (void) state;

    char * input = strdup("agent 000 inventory hardware save {\"type\":\"added\"}");
    char * output = calloc(1, OS_MAXSTR + 1);
    *output = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory hardware save {\"type\":\"added\"}");

    expect_string(__wrap_wdb_inventory_save_hw, payload, "{\"type\":\"added\"}");
    will_return(__wrap_wdb_inventory_save_hw, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Cannot save HW information.");

    int ret = wdb_parse(input, output);

    assert_int_equal(ret, -1);
    assert_string_equal(output, "err Cannot save HW information.");

    free(input);
    free(output);
}

void test_parse_inventory_program_invalid_query(void **state)
{
    (void) state;

    char * input1 = strdup("agent 000 inventory program");
    char * output1 = calloc(1, OS_MAXSTR + 1);
    *output1 = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory program");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid inventory query syntax: program");

    int ret = wdb_parse(input1, output1);

    assert_int_equal(ret, -1);
    assert_string_equal(output1, "err Invalid inventory query syntax, near 'program'");

    free(input1);
    free(output1);

    char * input2 = strdup("agent 000 inventory program save");
    char * output2 = calloc(1, OS_MAXSTR + 1);
    *output2 = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory program save");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid inventory query syntax: save");

    ret = wdb_parse(input2, output2);

    assert_int_equal(ret, -1);
    assert_string_equal(output2, "err Invalid inventory query syntax, near 'save'");

    free(input2);
    free(output2);

    char * input3 = strdup("agent 000 inventory program update {}");
    char * output3 = calloc(1, OS_MAXSTR + 1);
    *output3 = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory program update {}");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid inventory query syntax: update");

    ret = wdb_parse(input3, output3);

    assert_int_equal(ret, -1);
    assert_string_equal(output3, "err Invalid inventory query syntax, near 'update'");

    free(input3);
    free(output3);
}

void test_parse_inventory_program_save(void **state)
{
    (void) state;

    char * input = strdup("agent 000 inventory program save {\"type\":\"modified\"}");
    char * output = calloc(1, OS_MAXSTR + 1);
    *output = '\0';

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory program save {\"type\":\"modified\"}");

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap_wdb_inventory_save_program, payload, "{\"type\":\"modified\"}");
    will_return(__wrap_wdb_inventory_save_program, 0);

    int ret = wdb_parse(input, output);

    assert_int_equal(ret, 0);
    assert_string_equal(output, "ok");

    free(input);
    free(output);
}

void test_parse_inventory_program_save_error(void **state)
{
    (void) state;

    char * input = strdup("agent 000 inventory program save {\"type\":\"added\"}");
    char * output = calloc(1, OS_MAXSTR + 1);
    *output = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory program save {\"type\":\"added\"}");

    expect_string(__wrap_wdb_inventory_save_program, payload, "{\"type\":\"added\"}");
    will_return(__wrap_wdb_inventory_save_program, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Cannot save program information.");

    int ret = wdb_parse(input, output);

    assert_int_equal(ret, -1);
    assert_string_equal(output, "err Cannot save program information.");

    free(input);
    free(output);
}

void test_parse_inventory_program_delete(void **state)
{
    (void) state;

    char * input = strdup("agent 000 inventory program delete {\"type\":\"deleted\"}");
    char * output = calloc(1, OS_MAXSTR + 1);
    *output = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory program delete {\"type\":\"deleted\"}");

    expect_string(__wrap_wdb_inventory_delete_program, payload, "{\"type\":\"deleted\"}");
    will_return(__wrap_wdb_inventory_delete_program, 0);

    int ret = wdb_parse(input, output);

    assert_int_equal(ret, 0);
    assert_string_equal(output, "ok");

    free(input);
    free(output);
}

void test_parse_inventory_program_delete_error(void **state)
{
    (void) state;

    char * input = strdup("agent 000 inventory program delete {\"type\":\"deleted\"}");
    char * output = calloc(1, OS_MAXSTR + 1);
    *output = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory program delete {\"type\":\"deleted\"}");

    expect_string(__wrap_wdb_inventory_delete_program, payload, "{\"type\":\"deleted\"}");
    will_return(__wrap_wdb_inventory_delete_program, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Cannot delete old program information.");

    int ret = wdb_parse(input, output);

    assert_int_equal(ret, -1);
    assert_string_equal(output, "err Cannot delete old program information.");

    free(input);
    free(output);
}

void test_parse_inventory_hotfix_invalid_query(void **state)
{
    (void) state;

    char * input1 = strdup("agent 000 inventory hotfix");
    char * output1 = calloc(1, OS_MAXSTR + 1);
    *output1 = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory hotfix");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid inventory query syntax: hotfix");

    int ret = wdb_parse(input1, output1);

    assert_int_equal(ret, -1);
    assert_string_equal(output1, "err Invalid inventory query syntax, near 'hotfix'");

    free(input1);
    free(output1);

    char * input2 = strdup("agent 000 inventory hotfix save");
    char * output2 = calloc(1, OS_MAXSTR + 1);
    *output2 = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory hotfix save");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid inventory query syntax: save");

    ret = wdb_parse(input2, output2);

    assert_int_equal(ret, -1);
    assert_string_equal(output2, "err Invalid inventory query syntax, near 'save'");

    free(input2);
    free(output2);

    char * input3 = strdup("agent 000 inventory hotfix upgrade {}");
    char * output3 = calloc(1, OS_MAXSTR + 1);
    *output3 = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory hotfix upgrade {}");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid inventory query syntax: upgrade");

    ret = wdb_parse(input3, output3);

    assert_int_equal(ret, -1);
    assert_string_equal(output3, "err Invalid inventory query syntax, near 'upgrade'");

    free(input3);
    free(output3);
}

void test_parse_inventory_hotfix_save(void **state)
{
    (void) state;

    char * input = strdup("agent 000 inventory hotfix save {\"type\":\"added\"}");
    char * output = calloc(1, OS_MAXSTR + 1);
    *output = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory hotfix save {\"type\":\"added\"}");

    expect_string(__wrap_wdb_inventory_save_hotfix, payload, "{\"type\":\"added\"}");
    will_return(__wrap_wdb_inventory_save_hotfix, 0);

    int ret = wdb_parse(input, output);

    assert_int_equal(ret, 0);
    assert_string_equal(output, "ok");

    free(input);
    free(output);
}

void test_parse_inventory_hotfix_save_error(void **state)
{
    (void) state;

    char * input = strdup("agent 000 inventory hotfix save {\"type\":\"added\"}");
    char * output = calloc(1, OS_MAXSTR + 1);
    *output = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory hotfix save {\"type\":\"added\"}");

    expect_string(__wrap_wdb_inventory_save_hotfix, payload, "{\"type\":\"added\"}");
    will_return(__wrap_wdb_inventory_save_hotfix, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Cannot save hotfix information.");

    int ret = wdb_parse(input, output);

    assert_int_equal(ret, -1);
    assert_string_equal(output, "err Cannot save hotfix information.");

    free(input);
    free(output);
}

void test_parse_inventory_hotfix_delete(void **state)
{
    (void) state;

    char * input = strdup("agent 000 inventory hotfix delete {\"type\":\"deleted\"}");
    char * output = calloc(1, OS_MAXSTR + 1);
    *output = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory hotfix delete {\"type\":\"deleted\"}");

    expect_string(__wrap_wdb_inventory_delete_hotfix, payload, "{\"type\":\"deleted\"}");
    will_return(__wrap_wdb_inventory_delete_hotfix, 0);

    int ret = wdb_parse(input, output);

    assert_int_equal(ret, 0);
    assert_string_equal(output, "ok");

    free(input);
    free(output);
}

void test_parse_inventory_hotfix_delete_error(void **state)
{
    (void) state;

    char * input = strdup("agent 000 inventory hotfix delete {\"type\":\"deleted\"}");
    char * output = calloc(1, OS_MAXSTR + 1);
    *output = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory hotfix delete {\"type\":\"deleted\"}");

    expect_string(__wrap_wdb_inventory_delete_hotfix, payload, "{\"type\":\"deleted\"}");
    will_return(__wrap_wdb_inventory_delete_hotfix, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Cannot delete old hotfix information.");

    int ret = wdb_parse(input, output);

    assert_int_equal(ret, -1);
    assert_string_equal(output, "err Cannot delete old hotfix information.");

    free(input);
    free(output);
}

void test_parse_inventory_port_invalid_query(void **state)
{
    (void) state;

    char * input1 = strdup("agent 000 inventory port");
    char * output1 = calloc(1, OS_MAXSTR + 1);
    *output1 = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory port");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid inventory query syntax: port");

    int ret = wdb_parse(input1, output1);

    assert_int_equal(ret, -1);
    assert_string_equal(output1, "err Invalid inventory query syntax, near 'port'");

    free(input1);
    free(output1);

    char * input2 = strdup("agent 000 inventory port save");
    char * output2 = calloc(1, OS_MAXSTR + 1);
    *output2 = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory port save");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid inventory query syntax: save");

    ret = wdb_parse(input2, output2);

    assert_int_equal(ret, -1);
    assert_string_equal(output2, "err Invalid inventory query syntax, near 'save'");

    free(input2);
    free(output2);

    char * input3 = strdup("agent 000 inventory port open {}");
    char * output3 = calloc(1, OS_MAXSTR + 1);
    *output3 = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory port open {}");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid inventory query syntax: open");

    ret = wdb_parse(input3, output3);

    assert_int_equal(ret, -1);
    assert_string_equal(output3, "err Invalid inventory query syntax, near 'open'");

    free(input3);
    free(output3);
}

void test_parse_inventory_port_save(void **state)
{
    (void) state;

    char * input = strdup("agent 000 inventory port save {\"type\":\"modified\"}");
    char * output = calloc(1, OS_MAXSTR + 1);
    *output = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory port save {\"type\":\"modified\"}");

    expect_string(__wrap_wdb_inventory_save_port, payload, "{\"type\":\"modified\"}");
    will_return(__wrap_wdb_inventory_save_port, 0);

    int ret = wdb_parse(input, output);

    assert_int_equal(ret, 0);
    assert_string_equal(output, "ok");

    free(input);
    free(output);
}

void test_parse_inventory_port_save_error(void **state)
{
    (void) state;

    char * input = strdup("agent 000 inventory port save {\"type\":\"added\"}");
    char * output = calloc(1, OS_MAXSTR + 1);
    *output = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory port save {\"type\":\"added\"}");

    expect_string(__wrap_wdb_inventory_save_port, payload, "{\"type\":\"added\"}");
    will_return(__wrap_wdb_inventory_save_port, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Cannot save port information.");

    int ret = wdb_parse(input, output);

    assert_int_equal(ret, -1);
    assert_string_equal(output, "err Cannot save port information.");

    free(input);
    free(output);
}

void test_parse_inventory_port_delete(void **state)
{
    (void) state;

    char * input = strdup("agent 000 inventory port delete {\"type\":\"deleted\"}");
    char * output = calloc(1, OS_MAXSTR + 1);
    *output = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory port delete {\"type\":\"deleted\"}");

    expect_string(__wrap_wdb_inventory_delete_port, payload, "{\"type\":\"deleted\"}");
    will_return(__wrap_wdb_inventory_delete_port, 0);

    int ret = wdb_parse(input, output);

    assert_int_equal(ret, 0);
    assert_string_equal(output, "ok");

    free(input);
    free(output);
}

void test_parse_inventory_port_delete_error(void **state)
{
    (void) state;

    char * input = strdup("agent 000 inventory port delete {\"type\":\"deleted\"}");
    char * output = calloc(1, OS_MAXSTR + 1);
    *output = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory port delete {\"type\":\"deleted\"}");

    expect_string(__wrap_wdb_inventory_delete_port, payload, "{\"type\":\"deleted\"}");
    will_return(__wrap_wdb_inventory_delete_port, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Cannot delete old port information.");

    int ret = wdb_parse(input, output);

    assert_int_equal(ret, -1);
    assert_string_equal(output, "err Cannot delete old port information.");

    free(input);
    free(output);
}

void test_parse_inventory_process_invalid_query(void **state)
{
    (void) state;

    char * input1 = strdup("agent 000 inventory process");
    char * output1 = calloc(1, OS_MAXSTR + 1);
    *output1 = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory process");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid inventory query syntax: process");

    int ret = wdb_parse(input1, output1);

    assert_int_equal(ret, -1);
    assert_string_equal(output1, "err Invalid inventory query syntax, near 'process'");

    free(input1);
    free(output1);

    char * input2 = strdup("agent 000 inventory process save");
    char * output2 = calloc(1, OS_MAXSTR + 1);
    *output2 = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory process save");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid inventory query syntax: save");

    ret = wdb_parse(input2, output2);

    assert_int_equal(ret, -1);
    assert_string_equal(output2, "err Invalid inventory query syntax, near 'save'");

    free(input2);
    free(output2);

    char * input3 = strdup("agent 000 inventory process start {}");
    char * output3 = calloc(1, OS_MAXSTR + 1);
    *output3 = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory process start {}");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid inventory query syntax: start");

    ret = wdb_parse(input3, output3);

    assert_int_equal(ret, -1);
    assert_string_equal(output3, "err Invalid inventory query syntax, near 'start'");

    free(input3);
    free(output3);
}

void test_parse_inventory_process_save(void **state)
{
    (void) state;

    char * input = strdup("agent 000 inventory process save {\"type\":\"added\"}");
    char * output = calloc(1, OS_MAXSTR + 1);
    *output = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory process save {\"type\":\"added\"}");

    expect_string(__wrap_wdb_inventory_save_process, payload, "{\"type\":\"added\"}");
    will_return(__wrap_wdb_inventory_save_process, 0);

    int ret = wdb_parse(input, output);

    assert_int_equal(ret, 0);
    assert_string_equal(output, "ok");

    free(input);
    free(output);
}

void test_parse_inventory_process_save_error(void **state)
{
    (void) state;

    char * input = strdup("agent 000 inventory process save {\"type\":\"added\"}");
    char * output = calloc(1, OS_MAXSTR + 1);
    *output = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory process save {\"type\":\"added\"}");

    expect_string(__wrap_wdb_inventory_save_process, payload, "{\"type\":\"added\"}");
    will_return(__wrap_wdb_inventory_save_process, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Cannot save process information.");

    int ret = wdb_parse(input, output);

    assert_int_equal(ret, -1);
    assert_string_equal(output, "err Cannot save process information.");

    free(input);
    free(output);
}

void test_parse_inventory_process_delete(void **state)
{
    (void) state;

    char * input = strdup("agent 000 inventory process delete {\"type\":\"deleted\"}");
    char * output = calloc(1, OS_MAXSTR + 1);
    *output = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory process delete {\"type\":\"deleted\"}");

    expect_string(__wrap_wdb_inventory_delete_process, payload, "{\"type\":\"deleted\"}");
    will_return(__wrap_wdb_inventory_delete_process, 0);

    int ret = wdb_parse(input, output);

    assert_int_equal(ret, 0);
    assert_string_equal(output, "ok");

    free(input);
    free(output);
}

void test_parse_inventory_process_delete_error(void **state)
{
    (void) state;

    char * input = strdup("agent 000 inventory process delete {\"type\":\"deleted\"}");
    char * output = calloc(1, OS_MAXSTR + 1);
    *output = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory process delete {\"type\":\"deleted\"}");

    expect_string(__wrap_wdb_inventory_delete_process, payload, "{\"type\":\"deleted\"}");
    will_return(__wrap_wdb_inventory_delete_process, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Cannot delete old process information.");

    int ret = wdb_parse(input, output);

    assert_int_equal(ret, -1);
    assert_string_equal(output, "err Cannot delete old process information.");

    free(input);
    free(output);
}

void test_parse_inventory_network_scan_invalid_query(void **state)
{
    (void) state;

    char * input1 = strdup("agent 000 inventory network_scan");
    char * output1 = calloc(1, OS_MAXSTR + 1);
    *output1 = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory network_scan");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid inventory query syntax: network_scan");

    int ret = wdb_parse(input1, output1);

    assert_int_equal(ret, -1);
    assert_string_equal(output1, "err Invalid inventory query syntax, near 'network_scan'");

    free(input1);
    free(output1);

    char * input2 = strdup("agent 000 inventory network_scan update");
    char * output2 = calloc(1, OS_MAXSTR + 1);
    *output2 = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory network_scan update");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid inventory query syntax: update");

    ret = wdb_parse(input2, output2);

    assert_int_equal(ret, -1);
    assert_string_equal(output2, "err Invalid inventory query syntax, near 'update'");

    free(input2);
    free(output2);

    char * input3 = strdup("agent 000 inventory network_scan save {}");
    char * output3 = calloc(1, OS_MAXSTR + 1);
    *output3 = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory network_scan save {}");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid inventory query syntax: save");

    ret = wdb_parse(input3, output3);

    assert_int_equal(ret, -1);
    assert_string_equal(output3, "err Invalid inventory query syntax, near 'save'");

    free(input3);
    free(output3);
}

void test_parse_inventory_network_scan_save(void **state)
{
    (void) state;

    char * input = strdup("agent 000 inventory network_scan update {\"timestamp\":12345}");
    char * output = calloc(1, OS_MAXSTR + 1);
    *output = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory network_scan update {\"timestamp\":12345}");

    expect_string(__wrap_wdb_inventory_save_scan_info, inventory, "network");
    expect_string(__wrap_wdb_inventory_save_scan_info, payload, "{\"timestamp\":12345}");
    will_return(__wrap_wdb_inventory_save_scan_info, 0);

    int ret = wdb_parse(input, output);

    assert_int_equal(ret, 0);
    assert_string_equal(output, "ok");

    free(input);
    free(output);
}

void test_parse_inventory_network_scan_save_error(void **state)
{
    (void) state;

    char * input = strdup("agent 000 inventory network_scan update {\"timestamp\":12345}");
    char * output = calloc(1, OS_MAXSTR + 1);
    *output = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory network_scan update {\"timestamp\":12345}");

    expect_string(__wrap_wdb_inventory_save_scan_info, inventory, "network");
    expect_string(__wrap_wdb_inventory_save_scan_info, payload, "{\"timestamp\":12345}");
    will_return(__wrap_wdb_inventory_save_scan_info, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Cannot save network scan information.");

    int ret = wdb_parse(input, output);

    assert_int_equal(ret, -1);
    assert_string_equal(output, "err Cannot save network scan information.");

    free(input);
    free(output);
}

void test_parse_inventory_os_scan_invalid_query(void **state)
{
    (void) state;

    char * input1 = strdup("agent 000 inventory OS_scan");
    char * output1 = calloc(1, OS_MAXSTR + 1);
    *output1 = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory OS_scan");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid inventory query syntax: OS_scan");

    int ret = wdb_parse(input1, output1);

    assert_int_equal(ret, -1);
    assert_string_equal(output1, "err Invalid inventory query syntax, near 'OS_scan'");

    free(input1);
    free(output1);

    char * input2 = strdup("agent 000 inventory OS_scan update");
    char * output2 = calloc(1, OS_MAXSTR + 1);
    *output2 = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory OS_scan update");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid inventory query syntax: update");

    ret = wdb_parse(input2, output2);

    assert_int_equal(ret, -1);
    assert_string_equal(output2, "err Invalid inventory query syntax, near 'update'");

    free(input2);
    free(output2);

    char * input3 = strdup("agent 000 inventory OS_scan save {}");
    char * output3 = calloc(1, OS_MAXSTR + 1);
    *output3 = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory OS_scan save {}");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid inventory query syntax: save");

    ret = wdb_parse(input3, output3);

    assert_int_equal(ret, -1);
    assert_string_equal(output3, "err Invalid inventory query syntax, near 'save'");

    free(input3);
    free(output3);
}

void test_parse_inventory_os_scan_save(void **state)
{
    (void) state;

    char * input = strdup("agent 000 inventory OS_scan update {\"timestamp\":12345}");
    char * output = calloc(1, OS_MAXSTR + 1);
    *output = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory OS_scan update {\"timestamp\":12345}");

    expect_string(__wrap_wdb_inventory_save_scan_info, inventory, "OS");
    expect_string(__wrap_wdb_inventory_save_scan_info, payload, "{\"timestamp\":12345}");
    will_return(__wrap_wdb_inventory_save_scan_info, 0);

    int ret = wdb_parse(input, output);

    assert_int_equal(ret, 0);
    assert_string_equal(output, "ok");

    free(input);
    free(output);
}

void test_parse_inventory_os_scan_save_error(void **state)
{
    (void) state;

    char * input = strdup("agent 000 inventory OS_scan update {\"timestamp\":12345}");
    char * output = calloc(1, OS_MAXSTR + 1);
    *output = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory OS_scan update {\"timestamp\":12345}");

    expect_string(__wrap_wdb_inventory_save_scan_info, inventory, "OS");
    expect_string(__wrap_wdb_inventory_save_scan_info, payload, "{\"timestamp\":12345}");
    will_return(__wrap_wdb_inventory_save_scan_info, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Cannot save OS scan information.");

    int ret = wdb_parse(input, output);

    assert_int_equal(ret, -1);
    assert_string_equal(output, "err Cannot save OS scan information.");

    free(input);
    free(output);
}

void test_parse_inventory_hw_scan_invalid_query(void **state)
{
    (void) state;

    char * input1 = strdup("agent 000 inventory hardware_scan");
    char * output1 = calloc(1, OS_MAXSTR + 1);
    *output1 = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory hardware_scan");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid inventory query syntax: hardware_scan");

    int ret = wdb_parse(input1, output1);

    assert_int_equal(ret, -1);
    assert_string_equal(output1, "err Invalid inventory query syntax, near 'hardware_scan'");

    free(input1);
    free(output1);

    char * input2 = strdup("agent 000 inventory hardware_scan update");
    char * output2 = calloc(1, OS_MAXSTR + 1);
    *output2 = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory hardware_scan update");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid inventory query syntax: update");

    ret = wdb_parse(input2, output2);

    assert_int_equal(ret, -1);
    assert_string_equal(output2, "err Invalid inventory query syntax, near 'update'");

    free(input2);
    free(output2);

    char * input3 = strdup("agent 000 inventory hardware_scan save {}");
    char * output3 = calloc(1, OS_MAXSTR + 1);
    *output3 = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory hardware_scan save {}");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid inventory query syntax: save");

    ret = wdb_parse(input3, output3);

    assert_int_equal(ret, -1);
    assert_string_equal(output3, "err Invalid inventory query syntax, near 'save'");

    free(input3);
    free(output3);
}

void test_parse_inventory_hw_scan_save(void **state)
{
    (void) state;

    char * input = strdup("agent 000 inventory hardware_scan update {\"timestamp\":12345}");
    char * output = calloc(1, OS_MAXSTR + 1);
    *output = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory hardware_scan update {\"timestamp\":12345}");

    expect_string(__wrap_wdb_inventory_save_scan_info, inventory, "hardware");
    expect_string(__wrap_wdb_inventory_save_scan_info, payload, "{\"timestamp\":12345}");
    will_return(__wrap_wdb_inventory_save_scan_info, 0);

    int ret = wdb_parse(input, output);

    assert_int_equal(ret, 0);
    assert_string_equal(output, "ok");

    free(input);
    free(output);
}

void test_parse_inventory_hw_scan_save_error(void **state)
{
    (void) state;

    char * input = strdup("agent 000 inventory hardware_scan update {\"timestamp\":12345}");
    char * output = calloc(1, OS_MAXSTR + 1);
    *output = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory hardware_scan update {\"timestamp\":12345}");

    expect_string(__wrap_wdb_inventory_save_scan_info, inventory, "hardware");
    expect_string(__wrap_wdb_inventory_save_scan_info, payload, "{\"timestamp\":12345}");
    will_return(__wrap_wdb_inventory_save_scan_info, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Cannot save hardware scan information.");

    int ret = wdb_parse(input, output);

    assert_int_equal(ret, -1);
    assert_string_equal(output, "err Cannot save hardware scan information.");

    free(input);
    free(output);
}

void test_parse_inventory_program_scan_invalid_query(void **state)
{
    (void) state;

    char * input1 = strdup("agent 000 inventory program_scan");
    char * output1 = calloc(1, OS_MAXSTR + 1);
    *output1 = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory program_scan");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid inventory query syntax: program_scan");

    int ret = wdb_parse(input1, output1);

    assert_int_equal(ret, -1);
    assert_string_equal(output1, "err Invalid inventory query syntax, near 'program_scan'");

    free(input1);
    free(output1);

    char * input2 = strdup("agent 000 inventory program_scan update");
    char * output2 = calloc(1, OS_MAXSTR + 1);
    *output2 = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory program_scan update");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid inventory query syntax: update");

    ret = wdb_parse(input2, output2);

    assert_int_equal(ret, -1);
    assert_string_equal(output2, "err Invalid inventory query syntax, near 'update'");

    free(input2);
    free(output2);

    char * input3 = strdup("agent 000 inventory program_scan save {}");
    char * output3 = calloc(1, OS_MAXSTR + 1);
    *output3 = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory program_scan save {}");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid inventory query syntax: save");

    ret = wdb_parse(input3, output3);

    assert_int_equal(ret, -1);
    assert_string_equal(output3, "err Invalid inventory query syntax, near 'save'");

    free(input3);
    free(output3);
}

void test_parse_inventory_program_scan_save(void **state)
{
    (void) state;

    char * input = strdup("agent 000 inventory program_scan update {\"timestamp\":12345}");
    char * output = calloc(1, OS_MAXSTR + 1);
    *output = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory program_scan update {\"timestamp\":12345}");

    expect_string(__wrap_wdb_inventory_save_scan_info, inventory, "program");
    expect_string(__wrap_wdb_inventory_save_scan_info, payload, "{\"timestamp\":12345}");
    will_return(__wrap_wdb_inventory_save_scan_info, 0);

    int ret = wdb_parse(input, output);

    assert_int_equal(ret, 0);
    assert_string_equal(output, "ok");

    free(input);
    free(output);
}

void test_parse_inventory_program_scan_save_error(void **state)
{
    (void) state;

    char * input = strdup("agent 000 inventory program_scan update {\"timestamp\":12345}");
    char * output = calloc(1, OS_MAXSTR + 1);
    *output = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory program_scan update {\"timestamp\":12345}");

    expect_string(__wrap_wdb_inventory_save_scan_info, inventory, "program");
    expect_string(__wrap_wdb_inventory_save_scan_info, payload, "{\"timestamp\":12345}");
    will_return(__wrap_wdb_inventory_save_scan_info, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Cannot save program scan information.");

    int ret = wdb_parse(input, output);

    assert_int_equal(ret, -1);
    assert_string_equal(output, "err Cannot save program scan information.");

    free(input);
    free(output);
}

void test_parse_inventory_hotfix_scan_invalid_query(void **state)
{
    (void) state;

    char * input1 = strdup("agent 000 inventory hotfix_scan");
    char * output1 = calloc(1, OS_MAXSTR + 1);
    *output1 = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory hotfix_scan");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid inventory query syntax: hotfix_scan");

    int ret = wdb_parse(input1, output1);

    assert_int_equal(ret, -1);
    assert_string_equal(output1, "err Invalid inventory query syntax, near 'hotfix_scan'");

    free(input1);
    free(output1);

    char * input2 = strdup("agent 000 inventory hotfix_scan update");
    char * output2 = calloc(1, OS_MAXSTR + 1);
    *output2 = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory hotfix_scan update");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid inventory query syntax: update");

    ret = wdb_parse(input2, output2);

    assert_int_equal(ret, -1);
    assert_string_equal(output2, "err Invalid inventory query syntax, near 'update'");

    free(input2);
    free(output2);

    char * input3 = strdup("agent 000 inventory hotfix_scan save {}");
    char * output3 = calloc(1, OS_MAXSTR + 1);
    *output3 = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory hotfix_scan save {}");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid inventory query syntax: save");

    ret = wdb_parse(input3, output3);

    assert_int_equal(ret, -1);
    assert_string_equal(output3, "err Invalid inventory query syntax, near 'save'");

    free(input3);
    free(output3);
}

void test_parse_inventory_hotfix_scan_save(void **state)
{
    (void) state;

    char * input = strdup("agent 000 inventory hotfix_scan update {\"timestamp\":12345}");
    char * output = calloc(1, OS_MAXSTR + 1);
    *output = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory hotfix_scan update {\"timestamp\":12345}");

    expect_string(__wrap_wdb_inventory_save_scan_info, inventory, "hotfix");
    expect_string(__wrap_wdb_inventory_save_scan_info, payload, "{\"timestamp\":12345}");
    will_return(__wrap_wdb_inventory_save_scan_info, 0);

    int ret = wdb_parse(input, output);

    assert_int_equal(ret, 0);
    assert_string_equal(output, "ok");

    free(input);
    free(output);
}

void test_parse_inventory_hotfix_scan_save_error(void **state)
{
    (void) state;

    char * input = strdup("agent 000 inventory hotfix_scan update {\"timestamp\":12345}");
    char * output = calloc(1, OS_MAXSTR + 1);
    *output = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory hotfix_scan update {\"timestamp\":12345}");

    expect_string(__wrap_wdb_inventory_save_scan_info, inventory, "hotfix");
    expect_string(__wrap_wdb_inventory_save_scan_info, payload, "{\"timestamp\":12345}");
    will_return(__wrap_wdb_inventory_save_scan_info, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Cannot save hotfix scan information.");

    int ret = wdb_parse(input, output);

    assert_int_equal(ret, -1);
    assert_string_equal(output, "err Cannot save hotfix scan information.");

    free(input);
    free(output);
}

void test_parse_inventory_port_scan_invalid_query(void **state)
{
    (void) state;

    char * input1 = strdup("agent 000 inventory port_scan");
    char * output1 = calloc(1, OS_MAXSTR + 1);
    *output1 = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory port_scan");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid inventory query syntax: port_scan");

    int ret = wdb_parse(input1, output1);

    assert_int_equal(ret, -1);
    assert_string_equal(output1, "err Invalid inventory query syntax, near 'port_scan'");

    free(input1);
    free(output1);

    char * input2 = strdup("agent 000 inventory port_scan update");
    char * output2 = calloc(1, OS_MAXSTR + 1);
    *output2 = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory port_scan update");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid inventory query syntax: update");

    ret = wdb_parse(input2, output2);

    assert_int_equal(ret, -1);
    assert_string_equal(output2, "err Invalid inventory query syntax, near 'update'");

    free(input2);
    free(output2);

    char * input3 = strdup("agent 000 inventory port_scan save {}");
    char * output3 = calloc(1, OS_MAXSTR + 1);
    *output3 = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory port_scan save {}");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid inventory query syntax: save");

    ret = wdb_parse(input3, output3);

    assert_int_equal(ret, -1);
    assert_string_equal(output3, "err Invalid inventory query syntax, near 'save'");

    free(input3);
    free(output3);
}

void test_parse_inventory_port_scan_save(void **state)
{
    (void) state;

    char * input = strdup("agent 000 inventory port_scan update {\"timestamp\":12345}");
    char * output = calloc(1, OS_MAXSTR + 1);
    *output = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory port_scan update {\"timestamp\":12345}");

    expect_string(__wrap_wdb_inventory_save_scan_info, inventory, "port");
    expect_string(__wrap_wdb_inventory_save_scan_info, payload, "{\"timestamp\":12345}");
    will_return(__wrap_wdb_inventory_save_scan_info, 0);

    int ret = wdb_parse(input, output);

    assert_int_equal(ret, 0);
    assert_string_equal(output, "ok");

    free(input);
    free(output);
}

void test_parse_inventory_port_scan_save_error(void **state)
{
    (void) state;

    char * input = strdup("agent 000 inventory port_scan update {\"timestamp\":12345}");
    char * output = calloc(1, OS_MAXSTR + 1);
    *output = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory port_scan update {\"timestamp\":12345}");

    expect_string(__wrap_wdb_inventory_save_scan_info, inventory, "port");
    expect_string(__wrap_wdb_inventory_save_scan_info, payload, "{\"timestamp\":12345}");
    will_return(__wrap_wdb_inventory_save_scan_info, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Cannot save port scan information.");

    int ret = wdb_parse(input, output);

    assert_int_equal(ret, -1);
    assert_string_equal(output, "err Cannot save port scan information.");

    free(input);
    free(output);
}

void test_parse_inventory_process_scan_invalid_query(void **state)
{
    (void) state;

    char * input1 = strdup("agent 000 inventory process_scan");
    char * output1 = calloc(1, OS_MAXSTR + 1);
    *output1 = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory process_scan");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid inventory query syntax: process_scan");

    int ret = wdb_parse(input1, output1);

    assert_int_equal(ret, -1);
    assert_string_equal(output1, "err Invalid inventory query syntax, near 'process_scan'");

    free(input1);
    free(output1);

    char * input2 = strdup("agent 000 inventory process_scan update");
    char * output2 = calloc(1, OS_MAXSTR + 1);
    *output2 = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory process_scan update");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid inventory query syntax: update");

    ret = wdb_parse(input2, output2);

    assert_int_equal(ret, -1);
    assert_string_equal(output2, "err Invalid inventory query syntax, near 'update'");

    free(input2);
    free(output2);

    char * input3 = strdup("agent 000 inventory process_scan save {}");
    char * output3 = calloc(1, OS_MAXSTR + 1);
    *output3 = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory process_scan save {}");
    expect_string(__wrap__mdebug1, formatted_msg, "DB(000) Invalid inventory query syntax: save");

    ret = wdb_parse(input3, output3);

    assert_int_equal(ret, -1);
    assert_string_equal(output3, "err Invalid inventory query syntax, near 'save'");

    free(input3);
    free(output3);
}

void test_parse_inventory_process_scan_save(void **state)
{
    (void) state;

    char * input = strdup("agent 000 inventory process_scan update {\"timestamp\":12345}");
    char * output = calloc(1, OS_MAXSTR + 1);
    *output = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory process_scan update {\"timestamp\":12345}");

    expect_string(__wrap_wdb_inventory_save_scan_info, inventory, "process");
    expect_string(__wrap_wdb_inventory_save_scan_info, payload, "{\"timestamp\":12345}");
    will_return(__wrap_wdb_inventory_save_scan_info, 0);

    int ret = wdb_parse(input, output);

    assert_int_equal(ret, 0);
    assert_string_equal(output, "ok");

    free(input);
    free(output);
}

void test_parse_inventory_process_scan_save_error(void **state)
{
    (void) state;

    char * input = strdup("agent 000 inventory process_scan update {\"timestamp\":12345}");
    char * output = calloc(1, OS_MAXSTR + 1);
    *output = '\0';

    will_return(__wrap_wdb_open_agent2, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "Agent 000 query: inventory process_scan update {\"timestamp\":12345}");

    expect_string(__wrap_wdb_inventory_save_scan_info, inventory, "process");
    expect_string(__wrap_wdb_inventory_save_scan_info, payload, "{\"timestamp\":12345}");
    will_return(__wrap_wdb_inventory_save_scan_info, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Cannot save process scan information.");

    int ret = wdb_parse(input, output);

    assert_int_equal(ret, -1);
    assert_string_equal(output, "err Cannot save process scan information.");

    free(input);
    free(output);
}

void test_wdb_parse_rootcheck_badquery(void **state)
{
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("badquery ");
    expect_string(__wrap__mdebug2, formatted_msg, "DB(000) Invalid rootcheck query syntax: badquery");
    ret = wdb_parse_rootcheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid rootcheck query syntax, near 'badquery'");
    assert_int_equal(ret, -1);
    os_free(query);
}

void test_wdb_parse_rootcheck_delete_error(void **state)
{
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("delete");
    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__merror, formatted_msg, "DB(000) Cannot cache statement");

    ret = wdb_parse_rootcheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Error deleting rootcheck PM tuple");
    assert_int_equal(ret, -1);
    os_free(query);
}

void test_wdb_parse_rootcheck_delete_ok(void **state)
{
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("delete");
    will_return(__wrap_wdb_stmt_cache, 0);
    will_return(__wrap_wdb_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_changes, 10);

    ret = wdb_parse_rootcheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok 0");
    assert_int_equal(ret, 0);
    os_free(query);
}

void test_wdb_parse_rootcheck_save_invalid_no_next(void **state)
{
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("save");
    expect_string(__wrap__mdebug2, formatted_msg, "DB(000) Invalid rootcheck query syntax: save");
    ret = wdb_parse_rootcheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid rootcheck query syntax, near 'save'");
    assert_int_equal(ret, -1);
    os_free(query);
}

void test_wdb_parse_rootcheck_save_no_ptr(void **state)
{
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("save ");
    expect_string(__wrap__mdebug2, formatted_msg, "DB(000) Invalid rootcheck query syntax: save");
    ret = wdb_parse_rootcheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid rootcheck query syntax, near 'save'");
    assert_int_equal(ret, -1);
    os_free(query);
}

void test_wdb_parse_rootcheck_save_date_max_long(void **state)
{
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("save 9223372036854775807 asdasd");
    expect_string(__wrap__mdebug2, formatted_msg, "DB(000) Invalid rootcheck date timestamp: 9223372036854775807");
    ret = wdb_parse_rootcheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Invalid rootcheck query syntax, near 'save'");
    assert_int_equal(ret, -1);
    os_free(query);
}

void test_wdb_parse_rootcheck_save_update_cache_error(void **state)
{
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("save 123456789 Test");

    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__merror, formatted_msg, "DB(000) Cannot cache statement");

    expect_string(__wrap__merror, formatted_msg, "DB(000) Error updating rootcheck PM tuple on SQLite database");

    ret = wdb_parse_rootcheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Error updating rootcheck PM tuple");
    assert_int_equal(ret, -1);
    os_free(query);
}

void test_wdb_parse_rootcheck_save_update_success(void **state)
{
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("save 123456789 Test");

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 123456789);
    will_return_always(__wrap_sqlite3_bind_int, 1);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "Test");
    will_return(__wrap_sqlite3_bind_text, 1);
    will_return(__wrap_wdb_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_changes, 10);

    ret = wdb_parse_rootcheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok 1");
    assert_int_equal(ret, 0);
    os_free(query);
}

void test_wdb_parse_rootcheck_save_update_insert_cache_error(void **state)
{
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("save 123456789 Test");

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 123456789);
    will_return_always(__wrap_sqlite3_bind_int, 1);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "Test");
    will_return(__wrap_sqlite3_bind_text, 1);
    will_return(__wrap_wdb_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_changes, 0);

    will_return(__wrap_wdb_stmt_cache, -1);
    expect_string(__wrap__merror, formatted_msg, "DB(000) Cannot cache statement");

    expect_string(__wrap__merror, formatted_msg, "DB(000) Error inserting rootcheck PM tuple on SQLite database for agent");

    ret = wdb_parse_rootcheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "err Error updating rootcheck PM tuple");
    assert_int_equal(ret, -1);
    os_free(query);
}

void test_wdb_parse_rootcheck_save_update_insert_success(void **state)
{
    int ret;
    test_struct_t *data  = (test_struct_t *)*state;
    char *query = strdup("save 123456789 Test");

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 123456789);
    will_return_always(__wrap_sqlite3_bind_int, 1);
    expect_value(__wrap_sqlite3_bind_text, pos, 2);
    expect_string(__wrap_sqlite3_bind_text, buffer, "Test");
    will_return(__wrap_sqlite3_bind_text, 1);
    will_return(__wrap_wdb_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_changes, 0);

    will_return(__wrap_wdb_stmt_cache, 0);
    expect_value(__wrap_sqlite3_bind_int, index, 1);
    expect_value(__wrap_sqlite3_bind_int, value, 123456789);
    expect_value(__wrap_sqlite3_bind_int, index, 2);
    expect_value(__wrap_sqlite3_bind_int, value, 123456789);

    expect_value(__wrap_sqlite3_bind_text, pos, 3);
    expect_string(__wrap_sqlite3_bind_text, buffer, "Test");
    will_return(__wrap_sqlite3_bind_text, 1);
    expect_value(__wrap_sqlite3_bind_text, pos, 4);
    will_return(__wrap_sqlite3_bind_text, 1);
    expect_value(__wrap_sqlite3_bind_text, pos, 5);
    will_return(__wrap_sqlite3_bind_text, 1);
    will_return(__wrap_wdb_step, SQLITE_DONE);
    will_return(__wrap_sqlite3_last_insert_rowid, 10);

    ret = wdb_parse_rootcheck(data->wdb, query, data->output);

    assert_string_equal(data->output, "ok 2");
    assert_int_equal(ret, 0);
    os_free(query);
}



int main()
{
    const struct CMUnitTest tests[] =
    {
        cmocka_unit_test_setup_teardown(test_wdb_parse_syscheck_no_space, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_scan_info_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_scan_info_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_update_info_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_update_info_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_clean_old_entries_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_clean_old_entries_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_scan_info_update_noarg, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_scan_info_update_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_scan_info_update_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_scan_info_fim_check_control_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_scan_info_fim_check_control_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_syscheck_load_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_syscheck_load_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_fim_delete_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_fim_delete_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_syscheck_save_noarg, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_syscheck_save_invalid_type, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_syscheck_save_file_type_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_syscheck_save_file_nospace, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_syscheck_save_file_type_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_syscheck_save_registry_type_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_syscheck_save_registry_type_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_syscheck_save2_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_syscheck_save2_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_integrity_check_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_integrity_check_no_data, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_integrity_check_checksum_fail, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_integrity_check_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_integrity_clear_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_integrity_clear_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_invalid_command, test_setup, test_teardown),
        cmocka_unit_test(test_parse_no_input),
        cmocka_unit_test(test_parse_invalid_actor),
        cmocka_unit_test(test_parse_invalid_agent_id),
        cmocka_unit_test(test_parse_inventory_invalid_type),
        cmocka_unit_test(test_parse_inventory_network_invalid_query),
        cmocka_unit_test(test_parse_inventory_network_save),
        cmocka_unit_test(test_parse_inventory_network_save_error),
        cmocka_unit_test(test_parse_inventory_network_delete),
        cmocka_unit_test(test_parse_inventory_network_delete_error),
        cmocka_unit_test(test_parse_inventory_os_invalid_query),
        cmocka_unit_test(test_parse_inventory_os_save),
        cmocka_unit_test(test_parse_inventory_os_save_error),
        cmocka_unit_test(test_parse_inventory_hw_invalid_query),
        cmocka_unit_test(test_parse_inventory_hw_save),
        cmocka_unit_test(test_parse_inventory_hw_save_error),
        cmocka_unit_test(test_parse_inventory_program_invalid_query),
        cmocka_unit_test(test_parse_inventory_program_save),
        cmocka_unit_test(test_parse_inventory_program_save_error),
        cmocka_unit_test(test_parse_inventory_program_delete),
        cmocka_unit_test(test_parse_inventory_program_delete_error),
        cmocka_unit_test(test_parse_inventory_hotfix_invalid_query),
        cmocka_unit_test(test_parse_inventory_hotfix_save),
        cmocka_unit_test(test_parse_inventory_hotfix_save_error),
        cmocka_unit_test(test_parse_inventory_hotfix_delete),
        cmocka_unit_test(test_parse_inventory_hotfix_delete_error),
        cmocka_unit_test(test_parse_inventory_port_invalid_query),
        cmocka_unit_test(test_parse_inventory_port_save),
        cmocka_unit_test(test_parse_inventory_port_save_error),
        cmocka_unit_test(test_parse_inventory_port_delete),
        cmocka_unit_test(test_parse_inventory_port_delete_error),
        cmocka_unit_test(test_parse_inventory_process_invalid_query),
        cmocka_unit_test(test_parse_inventory_process_save),
        cmocka_unit_test(test_parse_inventory_process_save_error),
        cmocka_unit_test(test_parse_inventory_process_delete),
        cmocka_unit_test(test_parse_inventory_process_delete_error),
        cmocka_unit_test(test_parse_inventory_network_scan_invalid_query),
        cmocka_unit_test(test_parse_inventory_network_scan_save),
        cmocka_unit_test(test_parse_inventory_network_scan_save_error),
        cmocka_unit_test(test_parse_inventory_os_scan_invalid_query),
        cmocka_unit_test(test_parse_inventory_os_scan_save),
        cmocka_unit_test(test_parse_inventory_os_scan_save_error),
        cmocka_unit_test(test_parse_inventory_hw_scan_invalid_query),
        cmocka_unit_test(test_parse_inventory_hw_scan_save),
        cmocka_unit_test(test_parse_inventory_hw_scan_save_error),
        cmocka_unit_test(test_parse_inventory_program_scan_invalid_query),
        cmocka_unit_test(test_parse_inventory_program_scan_save),
        cmocka_unit_test(test_parse_inventory_program_scan_save_error),
        cmocka_unit_test(test_parse_inventory_hotfix_scan_invalid_query),
        cmocka_unit_test(test_parse_inventory_hotfix_scan_save),
        cmocka_unit_test(test_parse_inventory_hotfix_scan_save_error),
        cmocka_unit_test(test_parse_inventory_port_scan_invalid_query),
        cmocka_unit_test(test_parse_inventory_port_scan_save),
        cmocka_unit_test(test_parse_inventory_port_scan_save_error),
        cmocka_unit_test(test_parse_inventory_process_scan_invalid_query),
        cmocka_unit_test(test_parse_inventory_process_scan_save),
        cmocka_unit_test(test_parse_inventory_process_scan_save_error),
        cmocka_unit_test_setup_teardown(test_wdb_parse_rootcheck_badquery, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_rootcheck_delete_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_rootcheck_delete_ok, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_rootcheck_save_invalid_no_next, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_rootcheck_save_no_ptr, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_rootcheck_save_date_max_long, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_rootcheck_save_update_cache_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_rootcheck_save_update_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_rootcheck_save_update_insert_cache_error, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_wdb_parse_rootcheck_save_update_insert_success, test_setup, test_teardown)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);

}