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

int test_setup_valid_msg_unknown_operation(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("{\"type\":\"dbsync_processes\"}"), lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_valid_msg_invalid_field_list(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("{\"type\":\"dbsync_nothing\", \"operation\":\"invalid\", \"data\":{}}"), lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_hotfixes_valid_msg_with_separator_character(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("{\"type\":\"dbsync_hotfixes\", \"operation\":\"MODIFIED\", \"data\":{\"hotfix\":\"KB12|3456\",\"checksum\":\"abcdef|0123456789\"}}"), lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_hotfixes_valid_msg(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("{\"type\":\"dbsync_hotfixes\", \"operation\":\"MODIFIED\", \"data\":{\"hotfix\":\"KB123456\",\"checksum\":\"abcdef0123456789\"}}"), lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_packages_valid_msg(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("{ \
        \"type\":\"dbsync_packages\", \
        \"operation\":\"MODIFIED\",\
        \"data\":{\
            \"format\" : \"1\",\
            \"name\" : \"2\",\
            \"priority\" : \"3\",\
            \"groups\" : \"4\",\
            \"size\" : \"5\",\
            \"vendor\" : \"6\",\
            \"install_time\" : \"7\",\
            \"version\" : \"8\",\
            \"architecture\" : \"9\",\
            \"multiarch\" : \"10\",\
            \"source\" : \"11\",\
            \"description\" : \"12\",\
            \"location\" : \"13\",\
            \"triaged\" : \"14\",\
            \"cpe\" : \"15\",\
            \"msu_name\" : \"16\",\
            \"checksum\" : \"17\",\
            \"item_id\" : \"18\"\
        }}"), lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}


int test_setup_processes_valid_msg(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("{\
        \"type\":\"dbsync_processes\",\
        \"operation\":\"MODIFIED\",\
        \"data\":{ \
            \"pid\" : \"18\",\
            \"name\" : \"19\",\
            \"state\" : \"20\",\
            \"ppid\" : \"21\",\
            \"utime\" : \"22\",\
            \"stime\" : \"23\",\
            \"cmd\" : \"24\",\
            \"argvs\" : \"25\",\
            \"euser\" : \"26\",\
            \"ruser\" : \"27\",\
            \"suser\" : \"28\",\
            \"egroup\" : \"29\",\
            \"rgroup\" : \"30\",\
            \"sgroup\" : \"31\",\
            \"fgroup\" : \"32\",\
            \"priority\" : \"33\",\
            \"nice\" : \"34\",\
            \"size\" : \"35\",\
            \"vm_size\" : \"36\",\
            \"resident\" : \"37\",\
            \"share\" : \"38\",\
            \"start_time\" : \"39\",\
            \"pgrp\" : \"40\",\
            \"session\" : \"41\",\
            \"nlwp\" : \"42\",\
            \"tgid\" : \"43\",\
            \"tty\" : \"44\",\
            \"processor\" : \"45\",\
            \"checksum\" : \"46\"\
        }}"), lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_ports_valid_msg(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("{ \
        \"type\":\"dbsync_ports\",\
        \"operation\":\"MODIFIED\",\
        \"data\":{ \
            \"protocol\" : \"47\",\
            \"local_ip\" : \"48\",\
            \"local_port\" : \"49\",\
            \"remote_ip\" : \"50\",\
            \"remote_port\" : \"51\",\
            \"tx_queue\" : \"52\",\
            \"rx_queue\" : \"53\",\
            \"inode\" : \"54\",\
            \"state\" : \"55\",\
            \"pid\" : \"56\",\
            \"process\" : \"57\",\
            \"checksum\" : \"58\",\
            \"item_id\" : \"59\"\
        }}"), lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_network_iface_valid_msg(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("{ \
        \"type\":\"dbsync_network_iface\",\
        \"operation\":\"MODIFIED\",\
        \"data\":{ \
            \"name\" : \"59\",\
            \"adapter\" : \"60\",\
            \"type\" : \"61\",\
            \"state\" : \"62\",\
            \"mtu\" : \"63\",\
            \"mac\" : \"64\",\
            \"tx_packets\" : \"65\",\
            \"rx_packets\" : \"66\",\
            \"tx_bytes\" : \"67\",\
            \"rx_bytes\" : \"68\",\
            \"tx_errors\" : \"69\",\
            \"rx_errors\" : \"70\",\
            \"tx_dropped\" : \"71\",\
            \"rx_dropped\" : \"72\",\
            \"checksum\" : \"73\",\
            \"item_id\" : \"74\"\
    }}"), lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_network_protocol_valid_msg(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("{ \
        \"type\":\"dbsync_network_protocol\", \
        \"operation\":\"MODIFIED\",\
        \"data\":{ \
            \"iface\" : \"74\",\
            \"type\" : \"75\",\
            \"gateway\" : \"76\",\
            \"dhcp\" : \"77\",\
            \"metric\" : \"78\",\
            \"checksum\" : \"79\",\
            \"item_id\" : \"80\"\
    }}"), lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_network_address_valid_msg(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("{ \
        \"type\":\"dbsync_network_address\",\
        \"operation\":\"MODIFIED\",\
        \"data\":{\
            \"iface\" : \"80\",\
            \"proto\" : \"81\",\
            \"address\" : \"82\",\
            \"netmask\" : \"83\",\
            \"broadcast\" : \"84\",\
            \"checksum\" : \"85\",\
            \"item_id\" : \"86\"\
    }}"), lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_hardware_valid_msg(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("{\
        \"type\":\"dbsync_hwinfo\",\
        \"operation\":\"MODIFIED\",\
        \"data\":{\
            \"board_serial\" : \"86\",\
            \"cpu_name\" : \"87\",\
            \"cpu_cores\" : \"88\",\
            \"cpu_MHz\" : \"89\",\
            \"ram_total\" : \"90\",\
            \"ram_free\" : \"91\",\
            \"ram_usage\" : \"92\",\
            \"checksum\" : \"93\"\
    }}"), lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_os_valid_msg(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("{ \
        \"type\":\"dbsync_osinfo\",\
        \"operation\":\"MODIFIED\",\
        \"data\":{\
            \"hostname\" : \"93\",\
            \"architecture\" : \"94\",\
            \"os_name\" : \"95\",\
            \"os_version\" : \"96\",\
            \"os_codename\" : \"97\",\
            \"os_major\" : \"98\",\
            \"os_minor\" : \"99\",\
            \"os_patch\" : \"100\",\
            \"os_build\" : \"101\",\
            \"os_platform\" : \"102\",\
            \"sysname\" : \"103\",\
            \"release\" : \"104\",\
            \"version\" : \"105\",\
            \"os_release\" : \"106\",\
            \"os_display_version\" : \"107\",\
            \"checksum\" : \"108\"\
    }}"), lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_valid_msg_query_error(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("{\"type\":\"dbsync_hotfixes\", \"operation\":\"MODIFIED\", \"data\":{\"hotfix\":\"KB123456\",\"checksum\":\"abcdef0123456789\"}}"), lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup(void **state) {
    Eventinfo *lf;

    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
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

void test_syscollector_dbsync_valid_msg_unknown_operation(void **state)
{
    Eventinfo *lf = *state;
    expect_string(__wrap__merror, formatted_msg, "Incorrect/unknown operation, type: processes.");
    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send dbsync information to Wazuh DB.");
    int ret = DecodeSyscollector(lf, 0);

    assert_int_equal(ret, 0);
}

void test_syscollector_dbsync_valid_msg_invalid_field_list(void **state)
{
    Eventinfo *lf = *state;
    expect_string(__wrap__merror, formatted_msg, "Incorrect/unknown type value nothing.");
    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send dbsync information to Wazuh DB.");
    int ret = DecodeSyscollector(lf, 0);

    assert_int_equal(ret, 0);
}

void test_syscollector_dbsync_hotfixes_valid_msg_with_separator_character(void **state)
{
    Eventinfo *lf = *state;

    const char *query = "agent 001 dbsync hotfixes MODIFIED NULL|KB12?3456|abcdef?0123456789|";
    const char *result = "ok";
    int sock = 1;

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);
    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, 0);
}

void test_syscollector_dbsync_hotfixes_valid_msg(void **state)
{
    Eventinfo *lf = *state;

    const char *query = "agent 001 dbsync hotfixes MODIFIED NULL|KB123456|abcdef0123456789|";
    const char *result = "ok";
    int sock = 1;

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);
    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, 0);
}

void test_syscollector_dbsync_packages_valid_msg(void **state)
{
    Eventinfo *lf = *state;

    const char *query = "agent 001 dbsync packages MODIFIED NULL|1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18|";
    const char *result = "ok";
    int sock = 1;

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, 0);
}

void test_syscollector_dbsync_processes_valid_msg(void **state)
{
    Eventinfo *lf = *state;

    const char *query = "agent 001 dbsync processes MODIFIED NULL|18|19|20|21|22|23|24|25|26|27|28|29|30|31|32|33|34|35|36|37|38|39|40|41|42|43|44|45|46|";
    const char *result = "ok";
    int sock = 1;

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, 0);
}

void test_syscollector_dbsync_ports_valid_msg(void **state)
{
    Eventinfo *lf = *state;

    const char *query = "agent 001 dbsync ports MODIFIED NULL|47|48|49|50|51|52|53|54|55|56|57|58|59|";
    const char *result = "ok";
    int sock = 1;

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, 0);
}

void test_syscollector_dbsync_network_iface_valid_msg(void **state)
{
    Eventinfo *lf = *state;

    const char *query = "agent 001 dbsync network_iface MODIFIED NULL|59|60|61|62|63|64|65|66|67|68|69|70|71|72|73|74|";
    const char *result = "ok";
    int sock = 1;

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, 0);
}

void test_syscollector_dbsync_network_protocol_valid_msg(void **state)
{
    Eventinfo *lf = *state;

    const char *query = "agent 001 dbsync network_protocol MODIFIED 74|75|76|77|78|79|80|";
    const char *result = "ok";
    int sock = 1;

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, 0);
}

void test_syscollector_dbsync_network_address_valid_msg(void **state)
{
    Eventinfo *lf = *state;

    const char *query = "agent 001 dbsync network_address MODIFIED 80|81|82|83|84|85|86|";
    const char *result = "ok";
    int sock = 1;

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, 0);
}

void test_syscollector_dbsync_hardware_valid_msg(void **state)
{
    Eventinfo *lf = *state;

    const char *query = "agent 001 dbsync hwinfo MODIFIED NULL|86|87|88|89|90|91|92|93|";
    const char *result = "ok";
    int sock = 1;

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, 0);
}

void test_syscollector_dbsync_os_valid_msg(void **state)
{
    Eventinfo *lf = *state;

    const char *query = "agent 001 dbsync osinfo MODIFIED NULL|93|94|95|96|97|98|99|100|101|102|103|104|105|106|107|108|";
    const char *result = "ok";
    int sock = 1;

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, 0);
}


void test_syscollector_dbsync_valid_msg_query_error(void **state)
{
    Eventinfo *lf = *state;

    const char *query = "agent 001 dbsync hotfixes MODIFIED NULL|KB123456|abcdef0123456789|";
    const char *result = "fail";
    int sock = 1;

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, -1);

    expect_string(__wrap__merror, formatted_msg, "Wazuh-db query error, check wdb logs.");
    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send dbsync information to Wazuh DB.");

    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, 1);
}

/* Test DecodeSyscollector */
void test_DecodeSyscollector_invalid_event(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;

    os_strdup("(", lf->location);
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid received event.");

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 0);
}

void test_DecodeSyscollector_invalid_event_syscollector(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;

    os_strdup("(>", lf->location);
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid received event. Not syscollector.");

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 0);
}

void test_DecodeSyscollector_invalid_event_location(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;

    os_strdup("Test", lf->location);
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid received event. (Location)");

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 0);
}

void test_DecodeSyscollector_type_null(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;

    os_strdup("(>syscollector", lf->location);
    os_strdup("{\"Unit_test\": 1}", lf->log);
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid message. Type not found.");

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 0);
}

void test_DecodeSyscollector_invalid_type(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;

    os_strdup("syscollector", lf->location);
    os_strdup("{\"Unit_test\": 1, \"type\": \"Wrong\"}", lf->log);
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid message type: Wrong.");

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 0);
}

void test_DecodeSyscollector_type_no_string(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;

    os_strdup("(>syscollector", lf->location);
    os_strdup("{\"type\": 1}", lf->log);
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid message. Type not found.");

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 0);
}

/* Test decode_port */
void test_decode_port_id_object_json_null(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;

    os_strdup("(>syscollector", lf->location);
    os_strdup("{\"type\": \"port\"}", lf->log);
    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send ports information to Wazuh DB.");

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 0);
}

void test_decode_port_query_ex_fail_port_end(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query = "agent 001 port del 0";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\": \"port_end\", \"ID\": 0}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, "ok");
    will_return(__wrap_wdbc_query_ex, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send ports information to Wazuh DB.");

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 0);
}

void test_decode_port_parse_result_fail_port_end(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query = "agent 001 port del 1";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\": \"port_end\", \"ID\": 1}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, 1);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send ports information to Wazuh DB.");

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 0);
}

void test_decode_port_first_success_port_end(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\": \"port_end\", \"ID\": 1}", lf->log);

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 1);
}

void test_decode_port_second_success_port_end(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query = "agent 001 port del 2";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\": \"port_end\", \"ID\": 2}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 1);
}

void test_decode_port_success(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query = "agent 001 port del 2";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\": \"port\", \"ID\": 2}", lf->log);

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 1);
}

void test_decode_port_query_ex_fail_port(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query = "agent 001 port save 2|11/10/2021|TCP|192.168.1.2|541|192.168.1.3|541|1|1|1|state|1234|process";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\": \"port\",\"ID\": 2,\"timestamp\": \"11/10/2021\",\"port\": {\"protocol\": \"TCP\",\"local_ip\": \"192.168.1.2\",\
                    \"local_port\": 541,\"remote_ip\": \"192.168.1.3\",\"remote_port\": 541,\"tx_queue\": 1,\"rx_queue\": 1,\"inode\": 1,\
                    \"state\": \"state\",\"PID\": 1234,\"process\": \"process\"}}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 1);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send ports information to Wazuh DB.");

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 0);
}

void test_decode_same_port(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query = "agent 001 port save 2|11/10/2021|TCP|192.168.1.2|541|192.168.1.3|541|1|1|1|state|1234|process";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\": \"port\",\"ID\": 2,\"timestamp\": \"11/10/2021\",\"port\": {\"protocol\": \"TCP\",\"local_ip\": \"192.168.1.2\",\
                    \"local_port\": 541,\"remote_ip\": \"192.168.1.3\",\"remote_port\": 541,\"tx_queue\": 1,\"rx_queue\": 1,\"inode\": 1,\
                    \"state\": \"state\",\"PID\": 1234,\"process\": \"process\"}}", lf->log);

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 1);
}

void test_decode_parse_result_invalid(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query = "agent 001 port save 3|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\": \"port\",\"ID\": 3,\"port\": {}}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);
    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, 1);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send ports information to Wazuh DB.");

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 0);
}

void test_decode_parse_result_valid(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query = "agent 001 port save 4|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\": \"port\",\"ID\": 4,\"port\": {}}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);
    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 1);
}

/* Test decode_package */
void test_decode_package_id_object_json_null(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;

    os_strdup("(>syscollector", lf->location);
    os_strdup("{\"type\": \"program\"}", lf->log);
    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send packages information to Wazuh DB.");

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 0);
}

void test_decode_package_query_ex_fail_program_end(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query = "agent 001 package del 0";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\": \"program_end\", \"ID\": 0}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, "ok");
    will_return(__wrap_wdbc_query_ex, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send packages information to Wazuh DB.");

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 0);
}

void test_decode_package_parser_result_fail_program_end(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query = "agent 001 package del 1";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\": \"program_end\", \"ID\": 1}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, "ok");
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, 1);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send packages information to Wazuh DB.");

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 0);
}

void test_decode_package_parser_same_program_end(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query = "agent 001 package del 1";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\": \"program_end\", \"ID\": 1}", lf->log);

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 1);
}

void test_decode_package_parser_result_success_program_end(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query = "agent 001 package del 2";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\": \"program_end\", \"ID\": 2}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, "ok");
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 1);
}

void test_decode_package_first_success(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query = "agent 001 package del 2";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\": \"program\", \"ID\": 2}", lf->log);

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 1);
}

void test_decode_package_query_ex_fail(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query = "agent 001 package save 3|timestamp|format|name|priority|group|456|Wazuh|install_time|version|architecture|multi-arch|source|Unit test|location";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\": \"program\", \"ID\": 3, \"timestamp\": \"timestamp\", \"program\": {\"format\": \"format\", \"name\": \"name\",\
                \"priority\": \"priority\", \"group\": \"group\", \"size\": 456, \"vendor\": \"Wazuh\", \"version\": \"version\",\
                \"architecture\": \"architecture\", \"multi-arch\": \"multi-arch\", \"source\": \"source\", \"description\": \"Unit test\",\
                \"install_time\": \"install_time\", \"location\": \"location\"}}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 1);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send packages information to Wazuh DB.");

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 0);
}

void test_decode_package_parse_result_fail(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query = "agent 001 package save 4|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\": \"program\", \"ID\": 4, \"program\": {}}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, 1);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send packages information to Wazuh DB.");

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 0);
}

void test_decode_package_same_program(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query = "agent 001 package del 4";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\": \"program\", \"ID\": 4, \"program\": {}}", lf->log);

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 1);
}

void test_decode_package_second_success(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query = "agent 001 package save 5|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\": \"program\", \"ID\": 5, \"program\": {}}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 1);
}

/* Test decode_hotfix */
void test_decode_hotfix_id_object_json_null(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;

    os_strdup("(>syscollector", lf->location);
    os_strdup("{\"type\": \"hotfix\"}", lf->log);
    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send hotfixes information to Wazuh DB.");

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 0);
}

void test_decode_hotfix_query_ex_fail_hotfix_end(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query = "agent 001 hotfix del 1";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\": \"hotfix_end\", \"ID\": 1}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, -1);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send hotfixes information to Wazuh DB.");

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 0);
}

void test_decode_hotfix_parse_result_fail_hotfix_end(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query = "agent 001 hotfix del 1";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\": \"hotfix_end\", \"ID\": 1}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, 1);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send hotfixes information to Wazuh DB.");

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 0);
}

void test_decode_hotfix_parse_and_query_success_hotfix_end(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query = "agent 001 hotfix del 1";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\": \"hotfix_end\", \"ID\": 1}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 1);
}

void test_decode_hotfix_first_success(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query = "agent 001 hotfix del 1";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\": \"hotfix\", \"ID\": 1}", lf->log);

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 1);
}

void test_decode_hotfix_query_ex_fail(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query = "agent 001 hotfix save 1|timestamp|Test hotfix|";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\": \"hotfix\", \"ID\": 1, \"hotfix\": \"Test hotfix\", \"timestamp\": \"timestamp\"}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 1);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send hotfixes information to Wazuh DB.");

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 0);
}

void test_decode_hotfix_parse_result_fail(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query = "agent 001 hotfix save 1|timestamp|Test hotfix|";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\": \"hotfix\", \"ID\": 1, \"hotfix\": \"Test hotfix\", \"timestamp\": \"timestamp\"}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, 1);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send hotfixes information to Wazuh DB.");

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 0);
}

void test_decode_hotfix_second_success(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query = "agent 001 hotfix save 1|timestamp|Test hotfix|";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\": \"hotfix\", \"ID\": 1, \"hotfix\": \"Test hotfix\", \"timestamp\": \"timestamp\"}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 1);
}

/* Test decode_hardware */
void test_decode_hardware_inventory_null(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;

    os_strdup("(>syscollector", lf->location);
    os_strdup("{\"type\": \"hardware\"}", lf->log);

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 1);
}

void test_decode_hardware_query_ex_fail(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query = "agent 001 hardware save 1|timestamp|Board serial|Intel|4|2900.400000|8192.000000|4096.000000|4096";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\": \"hardware\", \"ID\": 1, \"timestamp\": \"timestamp\", \"inventory\": {\"board_serial\": \"Board serial\", \"cpu_name\": \"Intel\", \"cpu_cores\": 4, \"cpu_mhz\": 2900.4, \"ram_total\": 8192, \"ram_free\": 4096, \"ram_usage\": 4096}}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 1);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send hardware information to Wazuh DB.");

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 0);
}

void test_decode_hardware_parse_result_fail(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query = "agent 001 hardware save 1|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\": \"hardware\", \"ID\": 1, \"inventory\": {}}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, 1);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send hardware information to Wazuh DB.");

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 0);
}

void test_decode_hardware_success(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query = "agent 001 hardware save NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\": \"hardware\", \"inventory\": {}}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);


    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 1);
}

/* Test decode_osinfo */
void test_decode_osinfo_inventory_null(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;

    os_strdup("(>syscollector", lf->location);
    os_strdup("{\"type\": \"OS\"}", lf->log);

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 1);
}

void test_decode_osinfo_query_ex_fail(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query = "agent 001 osinfo save 1|timestamp|Test|x86_64|Debian|11|os_codename|11|3|os_build|os_platform|sysname|release|version|os_release|os_patch|os_display_version";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\": \"OS\", \"ID\": 1, \"timestamp\": \"timestamp\", \"inventory\": {\"os_name\": \"Debian\", \"os_version\": \"11\", \"os_codename\": \"os_codename\", \"hostname\": \"Test\", \"architecture\": \"x86_64\", \"os_major\": \"11\", \"os_minor\": \"3\", \"os_build\": \"os_build\", \"os_platform\": \"os_platform\", \"sysname\": \"sysname\", \"release\": \"release\", \"version\": \"version\", \"os_release\": \"os_release\", \"os_patch\": \"os_patch\", \"os_display_version\": \"os_display_version\"}}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 1);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send osinfo message to Wazuh DB.");

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 0);
}

void test_decode_osinfo_parse_result_fail(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query = "agent 001 osinfo save NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\": \"OS\", \"inventory\": {}}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, 1);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send osinfo message to Wazuh DB.");

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 0);
}

void test_decode_osinfo_success(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query = "agent 001 osinfo save NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\": \"OS\", \"inventory\": {}}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 1);
}

/* Test decode_netinfo */
void test_decode_netinfo_unknow_type(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;

    os_strdup("(>syscollector", lf->location);
    os_strdup("{\"type\": \"network\"}", lf->log);

    expect_string(__wrap__merror, formatted_msg, "at decode_netinfo(): unknown type found.");
    expect_string(__wrap__merror, formatted_msg, "Unable to send netinfo message to Wazuh DB.");

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 0);
}

void test_decode_netinfo_query_ex_network_end(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query = "agent 001 netinfo del 2";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\": \"network_end\", \"ID\": 2}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 1);

    expect_string(__wrap__merror, formatted_msg, "Unable to send netinfo message to Wazuh DB.");

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 0);
}

void test_decode_netinfo_parse_result_network_end(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query = "agent 001 netinfo del 2";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\": \"network_end\", \"ID\": 2}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, 1);

    expect_string(__wrap__merror, formatted_msg, "Unable to send netinfo message to Wazuh DB.");

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 0);
}

void test_decode_netinfo_first_success(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query = "agent 001 netinfo del 2";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\": \"network_end\", \"ID\": 2}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 1);
}

void test_decode_netinfo_iface_query_ex_fail(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query = "agent 001 netinfo save 2|timestamp|name|adapter|type|state|9|MAC|1|2|3|4|5|6|7|8";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\": \"network\", \"ID\": 2, \"timestamp\": \"timestamp\", \"iface\": {\
                \"name\": \"name\", \"adapter\": \"adapter\", \"type\": \"type\", \"state\": \"state\", \"MAC\": \"MAC\",\
                \"tx_packets\": 1, \"rx_packets\": 2, \"tx_bytes\": 3, \"rx_bytes\": 4, \"tx_errors\": 5, \"rx_errors\": 6, \
                \"tx_dropped\": 7, \"rx_dropped\": 8, \"MTU\": 9}}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 1);

    expect_string(__wrap__merror, formatted_msg, "Unable to send netinfo message to Wazuh DB.");

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 0);
}

void test_decode_netinfo_iface_parse_result_fail(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query = "agent 001 netinfo save NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\": \"network\", \"iface\": {}}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, 1);

    expect_string(__wrap__merror, formatted_msg, "Unable to send netinfo message to Wazuh DB.");

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 0);
}

void test_decode_netinfo_second_success(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query = "agent 001 netinfo save NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\": \"network\", \"iface\": {}}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 1);
}

void test_decode_netinfo_ipv4_query_ex_fail(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query1 = "agent 001 netinfo save 2|timestamp|name|adapter|type|state|9|MAC|1|2|3|4|5|6|7|8";
    const char *query2 = "agent 001 netproto save 2|name|0|gateway|dhcp|1";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\":\"network\", \"ID\":2, \"timestamp\":\"timestamp\", \"iface\":{\
                \"name\":\"name\", \"adapter\":\"adapter\", \"type\":\"type\", \"state\":\"state\",\
                \"MAC\":\"MAC\", \"tx_packets\":1, \"rx_packets\":2, \"tx_bytes\":3, \"rx_bytes\":4,\
                \"tx_errors\":5, \"rx_errors\":6, \"tx_dropped\":7, \"rx_dropped\":8, \"MTU\":9, \"IPv4\":\
                {\"gateway\":\"gateway\", \"dhcp\":\"dhcp\", \"metric\":1,\"address\":[\"address\"],\
                \"netmask\":[\"netmask\"], \"broadcast\":[\"broadcast\"]}}}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query1);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query2);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 1);

    expect_string(__wrap__merror, formatted_msg, "Unable to send netinfo message to Wazuh DB.");

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 0);
}

void test_decode_netinfo_ipv4_parse_result_fail(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query1 = "agent 001 netinfo save NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL";
    const char *query2 = "agent 001 netproto save NULL|NULL|0|NULL|NULL|NULL";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\": \"network\", \"iface\": {\"IPv4\": {}}}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query1);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query2);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, 1);

    expect_string(__wrap__merror, formatted_msg, "Unable to send netinfo message to Wazuh DB.");

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 0);
}

void test_decode_netinfo_netaddr_query_ex_fill_fail(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query1 = "agent 001 netinfo save 2|timestamp|name|adapter|type|state|9|MAC|1|2|3|4|5|6|7|8";
    const char *query2 = "agent 001 netproto save 2|name|0|gateway|dhcp|1";
    const char *query3 = "agent 001 netaddr save 2|name|0|address|netmask|broadcast";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\":\"network\", \"ID\":2, \"timestamp\":\"timestamp\", \"iface\":{\
                \"name\":\"name\", \"adapter\":\"adapter\", \"type\":\"type\", \"state\":\"state\",\
                \"MAC\":\"MAC\", \"tx_packets\":1, \"rx_packets\":2, \"tx_bytes\":3, \"rx_bytes\":4,\
                \"tx_errors\":5, \"rx_errors\":6, \"tx_dropped\":7, \"rx_dropped\":8, \"MTU\":9, \"IPv4\":\
                {\"gateway\":\"gateway\", \"dhcp\":\"dhcp\", \"metric\":1,\"address\":[\"address\"],\
                \"netmask\":[\"netmask\"], \"broadcast\":[\"broadcast\"]}}}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query1);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query2);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query3);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 1);

    expect_string(__wrap__merror, formatted_msg, "Unable to send netinfo message to Wazuh DB.");

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 0);
}

void test_decode_netinfo_netaddr_query_ex_null_fail(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query1 = "agent 001 netinfo save NULL|timestamp|NULL|adapter|type|state|9|MAC|1|2|3|4|5|6|7|8";
    const char *query2 = "agent 001 netproto save NULL|NULL|0|gateway|dhcp|1";
    const char *query3 = "agent 001 netaddr save NULL|NULL|0|address|NULL|NULL";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\":\"network\", \"timestamp\":\"timestamp\", \"iface\":{\
                \"adapter\":\"adapter\", \"type\":\"type\", \"state\":\"state\",\
                \"MAC\":\"MAC\", \"tx_packets\":1, \"rx_packets\":2, \"tx_bytes\":3, \"rx_bytes\":4,\
                \"tx_errors\":5, \"rx_errors\":6, \"tx_dropped\":7, \"rx_dropped\":8, \"MTU\":9, \"IPv4\":\
                {\"gateway\":\"gateway\", \"dhcp\":\"dhcp\", \"metric\":1,\"address\":[\"address\"]}}}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query1);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query2);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query3);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 1);

    expect_string(__wrap__merror, formatted_msg, "Unable to send netinfo message to Wazuh DB.");

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 0);
}

void test_decode_netinfo_netaddr_parse_result_fill_fail(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query1 = "agent 001 netinfo save 2|timestamp|name|adapter|type|state|9|MAC|1|2|3|4|5|6|7|8";
    const char *query2 = "agent 001 netproto save 2|name|0|gateway|dhcp|1";
    const char *query3 = "agent 001 netaddr save 2|name|0|address1|netmask1|broadcast1";
    const char *query4 = "agent 001 netaddr save 2|name|0|address2|netmask2|broadcast2";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\":\"network\", \"ID\":2, \"timestamp\":\"timestamp\", \"iface\":{\
                \"name\":\"name\", \"adapter\":\"adapter\", \"type\":\"type\", \"state\":\"state\",\
                \"MAC\":\"MAC\", \"tx_packets\":1, \"rx_packets\":2, \"tx_bytes\":3, \"rx_bytes\":4,\
                \"tx_errors\":5, \"rx_errors\":6, \"tx_dropped\":7, \"rx_dropped\":8, \"MTU\":9, \"IPv4\":\
                {\"gateway\":\"gateway\", \"dhcp\":\"dhcp\", \"metric\":1,\"address\":[\"address1\", \"address2\"],\
                \"netmask\":[\"netmask1\", \"netmask2\"], \"broadcast\":[\"broadcast1\", \"broadcast2\"]}}}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query1);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query2);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query3);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query4);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, 1);

    expect_string(__wrap__merror, formatted_msg, "Unable to send netinfo message to Wazuh DB.");

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 0);
}

void test_decode_netinfo_netaddr_parse_result_null_fail(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query1 = "agent 001 netinfo save 2|timestamp|name|adapter|type|state|9|MAC|1|2|3|4|5|6|7|8";
    const char *query2 = "agent 001 netproto save 2|name|0|gateway|dhcp|1";
    const char *query3 = "agent 001 netaddr save 2|name|0|address1|NULL|NULL";
    const char *query4 = "agent 001 netaddr save 2|name|0|address2|NULL|NULL";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\":\"network\", \"ID\":2, \"timestamp\":\"timestamp\", \"iface\":{\
                \"name\":\"name\", \"adapter\":\"adapter\", \"type\":\"type\", \"state\":\"state\",\
                \"MAC\":\"MAC\", \"tx_packets\":1, \"rx_packets\":2, \"tx_bytes\":3, \"rx_bytes\":4,\
                \"tx_errors\":5, \"rx_errors\":6, \"tx_dropped\":7, \"rx_dropped\":8, \"MTU\":9, \"IPv4\":\
                {\"gateway\":\"gateway\", \"dhcp\":\"dhcp\", \"metric\":1,\"address\":[\"address1\", \"address2\"]}}}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query1);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query2);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query3);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query4);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, 1);

    expect_string(__wrap__merror, formatted_msg, "Unable to send netinfo message to Wazuh DB.");

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 0);
}

void test_decode_netinfo_ipv6_query_ex_fail(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query1 = "agent 001 netinfo save NULL|timestamp|NULL|adapter|type|state|9|MAC|1|2|3|4|5|6|7|8";
    const char *query2 = "agent 001 netproto save NULL|NULL|0|gateway|dhcp|1";
    const char *query3 = "agent 001 netaddr save NULL|NULL|0|address|netmask|broadcast";
    const char *query4 = "agent 001 netproto save NULL|NULL|1|NULL|NULL|NULL";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\":\"network\", \"timestamp\":\"timestamp\", \"iface\":{\
                \"adapter\":\"adapter\", \"type\":\"type\", \"state\":\"state\",\
                \"MAC\":\"MAC\", \"tx_packets\":1, \"rx_packets\":2, \"tx_bytes\":3, \"rx_bytes\":4,\
                \"tx_errors\":5, \"rx_errors\":6, \"tx_dropped\":7, \"rx_dropped\":8, \"MTU\":9, \"IPv4\":\
                {\"gateway\":\"gateway\", \"dhcp\":\"dhcp\", \"metric\":1,\"address\":[\"address\"],\
                \"netmask\":[\"netmask\"], \"broadcast\":[\"broadcast\"]}, \"IPv6\":\
                {}}}}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query1);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query2);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query3);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query4);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 1);

    expect_string(__wrap__merror, formatted_msg, "Unable to send netinfo message to Wazuh DB.");

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 0);
}

void test_decode_netinfo_ipv6_parse_result_fail(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query1 = "agent 001 netinfo save 2|timestamp|name|adapter|type|state|9|MAC|1|2|3|4|5|6|7|8";
    const char *query2 = "agent 001 netproto save 2|name|0|NULL|NULL|NULL";
    const char *query3 = "agent 001 netproto save 2|name|1|gateway|dhcp|1";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\":\"network\", \"ID\":2, \"timestamp\":\"timestamp\", \"iface\":{\
                \"name\":\"name\", \"adapter\":\"adapter\", \"type\":\"type\", \"state\":\"state\",\
                \"MAC\":\"MAC\", \"tx_packets\":1, \"rx_packets\":2, \"tx_bytes\":3, \"rx_bytes\":4,\
                \"tx_errors\":5, \"rx_errors\":6, \"tx_dropped\":7, \"rx_dropped\":8, \"MTU\":9, \"IPv4\":\
                {\"address\": {}}, \"IPv6\": {\"gateway\":\"gateway\", \"dhcp\":\"dhcp\", \"metric\":1}}}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query1);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query2);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query3);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, 1);

    expect_string(__wrap__merror, formatted_msg, "Unable to send netinfo message to Wazuh DB.");

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 0);
}

void test_decode_netinfo_ipv6_netaddr_parse_result_fill_fail(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query1 = "agent 001 netinfo save 2|timestamp|name|adapter|type|state|9|MAC|1|2|3|4|5|6|7|8";
    const char *query2 = "agent 001 netproto save 2|name|0|NULL|NULL|NULL";
    const char *query3 = "agent 001 netproto save 2|name|1|NULL|NULL|NULL";
    const char *query4 = "agent 001 netaddr save 2|name|1|address1|netmask1|broadcast1";
    const char *query5 = "agent 001 netaddr save 2|name|1|address2|netmask2|broadcast2";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\":\"network\", \"ID\":2, \"timestamp\":\"timestamp\", \"iface\":{\
                \"name\":\"name\", \"adapter\":\"adapter\", \"type\":\"type\", \"state\":\"state\",\
                \"MAC\":\"MAC\", \"tx_packets\":1, \"rx_packets\":2, \"tx_bytes\":3, \"rx_bytes\":4,\
                \"tx_errors\":5, \"rx_errors\":6, \"tx_dropped\":7, \"rx_dropped\":8, \"MTU\":9, \"IPv4\":\
                {}, \"IPv6\": {\"address\": [\"address1\", \"address2\"], \"netmask\": [\"netmask1\", \"netmask2\"],\
                \"broadcast\": [\"broadcast1\", \"broadcast2\"]}}}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query1);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query2);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query3);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query4);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query5);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, 1);

    expect_string(__wrap__merror, formatted_msg, "Unable to send netinfo message to Wazuh DB.");

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 0);
}

void test_decode_netinfo_ipv6_netaddr_parse_result_null_fail(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query1 = "agent 001 netinfo save NULL|timestamp|NULL|adapter|type|state|9|MAC|1|2|3|4|5|6|7|8";
    const char *query2 = "agent 001 netproto save NULL|NULL|0|NULL|NULL|NULL";
    const char *query3 = "agent 001 netproto save NULL|NULL|1|NULL|NULL|NULL";
    const char *query4 = "agent 001 netaddr save NULL|NULL|1|address|NULL|NULL";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\":\"network\", \"timestamp\":\"timestamp\", \"iface\":{\
                \"adapter\":\"adapter\", \"type\":\"type\", \"state\":\"state\",\
                \"MAC\":\"MAC\", \"tx_packets\":1, \"rx_packets\":2, \"tx_bytes\":3, \"rx_bytes\":4,\
                \"tx_errors\":5, \"rx_errors\":6, \"tx_dropped\":7, \"rx_dropped\":8, \"MTU\":9, \"IPv4\":\
                {}, \"IPv6\": {\"address\": [\"address\"]}}}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query1);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query2);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query3);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query4);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, 1);

    expect_string(__wrap__merror, formatted_msg, "Unable to send netinfo message to Wazuh DB.");

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 0);
}

void test_decode_netinfo_ipv6_netaddr_query_ex_fill_fail(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query1 = "agent 001 netinfo save 2|timestamp|name|adapter|type|state|9|MAC|1|2|3|4|5|6|7|8";
    const char *query2 = "agent 001 netproto save 2|name|0|NULL|NULL|NULL";
    const char *query3 = "agent 001 netproto save 2|name|1|NULL|NULL|NULL";
    const char *query4 = "agent 001 netaddr save 2|name|1|address|netmask|broadcast";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\":\"network\", \"ID\":2, \"timestamp\":\"timestamp\", \"iface\":{\
                \"name\":\"name\", \"adapter\":\"adapter\", \"type\":\"type\", \"state\":\"state\",\
                \"MAC\":\"MAC\", \"tx_packets\":1, \"rx_packets\":2, \"tx_bytes\":3, \"rx_bytes\":4,\
                \"tx_errors\":5, \"rx_errors\":6, \"tx_dropped\":7, \"rx_dropped\":8, \"MTU\":9, \"IPv4\":\
                {}, \"IPv6\": {\"address\": [\"address\"], \"netmask\": [\"netmask\"], \"broadcast\": [\"broadcast\"]}}}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query1);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query2);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query3);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query4);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 1);

    expect_string(__wrap__merror, formatted_msg, "Unable to send netinfo message to Wazuh DB.");

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 0);
}

void test_decode_netinfo_ipv6_netaddr_query_ex_null_fail(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query1 = "agent 001 netinfo save 2|timestamp|name|adapter|type|state|9|MAC|1|2|3|4|5|6|7|8";
    const char *query2 = "agent 001 netproto save 2|name|0|NULL|NULL|NULL";
    const char *query3 = "agent 001 netproto save 2|name|1|NULL|NULL|NULL";
    const char *query4 = "agent 001 netaddr save 2|name|1|address|NULL|NULL";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\":\"network\", \"ID\":2, \"timestamp\":\"timestamp\", \"iface\":{\
                \"name\":\"name\", \"adapter\":\"adapter\", \"type\":\"type\", \"state\":\"state\",\
                \"MAC\":\"MAC\", \"tx_packets\":1, \"rx_packets\":2, \"tx_bytes\":3, \"rx_bytes\":4,\
                \"tx_errors\":5, \"rx_errors\":6, \"tx_dropped\":7, \"rx_dropped\":8, \"MTU\":9, \"IPv4\":\
                {}, \"IPv6\": {\"address\": [\"address\"]}}}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query1);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query2);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query3);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query4);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 1);

    expect_string(__wrap__merror, formatted_msg, "Unable to send netinfo message to Wazuh DB.");

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 0);
}

void test_decode_netinfo_third_success(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query1 = "agent 001 netinfo save 2|timestamp|name|adapter|type|state|9|MAC|1|2|3|4|5|6|7|8";
    const char *query2 = "agent 001 netproto save 2|name|0|NULL|NULL|NULL";
    const char *query3 = "agent 001 netproto save 2|name|1|NULL|NULL|NULL";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\":\"network\", \"ID\":2, \"timestamp\":\"timestamp\", \"iface\":{\
                \"name\":\"name\", \"adapter\":\"adapter\", \"type\":\"type\", \"state\":\"state\",\
                \"MAC\":\"MAC\", \"tx_packets\":1, \"rx_packets\":2, \"tx_bytes\":3, \"rx_bytes\":4,\
                \"tx_errors\":5, \"rx_errors\":6, \"tx_dropped\":7, \"rx_dropped\":8, \"MTU\":9, \"IPv4\":\
                {}, \"IPv6\": {\"address\": {}}}}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query1);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query2);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query3);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 1);
}

void test_decode_netinfo_fourth_success(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query1 = "agent 001 netinfo save 2|timestamp|name|adapter|type|state|9|MAC|1|2|3|4|5|6|7|8";
    const char *query2 = "agent 001 netproto save 2|name|0|NULL|NULL|NULL";
    const char *query3 = "agent 001 netproto save 2|name|1|NULL|NULL|NULL";
    const char *query4 = "agent 001 netaddr save 2|name|1|address|netmask|broadcast";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\":\"network\", \"ID\":2, \"timestamp\":\"timestamp\", \"iface\":{\
                \"name\":\"name\", \"adapter\":\"adapter\", \"type\":\"type\", \"state\":\"state\",\
                \"MAC\":\"MAC\", \"tx_packets\":1, \"rx_packets\":2, \"tx_bytes\":3, \"rx_bytes\":4,\
                \"tx_errors\":5, \"rx_errors\":6, \"tx_dropped\":7, \"rx_dropped\":8, \"MTU\":9, \"IPv4\":\
                {}, \"IPv6\": {\"address\": [\"address\"], \"netmask\": [\"netmask\"], \"broadcast\": [\"broadcast\"]}}}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query1);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query2);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query3);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query4);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 1);
}

void test_decode_netinfo_null_netaddr(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query1 = "agent 001 netinfo save 2|timestamp|name|adapter|type|state|9|MAC|1|2|3|4|5|6|7|8";
    const char *query2 = "agent 001 netproto save 2|name|0|NULL|NULL|NULL";
    const char *query3 = "agent 001 netproto save 2|name|1|NULL|NULL|NULL";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\":\"network\", \"ID\":2, \"timestamp\":\"timestamp\", \"iface\":{\
                \"name\":\"name\", \"adapter\":\"adapter\", \"type\":\"type\", \"state\":\"state\",\
                \"MAC\":\"MAC\", \"tx_packets\":1, \"rx_packets\":2, \"tx_bytes\":3, \"rx_bytes\":4,\
                \"tx_errors\":5, \"rx_errors\":6, \"tx_dropped\":7, \"rx_dropped\":8, \"MTU\":9, \"IPv4\":\
                {}, \"IPv6\": {}}}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query1);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query2);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query3);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 1);
}

/* Test decode_process */
void test_decode_process_id_object_json_null(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;

    os_strdup("(>syscollector", lf->location);
    os_strdup("{\"type\": \"process\"}", lf->log);
    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send processes information to Wazuh DB.");

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 0);
}

void test_decode_process_querry_ex_fail_process_end(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query = "agent 001 process del 1";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\": \"process_end\", \"ID\": 1}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 1);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send processes information to Wazuh DB.");

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 0);
}

void test_decode_process_first_success(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query = "agent 001 process del 1";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\": \"process_end\", \"ID\": 1}", lf->log);

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 1);
}

void test_decode_process_different_process_end_success(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query = "agent 001 process del 1";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\": \"process\", \"ID\": 1}", lf->log);

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 1);
}

void test_decode_process_parse_result_fail_process_end(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query = "agent 001 process del 2";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\": \"process_end\", \"ID\": 2}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, 1);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send processes information to Wazuh DB.");

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 0);
}

void test_decode_process_parse_result_success_process_end(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query = "agent 001 process del 3";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\": \"process_end\", \"ID\": 3}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 1);
}

void test_decode_process_querry_ex_fail(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query = "agent 001 process save 3|timestamp|3|name|state|25|1200|2|cmd|argvs1,argvs2|euser|ruser|suser|egroup|rgroup|sgroup|fgroup|1|2|3|4|5|6|7|8|10|9|11|12|13";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\": \"process\", \"ID\": 3, \"timestamp\": \"timestamp\", \"process\": {\"pid\": 3, \"name\": \"name\"\
                , \"state\": \"state\", \"ppid\": 25, \"utime\": 1200, \"stime\": 2, \"cmd\": \"cmd\", \"argvs\": [\"argvs1\",\
                \"argvs2\"], \"euser\": \"euser\", \"ruser\": \"ruser\", \"suser\": \"suser\", \"egroup\": \"egroup\"\
                , \"rgroup\": \"rgroup\", \"sgroup\": \"sgroup\", \"fgroup\": \"fgroup\", \"priority\": 1, \"nice\": 2, \"size\": 3\
                , \"vm_size\": 4, \"resident\": 5, \"share\": 6, \"start_time\": 7, \"pgrp\": 8, \"nlwp\": 9, \"session\": 10\
                , \"tgid\": 11, \"tty\": 12, \"processor\": 13}}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 1);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send processes information to Wazuh DB.");

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 0);
}

void test_decode_process_second_success(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query = "agent 001 process save 3|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\": \"process\", \"ID\": 3, \"process\": {}}", lf->log);

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 1);
}

void test_decode_process_parse_result_fail(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query = "agent 001 process save 4|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\": \"process\", \"ID\": 4, \"process\": {}}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, 1);

    expect_string(__wrap__mdebug1, formatted_msg, "Unable to send processes information to Wazuh DB.");

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 0);
}

void test_decode_process_parse_result_success(void **state) {
    Eventinfo *lf = *state;
    int output = 0, socket = 1;
    const char *query = "agent 001 process save 5|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL";
    const char *result = "ok";

    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);
    os_strdup("{\"type\": \"process\", \"ID\": 5, \"process\": {}}", lf->log);

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap_wdbc_parse_result, result, result);
    will_return(__wrap_wdbc_parse_result, WDBC_OK);

    output = DecodeSyscollector(lf, &socket);
    assert_int_equal(output, 1);
}




int main()
{
        const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_invalid_location, test_setup_invalid_location, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_invalid_json, test_setup_invalid_json, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_invalid_msgtype, test_setup_invalid_msgtype, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_valid_msg_unknown_operation, test_setup_valid_msg_unknown_operation, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_valid_msg_invalid_field_list, test_setup_valid_msg_invalid_field_list, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_valid_msg_query_error, test_setup_valid_msg_query_error, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_hotfixes_valid_msg_with_separator_character, test_setup_hotfixes_valid_msg_with_separator_character, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_hotfixes_valid_msg, test_setup_hotfixes_valid_msg, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_packages_valid_msg, test_setup_packages_valid_msg, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_processes_valid_msg, test_setup_processes_valid_msg, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_ports_valid_msg, test_setup_ports_valid_msg, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_network_iface_valid_msg, test_setup_network_iface_valid_msg, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_network_protocol_valid_msg, test_setup_network_protocol_valid_msg, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_network_address_valid_msg, test_setup_network_address_valid_msg, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_hardware_valid_msg, test_setup_hardware_valid_msg, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_os_valid_msg, test_setup_os_valid_msg, test_cleanup),
        /* Test DecodeSyscollector */
        cmocka_unit_test_setup_teardown(test_DecodeSyscollector_invalid_event, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_DecodeSyscollector_invalid_event_syscollector, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_DecodeSyscollector_invalid_event_location, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_DecodeSyscollector_type_null, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_DecodeSyscollector_invalid_type, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_DecodeSyscollector_type_no_string, test_setup, test_cleanup),
        /* Test decode_port */
        cmocka_unit_test_setup_teardown(test_decode_port_id_object_json_null, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_port_query_ex_fail_port_end, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_port_parse_result_fail_port_end, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_port_first_success_port_end, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_port_second_success_port_end, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_port_success, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_port_query_ex_fail_port, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_same_port, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_parse_result_invalid, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_parse_result_valid, test_setup, test_cleanup),
        /* Test decode_package */
        cmocka_unit_test_setup_teardown(test_decode_package_id_object_json_null, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_package_query_ex_fail_program_end, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_package_parser_result_fail_program_end, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_package_parser_same_program_end, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_package_parser_result_success_program_end, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_package_first_success, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_package_query_ex_fail, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_package_parse_result_fail, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_package_same_program, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_package_second_success, test_setup, test_cleanup),
        /* Test decode_hotfix */
        cmocka_unit_test_setup_teardown(test_decode_hotfix_id_object_json_null, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_hotfix_query_ex_fail_hotfix_end, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_hotfix_parse_result_fail_hotfix_end, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_hotfix_parse_and_query_success_hotfix_end, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_hotfix_first_success, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_hotfix_query_ex_fail, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_hotfix_parse_result_fail, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_hotfix_second_success, test_setup, test_cleanup),
        /* Test decode_hardware */
        cmocka_unit_test_setup_teardown(test_decode_hardware_inventory_null, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_hardware_query_ex_fail, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_hardware_parse_result_fail, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_hardware_success, test_setup, test_cleanup),
        /* Test decode_osinfo */
        cmocka_unit_test_setup_teardown(test_decode_osinfo_inventory_null, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_osinfo_query_ex_fail, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_osinfo_parse_result_fail, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_osinfo_success, test_setup, test_cleanup),
        /* Test decode_netinfo */
        cmocka_unit_test_setup_teardown(test_decode_netinfo_unknow_type, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_netinfo_query_ex_network_end, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_netinfo_parse_result_network_end, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_netinfo_first_success, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_netinfo_iface_query_ex_fail, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_netinfo_iface_parse_result_fail, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_netinfo_second_success, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_netinfo_ipv4_query_ex_fail, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_netinfo_ipv4_parse_result_fail, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_netinfo_netaddr_query_ex_fill_fail, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_netinfo_netaddr_query_ex_null_fail, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_netinfo_netaddr_parse_result_fill_fail, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_netinfo_netaddr_parse_result_null_fail, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_netinfo_ipv6_query_ex_fail, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_netinfo_ipv6_parse_result_fail, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_netinfo_ipv6_netaddr_parse_result_fill_fail, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_netinfo_ipv6_netaddr_parse_result_null_fail, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_netinfo_ipv6_netaddr_query_ex_fill_fail, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_netinfo_ipv6_netaddr_query_ex_null_fail, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_netinfo_third_success, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_netinfo_fourth_success, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_netinfo_null_netaddr, test_setup, test_cleanup),
        /* Test decode_process */
        cmocka_unit_test_setup_teardown(test_decode_process_id_object_json_null, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_process_querry_ex_fail_process_end, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_process_first_success, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_process_different_process_end_success, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_process_parse_result_fail_process_end, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_process_parse_result_success_process_end, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_process_querry_ex_fail, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_process_second_success, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_process_parse_result_fail, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_decode_process_parse_result_success, test_setup, test_cleanup),
    };
    return cmocka_run_group_tests(tests, test_setup_global, NULL);
}

