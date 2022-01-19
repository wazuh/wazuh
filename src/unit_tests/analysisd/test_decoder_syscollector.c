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
    };
    return cmocka_run_group_tests(tests, test_setup_global, NULL);
}
