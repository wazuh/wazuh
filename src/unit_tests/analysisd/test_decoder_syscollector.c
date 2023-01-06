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

int test_setup_valid_msg_null_agentid(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("{\"type\":\"dbsync_processes\"}"), lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);

    *state = lf;
    return 0;
}

int test_setup_valid_msg_invalid_field_list(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        {\
            \"type\":\"dbsync_nothing\",\
            \"operation\":\"invalid\",\
            \"data\":{}\
        }"), lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_valid_msg_with_no_type(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        {\
            \"type\":\"dbsync_\",\
            \"operation\":\"invalid\",\
            \"data\":{}\
        }"),
        lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_hotfixes_valid_msg_modified(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        { \
            \"type\":\"dbsync_hotfixes\",\
            \"operation\":\"MODIFIED\",\
            \"data\":\
            {\
                \"scan_time\":\"2021/10/29 14:26:24\",\
                \"hotfix\":\"KB123456\",\
                \"checksum\":\"abcdef0123456789\"\
            }\
        }"),
        lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}
int test_setup_packages_valid_msg_modified(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        { \
            \"type\":\"dbsync_packages\", \
            \"operation\":\"MODIFIED\",\
            \"data\":{\
                \"scan_time\":\"2021/10/29 14:26:24\",\
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
                \"checksum\" : \"17\",\
                \"item_id\" : \"18\"\
            }\
        }"), lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}


int test_setup_processes_valid_msg_modified(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        {\
            \"type\":\"dbsync_processes\",\
            \"operation\":\"MODIFIED\",\
            \"data\":{ \
                \"scan_time\":\"2021/10/29 14:26:24\",\
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
            }\
        }"),
        lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_ports_valid_msg_modified(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        {\
            \"type\":\"dbsync_ports\",\
            \"operation\":\"MODIFIED\",\
            \"data\":\
            {\
                \"scan_time\":\"2021/10/29 14:26:24\",\
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
            }\
        }"),
        lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_network_iface_valid_msg_modified(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        {\
            \"type\":\"dbsync_network_iface\",\
            \"operation\":\"MODIFIED\",\
            \"data\":\
            {\
                \"scan_time\":\"2021/10/29 14:26:24\",\
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
            }\
        }"), lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_network_protocol_valid_msg_modified(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        {\
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
            }\
        }"),
        lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_network_address_invalid_msg_modified(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        { \
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
            }\
        }"),
        lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_network_address_valid_msg_modified(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        { \
            \"type\":\"dbsync_network_address\",\
            \"operation\":\"MODIFIED\",\
            \"data\":{\
                \"iface\" : \"80\",\
                \"proto\" : 0,\
                \"address\" : \"82\",\
                \"netmask\" : \"83\",\
                \"broadcast\" : \"84\",\
                \"checksum\" : \"85\",\
                \"item_id\" : \"86\"\
            }\
        }"),
        lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_hardware_valid_msg_modified(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        {\
            \"type\":\"dbsync_hwinfo\",\
            \"operation\":\"MODIFIED\",\
            \"data\":{\
                \"scan_time\":\"2021/10/29 14:26:24\",\
                \"board_serial\" : \"86\",\
                \"cpu_name\" : \"87\",\
                \"cpu_cores\" : 88,\
                \"cpu_MHz\" : 89.9,\
                \"ram_total\" : 90,\
                \"ram_free\" : 91,\
                \"ram_usage\" : 92,\
                \"checksum\" : \"93\"\
            }\
        }"),
        lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_os_valid_msg_modified(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        {\
            \"type\":\"dbsync_osinfo\",\
            \"operation\":\"MODIFIED\",\
            \"data\":{\
                \"scan_time\":\"2021/10/29 14:26:24\",\
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
                \"checksum\" : \"107\",\
                \"os_display_version\" : \"108\",\
                \"reference\" : \"110\"\
            }\
        }"), lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_hotfixes_valid_msg_inserted(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        {\
            \"type\":\"dbsync_hotfixes\",\
            \"operation\":\"INSERTED\",\
            \"data\":{\
                \"scan_time\":\"2021/10/29 14:26:24\",\
                \"hotfix\":\"KB123456\",\
                \"checksum\":\"abcdef0123456789\"\
            }\
        }"),
        lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_packages_valid_msg_inserted(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        { \
            \"type\":\"dbsync_packages\", \
            \"operation\":\"INSERTED\",\
            \"data\":{\
                \"scan_time\":\"2021/10/29 14:26:24\",\
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
                \"checksum\" : \"17\",\
                \"item_id\" : \"18\"\
            }\
        }"),
        lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}


int test_setup_processes_valid_msg_inserted(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        {\
            \"type\":\"dbsync_processes\",\
            \"operation\":\"INSERTED\",\
            \"data\":{ \
                \"scan_time\":\"2021/10/29 14:26:24\",\
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
            }\
        }"),
        lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_ports_valid_msg_inserted(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        {\
            \"type\":\"dbsync_ports\",\
            \"operation\":\"INSERTED\",\
            \"data\":{ \
                \"scan_time\":\"2021/10/29 14:26:24\",\
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
            }\
        }"),
        lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_network_iface_valid_msg_inserted(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        { \
            \"type\":\"dbsync_network_iface\",\
            \"operation\":\"INSERTED\",\
            \"data\":{ \
                \"scan_time\":\"2021/10/29 14:26:24\",\
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
            }\
        }"), lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_network_protocol_valid_msg_inserted(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        { \
            \"type\":\"dbsync_network_protocol\", \
            \"operation\":\"INSERTED\",\
            \"data\":{ \
                \"iface\" : \"74\",\
                \"type\" : \"75\",\
                \"gateway\" : \"76\",\
                \"dhcp\" : \"77\",\
                \"metric\" : \"78\",\
                \"checksum\" : \"79\",\
                \"item_id\" : \"80\"\
            }\
        }"), lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_network_address_valid_msg_inserted(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        { \
            \"type\":\"dbsync_network_address\",\
            \"operation\":\"INSERTED\",\
            \"data\":{\
                \"iface\" : \"80\",\
                \"proto\" : 1,\
                \"address\" : \"82\",\
                \"netmask\" : \"83\",\
                \"broadcast\" : \"84\",\
                \"checksum\" : \"85\",\
                \"item_id\" : \"86\"\
            }\
        }"),
        lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_network_address_invalid_msg_inserted(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        { \
            \"type\":\"dbsync_network_address\",\
            \"operation\":\"INSERTED\",\
            \"data\":{\
                \"iface\" : \"80\",\
                \"proto\" : \"81\",\
                \"address\" : \"82\",\
                \"netmask\" : \"83\",\
                \"broadcast\" : \"84\",\
                \"checksum\" : \"85\",\
                \"item_id\" : \"86\"\
            }\
        }"),
        lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_hardware_valid_msg_inserted(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        {\
            \"type\":\"dbsync_hwinfo\",\
            \"operation\":\"INSERTED\",\
            \"data\":{\
                \"scan_time\":\"2021/10/29 14:26:24\",\
                \"board_serial\" : \"86\",\
                \"cpu_name\" : \"87\",\
                \"cpu_cores\" : 88,\
                \"cpu_MHz\" : 89.9,\
                \"ram_total\" : 90,\
                \"ram_free\" : 91,\
                \"ram_usage\" : 92,\
                \"checksum\" : 93\
            }\
        }"),
        lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_os_valid_msg_inserted(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        { \
            \"type\":\"dbsync_osinfo\",\
            \"operation\":\"INSERTED\",\
            \"data\":{\
                \"scan_time\":\"2021/10/29 14:26:24\",\
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
                \"checksum\" : \"107\",\
                \"os_display_version\" : \"108\",\
                \"reference\" : \"110\"\
            }\
        }"),
        lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_os_valid_msg_with_number_pk(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    // architecture will be a number PK
    if (lf->log = strdup("\
        {\
            \"type\":\"dbsync_osinfo\",\
            \"operation\":\"MODIFIED\",\
            \"data\":{\
                \"scan_time\":\"2021/10/29 14:26:24\",\
                \"hostname\" : \"93\",\
                \"architecture\" : 94,\
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
                \"checksum\" : \"107\",\
                \"os_display_version\" : \"108\",\
                \"reference\" : \"110\"\
            }\
        }"),
        lf->log == NULL)
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
    if (lf->log = strdup("\
        {\
            \"type\":\"dbsync_hotfixes\",\
            \"operation\":\"MODIFIED\",\
            \"data\":\
            {\
                \"hotfix\":\"KB123456\",\
                \"checksum\":\"abcdef0123456789\"\
            }\
        }"),
        lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_valid_msg_no_operation(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        {\
            \"type\":\"dbsync_hotfixes\",\
            \"data\":\
            {\
                \"hotfix\":\"KB123456\",\
                \"checksum\":\"abcdef0123456789\"\
            }}"),
        lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_valid_msg_empty_string(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        {\
            \"type\":\"dbsync_hwinfo\",\
            \"operation\":\"INSERTED\",\
            \"data\":\
            {\
                \"scan_time\":\"2021/10/29 14:26:24\",\
                \"board_serial\" : \"86\",\
                \"cpu_name\" : \"\",\
                \"cpu_cores\" : \"88\",\
                \"cpu_MHz\" : \"89\",\
                \"ram_total\" : \"90\",\
                \"ram_free\" : \"91\",\
                \"ram_usage\" : \"92\",\
                \"checksum\" : \"93\"\
            }\
        }"),
        lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_valid_msg_data_as_value(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        {\
            \"type\":\"dbsync_hotfixes\",\
            \"operation\":\"INSERTED\",\
            \"data\":\"data\"\
        }"),
        lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_insert_multiple_null_field_valid_msg(void ** state) {
    Eventinfo * lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        {\
            \"data\":\
            {\
                \"checksum\":\"944fb6182222660aeca5b27bcd14a579db60b58c\",\
                \"inode\":30905,\
                \"item_id\":\"31ec8d41b06cc6dea02d9f088067d379d761732d\",\
                \"local_ip\":\"192.168.100.90\",\
                \"local_port\":53462,\
                \"pid\":null,\
                \"process\":null,\
                \"protocol\":\"tcp\",\
                \"remote_ip\":null,\
                \"remote_port\":10000,\
                \"rx_queue\":null,\
                \"scan_time\":\"2021/11/01 17:38:40\",\
                \"state\":null,\
                \"tx_queue\":null\
            },\
            \"operation\":\"INSERTED\",\
            \"type\":\"dbsync_ports\"\
        }"),
        lf->log == NULL) {
        return -1;
    }
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_deleted_multiple_null_field_valid_msg(void ** state) {
    Eventinfo * lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        {\
            \"data\":\
            {\
                \"inode\":30905,\
                \"local_ip\":\"192.168.100.90\",\
                \"local_port\":53462,\
                \"protocol\":\"tcp\",\
                \"scan_time\":\"2021/11/01 17:40:48\"\
            },\
            \"operation\":\"DELETED\",\
            \"type\":\"dbsync_ports\"\
        }"),
        lf->log == NULL) {
        return -1;
    }
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
    const char type[] = {"processes"};
    char error_log[128];
    sprintf(error_log, INVALID_OPERATION, type);

    expect_string(__wrap__merror, formatted_msg, error_log);
    expect_string(__wrap__mdebug1, formatted_msg, UNABLE_TO_SEND_INFORMATION_TO_WDB);
    int ret = DecodeSyscollector(lf, 0);

    assert_int_equal(ret, 0);
}

void test_syscollector_dbsync_valid_msg_invalid_field_list(void **state)
{
    Eventinfo *lf = *state;
    const char type[] = {"nothing"};
    char error_log[128];
    sprintf(error_log, INVALID_TYPE, type);

    expect_string(__wrap__merror, formatted_msg, error_log);
    expect_string(__wrap__mdebug1, formatted_msg, UNABLE_TO_SEND_INFORMATION_TO_WDB);
    int ret = DecodeSyscollector(lf, 0);

    assert_int_equal(ret, 0);
}

void test_syscollector_dbsync_hotfixes_valid_msg_modified(void **state)
{
    Eventinfo *lf = *state;

    const char *query = "agent 001 dbsync hotfixes MODIFIED "
        "{"
            "\"scan_time\":\"2021/10/29 14:26:24\","
            "\"hotfix\":\"KB123456\","
            "\"checksum\":\"abcdef0123456789\""
        "}";
    const char *result = "ok ";
    int sock = 1;

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);
    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, 0);
}
void test_syscollector_dbsync_packages_valid_msg_modified(void **state)
{
    Eventinfo *lf = *state;

    const char *query = "agent 001 dbsync packages MODIFIED "
        "{"
            "\"scan_time\":\"2021/10/29 14:26:24\","
            "\"format\":\"1\","
            "\"name\":\"2\","
            "\"priority\":\"3\","
            "\"groups\":\"4\","
            "\"size\":\"5\","
            "\"vendor\":\"6\","
            "\"install_time\":\"7\","
            "\"version\":\"8\","
            "\"architecture\":\"9\","
            "\"multiarch\":\"10\","
            "\"source\":\"11\","
            "\"description\":\"12\","
            "\"location\":\"13\","
            "\"checksum\":\"17\","
            "\"item_id\":\"18\""
        "}";
    const char *result = "ok ";
    int sock = 1;

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, 0);
}
void test_syscollector_dbsync_processes_valid_msg_modified(void **state)
{
    Eventinfo *lf = *state;

    const char *query = "agent 001 dbsync processes MODIFIED "
        "{"
            "\"scan_time\":\"2021/10/29 14:26:24\","
            "\"pid\":\"18\","
            "\"name\":\"19\","
            "\"state\":\"20\","
            "\"ppid\":\"21\","
            "\"utime\":\"22\","
            "\"stime\":\"23\","
            "\"cmd\":\"24\","
            "\"argvs\":\"25\","
            "\"euser\":\"26\","
            "\"ruser\":\"27\","
            "\"suser\":\"28\","
            "\"egroup\":\"29\","
            "\"rgroup\":\"30\","
            "\"sgroup\":\"31\","
            "\"fgroup\":\"32\","
            "\"priority\":\"33\","
            "\"nice\":\"34\","
            "\"size\":\"35\","
            "\"vm_size\":\"36\","
            "\"resident\":\"37\","
            "\"share\":\"38\","
            "\"start_time\":\"39\","
            "\"pgrp\":\"40\","
            "\"session\":\"41\","
            "\"nlwp\":\"42\","
            "\"tgid\":\"43\","
            "\"tty\":\"44\","
            "\"processor\":\"45\","
            "\"checksum\":\"46\""
        "}";
    const char *result = "ok ";
    int sock = 1;

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, 0);
}
void test_syscollector_dbsync_ports_valid_msg_modified(void **state)
{
    Eventinfo *lf = *state;

    const char *query = "agent 001 dbsync ports MODIFIED "
        "{"
            "\"scan_time\":\"2021/10/29 14:26:24\","
            "\"protocol\":\"47\","
            "\"local_ip\":\"48\","
            "\"local_port\":\"49\","
            "\"remote_ip\":\"50\","
            "\"remote_port\":\"51\","
            "\"tx_queue\":\"52\","
            "\"rx_queue\":\"53\","
            "\"inode\":\"54\","
            "\"state\":\"55\","
            "\"pid\":\"56\","
            "\"process\":\"57\","
            "\"checksum\":\"58\","
            "\"item_id\":\"59\""
        "}";
    const char *result = "ok ";
    int sock = 1;

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, 0);
}
void test_syscollector_dbsync_network_iface_valid_msg_modified(void **state)
{
    Eventinfo *lf = *state;

    const char *query = "agent 001 dbsync network_iface MODIFIED "
        "{"
            "\"scan_time\":\"2021/10/29 14:26:24\","
            "\"name\":\"59\","
            "\"adapter\":\"60\","
            "\"type\":\"61\","
            "\"state\":\"62\","
            "\"mtu\":\"63\","
            "\"mac\":\"64\","
            "\"tx_packets\":\"65\","
            "\"rx_packets\":\"66\","
            "\"tx_bytes\":\"67\","
            "\"rx_bytes\":\"68\","
            "\"tx_errors\":\"69\","
            "\"rx_errors\":\"70\","
            "\"tx_dropped\":\"71\","
            "\"rx_dropped\":\"72\","
            "\"checksum\":\"73\","
            "\"item_id\":\"74\""
        "}";
    const char *result = "ok ";
    int sock = 1;

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, 0);
}
void test_syscollector_dbsync_network_protocol_valid_msg_modified(void **state)
{
    Eventinfo *lf = *state;

    const char *query = "agent 001 dbsync network_protocol MODIFIED "
        "{"
            "\"iface\":\"74\","
            "\"type\":\"75\","
            "\"gateway\":\"76\","
            "\"dhcp\":\"77\","
            "\"metric\":\"78\","
            "\"checksum\":\"79\","
            "\"item_id\":\"80\""
        "}";
    const char *result = "ok ";
    int sock = 1;

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, 0);
}
void test_syscollector_dbsync_network_address_invalid_msg_modified(void **state)
{
    Eventinfo *lf = *state;

    const char *query = "agent 001 dbsync network_address MODIFIED "
        "{"
            "\"iface\":\"80\","
            "\"proto\":\"81\","
            "\"address\":\"82\","
            "\"netmask\":\"83\","
            "\"broadcast\":\"84\","
            "\"checksum\":\"85\","
            "\"item_id\":\"86\""
        "}";
    const char *result = "ok ";
    int sock = 1;

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);
    expect_string(__wrap__mdebug2, formatted_msg, "Field 'proto' cannot be obtained.");
    expect_string(__wrap__mdebug2, formatted_msg, "Error while mapping 'proto' field value.");
    
    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, 0);
}
void test_syscollector_dbsync_network_address_valid_msg_modified(void **state)
{
    Eventinfo *lf = *state;

    const char *query = "agent 001 dbsync network_address MODIFIED "
        "{"
            "\"iface\":\"80\","
            "\"proto\":\"ipv4\","
            "\"address\":\"82\","
            "\"netmask\":\"83\","
            "\"broadcast\":\"84\","
            "\"checksum\":\"85\","
            "\"item_id\":\"86\""
        "}";
    const char *result = "ok ";
    int sock = 1;

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, 0);
}
void test_syscollector_dbsync_hardware_valid_msg_modified(void **state)
{
    Eventinfo *lf = *state;

    const char *query = "agent 001 dbsync hwinfo MODIFIED "
        "{"
            "\"scan_time\":\"2021/10/29 14:26:24\","
            "\"board_serial\":\"86\","
            "\"cpu_name\":\"87\","
            "\"cpu_cores\":88,"
            "\"cpu_MHz\":89.9,"
            "\"ram_total\":90,"
            "\"ram_free\":91,"
            "\"ram_usage\":92,"
            "\"checksum\":\"93\""
        "}";
    const char *result = "ok ";
    int sock = 1;

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, 0);
}
void test_syscollector_dbsync_os_valid_msg_modified(void **state)
{
    Eventinfo *lf = *state;

    const char *query = "agent 001 dbsync osinfo MODIFIED "
        "{"
            "\"scan_time\":\"2021/10/29 14:26:24\","
            "\"hostname\":\"93\","
            "\"architecture\":\"94\","
            "\"os_name\":\"95\","
            "\"os_version\":\"96\","
            "\"os_codename\":\"97\","
            "\"os_major\":\"98\","
            "\"os_minor\":\"99\","
            "\"os_patch\":\"100\","
            "\"os_build\":\"101\","
            "\"os_platform\":\"102\","
            "\"sysname\":\"103\","
            "\"release\":\"104\","
            "\"version\":\"105\","
            "\"os_release\":\"106\","
            "\"checksum\":\"107\","
            "\"os_display_version\":\"108\","
            "\"reference\":\"110\""
        "}";
    const char *result = "ok ";
    int sock = 1;

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, 0);
}
void test_syscollector_dbsync_hotfixes_valid_msg_inserted(void **state)
{
    Eventinfo *lf = *state;

    const char *query = "agent 001 dbsync hotfixes INSERTED "
        "{"
            "\"scan_time\":\"2021/10/29 14:26:24\","
            "\"hotfix\":\"KB123456\","
            "\"checksum\":\"abcdef0123456789\""
        "}";
    const char *result = "ok ";
    int sock = 1;

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);
    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, 0);
}
void test_syscollector_dbsync_packages_valid_msg_inserted(void **state)
{
    Eventinfo *lf = *state;

    const char *query = "agent 001 dbsync packages INSERTED "
        "{"
            "\"scan_time\":\"2021/10/29 14:26:24\","
            "\"format\":\"1\","
            "\"name\":\"2\","
            "\"priority\":\"3\","
            "\"groups\":\"4\","
            "\"size\":\"5\","
            "\"vendor\":\"6\","
            "\"install_time\":\"7\","
            "\"version\":\"8\","
            "\"architecture\":\"9\","
            "\"multiarch\":\"10\","
            "\"source\":\"11\","
            "\"description\":\"12\","
            "\"location\":\"13\","
            "\"checksum\":\"17\","
            "\"item_id\":\"18\""
        "}";
    const char *result = "ok ";
    int sock = 1;

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, 0);
}
void test_syscollector_dbsync_processes_valid_msg_inserted(void **state)
{
    Eventinfo *lf = *state;

    const char *query = "agent 001 dbsync processes INSERTED "
        "{"
            "\"scan_time\":\"2021/10/29 14:26:24\","
            "\"pid\":\"18\","
            "\"name\":\"19\","
            "\"state\":\"20\","
            "\"ppid\":\"21\","
            "\"utime\":\"22\","
            "\"stime\":\"23\","
            "\"cmd\":\"24\","
            "\"argvs\":\"25\","
            "\"euser\":\"26\","
            "\"ruser\":\"27\","
            "\"suser\":\"28\","
            "\"egroup\":\"29\","
            "\"rgroup\":\"30\","
            "\"sgroup\":\"31\","
            "\"fgroup\":\"32\","
            "\"priority\":\"33\","
            "\"nice\":\"34\","
            "\"size\":\"35\","
            "\"vm_size\":\"36\","
            "\"resident\":\"37\","
            "\"share\":\"38\","
            "\"start_time\":\"39\","
            "\"pgrp\":\"40\","
            "\"session\":\"41\","
            "\"nlwp\":\"42\","
            "\"tgid\":\"43\","
            "\"tty\":\"44\","
            "\"processor\":\"45\","
            "\"checksum\":\"46\""
        "}";
    const char *result = "ok ";
    int sock = 1;

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, 0);
}
void test_syscollector_dbsync_ports_valid_msg_inserted(void **state)
{
    Eventinfo *lf = *state;

    const char *query = "agent 001 dbsync ports INSERTED "
        "{"
            "\"scan_time\":\"2021/10/29 14:26:24\","
            "\"protocol\":\"47\","
            "\"local_ip\":\"48\","
            "\"local_port\":\"49\","
            "\"remote_ip\":\"50\","
            "\"remote_port\":\"51\","
            "\"tx_queue\":\"52\","
            "\"rx_queue\":\"53\","
            "\"inode\":\"54\","
            "\"state\":\"55\","
            "\"pid\":\"56\","
            "\"process\":\"57\","
            "\"checksum\":\"58\","
            "\"item_id\":\"59\""
        "}";
    const char *result = "ok ";
    int sock = 1;

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, 0);
}
void test_syscollector_dbsync_network_iface_valid_msg_inserted(void **state)
{
    Eventinfo *lf = *state;

    const char *query = "agent 001 dbsync network_iface INSERTED "
        "{"
            "\"scan_time\":\"2021/10/29 14:26:24\","
            "\"name\":\"59\","
            "\"adapter\":\"60\","
            "\"type\":\"61\","
            "\"state\":\"62\","
            "\"mtu\":\"63\","
            "\"mac\":\"64\","
            "\"tx_packets\":\"65\","
            "\"rx_packets\":\"66\","
            "\"tx_bytes\":\"67\","
            "\"rx_bytes\":\"68\","
            "\"tx_errors\":\"69\","
            "\"rx_errors\":\"70\","
            "\"tx_dropped\":\"71\","
            "\"rx_dropped\":\"72\","
            "\"checksum\":\"73\","
            "\"item_id\":\"74\""
        "}";
    const char *result = "ok ";
    int sock = 1;

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, 0);
}
void test_syscollector_dbsync_network_protocol_valid_msg_inserted(void **state)
{
    Eventinfo *lf = *state;

    const char *query = "agent 001 dbsync network_protocol INSERTED "
        "{"
            "\"iface\":\"74\","
            "\"type\":\"75\","
            "\"gateway\":\"76\","
            "\"dhcp\":\"77\","
            "\"metric\":\"78\","
            "\"checksum\":\"79\","
            "\"item_id\":\"80\""
        "}";
    const char *result = "ok ";
    int sock = 1;

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, 0);
}
void test_syscollector_dbsync_network_address_invalid_msg_inserted(void **state)
{
    Eventinfo *lf = *state;

    const char *query = "agent 001 dbsync network_address INSERTED "
        "{"
            "\"iface\":\"80\","
            "\"proto\":\"81\","
            "\"address\":\"82\","
            "\"netmask\":\"83\","
            "\"broadcast\":\"84\","
            "\"checksum\":\"85\","
            "\"item_id\":\"86\""
        "}";
    const char *result = "ok ";
    int sock = 1;

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);
    expect_string(__wrap__mdebug2, formatted_msg, "Field 'proto' cannot be obtained.");
    expect_string(__wrap__mdebug2, formatted_msg, "Error while mapping 'proto' field value.");

    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, 0);
}
void test_syscollector_dbsync_network_address_valid_msg_inserted(void **state)
{
    Eventinfo *lf = *state;

    const char *query = "agent 001 dbsync network_address INSERTED "
        "{"
            "\"iface\":\"80\","
            "\"proto\":\"ipv6\","
            "\"address\":\"82\","
            "\"netmask\":\"83\","
            "\"broadcast\":\"84\","
            "\"checksum\":\"85\","
            "\"item_id\":\"86\""
        "}";
    const char *result = "ok ";
    int sock = 1;

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, 0);
}
void test_syscollector_dbsync_hardware_valid_msg_inserted(void **state)
{
    Eventinfo *lf = *state;

    const char *query = "agent 001 dbsync hwinfo INSERTED "
        "{"
            "\"scan_time\":\"2021/10/29 14:26:24\","
            "\"board_serial\":\"86\","
            "\"cpu_name\":\"87\","
            "\"cpu_cores\":88,"
            "\"cpu_MHz\":89.9,"
            "\"ram_total\":90,"
            "\"ram_free\":91,"
            "\"ram_usage\":92,"
            "\"checksum\":93"
        "}";
    const char *result = "ok ";
    int sock = 1;

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, 0);
}
void test_syscollector_dbsync_os_valid_msg_inserted(void **state)
{
    Eventinfo *lf = *state;

    const char *query = "agent 001 dbsync osinfo INSERTED "
        "{"
            "\"scan_time\":\"2021/10/29 14:26:24\","
            "\"hostname\":\"93\","
            "\"architecture\":\"94\","
            "\"os_name\":\"95\","
            "\"os_version\":\"96\","
            "\"os_codename\":\"97\","
            "\"os_major\":\"98\","
            "\"os_minor\":\"99\","
            "\"os_patch\":\"100\","
            "\"os_build\":\"101\","
            "\"os_platform\":\"102\","
            "\"sysname\":\"103\","
            "\"release\":\"104\","
            "\"version\":\"105\","
            "\"os_release\":\"106\","
            "\"checksum\":\"107\","
            "\"os_display_version\":\"108\","
            "\"reference\":\"110\""
        "}";
    const char *result = "ok ";
    int sock = 1;

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, 0);
}

void test_syscollector_dbsync_os_valid_msg_with_number_pk(void **state)
{
    Eventinfo *lf = *state;

    const char *query = "agent 001 dbsync osinfo MODIFIED "
        "{"
            "\"scan_time\":\"2021/10/29 14:26:24\","
            "\"hostname\":\"93\","
            "\"architecture\":94,"
            "\"os_name\":\"95\","
            "\"os_version\":\"96\","
            "\"os_codename\":\"97\","
            "\"os_major\":\"98\","
            "\"os_minor\":\"99\","
            "\"os_patch\":\"100\","
            "\"os_build\":\"101\","
            "\"os_platform\":\"102\","
            "\"sysname\":\"103\","
            "\"release\":\"104\","
            "\"version\":\"105\","
            "\"os_release\":\"106\","
            "\"checksum\":\"107\","
            "\"os_display_version\":\"108\","
            "\"reference\":\"110\""
        "}";
    const char *result = "ok ";
    int sock = 1;

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, 0);
}

void test_syscollector_dbsync_with_no_type(void **state)
{
    Eventinfo *lf = *state;
    int sock = 1;
    const char type[] = {"dbsync"};
    char error_log[128];
    sprintf(error_log, INVALID_PREFIX, type);

    expect_string(__wrap__merror, formatted_msg, error_log);
    expect_string(__wrap__mdebug1, formatted_msg, UNABLE_TO_SEND_INFORMATION_TO_WDB);
    int ret = DecodeSyscollector(lf, &sock);
    assert_int_equal(ret, 0);
}

void test_syscollector_dbsync_valid_msg_query_error(void **state)
{
    Eventinfo *lf = *state;

    const char *query = "agent 001 dbsync hotfixes MODIFIED "
        "{"
            "\"hotfix\":\"KB123456\","
            "\"checksum\":\"abcdef0123456789\""
        "}";
    const char *result = "fail";
    int sock = 1;

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, -1);

    expect_string(__wrap__mdebug1, formatted_msg, UNABLE_TO_SEND_INFORMATION_TO_WDB);
    expect_string(__wrap__mdebug2, formatted_msg, WDBC_QUERY_EX_ERROR);

    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, 1);
}

void test_syscollector_dbsync_os_valid_msg_no_result_payload(void **state)
{
    Eventinfo *lf = *state;

    const char *query = "agent 001 dbsync osinfo MODIFIED "
        "{"
            "\"scan_time\":\"2021/10/29 14:26:24\","
            "\"hostname\":\"93\","
            "\"architecture\":\"94\","
            "\"os_name\":\"95\","
            "\"os_version\":\"96\","
            "\"os_codename\":\"97\","
            "\"os_major\":\"98\","
            "\"os_minor\":\"99\","
            "\"os_patch\":\"100\","
            "\"os_build\":\"101\","
            "\"os_platform\":\"102\","
            "\"sysname\":\"103\","
            "\"release\":\"104\","
            "\"version\":\"105\","
            "\"os_release\":\"106\","
            "\"checksum\":\"107\","
            "\"os_display_version\":\"108\","
            "\"reference\":\"110\""
        "}";
    const char *result = "";
    int sock = 1;

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    expect_string(__wrap__merror, formatted_msg, INVALID_RESPONSE);
    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, 0);
}

void test_syscollector_dbsync_valid_msg_no_operation_or_data_no_object(void **state)
{
    Eventinfo *lf = *state;
    int sock = 1;
    const char type[] = {"hotfixes"};
    char error_log[128];
    sprintf(error_log, INVALID_OPERATION, type);

    expect_string(__wrap__merror, formatted_msg, error_log);
    expect_string(__wrap__mdebug1, formatted_msg, UNABLE_TO_SEND_INFORMATION_TO_WDB);

    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, 1);
}

void test_syscollector_dbsync_empty_string(void **state)
{
    Eventinfo *lf = *state;

    const char *query = "agent 001 dbsync hwinfo INSERTED "
        "{"
            "\"scan_time\":\"2021/10/29 14:26:24\","
            "\"board_serial\":\"86\","
            "\"cpu_name\":\"\","
            "\"cpu_cores\":\"88\","
            "\"cpu_MHz\":\"89\","
            "\"ram_total\":\"90\","
            "\"ram_free\":\"91\","
            "\"ram_usage\":\"92\","
            "\"checksum\":\"93\""
        "}";
    const char *result = "ok ";
    int sock = 1;

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, 0);
}

void test_syscollector_dbsync_valid_msg_null_agentid(void **state)
{
    Eventinfo *lf = *state;
    int sock = 1;

    expect_string(__wrap__mdebug1, formatted_msg, UNABLE_TO_SEND_INFORMATION_TO_WDB);

    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, 1);
}

void test_syscollector_dbsync_insert_multiple_null_valid_msg(void ** state) {
    Eventinfo * lf = *state;

    const char * query = "agent 001 dbsync ports INSERTED "
        "{"
            "\"checksum\":\"944fb6182222660aeca5b27bcd14a579db60b58c\","
            "\"inode\":30905,"
            "\"item_id\":\"31ec8d41b06cc6dea02d9f088067d379d761732d\","
            "\"local_ip\":\"192.168.100.90\","
            "\"local_port\":53462,"
            "\"pid\":null,"
            "\"process\":null,"
            "\"protocol\":\"tcp\","
            "\"remote_ip\":null,"
            "\"remote_port\":10000,"
            "\"rx_queue\":null,"
            "\"scan_time\":\"2021/11/01 17:38:40\","
            "\"state\":null,"
            "\"tx_queue\":null"
        "}";
    const char * result = "ok ";

    int sock = 1;

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);
    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, 0);

    int index = 0;

    assert_string_equal(lf->fields[index].key, "type");
    assert_string_equal(lf->fields[index++].value, "dbsync_ports");

    assert_string_equal(lf->fields[index].key, "port.protocol");
    assert_string_equal(lf->fields[index++].value, "tcp");

    assert_string_equal(lf->fields[index].key, "port.local_ip");
    assert_string_equal(lf->fields[index++].value, "192.168.100.90");

    assert_string_equal(lf->fields[index].key, "port.local_port");
    assert_string_equal(lf->fields[index++].value, "53462");

    assert_string_equal(lf->fields[index].key, "port.remote_ip");
    assert_string_equal(lf->fields[index++].value, "");

    assert_string_equal(lf->fields[index].key, "port.remote_port");
    assert_string_equal(lf->fields[index++].value, "10000");

    assert_string_equal(lf->fields[index].key, "port.tx_queue");
    assert_string_equal(lf->fields[index++].value, "");

    assert_string_equal(lf->fields[index].key, "port.rx_queue");
    assert_string_equal(lf->fields[index++].value, "");

    assert_string_equal(lf->fields[index].key, "port.inode");
    assert_string_equal(lf->fields[index++].value, "30905");

    assert_string_equal(lf->fields[index].key, "port.state");
    assert_string_equal(lf->fields[index++].value, "");

    assert_string_equal(lf->fields[index].key, "port.pid");
    assert_string_equal(lf->fields[index++].value, "");

    assert_string_equal(lf->fields[index].key, "port.process");
    assert_string_equal(lf->fields[index++].value, "");

    assert_string_equal(lf->fields[index].key, "operation_type");
    assert_string_equal(lf->fields[index++].value, "INSERTED");
}

void test_syscollector_dbsync_deleted_multiple_null_valid_msg(void ** state) {
    Eventinfo * lf = *state;

    const char *query = "agent 001 dbsync ports DELETED "
        "{"
            "\"inode\":30905,"
            "\"local_ip\":\"192.168.100.90\","
            "\"local_port\":53462,"
            "\"protocol\":\"tcp\","
            "\"scan_time\":\"2021/11/01 17:40:48\""
        "}";

    const char * result = "ok ";

    int sock = 1;

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);
    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, 0);

    int index = 0;

    assert_string_equal(lf->fields[index].key, "type");
    assert_string_equal(lf->fields[index++].value, "dbsync_ports");

    assert_string_equal(lf->fields[index].key, "port.protocol");
    assert_string_equal(lf->fields[index++].value, "tcp");

    assert_string_equal(lf->fields[index].key, "port.local_ip");
    assert_string_equal(lf->fields[index++].value, "192.168.100.90");

    assert_string_equal(lf->fields[index].key, "port.local_port");
    assert_string_equal(lf->fields[index++].value, "53462");

    assert_string_equal(lf->fields[index].key, "port.remote_ip");
    assert_string_equal(lf->fields[index++].value, "");

    assert_string_equal(lf->fields[index].key, "port.remote_port");
    assert_string_equal(lf->fields[index++].value, "");

    assert_string_equal(lf->fields[index].key, "port.tx_queue");
    assert_string_equal(lf->fields[index++].value, "");

    assert_string_equal(lf->fields[index].key, "port.rx_queue");
    assert_string_equal(lf->fields[index++].value, "");

    assert_string_equal(lf->fields[index].key, "port.inode");
    assert_string_equal(lf->fields[index++].value, "30905");

    assert_string_equal(lf->fields[index].key, "port.state");
    assert_string_equal(lf->fields[index++].value, "");

    assert_string_equal(lf->fields[index].key, "port.pid");
    assert_string_equal(lf->fields[index++].value, "");

    assert_string_equal(lf->fields[index].key, "port.process");
    assert_string_equal(lf->fields[index++].value, "");

    assert_string_equal(lf->fields[index].key, "operation_type");
    assert_string_equal(lf->fields[index++].value, "DELETED");
}

int main()
{
    const struct CMUnitTest tests[] = {
        /* Misc invalid tests*/
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_invalid_location, test_setup_invalid_location, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_invalid_json, test_setup_invalid_json, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_invalid_msgtype, test_setup_invalid_msgtype, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_valid_msg_unknown_operation, test_setup_valid_msg_unknown_operation, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_valid_msg_invalid_field_list, test_setup_valid_msg_invalid_field_list, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_valid_msg_query_error, test_setup_valid_msg_query_error, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_with_no_type, test_setup_valid_msg_with_no_type, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_valid_msg_no_operation_or_data_no_object, test_setup_valid_msg_data_as_value, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_valid_msg_no_operation_or_data_no_object, test_setup_valid_msg_no_operation, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_empty_string, test_setup_valid_msg_empty_string, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_valid_msg_null_agentid, test_setup_valid_msg_null_agentid, test_cleanup),
        /* MODIFIED delta tests*/
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_hotfixes_valid_msg_modified, test_setup_hotfixes_valid_msg_modified, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_packages_valid_msg_modified, test_setup_packages_valid_msg_modified, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_processes_valid_msg_modified, test_setup_processes_valid_msg_modified, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_ports_valid_msg_modified, test_setup_ports_valid_msg_modified, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_network_iface_valid_msg_modified, test_setup_network_iface_valid_msg_modified, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_network_protocol_valid_msg_modified, test_setup_network_protocol_valid_msg_modified, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_network_address_invalid_msg_modified, test_setup_network_address_invalid_msg_modified, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_network_address_valid_msg_modified, test_setup_network_address_valid_msg_modified, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_hardware_valid_msg_modified, test_setup_hardware_valid_msg_modified, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_os_valid_msg_modified, test_setup_os_valid_msg_modified, test_cleanup),
        /* INSERTED delta tests*/
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_hotfixes_valid_msg_inserted, test_setup_hotfixes_valid_msg_inserted, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_packages_valid_msg_inserted, test_setup_packages_valid_msg_inserted, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_processes_valid_msg_inserted, test_setup_processes_valid_msg_inserted, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_ports_valid_msg_inserted, test_setup_ports_valid_msg_inserted, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_network_iface_valid_msg_inserted, test_setup_network_iface_valid_msg_inserted, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_network_protocol_valid_msg_inserted, test_setup_network_protocol_valid_msg_inserted, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_network_address_valid_msg_inserted, test_setup_network_address_valid_msg_inserted, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_network_address_invalid_msg_inserted, test_setup_network_address_invalid_msg_inserted, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_hardware_valid_msg_inserted, test_setup_hardware_valid_msg_inserted, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_os_valid_msg_inserted, test_setup_os_valid_msg_inserted, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_os_valid_msg_with_number_pk, test_setup_os_valid_msg_with_number_pk, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_insert_multiple_null_valid_msg, test_setup_insert_multiple_null_field_valid_msg, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_deleted_multiple_null_valid_msg, test_setup_deleted_multiple_null_field_valid_msg, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_os_valid_msg_no_result_payload, test_setup_os_valid_msg_modified, test_cleanup)
    };
    return cmocka_run_group_tests(tests, test_setup_global, NULL);
}
