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
    Config.decoder_order_size = 34;
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

int test_setup_users_valid_msg_modified(void **state) 
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (os_strdup("\
        { \
            \"data\":{ \
                \"checksum\":\"da281181ada27e31ce8649ba38c0e2de9b242e40\", \
                \"host_ip\":null, \
                \"process_pid\":null, \
                \"scan_time\":\"2025/06/04 20:16:55\", \
                \"user_full_name\":\"daemon\", \
                \"user_group_id\":1, \
                \"user_group_id_signed\":1, \
                \"user_home\":\"/usr/sbin\", \
                \"user_id\":1, \
                \"user_is_remote\":1, \
                \"user_last_login\":null, \
                \"user_name\":\"daemon\", \
                \"user_password_expiration_date\":-1, \
                \"user_password_hash_algorithm\":null, \
                \"user_password_inactive_days\":-1, \
                \"user_password_last_change\":19977, \
                \"user_password_max_days_between_changes\":99999, \
                \"user_password_min_days_between_changes\":0, \
                \"user_password_status\":\"locked\", \
                \"user_password_warning_days_before_expiration\":7, \
                \"user_shell\":\"/usr/sbin/nologin\", \
                \"user_uid_signed\":1 \
            }, \
            \"operation\":\"MODIFIED\", \
            \"type\":\"dbsync_users\" \
        }", lf->log), NULL == lf->log) {
        return -1;
    }
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_groups_valid_msg_modified(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (os_strdup("\
        { \
            \"data\":{ \
                \"checksum\":\"0de011b2818a50c78529f56c00433857622bfdb8\", \
                \"group_description\":\"Les membres du groupe Administrateurs disposent d'un accès complet et illimité à l'ordinateur et au domaine\", \
                \"group_id\":544, \
                \"group_id_signed\":544, \
                \"group_is_hidden\":null, \
                \"group_name\":\"Administrateurs\", \
                \"group_users\":\"54358:Administrateur\", \
                \"group_uuid\":\"S-1-5-32-544\", \
                \"scan_time\":\"2025/06/11 14:59:57\" \
            }, \
            \"operation\":\"MODIFIED\", \
            \"type\":\"dbsync_groups\" \
        } \
        }", lf->log), NULL == lf->log) {
        return -1;
    }
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

int test_setup_users_valid_msg_inserted(void **state) 
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (os_strdup("\
        { \
            \"data\":{ \
                \"checksum\":\"da281181ada27e31ce8649ba38c0e2de9b242e40\", \
                \"host_ip\":null, \
                \"process_pid\":null, \
                \"scan_time\":\"2025/06/04 20:16:55\", \
                \"user_full_name\":\"daemon\", \
                \"user_group_id\":1, \
                \"user_group_id_signed\":1, \
                \"user_home\":\"/usr/sbin\", \
                \"user_id\":1, \
                \"user_is_remote\":1, \
                \"user_last_login\":null, \
                \"user_name\":\"daemon\", \
                \"user_password_expiration_date\":-1, \
                \"user_password_hash_algorithm\":null, \
                \"user_password_inactive_days\":-1, \
                \"user_password_last_change\":19977, \
                \"user_password_max_days_between_changes\":99999, \
                \"user_password_min_days_between_changes\":0, \
                \"user_password_status\":\"locked\", \
                \"user_password_warning_days_before_expiration\":7, \
                \"user_shell\":\"/usr/sbin/nologin\", \
                \"user_uid_signed\":1 \
            }, \
            \"operation\":\"INSERTED\", \
            \"type\":\"dbsync_users\" \
        }", lf->log), NULL == lf->log) {
        return -1;
    }
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_groups_valid_msg_inserted(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (os_strdup("\
        { \
            \"data\":{ \
                \"checksum\":\"0de011b2818a50c78529f56c00433857622bfdb8\", \
                \"group_description\":\"Les membres du groupe Administrateurs disposent d'un accès complet et illimité à l'ordinateur et au domaine\", \
                \"group_id\":544, \
                \"group_id_signed\":544, \
                \"group_is_hidden\":null, \
                \"group_name\":\"Administrateurs\", \
                \"group_users\":\"54358:Administrateur\", \
                \"group_uuid\":\"S-1-5-32-544\", \
                \"scan_time\":\"2025/06/11 14:59:57\" \
            }, \
            \"operation\":\"INSERTED\", \
            \"type\":\"dbsync_groups\" \
        } \
        }", lf->log), NULL == lf->log) {
        return -1;
    }
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

int test_setup_hardware_valid_msg(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        {\
            \"type\":\"hardware\",\
            \"ID\":100,\
            \"timestamp\":\"2021/10/29 14:26:24\",\
            \"inventory\":{\
                \"board_serial\" : \"86\",\
                \"cpu_name\" : \"87\",\
                \"cpu_cores\" : 88,\
                \"cpu_mhz\" : 89.9,\
                \"ram_total\" : 90,\
                \"ram_free\" : 91,\
                \"ram_usage\" : 92\
            }\
        }"),
        lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_hardware_valid_msg_inventory_empty(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        {\
            \"type\":\"hardware\",\
            \"inventory\":{\
            }\
        }"),
        lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_hardware_valid_msg_without_inventory(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        {\
            \"type\":\"hardware\",\
            \"ID\":100,\
            \"timestamp\":\"2021/10/29 14:26:24\"\
        }"),
        lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_hotfix_valid_msg(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        {\
            \"type\":\"hotfix\",\
            \"ID\":100,\
            \"timestamp\":\"2021/10/29 14:26:24\",\
            \"hotfix\":\"hotfix-version-test\"\
        }"),
        lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_hotfix_valid_hotfix_end_msg(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        {\
            \"type\":\"hotfix_end\",\
            \"ID\":100\
        }"),
        lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_hotfix_valid_msg_empty(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        {\
            \"type\":\"hotfix\"\
        }"),
        lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_netinfo_valid_msg(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        {\
            \"type\":\"network\",\
            \"ID\":100,\
            \"timestamp\":\"2021/10/29 14:26:24\",\
            \"iface\":{\
                \"name\" : \"86\",\
                \"adapter\" : \"87\",\
                \"type\" : \"88\",\
                \"state\" : \"89\",\
                \"MAC\" : \"90\",\
                \"tx_packets\" : 91,\
                \"rx_packets\" : 92,\
                \"tx_bytes\" : 93,\
                \"rx_bytes\" : 94,\
                \"tx_errors\" : 95,\
                \"rx_errors\" : 96,\
                \"tx_dropped\" : 97,\
                \"rx_dropped\" : 98,\
                \"MTU\" : 99,\
                \"IPv4\":{\
                    \"address\" : [ \"0.0.0.0\", \"0.0.1.0\" ],\
                    \"netmask\" : [ \"255.255.255.255\", \"255.255.255.254\" ],\
                    \"broadcast\" : [ \"0.0.0.1\", \"0.0.1.1\" ],\
                    \"gateway\" : \"0.0.0.2\",\
                    \"dhcp\" : \"0.0.0.3\",\
                    \"metric\" : 10\
                },\
                \"IPv6\":{\
                    \"address\" : [ \"0000:0000:0000:0:0000:0000:0000:0000\",\
                                    \"0000:0000:0000:0:0000:0000:0001:0000\" ],\
                    \"netmask\" : [ \"0000::\", \"0001::\" ],\
                    \"broadcast\" : [ \"0000:0000:0000:0:0000:0000:0000:0001\",\
                                      \"0000:0000:0000:0:0000:0000:0001:0001\" ],\
                    \"gateway\" : \"0000:0000:0000:0:0000:0000:0000:0002\",\
                    \"dhcp\" : \"0000:0000:0000:0:0000:0000:0000:0003\",\
                    \"metric\" : 10\
                }\
            }\
        }"),
        lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_netinfo_valid_msg_groups_empty(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        {\
            \"type\":\"network\",\
            \"iface\":{\
                \"IPv4\":{\
                },\
                \"IPv6\":{\
                }\
            }\
        }"),
        lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_netinfo_valid_msg_address_array_empty(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        {\
            \"type\":\"network\",\
            \"iface\":{\
                \"IPv4\":{\
                    \"address\" : [ \"0.0.0.0\" ]\
                },\
                \"IPv6\":{\
                    \"address\" : [ \"0000:0000:0000:0:0000:0000:0000:0000\" ]\
                }\
            }\
        }"),
        lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_netinfo_valid_msg_net_data_free(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        {\
            \"type\":\"network\",\
            \"iface\":{\
                \"IPv4\":{\
                    \"address\" : [ \"0.0.0.0\" ],\
                    \"netmask\" : [ \"255.255.255.255\" ],\
                    \"broadcast\" : [ \"0.0.0.1\" ]\
                },\
                \"IPv6\":{\
                    \"address\" : [ \"0000:0000:0000:0:0000:0000:0000:0000\" ],\
                    \"netmask\" : [ \"0000::\" ],\
                    \"broadcast\" : [ \"0000:0000:0000:0:0000:0000:0000:0001\" ]\
                }\
            }\
        }"),
        lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_netinfo_valid_network_end_msg(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        {\
            \"type\":\"network_end\",\
            \"ID\":100\
        }"),
        lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_osinfo_valid_msg(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        {\
            \"type\":\"OS\",\
            \"ID\":100,\
            \"timestamp\":\"2021/10/29 14:26:24\",\
            \"inventory\":{\
                \"os_name\":\"name\",\
                \"os_version\":\"0.0.1\",\
                \"os_codename\":\"test\",\
                \"hostname\":\"host\",\
                \"architecture\":\"x86\",\
                \"os_major\":\"0\",\
                \"os_minor\":\"0\",\
                \"os_build\":\"1\",\
                \"os_platform\":\"platform\",\
                \"sysname\":\"sysname\",\
                \"release\":\"R1\",\
                \"version\":\"0.0.2\",\
                \"os_release\":\"R2\",\
                \"os_patch\":\"P1\",\
                \"os_display_version\":\"0.0.1-R2-P1\"\
            }\
        }"),
        lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_osinfo_valid_msg_inventory_empty(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        {\
            \"type\":\"OS\",\
            \"inventory\":{\
            }\
        }"),
        lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_package_valid_msg(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        {\
            \"type\":\"program\",\
            \"ID\":100,\
            \"timestamp\":\"2021/10/29 14:26:24\",\
            \"program\":{\
                \"format\":\"format\",\
                \"name\":\"name\",\
                \"priority\":\"priority\",\
                \"group\":\"group\",\
                \"size\": 0,\
                \"vendor\":\"vendor\",\
                \"version\":\"version\",\
                \"architecture\":\"architecture\",\
                \"multi-arch\":\"multi-arch\",\
                \"source\":\"source\",\
                \"description\":\"description\",\
                \"install_time\":\"install_time\",\
                \"location\":\"location\"\
            }\
        }"),
        lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_package_valid_msg_program_empty(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        {\
            \"type\":\"program\",\
            \"ID\":100,\
            \"program\":{\
            }\
        }"),
        lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_package_valid_msg_without_ID(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        {\
            \"type\":\"program\",\
            \"program\":{\
            }\
        }"),
        lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_package_valid_msg_program_end(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        {\
            \"type\":\"program_end\",\
            \"ID\":100\
        }"),
        lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_port_valid_msg(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        {\
            \"type\":\"port\",\
            \"ID\":100,\
            \"timestamp\":\"2021/10/29 14:26:24\",\
            \"port\":{\
                \"protocol\":\"protocol\",\
                \"local_ip\":\"0.0.0.0\",\
                \"local_port\":10,\
                \"remote_ip\":\"0.0.0.1\",\
                \"remote_port\":11,\
                \"tx_queue\":12,\
                \"rx_queue\":13,\
                \"inode\":14,\
                \"state\":\"ok\",\
                \"PID\":15,\
                \"process\":\"process\"\
            }\
        }"),
        lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_port_valid_msg_port_empty(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        {\
            \"type\":\"port\",\
            \"ID\":100,\
            \"port\":{\
            }\
        }"),
        lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_port_valid_msg_without_ID(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        {\
            \"type\":\"port\",\
            \"port\":{\
            }\
        }"),
        lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_port_valid_msg_port_end(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        {\
            \"type\":\"port_end\",\
            \"ID\":100\
        }"),
        lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_process_valid_msg(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        {\
            \"type\":\"process\",\
            \"ID\":100,\
            \"timestamp\":\"2021/10/29 14:26:24\",\
            \"process\":{\
                \"pid\":10,\
                \"name\":\"name\",\
                \"state\":\"state\",\
                \"ppid\":11,\
                \"utime\":12,\
                \"stime\":13,\
                \"cmd\":\"cmd\",\
                \"argvs\": [ \"arg\" ],\
                \"euser\":\"euser\",\
                \"ruser\":\"ruser\",\
                \"suser\":\"suser\",\
                \"egroup\":\"egroup\",\
                \"rgroup\":\"rgroup\",\
                \"sgroup\":\"sgroup\",\
                \"fgroup\":\"fgroup\",\
                \"priority\":14,\
                \"nice\":15,\
                \"size\":16,\
                \"vm_size\":17,\
                \"resident\":18,\
                \"share\":19,\
                \"start_time\":20,\
                \"pgrp\":21,\
                \"session\":22,\
                \"nlwp\":23,\
                \"tgid\":24,\
                \"tty\":25,\
                \"processor\":26\
            }\
        }"),
        lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_process_valid_msg_process_empty(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        {\
            \"type\":\"process\",\
            \"ID\":100,\
            \"process\":{\
            }\
        }"),
        lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_process_valid_msg_without_ID(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        {\
            \"type\":\"process\",\
            \"process\":{\
            }\
        }"),
        lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
    return 0;
}

int test_setup_process_valid_msg_process_end(void **state)
{
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    if (lf->log = strdup("\
        {\
            \"type\":\"process_end\",\
            \"ID\":100\
        }"),
        lf->log == NULL)
        return -1;
    os_strdup("(>syscollector", lf->location);
    os_strdup("001", lf->agent_id);

    *state = lf;
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

void test_syscollector_dbsync_users_valid_msg_modified(void **state)
{
    Eventinfo *lf = *state;

    const char *query = "agent 001 dbsync users MODIFIED "
        "{" 
            "\"checksum\":\"da281181ada27e31ce8649ba38c0e2de9b242e40\","
            "\"host_ip\":null,"
            "\"process_pid\":null,"
            "\"scan_time\":\"2025/06/04 20:16:55\","
            "\"user_full_name\":\"daemon\","
            "\"user_group_id\":1,"
            "\"user_group_id_signed\":1,"
            "\"user_home\":\"/usr/sbin\","
            "\"user_id\":1,"
            "\"user_is_remote\":1,"
            "\"user_last_login\":null,"
            "\"user_name\":\"daemon\","
            "\"user_password_expiration_date\":-1,"
            "\"user_password_hash_algorithm\":null,"
            "\"user_password_inactive_days\":-1,"
            "\"user_password_last_change\":19977,"
            "\"user_password_max_days_between_changes\":99999,"
            "\"user_password_min_days_between_changes\":0,"
            "\"user_password_status\":\"locked\","
            "\"user_password_warning_days_before_expiration\":7,"
            "\"user_shell\":\"/usr/sbin/nologin\","
            "\"user_uid_signed\":1"
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

void test_syscollector_dbsync_groups_valid_msg_modified(void **state)
{
    Eventinfo *lf = *state;

    const char *query = "agent 001 dbsync groups MODIFIED "
        "{"
            "\"checksum\":\"0de011b2818a50c78529f56c00433857622bfdb8\","
            "\"group_description\":\"Les membres du groupe Administrateurs disposent d'un accès complet et illimité à l'ordinateur et au domaine\","
            "\"group_id\":544,"
            "\"group_id_signed\":544,"
            "\"group_is_hidden\":null,"
            "\"group_name\":\"Administrateurs\","
            "\"group_users\":\"54358:Administrateur\","
            "\"group_uuid\":\"S-1-5-32-544\","
            "\"scan_time\":\"2025/06/11 14:59:57\""
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

void test_syscollector_dbsync_users_valid_msg_inserted(void **state)
{
    Eventinfo *lf = *state;

    const char *query = "agent 001 dbsync users INSERTED "
        "{" 
            "\"checksum\":\"da281181ada27e31ce8649ba38c0e2de9b242e40\","
            "\"host_ip\":null,"
            "\"process_pid\":null,"
            "\"scan_time\":\"2025/06/04 20:16:55\","
            "\"user_full_name\":\"daemon\","
            "\"user_group_id\":1,"
            "\"user_group_id_signed\":1,"
            "\"user_home\":\"/usr/sbin\","
            "\"user_id\":1,"
            "\"user_is_remote\":1,"
            "\"user_last_login\":null,"
            "\"user_name\":\"daemon\","
            "\"user_password_expiration_date\":-1,"
            "\"user_password_hash_algorithm\":null,"
            "\"user_password_inactive_days\":-1,"
            "\"user_password_last_change\":19977,"
            "\"user_password_max_days_between_changes\":99999,"
            "\"user_password_min_days_between_changes\":0,"
            "\"user_password_status\":\"locked\","
            "\"user_password_warning_days_before_expiration\":7,"
            "\"user_shell\":\"/usr/sbin/nologin\","
            "\"user_uid_signed\":1"
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

void test_syscollector_dbsync_groups_valid_msg_inserted(void **state)
{
    Eventinfo *lf = *state;

    const char *query = "agent 001 dbsync groups INSERTED "
        "{"
            "\"checksum\":\"0de011b2818a50c78529f56c00433857622bfdb8\","
            "\"group_description\":\"Les membres du groupe Administrateurs disposent d'un accès complet et illimité à l'ordinateur et au domaine\","
            "\"group_id\":544,"
            "\"group_id_signed\":544,"
            "\"group_is_hidden\":null,"
            "\"group_name\":\"Administrateurs\","
            "\"group_users\":\"54358:Administrateur\","
            "\"group_uuid\":\"S-1-5-32-544\","
            "\"scan_time\":\"2025/06/11 14:59:57\""
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

void test_syscollector_hardware_valid (void **state)
{
    Eventinfo *lf = *state;
    const char *query = "agent 001 hardware save 100|"
            "2021/10/29 14:26:24|86|87|88|89.900000|"
            "90.000000|91.000000|92";
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

void test_syscollector_hardware_valid_inventory_empty (void **state)
{
    Eventinfo *lf = *state;
    const char *query = "agent 001 hardware save NULL|NULL|"
            "NULL|NULL|NULL|NULL|NULL|NULL|NULL";
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

void test_syscollector_hardware_valid_without_inventory (void **state)
{
    Eventinfo *lf = *state;

    int ret = DecodeSyscollector(lf, 0);

    assert_int_not_equal(ret, -1);
}

void test_syscollector_hardware_invalid_query (void **state)
{
    Eventinfo *lf = *state;
    int sock = 1;
    const char *result = "";

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_any(__wrap_wdbc_query_ex, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, -1);
    expect_string(__wrap__mdebug1, formatted_msg, 
            "Unable to send hardware information to Wazuh DB.");

    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, -1);
}

void test_syscollector_hardware_parse_result_not_ok (void **state)
{
    Eventinfo *lf = *state;
    const char *result = "not_ok ";
    int sock = 1;

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_any(__wrap_wdbc_query_ex, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);
    expect_string(__wrap__mdebug1, formatted_msg, 
            "Unable to send hardware information to Wazuh DB.");

    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, -1);
}

void test_syscollector_hotfix_valid (void **state)
{
    Eventinfo *lf = *state;
    const char *query = "agent 001 hotfix save 100|"
            "2021/10/29 14:26:24|hotfix-version-test|";
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

void test_syscollector_hotfix_valid_hotfix_end (void **state)
{
    Eventinfo *lf = *state;
    const char *query = "agent 001 hotfix del 100";
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

void test_syscollector_hotfix_invalid_query (void **state)
{
    Eventinfo *lf = *state;
    int sock = 1;
    const char *result = "";

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_any(__wrap_wdbc_query_ex, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, -1);
    expect_string(__wrap__mdebug1, formatted_msg, 
            "Unable to send hotfixes information to Wazuh DB.");

    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, -1);
}

void test_syscollector_hotfix_invalid_hotfix_end_query (void **state)
{
    test_syscollector_hotfix_invalid_query(state);
}

void test_syscollector_hotfix_without_ID (void **state)
{
    Eventinfo *lf = *state;

    expect_string(__wrap__mdebug1, formatted_msg, 
            "Unable to send hotfixes information to Wazuh DB.");

    int ret = DecodeSyscollector(lf, 0);

    assert_int_not_equal(ret, -1);
}

void test_syscollector_hotfix_parse_result_not_ok (void **state)
{
    Eventinfo *lf = *state;
    const char *result = "not_ok ";
    int sock = 1;

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_any(__wrap_wdbc_query_ex, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);
    expect_string(__wrap__mdebug1, formatted_msg, 
            "Unable to send hotfixes information to Wazuh DB.");

    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, -1);
}

void test_syscollector_netinfo_valid (void **state)
{
    Eventinfo *lf = *state;
    const char *queries[] = { "agent 001 netinfo save 100|2021/10/29 14:26:24|"
                "86|87|88|89|99|90|91|92|93|94|95|96|97|98",
            "agent 001 netproto save 100|86|0|0.0.0.2|0.0.0.3|10",
            "agent 001 netaddr save 100|86|0|0.0.0.0|255.255.255.255|0.0.0.1",
            "agent 001 netaddr save 100|86|0|0.0.1.0|255.255.255.254|0.0.1.1",
            "agent 001 netproto save 100|86|1|0000:0000:0000:0:0000:0000:0000:0002|"
                "0000:0000:0000:0:0000:0000:0000:0003|10",
            "agent 001 netaddr save 100|86|1|0000:0000:0000:0:0000:0000:0000:0000|"
                "0000::|0000:0000:0000:0:0000:0000:0000:0001", 
            "agent 001 netaddr save 100|86|1|0000:0000:0000:0:0000:0000:0001:0000|"
                "0001::|0000:0000:0000:0:0000:0000:0001:0001" };

    const char *result = "ok ";
    int sock = 1;
    size_t count = sizeof(queries) / sizeof(*queries);

    for (int i = 0; i < count; i++)
    {
        expect_any(__wrap_wdbc_query_ex, *sock);
        expect_string(__wrap_wdbc_query_ex, query, queries[i]);
        expect_any(__wrap_wdbc_query_ex, len);
        will_return(__wrap_wdbc_query_ex, result);
        will_return(__wrap_wdbc_query_ex, 0);
    }

    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, 0);
}

static const char *valid_empty_queries[] = { "agent 001 netinfo save NULL|NULL|"
                "NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL",
            "agent 001 netproto save NULL|NULL|0|NULL|NULL|NULL",
            "agent 001 netproto save NULL|NULL|1|NULL|"
                "NULL|NULL" };

void test_syscollector_netinfo_valid_groups_empty (void **state)
{
    Eventinfo *lf = *state;
    const char *result = "ok ";
    int sock = 1;
    size_t count = sizeof(valid_empty_queries) / sizeof(*valid_empty_queries);

    for (int i = 0; i < count; i++)
    {
        expect_any(__wrap_wdbc_query_ex, *sock);
        expect_string(__wrap_wdbc_query_ex, query, valid_empty_queries[i]);
        expect_any(__wrap_wdbc_query_ex, len);
        will_return(__wrap_wdbc_query_ex, result);
        will_return(__wrap_wdbc_query_ex, 0);
    }

    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, 0);
}

static const char *valid_empty_address_array_queries[] = { "agent 001 netinfo save NULL|NULL|"
                "NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL",
            "agent 001 netproto save NULL|NULL|0|NULL|NULL|NULL",
            "agent 001 netaddr save NULL|NULL|0|0.0.0.0|NULL|NULL",
            "agent 001 netproto save NULL|NULL|1|NULL|"
                "NULL|NULL",
            "agent 001 netaddr save NULL|NULL|1|0000:0000:0000:0:0000:0000:0000:0000|"
                "NULL|NULL" };

void test_syscollector_netinfo_valid_address_array_empty (void **state)
{
    Eventinfo *lf = *state;
    const char *result = "ok ";
    int sock = 1;
    size_t count = sizeof(valid_empty_address_array_queries) / sizeof(*valid_empty_address_array_queries);

    for (int i = 0; i < count; i++)
    {
        expect_any(__wrap_wdbc_query_ex, *sock);
        expect_string(__wrap_wdbc_query_ex, query, valid_empty_address_array_queries[i]);
        expect_any(__wrap_wdbc_query_ex, len);
        will_return(__wrap_wdbc_query_ex, result);
        will_return(__wrap_wdbc_query_ex, 0);
    }

    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, 0);
}

void test_syscollector_netinfo_valid_network_end (void **state)
{
    Eventinfo *lf = *state;
    const char *query = "agent 001 netinfo del 100";
    const char *result = "ok ";
    const char *result_not_ok = "not ok ";
    int sock = 1;

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    int ret = DecodeSyscollector(lf, &sock);
    assert_int_not_equal(ret, 0);
 
    // Invalid query
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, -1);
    expect_string(__wrap__merror, formatted_msg, "Unable to send netinfo message to Wazuh DB.");

    ret = DecodeSyscollector(lf, &sock);
    assert_int_not_equal(ret, -1);

    // Invalid parse
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result_not_ok);
    will_return(__wrap_wdbc_query_ex, 0);
    expect_string(__wrap__merror, formatted_msg, "Unable to send netinfo message to Wazuh DB.");

    ret = DecodeSyscollector(lf, &sock);
    assert_int_not_equal(ret, -1);
}

void test_syscollector_netinfo_invalid_query (void **state, const int edge, const bool parse)
{
    Eventinfo *lf = *state;

    const char *result = "ok ";
    const char *result_not_ok = "not ok ";
    int sock = 1;
    int i = 0;

    for (; i < edge; i++)
    {
        expect_any(__wrap_wdbc_query_ex, *sock);
        expect_string(__wrap_wdbc_query_ex, query, valid_empty_queries[i]);
        expect_any(__wrap_wdbc_query_ex, len);
        will_return(__wrap_wdbc_query_ex, result);
        will_return(__wrap_wdbc_query_ex, 0);
    }

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, valid_empty_queries[i]);
    expect_any(__wrap_wdbc_query_ex, len);
    if (parse)
    {
        will_return(__wrap_wdbc_query_ex, result_not_ok);
        will_return(__wrap_wdbc_query_ex, 0);
    }
    else
    {
        will_return(__wrap_wdbc_query_ex, result);
        will_return(__wrap_wdbc_query_ex, -1);
    }
    expect_string(__wrap__merror, formatted_msg, "Unable to send netinfo message to Wazuh DB.");

    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, -1);
}

void test_syscollector_netinfo_invalid_queries (void **state)
{
    size_t count = sizeof(valid_empty_queries) / sizeof(*valid_empty_queries);

    for (int i = 0; i < count; i++)
    {
        test_syscollector_netinfo_invalid_query (state, i, false);
        test_syscollector_netinfo_invalid_query (state, i, true);
    }
}

void test_syscollector_netinfo_invalid_address_array_empty_query (void **state, const int edge, const bool parse)
{
    Eventinfo *lf = *state;
    const char *result = "ok ";
    const char *result_not_ok = "not ok ";
    int sock = 1;
    int i = 0;

    for (; i < edge; i++)
    {
        expect_any(__wrap_wdbc_query_ex, *sock);
        expect_string(__wrap_wdbc_query_ex, query, valid_empty_address_array_queries[i]);
        expect_any(__wrap_wdbc_query_ex, len);
        will_return(__wrap_wdbc_query_ex, result);
        will_return(__wrap_wdbc_query_ex, 0);
    }

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, valid_empty_address_array_queries[i]);
    expect_any(__wrap_wdbc_query_ex, len);
    if (parse)
    {
        will_return(__wrap_wdbc_query_ex, result_not_ok);
        will_return(__wrap_wdbc_query_ex, 0);
    }
    else
    {
        will_return(__wrap_wdbc_query_ex, result);
        will_return(__wrap_wdbc_query_ex, -1);
    }
    expect_string(__wrap__merror, formatted_msg, "Unable to send netinfo message to Wazuh DB.");

    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, -1);
}

void test_syscollector_netinfo_invalid_address_array_empty_queries (void **state)
{
    size_t count = sizeof(valid_empty_address_array_queries) / sizeof(*valid_empty_address_array_queries);

    for (int i = 0; i < count; i++)
    {
        test_syscollector_netinfo_invalid_address_array_empty_query (state, i, false);
        test_syscollector_netinfo_invalid_address_array_empty_query (state, i, true);
    }
}

static const char *valid_empty_address_array_free[] = { "agent 001 netinfo save NULL|NULL|"
                "NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL",
            "agent 001 netproto save NULL|NULL|0|NULL|NULL|NULL",
            "agent 001 netaddr save NULL|NULL|0|0.0.0.0|255.255.255.255|0.0.0.1",
            "agent 001 netproto save NULL|NULL|1|NULL|"
                "NULL|NULL",
            "agent 001 netaddr save NULL|NULL|1|0000:0000:0000:0:0000:0000:0000:0000|"
                "0000::|0000:0000:0000:0:0000:0000:0000:0001" };

void test_syscollector_netinfo_net_array_data_free (void **state, const int edge, const bool parse)
{
    Eventinfo *lf = *state;
    const char *result = "ok ";
    const char *result_not_ok = "not ok ";
    int sock = 1;
    int i = 0;

    for (; i < edge; i++)
    {
        expect_any(__wrap_wdbc_query_ex, *sock);
        expect_string(__wrap_wdbc_query_ex, query, valid_empty_address_array_free[i]);
        expect_any(__wrap_wdbc_query_ex, len);
        will_return(__wrap_wdbc_query_ex, result);
        will_return(__wrap_wdbc_query_ex, 0);
    }

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, valid_empty_address_array_free[i]);
    expect_any(__wrap_wdbc_query_ex, len);
    if (parse)
    {
        will_return(__wrap_wdbc_query_ex, result_not_ok);
        will_return(__wrap_wdbc_query_ex, 0);
    }
    else
    {
        will_return(__wrap_wdbc_query_ex, result);
        will_return(__wrap_wdbc_query_ex, -1);
    }
    expect_string(__wrap__merror, formatted_msg, "Unable to send netinfo message to Wazuh DB.");

    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, -1);
}

void test_syscollector_netinfo_net_data_free (void **state)
{
    size_t count = sizeof(valid_empty_address_array_free) / sizeof(*valid_empty_address_array_free);

    for (int i = 0; i < count; i++)
    {
        test_syscollector_netinfo_net_array_data_free (state, i, false);
        test_syscollector_netinfo_net_array_data_free (state, i, true);
    }
}

void test_syscollector_osinfo_valid (void **state)
{
    Eventinfo *lf = *state;
    const char *query = "agent 001 osinfo set 100|2021/10/29 14:26:24|host|x86|"
            "name|0.0.1|test|0|0|1|platform|sysname|R1|0.0.2|R2|P1|0.0.1-R2-P1";
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

static const char *osinfo_empty_query = "agent 001 osinfo set NULL|NULL|NULL|NULL|NULL|NULL|"
            "NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL";

void test_syscollector_osinfo_valid_inventory_empty (void **state)
{
    Eventinfo *lf = *state;
    const char *result = "ok ";
    int sock = 1;

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, osinfo_empty_query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    int ret = DecodeSyscollector(lf, &sock);

    assert_int_not_equal(ret, 0);
}

void test_syscollector_osinfo_invalid_inventory_empty (void **state)
{
    Eventinfo *lf = *state;
    const char *result = "ok ";
    const char *result_not_ok = "not ok ";
    int sock = 1;

    // Invalid query out
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, osinfo_empty_query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, -1);
    expect_string(__wrap__mdebug1, formatted_msg, 
            "Unable to send osinfo message to Wazuh DB.");

    int ret = DecodeSyscollector(lf, &sock);
    assert_int_not_equal(ret, -1);

    // Invalid parse out
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, osinfo_empty_query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result_not_ok);
    will_return(__wrap_wdbc_query_ex, 0);
    expect_string(__wrap__mdebug1, formatted_msg, 
            "Unable to send osinfo message to Wazuh DB.");

    ret = DecodeSyscollector(lf, &sock);
    assert_int_not_equal(ret, -1);
}

void test_syscollector_package_valid (void **state)
{
    Eventinfo *lf = *state;
    const char *query = "agent 001 package save 100|2021/10/29 14:26:24|"
            "format|name|priority|group|0|vendor|install_time|version|"
            "architecture|multi-arch|source|description|location|"
            "0b50c065ffd996675a6b8e95e716091165796053";
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

extern int error_package;
extern int prev_package_id;

void test_syscollector_package_program_empty (void **state)
{
    Eventinfo *lf = *state;
    const char *query = "agent 001 package save 100|NULL|NULL|NULL|NULL|NULL|"
            "NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|"
            "da39a3ee5e6b4b0d3255bfef95601890afd80709";
    const char *result = "ok ";
    const char *result_not_ok = "not ok ";
    int sock = 1;

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    int ret = DecodeSyscollector(lf, &sock);
    assert_int_not_equal(ret, 0);

    // Clean previous package error, and exit
    error_package = 1;
    prev_package_id = 100;
    ret = DecodeSyscollector(lf, &sock);
    assert_int_not_equal(ret, 0);

    // Clean previous package error, and continue
    error_package = 1;
    prev_package_id++;
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    ret = DecodeSyscollector(lf, &sock);
    assert_int_not_equal(ret, 0);

    // Query error out
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, -1);
    expect_string(__wrap__mdebug1, formatted_msg, 
            "Unable to send packages information to Wazuh DB.");

    ret = DecodeSyscollector(lf, &sock);
    assert_int_not_equal(ret, -1);

    // Parse error out
    error_package = 0;
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result_not_ok);
    will_return(__wrap_wdbc_query_ex, 0);
    expect_string(__wrap__mdebug1, formatted_msg, 
            "Unable to send packages information to Wazuh DB.");

    ret = DecodeSyscollector(lf, &sock);
    assert_int_not_equal(ret, -1);
}

void test_syscollector_package_valid_without_ID (void **state)
{
    Eventinfo *lf = *state;

    expect_string(__wrap__mdebug1, formatted_msg, 
            "Unable to send packages information to Wazuh DB.");

    int ret = DecodeSyscollector(lf, NULL);

    assert_int_not_equal(ret, -1);
}

void test_syscollector_package_program_end (void **state)
{
    Eventinfo *lf = *state;
    const char *query = "agent 001 package del 100";
    const char *result = "ok ";
    const char *result_not_ok = "not ok ";
    int sock = 1;

    error_package = 0;
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    int ret = DecodeSyscollector(lf, &sock);
    assert_int_not_equal(ret, 0);

    // Invalid query out
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, -1);
    expect_string(__wrap__mdebug1, formatted_msg, 
            "Unable to send packages information to Wazuh DB.");

    ret = DecodeSyscollector(lf, &sock);
    assert_int_not_equal(ret, -1);

    // Return ok after query error
    ret = DecodeSyscollector(lf, &sock);
    assert_int_not_equal(ret, 0);

    // Return ok after query error, changing package_id
    prev_package_id++;
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result_not_ok);
    will_return(__wrap_wdbc_query_ex, 0);
    expect_string(__wrap__mdebug1, formatted_msg, 
            "Unable to send packages information to Wazuh DB.");

    ret = DecodeSyscollector(lf, &sock);
    assert_int_not_equal(ret, -1);

    // Invalid parse out
    error_package = 0;
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result_not_ok);
    will_return(__wrap_wdbc_query_ex, 0);
    expect_string(__wrap__mdebug1, formatted_msg, 
            "Unable to send packages information to Wazuh DB.");

    ret = DecodeSyscollector(lf, &sock);
    assert_int_not_equal(ret, -1);
}

void test_syscollector_port_valid (void **state)
{
    Eventinfo *lf = *state;
    const char *query = "agent 001 port save 100|2021/10/29 14:26:24|protocol|"
            "0.0.0.0|10|0.0.0.1|11|12|13|14|ok|15|process";
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

extern int error_port;
extern int prev_port_id;

void test_syscollector_port_empty (void **state)
{
    Eventinfo *lf = *state;
    const char *query = "agent 001 port save 100|NULL|NULL|NULL|NULL|NULL|NULL|"
            "NULL|NULL|NULL|NULL|NULL|NULL";
    const char *result = "ok ";
    const char *result_not_ok = "not ok ";
    int sock = 1;

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    int ret = DecodeSyscollector(lf, &sock);
    assert_int_not_equal(ret, 0);

    // Clean previous port error, and exit
    error_port = 1;
    prev_port_id = 100;
    ret = DecodeSyscollector(lf, &sock);
    assert_int_not_equal(ret, 0);

    // Clean previous port error, and continue
    error_port = 1;
    prev_port_id++;
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    ret = DecodeSyscollector(lf, &sock);
    assert_int_not_equal(ret, 0);

    // Query error out
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, -1);
    expect_string(__wrap__mdebug1, formatted_msg, 
            "Unable to send ports information to Wazuh DB.");

    ret = DecodeSyscollector(lf, &sock);
    assert_int_not_equal(ret, -1);

    // Parse error out
    error_port = 0;
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result_not_ok);
    will_return(__wrap_wdbc_query_ex, 0);
    expect_string(__wrap__mdebug1, formatted_msg, 
            "Unable to send ports information to Wazuh DB.");

    ret = DecodeSyscollector(lf, &sock);
    assert_int_not_equal(ret, -1);
}

void test_syscollector_port_valid_without_ID (void **state)
{
    Eventinfo *lf = *state;

    expect_string(__wrap__mdebug1, formatted_msg, 
            "Unable to send ports information to Wazuh DB.");

    int ret = DecodeSyscollector(lf, NULL);

    assert_int_not_equal(ret, -1);
}

void test_syscollector_port_end (void **state)
{
    Eventinfo *lf = *state;
    const char *query = "agent 001 port del 100";
    const char *result = "ok ";
    const char *result_not_ok = "not ok ";
    int sock = 1;

    error_port = 0;
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    int ret = DecodeSyscollector(lf, &sock);
    assert_int_not_equal(ret, 0);

    // Invalid query out
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, -1);
    expect_string(__wrap__mdebug1, formatted_msg, 
            "Unable to send ports information to Wazuh DB.");

    ret = DecodeSyscollector(lf, &sock);
    assert_int_not_equal(ret, -1);

    // Return ok after query error
    ret = DecodeSyscollector(lf, &sock);
    assert_int_not_equal(ret, 0);

    // Return ok after query error, changing port_id
    prev_port_id++;
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result_not_ok);
    will_return(__wrap_wdbc_query_ex, 0);
    expect_string(__wrap__mdebug1, formatted_msg, 
            "Unable to send ports information to Wazuh DB.");

    ret = DecodeSyscollector(lf, &sock);
    assert_int_not_equal(ret, -1);

    // Invalid parse out
    error_port = 0;
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result_not_ok);
    will_return(__wrap_wdbc_query_ex, 0);
    expect_string(__wrap__mdebug1, formatted_msg, 
            "Unable to send ports information to Wazuh DB.");

    ret = DecodeSyscollector(lf, &sock);
    assert_int_not_equal(ret, -1);
}

void test_syscollector_process_valid (void **state)
{
    Eventinfo *lf = *state;
    const char *query = "agent 001 process save 100|2021/10/29 14:26:24|10|name|"
            "state|11|12|13|cmd|arg|euser|ruser|suser|egroup|rgroup|sgroup|fgroup|"
            "14|15|16|17|18|19|20|21|22|23|24|25|26";
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

extern int error_process;
extern int prev_process_id;

void test_syscollector_process_empty (void **state)
{
    Eventinfo *lf = *state;
    const char *query = "agent 001 process save 100|NULL|NULL|NULL|NULL|NULL|"
            "NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|"
            "NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL|NULL";
    const char *result = "ok ";
    const char *result_not_ok = "not ok ";
    int sock = 1;

    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    int ret = DecodeSyscollector(lf, &sock);
    assert_int_not_equal(ret, 0);

    // Clean previous process error, and exit
    error_process = 1;
    prev_process_id = 100;
    ret = DecodeSyscollector(lf, &sock);
    assert_int_not_equal(ret, 0);

    // Clean previous process error, and continue
    error_process = 1;
    prev_process_id++;
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    ret = DecodeSyscollector(lf, &sock);
    assert_int_not_equal(ret, 0);

    // Query error out
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, -1);
    expect_string(__wrap__mdebug1, formatted_msg, 
            "Unable to send processes information to Wazuh DB.");

    ret = DecodeSyscollector(lf, &sock);
    assert_int_not_equal(ret, -1);

    // Parse error out
    error_process = 0;
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result_not_ok);
    will_return(__wrap_wdbc_query_ex, 0);
    expect_string(__wrap__mdebug1, formatted_msg, 
            "Unable to send processes information to Wazuh DB.");

    ret = DecodeSyscollector(lf, &sock);
    assert_int_not_equal(ret, -1);
}

void test_syscollector_process_valid_without_ID (void **state)
{
    Eventinfo *lf = *state;

    expect_string(__wrap__mdebug1, formatted_msg, 
            "Unable to send processes information to Wazuh DB.");

    int ret = DecodeSyscollector(lf, NULL);

    assert_int_not_equal(ret, -1);
}

void test_syscollector_process_end (void **state)
{
    Eventinfo *lf = *state;
    const char *query = "agent 001 process del 100";
    const char *result = "ok ";
    const char *result_not_ok = "not ok ";
    int sock = 1;

    error_process = 0;
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, 0);

    int ret = DecodeSyscollector(lf, &sock);
    assert_int_not_equal(ret, 0);

    // Invalid query out
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result);
    will_return(__wrap_wdbc_query_ex, -1);
    expect_string(__wrap__mdebug1, formatted_msg, 
            "Unable to send processes information to Wazuh DB.");

    ret = DecodeSyscollector(lf, &sock);
    assert_int_not_equal(ret, -1);

    // Return ok after query error
    ret = DecodeSyscollector(lf, &sock);
    assert_int_not_equal(ret, 0);

    // Return ok after query error, changing package_id
    prev_process_id++;
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result_not_ok);
    will_return(__wrap_wdbc_query_ex, 0);
    expect_string(__wrap__mdebug1, formatted_msg, 
            "Unable to send processes information to Wazuh DB.");

    ret = DecodeSyscollector(lf, &sock);
    assert_int_not_equal(ret, -1);

    // Invalid parse out
    error_process = 0;
    expect_any(__wrap_wdbc_query_ex, *sock);
    expect_string(__wrap_wdbc_query_ex, query, query);
    expect_any(__wrap_wdbc_query_ex, len);
    will_return(__wrap_wdbc_query_ex, result_not_ok);
    will_return(__wrap_wdbc_query_ex, 0);
    expect_string(__wrap__mdebug1, formatted_msg, 
            "Unable to send processes information to Wazuh DB.");

    ret = DecodeSyscollector(lf, &sock);
    assert_int_not_equal(ret, -1);
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
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_users_valid_msg_modified, test_setup_users_valid_msg_modified, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_groups_valid_msg_modified, test_setup_groups_valid_msg_modified, test_cleanup),
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
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_os_valid_msg_no_result_payload, test_setup_os_valid_msg_modified, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_users_valid_msg_inserted, test_setup_users_valid_msg_inserted, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_dbsync_groups_valid_msg_inserted, test_setup_groups_valid_msg_inserted, test_cleanup),
        // Hardware tests
        cmocka_unit_test_setup_teardown(test_syscollector_hardware_valid, test_setup_hardware_valid_msg, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_hardware_valid_inventory_empty, test_setup_hardware_valid_msg_inventory_empty, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_hardware_valid_without_inventory, test_setup_hardware_valid_msg_without_inventory, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_hardware_invalid_query, test_setup_hardware_valid_msg_inventory_empty, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_hardware_parse_result_not_ok, test_setup_hardware_valid_msg_inventory_empty, test_cleanup),
        // Hotfix tests
        cmocka_unit_test_setup_teardown(test_syscollector_hotfix_valid, test_setup_hotfix_valid_msg, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_hotfix_valid_hotfix_end, test_setup_hotfix_valid_hotfix_end_msg, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_hotfix_invalid_query, test_setup_hotfix_valid_msg, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_hotfix_invalid_hotfix_end_query, test_setup_hotfix_valid_hotfix_end_msg, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_hotfix_without_ID, test_setup_hotfix_valid_msg_empty, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_hotfix_parse_result_not_ok, test_setup_hotfix_valid_msg, test_cleanup),
        // Netinfo tests
        cmocka_unit_test_setup_teardown(test_syscollector_netinfo_valid, test_setup_netinfo_valid_msg, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_netinfo_valid_groups_empty, test_setup_netinfo_valid_msg_groups_empty, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_netinfo_valid_address_array_empty, test_setup_netinfo_valid_msg_address_array_empty, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_netinfo_valid_network_end, test_setup_netinfo_valid_network_end_msg, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_netinfo_invalid_queries, test_setup_netinfo_valid_msg_groups_empty, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_netinfo_invalid_address_array_empty_queries, test_setup_netinfo_valid_msg_address_array_empty, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_netinfo_net_data_free, test_setup_netinfo_valid_msg_net_data_free, test_cleanup),
        // OSinfo tests
        cmocka_unit_test_setup_teardown(test_syscollector_osinfo_valid, test_setup_osinfo_valid_msg, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_osinfo_valid_inventory_empty, test_setup_osinfo_valid_msg_inventory_empty, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_osinfo_invalid_inventory_empty, test_setup_osinfo_valid_msg_inventory_empty, test_cleanup),
        // Package tests
        cmocka_unit_test_setup_teardown(test_syscollector_package_valid, test_setup_package_valid_msg, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_package_program_empty, test_setup_package_valid_msg_program_empty, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_package_valid_without_ID, test_setup_package_valid_msg_without_ID, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_package_program_end, test_setup_package_valid_msg_program_end, test_cleanup),
        // Port tests
        cmocka_unit_test_setup_teardown(test_syscollector_port_valid, test_setup_port_valid_msg, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_port_empty, test_setup_port_valid_msg_port_empty, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_port_valid_without_ID, test_setup_port_valid_msg_without_ID, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_port_end, test_setup_port_valid_msg_port_end, test_cleanup),
        // Process tests
        cmocka_unit_test_setup_teardown(test_syscollector_process_valid, test_setup_process_valid_msg, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_process_empty, test_setup_process_valid_msg_process_empty, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_process_valid_without_ID, test_setup_process_valid_msg_without_ID, test_cleanup),
        cmocka_unit_test_setup_teardown(test_syscollector_process_end, test_setup_process_valid_msg_process_end, test_cleanup)
    };
    return cmocka_run_group_tests(tests, test_setup_global, NULL);
}
