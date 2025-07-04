/*
 * Wazuh Database Daemon
 * Copyright (C) 2015, Wazuh Inc.
 * January 16, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wazuhdb_op.h"
#include "wdb.h"
#include "wdb_agents.h"
#include "external/cJSON/cJSON.h"
#include "wdb_state.h"

#define HOTFIXES_FIELD_COUNT 3
static struct column_list const TABLE_HOTFIXES[HOTFIXES_FIELD_COUNT+1] = {
    { .value = {FIELD_INTEGER, 1, true, false, NULL, "scan_id", {.integer = 0}, true}, .next = &TABLE_HOTFIXES[1] },
    { .value = {FIELD_TEXT, 2, false, false, NULL,"scan_time", {.text = ""}, true}, .next = &TABLE_HOTFIXES[2] },
    { .value = {FIELD_TEXT, 3, false, true, NULL,"hotfix", {.text = ""}, true}, .next = &TABLE_HOTFIXES[3] },
    { .value = {FIELD_TEXT, 4, false, false, NULL,"checksum", {.text = ""}, false}, .next = NULL },
};

#define PROCESSES_FIELD_COUNT 30
static struct column_list const TABLE_PROCESSES[PROCESSES_FIELD_COUNT+1] = {
    { .value = { FIELD_INTEGER, 1, true, false, NULL, "scan_id", {.integer = 0}, true}, .next = &TABLE_PROCESSES[1] },
    { .value = { FIELD_TEXT, 2, false, false, NULL,"scan_time", {.text = ""}, true}, .next = &TABLE_PROCESSES[2] },
    { .value = { FIELD_TEXT, 3, false, true, NULL, "pid", {.text = ""}, true}, .next = &TABLE_PROCESSES[3] },
    { .value = { FIELD_TEXT, 4, false, false, NULL, "name", {.text = ""}, true}, .next = &TABLE_PROCESSES[4] },
    { .value = { FIELD_TEXT, 5, false, false, NULL, "state", {.text = ""}, true}, .next = &TABLE_PROCESSES[5] },
    { .value = { FIELD_INTEGER, 6, false, false, NULL, "ppid", {.integer = 0}, true}, .next = &TABLE_PROCESSES[6] },
    { .value = { FIELD_INTEGER, 7, false, false, NULL, "utime", {.integer = 0}, true}, .next = &TABLE_PROCESSES[7] },
    { .value = { FIELD_INTEGER, 8, false, false, NULL, "stime", {.integer = 0}, true}, .next = &TABLE_PROCESSES[8] },
    { .value = { FIELD_TEXT, 9, false, false, NULL, "cmd", {.text = ""}, true}, .next = &TABLE_PROCESSES[9] },
    { .value = { FIELD_TEXT, 10, false, false, NULL, "argvs", {.text = ""}, true}, .next = &TABLE_PROCESSES[10] },
    { .value = { FIELD_TEXT, 11, false, false, NULL, "euser", {.text = ""}, true}, .next = &TABLE_PROCESSES[11] },
    { .value = { FIELD_TEXT, 12, false, false, NULL, "ruser", {.text = ""}, true}, .next = &TABLE_PROCESSES[12] },
    { .value = { FIELD_TEXT, 13, false, false, NULL, "suser", {.text = ""}, true}, .next = &TABLE_PROCESSES[13] },
    { .value = { FIELD_TEXT, 14, false, false, NULL, "egroup", {.text = ""}, true}, .next = &TABLE_PROCESSES[14] },
    { .value = { FIELD_TEXT, 15, false, false, NULL, "rgroup", {.text = ""}, true}, .next = &TABLE_PROCESSES[15] },
    { .value = { FIELD_TEXT, 16, false, false, NULL, "sgroup", {.text = ""}, true}, .next = &TABLE_PROCESSES[16] },
    { .value = { FIELD_TEXT, 17, false, false, NULL, "fgroup", {.text = ""}, true}, .next = &TABLE_PROCESSES[17] },
    { .value = { FIELD_INTEGER, 18, false, false, NULL, "priority", {.integer = 0}, true}, .next = &TABLE_PROCESSES[18] },
    { .value = { FIELD_INTEGER, 19, false, false, NULL, "nice", {.integer = 0}, true}, .next = &TABLE_PROCESSES[19] },
    { .value = { FIELD_INTEGER, 20, false, false, NULL, "size", {.integer = 0}, true}, .next = &TABLE_PROCESSES[20] },
    { .value = { FIELD_INTEGER, 21, false, false, NULL, "vm_size", {.integer = 0}, true}, .next = &TABLE_PROCESSES[21] },
    { .value = { FIELD_INTEGER, 22, false, false, NULL, "resident", {.integer = 0}, true}, .next = &TABLE_PROCESSES[22] },
    { .value = { FIELD_INTEGER, 23, false, false, NULL, "share", {.integer = 0}, true}, .next = &TABLE_PROCESSES[23] },
    { .value = { FIELD_INTEGER_LONG, 24, false, false, NULL, "start_time", {.integer_long = 0LL}, true}, .next = &TABLE_PROCESSES[24] },
    { .value = { FIELD_INTEGER, 25, false, false, NULL, "pgrp", {.integer = 0}, true}, .next = &TABLE_PROCESSES[25] },
    { .value = { FIELD_INTEGER, 26, false, false, NULL, "session", {.integer = 0}, true}, .next = &TABLE_PROCESSES[26] },
    { .value = { FIELD_INTEGER, 27, false, false, NULL, "nlwp", {.integer = 0}, true}, .next = &TABLE_PROCESSES[27] },
    { .value = { FIELD_INTEGER, 28, false, false, NULL, "tgid", {.integer = 0}, true}, .next = &TABLE_PROCESSES[28] },
    { .value = { FIELD_INTEGER, 29, false, false, NULL, "tty", {.integer = 0}, true}, .next = &TABLE_PROCESSES[29] },
    { .value = { FIELD_INTEGER, 30, false, false, NULL, "processor", {.integer = 0}, true}, .next = &TABLE_PROCESSES[30] },
    { .value = { FIELD_TEXT, 31, false, false, NULL, "checksum", {.text = ""}, false}, .next = NULL }
};

#define NETIFACE_FIELD_COUNT 17
static struct column_list const TABLE_NETIFACE[NETIFACE_FIELD_COUNT+1] = {
    { .value = { FIELD_INTEGER, 1, true, false, NULL, "scan_id", {.integer = 0}, true}, .next = &TABLE_NETIFACE[1] },
    { .value = { FIELD_TEXT, 2, false, false, NULL, "scan_time", {.text = ""}, true}, .next = &TABLE_NETIFACE[2] },
    { .value = { FIELD_TEXT, 3, false, true, NULL, "name", {.text = ""}, true}, .next = &TABLE_NETIFACE[3] },
    { .value = { FIELD_TEXT, 4, false, false, NULL, "adapter", {.text = ""}, true}, .next = &TABLE_NETIFACE[4] },
    { .value = { FIELD_TEXT, 5, false, false, NULL, "type", {.text = ""}, true}, .next = &TABLE_NETIFACE[5] },
    { .value = { FIELD_TEXT, 6, false, false, NULL, "state", {.text = ""}, true}, .next = &TABLE_NETIFACE[6] },
    { .value = { FIELD_INTEGER, 7, false, false, NULL, "mtu", {.integer = 0}, true}, .next = &TABLE_NETIFACE[7] },
    { .value = { FIELD_TEXT, 8, false, false, NULL, "mac", {.text = ""}, true}, .next = &TABLE_NETIFACE[8] },
    { .value = { FIELD_INTEGER, 9, false, false, NULL, "tx_packets", {.integer = 0}, true}, .next = &TABLE_NETIFACE[9] },
    { .value = { FIELD_INTEGER, 10, false, false, NULL, "rx_packets", {.integer = 0}, true}, .next = &TABLE_NETIFACE[10] },
    { .value = { FIELD_INTEGER, 11, false, false, NULL, "tx_bytes", {.integer = 0}, true}, .next = &TABLE_NETIFACE[11] },
    { .value = { FIELD_INTEGER, 12, false, false, NULL, "rx_bytes", {.integer = 0}, true}, .next = &TABLE_NETIFACE[12] },
    { .value = { FIELD_INTEGER, 13, false, false, NULL, "tx_errors", {.integer = 0}, true}, .next = &TABLE_NETIFACE[13] },
    { .value = { FIELD_INTEGER, 14, false, false, NULL, "rx_errors", {.integer = 0}, true}, .next = &TABLE_NETIFACE[14] },
    { .value = { FIELD_INTEGER, 15, false, false, NULL, "tx_dropped", {.integer = 0}, true}, .next = &TABLE_NETIFACE[15] },
    { .value = { FIELD_INTEGER, 16, false, false, NULL, "rx_dropped", {.integer = 0}, true}, .next = &TABLE_NETIFACE[16] },
    { .value = { FIELD_TEXT, 17, false, false, NULL, "checksum", {.text = ""}, false}, .next = &TABLE_NETIFACE[17] },
    { .value = { FIELD_TEXT, 18, false, false, NULL, "item_id", {.text = ""}, true}, .next = NULL }
};

#define NETPROTO_FIELD_COUNT 7
static struct column_list const TABLE_NETPROTO[NETPROTO_FIELD_COUNT+1] = {
    { .value = { FIELD_INTEGER, 1, true, false, NULL, "scan_id", {.integer = 0}, true}, .next = &TABLE_NETPROTO[1]},
    { .value = { FIELD_TEXT, 2, false, true, NULL, "iface", {.text = ""}, true}, .next = &TABLE_NETPROTO[2]},
    { .value = { FIELD_TEXT, 3, false, true, NULL, "type", {.text = ""}, true}, .next = &TABLE_NETPROTO[3]},
    { .value = { FIELD_TEXT, 4, false, false, NULL, "gateway", {.text = ""}, true}, .next = &TABLE_NETPROTO[4]},
    { .value = { FIELD_TEXT, 5, false, false, NULL, "dhcp", {.text = ""}, false}, .next = &TABLE_NETPROTO[5]},
    { .value = { FIELD_INTEGER, 6, false, false, NULL, "metric", {.integer = 0}, true}, .next = &TABLE_NETPROTO[6]},
    { .value = { FIELD_TEXT, 7, false, false, NULL, "checksum", {.text = ""}, false}, .next = &TABLE_NETPROTO[7]},
    { .value = { FIELD_TEXT, 8, false, false, NULL, "item_id", {.text = ""}, true}, .next = NULL }
};

#define NETADDR_FIELD_COUNT 7
static struct column_list const TABLE_NETADDR[NETADDR_FIELD_COUNT+1] = {
    { .value = { FIELD_INTEGER, 1, true, false, NULL, "scan_id", {.integer = 0}, true}, .next = &TABLE_NETADDR[1]},
    { .value = { FIELD_TEXT, 2, false, true, NULL, "iface", {.text = ""}, true}, .next = &TABLE_NETADDR[2]},
    { .value = { FIELD_TEXT, 3, false, true, NULL, "proto", {.text = ""}, true}, .next = &TABLE_NETADDR[3]},
    { .value = { FIELD_TEXT, 4, false, true, NULL, "address", {.text = ""}, true}, .next = &TABLE_NETADDR[4]},
    { .value = { FIELD_TEXT, 5, false, false, NULL, "netmask", {.text = ""}, true}, .next = &TABLE_NETADDR[5]},
    { .value = { FIELD_TEXT, 6, false, false, NULL, "broadcast", {.text = ""}, true}, .next = &TABLE_NETADDR[6]},
    { .value = { FIELD_TEXT, 7, false, false, NULL, "checksum", {.text = ""}, false}, .next = &TABLE_NETADDR[7]},
    { .value = { FIELD_TEXT, 8, false, false, NULL, "item_id", {.text = ""}, true}, .next = NULL},
};

#define PORTS_FIELD_COUNT 14
static struct column_list const TABLE_PORTS[PORTS_FIELD_COUNT+1] = {
    { .value = { FIELD_INTEGER, 1, true, false, NULL, "scan_id", {.integer = 0}, true}, .next = &TABLE_PORTS[1]},
    { .value = { FIELD_TEXT, 2, false, false, NULL, "scan_time", {.text = ""}, true}, .next = &TABLE_PORTS[2]},
    { .value = { FIELD_TEXT, 3, false, true, NULL, "protocol", {.text = ""}, true}, .next = &TABLE_PORTS[3]},
    { .value = { FIELD_TEXT, 4, false, true, NULL, "local_ip", {.text = ""}, true}, .next = &TABLE_PORTS[4]},
    { .value = { FIELD_INTEGER, 5, false, true, NULL, "local_port", {.integer = 0}, true}, .next = &TABLE_PORTS[5]},
    { .value = { FIELD_TEXT, 6, false, false, NULL, "remote_ip", {.text = ""}, true}, .next = &TABLE_PORTS[6]},
    { .value = { FIELD_INTEGER, 7, false, false, NULL, "remote_port", {.integer = 0}, true}, .next = &TABLE_PORTS[7]},
    { .value = { FIELD_INTEGER, 8, false, false, NULL, "tx_queue", {.integer = 0}, true}, .next = &TABLE_PORTS[8]},
    { .value = { FIELD_INTEGER, 9, false, false, NULL, "rx_queue", {.integer = 0}, true}, .next = &TABLE_PORTS[9]},
    { .value = { FIELD_INTEGER_LONG, 10, false, true, NULL, "inode", {.integer_long = 0LL}, true}, .next = &TABLE_PORTS[10]},
    { .value = { FIELD_TEXT, 11, false, false, NULL, "state", {.text = ""}, true}, .next = &TABLE_PORTS[11]},
    { .value = { FIELD_INTEGER, 12, false, false, "pid", "PID", {.integer = 0}, true}, .next = &TABLE_PORTS[12]},
    { .value = { FIELD_TEXT, 13, false, false, NULL, "process", {.text = ""}, true}, .next = &TABLE_PORTS[13]},
    { .value = { FIELD_TEXT, 14, false, false, NULL, "checksum", {.text = ""}, false}, .next = &TABLE_PORTS[14]},
    { .value = { FIELD_TEXT, 15, false, false, NULL, "item_id", {.text = ""}, true}, .next = NULL},
};

#define PACKAGES_FIELD_COUNT 18
static struct column_list const TABLE_PACKAGES[PACKAGES_FIELD_COUNT+1] = {
    { .value = { FIELD_INTEGER, 1, true, false, NULL, "scan_id", {.integer = 0}, true}, .next = &TABLE_PACKAGES[1] },
    { .value = { FIELD_TEXT, 2, false, false, NULL, "scan_time", {.text = ""}, true}, .next = &TABLE_PACKAGES[2] },
    { .value = { FIELD_TEXT, 3, false, true, NULL, "format", {.text = ""}, false}, .next = &TABLE_PACKAGES[3] },
    { .value = { FIELD_TEXT, 4, false, true, NULL, "name", {.text = ""}, true}, .next = &TABLE_PACKAGES[4] },
    { .value = { FIELD_TEXT, 5, false, false, NULL, "priority", {.text = ""}, true}, .next = &TABLE_PACKAGES[5] },
    { .value = { FIELD_TEXT, 6, false, false, "groups", "section", {.text = ""}, true}, .next = &TABLE_PACKAGES[6] },
    { .value = { FIELD_INTEGER, 7, false, false, NULL, "size", {.integer = 0}, true}, .next = &TABLE_PACKAGES[7] },
    { .value = { FIELD_TEXT, 8, false, false, NULL, "vendor", {.text = ""}, true}, .next = &TABLE_PACKAGES[8] },
    { .value = { FIELD_TEXT, 9, false, false, NULL, "install_time", {.text = ""}, true}, .next = &TABLE_PACKAGES[9] },
    { .value = { FIELD_TEXT, 10, false, true, NULL, "version", {.text = ""}, true}, .next = &TABLE_PACKAGES[10] },
    { .value = { FIELD_TEXT, 11, false, true, NULL, "architecture", {.text = ""}, true}, .next = &TABLE_PACKAGES[11] },
    { .value = { FIELD_TEXT, 12, false, false, NULL, "multiarch", {.text = ""}, true}, .next = &TABLE_PACKAGES[12] },
    { .value = { FIELD_TEXT, 13, false, false, NULL, "source", {.text = ""}, true}, .next = &TABLE_PACKAGES[13] },
    { .value = { FIELD_TEXT, 14, false, false, NULL, "description", {.text = ""}, true}, .next = &TABLE_PACKAGES[14] },
    { .value = { FIELD_TEXT, 15, false, true, NULL, "location", {.text = ""}, false}, .next = &TABLE_PACKAGES[15] },
    { .value = { FIELD_TEXT, 16, true, false, NULL, "cpe", {.text = ""}, true}, .next = &TABLE_PACKAGES[16] },
    { .value = { FIELD_TEXT, 17, true, false, NULL, "msu_name", {.text = ""}, true}, .next = &TABLE_PACKAGES[17] },
    { .value = { FIELD_TEXT, 18, false, false, NULL, "checksum", {.text = ""}, false}, .next = &TABLE_PACKAGES[18] },
    { .value = { FIELD_TEXT, 19, false, false, NULL, "item_id", {.text = ""}, true}, .next = NULL },
};

#define OS_FIELD_COUNT 18
static struct column_list const TABLE_OS[OS_FIELD_COUNT+1] = {
    { .value = { FIELD_INTEGER, 1, true, false, NULL, "scan_id", {.integer = 0}, true}, .next = &TABLE_OS[1] },
    { .value = { FIELD_TEXT, 2, false, false, NULL, "scan_time", {.text = ""}, true}, .next = &TABLE_OS[2] },
    { .value = { FIELD_TEXT, 3, false, false, NULL, "hostname", {.text = ""}, true}, .next = &TABLE_OS[3] },
    { .value = { FIELD_TEXT, 4, false, false, NULL, "architecture", {.text = ""}, true}, .next = &TABLE_OS[4] },
    { .value = { FIELD_TEXT, 5, false, true, NULL, "os_name", {.text = ""}, true}, .next = &TABLE_OS[5] },
    { .value = { FIELD_TEXT, 6, false, false, NULL, "os_version", {.text = ""}, true}, .next = &TABLE_OS[6] },
    { .value = { FIELD_TEXT, 7, false, false, NULL, "os_codename", {.text = ""}, true}, .next = &TABLE_OS[7] },
    { .value = { FIELD_TEXT, 8, false, false, NULL, "os_major", {.text = ""}, true}, .next = &TABLE_OS[8] },
    { .value = { FIELD_TEXT, 9, false, false, NULL, "os_minor", {.text = ""}, true}, .next = &TABLE_OS[9] },
    { .value = { FIELD_TEXT, 10, false, false, NULL, "os_patch", {.text = ""}, true}, .next = &TABLE_OS[10] },
    { .value = { FIELD_TEXT, 11, false, false, NULL, "os_build", {.text = ""}, true}, .next = &TABLE_OS[11] },
    { .value = { FIELD_TEXT, 12, false, false, NULL, "os_platform", {.text = ""}, true}, .next = &TABLE_OS[12] },
    { .value = { FIELD_TEXT, 13, false, false, NULL, "sysname", {.text = ""}, true}, .next = &TABLE_OS[13] },
    { .value = { FIELD_TEXT, 14, false, false, NULL, "release", {.text = ""}, true}, .next = &TABLE_OS[14] },
    { .value = { FIELD_TEXT, 15, false, false, NULL, "version", {.text = ""}, true}, .next = &TABLE_OS[15] },
    { .value = { FIELD_TEXT, 16, false, false, NULL, "os_release", {.text = ""}, true}, .next = &TABLE_OS[16] },
    { .value = { FIELD_TEXT, 17, false, false, NULL, "checksum", {.text = ""}, false}, .next = &TABLE_OS[17] },
    { .value = { FIELD_TEXT, 18, false, false, NULL, "os_display_version", {.text = ""}, true}, .next = &TABLE_OS[18] },
    { .value = { FIELD_TEXT, 19, true, false, NULL, "reference", {.text = ""}, false}, .next = NULL },
};

#define HARDWARE_FIELD_COUNT 9
static struct column_list const TABLE_HARDWARE[HARDWARE_FIELD_COUNT+1] = {
    { .value = { FIELD_INTEGER, 1, true, false, NULL, "scan_id", {.integer = 0}, true}, .next = &TABLE_HARDWARE[1] },
    { .value = { FIELD_TEXT, 2, false, false, NULL, "scan_time", {.text = ""}, true}, .next = &TABLE_HARDWARE[2] },
    { .value = { FIELD_TEXT, 3, false, true, NULL, "board_serial", {.text = ""}, true}, .next = &TABLE_HARDWARE[3] },
    { .value = { FIELD_TEXT, 4, false, false, NULL, "cpu_name", {.text = ""}, true}, .next = &TABLE_HARDWARE[4] },
    { .value = { FIELD_INTEGER, 5, false, false, NULL, "cpu_cores", {.integer = 0}, true}, .next = &TABLE_HARDWARE[5] },
    { .value = { FIELD_REAL, 6, false, false, NULL, "cpu_mhz", {.real = 0.0}, true}, .next = &TABLE_HARDWARE[6] },
    { .value = { FIELD_INTEGER, 7, false, false, NULL, "ram_total", {.integer = 0}, true}, .next = &TABLE_HARDWARE[7] },
    { .value = { FIELD_INTEGER, 8, false, false, NULL, "ram_free", {.integer = 0}, true}, .next = &TABLE_HARDWARE[8] },
    { .value = { FIELD_INTEGER, 9, false, false, NULL, "ram_usage", {.integer = 0}, true}, .next = &TABLE_HARDWARE[9] },
    { .value = { FIELD_TEXT, 10, false, false, NULL, "checksum", {.text = ""}, false}, .next = NULL }
};

#define USERS_FIELD_COUNT 33
static struct column_list const TABLE_USERS[USERS_FIELD_COUNT+1] = {
    { .value = { FIELD_INTEGER, 1, true, false, NULL, "scan_id", {.integer = 0}, true}, .next = &TABLE_USERS[1]},
    { .value = { FIELD_TEXT, 2, false, false, NULL, "scan_time", {.text = ""}, true}, .next = &TABLE_USERS[2]},
    { .value = { FIELD_TEXT, 3, false, true, NULL, "user_name", {.text = ""}, true}, .next = &TABLE_USERS[3]},
    { .value = { FIELD_TEXT, 4, false, false, NULL, "user_full_name", {.text = ""}, true}, .next = &TABLE_USERS[4]},
    { .value = { FIELD_TEXT, 5, false, false, NULL, "user_home", {.text = ""}, true}, .next = &TABLE_USERS[5]},
    { .value = { FIELD_INTEGER_LONG, 6, false, false, NULL, "user_id", {.integer_long = 0LL}, true}, .next = &TABLE_USERS[6]},
    { .value = { FIELD_INTEGER_LONG, 7, false, false, NULL, "user_uid_signed", {.integer_long = 0LL}, true}, .next = &TABLE_USERS[7]},
    { .value = { FIELD_TEXT, 8, false, false, NULL, "user_uuid", {.text = ""}, true}, .next = &TABLE_USERS[8]},
    { .value = { FIELD_TEXT, 9, false, false, NULL, "user_groups", {.text = ""}, true}, .next = &TABLE_USERS[9]},
    { .value = { FIELD_INTEGER_LONG, 10, false, false, NULL, "user_group_id", {.integer_long = 0LL}, true}, .next = &TABLE_USERS[10]},
    { .value = { FIELD_INTEGER_LONG, 11, false, false, NULL, "user_group_id_signed", {.integer_long = 0LL}, true}, .next = &TABLE_USERS[11]},
    { .value = { FIELD_REAL, 12, false, false, NULL, "user_created", {.real = 0.0}, true}, .next = &TABLE_USERS[12]},
    { .value = { FIELD_TEXT, 13, false, false, NULL, "user_roles", {.text = ""}, true}, .next = &TABLE_USERS[13]},
    { .value = { FIELD_TEXT, 14, false, false, NULL, "user_shell", {.text = ""}, true}, .next = &TABLE_USERS[14]},
    { .value = { FIELD_TEXT, 15, false, false, NULL, "user_type", {.text = ""}, true}, .next = &TABLE_USERS[15]},
    { .value = { FIELD_INTEGER, 16, false, false, NULL, "user_is_hidden", {.integer = 0}, true}, .next = &TABLE_USERS[16]},
    { .value = { FIELD_INTEGER, 17, false, false, NULL, "user_is_remote", {.integer = 0}, true}, .next = &TABLE_USERS[17]},
    { .value = { FIELD_INTEGER_LONG, 18, false, false, NULL, "user_last_login", {.integer_long = 0LL}, true}, .next = &TABLE_USERS[18]},
    { .value = { FIELD_INTEGER_LONG, 19, false, false, NULL, "user_auth_failed_count", {.integer_long = 0LL}, true}, .next = &TABLE_USERS[19]},
    { .value = { FIELD_REAL, 20, false, false, NULL, "user_auth_failed_timestamp", {.real = 0.0}, true}, .next = &TABLE_USERS[20]},
    { .value = { FIELD_REAL, 21, false, false, NULL, "user_password_last_change", {.real = 0.0}, true}, .next = &TABLE_USERS[21]},
    { .value = { FIELD_INTEGER, 22, false, false, NULL, "user_password_expiration_date", {.integer = 0}, true}, .next = &TABLE_USERS[22]},
    { .value = { FIELD_TEXT, 23, false, false, NULL, "user_password_hash_algorithm", {.text = ""}, true}, .next = &TABLE_USERS[23]},
    { .value = { FIELD_INTEGER, 24, false, false, NULL, "user_password_inactive_days", {.integer = 0}, true}, .next = &TABLE_USERS[24]},
    { .value = { FIELD_INTEGER, 25, false, false, NULL, "user_password_max_days_between_changes", {.integer = 0}, true}, .next = &TABLE_USERS[25]},
    { .value = { FIELD_INTEGER, 26, false, false, NULL, "user_password_min_days_between_changes", {.integer = 0}, true}, .next = &TABLE_USERS[26]},
    { .value = { FIELD_TEXT, 27, false, false, NULL, "user_password_status", {.text = ""}, true}, .next = &TABLE_USERS[27]},
    { .value = { FIELD_INTEGER, 28, false, false, NULL, "user_password_warning_days_before_expiration", {.integer = 0}, true}, .next = &TABLE_USERS[28]},
    { .value = { FIELD_INTEGER_LONG, 29, false, false, NULL, "process_pid", {.integer_long = 0LL}, true}, .next = &TABLE_USERS[29]},
    { .value = { FIELD_TEXT, 30, false, false, NULL, "host_ip", {.text = ""}, true}, .next = &TABLE_USERS[30]},
    { .value = { FIELD_INTEGER, 31, false, false, NULL, "login_status", {.integer = 0}, true}, .next = &TABLE_USERS[31]},
    { .value = { FIELD_TEXT, 32, false, false, NULL, "login_tty", {.text = ""}, true}, .next = &TABLE_USERS[32]},
    { .value = { FIELD_TEXT, 33, false, false, NULL, "login_type", {.text = ""}, true}, .next = &TABLE_USERS[33]},
    { .value = { FIELD_TEXT, 34, false, false, NULL, "checksum", {.text = ""}, true}, .next = NULL}
};

#define GROUPS_FIELD_COUNT 9
static struct column_list const TABLE_GROUPS[GROUPS_FIELD_COUNT+1] = {
    { .value = { FIELD_INTEGER, 1, true, false, NULL, "scan_id", {.integer = 0}, true}, .next = &TABLE_GROUPS[1]},
    { .value = { FIELD_TEXT, 2, false, false, NULL, "scan_time", {.text = ""}, true}, .next = &TABLE_GROUPS[2]},
    { .value = { FIELD_INTEGER_LONG, 3, false, false, NULL, "group_id", {.integer_long = 0LL}, true}, .next = &TABLE_GROUPS[3]},
    { .value = { FIELD_TEXT, 4, false, true, NULL, "group_name", {.text = ""}, true}, .next = &TABLE_GROUPS[4]},
    { .value = { FIELD_TEXT, 5, false, false, NULL, "group_description", {.text = ""}, true}, .next = &TABLE_GROUPS[5]},
    { .value = { FIELD_INTEGER_LONG, 6, false, false, NULL, "group_id_signed", {.integer_long = 0LL}, true}, .next = &TABLE_GROUPS[6]},
    { .value = { FIELD_TEXT, 7, false, false, NULL, "group_uuid", {.text = ""}, true}, .next = &TABLE_GROUPS[7]},
    { .value = { FIELD_INTEGER, 8, false, false, NULL, "group_is_hidden", {.integer = 0}, true}, .next = &TABLE_GROUPS[8]},
    { .value = { FIELD_TEXT, 9, false, false, NULL, "group_users", {.text = ""}, true}, .next = &TABLE_GROUPS[9]},
    { .value = { FIELD_TEXT, 10, false, false, NULL, "checksum", {.text = ""}, true}, .next = NULL}
};

static struct kv_list const TABLE_MAP[] = {
    { .current = { "network_iface", "sys_netiface", false, TABLE_NETIFACE, NETIFACE_FIELD_COUNT }, .next = &TABLE_MAP[1]},
    { .current = { "network_protocol", "sys_netproto", false, TABLE_NETPROTO, NETPROTO_FIELD_COUNT }, .next = &TABLE_MAP[2]},
    { .current = { "network_address", "sys_netaddr", false, TABLE_NETADDR, NETADDR_FIELD_COUNT }, .next = &TABLE_MAP[3]},
    { .current = { "osinfo", "sys_osinfo", false, TABLE_OS, OS_FIELD_COUNT }, .next = &TABLE_MAP[4]},
    { .current = { "hwinfo", "sys_hwinfo", false, TABLE_HARDWARE, HARDWARE_FIELD_COUNT }, .next = &TABLE_MAP[5]},
    { .current = { "ports", "sys_ports", false, TABLE_PORTS, PORTS_FIELD_COUNT }, .next = &TABLE_MAP[6]},
    { .current = { "packages", "sys_programs", false, TABLE_PACKAGES, PACKAGES_FIELD_COUNT }, .next = &TABLE_MAP[7]},
    { .current = { "hotfixes", "sys_hotfixes",  false, TABLE_HOTFIXES, HOTFIXES_FIELD_COUNT }, .next = &TABLE_MAP[8]},
    { .current = { "processes", "sys_processes",  false, TABLE_PROCESSES, PROCESSES_FIELD_COUNT }, .next = &TABLE_MAP[9]},
    { .current = { "users", "sys_users", false, TABLE_USERS, USERS_FIELD_COUNT }, .next = &TABLE_MAP[10]},
    { .current = { "groups", "sys_groups", false, TABLE_GROUPS, GROUPS_FIELD_COUNT }, .next = NULL}
};

#define AGENT_ID_LEN 64

sqlite3 * wdb_global_pre(void **wdb_ctx)
{
    struct timeval begin;
    struct timeval end;
    struct timeval diff;
    wdb_t * wdb;

    w_inc_global();

    gettimeofday(&begin, 0);
    if (wdb = wdb_open_global(), !wdb) {
        mdebug2("Couldn't open DB global: %s/%s.db", WDB2_DIR, WDB_GLOB_NAME);
        gettimeofday(&end, 0);
        timersub(&end, &begin, &diff);
        w_inc_global_open_time(diff);
        return NULL;
    } else if (!wdb->enabled) {
        mdebug2("Database disabled: %s/%s.db.", WDB2_DIR, WDB_GLOB_NAME);
        wdb_pool_leave(wdb);
        gettimeofday(&end, 0);
        timersub(&end, &begin, &diff);
        w_inc_global_open_time(diff);
        return NULL;
    }

    gettimeofday(&end, 0);
    timersub(&end, &begin, &diff);
    w_inc_global_open_time(diff);

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return NULL;
    }

    *wdb_ctx = (void *)wdb;
    return wdb->db;
}

void wdb_global_post(void *wdb_ctx)
{
    wdb_t * wdb = (wdb_t *)wdb_ctx;

    if (wdb) {
        wdb_pool_leave(wdb);
    }
}

int wdb_parse(char * input, char * output, int peer) {
    char * actor;
    char * id;
    char * query;
    char * sql;
    char * next;
    char path[PATH_MAX + 1];
    int agent_id = 0;
    char sagent_id[AGENT_ID_LEN] = "000";
    wdb_t * wdb;
    wdb_t * wdb_global;
    cJSON * data;
    char * out;
    int result = 0;
    struct timeval begin;
    struct timeval end;
    struct timeval diff;

    w_inc_queries_total();

    if (!input) {
        mdebug1("Empty input query.");
        return OS_INVALID;
    }

    // Clean string
    while (*input == ' ' || *input == '\n') {
        input++;
    }

    if (next = wstr_chr(input, ' '), !next) {
        mdebug1("Invalid DB query syntax.");
        mdebug2("DB query: %s", input);
        snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", input);
        return OS_INVALID;
    }

    actor = input;
    *next++ = '\0';

    if (strcmp(actor, "agent") == 0) {
        id = next;

        w_inc_agent();

        if (next = wstr_chr(id, ' '), !next) {
            mdebug1("Invalid DB query syntax.");
            mdebug2("DB query error near: %s", id);
            snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", id);
            return OS_INVALID;
        }

        *next++ = '\0';
        query = next;

        if (agent_id = strtol(id, &next, 10), *next) {
            mdebug1("Invalid agent ID '%s'", id);
            snprintf(output, OS_MAXSTR + 1, "err Invalid agent ID '%.32s'", id);
            return OS_INVALID;
        }

        snprintf(sagent_id, sizeof(sagent_id), "%03d", agent_id);

        mdebug2("Agent %s query: %s", sagent_id, query);

        // Don't perform this check if it's a manager.
        if (agent_id != 0) {
            if (wdb_global = wdb_open_global(), !wdb_global) {
                mdebug2("Couldn't open DB global: %s/%s.db", WDB2_DIR, WDB_GLOB_NAME);
                snprintf(output, OS_MAXSTR + 1, "err Couldn't open DB global");
                return OS_INVALID;
            } else if (!wdb_global->enabled) {
                mdebug2("Database disabled: %s/%s.db.", WDB2_DIR, WDB_GLOB_NAME);
                snprintf(output, OS_MAXSTR + 1, "err DB global disabled.");
                wdb_pool_leave(wdb_global);
                return OS_INVALID;
            }

            if (wdb_global_agent_exists(wdb_global, agent_id) <= 0) {
                mdebug2("No agent with id %s found.", sagent_id);
                snprintf(output, OS_MAXSTR + 1, "err Agent not found");
                wdb_pool_leave(wdb_global);
                return OS_INVALID;
            }
            wdb_pool_leave(wdb_global);
        }

        gettimeofday(&begin, 0);
        if (wdb = wdb_open_agent2(agent_id), !wdb) {
            merror("Couldn't open DB for agent '%s'", sagent_id);
            snprintf(output, OS_MAXSTR + 1, "err Couldn't open DB for agent %d", agent_id);
            gettimeofday(&end, 0);
            timersub(&end, &begin, &diff);
            w_inc_agent_open_time(diff);
            return OS_INVALID;
        }
        gettimeofday(&end, 0);
        timersub(&end, &begin, &diff);
        w_inc_agent_open_time(diff);
        // Add the current peer to wdb structure
        wdb->peer = peer;

        if (next = wstr_chr(query, ' '), next) {
            *next++ = '\0';
        }

        if (strcmp(query, "syscheck") == 0) {
            w_inc_agent_syscheck();
            if (!next) {
                mdebug1("DB(%s) Invalid FIM query syntax.", sagent_id);
                mdebug2("DB(%s) FIM query error near: %s", sagent_id, query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid Syscheck query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_syscheck(wdb, WDB_FIM, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_agent_syscheck_time(diff);
            }
        } else if (strcmp(query, "fim_file") == 0) {
            w_inc_agent_fim_file();
            if (!next) {
                mdebug1("DB(%s) Invalid FIM file query syntax.", sagent_id);
                mdebug2("DB(%s) FIM file query error near: %s", sagent_id, query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid Syscheck query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_syscheck(wdb, WDB_FIM_FILE, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_agent_fim_file_time(diff);
            }
        } else if (strcmp(query, "fim_registry") == 0) {
            w_inc_agent_fim_registry();
            if (!next) {
                mdebug1("DB(%s) Invalid FIM registry query syntax.", sagent_id);
                mdebug2("DB(%s) FIM registry query error near: %s", sagent_id, query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid Syscheck query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_syscheck(wdb, WDB_FIM_REGISTRY, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_agent_fim_registry_time(diff);
            }
        } else if (strcmp(query, "fim_registry_key") == 0) {
            w_inc_agent_fim_registry_key();
            if (!next) {
                mdebug1("DB(%s) Invalid FIM registry key query syntax.", sagent_id);
                mdebug2("DB(%s) FIM registry key query error near: %s", sagent_id, query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid Syscheck query syntax, near '%.32s'", query);
                result = -1;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_syscheck(wdb, WDB_FIM_REGISTRY_KEY, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_agent_fim_registry_key_time(diff);
            }
        } else if (strcmp(query, "fim_registry_value") == 0) {
            w_inc_agent_fim_registry_value();
            if (!next) {
                mdebug1("DB(%s) Invalid FIM registry value query syntax.", sagent_id);
                mdebug2("DB(%s) FIM registry value query error near: %s", sagent_id, query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid Syscheck query syntax, near '%.32s'", query);
                result = -1;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_syscheck(wdb, WDB_FIM_REGISTRY_VALUE, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_agent_fim_registry_value_time(diff);
            }
        } else if (strcmp(query, "sca") == 0) {
            w_inc_agent_sca();
            if (!next) {
                mdebug1("Invalid DB query syntax.");
                mdebug2("DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_sca(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_agent_sca_time(diff);
            }
        } else if (strcmp(query, "netinfo") == 0) {
            w_inc_agent_syscollector_deprecated_network_info();
            if (!next) {
                mdebug1("DB(%s) Invalid DB query syntax.", sagent_id);
                mdebug2("DB(%s) query error near: %s", sagent_id, query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_netinfo(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_agent_syscollector_deprecated_network_info_time(diff);
            }
        } else if (strcmp(query, "netproto") == 0) {
            w_inc_agent_syscollector_deprecated_network_protocol();
            if (!next) {
                mdebug1("DB(%s) Invalid DB query syntax.", sagent_id);
                mdebug2("DB(%s) query error near: %s", sagent_id, query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_netproto(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_agent_syscollector_deprecated_network_protocol_time(diff);
            }
        } else if (strcmp(query, "netaddr") == 0) {
            w_inc_agent_syscollector_deprecated_network_address();
            if (!next) {
                mdebug1("DB(%s) Invalid DB query syntax.", sagent_id);
                mdebug2("DB(%s) query error near: %s", sagent_id, query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_netaddr(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_agent_syscollector_deprecated_network_address_time(diff);
            }
        } else if (strcmp(query, "osinfo") == 0) {
            w_inc_agent_syscollector_deprecated_osinfo();
            if (!next) {
                mdebug1("DB(%s) Invalid DB query syntax.", sagent_id);
                mdebug2("DB(%s) query error near: %s", sagent_id, query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_osinfo(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_agent_syscollector_deprecated_osinfo_time(diff);
            }
        } else if (strcmp(query, "hardware") == 0) {
            w_inc_agent_syscollector_deprecated_hardware();
            if (!next) {
                mdebug1("DB(%s) Invalid DB query syntax.", sagent_id);
                mdebug2("DB(%s) query error near: %s", sagent_id, query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_hardware(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_agent_syscollector_deprecated_hardware_time(diff);
            }
        } else if (strcmp(query, "port") == 0) {
            w_inc_agent_syscollector_deprecated_ports();
            if (!next) {
                mdebug1("DB(%s) Invalid DB query syntax.", sagent_id);
                mdebug2("DB(%s) query error near: %s", sagent_id, query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_ports(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_agent_syscollector_deprecated_ports_time(diff);
            }
        } else if (strcmp(query, "package") == 0) {
            w_inc_agent_syscollector_deprecated_packages();
            if (!next) {
                mdebug1("DB(%s) Invalid DB query syntax.", sagent_id);
                mdebug2("DB(%s) query error near: %s", sagent_id, query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_packages(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_agent_syscollector_deprecated_packages_time(diff);
            }
        } else if (strcmp(query, "hotfix") == 0) {
            w_inc_agent_syscollector_deprecated_hotfixes();
            if (!next) {
                mdebug1("DB(%s) Invalid DB query syntax.", sagent_id);
                mdebug2("DB(%s) query error near: %s", sagent_id, query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_hotfixes(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_agent_syscollector_deprecated_hotfixes_time(diff);
            }
        } else if (strcmp(query, "process") == 0) {
            w_inc_agent_syscollector_deprecated_process();
            if (!next) {
                mdebug1("DB(%s) Invalid DB query syntax.", sagent_id);
                mdebug2("DB(%s) query error near: %s", sagent_id, query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_processes(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_agent_syscollector_deprecated_process_time(diff);
            }
        } else if (strcmp(query, "dbsync") == 0) {
            w_inc_agent_dbsync();
            if (!next) {
                mdebug1("DB(%s) Invalid DB query syntax.", sagent_id);
                mdebug2("DB(%s) query error near: %s", sagent_id, query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_dbsync(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_agent_dbsync_time(diff);
            }
        } else if (strcmp(query, "ciscat") == 0) {
            w_inc_agent_ciscat();
            if (!next) {
                mdebug1("DB(%s) Invalid DB query syntax.", sagent_id);
                mdebug2("DB(%s) query error near: %s", sagent_id, query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_ciscat(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_agent_ciscat_time(diff);
            }
        } else if (strcmp(query, "rootcheck") == 0) {
            w_inc_agent_rootcheck();
            if (!next) {
                mdebug1("DB(%s) Invalid rootcheck query syntax.", sagent_id);
                mdebug2("DB(%s) rootcheck query error near: %s", sagent_id, query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid Rootcheck query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_rootcheck(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_agent_rootcheck_time(diff);
            }
        } else if (strcmp(query, "sql") == 0) {
            w_inc_agent_sql();
            if (!next) {
                mdebug1("DB(%s) Invalid DB query syntax.", sagent_id);
                mdebug2("DB(%s) query error near: %s", sagent_id, query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                sql = next;

                gettimeofday(&begin, 0);
                data = wdb_exec(wdb->db, sql);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_agent_sql_time(diff);
                if (data) {
                    out = cJSON_PrintUnformatted(data);
                    snprintf(output, OS_MAXSTR + 1, "ok %s", out);
                    os_free(out);
                    cJSON_Delete(data);
                } else {
                    mdebug1("DB(%s) Cannot execute SQL query.", sagent_id);
                    mdebug2("DB(%s) SQL query: %s", sagent_id, sql);
                    snprintf(output, OS_MAXSTR + 1, "err Cannot execute SQL query");
                    result = OS_INVALID;
                }
            }
        } else if (strcmp(query, "remove") == 0) {
            w_inc_agent_remove();
            snprintf(output, OS_MAXSTR + 1, "ok");

            gettimeofday(&begin, 0);
            if (wdb_close(wdb, FALSE) < 0) {
                mdebug1("DB(%s) Cannot close database.", sagent_id);
                snprintf(output, OS_MAXSTR + 1, "err Cannot close database");
                result = OS_INVALID;
            }

            wdb_pool_leave(wdb);

            if (wdb_remove_database(sagent_id) < 0) {
                snprintf(output, OS_MAXSTR + 1, "err Cannot remove database");
                result = OS_INVALID;
            }
            gettimeofday(&end, 0);
            timersub(&end, &begin, &diff);
            w_inc_agent_remove_time(diff);

            return result;
        } else if (strcmp(query, "begin") == 0) {
            w_inc_agent_begin();
            gettimeofday(&begin, 0);
            if (wdb_begin2(wdb) < 0) {
                mdebug1("DB(%s) Cannot begin transaction.", sagent_id);
                snprintf(output, OS_MAXSTR + 1, "err Cannot begin transaction");
                result = OS_INVALID;
            } else {
                snprintf(output, OS_MAXSTR + 1, "ok");
            }
            gettimeofday(&end, 0);
            timersub(&end, &begin, &diff);
            w_inc_agent_begin_time(diff);
        } else if (strcmp(query, "commit") == 0) {
            w_inc_agent_commit();
            gettimeofday(&begin, 0);
            if (wdb_commit2(wdb) < 0) {
                mdebug1("DB(%s) Cannot end transaction.", sagent_id);
                snprintf(output, OS_MAXSTR + 1, "err Cannot end transaction");
                result = OS_INVALID;
            } else {
                snprintf(output, OS_MAXSTR + 1, "ok");
            }
            gettimeofday(&end, 0);
            timersub(&end, &begin, &diff);
            w_inc_agent_commit_time(diff);
        } else if (strcmp(query, "close") == 0) {
            w_inc_agent_close();
            snprintf(output, OS_MAXSTR + 1, "ok");

            gettimeofday(&begin, 0);
            if (wdb_close(wdb, TRUE) < 0) {
                mdebug1("DB(%s) Cannot close database.", sagent_id);
                snprintf(output, OS_MAXSTR + 1, "err Cannot close database");
                result = OS_INVALID;
            }
            wdb_pool_leave(wdb);
            gettimeofday(&end, 0);
            timersub(&end, &begin, &diff);
            w_inc_agent_close_time(diff);

            return result;
        } else if (strncmp(query, "syscollector_", 7) == 0) {
            if (!next) {
                mdebug1("DB(%s) Invalid Syscollector query syntax.", sagent_id);
                mdebug2("DB(%s) Syscollector query error near: %s", sagent_id, query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid Syscollector query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_syscollector(wdb, query, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_agent_syscollector_times(diff, result);
            }
        } else if (strcmp(query, "vacuum") == 0) {
            w_inc_agent_vacuum();
            gettimeofday(&begin, 0);
            if (wdb_commit2(wdb) < 0) {
                mdebug1("DB(%s) Cannot end transaction.", sagent_id);
                snprintf(output, OS_MAXSTR + 1, "err Cannot end transaction");
                result = -1;
            }

            wdb_finalize_all_statements(wdb);

            if (result != -1) {
                if (wdb_vacuum(wdb) < 0) {
                    mdebug1("DB(%s) Cannot vacuum database.", sagent_id);
                    snprintf(output, OS_MAXSTR + 1, "err Cannot vacuum database");
                    result = -1;
                } else {
                    int fragmentation_after_vacuum;

                    // save fragmentation after vacuum
                    if (fragmentation_after_vacuum = wdb_get_db_state(wdb), fragmentation_after_vacuum == OS_INVALID) {
                        mdebug1("DB(%s) Couldn't get fragmentation after vacuum for the database.", wdb->id);
                        snprintf(output, OS_MAXSTR + 1, "err Vacuum performed, but couldn't get fragmentation information after vacuum");
                        result = -1;
                    } else {
                        char str_vacuum_time[OS_SIZE_128] = { '\0' };
                        char str_vacuum_value[OS_SIZE_128] = { '\0' };

                        snprintf(str_vacuum_time, OS_SIZE_128, "%ld", time(0));
                        snprintf(str_vacuum_value, OS_SIZE_128, "%d", fragmentation_after_vacuum);
                        if (wdb_update_last_vacuum_data(wdb, str_vacuum_time, str_vacuum_value) != OS_SUCCESS) {
                            mdebug1("DB(%s) Couldn't update last vacuum info for the database.", wdb->id);
                            snprintf(output, OS_MAXSTR + 1, "err Vacuum performed, but last vacuum information couldn't be updated in the metadata table");
                            result = -1;
                        } else {
                            cJSON *json_fragmentation = cJSON_CreateObject();
                            cJSON_AddNumberToObject(json_fragmentation, "fragmentation_after_vacuum", fragmentation_after_vacuum);
                            char *out = cJSON_PrintUnformatted(json_fragmentation);
                            snprintf(output, OS_MAXSTR + 1, "ok %s", out);

                            os_free(out);
                            cJSON_Delete(json_fragmentation);
                            result = 0;
                        }
                    }
                }
            }
            gettimeofday(&end, 0);
            timersub(&end, &begin, &diff);
            w_inc_agent_vacuum_time(diff);
        } else if (strcmp(query, "get_fragmentation") == 0) {
            w_inc_agent_get_fragmentation();
            gettimeofday(&begin, 0);
            int state = wdb_get_db_state(wdb);
            int free_pages = wdb_get_db_free_pages_percentage(wdb);
            if (state < 0 || free_pages < 0) {
                mdebug1("DB(%s) Cannot get database fragmentation.", sagent_id);
                snprintf(output, OS_MAXSTR + 1, "err Cannot get database fragmentation");
                result = -1;
            } else {
                cJSON *json_fragmentation = cJSON_CreateObject();
                cJSON_AddNumberToObject(json_fragmentation, "fragmentation", state);
                cJSON_AddNumberToObject(json_fragmentation, "free_pages_percentage", free_pages);
                char *out = cJSON_PrintUnformatted(json_fragmentation);
                snprintf(output, OS_MAXSTR + 1, "ok %s", out);

                os_free(out);
                cJSON_Delete(json_fragmentation);
                result = 0;
            }
            gettimeofday(&end, 0);
            timersub(&end, &begin, &diff);
            w_inc_agent_get_fragmentation_time(diff);
        } else if (strcmp(query, "sleep") == 0) {
            unsigned long delay_ms;
            w_inc_agent_sleep();
            gettimeofday(&begin, 0);
            if (!next || (delay_ms = strtoul(next, NULL, 10)) == ULONG_MAX) {
                mdebug1("DB(%s) Invalid DB query syntax.", sagent_id);
                mdebug2("DB(%s) query error near: %s", sagent_id, query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                w_time_delay(delay_ms);
                snprintf(output, OS_MAXSTR + 1, "ok ");
            }
            gettimeofday(&end, 0);
            timersub(&end, &begin, &diff);
            w_inc_agent_sleep_time(diff);
        } else {
            mdebug1("DB(%s) Invalid DB query syntax.", sagent_id);
            mdebug2("DB(%s) query error near: %s", sagent_id, query);
            snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
            result = OS_INVALID;
        }
        if (result == OS_INVALID) {
            snprintf(path, sizeof(path), "%s/%s.db", WDB2_DIR, wdb->id);
            if (!w_is_file(path)) {
                mwarn("DB(%s) not found. This behavior is unexpected, the database will be recreated.", path);
                wdb_close(wdb, FALSE);
            }
        }
        wdb_pool_leave(wdb);
        return result;
    } else if (strcmp(actor, "wazuhdb") == 0) {
        query = next;

        w_inc_wazuhdb();

        if (next = wstr_chr(query, ' '), !next) {
            mdebug1("Invalid DB query syntax.");
            mdebug2("DB query error near: %s", query);
            snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
            return OS_INVALID;
        }
        *next++ = '\0';

        if (strcmp(query, "remove") == 0) {
            w_inc_wazuhdb_remove();
            gettimeofday(&begin, 0);
            data = wdb_remove_multiple_agents(next);
            gettimeofday(&end, 0);
            timersub(&end, &begin, &diff);
            w_inc_wazuhdb_remove_time(diff);
            out = cJSON_PrintUnformatted(data);
            snprintf(output, OS_MAXSTR + 1, "ok %s", out);
            os_free(out);
            cJSON_Delete(data);
        } else {
            mdebug1("Invalid DB query syntax.");
            mdebug2("DB query error near: %s", query);
            snprintf(output, OS_MAXSTR + 1, "err No agents id provided");
            result = OS_INVALID;
        }
        return result;
    } else if (strcmp(actor, "mitre") == 0) {
        query = next;

        w_inc_mitre();

        mdebug2("Mitre query: %s", query);

        if (wdb = wdb_open_mitre(), !wdb) {
            mdebug2("Couldn't open DB mitre: %s/%s.db", WDB_DIR, WDB_MITRE_NAME);
            snprintf(output, OS_MAXSTR + 1, "err Couldn't open DB mitre");
            return OS_INVALID;
        }
        // Add the current peer to wdb structure
        wdb->peer = peer;

        if (next = wstr_chr(query, ' '), !next) {
            mdebug1("Invalid DB query syntax.");
            mdebug2("DB query error near: %s", query);
            snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
            wdb_pool_leave(wdb);
            return OS_INVALID;
        }
        *next++ = '\0';

        if (strcmp(query, "sql") == 0) {
            w_inc_mitre_sql();
            if (!next) {
                mdebug1("Mitre DB Invalid DB query syntax.");
                mdebug2("Mitre DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                sql = next;

                gettimeofday(&begin, 0);
                data = wdb_exec(wdb->db, sql);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_mitre_sql_time(diff);
                if (data) {
                    out = cJSON_PrintUnformatted(data);
                    snprintf(output, OS_MAXSTR + 1, "ok %s", out);
                    os_free(out);
                    cJSON_Delete(data);
                } else {
                    mdebug1("Mitre DB Cannot execute SQL query; err database %s/%s.db: %s", WDB_DIR, WDB_MITRE_NAME, sqlite3_errmsg(wdb->db));
                    mdebug2("Mitre DB SQL query: %s", sql);
                    snprintf(output, OS_MAXSTR + 1, "err Cannot execute Mitre database query; %s", sqlite3_errmsg(wdb->db));
                    result = OS_INVALID;
                }
            }
        } else {
            mdebug1("Invalid DB query syntax.");
            mdebug2("DB query error near: %s", query);
            snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
            result = OS_INVALID;
        }
        wdb_pool_leave(wdb);
        return result;
    } else if (strcmp(actor, "global") == 0) {
        query = next;

        w_inc_global();

        mdebug2("Global query: %s", query);

        gettimeofday(&begin, 0);
        if (wdb = wdb_open_global(), !wdb) {
            mdebug2("Couldn't open DB global: %s/%s.db", WDB2_DIR, WDB_GLOB_NAME);
            snprintf(output, OS_MAXSTR + 1, "err Couldn't open DB global");
            gettimeofday(&end, 0);
            timersub(&end, &begin, &diff);
            w_inc_global_open_time(diff);
            return OS_INVALID;
        } else if (!wdb->enabled) {
            mdebug2("Database disabled: %s/%s.db.", WDB2_DIR, WDB_GLOB_NAME);
            snprintf(output, OS_MAXSTR + 1, "err DB global disabled.");
            wdb_pool_leave(wdb);
            gettimeofday(&end, 0);
            timersub(&end, &begin, &diff);
            w_inc_global_open_time(diff);
            return OS_INVALID;
        }
        gettimeofday(&end, 0);
        timersub(&end, &begin, &diff);
        w_inc_global_open_time(diff);
        // Add the current peer to wdb structure
        wdb->peer = peer;

        if (next = wstr_chr(query, ' '), next) {
            *next++ = '\0';
        }

        if (strcmp(query, "sql") == 0) {
            w_inc_global_sql();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                sql = next;

                gettimeofday(&begin, 0);
                data = wdb_exec(wdb->db, sql);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_sql_time(diff);
                if (data) {
                    out = cJSON_PrintUnformatted(data);
                    snprintf(output, OS_MAXSTR + 1, "ok %s", out);
                    os_free(out);
                    cJSON_Delete(data);
                } else {
                    mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db: %s", WDB2_DIR, WDB_GLOB_NAME, sqlite3_errmsg(wdb->db));
                    mdebug2("Global DB SQL query: %s", next);
                    snprintf(output, OS_MAXSTR + 1, "err Cannot execute Global database query; %s", sqlite3_errmsg(wdb->db));
                    result = OS_INVALID;
                }
            }
        } else if (strcmp(query, "insert-agent") == 0) {
            w_inc_global_agent_insert_agent();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for insert-agent.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_global_insert_agent(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_agent_insert_agent_time(diff);
            }
        } else if (strcmp(query, "update-agent-name") == 0) {
            w_inc_global_agent_update_agent_name();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for update-agent-name.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_global_update_agent_name(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_agent_update_agent_name_time(diff);
            }
        } else if (strcmp(query, "update-agent-data") == 0) {
            w_inc_global_agent_update_agent_data();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for update-agent-data.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_global_update_agent_data(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_agent_update_agent_data_time(diff);
            }
        } else if (strcmp(query, "get-labels") == 0) {
            w_inc_global_labels_get_labels();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for get-labels.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_global_get_agent_labels(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_labels_get_labels_time(diff);
            }
        } else if (strcmp(query, "update-keepalive") == 0) {
            w_inc_global_agent_update_keepalive();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for update-keepalive.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_global_update_agent_keepalive(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_agent_update_keepalive_time(diff);
            }
        } else if (strcmp(query, "update-connection-status") == 0) {
            w_inc_global_agent_update_connection_status();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for update-connection-status.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_global_update_connection_status(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_agent_update_connection_status_time(diff);
            }
        } else if (strcmp(query, "update-status-code") == 0) {
            w_inc_global_agent_update_status_code();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for update-status-code.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_global_update_status_code(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_agent_update_status_code_time(diff);
            }
        } else if (strcmp(query, "delete-agent") == 0) {
            w_inc_global_agent_delete_agent();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for delete-agent.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_global_delete_agent(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_agent_delete_agent_time(diff);
            }
        } else if (strcmp(query, "select-agent-name") == 0) {
            w_inc_global_agent_select_agent_name();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for select-agent-name.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_global_select_agent_name(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_agent_select_agent_name_time(diff);
            }
        } else if (strcmp(query, "select-agent-group") == 0) {
            w_inc_global_agent_select_agent_group();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for select-agent-group.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_global_select_agent_group(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_agent_select_agent_group_time(diff);
            }
        } else if (strcmp(query, "find-agent") == 0) {
            w_inc_global_agent_find_agent();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for find-agent.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_global_find_agent(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_agent_find_agent_time(diff);
            }
        } else if (strcmp(query, "find-group") == 0) {
            w_inc_global_group_find_group();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for find-group.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_global_find_group(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_group_find_group_time(diff);
            }
        } else if (strcmp(query, "insert-agent-group") == 0) {
            w_inc_global_group_insert_agent_group();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for insert-agent-group.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_global_insert_agent_group(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_group_insert_agent_group_time(diff);
            }
        } else if (strcmp(query, "select-group-belong") == 0) {
            w_inc_global_belongs_select_group_belong();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for select-group-belong.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_global_select_group_belong(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_belongs_select_group_belong_time(diff);
            }
        } else if (strcmp(query, "get-group-agents") == 0) {
            w_inc_global_belongs_get_group_agent();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for get-group-agents.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_global_get_group_agents(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_belongs_get_group_agent_time(diff);
            }
        } else if (strcmp(query, "delete-group") == 0) {
            w_inc_global_group_delete_group();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for delete-group.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_global_delete_group(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_group_delete_group_time(diff);
            }
        } else if (strcmp(query, "select-groups") == 0) {
            w_inc_global_group_select_groups();
            gettimeofday(&begin, 0);
            result = wdb_parse_global_select_groups(wdb, output);
            gettimeofday(&end, 0);
            timersub(&end, &begin, &diff);
            w_inc_global_group_select_groups_time(diff);
        } else if (strcmp(query, "sync-agent-groups-get") == 0) {
            w_inc_global_agent_sync_agent_groups_get();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for sync-agent-groups-get.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_global_sync_agent_groups_get(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_agent_sync_agent_groups_get_time(diff);
            }
        } else if (strcmp(query, "set-agent-groups") == 0) {
            w_inc_global_agent_set_agent_groups();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for set-agent-groups.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_global_set_agent_groups(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_agent_set_agent_groups_time(diff);
            }
        } else if (strcmp(query, "sync-agent-info-get") == 0) {
            w_inc_global_agent_sync_agent_info_get();
            gettimeofday(&begin, 0);
            result = wdb_parse_global_sync_agent_info_get(wdb, next, output);
            gettimeofday(&end, 0);
            timersub(&end, &begin, &diff);
            w_inc_global_agent_sync_agent_info_get_time(diff);
        } else if (strcmp(query, "sync-agent-info-set") == 0) {
            w_inc_global_agent_sync_agent_info_set();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for sync-agent-info-set.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_global_sync_agent_info_set(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_agent_sync_agent_info_set_time(diff);
            }
        } else if (strcmp(query, "get-groups-integrity") == 0) {
            w_inc_global_agent_get_groups_integrity();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for get-groups-integrity.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_get_groups_integrity(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_agent_get_groups_integrity_time(diff);
            }
        } else if (strcmp(query, "recalculate-agent-group-hashes") == 0) {
            w_inc_global_agent_recalculate_agent_group_hashes();
            gettimeofday(&begin, 0);
            result = wdb_parse_global_recalculate_agent_group_hashes(wdb, output);
            gettimeofday(&end, 0);
            timersub(&end, &begin, &diff);
            w_inc_global_agent_recalculate_agent_group_hashes_time(diff);
        } else if (strcmp(query, "disconnect-agents") == 0) {
            w_inc_global_agent_disconnect_agents();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for disconnect-agents.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_global_disconnect_agents(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_agent_disconnect_agents_time(diff);
            }
        } else if (strcmp(query, "get-all-agents") == 0) {
            w_inc_global_agent_get_all_agents();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for get-all-agents.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_global_get_all_agents(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_agent_get_all_agents_time(diff);
            }
        } else if (strcmp(query, "get-distinct-groups") == 0) {
            w_inc_global_agent_get_distinct_groups();
            gettimeofday(&begin, 0);
            result = wdb_parse_global_get_distinct_agent_groups(wdb, next, output);
            gettimeofday(&end, 0);
            timersub(&end, &begin, &diff);
            w_inc_global_agent_get_distinct_groups_time(diff);
        } else if (strcmp(query, "get-agent-info") == 0) {
            w_inc_global_agent_get_agent_info();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for get-agent-info.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_global_get_agent_info(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_agent_get_agent_info_time(diff);
            }
        } else if (strcmp(query, "reset-agents-connection") == 0) {
            w_inc_global_agent_reset_agents_connection();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for reset-agents-connection.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_reset_agents_connection(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_agent_reset_agents_connection_time(diff);
            }
        } else if (strcmp(query, "get-agents-by-connection-status") == 0) {
            w_inc_global_agent_get_agents_by_connection_status();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for get-agents-by-connection-status.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                gettimeofday(&begin, 0);
                result = wdb_parse_global_get_agents_by_connection_status(wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_agent_get_agents_by_connection_status_time(diff);
            }
        } else if (strcmp(query, "backup") == 0) {
            w_inc_global_backup();
            if (!next) {
                mdebug1("Global DB Invalid DB query syntax for backup.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                // The "backup restore" command takes the pool_mutex to remove the wdb pointer
                gettimeofday(&begin, 0);
                result = wdb_parse_global_backup(&wdb, next, output);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_global_backup_time(diff);
            }
        } else if (strcmp(query, "vacuum") == 0) {
            w_inc_global_vacuum();
            gettimeofday(&begin, 0);
            if (wdb_commit2(wdb) < 0) {
                mdebug1("Global DB Cannot end transaction.");
                snprintf(output, OS_MAXSTR + 1, "err Cannot end transaction");
                result = -1;
            }

            wdb_finalize_all_statements(wdb);

            if (result != -1) {
                if (wdb_vacuum(wdb) < 0) {
                    mdebug1("Global DB Cannot vacuum database.");
                    snprintf(output, OS_MAXSTR + 1, "err Cannot vacuum database");
                    result = -1;
                } else {
                    int fragmentation_after_vacuum;

                    // save fragmentation after vacuum
                    if (fragmentation_after_vacuum = wdb_get_db_state(wdb), fragmentation_after_vacuum == OS_INVALID) {
                        mdebug1("Global DB Couldn't get fragmentation after vacuum for the database.");
                        snprintf(output, OS_MAXSTR + 1, "err Vacuum performed, but couldn't get fragmentation information after vacuum");
                        result = -1;
                    } else {
                        char str_vacuum_time[OS_SIZE_128] = { '\0' };
                        char str_vacuum_value[OS_SIZE_128] = { '\0' };

                        snprintf(str_vacuum_time, OS_SIZE_128, "%ld", time(0));
                        snprintf(str_vacuum_value, OS_SIZE_128, "%d", fragmentation_after_vacuum);
                        if (wdb_update_last_vacuum_data(wdb, str_vacuum_time, str_vacuum_value) != OS_SUCCESS) {
                            mdebug1("Global DB Couldn't update last vacuum info for the database.");
                            snprintf(output, OS_MAXSTR + 1, "err Vacuum performed, but last vacuum information couldn't be updated in the metadata table");
                            result = -1;
                        } else {
                            cJSON *json_fragmentation = cJSON_CreateObject();
                            cJSON_AddNumberToObject(json_fragmentation, "fragmentation_after_vacuum", fragmentation_after_vacuum);
                            char *out = cJSON_PrintUnformatted(json_fragmentation);
                            snprintf(output, OS_MAXSTR + 1, "ok %s", out);

                            os_free(out);
                            cJSON_Delete(json_fragmentation);
                            result = 0;
                        }
                    }
                }
            }
            gettimeofday(&end, 0);
            timersub(&end, &begin, &diff);
            w_inc_global_vacuum_time(diff);
        } else if (strcmp(query, "get_fragmentation") == 0) {
            w_inc_global_get_fragmentation();
            gettimeofday(&begin, 0);
            int state = wdb_get_db_state(wdb);
            int free_pages = wdb_get_db_free_pages_percentage(wdb);
            if (state < 0 || free_pages < 0) {
                mdebug1("Global DB Cannot get database fragmentation.");
                snprintf(output, OS_MAXSTR + 1, "err Cannot get database fragmentation");
                result = -1;
            } else {
                cJSON *json_fragmentation = cJSON_CreateObject();
                cJSON_AddNumberToObject(json_fragmentation, "fragmentation", state);
                cJSON_AddNumberToObject(json_fragmentation, "free_pages_percentage", free_pages);
                char *out = cJSON_PrintUnformatted(json_fragmentation);
                snprintf(output, OS_MAXSTR + 1, "ok %s", out);

                os_free(out);
                cJSON_Delete(json_fragmentation);
                result = 0;
            }
            gettimeofday(&end, 0);
            timersub(&end, &begin, &diff);
            w_inc_global_get_fragmentation_time(diff);
        } else if (strcmp(query, "sleep") == 0) {
            unsigned long delay_ms;
            w_inc_global_sleep();
            gettimeofday(&begin, 0);
            if (!next || (delay_ms = strtoul(next, NULL, 10)) == ULONG_MAX) {
                mdebug1("Global DB Invalid DB query syntax.");
                mdebug2("Global DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                w_time_delay(delay_ms);
                snprintf(output, OS_MAXSTR + 1, "ok ");
            }
            gettimeofday(&end, 0);
            timersub(&end, &begin, &diff);
            w_inc_global_sleep_time(diff);
        } else {
            mdebug1("Invalid DB query syntax.");
            mdebug2("Global DB query error near: %s", query);
            snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
            result = OS_INVALID;
        }
        if (result == OS_INVALID) {
            snprintf(path, sizeof(path), "%s/%s.db", WDB2_DIR, wdb->id);
            if (!w_is_file(path)) {
                mwarn("DB(%s) not found. This behavior is unexpected, the database will be recreated.", path);
                wdb_close(wdb, FALSE);
            }
        }
        wdb_pool_leave(wdb);
        return result;
    } else if (strcmp(actor, "task") == 0) {
        cJSON *parameters_json = NULL;
        const char *json_err;
        query = next;

        w_inc_task();

        mdebug2("Task query: %s", query);

        if (wdb = wdb_open_tasks(), !wdb) {
            mdebug2("Couldn't open DB task: %s/%s.db", WDB_TASK_DIR, WDB_TASK_NAME);
            snprintf(output, OS_MAXSTR + 1, "err Couldn't open DB task");
            return OS_INVALID;
        }
        // Add the current peer to wdb structure
        wdb->peer = peer;

        if (next = wstr_chr(query, ' '), !next) {
            mdebug1("Invalid DB query syntax.");
            mdebug2("DB query error near: %s", query);
            snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
            wdb_pool_leave(wdb);
            return OS_INVALID;
        }

        *next++ = '\0';

        if (!strcmp("upgrade", query)) {
            w_inc_task_upgrade();
            if (!next) {
                mdebug1("Task DB Invalid DB query syntax.");
                mdebug2("Task DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                wdb_pool_leave(wdb);
                return OS_INVALID;
            }

            // Detect parameters
            if (parameters_json = cJSON_ParseWithOpts(next, &json_err, 0), !parameters_json) {
                snprintf(output, OS_MAXSTR + 1, "err Invalid command parameters, near '%.32s'", next);
                wdb_pool_leave(wdb);
                return OS_INVALID;
            }

            gettimeofday(&begin, 0);
            result = wdb_parse_task_upgrade(wdb, parameters_json, "upgrade", output);
            gettimeofday(&end, 0);
            timersub(&end, &begin, &diff);
            w_inc_task_upgrade_time(diff);
            cJSON_Delete(parameters_json);

        } else if (!strcmp("upgrade_custom", query)) {
            w_inc_task_upgrade_custom();
            if (!next) {
                mdebug1("Task DB Invalid DB query syntax.");
                mdebug2("Task DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                wdb_pool_leave(wdb);
                return OS_INVALID;
            }

            // Detect parameters
            if (parameters_json = cJSON_ParseWithOpts(next, &json_err, 0), !parameters_json) {
                snprintf(output, OS_MAXSTR + 1, "err Invalid command parameters, near '%.32s'", next);
                wdb_pool_leave(wdb);
                return OS_INVALID;
            }

            gettimeofday(&begin, 0);
            result = wdb_parse_task_upgrade(wdb, parameters_json, "upgrade_custom", output);
            gettimeofday(&end, 0);
            timersub(&end, &begin, &diff);
            w_inc_task_upgrade_custom_time(diff);
            cJSON_Delete(parameters_json);

        } else if (!strcmp("upgrade_get_status", query)) {
            w_inc_task_upgrade_get_status();
            if (!next) {
                mdebug1("Task DB Invalid DB query syntax.");
                mdebug2("Task DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                wdb_pool_leave(wdb);
                return OS_INVALID;
            }

            // Detect parameters
            if (parameters_json = cJSON_ParseWithOpts(next, &json_err, 0), !parameters_json) {
                snprintf(output, OS_MAXSTR + 1, "err Invalid command parameters, near '%.32s'", next);
                wdb_pool_leave(wdb);
                return OS_INVALID;
            }

            gettimeofday(&begin, 0);
            result = wdb_parse_task_upgrade_get_status(wdb, parameters_json, output);
            gettimeofday(&end, 0);
            timersub(&end, &begin, &diff);
            w_inc_task_upgrade_get_status_time(diff);
            cJSON_Delete(parameters_json);

        } else if (!strcmp("upgrade_update_status", query)) {
            w_inc_task_upgrade_update_status();
            if (!next) {
                mdebug1("Task DB Invalid DB query syntax.");
                mdebug2("Task DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                wdb_pool_leave(wdb);
                return OS_INVALID;
            }

            // Detect parameters
            if (parameters_json = cJSON_ParseWithOpts(next, &json_err, 0), !parameters_json) {
                snprintf(output, OS_MAXSTR + 1, "err Invalid command parameters, near '%.32s'", next);
                wdb_pool_leave(wdb);
                return OS_INVALID;
            }

            gettimeofday(&begin, 0);
            result = wdb_parse_task_upgrade_update_status(wdb, parameters_json, output);
            gettimeofday(&end, 0);
            timersub(&end, &begin, &diff);
            w_inc_task_upgrade_update_status_time(diff);
            cJSON_Delete(parameters_json);

        } else if (!strcmp("upgrade_result", query)) {
            w_inc_task_upgrade_result();
            if (!next) {
                mdebug1("Task DB Invalid DB query syntax.");
                mdebug2("Task DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                wdb_pool_leave(wdb);
                return OS_INVALID;
            }

            // Detect parameters
            if (parameters_json = cJSON_ParseWithOpts(next, &json_err, 0), !parameters_json) {
                snprintf(output, OS_MAXSTR + 1, "err Invalid command parameters, near '%.32s'", next);
                wdb_pool_leave(wdb);
                return OS_INVALID;
            }

            gettimeofday(&begin, 0);
            result = wdb_parse_task_upgrade_result(wdb, parameters_json, output);
            gettimeofday(&end, 0);
            timersub(&end, &begin, &diff);
            w_inc_task_upgrade_result_time(diff);
            cJSON_Delete(parameters_json);

        } else if (!strcmp("upgrade_cancel_tasks", query)) {
            w_inc_task_upgrade_cancel_tasks();
            if (!next) {
                mdebug1("Task DB Invalid DB query syntax.");
                mdebug2("Task DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                wdb_pool_leave(wdb);
                return OS_INVALID;
            }

            // Detect parameters
            if (parameters_json = cJSON_ParseWithOpts(next, &json_err, 0), !parameters_json) {
                snprintf(output, OS_MAXSTR + 1, "err Invalid command parameters, near '%.32s'", next);
                wdb_pool_leave(wdb);
                return OS_INVALID;
            }

            gettimeofday(&begin, 0);
            result = wdb_parse_task_upgrade_cancel_tasks(wdb, parameters_json, output);
            gettimeofday(&end, 0);
            timersub(&end, &begin, &diff);
            w_inc_task_upgrade_cancel_tasks_time(diff);
            cJSON_Delete(parameters_json);

        } else if (!strcmp("set_timeout", query)) {
            w_inc_task_set_timeout();
            if (!next) {
                mdebug1("Task DB Invalid DB query syntax.");
                mdebug2("Task DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                wdb_pool_leave(wdb);
                return OS_INVALID;
            }

            // Detect parameters
            if (parameters_json = cJSON_ParseWithOpts(next, &json_err, 0), !parameters_json) {
                snprintf(output, OS_MAXSTR + 1, "err Invalid command parameters, near '%.32s'", next);
                wdb_pool_leave(wdb);
                return OS_INVALID;
            }

            gettimeofday(&begin, 0);
            result = wdb_parse_task_set_timeout(wdb, parameters_json, output);
            gettimeofday(&end, 0);
            timersub(&end, &begin, &diff);
            w_inc_task_set_timeout_time(diff);
            cJSON_Delete(parameters_json);

        } else if (!strcmp("delete_old", query)) {
            w_inc_task_delete_old();
            if (!next) {
                mdebug1("Task DB Invalid DB query syntax.");
                mdebug2("Task DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                wdb_pool_leave(wdb);
                return OS_INVALID;
            }

            // Detect parameters
            if (parameters_json = cJSON_ParseWithOpts(next, &json_err, 0), !parameters_json) {
                snprintf(output, OS_MAXSTR + 1, "err Invalid command parameters, near '%.32s'", next);
                wdb_pool_leave(wdb);
                return OS_INVALID;
            }

            gettimeofday(&begin, 0);
            result = wdb_parse_task_delete_old(wdb, parameters_json, output);
            gettimeofday(&end, 0);
            timersub(&end, &begin, &diff);
            w_inc_task_delete_old_time(diff);
            cJSON_Delete(parameters_json);

        } else if (!strcmp("sql", query)) {
            w_inc_task_sql();
            if (!next) {
                mdebug1("Task DB Invalid DB query syntax.");
                mdebug2("Task DB query error near: %s", query);
                snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
                result = OS_INVALID;
            } else {
                sql = next;

                gettimeofday(&begin, 0);
                data = wdb_exec(wdb->db, sql);
                gettimeofday(&end, 0);
                timersub(&end, &begin, &diff);
                w_inc_task_sql_time(diff);
                if (data) {
                    out = cJSON_PrintUnformatted(data);
                    snprintf(output, OS_MAXSTR + 1, "ok %s", out);
                    os_free(out);
                    cJSON_Delete(data);
                } else {
                    mdebug1("Tasks DB Cannot execute SQL query; err database %s/%s.db: %s", WDB_TASK_DIR, WDB_TASK_NAME, sqlite3_errmsg(wdb->db));
                    mdebug2("Tasks DB SQL query: %s", sql);
                    snprintf(output, OS_MAXSTR + 1, "err Cannot execute Tasks database query; %s", sqlite3_errmsg(wdb->db));
                    result = OS_INVALID;
                }
            }
        } else {
            mdebug1("Invalid DB query syntax.");
            mdebug2("Task DB query error near: %s", query);
            snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", query);
            result = OS_INVALID;
        }
        wdb_pool_leave(wdb);
        return result;
    } else {
        mdebug1("DB(%s) Invalid DB query actor: %s", sagent_id, actor);
        snprintf(output, OS_MAXSTR + 1, "err Invalid DB query actor: '%.32s'", actor);
        return OS_INVALID;
    }
}

int wdb_parse_syscheck(wdb_t * wdb, wdb_component_t component, char * input, char * output) {
    char * curr;
    char * next;
    char * checksum;
    char buffer[OS_MAXSTR - WDB_RESPONSE_BEGIN_SIZE];
    int ftype;
    int result;
    long ts;

    if (next = wstr_chr(input, ' '), !next) {
        mdebug2("DB(%s) Invalid FIM query syntax: %s", wdb->id, input);
        snprintf(output, OS_MAXSTR + 1, "err Invalid FIM query syntax, near '%.32s'", input);
        return OS_INVALID;
    }

    curr = input;
    *next++ = '\0';

    if (strcmp(curr, "scan_info_get") == 0) {
        if (result = wdb_scan_info_get(wdb, "fim", next, &ts), result < 0) {
            mdebug1("DB(%s) Cannot get FIM scan info.", wdb->id);
            snprintf(output, OS_MAXSTR + 1, "err Cannot get fim scan info.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok %ld", ts);
        }

        return result;
    } else if (strcmp(curr, "updatedate") == 0) {
        if (result = wdb_fim_update_date_entry(wdb, next), result < 0) {
            mdebug1("DB(%s) Cannot update fim date field.", wdb->id);
            snprintf(output, OS_MAXSTR + 1, "err Cannot update fim date field.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;
    } else if (strcmp(curr, "cleandb") == 0) {
        if (result = wdb_fim_clean_old_entries(wdb), result < 0) {
            mdebug1("DB(%s) Cannot clean fim database.", wdb->id);
            snprintf(output, OS_MAXSTR + 1, "err Cannot clean fim database.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;
    } else if (strcmp(curr, "scan_info_update") == 0) {
        curr = next;

        if (next = wstr_chr(curr, ' '), !next) {
            mdebug1("DB(%s) Invalid scan_info fim query syntax.", wdb->id);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Syscheck query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        *next++ = '\0';
        ts = atol(next);
        if (result = wdb_scan_info_update(wdb, "fim", curr, ts), result < 0) {
            mdebug1("DB(%s) Cannot save fim control message.", wdb->id);
            snprintf(output, OS_MAXSTR + 1, "err Cannot save fim control message");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;
    } else if (strcmp(curr, "control") == 0) {
        if (result = wdb_scan_info_fim_checks_control(wdb, next), result < 0) {
            mdebug1("DB(%s) Cannot save fim check_control message.", wdb->id);
            snprintf(output, OS_MAXSTR + 1, "err Cannot save fim control message");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;
    } else if (strcmp(curr, "load") == 0) {
        if (result = wdb_syscheck_load(wdb, next, buffer, sizeof(buffer)), result < 0) {
            mdebug1("DB(%s) Cannot load FIM.", wdb->id);
            snprintf(output, OS_MAXSTR + 1, "err Cannot load Syscheck");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok %s", buffer);
        }

        return result;
    } else if (strcmp(curr, "delete") == 0) {
        if (result = wdb_fim_delete(wdb, next), result < 0) {
            mdebug1("DB(%s) Cannot delete FIM entry.", wdb->id);
            snprintf(output, OS_MAXSTR + 1, "err Cannot delete Syscheck");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;
    } else if (strcmp(curr, "save") == 0) {
        curr = next;

        if (next = wstr_chr(curr, ' '), !next) {
            mdebug1("DB(%s) Invalid FIM query syntax.", wdb->id);
            mdebug2("DB(%s) FIM query: %s", wdb->id, curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Syscheck query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        *next++ = '\0';

        if (strcmp(curr, "file") == 0) {
            ftype = WDB_FILE_TYPE_FILE;
        } else if (strcmp(curr, "registry") == 0) {
            ftype = WDB_FILE_TYPE_REGISTRY;
        } else {
            mdebug1("DB(%s) Invalid FIM query syntax.", wdb->id);
            mdebug2("DB(%s) FIM query: %s", wdb->id, curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Syscheck query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        checksum = next;

        if (next = wstr_chr(checksum, ' '), !next) {
            mdebug1("DB(%s) Invalid FIM query syntax.", wdb->id);
            mdebug2("FIM query: %s", checksum);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Syscheck query syntax, near '%.32s'", checksum);
            return OS_INVALID;
        }

        *next++ = '\0';

        // Only the part before '!' has been escaped
        char *mark = strchr(checksum, '!');
        if (mark) *mark = '\0';
        char *unsc_checksum = wstr_replace(checksum, "\\ ", " ");
        if (mark) {
            *mark = '!';
            size_t unsc_size = strlen(unsc_checksum);
            size_t mark_size = strlen(mark);
            os_realloc(unsc_checksum, unsc_size + mark_size + 1, unsc_checksum);
            strncpy(unsc_checksum + unsc_size, mark, mark_size + 1);
            unsc_checksum[unsc_size + mark_size] = '\0';
        }

        if (result = wdb_syscheck_save(wdb, ftype, unsc_checksum, next), result < 0) {
            mdebug1("DB(%s) Cannot save FIM.", wdb->id);
            snprintf(output, OS_MAXSTR + 1, "err Cannot save Syscheck");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }
        free(unsc_checksum);

        return result;
    } else if (strcmp(curr, "save2") == 0) {
        if (wdb_syscheck_save2(wdb, next) == OS_INVALID) {
            mdebug1("DB(%s) Cannot save FIM.", wdb->id);
            snprintf(output, OS_MAXSTR + 1, "err Cannot save Syscheck");
            return OS_INVALID;
        }

        snprintf(output, OS_MAXSTR + 1, "ok");
        return 0;
    } else if (strncmp(curr, "integrity_check_", 16) == 0) {
        dbsync_msg action = INTEGRITY_CLEAR;
        if (0 == strcmp(curr, INTEGRITY_COMMANDS[INTEGRITY_CHECK_GLOBAL])) {
            action = INTEGRITY_CHECK_GLOBAL;
        } else if (0 == strcmp(curr, INTEGRITY_COMMANDS[INTEGRITY_CHECK_LEFT])) {
            action = INTEGRITY_CHECK_LEFT;
        } else if (0 == strcmp(curr, INTEGRITY_COMMANDS[INTEGRITY_CHECK_RIGHT])) {
            action = INTEGRITY_CHECK_RIGHT;
        }

        switch (wdbi_query_checksum(wdb, component, action, next)) {
        case INTEGRITY_SYNC_ERR:
            mdebug1("DB(%s) Cannot query FIM range checksum.", wdb->id);
            snprintf(output, OS_MAXSTR + 1, "err Cannot perform range checksum");
            return OS_INVALID;

        case INTEGRITY_SYNC_NO_DATA:
            snprintf(output, OS_MAXSTR + 1, "ok no_data");
            break;

        case INTEGRITY_SYNC_CKS_FAIL:
            snprintf(output, OS_MAXSTR + 1, "ok checksum_fail");
            break;

        default:
            snprintf(output, OS_MAXSTR + 1, "ok ");
        }

        return 0;
    } else if (strcmp(curr, "integrity_clear") == 0) {
        switch (wdbi_query_clear(wdb, component, next)) {
        case OS_INVALID:
            mdebug1("DB(%s) Cannot query FIM range checksum.", wdb->id);
            snprintf(output, OS_MAXSTR + 1, "err Cannot perform range checksum");
            return OS_INVALID;

        default:
            snprintf(output, OS_MAXSTR + 1, "ok ");
        }

        return 0;
    } else {
        mdebug1("DB(%s) Invalid FIM query syntax.", wdb->id);
        mdebug2("DB query error near: %s", curr);
        snprintf(output, OS_MAXSTR + 1, "err Invalid Syscheck query syntax, near '%.32s'", curr);
        return OS_INVALID;
    }
}

int wdb_parse_syscollector(wdb_t * wdb, const char * query, char * input, char * output) {
    char * curr;
    char * next;
    wdb_component_t component;

    if (strcmp(query, "syscollector_processes") == 0)
    {
        w_inc_agent_syscollector_processes();
        component = WDB_SYSCOLLECTOR_PROCESSES;
        mdebug2("DB(%s) syscollector_processes Syscollector query. ", wdb->id);
    }
    else if (strcmp(query, "syscollector_packages") == 0)
    {
        w_inc_agent_syscollector_packages();
        component = WDB_SYSCOLLECTOR_PACKAGES;
        mdebug2("DB(%s) syscollector_packages Syscollector query. ", wdb->id);
    }
    else if (strcmp(query, "syscollector_hotfixes") == 0)
    {
        w_inc_agent_syscollector_hotfixes();
        component = WDB_SYSCOLLECTOR_HOTFIXES;
        mdebug2("DB(%s) syscollector_hotfixes Syscollector query. ", wdb->id);
    }
    else if (strcmp(query, "syscollector_ports") == 0)
    {
        w_inc_agent_syscollector_ports();
        component = WDB_SYSCOLLECTOR_PORTS;
        mdebug2("DB(%s) syscollector_ports Syscollector query. ", wdb->id);
    }
    else if (strcmp(query, "syscollector_network_protocol") == 0)
    {
        w_inc_agent_syscollector_network_protocol();
        component = WDB_SYSCOLLECTOR_NETPROTO;
        mdebug2("DB(%s) syscollector_network_protocol Syscollector query. ", wdb->id);
    }
    else if (strcmp(query, "syscollector_network_address") == 0)
    {
        w_inc_agent_syscollector_network_address();
        component = WDB_SYSCOLLECTOR_NETADDRESS;
        mdebug2("DB(%s) syscollector_network_address Syscollector query. ", wdb->id);
    }
    else if (strcmp(query, "syscollector_network_iface") == 0)
    {
        w_inc_agent_syscollector_network_iface();
        component = WDB_SYSCOLLECTOR_NETINFO;
        mdebug2("DB(%s) syscollector_network_iface Syscollector query. ", wdb->id);
    }
    else if (strcmp(query, "syscollector_hwinfo") == 0)
    {
        w_inc_agent_syscollector_hwinfo();
        component = WDB_SYSCOLLECTOR_HWINFO;
        mdebug2("DB(%s) syscollector_hwinfo Syscollector query. ", wdb->id);
    }
    else if (strcmp(query, "syscollector_osinfo") == 0)
    {
        w_inc_agent_syscollector_osinfo();
        component = WDB_SYSCOLLECTOR_OSINFO;
        mdebug2("DB(%s) syscollector_osinfo Syscollector query. ", wdb->id);
    }
    else if (strcmp(query, "syscollector_users") == 0)
    {
        w_inc_agent_syscollector_users();
        component = WDB_SYSCOLLECTOR_USERS;
        mdebug2("DB(%s) syscollector_users Syscollector query. ", wdb->id);
    }
    else if (strcmp(query, "syscollector_groups") == 0)
    {
        w_inc_agent_syscollector_groups();
        component = WDB_SYSCOLLECTOR_GROUPS;
        mdebug2("DB(%s) syscollector_groups Syscollector query. ", wdb->id);
    }
    else
    {
        mdebug2("DB(%s) Invalid Syscollector query : %s", wdb->id, query);
        snprintf(output, OS_MAXSTR + 1, "err Invalid Syscollector query syntax, near '%.32s'", query);
        return OS_INVALID;
    }

    if (next = wstr_chr(input, ' '), !next) {
        mdebug2("DB(%s) Invalid Syscollector query syntax: %s", wdb->id, input);
        snprintf(output, OS_MAXSTR + 1, "err Invalid Syscollector query syntax, near '%.32s'", input);
        return OS_INVALID;
    }

    curr = input;
    *next++ = '\0';
    if (strcmp(curr, "save2") == 0) {
        if (wdb_syscollector_save2(wdb, component, next) == OS_INVALID) {
            mdebug1("DB(%s) Cannot save Syscollector.", wdb->id);
            snprintf(output, OS_MAXSTR + 1, "err Cannot save Syscollector");
            return OS_INVALID;
        }

        snprintf(output, OS_MAXSTR + 1, "ok");
        return component;
    }
    if (strncmp(curr, "integrity_check_", 16) == 0) {
        dbsync_msg action = INTEGRITY_CLEAR;
        if (0 == strcmp(curr, INTEGRITY_COMMANDS[INTEGRITY_CHECK_GLOBAL])) {
            action = INTEGRITY_CHECK_GLOBAL;
        } else if (0 == strcmp(curr, INTEGRITY_COMMANDS[INTEGRITY_CHECK_LEFT])) {
            action = INTEGRITY_CHECK_LEFT;
        } else if (0 == strcmp(curr, INTEGRITY_COMMANDS[INTEGRITY_CHECK_RIGHT])) {
            action = INTEGRITY_CHECK_RIGHT;
        }

        switch (wdbi_query_checksum(wdb, component, action, next)) {
        case INTEGRITY_SYNC_ERR:
            mdebug1("DB(%s) Cannot query Syscollector range checksum.", wdb->id);
            snprintf(output, OS_MAXSTR + 1, "err Cannot perform range checksum");
            return OS_INVALID;

        case INTEGRITY_SYNC_NO_DATA:
            snprintf(output, OS_MAXSTR + 1, "ok no_data");
            break;

        case INTEGRITY_SYNC_CKS_FAIL:
            snprintf(output, OS_MAXSTR + 1, "ok checksum_fail");
            break;

        default:
            snprintf(output, OS_MAXSTR + 1, "ok ");
        }

        return component;
    } else if (strncmp(curr, "integrity_clear", 15) == 0) {
        switch (wdbi_query_clear(wdb, component, next)) {
        case OS_INVALID:
            mdebug1("DB(%s) Cannot query Syscollector range checksum.", wdb->id);
            snprintf(output, OS_MAXSTR + 1, "err Cannot perform range checksum");
            return OS_INVALID;

        default:
            snprintf(output, OS_MAXSTR + 1, "ok ");
        }

        return component;
    } else {
        mdebug1("DB(%s) Invalid Syscollector query syntax.", wdb->id);
        mdebug2("DB query error near: %s", curr);
        snprintf(output, OS_MAXSTR + 1, "err Invalid Syscollector query syntax, near '%.32s'", curr);
        return OS_INVALID;
    }
}

int wdb_parse_sca(wdb_t * wdb, char * input, char * output) {
    char * curr;
    char * next;
    char * result_check; // Pass, failed, or not applicable
    char * reason_check;
    int result;

    if (next = strchr(input, ' '), !next) {
        mdebug1("Invalid Security Configuration Assessment query syntax.");
        mdebug2("Security Configuration Assessment query: %s", input);
        snprintf(output, OS_MAXSTR + 1, "err Invalid Security Configuration Assessment query syntax, near '%.32s'", input);
        return OS_INVALID;
    }

    curr = input;
    *next++ = '\0';

    if (strcmp(curr, "query") == 0) {
        int pm_id;
        char result_found[OS_MAXSTR - WDB_RESPONSE_BEGIN_SIZE] = {0};

        curr = next;
        pm_id = strtol(curr, NULL, 10);

        result = wdb_sca_find(wdb, pm_id, result_found);

        switch (result) {
            case 0:
                snprintf(output, OS_MAXSTR + 1, "ok not found");
                break;
            case 1:
                snprintf(output, OS_MAXSTR + 1, "ok found %s", result_found);
                break;
            default:
                mdebug1("Cannot query Security Configuration Assessment.");
                snprintf(output, OS_MAXSTR + 1, "err Cannot query Security Configuration Assessment");
        }

        return result;
    } else if (strcmp(curr, "update") == 0) {
        int pm_id;
        int scan_id;

        curr = next;
        pm_id = strtol(curr, NULL, 10);

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Security Configuration Assessment query syntax.");
            mdebug2("Security Configuration Assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Security Configuration Assessment query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        *next++ = '\0';
        result_check = next;

        curr = next;
        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Security Configuration Assessment query syntax.");
            mdebug2("Security Configuration Assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Security Configuration Assessment query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        *next++ = '\0';
        reason_check = next;

        curr = next;
        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Security Configuration Assessment query syntax.");
            mdebug2("Security Configuration Assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Security Configuration Assessment query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        *next++ = '\0';
        curr = next;
        if (!strncmp(curr, "NULL", 4))
            scan_id = OS_INVALID;
        else
            scan_id = strtol(curr, NULL, 10);

        if (result = wdb_sca_update(wdb, result_check, pm_id, scan_id, reason_check), result < 0) {
            mdebug1("Cannot update Security Configuration Assessment information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot update Security Configuration Assessment information.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;
    } else if (strcmp(curr, "insert") == 0) {
        curr = next;
        cJSON *event;
        const char *jsonErrPtr;
        if (event = cJSON_ParseWithOpts(curr, &jsonErrPtr, 0), !event)
        {
            mdebug1("Invalid Security Configuration Assessment query syntax. JSON object not found or invalid");
            snprintf(output, OS_MAXSTR + 1, "err Invalid Security Configuration Assessment query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        cJSON *id = NULL;
        cJSON *scan_id = NULL;
        cJSON *title = NULL;
        cJSON *description = NULL;
        cJSON *rationale = NULL;
        cJSON *remediation = NULL;
        cJSON *condition = NULL;
        cJSON *file = NULL;
        cJSON *directory = NULL;
        cJSON *process = NULL;
        cJSON *registry = NULL;
        cJSON *command = NULL;
        cJSON *reference = NULL;
        cJSON *result_check = NULL;
        cJSON *policy_id = NULL;
        cJSON *check = NULL;
        cJSON *reason = NULL;

        if (scan_id = cJSON_GetObjectItem(event, "id"), !scan_id) {
            mdebug1("Invalid Security Configuration Assessment query syntax. JSON object not found or invalid");
            snprintf(output, OS_MAXSTR + 1, "err Invalid Security Configuration Assessment query syntax, near '%.32s'", curr);
            cJSON_Delete(event);
            return OS_INVALID;
        }

        if (!cJSON_IsNumber(scan_id)) {
            mdebug1("Malformed JSON: field 'id' must be a number");
            snprintf(output, OS_MAXSTR + 1, "err Invalid Security Configuration Assessment query syntax, near '%.32s'", curr);
            cJSON_Delete(event);
            return OS_INVALID;
        }

        if (scan_id->valueint < 0) {
            mdebug1("Malformed JSON: field 'id' cannot be negative");
            snprintf(output, OS_MAXSTR + 1, "err Invalid Security Configuration Assessment query syntax, near '%.32s'", curr);
            cJSON_Delete(event);
            return OS_INVALID;
        }

        if (policy_id = cJSON_GetObjectItem(event, "policy_id"), !policy_id) {
            mdebug1("Malformed JSON: field 'policy_id' not found");
            snprintf(output, OS_MAXSTR + 1, "err Invalid Security Configuration Assessment query syntax, near '%.32s'", curr);
            cJSON_Delete(event);
            return OS_INVALID;
        }

        if (!policy_id->valuestring) {
            mdebug1("Malformed JSON: field 'policy_id' must be a string");
            snprintf(output, OS_MAXSTR + 1, "err Invalid Security Configuration Assessment query syntax, near '%.32s'", curr);
            cJSON_Delete(event);
            return OS_INVALID;
        }

        if (check = cJSON_GetObjectItem(event, "check"), !check) {
            mdebug1("Malformed JSON: field 'check' not found");
            cJSON_Delete(event);
            return OS_INVALID;

        } else {
            if (id = cJSON_GetObjectItem(check, "id"), !id) {
                mdebug1("Malformed JSON: field 'id' not found");
                cJSON_Delete(event);
                return OS_INVALID;
            }

            if (!id->valueint) {
                mdebug1("Malformed JSON: field 'id' must be a string");
                cJSON_Delete(event);
                return OS_INVALID;
            }

            if (title = cJSON_GetObjectItem(check, "title"), !title) {
                mdebug1("Malformed JSON: field 'title' not found");
                cJSON_Delete(event);
                return OS_INVALID;
            }

            if (!title->valuestring) {
                mdebug1("Malformed JSON: field 'title' must be a string");
                cJSON_Delete(event);
                return OS_INVALID;
            }

            description = cJSON_GetObjectItem(check, "description");

            if (description && !description->valuestring) {
                mdebug1("Malformed JSON: field 'description' must be a string");
                cJSON_Delete(event);
                return OS_INVALID;
            }

            rationale = cJSON_GetObjectItem(check, "rationale");

            if (rationale && !rationale->valuestring) {
                mdebug1("Malformed JSON: field 'rationale' must be a string");
                cJSON_Delete(event);
                return OS_INVALID;
            }

            remediation = cJSON_GetObjectItem(check, "remediation");
            if (remediation && !remediation->valuestring) {
                mdebug1("Malformed JSON: field 'remediation' must be a string");
                cJSON_Delete(event);
                return OS_INVALID;
            }

            reference = cJSON_GetObjectItem(check, "references");

            if (reference && !reference->valuestring) {
                mdebug1("Malformed JSON: field 'reference' must be a string");
                cJSON_Delete(event);
                return OS_INVALID;
            }

            file = cJSON_GetObjectItem(check, "file");
            if (file && !file->valuestring) {
                mdebug1("Malformed JSON: field 'file' must be a string");
                cJSON_Delete(event);
                return OS_INVALID;
            }

            condition = cJSON_GetObjectItem(check, "condition");
            if (condition && !condition->valuestring) {
                mdebug1("Malformed JSON: field 'condition' must be a string");
                cJSON_Delete(event);
                return OS_INVALID;
            }

            directory = cJSON_GetObjectItem(check, "directory");
            if (directory && !directory->valuestring) {
                mdebug1("Malformed JSON: field 'directory' must be a string");
                cJSON_Delete(event);
                return OS_INVALID;
            }

            process = cJSON_GetObjectItem(check, "process");
            if (process && !process->valuestring) {
                mdebug1("Malformed JSON: field 'process' must be a string");
                return OS_INVALID;
            }

            registry = cJSON_GetObjectItem(check, "registry");
            if (registry && !registry->valuestring) {
                mdebug1("Malformed JSON: field 'registry' must be a string");
                cJSON_Delete(event);
                return OS_INVALID;
            }

            command = cJSON_GetObjectItem(check, "command");
            if (command && !command->valuestring) {
                mdebug1("Malformed JSON: field 'command' must be a string");
                cJSON_Delete(event);
                return OS_INVALID;
            }

            result_check = cJSON_GetObjectItem(check, "result");
            if (result_check && !result_check->valuestring) {
                mdebug1("Malformed JSON: field 'result' must be a string");
                cJSON_Delete(event);
                return OS_INVALID;
            }

            reason = cJSON_GetObjectItem(check, "reason");
            if (reason && !reason->valuestring) {
                mdebug1("Malformed JSON: field 'reason' must be a string");
                cJSON_Delete(event);
                return OS_INVALID;
            }
        }

        if (result = wdb_sca_save(wdb, id->valueint, scan_id->valueint, title->valuestring,
                    description ? description->valuestring : NULL,
                    rationale ? rationale->valuestring : NULL,
                    remediation ? remediation->valuestring : NULL,
                    condition ? condition->valuestring : NULL,
                    file ? file->valuestring : NULL,
                    directory ? directory->valuestring : NULL,
                    process ? process->valuestring : NULL,
                    registry ? registry->valuestring : NULL,
                    reference ? reference->valuestring : NULL,
                    result_check ? result_check->valuestring : "not applicable",
                    policy_id->valuestring,
                    command ? command->valuestring : NULL,
                    reason ? reason->valuestring : NULL),
            result < 0)
        {
            mdebug1("Cannot save Security Configuration Assessment information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot save Security Configuration Assessment information.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        cJSON_Delete(event);

        return result;
    } else if (strcmp(curr, "delete_policy") == 0) {
        char *policy_id;

        curr = next;
        policy_id = curr;

        if (result = wdb_sca_policy_delete(wdb, policy_id), result < 0) {
            mdebug1("Cannot delete Security Configuration Assessment information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot delete Security Configuration Assessment information.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;
    } else if (strcmp(curr, "delete_check_distinct") == 0) {
        char *policy_id;
        int scan_id;

        curr = next;
        policy_id = curr;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Security Configuration Assessment query syntax.");
            mdebug2("Security Configuration Assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Security Configuration Assessment query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        *next++ = '\0';
        curr = next;
        if (!strncmp(curr, "NULL", 4))
            scan_id = OS_INVALID;
        else
            scan_id = strtol(curr, NULL, 10);

        if (result = wdb_sca_check_delete_distinct(wdb, policy_id, scan_id), result < 0) {
            mdebug1("Cannot delete Security Configuration Assessment checks.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot delete Security Configuration Assessment checks.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
            wdb_sca_check_compliances_delete(wdb);
            wdb_sca_check_rules_delete(wdb);
        }

        return result;

    } else if (strcmp(curr, "delete_check") == 0) {
        char *policy_id;

        curr = next;
        policy_id = curr;

        if (result = wdb_sca_check_delete(wdb, policy_id), result < 0) {
            mdebug1("Cannot delete Security Configuration Assessment information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot delete Security Configuration Assessment check information.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
            wdb_sca_check_compliances_delete(wdb);
            wdb_sca_check_rules_delete(wdb);
        }

        return result;
    } else if (strcmp(curr, "query_results") == 0) {
        char * policy_id;
        char result_found[OS_MAXSTR - WDB_RESPONSE_BEGIN_SIZE] = {0};

        curr = next;
        policy_id = curr;

        result = wdb_sca_checks_get_result(wdb, policy_id, result_found);

        switch (result) {
            case 0:
                snprintf(output, OS_MAXSTR + 1, "ok not found");
                break;
            case 1:
                snprintf(output, OS_MAXSTR + 1, "ok found %s", result_found);
                break;
            default:
                mdebug1("Cannot query Security Configuration Assessment.");
                snprintf(output, OS_MAXSTR + 1, "err Cannot query Security Configuration Assessment global");
        }

        return result;
    } else if (strcmp(curr, "query_scan") == 0) {
        char *policy_id;
        char result_found[OS_MAXSTR - WDB_RESPONSE_BEGIN_SIZE] = {0};

        curr = next;
        policy_id = curr;

        result = wdb_sca_scan_find(wdb, policy_id, result_found);

        switch (result) {
            case 0:
                snprintf(output, OS_MAXSTR + 1, "ok not found");
                break;
            case 1:
                snprintf(output, OS_MAXSTR + 1, "ok found %s", result_found);
                break;
            default:
                mdebug1("Cannot query Security Configuration Assessment.");
                snprintf(output, OS_MAXSTR + 1, "err Cannot query Security Configuration Assessment scan");
        }

        return result;
    } else if (strcmp(curr, "query_policies") == 0) {
        char result_found[OS_MAXSTR - WDB_RESPONSE_BEGIN_SIZE] = {0};

        result = wdb_sca_policy_get_id(wdb, result_found);

        switch (result) {
            case 0:
                snprintf(output, OS_MAXSTR + 1, "ok not found");
                break;
            case 1:
                snprintf(output, OS_MAXSTR + 1, "ok found %s", result_found);
                break;
            default:
                mdebug1("Cannot query Security Configuration Assessment.");
                snprintf(output, OS_MAXSTR + 1, "err Cannot query Security Configuration Assessment scan");
        }

        return result;
    } else if (strcmp(curr, "query_policy") == 0) {
        char *policy;
        char result_found[OS_MAXSTR - WDB_RESPONSE_BEGIN_SIZE] = {0};

        curr = next;
        policy = curr;

        result = wdb_sca_policy_find(wdb, policy, result_found);

        switch (result) {
            case 0:
                snprintf(output, OS_MAXSTR + 1, "ok not found");
                break;
            case 1:
                snprintf(output, OS_MAXSTR + 1, "ok found %s", result_found);
                break;
            default:
                mdebug1("Cannot query Security Configuration Assessment.");
                snprintf(output, OS_MAXSTR + 1, "err Cannot query policy scan");
        }

        return result;
    } else if (strcmp(curr, "query_policy_sha256") == 0) {
        char *policy;
        char result_found[OS_MAXSTR - WDB_RESPONSE_BEGIN_SIZE] = {0};

        curr = next;
        policy = curr;

        result = wdb_sca_policy_sha256(wdb, policy, result_found);
        switch (result) {
            case 0:
                snprintf(output, OS_MAXSTR + 1, "ok not found");
                break;
            case 1:
                snprintf(output, OS_MAXSTR + 1, "ok found %s", result_found);
                break;
            default:
                mdebug1("Cannot query Security Configuration Assessment.");
                snprintf(output, OS_MAXSTR + 1, "err Cannot query policy scan");
        }

        return result;
    } else if (strcmp(curr, "insert_policy") == 0) {
        char *name;
        char *file;
        char *id;
        char *description;
        char *references;
        char *hash_file;

        curr = next;
        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Security Configuration Assessment query syntax.");
            mdebug2("Security Configuration Assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Security Configuration Assessment query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        name = curr;
        *next++ = '\0';

        curr = next;
        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Security Configuration Assessment query syntax.");
            mdebug2("Security Configuration Assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Security Configuration Assessment query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        file = curr;
        *next++ = '\0';

        curr = next;
        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Security Configuration Assessment query syntax.");
            mdebug2("Security Configuration Assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Security Configuration Assessment query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        id = curr;
        *next++ = '\0';

        curr = next;
        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Security Configuration Assessment query syntax.");
            mdebug2("Security Configuration Assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Security Configuration Assessment query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        description = curr;
        *next++ = '\0';

        curr = next;
        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Security Configuration Assessment query syntax.");
            mdebug2("Security Configuration Assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Security Configuration Assessment query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        references = curr;
        *next++ = '\0';

        hash_file = next;
        if (result = wdb_sca_policy_info_save(wdb, name, file, id, description, references, hash_file), result < 0) {
            mdebug1("Cannot save Security Configuration Assessment information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot save Security Configuration Assessment global information.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;

    } else if (strcmp(curr, "insert_rules") == 0) {
        int id_check;
        char *type;
        char *rule;

         curr = next;

         if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Security Configuration Assessment query syntax.");
            mdebug2("Security Configuration Assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Security Configuration Assessment query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

         id_check = strtol(curr, NULL, 10);
        *next++ = '\0';

         curr = next;
        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Security Configuration Assessment query syntax.");
            mdebug2("Security Configuration Assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid configuration assessment query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

         type = curr;
        *next++ = '\0';

         rule = next;
        if (result = wdb_sca_rules_save(wdb, id_check, type, rule), result < 0) {
            mdebug1("Cannot save configuration assessment information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot save configuration assessment global information.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

         return result;

    } else if (strcmp(curr, "insert_compliance") == 0) {
        int id_check;
        char *key;
        char *value;

        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Security Configuration Assessment query syntax.");
            mdebug2("Security Configuration Assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Security Configuration Assessment query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        id_check = strtol(curr, NULL, 10);
        *next++ = '\0';

        curr = next;
        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Security Configuration Assessment query syntax.");
            mdebug2("Security Configuration Assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid configuration assessment query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        key = curr;
        *next++ = '\0';

        value = next;
        if (result = wdb_sca_compliance_save(wdb, id_check, key, value), result < 0) {
            mdebug1("Cannot save configuration assessment information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot save configuration assessment global information.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;
    } else if (strcmp(curr, "insert_scan_info") == 0) {
        curr = next;

        int pm_start_scan;
        int pm_end_scan;
        int scan_id;
        char * policy_id;
        int pass;
        int fail;
        int invalid;
        int total_checks;
        int score;
        char *hash;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid configuration assessment query syntax.");
            mdebug2("configuration assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid configuration assessment query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        if (!strncmp(curr, "NULL", 4))
            pm_start_scan = OS_INVALID;
        else
            pm_start_scan = strtol(curr, NULL, 10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid configuration assessment query syntax.");
            mdebug2("configuration assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid configuration assessment query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        if (!strncmp(curr, "NULL", 4))
            pm_end_scan = OS_INVALID;
        else
            pm_end_scan = strtol(curr, NULL, 10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid configuration assessment query syntax.");
            mdebug2("configuration assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid configuration assessment query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        if (!strncmp(curr, "NULL", 4))
            scan_id = OS_INVALID;
        else
            scan_id = strtol(curr, NULL, 10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid configuration assessment query syntax.");
            mdebug2("configuration assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid configuration assessment query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        policy_id = curr;
        *next++ = '\0';

        curr = next;
        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid configuration assessment query syntax.");
            mdebug2("configuration assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid configuration assessment query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        if (!strncmp(curr, "NULL", 4))
            pass = OS_INVALID;
        else
            pass = strtol(curr, NULL, 10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid configuration assessment query syntax.");
            mdebug2("configuration assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid configuration assessment query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        if (!strncmp(curr, "NULL", 4))
            fail = OS_INVALID;
        else
            fail = strtol(curr, NULL, 10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid configuration assessment query syntax.");
            mdebug2("configuration assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid configuration assessment query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        if (!strncmp(curr, "NULL", 4))
            invalid = OS_INVALID;
        else
            invalid = strtol(curr, NULL, 10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid configuration assessment query syntax.");
            mdebug2("configuration assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid configuration assessment query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        if (!strncmp(curr, "NULL", 4))
            total_checks = OS_INVALID;
        else
            total_checks = strtol(curr, NULL, 10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid configuration assessment query syntax.");
            mdebug2("configuration assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid configuration assessment query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        if (!strncmp(curr, "NULL", 4))
            score = OS_INVALID;
        else
            score = strtol(curr, NULL, 10);

        *next++ = '\0';

        hash = next;
        if (result = wdb_sca_scan_info_save(wdb, pm_start_scan, pm_end_scan, scan_id, policy_id, pass, fail, invalid, total_checks, score, hash), result < 0) {
            mdebug1("Cannot save configuration assessment information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot save configuration assessment information.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;
    } else if (strcmp(curr, "update_scan_info") == 0) {
        curr = next;

        char *module;
        int pm_end_scan;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid configuration assessment query syntax.");
            mdebug2("configuration assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid configuration assessment query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        module = curr;
        *next++ = '\0';

        if (!strcmp(module, "NULL"))
            module = NULL;

        *next++ = '\0';
        curr = next;

        if (!strncmp(curr, "NULL", 4))
            pm_end_scan = OS_INVALID;
        else
            pm_end_scan = strtol(curr, NULL, 10);

        if (result = wdb_sca_scan_info_update(wdb, module, pm_end_scan), result < 0) {
            mdebug1("Cannot save configuration assessment information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot save configuration assessment information.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;
    } else if (strcmp(curr, "update_scan_info_start") == 0) {
        char *policy_id;
        int pm_start_scan;
        int pm_end_scan;
        int scan_id;
        int pass;
        int fail;
        int invalid;
        int total_checks;
        int score;
        char *hash;

        curr = next;
        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid configuration assessment query syntax.");
            mdebug2("configuration assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid configuration assessment query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        policy_id = curr;

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid configuration assessment query syntax.");
            mdebug2("configuration assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid configuration assessment query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        if (!strcmp(policy_id, "NULL"))
            policy_id = NULL;

        *next++ = '\0';
        curr = next;

        if (!strncmp(curr, "NULL", 4))
            pm_start_scan = OS_INVALID;
        else
            pm_start_scan = strtol(curr, NULL, 10);

        curr = next;
        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid configuration assessment query syntax.");
            mdebug2("configuration assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid configuration assessment query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        if (!strncmp(curr, "NULL", 4))
            pm_end_scan = OS_INVALID;
        else
            pm_end_scan = strtol(curr, NULL, 10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid configuration assessment query syntax.");
            mdebug2("configuration assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid configuration assessment query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        if (!strncmp(curr, "NULL", 4))
            scan_id = OS_INVALID;
        else
            scan_id = strtol(curr, NULL, 10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid configuration assessment query syntax.");
            mdebug2("configuration assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid configuration assessment query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        if (!strncmp(curr, "NULL", 4))
            pass = OS_INVALID;
        else
            pass = strtol(curr, NULL, 10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid configuration assessment query syntax.");
            mdebug2("configuration assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid configuration assessment query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        if (!strncmp(curr, "NULL", 4))
            fail = OS_INVALID;
        else
            fail = strtol(curr, NULL, 10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid configuration assessment query syntax.");
            mdebug2("configuration assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid configuration assessment query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        if (!strncmp(curr, "NULL", 4))
            invalid = OS_INVALID;
        else
            invalid = strtol(curr, NULL, 10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid configuration assessment query syntax.");
            mdebug2("configuration assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid configuration assessment query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        if (!strncmp(curr, "NULL", 4))
            total_checks = OS_INVALID;
        else
            total_checks = strtol(curr, NULL, 10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid configuration assessment query syntax.");
            mdebug2("configuration assessment query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid configuration assessment query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        if (!strncmp(curr, "NULL", 4))
            score = OS_INVALID;
        else
            score = strtol(curr, NULL, 10);

        *next++ = '\0';

        hash = next;

        if (result = wdb_sca_scan_info_update_start(wdb, policy_id, pm_start_scan, pm_end_scan, scan_id, pass, fail, invalid, total_checks, score, hash), result < 0) {
            mdebug1("Cannot save configuration assessment information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot save configuration assessment information.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;
    } else {
        mdebug1("Invalid configuration assessment query syntax.");
        mdebug2("DB query error near: %s", curr);
        snprintf(output, OS_MAXSTR + 1, "err Invalid Rootcheck query syntax, near '%.32s'", curr);
        return OS_INVALID;
    }
}

int wdb_parse_netinfo(wdb_t * wdb, char * input, char * output) {
    char * curr;
    char * next;
    char * scan_id;
    char * scan_time;
    char * name;
    char * adapter;
    char * type;
    char * state;
    int mtu;
    char * mac;
    long tx_packets;
    long rx_packets;
    long tx_bytes;
    long rx_bytes;
    long tx_errors;
    long rx_errors;
    long tx_dropped;
    long rx_dropped;
    long result;

    if (next = strchr(input, ' '), !next) {
        mdebug1("Invalid Network query syntax.");
        mdebug2("Network query: %s", input);
        snprintf(output, OS_MAXSTR + 1, "err Invalid Network query syntax, near '%.32s'", input);
        return OS_INVALID;
    }

    curr = input;
    *next++ = '\0';

    if (strcmp(curr, "save") == 0) {
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Network query syntax.");
            mdebug2("Network query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Network query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        scan_id = curr;
        *next++ = '\0';
        curr = next;

        if (!strcmp(scan_id, "NULL"))
            scan_id = NULL;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Network query syntax.");
            mdebug2("Network query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Network query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        scan_time = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Network query syntax.");
            mdebug2("Network query: %s", scan_time);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Network query syntax, near '%.32s'", scan_time);
            return OS_INVALID;
        }

        if (!strcmp(scan_time, "NULL"))
            scan_time = NULL;

        name = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Network query syntax.");
            mdebug2("Network query: %s", name);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Network query syntax, near '%.32s'", name);
            return OS_INVALID;
        }

        if (!strcmp(name, "NULL"))
            name = NULL;

        adapter = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Network query syntax.");
            mdebug2("Network query: %s", adapter);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Network query syntax, near '%.32s'", adapter);
            return OS_INVALID;
        }

        if (!strcmp(adapter, "NULL"))
            adapter = NULL;

        type = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Network query syntax.");
            mdebug2("Network query: %s", type);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Network query syntax, near '%.32s'", type);
            return OS_INVALID;
        }

        if (!strcmp(type, "NULL"))
            type = NULL;

        state = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Network query syntax.");
            mdebug2("Network query: %s", state);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Network query syntax, near '%.32s'", state);
            return OS_INVALID;
        }

        if (!strcmp(state, "NULL"))
            state = NULL;

        if (!strncmp(curr, "NULL", 4))
            mtu = OS_INVALID;
        else
            mtu = strtol(curr, NULL, 10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Network query syntax.");
            mdebug2("Network query: %d", mtu);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Network query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        mac = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Network query syntax.");
            mdebug2("Network query: %s", mac);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Network query syntax, near '%.32s'", mac);
            return OS_INVALID;
        }

        if (!strcmp(mac, "NULL"))
            mac = NULL;

        if (!strncmp(curr, "NULL", 4))
            tx_packets = OS_INVALID;
        else
            tx_packets = strtol(curr, NULL, 10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Network query syntax.");
            mdebug2("Network query: %ld", tx_packets);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Network query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        if (!strncmp(curr, "NULL", 4))
            rx_packets = OS_INVALID;
        else
            rx_packets = strtol(curr, NULL, 10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Network query syntax.");
            mdebug2("Network query: %ld", rx_packets);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Network query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        if (!strncmp(curr, "NULL", 4))
            tx_bytes = OS_INVALID;
        else
            tx_bytes = strtol(curr, NULL, 10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Network query syntax.");
            mdebug2("Network query: %ld", tx_bytes);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Network query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        if (!strncmp(curr, "NULL", 4))
            rx_bytes = OS_INVALID;
        else
            rx_bytes = strtol(curr, NULL, 10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Network query syntax.");
            mdebug2("Network query: %ld", rx_bytes);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Network query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        if (!strncmp(curr, "NULL", 4))
            tx_errors = OS_INVALID;
        else
            tx_errors = strtol(curr, NULL, 10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Network query syntax.");
            mdebug2("Network query: %ld", tx_errors);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Network query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        if (!strncmp(curr, "NULL", 4))
            rx_errors = OS_INVALID;
        else
            rx_errors = strtol(curr, NULL, 10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Network query syntax.");
            mdebug2("Network query: %ld", rx_errors);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Network query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        if (!strncmp(curr, "NULL", 4))
            tx_dropped = OS_INVALID;
        else
            tx_dropped = strtol(curr, NULL, 10);

        *next++ = '\0';
        if (!strncmp(next, "NULL", 4))
            rx_dropped = OS_INVALID;
        else
            rx_dropped = strtol(next, NULL, 10);

        if (result = wdb_netinfo_save(wdb, scan_id, scan_time, name, adapter, type, state, mtu, mac, tx_packets, rx_packets, tx_bytes, rx_bytes, tx_errors, rx_errors, tx_dropped, rx_dropped, SYSCOLLECTOR_LEGACY_CHECKSUM_VALUE, NULL, FALSE), result < 0) {
            mdebug1("Cannot save Network information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot save Network information.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;

    } else if (strcmp(curr, "del") == 0) {
        if (!strcmp(next, "NULL"))
            scan_id = NULL;
        else
            scan_id = next;

        if (result = wdb_netinfo_delete(wdb, scan_id), result < 0) {
            mdebug1("Cannot delete old network information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot delete old network information.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;

    } else {
        mdebug1("Invalid netinfo query syntax.");
        mdebug2("DB query error near: %s", curr);
        snprintf(output, OS_MAXSTR + 1, "err Invalid netinfo query syntax, near '%.32s'", curr);
        return OS_INVALID;
    }
}

int wdb_parse_netproto(wdb_t * wdb, char * input, char * output) {
    char * curr;
    char * next;
    char * scan_id;
    char * iface;
    int type;
    char * gateway;
    int metric;
    char * dhcp;
    int result;

    if (next = strchr(input, ' '), !next) {
        mdebug1("Invalid netproto query syntax.");
        mdebug2("netproto query: %s", input);
        snprintf(output, OS_MAXSTR + 1, "err Invalid netproto query syntax, near '%.32s'", input);
        return OS_INVALID;
    }

    curr = input;
    *next++ = '\0';

    if (strcmp(curr, "save") == 0) {
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid netproto query syntax.");
            mdebug2("netproto query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid netproto query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        scan_id = curr;
        *next++ = '\0';
        curr = next;

        if (!strcmp(scan_id, "NULL"))
            scan_id = NULL;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid netproto query syntax.");
            mdebug2("netproto query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid netproto query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        iface = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid netproto query syntax.");
            mdebug2("netproto query: %s", iface);
            snprintf(output, OS_MAXSTR + 1, "err Invalid netproto query syntax, near '%.32s'", iface);
            return OS_INVALID;
        }

        if (!strcmp(iface, "NULL"))
            iface = NULL;

        type = strtol(curr, NULL, 10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Network query syntax.");
            mdebug2("Network query: %d", type);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Network query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        gateway = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid netproto query syntax.");
            mdebug2("netproto query: %s", gateway);
            snprintf(output, OS_MAXSTR + 1, "err Invalid netproto query syntax, near '%.32s'", gateway);
            return OS_INVALID;
        }

        if (!strcmp(gateway, "NULL"))
            gateway = NULL;

        dhcp = curr;
        *next++ = '\0';

        if (!strcmp(dhcp, "NULL"))
            dhcp = NULL;

        if (!strncmp(next, "NULL", 4))
            metric = OS_INVALID;
        else
            metric = strtol(next, NULL, 10);

        if (result = wdb_netproto_save(wdb, scan_id, iface, type, gateway, dhcp, metric, SYSCOLLECTOR_LEGACY_CHECKSUM_VALUE, NULL, FALSE), result < 0) {
            mdebug1("Cannot save netproto information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot save netproto information.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;

    } else {
        mdebug1("Invalid netproto query syntax.");
        mdebug2("DB query error near: %s", curr);
        snprintf(output, OS_MAXSTR + 1, "err Invalid netproto query syntax, near '%.32s'", curr);
        return OS_INVALID;
    }
}

int wdb_parse_netaddr(wdb_t * wdb, char * input, char * output) {
    char * curr;
    char * next;
    char * scan_id;
    int proto;
    char * address;
    char * netmask;
    char * broadcast;
    char * iface;
    int result;

    if (next = strchr(input, ' '), !next) {
        mdebug1("Invalid netaddr query syntax.");
        mdebug2("netaddr query: %s", input);
        snprintf(output, OS_MAXSTR + 1, "err Invalid netaddr query syntax, near '%.32s'", input);
        return OS_INVALID;
    }

    curr = input;
    *next++ = '\0';

    if (strcmp(curr, "save") == 0) {
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid netaddr query syntax.");
            mdebug2("netaddr query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid netaddr query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        scan_id = curr;
        *next++ = '\0';
        curr = next;

        if (!strcmp(scan_id, "NULL"))
            scan_id = NULL;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid netaddr query syntax.");
            mdebug2("netaddr query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid netaddr query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        iface = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid netaddr query syntax.");
            mdebug2("netaddr query: %s", iface);
            snprintf(output, OS_MAXSTR + 1, "err Invalid netaddr query syntax, near '%.32s'", iface);
            return OS_INVALID;
        }

        if (!strcmp(iface, "NULL"))
            iface = NULL;

        proto = strtol(curr, NULL, 10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Network query syntax.");
            mdebug2("Network query: %d", proto);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Network query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        address = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid netaddr query syntax.");
            mdebug2("netaddr query: %s", address);
            snprintf(output, OS_MAXSTR + 1, "err Invalid netaddr query syntax, near '%.32s'", address);
            return OS_INVALID;
        }

        if (!strcmp(address, "NULL"))
            address = NULL;

        netmask = curr;
        *next++ = '\0';

        if (!strcmp(netmask, "NULL"))
            netmask = NULL;

        if (!strcmp(next, "NULL"))
            broadcast = NULL;
        else
            broadcast = next;

        if (result = wdb_netaddr_save(wdb, scan_id, iface, proto, address, netmask, broadcast, SYSCOLLECTOR_LEGACY_CHECKSUM_VALUE, NULL, FALSE), result < 0) {
            mdebug1("Cannot save netaddr information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot save netaddr information.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;

    } else {
        mdebug1("Invalid netaddr query syntax.");
        mdebug2("DB query error near: %s", curr);
        snprintf(output, OS_MAXSTR + 1, "err Invalid netaddr query syntax, near '%.32s'", curr);
        return OS_INVALID;
    }
}

int wdb_parse_osinfo(wdb_t* wdb, char* input, char* output) {
    int result = OS_INVALID;
    char * next;
    const char delim[] = " ";
    char *tail = NULL;

    next = strtok_r(input, delim, &tail);

    if (!next) {
        snprintf(output, OS_MAXSTR + 1, "err Missing osinfo action");
    }
    else if (strcmp(next, "get") == 0) {
        result = wdb_parse_agents_get_sys_osinfo(wdb, output);
    }
    else if (strcmp(next, "set") == 0) {
        result = wdb_parse_agents_set_sys_osinfo(wdb, tail, output);
    }
    else {
        snprintf(output, OS_MAXSTR + 1, "err Invalid osinfo action: %s", next);
    }

    return result;
}

int wdb_parse_agents_get_sys_osinfo(wdb_t* wdb, char* output) {
    int ret = OS_INVALID;
    cJSON *result = wdb_agents_get_sys_osinfo(wdb);
    if (!result) {
        snprintf(output, OS_MAXSTR + 1, "err Cannot get sys_osinfo database table information; SQL err: %s", sqlite3_errmsg(wdb->db));
    }
    else {
        char *out = cJSON_PrintUnformatted(result);
        snprintf(output, OS_MAXSTR + 1, "ok %s", out);
        os_free(out);
        cJSON_Delete(result);
        ret = OS_SUCCESS;
    }
    return ret;
}

int wdb_parse_agents_set_sys_osinfo(wdb_t * wdb, char * input, char * output) {
    char * curr;
    char * next;
    char * scan_id;
    char * scan_time;
    char * hostname;
    char * architecture;
    char * os_name;
    char * os_version;
    char * os_codename;
    char * os_major;
    char * os_minor;
    char * os_build;
    char * os_platform;
    char * sysname;
    char * release;
    char * version;
    char * os_release;
    char * os_patch;
    char * os_display_version;
    int result;

    curr = input;

    if (next = strchr(curr, '|'), !next) {
        mdebug1("Invalid OS info query syntax.");
        snprintf(output, OS_MAXSTR + 1, "err Invalid OS info query syntax");
        return OS_INVALID;
    }

    scan_id = curr;
    *next++ = '\0';
    curr = next;

    if (!strcmp(scan_id, "NULL"))
        scan_id = NULL;

    if (next = strchr(curr, '|'), !next) {
        mdebug1("Invalid OS info query syntax.");
        snprintf(output, OS_MAXSTR + 1, "err Invalid OS info query syntax");
        return OS_INVALID;
    }

    scan_time = curr;
    *next++ = '\0';
    curr = next;

    if (!strcmp(scan_time, "NULL"))
        scan_time = NULL;

    if (next = strchr(curr, '|'), !next) {
        mdebug1("Invalid OS info query syntax.");
        snprintf(output, OS_MAXSTR + 1, "err Invalid OS info query syntax");
        return OS_INVALID;
    }

    hostname = curr;
    *next++ = '\0';
    curr = next;

    if (!strcmp(hostname, "NULL"))
        hostname = NULL;

    if (next = strchr(curr, '|'), !next) {
        mdebug1("Invalid OS info query syntax.");
        snprintf(output, OS_MAXSTR + 1, "err Invalid OS info query syntax");
        return OS_INVALID;
    }

    architecture = curr;
    *next++ = '\0';
    curr = next;

    if (!strcmp(architecture, "NULL"))
        architecture = NULL;

    if (next = strchr(curr, '|'), !next) {
        mdebug1("Invalid OS info query syntax.");
        snprintf(output, OS_MAXSTR + 1, "err Invalid OS info query syntax");
        return OS_INVALID;
    }

    os_name = curr;
    *next++ = '\0';
    curr = next;

    if (!strcmp(os_name, "NULL"))
        os_name = NULL;

    if (next = strchr(curr, '|'), !next) {
        mdebug1("Invalid OS info query syntax.");
        snprintf(output, OS_MAXSTR + 1, "err Invalid OS info query syntax");
        return OS_INVALID;
    }

    os_version = curr;
    *next++ = '\0';
    curr = next;

    if (!strcmp(os_version, "NULL"))
        os_version = NULL;

    if (next = strchr(curr, '|'), !next) {
        mdebug1("Invalid OS info query syntax.");
        snprintf(output, OS_MAXSTR + 1, "err Invalid OS info query syntax");
        return OS_INVALID;
    }

    os_codename = curr;
    *next++ = '\0';
    curr = next;

    if (!strcmp(os_codename, "NULL"))
        os_codename = NULL;

    if (next = strchr(curr, '|'), !next) {
        mdebug1("Invalid OS info query syntax.");
        snprintf(output, OS_MAXSTR + 1, "err Invalid OS info query syntax");
        return OS_INVALID;
    }

    os_major = curr;
    *next++ = '\0';
    curr = next;

    if (!strcmp(os_major, "NULL"))
        os_major = NULL;

    if (next = strchr(curr, '|'), !next) {
        mdebug1("Invalid OS info query syntax.");
        snprintf(output, OS_MAXSTR + 1, "err Invalid OS info query syntax");
        return OS_INVALID;
    }

    os_minor = curr;
    *next++ = '\0';
    curr = next;

    if (!strcmp(os_minor, "NULL"))
        os_minor = NULL;

    if (next = strchr(curr, '|'), !next) {
        mdebug1("Invalid OS info query syntax.");
        snprintf(output, OS_MAXSTR + 1, "err Invalid OS info query syntax");
        return OS_INVALID;
    }

    os_build = curr;
    *next++ = '\0';
    curr = next;

    if (!strcmp(os_build, "NULL"))
        os_build = NULL;

    if (next = strchr(curr, '|'), !next) {
        mdebug1("Invalid OS info query syntax.");
        snprintf(output, OS_MAXSTR + 1, "err Invalid OS info query syntax");
        return OS_INVALID;
    }

    os_platform = curr;
    *next++ = '\0';
    curr = next;

    if (!strcmp(os_platform, "NULL"))
        os_platform = NULL;

    if (next = strchr(curr, '|'), !next) {
        mdebug1("Invalid OS info query syntax.");
        snprintf(output, OS_MAXSTR + 1, "err Invalid OS info query syntax");
        return OS_INVALID;
    }

    sysname = curr;
    *next++ = '\0';
    curr = next;

    if (!strcmp(sysname, "NULL"))
        sysname = NULL;

    if (next = strchr(curr, '|'), !next) {
        mdebug1("Invalid OS info query syntax.");
        snprintf(output, OS_MAXSTR + 1, "err Invalid OS info query syntax");
        return OS_INVALID;
    }

    release = curr;
    *next++ = '\0';
    curr = next;

    if (!strcmp(release, "NULL"))
        release = NULL;

    if (next = strchr(curr, '|'), !next) {
        mdebug1("Invalid OS info query syntax.");
        snprintf(output, OS_MAXSTR + 1, "err Invalid OS info query syntax");
        return OS_INVALID;
    }

    version = curr;
    *next++ = '\0';
    curr = next;

    if (!strcmp(version, "NULL"))
        version = NULL;

    if (next = strchr(curr, '|'), !next) {
        mdebug1("Invalid OS info query syntax.");
        snprintf(output, OS_MAXSTR + 1, "err Invalid OS info query syntax");
        return OS_INVALID;
    }

    os_release = curr;
    *next++ = '\0';
    curr = next;

    if (!strcmp(os_release, "NULL"))
    os_release = NULL;

    if (next = strchr(curr, '|'), !next) {
        mdebug1("Invalid OS info query syntax.");
        mdebug2("OS info query: %s", curr);
        snprintf(output, OS_MAXSTR + 1, "err Invalid OS info query syntax, near '%.32s'", curr);
        return OS_INVALID;
    }

    os_patch = curr;
    *next++ = '\0';

    if (!strcmp(os_patch, "NULL"))
        os_patch = NULL;

    if (!strcmp(next, "NULL"))
        os_display_version = NULL;
    else
        os_display_version = next;

    if (result = wdb_osinfo_save(wdb, scan_id, scan_time, hostname, architecture, os_name, os_version, os_codename, os_major, os_minor, os_patch, os_build, os_platform, sysname, release, version, os_release, os_display_version, SYSCOLLECTOR_LEGACY_CHECKSUM_VALUE, FALSE), result < 0) {
        mdebug1("Cannot save OS information.");
        snprintf(output, OS_MAXSTR + 1, "err Cannot save OS information.");
    } else {
        snprintf(output, OS_MAXSTR + 1, "ok");
    }

    return result;
}

int wdb_parse_hardware(wdb_t * wdb, char * input, char * output) {
    char * curr;
    char * next;
    char * scan_id;
    char * scan_time;
    char * serial;
    char * cpu_name;
    int cpu_cores;
    double cpu_mhz;
    uint64_t ram_total;
    uint64_t ram_free;
    int ram_usage;
    int result;

    if (next = strchr(input, ' '), !next) {
        mdebug1("Invalid HW info query syntax.");
        mdebug2("HW info query: %s", input);
        snprintf(output, OS_MAXSTR + 1, "err Invalid HW info query syntax, near '%.32s'", input);
        return OS_INVALID;
    }

    curr = input;
    *next++ = '\0';

    if (strcmp(curr, "save") == 0) {
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid HW info query syntax.");
            mdebug2("HW info query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid HW info query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        scan_id = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid HW info query syntax.");
            mdebug2("HW info query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid HW info query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        if (!strcmp(scan_id, "NULL"))
            scan_id = NULL;

        scan_time = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid HW info query syntax.");
            mdebug2("HW info query: %s", scan_time);
            snprintf(output, OS_MAXSTR + 1, "err Invalid HW info query syntax, near '%.32s'", scan_time);
            return OS_INVALID;
        }

        if (!strcmp(scan_time, "NULL"))
            scan_time = NULL;

        serial = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid HW info query syntax.");
            mdebug2("HW info query: %s", serial);
            snprintf(output, OS_MAXSTR + 1, "err Invalid HW info query syntax, near '%.32s'", serial);
            return OS_INVALID;
        }

        if (!strcmp(serial, "NULL"))
            serial = NULL;

        cpu_name = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid HW info query syntax.");
            mdebug2("HW info query: %s", cpu_name);
            snprintf(output, OS_MAXSTR + 1, "err Invalid HW info query syntax, near '%.32s'", cpu_name);
            return OS_INVALID;
        }

        if (!strcmp(cpu_name, "NULL"))
            cpu_name = NULL;

        cpu_cores = strtol(curr, NULL, 10);
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid HW info query syntax.");
            mdebug2("HW info query: %d", cpu_cores);
            snprintf(output, OS_MAXSTR + 1, "err Invalid HW info query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        cpu_mhz = strtod(curr, NULL);
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid HW info query syntax.");
            mdebug2("HW info query: %f", cpu_mhz);
            snprintf(output, OS_MAXSTR + 1, "err Invalid HW info query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        ram_total = strtol(curr, NULL, 10);
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid HW info query syntax.");
            mdebug2("HW info query: %" PRIu64, ram_total);
            snprintf(output, OS_MAXSTR + 1, "err Invalid HW info query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        ram_free = strtol(curr, NULL, 10);
        *next++ = '\0';
        ram_usage = strtol(next, NULL, 10);

        if (result = wdb_hardware_save(wdb, scan_id, scan_time, serial, cpu_name, cpu_cores, cpu_mhz, ram_total, ram_free, ram_usage, SYSCOLLECTOR_LEGACY_CHECKSUM_VALUE, FALSE), result < 0) {
            mdebug1("wdb_parse_hardware(): Cannot save HW information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot save HW information.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;
    } else {
        mdebug1("Invalid HW info query syntax.");
        mdebug2("DB query error near: %s", curr);
        snprintf(output, OS_MAXSTR + 1, "err Invalid HW info query syntax, near '%.32s'", curr);
        return OS_INVALID;
    }
}

int wdb_parse_ports(wdb_t * wdb, char * input, char * output) {
    char * curr;
    char * next;
    char * scan_id;
    char * scan_time;
    char * protocol;
    char * local_ip;
    int local_port;
    char * remote_ip;
    int remote_port;
    int tx_queue;
    int rx_queue;
    long long inode;
    char * state;
    int pid;
    char * process;
    int result;

    if (next = strchr(input, ' '), !next) {
        mdebug1("Invalid Port query syntax.");
        mdebug2("Port query: %s", input);
        snprintf(output, OS_MAXSTR + 1, "err Invalid Port query syntax, near '%.32s'", input);
        return OS_INVALID;
    }

    curr = input;
    *next++ = '\0';

    if (strcmp(curr, "save") == 0) {
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Port query syntax.");
            mdebug2("Port query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Port query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        scan_id = curr;
        *next++ = '\0';
        curr = next;

        if (!strcmp(scan_id, "NULL"))
            scan_id = NULL;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Port query syntax.");
            mdebug2("Port query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Port query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        scan_time = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Port query syntax.");
            mdebug2("Port query: %s", scan_time);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Port query syntax, near '%.32s'", scan_time);
            return OS_INVALID;
        }

        if (!strcmp(scan_time, "NULL"))
            scan_time = NULL;

        protocol = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Port query syntax.");
            mdebug2("Port query: %s", protocol);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Port query syntax, near '%.32s'", protocol);
            return OS_INVALID;
        }

        if (!strcmp(protocol, "NULL"))
            protocol = NULL;

        local_ip = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Port query syntax.");
            mdebug2("Port query: %s", local_ip);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Port query syntax, near '%.32s'", local_ip);
            return OS_INVALID;
        }

        if (!strcmp(local_ip, "NULL"))
            local_ip = NULL;

        if (!strncmp(curr, "NULL", 4))
            local_port = OS_INVALID;
        else
            local_port = strtol(curr, NULL, 10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Port query syntax.");
            mdebug2("Port query: %d", local_port);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Port query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        remote_ip = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Port query syntax.");
            mdebug2("Port query: %s", remote_ip);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Port query syntax, near '%.32s'", remote_ip);
            return OS_INVALID;
        }

        if (!strcmp(remote_ip, "NULL"))
            remote_ip = NULL;

        if (!strncmp(curr, "NULL", 4))
            remote_port = OS_INVALID;
        else
            remote_port = strtol(curr, NULL, 10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Port query syntax.");
            mdebug2("Port query: %d", remote_port);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Port query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        if (!strncmp(curr, "NULL", 4))
            tx_queue = OS_INVALID;
        else
            tx_queue = strtol(curr, NULL, 10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Port query syntax.");
            mdebug2("Port query: %d", tx_queue);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Port query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        if (!strncmp(curr, "NULL", 4))
            rx_queue = OS_INVALID;
        else
            rx_queue = strtol(curr, NULL, 10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Port query syntax.");
            mdebug2("Port query: %d", rx_queue);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Port query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        if (!strncmp(curr, "NULL", 4))
            inode = OS_INVALID;
        else
            inode = strtoll(curr, NULL, 10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Port query syntax.");
            mdebug2("Port query: %lld", inode);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Port query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        state = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Port query syntax.");
            mdebug2("Port query: %s", state);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Port query syntax, near '%.32s'", state);
            return OS_INVALID;
        }

        if (!strcmp(state, "NULL"))
            state = NULL;

        if (!strncmp(curr, "NULL", 4))
            pid = OS_INVALID;
        else
            pid = strtol(curr, NULL, 10);

        *next++ = '\0';
        if (!strncmp(next, "NULL", 4))
            process = NULL;
        else
            process = next;

        if (result = wdb_port_save(wdb, scan_id, scan_time, protocol, local_ip, local_port, remote_ip, remote_port, tx_queue, rx_queue, inode, state, pid, process, SYSCOLLECTOR_LEGACY_CHECKSUM_VALUE, NULL, TRUE), result < 0) {
            mdebug1("Cannot save Port information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot save Port information.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;
    } else if (strcmp(curr, "del") == 0) {
        if (!strcmp(next, "NULL"))
            scan_id = NULL;
        else
            scan_id = next;

        if (result = wdb_port_delete(wdb, scan_id), result < 0) {
            mdebug1("Cannot delete old Port information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot delete old Port information.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;

    } else {
        mdebug1("Invalid Port query syntax.");
        mdebug2("DB query error near: %s", curr);
        snprintf(output, OS_MAXSTR + 1, "err Invalid Port query syntax, near '%.32s'", curr);
        return OS_INVALID;
    }
}

int wdb_parse_packages(wdb_t * wdb, char * input, char * output) {
    int result = OS_INVALID;
    char* next = NULL;
    char* tail = NULL;
    char* action = strtok_r(input, " ", &tail);

    if (!action) {
        mdebug1("Invalid package info query syntax. Missing action");
        mdebug2("DB query error. Missing action");
        snprintf(output, OS_MAXSTR + 1, "err Invalid package info query syntax. Missing action");
        return result;
    }
    else if (strcmp(action, "save") == 0) {
        /* The format of the data is scan_id|scan_time|format|name|priority|section|size|vendor|install_time|version|architecture|multiarch|source|description|location|item_id*/
        #define SAVE_PACKAGE_FIELDS_AMOUNT 16
        char* fields[SAVE_PACKAGE_FIELDS_AMOUNT] = {NULL};
        char* last = NULL;

        for (int i = 0; i < SAVE_PACKAGE_FIELDS_AMOUNT; i++) {
            last = tail;
            if (i < SAVE_PACKAGE_FIELDS_AMOUNT-1) {
                if (next = strchr(tail, '|'), !next) {
                    mdebug1("Invalid package info query syntax.");
                    mdebug2("Package info query: %s", last);
                    snprintf(output, OS_MAXSTR + 1, "err Invalid package info query syntax, near '%.32s'", last);
                    return result;
                }
                *next++ = '\0';
                tail = next;
            }
            if (strcmp(last, "NULL"))
            {
                fields[i] = last;
            }
        }

        /* size (field[6]) must be converted and can be represented as NULL with a string longer than "NULL" */
        long size = OS_INVALID;
        if (fields[6] && strncmp(fields[6], "NULL", 4)) {
            size = strtol(fields[6], NULL, 10);
        }

        if (result = wdb_package_save(wdb, fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], size, fields[7], fields[8], fields[9], fields[10], fields[11], fields[12], fields[13], fields[14], SYSCOLLECTOR_LEGACY_CHECKSUM_VALUE, fields[15], FALSE), result < 0) {
            mdebug1("Cannot save package information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot save package information.");
        } else {
            wdbi_update_attempt(wdb, WDB_SYSCOLLECTOR_PACKAGES, (unsigned)time(NULL), "", "", TRUE);
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;

    }
    else if (strcmp(action, "del") == 0) {
        char* scan_id = NULL;
        if (strcmp(tail, "NULL")) {
            scan_id = tail;
        }

        if (result = wdb_package_update(wdb, scan_id), result < 0) {
            mdebug1("Cannot update scanned packages.");
        }

        if (result = wdb_package_delete(wdb, scan_id), result < 0) {
            mdebug1("Cannot delete old package information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot delete old package information.");
        } else {
            wdbi_update_completion(wdb, WDB_SYSCOLLECTOR_PACKAGES, (unsigned)time(NULL), "", "");
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;

    }
    else if (strcmp(action, "get") == 0) {
        cJSON* status_response = NULL;
        result = wdb_agents_get_packages(wdb, &status_response);
        if (status_response) {
            char *out = cJSON_PrintUnformatted(status_response);
            if (OS_SUCCESS == result) {
                snprintf(output, OS_MAXSTR + 1, "ok %s", out);
            } else {
                snprintf(output, OS_MAXSTR + 1, "err %s", out);
            }
            os_free(out);
            cJSON_Delete(status_response);
        } else {
            mdebug1("Error getting packages from sys_programs");
            snprintf(output, OS_MAXSTR + 1, "err Error getting packages from sys_programs");
        }
        if (OS_SOCKTERR == result) {
            // Close the socket and send nothing as a response
            close(wdb->peer);
            *output = '\0';
        }

        return result;
    }
    else {
        mdebug1("Invalid package info query syntax.");
        mdebug2("DB query error near: %s", input);
        snprintf(output, OS_MAXSTR + 1, "err Invalid package info query syntax, near '%.32s'", input);
        return result;
    }
}

int wdb_parse_hotfixes(wdb_t * wdb, char * input, char * output) {
    int result = OS_INVALID;
    char* next = NULL;
    char* tail = NULL;
    char* action = strtok_r(input, " ", &tail);

    if (!action) {
        mdebug1("Invalid hotfix info query syntax. Missing action");
        mdebug2("DB query error. Missing action");
        snprintf(output, OS_MAXSTR + 1, "err Invalid hotfix info query syntax. Missing action");
        return result;
    }
    else if (strcmp(action, "save") == 0) {
        /* The format of the data is scan_id|scan_time|hotfix */
        #define SAVE_HOTFIX_FIELDS_AMOUNT 3
        char* fields[SAVE_HOTFIX_FIELDS_AMOUNT] = {NULL};
        char* last = tail;

        for (int i = 0; i < SAVE_HOTFIX_FIELDS_AMOUNT; i++) {
            if (!(next = strtok_r(NULL, "|", &tail))) {
                mdebug1("Invalid hotfix info query syntax.");
                mdebug2("Hotfix info query: %s", last);
                snprintf(output, OS_MAXSTR + 1, "err Invalid hotfix info query syntax, near '%.32s'", last);
                return OS_INVALID;
            }
            last = next;
            if (strcmp(next, "NULL"))
            {
                fields[i] = next;
            }
        }

        if (result = wdb_hotfix_save(wdb, fields[0], fields[1], fields[2], SYSCOLLECTOR_LEGACY_CHECKSUM_VALUE, FALSE), result < 0) {
            mdebug1("Cannot save hotfix information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot save hotfix information.");
        } else {
            wdbi_update_attempt(wdb, WDB_SYSCOLLECTOR_HOTFIXES, (unsigned)time(NULL), "", "", TRUE);
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;
    }
    else if (strcmp(action, "del") == 0) {
        char* scan_id = NULL;
        if (strcmp(tail, "NULL")) {
            scan_id = tail;
        }

        if (result = wdb_hotfix_delete(wdb, scan_id), result < 0) {
            mdebug1("Cannot delete old hotfix information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot delete old hotfix information.");
        } else {
            wdbi_update_completion(wdb, WDB_SYSCOLLECTOR_HOTFIXES, (unsigned)time(NULL), "", "");
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;

    }
    else if (strcmp(action, "get") == 0) {
        cJSON* status_response = NULL;
        result = wdb_agents_get_hotfixes(wdb, &status_response);
        if (status_response) {
            char *out = cJSON_PrintUnformatted(status_response);
            if (OS_SUCCESS == result) {
                snprintf(output, OS_MAXSTR + 1, "ok %s", out);
            } else {
                snprintf(output, OS_MAXSTR + 1, "err %s", out);
            }
            os_free(out);
            cJSON_Delete(status_response);
        } else {
            mdebug1("Error getting hotfixes from sys_hotfixes");
            snprintf(output, OS_MAXSTR + 1, "err Error getting hotfixes from sys_hotfixes");
        }
        if (OS_SOCKTERR == result) {
            // Close the socket and send nothing as a response
            close(wdb->peer);
            *output = '\0';
        }

        return result;
    }
    else {
        mdebug1("Invalid hotfix info query syntax.");
        mdebug2("DB query error near: %s", input);
        snprintf(output, OS_MAXSTR + 1, "err Invalid hotfix info query syntax, near '%.32s'", input);
        return result;
    }
}

int wdb_parse_processes(wdb_t * wdb, char * input, char * output) {
    char * curr;
    char * next;
    char * scan_id;
    char * scan_time;
    int pid, ppid, utime, stime, priority, nice, size, vm_size, resident, share, pgrp, session, nlwp, tgid, tty, processor;
    long long start_time;
    char * name;
    char * state;
    char * cmd;
    char * argvs;
    char * euser;
    char * ruser;
    char * suser;
    char * egroup;
    char * rgroup;
    char * sgroup;
    char * fgroup;
    int result;

    if (next = strchr(input, ' '), !next) {
        mdebug1("Invalid Process query syntax.");
        mdebug2("Process query: %s", input);
        snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", input);
        return OS_INVALID;
    }

    curr = input;
    *next++ = '\0';

    if (strcmp(curr, "save") == 0) {
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        scan_id = curr;
        *next++ = '\0';
        curr = next;

        if (!strcmp(scan_id, "NULL"))
            scan_id = NULL;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        scan_time = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %s", scan_time);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", scan_time);
            return OS_INVALID;
        }

        if (!strcmp(scan_time, "NULL"))
            scan_time = NULL;

        if (!strncmp(curr, "NULL", 4))
            pid = OS_INVALID;
        else
            pid = strtol(curr, NULL, 10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %d", pid);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        name = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %s", name);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", name);
            return OS_INVALID;
        }

        if (!strcmp(name, "NULL"))
            name = NULL;

        state = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %s", state);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", state);
            return OS_INVALID;
        }

        if (!strcmp(state, "NULL"))
            state = NULL;

        if (!strncmp(curr, "NULL", 4))
            ppid = OS_INVALID;
        else
            ppid = strtol(curr, NULL, 10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %d", ppid);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        if (!strncmp(curr, "NULL", 4))
            utime = OS_INVALID;
        else
            utime = strtol(curr, NULL, 10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %d", utime);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        if (!strncmp(curr, "NULL", 4))
            stime = OS_INVALID;
        else
            stime = strtol(curr, NULL, 10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %d", stime);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        cmd = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %s", cmd);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", cmd);
            return OS_INVALID;
        }

        if (!strcmp(cmd, "NULL"))
            cmd = NULL;

        argvs = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %s", argvs);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", argvs);
            return OS_INVALID;
        }

        if (!strcmp(argvs, "NULL"))
            argvs = NULL;

        euser = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %s", euser);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", euser);
            return OS_INVALID;
        }

        if (!strcmp(euser, "NULL"))
            euser = NULL;

        ruser = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %s", ruser);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", ruser);
            return OS_INVALID;
        }

        if (!strcmp(ruser, "NULL"))
            ruser = NULL;

        suser = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %s", suser);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", suser);
            return OS_INVALID;
        }

        if (!strcmp(suser, "NULL"))
            suser = NULL;

        egroup = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %s", egroup);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", egroup);
            return OS_INVALID;
        }

        if (!strcmp(egroup, "NULL"))
            egroup = NULL;

        rgroup = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %s", rgroup);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", rgroup);
            return OS_INVALID;
        }

        if (!strcmp(rgroup, "NULL"))
            rgroup = NULL;

        sgroup = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %s", sgroup);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", sgroup);
            return OS_INVALID;
        }

        if (!strcmp(sgroup, "NULL"))
            sgroup = NULL;

        fgroup = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %s", fgroup);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", fgroup);
            return OS_INVALID;
        }

        if (!strcmp(fgroup, "NULL"))
            fgroup = NULL;

        if (!strncmp(curr, "NULL", 4))
            priority = OS_INVALID;
        else
            priority = strtol(curr, NULL, 10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %d", priority);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        if (!strncmp(curr, "NULL", 4))
            nice = 0;
        else
            nice = strtol(curr, NULL, 10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %d", nice);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        if (!strncmp(curr, "NULL", 4))
            size = OS_INVALID;
        else
            size = strtol(curr, NULL, 10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %d", size);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        if (!strncmp(curr, "NULL", 4))
            vm_size = OS_INVALID;
        else
            vm_size = strtol(curr, NULL, 10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %d", vm_size);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        if (!strncmp(curr, "NULL", 4))
            resident = OS_INVALID;
        else
            resident = strtol(curr, NULL, 10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %d", resident);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        if (!strncmp(curr, "NULL", 4))
            share = OS_INVALID;
        else
            share = strtol(curr, NULL, 10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %d", share);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        if (!strncmp(curr, "NULL", 4))
            start_time = OS_INVALID;
        else
            start_time = (long long) strtoull(curr, NULL, 10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %lld", start_time);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        if (!strncmp(curr, "NULL", 4))
            pgrp = OS_INVALID;
        else
            pgrp = strtol(curr, NULL, 10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %d", pgrp);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        if (!strncmp(curr, "NULL", 4))
            session = OS_INVALID;
        else
            session = strtol(curr, NULL, 10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %d", session);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        if (!strncmp(curr, "NULL", 4))
            nlwp = OS_INVALID;
        else
            nlwp = strtol(curr, NULL, 10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %d", nlwp);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        if (!strncmp(curr, "NULL", 4))
            tgid = OS_INVALID;
        else
            tgid = strtol(curr, NULL, 10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid Process query syntax.");
            mdebug2("Process query: %d", tgid);
            snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        if (!strncmp(curr, "NULL", 4))
            tty = OS_INVALID;
        else
            tty = strtol(curr, NULL, 10);

        *next++ = '\0';
        if (!strncmp(next, "NULL", 4))
            processor = OS_INVALID;
        else
            processor = strtol(next, NULL, 10);

        if (result = wdb_process_save(wdb, scan_id, scan_time, pid, name, state, ppid, utime, stime, cmd, argvs, euser, ruser, suser, egroup, rgroup, sgroup, fgroup, priority, nice, size, vm_size, resident, share, start_time, pgrp, session, nlwp, tgid, tty, processor, SYSCOLLECTOR_LEGACY_CHECKSUM_VALUE, FALSE), result < 0) {
            mdebug1("Cannot save Process information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot save Process information.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;
    } else if (strcmp(curr, "del") == 0) {
        if (!strcmp(next, "NULL"))
            scan_id = NULL;
        else
            scan_id = next;

        if (result = wdb_process_delete(wdb, scan_id), result < 0) {
            mdebug1("Cannot delete old Process information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot delete old Process information.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;

    } else {
        mdebug1("Invalid Process query syntax.");
        mdebug2("DB query error near: %s", curr);
        snprintf(output, OS_MAXSTR + 1, "err Invalid Process query syntax, near '%.32s'", curr);
        return OS_INVALID;
    }
}

int wdb_parse_ciscat(wdb_t * wdb, char * input, char * output) {
    char * curr;
    char * next;
    char * scan_id;
    char * scan_time;
    char * benchmark;
    char * profile;
    int pass, fail, error, notchecked, unknown, score;
    int result;

    if (next = strchr(input, ' '), !next) {
        mdebug1("Invalid CISCAT query syntax.");
        mdebug2("CISCAT query: %s", input);
        snprintf(output, OS_MAXSTR + 1, "err Invalid CISCAT query syntax, near '%.32s'", input);
        return OS_INVALID;
    }

    curr = input;
    *next++ = '\0';

    if (strcmp(curr, "save") == 0) {
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid CISCAT query syntax.");
            mdebug2("CISCAT query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid CISCAT query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        scan_id = curr;
        *next++ = '\0';
        curr = next;

        if (!strcmp(scan_id, "NULL"))
            scan_id = NULL;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid CISCAT query syntax.");
            mdebug2("CISCAT query: %s", curr);
            snprintf(output, OS_MAXSTR + 1, "err Invalid CISCAT query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        scan_time = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid CISCAT query syntax.");
            mdebug2("CISCAT query: %s", scan_time);
            snprintf(output, OS_MAXSTR + 1, "err Invalid CISCAT query syntax, near '%.32s'", scan_time);
            return OS_INVALID;
        }

        if (!strcmp(scan_time, "NULL"))
            scan_time = NULL;

        benchmark = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid CISCAT query syntax.");
            mdebug2("CISCAT query: %s", benchmark);
            snprintf(output, OS_MAXSTR + 1, "err Invalid CISCAT query syntax, near '%.32s'", benchmark);
            return OS_INVALID;
        }

        if (!strcmp(benchmark, "NULL"))
            benchmark = NULL;

        profile = curr;
        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid CISCAT query syntax.");
            mdebug2("CISCAT query: %s", profile);
            snprintf(output, OS_MAXSTR + 1, "err Invalid CISCAT query syntax, near '%.32s'", profile);
            return OS_INVALID;
        }

        if (!strcmp(profile, "NULL"))
            profile = NULL;

        if (!strncmp(curr, "NULL", 4))
            pass = OS_INVALID;
        else
            pass = strtol(curr, NULL, 10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid CISCAT query syntax.");
            mdebug2("CISCAT query: %d", pass);
            snprintf(output, OS_MAXSTR + 1, "err Invalid CISCAT query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        if (!strncmp(curr, "NULL", 4))
            fail = OS_INVALID;
        else
            fail = strtol(curr, NULL, 10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid CISCAT query syntax.");
            mdebug2("CISCAT query: %d", fail);
            snprintf(output, OS_MAXSTR + 1, "err Invalid CISCAT query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        if (!strncmp(curr, "NULL", 4))
            error = OS_INVALID;
        else
            error = strtol(curr, NULL, 10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid CISCAT query syntax.");
            mdebug2("CISCAT query: %d", error);
            snprintf(output, OS_MAXSTR + 1, "err Invalid CISCAT query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        if (!strncmp(curr, "NULL", 4))
            notchecked = OS_INVALID;
        else
            notchecked = strtol(curr, NULL, 10);

        *next++ = '\0';
        curr = next;

        if (next = strchr(curr, '|'), !next) {
            mdebug1("Invalid CISCAT query syntax.");
            mdebug2("CISCAT query: %d", notchecked);
            snprintf(output, OS_MAXSTR + 1, "err Invalid CISCAT query syntax, near '%.32s'", curr);
            return OS_INVALID;
        }

        if (!strncmp(curr, "NULL", 4))
            unknown = OS_INVALID;
        else
            unknown = strtol(curr, NULL, 10);

        *next++ = '\0';
        if (!strncmp(next, "NULL", 4))
            score = OS_INVALID;
        else
            score = strtol(next, NULL, 10);

        if (result = wdb_ciscat_save(wdb, scan_id, scan_time, benchmark, profile, pass, fail, error, notchecked, unknown, score), result < 0) {
            mdebug1("Cannot save CISCAT information.");
            snprintf(output, OS_MAXSTR + 1, "err Cannot save CISCAT information.");
        } else {
            snprintf(output, OS_MAXSTR + 1, "ok");
        }

        return result;
    } else {
        mdebug1("Invalid CISCAT query syntax.");
        mdebug2("DB query error near: %s", curr);
        snprintf(output, OS_MAXSTR + 1, "err Invalid CISCAT query syntax, near '%.32s'", curr);
        return OS_INVALID;
    }
}

int wdb_parse_rootcheck(wdb_t * wdb, char * input, char * output) {
    char * curr;
    char * next;
    int result = 0;
    next = wstr_chr(input, ' ');

    if (next) {
        *next++ = '\0';
    }

    curr = input;

    if (strcmp(curr, "delete") == 0) {
        result = wdb_rootcheck_delete(wdb);
        if (result >= 0) {
            snprintf(output, OS_MAXSTR + 1, "ok 0");
            return 0;
        } else {
            snprintf(output, OS_MAXSTR + 1, "err Error deleting rootcheck PM tuple");
            return OS_INVALID;
        }
    } else if (strcmp(curr, "save") == 0) {
        rk_event_t event;

        if (!next) {
            mdebug2("DB(%s) Invalid rootcheck query syntax: %s", wdb->id, input);
            snprintf(output, OS_MAXSTR + 1, "err Invalid rootcheck query syntax, near '%.32s'", input);
            return OS_INVALID;
        }

        char *ptr = wstr_chr(next, ' ');

        if (!ptr) {
            mdebug2("DB(%s) Invalid rootcheck query syntax: %s", wdb->id, input);
            snprintf(output, OS_MAXSTR + 1, "err Invalid rootcheck query syntax, near '%.32s'", input);
            return OS_INVALID;
        }

        *ptr++ = '\0';

        event.date_last = strtol(next, NULL, 10);
        event.date_first = event.date_last;
        event.log = ptr;

        if (event.date_last == LONG_MAX || event.date_last < 0) {
            mdebug2("DB(%s) Invalid rootcheck date timestamp: %li", wdb->id, event.date_last);
            snprintf(output, OS_MAXSTR + 1, "err Invalid rootcheck query syntax, near '%.32s'", input);
            return OS_INVALID;
        }

        switch (wdb_rootcheck_update(wdb, &event)) {
            case OS_INVALID:
                merror("DB(%s) Error updating rootcheck PM tuple on SQLite database", wdb->id);
                snprintf(output, OS_MAXSTR + 1, "err Error updating rootcheck PM tuple");
                result = OS_INVALID;
                break;
            case OS_SUCCESS:
                if (wdb_rootcheck_insert(wdb, &event) < 0) {
                    merror("DB(%s) Error inserting rootcheck PM tuple on SQLite database for agent", wdb->id);
                    snprintf(output, OS_MAXSTR + 1, "err Error updating rootcheck PM tuple");
                    result = OS_INVALID;
                } else {
                    snprintf(output, OS_MAXSTR + 1, "ok 2");
                }
                break;
            default:
                snprintf(output, OS_MAXSTR + 1, "ok 1");
                break;
        }
    } else {
        mdebug2("DB(%s) Invalid rootcheck query syntax: %s", wdb->id, input);
        snprintf(output, OS_MAXSTR + 1, "err Invalid rootcheck query syntax, near '%.32s'", input);
        result = OS_INVALID;
    }
    return result;
}

int wdb_parse_global_insert_agent(wdb_t * wdb, char * input, char * output) {
    cJSON *agent_data = NULL;
    const char *error = NULL;
    cJSON *j_id = NULL;
    cJSON *j_name = NULL;
    cJSON *j_ip = NULL;
    cJSON *j_register_ip = NULL;
    cJSON *j_internal_key = NULL;
    cJSON *j_group = NULL;
    cJSON *j_date_add = NULL;

    agent_data = cJSON_ParseWithOpts(input, &error, TRUE);
    if (!agent_data) {
        mdebug1("Global DB Invalid JSON syntax when inserting agent.");
        mdebug2("Global DB JSON error near: %s", error);
        snprintf(output, OS_MAXSTR + 1, "err Invalid JSON syntax, near '%.32s'", input);
        return OS_INVALID;
    } else {
        j_id = cJSON_GetObjectItem(agent_data, "id");
        j_name = cJSON_GetObjectItem(agent_data, "name");
        j_ip = cJSON_GetObjectItem(agent_data, "ip");
        j_register_ip = cJSON_GetObjectItem(agent_data, "register_ip");
        j_internal_key = cJSON_GetObjectItem(agent_data, "internal_key");
        j_group = cJSON_GetObjectItem(agent_data, "group");
        j_date_add = cJSON_GetObjectItem(agent_data, "date_add");

        // These are the only constraints defined in the database for this
        // set of parameters. All the other parameters could be NULL.
        if (cJSON_IsNumber(j_id) &&
            cJSON_IsString(j_name) && j_name->valuestring &&
            cJSON_IsNumber(j_date_add)) {
            // Getting each field
            int id = j_id->valueint;
            char* name = j_name->valuestring;
            char* ip = cJSON_IsString(j_ip) ? j_ip->valuestring : NULL;
            char* register_ip = cJSON_IsString(j_register_ip) ? j_register_ip->valuestring : NULL;
            char* internal_key = cJSON_IsString(j_internal_key) ? j_internal_key->valuestring : NULL;
            char* group = cJSON_IsString(j_group) ? j_group->valuestring : NULL;
            int date_add = j_date_add->valueint;

            if (OS_SUCCESS != wdb_global_insert_agent(wdb, id, name, ip, register_ip, internal_key, group, date_add)) {
                mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db: %s", WDB2_DIR, WDB_GLOB_NAME, sqlite3_errmsg(wdb->db));
                snprintf(output, OS_MAXSTR + 1, "err Cannot execute Global database query; %s", sqlite3_errmsg(wdb->db));
                cJSON_Delete(agent_data);
                return OS_INVALID;
            }
        } else {
            mdebug1("Global DB Invalid JSON data when inserting agent. Not compliant with constraints defined in the database.");
            snprintf(output, OS_MAXSTR + 1, "err Invalid JSON data, near '%.32s'", input);
            cJSON_Delete(agent_data);
            return OS_INVALID;
        }
    }

    wdb_global_group_hash_cache(WDB_GLOBAL_GROUP_HASH_CLEAR, NULL);

    snprintf(output, OS_MAXSTR + 1, "ok");
    cJSON_Delete(agent_data);

    return OS_SUCCESS;
}

int wdb_parse_global_update_agent_name(wdb_t * wdb, char * input, char * output) {
    cJSON *agent_data = NULL;
    const char *error = NULL;
    cJSON *j_id = NULL;
    cJSON *j_name = NULL;

    agent_data = cJSON_ParseWithOpts(input, &error, TRUE);
    if (!agent_data) {
        mdebug1("Global DB Invalid JSON syntax when updating agent name.");
        mdebug2("Global DB JSON error near: %s", error);
        snprintf(output, OS_MAXSTR + 1, "err Invalid JSON syntax, near '%.32s'", input);
        return OS_INVALID;
    } else {
        j_id = cJSON_GetObjectItem(agent_data, "id");
        j_name = cJSON_GetObjectItem(agent_data, "name");

        if (cJSON_IsNumber(j_id) &&
            cJSON_IsString(j_name) && j_name->valuestring) {
            // Getting each field
            int id = j_id->valueint;
            char* name = j_name->valuestring;

            if (OS_SUCCESS != wdb_global_update_agent_name(wdb, id, name)) {
                mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db: %s", WDB2_DIR, WDB_GLOB_NAME, sqlite3_errmsg(wdb->db));
                snprintf(output, OS_MAXSTR + 1, "err Cannot execute Global database query; %s", sqlite3_errmsg(wdb->db));
                cJSON_Delete(agent_data);
                return OS_INVALID;
            }
        } else {
            mdebug1("Global DB Invalid JSON data when updating agent name.");
            snprintf(output, OS_MAXSTR + 1, "err Invalid JSON data, near '%.32s'", input);
            cJSON_Delete(agent_data);
            return OS_INVALID;
        }
    }

    snprintf(output, OS_MAXSTR + 1, "ok");
    cJSON_Delete(agent_data);

    return OS_SUCCESS;
}

int wdb_parse_global_update_agent_data(wdb_t * wdb, char * input, char * output) {
    cJSON *agent_data = NULL;
    const char *error = NULL;
    cJSON *j_id = NULL;
    cJSON *j_os_name = NULL;
    cJSON *j_os_version = NULL;
    cJSON *j_os_major = NULL;
    cJSON *j_os_minor = NULL;
    cJSON *j_os_codename = NULL;
    cJSON *j_os_platform = NULL;
    cJSON *j_os_build = NULL;
    cJSON *j_os_uname = NULL;
    cJSON *j_os_arch = NULL;
    cJSON *j_version = NULL;
    cJSON *j_config_sum = NULL;
    cJSON *j_merged_sum = NULL;
    cJSON *j_manager_host = NULL;
    cJSON *j_node_name = NULL;
    cJSON *j_agent_ip = NULL;
    cJSON *j_connection_status = NULL;
    cJSON *j_sync_status = NULL;
    cJSON *j_labels = NULL;
    cJSON *j_group_config_status = NULL;

    agent_data = cJSON_ParseWithOpts(input, &error, TRUE);
    if (!agent_data) {
        mdebug1("Global DB Invalid JSON syntax when updating agent version.");
        mdebug2("Global DB JSON error near: %s", error);
        snprintf(output, OS_MAXSTR + 1, "err Invalid JSON syntax, near '%.32s'", input);
        return OS_INVALID;
    } else {
        j_id = cJSON_GetObjectItem(agent_data, "id");
        j_os_name = cJSON_GetObjectItem(agent_data, "os_name");
        j_os_version = cJSON_GetObjectItem(agent_data, "os_version");
        j_os_major = cJSON_GetObjectItem(agent_data, "os_major");
        j_os_minor = cJSON_GetObjectItem(agent_data, "os_minor");
        j_os_codename = cJSON_GetObjectItem(agent_data, "os_codename");
        j_os_platform = cJSON_GetObjectItem(agent_data, "os_platform");
        j_os_build = cJSON_GetObjectItem(agent_data, "os_build");
        j_os_uname = cJSON_GetObjectItem(agent_data, "os_uname");
        j_os_arch = cJSON_GetObjectItem(agent_data, "os_arch");
        j_version = cJSON_GetObjectItem(agent_data, "version");
        j_config_sum = cJSON_GetObjectItem(agent_data, "config_sum");
        j_merged_sum = cJSON_GetObjectItem(agent_data, "merged_sum");
        j_manager_host = cJSON_GetObjectItem(agent_data, "manager_host");
        j_node_name = cJSON_GetObjectItem(agent_data, "node_name");
        j_agent_ip = cJSON_GetObjectItem(agent_data, "agent_ip");
        j_connection_status = cJSON_GetObjectItem(agent_data, "connection_status");
        j_sync_status = cJSON_GetObjectItem(agent_data, "sync_status");
        j_labels = cJSON_GetObjectItem(agent_data, "labels");
        j_group_config_status = cJSON_GetObjectItem(agent_data, "group_config_status");

        if (cJSON_IsNumber(j_id)) {
            // Getting each field
            int id = j_id->valueint;
            char *os_name = cJSON_IsString(j_os_name) ? j_os_name->valuestring : NULL;
            char *os_version = cJSON_IsString(j_os_version) ? j_os_version->valuestring : NULL;
            char *os_major = cJSON_IsString(j_os_major) ? j_os_major->valuestring : NULL;
            char *os_minor = cJSON_IsString(j_os_minor) ? j_os_minor->valuestring : NULL;
            char *os_codename = cJSON_IsString(j_os_codename) ? j_os_codename->valuestring : NULL;
            char *os_platform = cJSON_IsString(j_os_platform) ? j_os_platform->valuestring : NULL;
            char *os_build = cJSON_IsString(j_os_build) ? j_os_build->valuestring : NULL;
            char *os_uname = cJSON_IsString(j_os_uname) ? j_os_uname->valuestring : NULL;
            char *os_arch = cJSON_IsString(j_os_arch) ? j_os_arch->valuestring : NULL;
            char *version = cJSON_IsString(j_version) ? j_version->valuestring : NULL;
            char *config_sum = cJSON_IsString(j_config_sum) ? j_config_sum->valuestring : NULL;
            char *merged_sum = cJSON_IsString(j_merged_sum) ? j_merged_sum->valuestring : NULL;
            char *manager_host = cJSON_IsString(j_manager_host) ? j_manager_host->valuestring : NULL;
            char *node_name = cJSON_IsString(j_node_name) ? j_node_name->valuestring : NULL;
            char *agent_ip = cJSON_IsString(j_agent_ip) ? j_agent_ip->valuestring : NULL;
            char *connection_status = cJSON_IsString(j_connection_status) ? j_connection_status->valuestring : NULL;
            char *sync_status = cJSON_IsString(j_sync_status) ? j_sync_status->valuestring : "synced";
            char *labels = cJSON_IsString(j_labels) ? j_labels->valuestring : NULL;
            char *group_config_status = cJSON_IsString(j_group_config_status) ? j_group_config_status->valuestring : NULL;

            char *validated_sync_status = wdb_global_validate_sync_status(wdb, id, sync_status);

            if (OS_SUCCESS != wdb_global_update_agent_version(wdb, id, os_name, os_version, os_major, os_minor, os_codename,
                                                              os_platform, os_build, os_uname, os_arch, version, config_sum,
                                                              merged_sum, manager_host, node_name, agent_ip, connection_status,
                                                              validated_sync_status, group_config_status)) {
                mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db: %s", WDB2_DIR, WDB_GLOB_NAME, sqlite3_errmsg(wdb->db));
                snprintf(output, OS_MAXSTR + 1, "err Cannot execute Global database query; %s", sqlite3_errmsg(wdb->db));
                cJSON_Delete(agent_data);
                os_free(validated_sync_status);
                return OS_INVALID;
            } else {
                // We will only add the agent's labels if the agent was successfully added to the database.
                // We dont check for NULL because if NULL, the current labels should be removed.
                // The output string will be filled by the labels setter method.
                char *labels_data = NULL;
                os_calloc(OS_MAXSTR, sizeof(char), labels_data);
                snprintf(labels_data, OS_MAXSTR, "%d", id);
                wm_strcat(&labels_data, labels, ' ');

                int result = wdb_parse_global_set_agent_labels(wdb, labels_data, output);

                cJSON_Delete(agent_data);
                os_free(validated_sync_status);
                os_free(labels_data);
                return result;
            }
        } else {
            mdebug1("Global DB Invalid JSON data when updating agent version.");
            snprintf(output, OS_MAXSTR + 1, "err Invalid JSON data, near '%.32s'", input);
            cJSON_Delete(agent_data);
            return OS_INVALID;
        }
    }

    return OS_SUCCESS;
}

int wdb_parse_global_get_agent_labels(wdb_t * wdb, char * input, char * output) {
    int agent_id = 0;
    cJSON *labels = NULL;
    char *out = NULL;

    agent_id = atoi(input);

    if (labels = wdb_global_get_agent_labels(wdb, agent_id), !labels) {
        mdebug1("Error getting agent labels from global.db.");
        snprintf(output, OS_MAXSTR + 1, "err Error getting agent labels from global.db.");
        return OS_INVALID;
    }

    out = cJSON_PrintUnformatted(labels);
    snprintf(output, OS_MAXSTR + 1, "ok %s", out);
    os_free(out);
    cJSON_Delete(labels);

    return OS_SUCCESS;
}

int wdb_parse_global_set_agent_labels(wdb_t * wdb, char * input, char * output) {
    char *id = NULL;
    char *label = NULL;
    char *value = NULL;
    char *savedptr = NULL;
    char id_delim[] = { ' ', '\0' };
    char label_delim[] = { '\n', '\0' };

    // The input could be in the next ways
    // "agent_id key1:value1\nkey2:value2" --> In this, case strtok_r finds a space, so we remove the
    //                                         old labels using the agent_id and then insert the new ones.
    // "agent_id" --> In this, case strtok_r finds the NULL character and we just remove the old
    //                labels using the agent_id. The next strtok_r will finalize the execution.
    if (id = strtok_r(input, id_delim, &savedptr), !id) {
        mdebug1("Invalid DB query syntax.");
        mdebug2("DB query error near: %s", input);
        snprintf(output, OS_MAXSTR + 1, "err Invalid DB query syntax, near '%.32s'", input);
        return OS_INVALID;
    }

    int agent_id = atoi(id);

    // Removing old labels from the labels table
    if (OS_SUCCESS != wdb_global_del_agent_labels(wdb, agent_id)) {
        mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db: %s", WDB2_DIR, WDB_GLOB_NAME, sqlite3_errmsg(wdb->db));
        snprintf(output, OS_MAXSTR + 1, "err Cannot execute Global database query; %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    // Parsing the labes string "key1:value1\nkey2:value2"
    for (label = strtok_r(NULL, label_delim, &savedptr); label; label = strtok_r(NULL, label_delim, &savedptr)) {
        if (value = strstr(label, ":"), value) {
            *value = '\0';
            value++;
        } else {
            continue;
        }

        // Inserting new labels in the database
        if (OS_SUCCESS != wdb_global_set_agent_label(wdb, agent_id, label, value)) {
            mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db: %s", WDB2_DIR, WDB_GLOB_NAME, sqlite3_errmsg(wdb->db));
            snprintf(output, OS_MAXSTR + 1, "err Cannot execute Global database query; %s", sqlite3_errmsg(wdb->db));
            return OS_INVALID;
        }

        value = NULL;
    }

    snprintf(output, OS_MAXSTR + 1, "ok");

    return OS_SUCCESS;
}

int wdb_parse_global_update_agent_keepalive(wdb_t * wdb, char * input, char * output) {
    cJSON *agent_data = NULL;
    const char *error = NULL;
    cJSON *j_id = NULL;
    cJSON *j_connection_status = NULL;
    cJSON *j_sync_status = NULL;

    agent_data = cJSON_ParseWithOpts(input, &error, TRUE);
    if (!agent_data) {
        mdebug1("Global DB Invalid JSON syntax when updating agent keepalive.");
        mdebug2("Global DB JSON error near: %s", error);
        snprintf(output, OS_MAXSTR + 1, "err Invalid JSON syntax, near '%.32s'", input);
        return OS_INVALID;
    } else {
        j_id = cJSON_GetObjectItem(agent_data, "id");
        j_connection_status = cJSON_GetObjectItem(agent_data, "connection_status");
        j_sync_status = cJSON_GetObjectItem(agent_data, "sync_status");

        if (cJSON_IsNumber(j_id) && cJSON_IsString(j_connection_status) && cJSON_IsString(j_sync_status)) {
            // Getting each field
            int id = j_id->valueint;
            char *connection_status = j_connection_status->valuestring;
            char *sync_status = j_sync_status->valuestring;

            char *validated_sync_status = wdb_global_validate_sync_status(wdb, id, sync_status);

            if (OS_SUCCESS != wdb_global_update_agent_keepalive(wdb, id, connection_status, validated_sync_status)) {
                mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db: %s", WDB2_DIR, WDB_GLOB_NAME, sqlite3_errmsg(wdb->db));
                snprintf(output, OS_MAXSTR + 1, "err Cannot execute Global database query; %s", sqlite3_errmsg(wdb->db));
                cJSON_Delete(agent_data);
                os_free(validated_sync_status);
                return OS_INVALID;
            }

            os_free(validated_sync_status);
        } else {
            mdebug1("Global DB Invalid JSON data when updating agent keepalive.");
            snprintf(output, OS_MAXSTR + 1, "err Invalid JSON data, near '%.32s'", input);
            cJSON_Delete(agent_data);
            return OS_INVALID;
        }
    }

    snprintf(output, OS_MAXSTR + 1, "ok");
    cJSON_Delete(agent_data);

    return OS_SUCCESS;
}

int wdb_parse_global_update_connection_status(wdb_t * wdb, char * input, char * output) {
    cJSON *agent_data = NULL;
    const char *error = NULL;
    cJSON *j_id = NULL;
    cJSON *j_connection_status = NULL;
    cJSON *j_sync_status = NULL;
    cJSON *j_status_code = NULL;

    agent_data = cJSON_ParseWithOpts(input, &error, TRUE);
    if (!agent_data) {
        mdebug1("Global DB Invalid JSON syntax when updating agent connection status.");
        mdebug2("Global DB JSON error near: %s", error);
        snprintf(output, OS_MAXSTR + 1, "err Invalid JSON syntax, near '%.32s'", input);
        return OS_INVALID;
    } else {
        j_id = cJSON_GetObjectItem(agent_data, "id");
        j_connection_status = cJSON_GetObjectItem(agent_data, "connection_status");
        j_sync_status = cJSON_GetObjectItem(agent_data, "sync_status");
        j_status_code = cJSON_GetObjectItem(agent_data, "status_code");

        if (cJSON_IsNumber(j_id) && cJSON_IsString(j_connection_status) && cJSON_IsString(j_sync_status) && cJSON_IsNumber(j_status_code)) {
            // Getting each field
            int id = j_id->valueint;
            char *connection_status = j_connection_status->valuestring;
            char *sync_status = j_sync_status->valuestring;
            int status_code = j_status_code->valueint;

            char *validated_sync_status = wdb_global_validate_sync_status(wdb, id, sync_status);

            if (OS_SUCCESS != wdb_global_update_agent_connection_status(wdb, id, connection_status, validated_sync_status, status_code)) {
                mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db: %s", WDB2_DIR, WDB_GLOB_NAME, sqlite3_errmsg(wdb->db));
                snprintf(output, OS_MAXSTR + 1, "err Cannot execute Global database query; %s", sqlite3_errmsg(wdb->db));
                cJSON_Delete(agent_data);
                os_free(validated_sync_status);
                return OS_INVALID;
            }

            os_free(validated_sync_status);
        } else {
            mdebug1("Global DB Invalid JSON data when updating agent connection status.");
            snprintf(output, OS_MAXSTR + 1, "err Invalid JSON data, near '%.32s'", input);
            cJSON_Delete(agent_data);
            return OS_INVALID;
        }
    }

    snprintf(output, OS_MAXSTR + 1, "ok");
    cJSON_Delete(agent_data);

    return OS_SUCCESS;
}

int wdb_parse_global_update_status_code(wdb_t * wdb, char * input, char * output) {
    cJSON *agent_data = NULL;
    const char *error = NULL;
    cJSON *j_id = NULL;
    cJSON *j_status_code = NULL;
    cJSON *j_version = NULL;
    cJSON *j_sync_status = NULL;

    agent_data = cJSON_ParseWithOpts(input, &error, TRUE);
    if (!agent_data) {
        mdebug1("Global DB Invalid JSON syntax when updating agent status code.");
        mdebug2("Global DB JSON error near: %s", error);
        snprintf(output, OS_MAXSTR + 1, "err Invalid JSON syntax, near '%.32s'", input);
        return OS_INVALID;
    } else {
        j_id = cJSON_GetObjectItem(agent_data, "id");
        j_status_code = cJSON_GetObjectItem(agent_data, "status_code");
        j_version = cJSON_GetObjectItem(agent_data, "version");
        j_sync_status = cJSON_GetObjectItem(agent_data, "sync_status");

        if (cJSON_IsNumber(j_id) && cJSON_IsNumber(j_status_code) && (j_version == NULL || cJSON_IsString(j_version)) && cJSON_IsString(j_sync_status)) {
            // Getting each field
            int id = j_id->valueint;
            int status_code = j_status_code->valueint;
            char *version = NULL;
            if (j_version != NULL) {
                version = j_version->valuestring;
            }
            char *sync_status = j_sync_status->valuestring;

            char *validated_sync_status = wdb_global_validate_sync_status(wdb, id, sync_status);

            if (OS_SUCCESS != wdb_global_update_agent_status_code(wdb, id, status_code, version, validated_sync_status)) {
                mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db: %s", WDB2_DIR, WDB_GLOB_NAME, sqlite3_errmsg(wdb->db));
                snprintf(output, OS_MAXSTR + 1, "err Cannot execute Global database query; %s", sqlite3_errmsg(wdb->db));
                cJSON_Delete(agent_data);
                os_free(validated_sync_status);
                return OS_INVALID;
            }

            os_free(validated_sync_status);
        } else {
            mdebug1("Global DB Invalid JSON data when updating agent status code.");
            snprintf(output, OS_MAXSTR + 1, "err Invalid JSON data, near '%.32s'", input);
            cJSON_Delete(agent_data);
            return OS_INVALID;
        }
    }

    snprintf(output, OS_MAXSTR + 1, "ok");
    cJSON_Delete(agent_data);

    return OS_SUCCESS;
}

int wdb_parse_global_delete_agent(wdb_t * wdb, char * input, char * output) {
    int agent_id = 0;

    agent_id = atoi(input);
    char padded_agent_id[AGENT_ID_LEN];
    snprintf(padded_agent_id, sizeof(padded_agent_id), "%03d", agent_id);

    if (OS_SUCCESS != wdb_global_delete_agent(wdb, agent_id)) {
        mdebug1("Error deleting agent from agent table in global.db.");
        snprintf(output, OS_MAXSTR + 1, "err Error deleting agent from agent table in global.db.");
        return OS_INVALID;
    }

    if (router_agent_events_handle) {
        cJSON* j_msg_to_send = NULL;
        cJSON* j_agent_info = NULL;
        char* msg_to_send = NULL;

        j_msg_to_send = cJSON_CreateObject();
        j_agent_info = cJSON_CreateObject();


        cJSON_AddStringToObject(j_agent_info, "agent_id", padded_agent_id);
        cJSON_AddItemToObject(j_msg_to_send, "agent_info", j_agent_info);

        cJSON_AddStringToObject(j_msg_to_send, "action", "deleteAgent");

        msg_to_send = cJSON_PrintUnformatted(j_msg_to_send);

        if (msg_to_send) {
            router_provider_send(router_agent_events_handle, msg_to_send, strlen(msg_to_send));
        } else {
            mdebug2("Unable to dump agent db upgrade message to publish. Agent %s", wdb->id);
        }

        cJSON_Delete(j_msg_to_send);
        cJSON_free(msg_to_send);
    }


    wdb_global_group_hash_cache(WDB_GLOBAL_GROUP_HASH_CLEAR, NULL);

    snprintf(output, OS_MAXSTR + 1, "ok");

    return OS_SUCCESS;
}

int wdb_parse_global_select_agent_name(wdb_t * wdb, char * input, char * output) {
    int agent_id = 0;
    cJSON *name = NULL;
    char *out = NULL;

    agent_id = atoi(input);

    if (name = wdb_global_select_agent_name(wdb, agent_id), !name) {
        mdebug1("Error getting agent name from global.db.");
        snprintf(output, OS_MAXSTR + 1, "err Error getting agent name from global.db.");
        return OS_INVALID;
    }

    out = cJSON_PrintUnformatted(name);
    snprintf(output, OS_MAXSTR + 1, "ok %s", out);
    os_free(out);
    cJSON_Delete(name);

    return OS_SUCCESS;
}

int wdb_parse_global_select_agent_group(wdb_t * wdb, char * input, char * output) {
    int agent_id = 0;
    cJSON *name = NULL;
    char *out = NULL;

    agent_id = atoi(input);

    if (name = wdb_global_select_agent_group(wdb, agent_id), !name) {
        mdebug1("Error getting agent group from global.db.");
        snprintf(output, OS_MAXSTR + 1, "err Error getting agent group from global.db.");
        return OS_INVALID;
    }

    out = cJSON_PrintUnformatted(name);
    snprintf(output, OS_MAXSTR + 1, "ok %s", out);
    os_free(out);
    cJSON_Delete(name);

    return OS_SUCCESS;
}

int wdb_parse_global_find_agent(wdb_t * wdb, char * input, char * output) {
    cJSON *agent_data = NULL;
    const char *error = NULL;
    cJSON *j_name = NULL;
    cJSON *j_ip = NULL;
    cJSON *j_id = NULL;
    char *out = NULL;

    agent_data = cJSON_ParseWithOpts(input, &error, TRUE);
    if (!agent_data) {
        mdebug1("Global DB Invalid JSON syntax when finding agent id.");
        mdebug2("Global DB JSON error near: %s", error);
        snprintf(output, OS_MAXSTR + 1, "err Invalid JSON syntax, near '%.32s'", input);
        return OS_INVALID;
    } else {
        j_name = cJSON_GetObjectItem(agent_data, "name");
        j_ip = cJSON_GetObjectItem(agent_data, "ip");

        if (cJSON_IsString(j_name) && cJSON_IsString(j_ip)) {
            // Getting each field
            char *name = j_name->valuestring;
            char *ip = j_ip->valuestring;

            if (j_id = wdb_global_find_agent(wdb, name, ip), !j_id) {
                mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db: %s", WDB2_DIR, WDB_GLOB_NAME, sqlite3_errmsg(wdb->db));
                snprintf(output, OS_MAXSTR + 1, "err Cannot execute Global database query; %s", sqlite3_errmsg(wdb->db));
                cJSON_Delete(agent_data);
                return OS_INVALID;
            }
        } else {
            mdebug1("Global DB Invalid JSON data when finding agent id.");
            snprintf(output, OS_MAXSTR + 1, "err Invalid JSON data, near '%.32s'", input);
            cJSON_Delete(agent_data);
            return OS_INVALID;
        }
    }

    out = cJSON_PrintUnformatted(j_id);
    snprintf(output, OS_MAXSTR + 1, "ok %s", out);
    os_free(out);
    cJSON_Delete(j_id);
    cJSON_Delete(agent_data);

    return OS_SUCCESS;
}

int wdb_parse_global_find_group(wdb_t * wdb, char * input, char * output) {
    char *group_name = NULL;
    cJSON *group_id = NULL;
    char *out = NULL;

    group_name = input;

    if (group_id = wdb_global_find_group(wdb, group_name), !group_id) {
        mdebug1("Error getting group id from global.db.");
        snprintf(output, OS_MAXSTR + 1, "err Error getting group id from global.db.");
        return OS_INVALID;
    }

    out = cJSON_PrintUnformatted(group_id);
    snprintf(output, OS_MAXSTR + 1, "ok %s", out);
    os_free(out);
    cJSON_Delete(group_id);

    return OS_SUCCESS;
}

int wdb_parse_global_insert_agent_group(wdb_t * wdb, char * input, char * output) {
    char *group_name = NULL;

    group_name = input;

    if (OS_SUCCESS != wdb_global_insert_agent_group(wdb, group_name)) {
        mdebug1("Error inserting group in global.db.");
        snprintf(output, OS_MAXSTR + 1, "err Error inserting group in global.db.");
        return OS_INVALID;
    }

    snprintf(output, OS_MAXSTR + 1, "ok");

    return OS_SUCCESS;
}

int wdb_parse_global_select_group_belong(wdb_t *wdb, char *input, char *output) {
    int agent_id = atoi(input);
    cJSON *agent_groups = NULL;

    if (agent_groups = wdb_global_select_group_belong(wdb, agent_id), !agent_groups) {
        mdebug1("Error getting agent groups information from global.db.");
        snprintf(output, OS_MAXSTR + 1, "err Error getting agent groups information from global.db.");
        return OS_INVALID;
    }

    char *out = NULL;
    out = cJSON_PrintUnformatted(agent_groups);
    snprintf(output, OS_MAXSTR + 1, "ok %s", out);
    os_free(out);
    cJSON_Delete(agent_groups);

    return OS_SUCCESS;
}

int wdb_parse_global_get_group_agents(wdb_t* wdb, char* input, char* output) {
    int last_agent_id = 0;
    char *next = NULL;
    const char delim[2] = " ";
    char *savedptr = NULL;
    char *group_name = NULL;

    /* Get group name */
    next = strtok_r(input, delim, &savedptr);
    if (next == NULL) {
        mdebug1("Invalid arguments, group name not found.");
        snprintf(output, OS_MAXSTR + 1, "err Invalid arguments, group name not found.");
        return OS_INVALID;
    }
    group_name = next;

    /* Get last_id */
    next = strtok_r(NULL, delim, &savedptr);
    if (next == NULL || strcmp(next, "last_id") != 0) {
        mdebug1("Invalid arguments, 'last_id' not found.");
        snprintf(output, OS_MAXSTR + 1, "err Invalid arguments, 'last_id' not found.");
        return OS_INVALID;
    }
    next = strtok_r(NULL, delim, &savedptr);
    if (next == NULL) {
        mdebug1("Invalid arguments, last agent id not found.");
        snprintf(output, OS_MAXSTR + 1, "err Invalid arguments, last agent id not found.");
        return OS_INVALID;
    }
    last_agent_id = atoi(next);

    // Execute command
    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_group_agents(wdb, &status, group_name, last_agent_id);
    if (!result) {
        mdebug1("Error getting group agents from global.db.");
        snprintf(output, OS_MAXSTR + 1, "err Error getting group agents from global.db.");
        return OS_INVALID;
    }

    //Print response
    char* out = cJSON_PrintUnformatted(result);
    snprintf(output, OS_MAXSTR + 1, "%s %s",  WDBC_RESULT[status], out);

    cJSON_Delete(result);
    os_free(out)

    return OS_SUCCESS;
}

int wdb_parse_global_delete_group(wdb_t * wdb, char * input, char * output) {
    char *group_name = NULL;

    group_name = input;

    if (OS_SUCCESS != wdb_global_delete_group(wdb, group_name)) {
        mdebug1("Error deleting group in global.db.");
        snprintf(output, OS_MAXSTR + 1, "err Error deleting group in global.db.");
        return OS_INVALID;
    }

    snprintf(output, OS_MAXSTR + 1, "ok");

    return OS_SUCCESS;
}

int wdb_parse_global_select_groups(wdb_t * wdb, char * output) {
    cJSON *groups = NULL;
    char *out = NULL;

    if (groups = wdb_global_select_groups(wdb), !groups) {
        mdebug1("Error getting groups from global.db.");
        snprintf(output, OS_MAXSTR + 1, "err Error getting groups from global.db.");
        return OS_INVALID;
    }

    out = cJSON_PrintUnformatted(groups);
    snprintf(output, OS_MAXSTR + 1, "ok %s", out);
    os_free(out);
    cJSON_Delete(groups);

    return OS_SUCCESS;
}

int wdb_parse_global_set_agent_groups(wdb_t* wdb, char* input, char* output) {
    int ret = OS_SUCCESS;
    const char *error = NULL;
    cJSON *args = cJSON_ParseWithOpts(input, &error, TRUE);
    if (args) {
        cJSON *j_mode = cJSON_GetObjectItem(args, "mode");
        cJSON *j_sync_status = cJSON_GetObjectItem(args, "sync_status");
        cJSON *j_groups_data = cJSON_GetObjectItem(args, "data");

        // Mandatory fields
        if (cJSON_IsArray(j_groups_data) && cJSON_IsString(j_mode)) {
            wdb_groups_set_mode_t mode = WDB_GROUP_INVALID_MODE;
            char* sync_status = "synced";
            if (0 == strcmp(j_mode->valuestring, "override")) {
                mode = WDB_GROUP_OVERRIDE;
            } else if (0 == strcmp(j_mode->valuestring, "append")) {
                mode = WDB_GROUP_APPEND;
            } else if (0 == strcmp(j_mode->valuestring, "empty_only")) {
                mode = WDB_GROUP_EMPTY_ONLY;
            } else if (0 == strcmp(j_mode->valuestring, "remove")) {
                mode = WDB_GROUP_REMOVE;
            }

            if (WDB_GROUP_INVALID_MODE != mode) {
                if (cJSON_IsString(j_sync_status)) {
                    sync_status = j_sync_status->valuestring;
                }

                wdbc_result status = wdb_global_set_agent_groups(wdb, mode, sync_status, j_groups_data);
                if (status == WDBC_OK) {
                    snprintf(output, OS_MAXSTR + 1, "%s",  WDBC_RESULT[status]);
                } else {
                    snprintf(output, OS_MAXSTR + 1, "%s An error occurred during the set of the groups",  WDBC_RESULT[status]);
                    ret = OS_INVALID;
                }
            } else {
                mdebug1("Invalid mode '%s' in set_agent_groups command.", j_mode->valuestring);
                snprintf(output, OS_MAXSTR + 1, "err Invalid mode '%s' in set_agent_groups command", j_mode->valuestring);
                ret = OS_INVALID;
            }
        } else {
            mdebug1("Missing mandatory fields in set_agent_groups command.");
            snprintf(output, OS_MAXSTR + 1, "err Invalid JSON data, missing required fields");
            ret = OS_INVALID;
        }
        cJSON_Delete(args);
    } else {
        mdebug1("Global DB Invalid JSON syntax when parsing set_agent_groups");
        mdebug2("Global DB JSON error near: %s", error);
        snprintf(output, OS_MAXSTR + 1, "err Invalid JSON syntax, near '%.32s'", input);
        ret = OS_INVALID;
    }

    return ret;
}

int wdb_parse_global_sync_agent_groups_get(wdb_t* wdb, char* input, char* output) {
    int ret = OS_SUCCESS;
    const char *error = NULL;
    cJSON *args = cJSON_ParseWithOpts(input, &error, TRUE);
    if (args) {
        cJSON *j_sync_condition = cJSON_GetObjectItem(args, "condition");
        cJSON *j_last_id = cJSON_GetObjectItem(args, "last_id");
        cJSON *j_set_synced = cJSON_GetObjectItem(args, "set_synced");
        cJSON *j_get_hash = cJSON_GetObjectItem(args, "get_global_hash");
        cJSON *j_agent_registration_delta = cJSON_GetObjectItem(args, "agent_registration_delta");

        // Checking data types of alternative parameters in case they would have been sent in the input JSON.
        if ((j_sync_condition && !cJSON_IsString(j_sync_condition)) ||
            (j_last_id && (!cJSON_IsNumber(j_last_id) || j_last_id->valueint < 0)) ||
            (j_set_synced && !cJSON_IsBool(j_set_synced)) ||
            (j_get_hash && !cJSON_IsBool(j_get_hash)) ||
            (j_agent_registration_delta && (!cJSON_IsNumber(j_agent_registration_delta) || j_agent_registration_delta->valueint < 0))) {
            mdebug1("Invalid alternative fields data in sync-agent-groups-get command.");
            snprintf(output, OS_MAXSTR + 1, "err Invalid JSON data, invalid alternative fields data");
            ret = OS_INVALID;
        } else {
            wdb_groups_sync_condition_t condition = WDB_GROUP_NO_CONDITION;
            int last_id = 0;
            bool set_synced = false;
            bool get_hash = false;
            int agent_registration_delta = 0;

            if (j_sync_condition && 0 == strcmp(j_sync_condition->valuestring, "sync_status")) {
                condition = WDB_GROUP_SYNC_STATUS;
            } else if (j_sync_condition && 0 == strcmp(j_sync_condition->valuestring, "all")) {
                condition = WDB_GROUP_ALL;
            } else if (j_sync_condition) {
                condition = WDB_GROUP_INVALID_CONDITION;
            }
            if (j_last_id) {
                last_id = j_last_id->valueint;
            }
            if (cJSON_IsTrue(j_set_synced)) {
                set_synced = true;
            }
            if (cJSON_IsTrue(j_get_hash)) {
                get_hash = true;
            }
            if (j_agent_registration_delta) {
                agent_registration_delta = j_agent_registration_delta->valueint;
            }

            cJSON* agent_group_sync = NULL;
            wdbc_result status = wdb_global_sync_agent_groups_get(wdb, condition, last_id, set_synced, get_hash, agent_registration_delta, &agent_group_sync);
            if (agent_group_sync) {
                char* response = cJSON_PrintUnformatted(agent_group_sync);
                cJSON_Delete(agent_group_sync);
                if (strlen(response) <= WDB_MAX_RESPONSE_SIZE) {
                    snprintf(output, OS_MAXSTR + 1, "%s %s", WDBC_RESULT[status], response);
                } else {
                    snprintf(output, OS_MAXSTR + 1, "err %s", "Invalid response from wdb_global_sync_agent_groups_get");
                    ret = OS_INVALID;
                }
                os_free(response);
            } else {
                snprintf(output, OS_MAXSTR + 1, "err %s", "Could not obtain a response from wdb_global_sync_agent_groups_get");
                ret = OS_INVALID;
            }
        }
        cJSON_Delete(args);
    } else {
        mdebug1("Global DB Invalid JSON syntax when parsing sync-agent-groups-get");
        mdebug2("Global DB JSON error near: %s", error);
        snprintf(output, OS_MAXSTR + 1, "err Invalid JSON syntax, near '%.32s'", input);
        ret = OS_INVALID;
    }

    return ret;
}

int wdb_parse_global_sync_agent_info_get(wdb_t* wdb, char* input, char* output) {
    static int last_id = 0;
    char* agent_info_sync = NULL;

    if (input) {
        char *next = wstr_chr(input, ' ');
        if (next) {
            *next++ = '\0';
            if (strcmp(input, "last_id") == 0) {
                last_id = atoi(next);
            }
        }
    }

    wdbc_result status = wdb_global_sync_agent_info_get(wdb, &last_id, &agent_info_sync);
    snprintf(output, OS_MAXSTR + 1, "%s %s",  WDBC_RESULT[status], agent_info_sync);
    os_free(agent_info_sync)
    if (status != WDBC_DUE) {
        last_id = 0;
    }

    return OS_SUCCESS;
}

int wdb_parse_global_sync_agent_info_set(wdb_t * wdb, char * input, char * output) {
    const char *error = NULL;
    int agent_id = 0;
    cJSON *root = NULL;
    cJSON *json_agent = NULL;
    cJSON *json_field = NULL;
    cJSON *json_label = NULL;
    cJSON *json_labels = NULL;
    cJSON *json_key = NULL;
    cJSON *json_value = NULL;
    cJSON *json_id = NULL;

    /*
    * The cJSON_GetErrorPtr() method is not thread safe, using cJSON_ParseWithOpts() instead,
    * error indicates where the string caused an error.
    * The third arguments is TRUE and it will give an error if the input string
    * contains data after the JSON command
    */
    root = cJSON_ParseWithOpts(input, &error, TRUE);
    if (!root) {
        mdebug1("Global DB Invalid JSON syntax updating unsynced agents.");
        mdebug2("Global DB JSON error near: %s", error);
        snprintf(output, OS_MAXSTR + 1, "err Invalid JSON syntax, near '%.32s'", input);
        return OS_INVALID;

    } else {
        cJSON_ArrayForEach(json_agent, root) {
            // Inserting new agent information in the database
            if (OS_SUCCESS != wdb_global_sync_agent_info_set(wdb, json_agent)) {
                mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db: %s", WDB2_DIR, WDB_GLOB_NAME, sqlite3_errmsg(wdb->db));
                snprintf(output, OS_MAXSTR + 1, "err Cannot execute Global database query; %s", sqlite3_errmsg(wdb->db));
                cJSON_Delete(root);
                return OS_INVALID;
            }
            // Checking for labels
            json_labels = cJSON_GetObjectItem(json_agent, "labels");
            if (cJSON_IsArray(json_labels)) {
                // The JSON has a label array
                // Removing old labels from the labels table before inserting
                json_field = cJSON_GetObjectItem(json_agent, "id");
                agent_id = cJSON_IsNumber(json_field) ? json_field->valueint : OS_INVALID;

                if (agent_id == OS_INVALID) {
                    mdebug1("Global DB Cannot execute SQL query; incorrect agent id in labels array.");
                    snprintf(output, OS_MAXSTR + 1, "err Cannot update labels due to invalid id.");
                    cJSON_Delete(root);
                    return OS_INVALID;
                }

                else if (OS_SUCCESS != wdb_global_del_agent_labels(wdb, agent_id)) {
                    mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db: %s", WDB2_DIR, WDB_GLOB_NAME, sqlite3_errmsg(wdb->db));
                    snprintf(output, OS_MAXSTR + 1, "err Cannot execute Global database query; %s", sqlite3_errmsg(wdb->db));
                    cJSON_Delete(root);
                    return OS_INVALID;
                }
                // For every label in array, insert it in the database
                cJSON_ArrayForEach(json_label, json_labels) {
                    json_key = cJSON_GetObjectItem(json_label, "key");
                    json_value = cJSON_GetObjectItem(json_label, "value");
                    json_id = cJSON_GetObjectItem(json_label, "id");

                    if (cJSON_IsString(json_key) && json_key->valuestring != NULL && cJSON_IsString(json_value) &&
                        json_value->valuestring != NULL && cJSON_IsNumber(json_id)) {
                        // Inserting labels in the database
                        if (OS_SUCCESS != wdb_global_set_agent_label(wdb, json_id->valueint, json_key->valuestring, json_value->valuestring)) {
                            mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db: %s", WDB2_DIR, WDB_GLOB_NAME, sqlite3_errmsg(wdb->db));
                            snprintf(output, OS_MAXSTR + 1, "err Cannot execute Global database query; %s", sqlite3_errmsg(wdb->db));
                            cJSON_Delete(root);
                            return OS_INVALID;
                        }
                    }
                }
            }
        }
    }

    snprintf(output, OS_MAXSTR + 1, "ok");
    cJSON_Delete(root);

    return OS_SUCCESS;
}

int wdb_parse_get_groups_integrity(wdb_t* wdb, char* input, char* output) {
    int input_len = strlen(input);
    if (input_len < OS_SHA1_HEXDIGEST_SIZE) {
        mdebug1("Hash hex-digest does not have the expected length. Expected (%d) got (%d)",
                OS_SHA1_HEXDIGEST_SIZE,
                input_len);
        snprintf(output,
                 OS_MAXSTR + 1,
                 "err Hash hex-digest does not have the expected length. Expected (%d) got (%d)",
                 OS_SHA1_HEXDIGEST_SIZE,
                 input_len);
        return OS_INVALID;
    }

    os_sha1 hash = {0};
    strncpy(hash, input, OS_SHA1_HEXDIGEST_SIZE);

    cJSON *j_result = wdb_global_get_groups_integrity(wdb, hash);
    if (j_result == NULL) {
        mdebug1("Error getting groups integrity information from global.db.");
        snprintf(output, OS_MAXSTR + 1, "err Error getting groups integrity information from global.db.");
        return OS_INVALID;
    }

    char* out = cJSON_PrintUnformatted(j_result);
    snprintf(output, OS_MAXSTR + 1, "ok %s", out);
    os_free(out);
    cJSON_Delete(j_result);
    return OS_SUCCESS;
}

int wdb_parse_global_recalculate_agent_group_hashes(wdb_t* wdb, char* output) {

    if (OS_SUCCESS != wdb_global_recalculate_all_agent_groups_hash(wdb)) {
        mwarn("Error recalculating group hash of agents in global.db.");
        snprintf(output, OS_MAXSTR + 1, "err Error recalculating group hash of agents in global.db");
        return OS_INVALID;
    }

    snprintf(output, OS_MAXSTR + 1, "ok");

    return OS_SUCCESS;
}

int wdb_parse_global_get_agent_info(wdb_t* wdb, char* input, char* output) {
    int agent_id = 0;
    cJSON *agent_info = NULL;
    char *out = NULL;

    agent_id = atoi(input);

    if (agent_info = wdb_global_get_agent_info(wdb, agent_id), !agent_info) {
        mdebug1("Error getting agent information from global.db.");
        snprintf(output, OS_MAXSTR + 1, "err Error getting agent information from global.db.");
        return OS_INVALID;
    }

    out = cJSON_PrintUnformatted(agent_info);
    snprintf(output, OS_MAXSTR + 1, "ok %s", out);
    os_free(out);
    cJSON_Delete(agent_info);

    return OS_SUCCESS;
}

int wdb_parse_global_get_agents_by_connection_status(wdb_t* wdb, char* input, char* output) {
    int last_id = 0;
    int limit = 0;
    char *connection_status = NULL;
    char *node_name = NULL;
    char *next = NULL;
    const char delim[2] = " ";
    char *savedptr = NULL;

    /* Get last_id*/
    next = strtok_r(input, delim, &savedptr);
    if (next == NULL) {
        mdebug1("Invalid arguments 'last_id' not found.");
        snprintf(output, OS_MAXSTR + 1, "err Invalid arguments 'last_id' not found");
        return OS_INVALID;
    }
    last_id = atoi(next);
    /* Get connection status */
    next = strtok_r(NULL, delim, &savedptr);
    if (next == NULL) {
        mdebug1("Invalid arguments 'connection_status' not found.");
        snprintf(output, OS_MAXSTR + 1, "err Invalid arguments 'connection_status' not found");
        return OS_INVALID;
    }
    connection_status = next;

    /* Get node name */
    next = strtok_r(NULL, delim, &savedptr);
    if (next != NULL) {
        node_name = next;

        /* Get limit */
        next = strtok_r(NULL, delim, &savedptr);
        if (next == NULL) {
            mdebug1("Invalid arguments 'limit' not found.");
            snprintf(output, OS_MAXSTR + 1, "err Invalid arguments 'limit' not found");
            return OS_INVALID;
        }
        limit = atoi(next);
    }

    // Execute command
    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_agents_by_connection_status(wdb, last_id, connection_status, node_name, limit, &status);
    if (!result) {
        mdebug1("Error getting agents by connection status from global.db.");
        snprintf(output, OS_MAXSTR + 1, "err Error getting agents by connection status from global.db.");
        return OS_INVALID;
    }

    //Print response
    char* out = cJSON_PrintUnformatted(result);
    snprintf(output, OS_MAXSTR + 1, "%s %s",  WDBC_RESULT[status], out);

    cJSON_Delete(result);
    os_free(out)

    return OS_SUCCESS;
}

int wdb_parse_global_get_all_agents(wdb_t* wdb, char* input, char* output) {
    int last_id = 0;
    char *next = NULL;
    const char delim[2] = " ";
    char *savedptr = NULL;

    /* Check if is last_id or context */
    next = strtok_r(input, delim, &savedptr);
    if (next == NULL || (strcmp(next, "last_id") != 0 && strcmp(next, "context") != 0)) {
        mdebug1("Invalid arguments 'last_id' or 'context' not found.");
        snprintf(output, OS_MAXSTR + 1, "err Invalid arguments 'last_id' or 'context' not found");
        return OS_INVALID;
    }

    if (strcmp(next, "context") == 0) {
        int status = wdb_global_get_all_agents_context(wdb);
        if (status != OS_SUCCESS) {
            snprintf(output, OS_MAXSTR + 1, "err Error getting agents from global.db.");
        }
        else {
            snprintf(output, OS_MAXSTR + 1, "ok []");
        }
        return status;
    }
    else {
        next = strtok_r(NULL, delim, &savedptr);
        if (next == NULL) {
            mdebug1("Invalid arguments 'last_id' not found.");
            snprintf(output, OS_MAXSTR + 1, "err Invalid arguments 'last_id' not found");
            return OS_INVALID;
        }
        last_id = atoi(next);

        // Execute command
        wdbc_result status = WDBC_UNKNOWN;
        cJSON* result = wdb_global_get_all_agents(wdb, last_id, &status);

        if (!result) {
            mdebug1("Error getting agents from global.db.");
            snprintf(output, OS_MAXSTR + 1, "err Error getting agents from global.db.");
            return OS_INVALID;
        }

        //Print response
        char* out = cJSON_PrintUnformatted(result);
        snprintf(output, OS_MAXSTR + 1, "%s %s",  WDBC_RESULT[status], out);

        cJSON_Delete(result);
        os_free(out);

        return OS_SUCCESS;
    }
}

int wdb_parse_global_get_distinct_agent_groups(wdb_t* wdb, char* input, char* output) {

    // Execute command
    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_distinct_agent_groups(wdb, input, &status);
    if (!result) {
        mdebug1("Error getting agent groups from global.db.");
        snprintf(output, OS_MAXSTR + 1, "err Error getting agent groups from global.db.");
        return OS_INVALID;
    }

    //Print response
    char* out = cJSON_PrintUnformatted(result);
    snprintf(output, OS_MAXSTR + 1, "%s %s",  WDBC_RESULT[status], out);

    cJSON_Delete(result);
    os_free(out)

    return OS_SUCCESS;
}

int wdb_parse_reset_agents_connection(wdb_t * wdb, char* input, char * output) {
    if (OS_SUCCESS != wdb_global_reset_agents_connection(wdb, input)) {
        mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db: %s", WDB2_DIR, WDB_GLOB_NAME, sqlite3_errmsg(wdb->db));
        snprintf(output, OS_MAXSTR + 1, "err Cannot execute Global database query; %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    snprintf(output, OS_MAXSTR + 1, "ok");
    return OS_SUCCESS;
}

int wdb_parse_global_disconnect_agents(wdb_t* wdb, char* input, char* output) {
    int last_id = 0;
    int keep_alive = 0;
    char *sync_status = NULL;
    char *next = NULL;
    const char delim[2] = " ";
    char *savedptr = NULL;

    /* Get last id*/
    next = strtok_r(input, delim, &savedptr);
    if (next == NULL) {
        mdebug1("Invalid arguments last id not found.");
        snprintf(output, OS_MAXSTR + 1, "err Invalid arguments last id not found");
        return OS_INVALID;
    }
    last_id = atoi(next);

    /* Get keepalive*/
    next = strtok_r(NULL, delim, &savedptr);
    if (next == NULL) {
        mdebug1("Invalid arguments keepalive not found.");
        snprintf(output, OS_MAXSTR + 1, "err Invalid arguments keepalive not found");
        return OS_INVALID;
    }
    keep_alive = atoi(next);

    /* Get sync_status*/
    next = strtok_r(NULL, delim, &savedptr);
    if (next == NULL) {
        mdebug1("Invalid arguments sync_status not found.");
        snprintf(output, OS_MAXSTR + 1, "err Invalid arguments sync_status not found");
        return OS_INVALID;
    }
    sync_status = next;

    // Execute command
    wdbc_result status = WDBC_UNKNOWN;
    cJSON* result = wdb_global_get_agents_to_disconnect(wdb, last_id, keep_alive, sync_status, &status);
    if (!result) {
        mdebug1("Error getting agents to be disconnected from global.db.");
        snprintf(output, OS_MAXSTR + 1, "err Error getting agents to be disconnected from global.db.");
        return OS_INVALID;
    }

    //Print response
    char* out = cJSON_PrintUnformatted(result);
    snprintf(output, OS_MAXSTR + 1, "%s %s",  WDBC_RESULT[status], out);

    cJSON_Delete(result);
    os_free(out)

    return OS_SUCCESS;
}

int wdb_parse_global_backup(wdb_t** wdb, char* input, char* output) {
    int result = OS_INVALID;
    char * next;
    const char delim[] = " ";
    char *tail = NULL;

    next = strtok_r(input, delim, &tail);

    if (!next) {
        snprintf(output, OS_MAXSTR + 1, "err Missing backup action");
    }
    else if (strcmp(next, "create") == 0) {
        result = wdb_global_create_backup(*wdb, output, NULL);
        if (OS_SUCCESS != result) {
            merror("Creating Global DB snapshot on demand failed: %s", output);
        }
    }
    else if (strcmp(next, "get") == 0) {
        result = wdb_parse_global_get_backup(output);
    }
    else if (strcmp(next, "restore") == 0) {
        // During a restore, the global wdb_t pointer may change. The mutex prevents anyone else from accesing it
        result = wdb_parse_global_restore_backup(wdb, tail, output);
    }
    else {
        snprintf(output, OS_MAXSTR + 1, "err Invalid backup action: %s", next);
    }

    return result;
}

int wdb_parse_global_get_backup(char* output) {
    cJSON* j_backups = wdb_global_get_backups();

    if (j_backups) {
        char* out = cJSON_PrintUnformatted(j_backups);
        snprintf(output, OS_MAXSTR + 1, "ok %s", out);
        os_free(out);
        cJSON_Delete(j_backups);
        return OS_SUCCESS;
    } else {
        snprintf(output, OS_MAXSTR + 1, "err Cannot execute backup get command, unable to open '%s' folder", WDB_BACKUP_FOLDER);
        return OS_INVALID;
    }
}

int wdb_parse_global_restore_backup(wdb_t** wdb, char* input, char* output) {
    cJSON *j_parameters = NULL;
    const char *error = NULL;
    int result = OS_INVALID;

    j_parameters = cJSON_ParseWithOpts(input, &error, TRUE);

    if (!j_parameters && strcmp(input, "")) {
        mdebug1("Invalid backup JSON syntax when restoring snapshot.");
        mdebug2("JSON error near: %s", error);
        snprintf(output, OS_MAXSTR + 1, "err Invalid JSON syntax, near '%.32s'", input);
        return OS_INVALID;
    } else {
        char* snapshot = cJSON_GetStringValue(cJSON_GetObjectItem(j_parameters, "snapshot"));
        cJSON* j_save_pre_restore_state = cJSON_GetObjectItem(j_parameters, "save_pre_restore_state");
        bool save_pre_restore_state = cJSON_IsBool(j_save_pre_restore_state) ? (bool) j_save_pre_restore_state->valueint : false;
        result = wdb_global_restore_backup(wdb, snapshot, save_pre_restore_state, output);
    }

    cJSON_Delete(j_parameters);
    return result;
}

bool process_dbsync_data(wdb_t * wdb, const struct kv * kv_value, const char * operation, const char * raw_data) {
    bool ret_val = false;
    const char * parse_error;
    cJSON * data = cJSON_ParseWithOpts(raw_data, &parse_error, true);
    if (NULL != data) {
        if (strcmp(operation, "INSERTED") == 0 || strcmp(operation, "MODIFIED") == 0) {
            ret_val = wdb_upsert_dbsync(wdb, kv_value, data);
        } else if (strcmp(operation, "DELETED") == 0) {
            wdb_delete_dbsync(wdb, kv_value, data);
            ret_val = true;
        } else {
            mdebug1("Invalid operation type: %s", operation);
        }
        cJSON_Delete(data);
    } else {
        mdebug1(DB_DELTA_PARSING_ERR);
        mdebug2("JSON error near: %s", parse_error);
    }
    return ret_val;
}

int wdb_parse_dbsync(wdb_t * wdb, char * input, char * output) {
    int ret_val = OS_INVALID;
    char *next = NULL;
    char *curr = input;
    if (next = strchr(curr, ' '), !next) {
        mdebug2("DBSYNC query: %s", input);
        snprintf(output, OS_MAXSTR + 1, "err Invalid dbsync query syntax, near '%.32s'", input);
        return ret_val;
    }

    char *table_key = curr;
    *next++ = '\0';
    curr = next;
    if (next = strchr(curr, ' '), !next) {
        mdebug2("DBSYNC query: %s", input);
        snprintf(output, OS_MAXSTR + 1, "err Invalid dbsync query syntax, near '%.32s'", input);
        return ret_val;
    }

    char *operation = curr;
    *next++ = '\0';
    curr = next;

    if (!strlen(curr)) {
        mdebug2("DBSYNC query: %s", input);
        snprintf(output, OS_MAXSTR + 1, "err Invalid dbsync query syntax, near '%.32s'", input);
        return ret_val;
    }

    char *data = curr;
    struct kv_list const *head = TABLE_MAP;
    while (NULL != head) {
        if (strncmp(head->current.key, table_key, OS_SIZE_256 - 1) == 0) {
            ret_val = process_dbsync_data(wdb, &head->current, operation, data) ? OS_SUCCESS : OS_INVALID;
            break;
        }
        head = head->next;
    }

    if (OS_SUCCESS == ret_val) {
        strcat(output, "ok ");
    } else {
        strcat(output, "err");
    }
    return ret_val;
}

int wdb_parse_task_upgrade(wdb_t* wdb, const cJSON *parameters, const char *command, char* output) {
    int result = OS_INVALID;
    int agent_id = OS_INVALID;
    char *node = NULL;
    char *module = NULL;

    cJSON *agent_id_json = cJSON_GetObjectItem(parameters, "agent");
    if (!agent_id_json || (agent_id_json->type != cJSON_Number)) {
        snprintf(output, OS_MAXSTR + 1, "err Error insert task: 'parsing agent error'");
        return OS_INVALID;
    }
    agent_id = agent_id_json->valueint;

    cJSON *node_json = cJSON_GetObjectItem(parameters, "node");
    if (!node_json || (node_json->type != cJSON_String)) {
        snprintf(output, OS_MAXSTR + 1, "err Error insert task: 'parsing node error'");
        return OS_INVALID;
    }
    node = node_json->valuestring;

    cJSON *module_json = cJSON_GetObjectItem(parameters, "module");
    if (!module_json || (module_json->type != cJSON_String)) {
        snprintf(output, OS_MAXSTR + 1, "err Error insert task: 'parsing module error'");
        return OS_INVALID;
    }
    module = module_json->valuestring;

    result = wdb_task_insert_task(wdb, agent_id, node, module, command);

    cJSON *response = cJSON_CreateObject();
    char *out = NULL;

    if (result >= 0) {
        cJSON_AddNumberToObject(response, "error", OS_SUCCESS);
        cJSON_AddNumberToObject(response, "task_id", result);
        result = OS_SUCCESS;
    } else {
        cJSON_AddNumberToObject(response, "error", result);
    }
    out = cJSON_PrintUnformatted(response);

    snprintf(output, OS_MAXSTR + 1, "ok %s", out);

    os_free(out);
    cJSON_Delete(response);

    return result;
}

int wdb_parse_task_upgrade_get_status(wdb_t* wdb, const cJSON *parameters, char* output) {
    int result = OS_INVALID;
    int agent_id = OS_INVALID;
    char *node = NULL;
    char *task_status = NULL;

    cJSON *agent_id_json = cJSON_GetObjectItem(parameters, "agent");
    if (!agent_id_json || (agent_id_json->type != cJSON_Number)) {
        snprintf(output, OS_MAXSTR + 1, "err Error get upgrade task status: 'parsing agent error'");
        return OS_INVALID;
    }
    agent_id = agent_id_json->valueint;

    cJSON *node_json = cJSON_GetObjectItem(parameters, "node");
    if (!node_json || (node_json->type != cJSON_String)) {
        snprintf(output, OS_MAXSTR + 1, "err Error get upgrade task status: 'parsing node error'");
        return OS_INVALID;
    }
    node = node_json->valuestring;

    result = wdb_task_get_upgrade_task_status(wdb, agent_id, node, &task_status);

    cJSON *response = cJSON_CreateObject();
    char *out = NULL;

    cJSON_AddNumberToObject(response, "error", result);
    if (result == OS_SUCCESS) {
        cJSON_AddStringToObject(response, "status", task_status);
    }
    out = cJSON_PrintUnformatted(response);

    snprintf(output, OS_MAXSTR + 1, "ok %s", out);

    os_free(out);
    cJSON_Delete(response);

    os_free(task_status);

    return result;
}

int wdb_parse_task_upgrade_update_status(wdb_t* wdb, const cJSON *parameters, char* output) {
    int result = OS_INVALID;
    int agent_id = OS_INVALID;
    char *node = NULL;
    char *status = NULL;
    char *error = NULL;

    cJSON *agent_id_json = cJSON_GetObjectItem(parameters, "agent");
    if (!agent_id_json || (agent_id_json->type != cJSON_Number)) {
        snprintf(output, OS_MAXSTR + 1, "err Error upgrade update status task: 'parsing agent error'");
        return OS_INVALID;
    }
    agent_id = agent_id_json->valueint;

    cJSON *node_json = cJSON_GetObjectItem(parameters, "node");
    if (!node_json || (node_json->type != cJSON_String)) {
        snprintf(output, OS_MAXSTR + 1, "err Error upgrade update status task: 'parsing node error'");
        return OS_INVALID;
    }
    node = node_json->valuestring;

    cJSON *status_json = cJSON_GetObjectItem(parameters, "status");
    if (!status_json || (status_json->type != cJSON_String)) {
        snprintf(output, OS_MAXSTR + 1, "err Error upgrade update status task: 'parsing status error'");
        return OS_INVALID;
    }
    status = status_json->valuestring;

    cJSON *error_json = cJSON_GetObjectItem(parameters, "error_msg");
    if (error_json && (error_json->type == cJSON_String)) {
        error = error_json->valuestring;
    }

    result = wdb_task_update_upgrade_task_status(wdb, agent_id, node, status, error);

    cJSON *response = cJSON_CreateObject();
    char *out = NULL;

    cJSON_AddNumberToObject(response, "error", result);
    out = cJSON_PrintUnformatted(response);

    snprintf(output, OS_MAXSTR + 1, "ok %s", out);

    os_free(out);
    cJSON_Delete(response);

    return result;
}

int wdb_parse_task_upgrade_result(wdb_t* wdb, const cJSON *parameters, char* output) {
    int result = OS_INVALID;
    int agent_id = OS_INVALID;
    char *node_result = NULL;
    char *module_result = NULL;
    char *command_result = NULL;
    char *status = NULL;
    char *error = NULL;
    int create_time = OS_INVALID;
    int last_update_time = OS_INVALID;

    cJSON *agent_id_json = cJSON_GetObjectItem(parameters, "agent");
    if (!agent_id_json || (agent_id_json->type != cJSON_Number)) {
        snprintf(output, OS_MAXSTR + 1, "err Error upgrade result task: 'parsing agent error'");
        return OS_INVALID;
    }
    agent_id = agent_id_json->valueint;

    result = wdb_task_get_upgrade_task_by_agent_id(wdb, agent_id, &node_result, &module_result, &command_result, &status, &error, &create_time, &last_update_time);

    cJSON *response = cJSON_CreateObject();
    char *out = NULL;

    if (result >= 0) {
        cJSON_AddNumberToObject(response, "error", OS_SUCCESS);
        cJSON_AddNumberToObject(response, "task_id", result);
        cJSON_AddStringToObject(response, "node", node_result);
        cJSON_AddStringToObject(response, "module", module_result);
        cJSON_AddStringToObject(response, "command", command_result);
        cJSON_AddStringToObject(response, "status", status);
        cJSON_AddStringToObject(response, "error_msg", error);
        cJSON_AddNumberToObject(response, "create_time", create_time);
        cJSON_AddNumberToObject(response, "update_time", last_update_time);
        result = OS_SUCCESS;
    } else {
        cJSON_AddNumberToObject(response, "error", result);
    }
    out = cJSON_PrintUnformatted(response);

    snprintf(output, OS_MAXSTR + 1, "ok %s", out);

    os_free(out);
    cJSON_Delete(response);

    os_free(node_result);
    os_free(module_result);
    os_free(command_result);
    os_free(status);
    os_free(error);

    return result;
}

int wdb_parse_task_upgrade_cancel_tasks(wdb_t* wdb, const cJSON *parameters, char* output) {
    int result = OS_INVALID;
    char *node = NULL;

    cJSON *node_json = cJSON_GetObjectItem(parameters, "node");
    if (!node_json || (node_json->type != cJSON_String)) {
        snprintf(output, OS_MAXSTR + 1, "err Error upgrade cancel task: 'parsing node error'");
        return OS_INVALID;
    }
    node = node_json->valuestring;

    result = wdb_task_cancel_upgrade_tasks(wdb, node);

    cJSON *response = cJSON_CreateObject();
    char *out = NULL;

    cJSON_AddNumberToObject(response, "error", result);
    out = cJSON_PrintUnformatted(response);

    snprintf(output, OS_MAXSTR + 1, "ok %s", out);

    os_free(out);
    cJSON_Delete(response);

    return result;
}

int wdb_parse_task_set_timeout(wdb_t* wdb, const cJSON *parameters, char* output) {
    int result = OS_INVALID;
    int now = OS_INVALID;
    int interval = OS_INVALID;
    time_t next_timeout = OS_INVALID;

    cJSON *now_json = cJSON_GetObjectItem(parameters, "now");
    if (!now_json || (now_json->type != cJSON_Number)) {
        snprintf(output, OS_MAXSTR + 1, "err Error set timeout task: 'parsing now error'");
        return OS_INVALID;
    }
    now = now_json->valueint;

    cJSON *interval_json = cJSON_GetObjectItem(parameters, "interval");
    if (!interval_json || (interval_json->type != cJSON_Number)) {
        snprintf(output, OS_MAXSTR + 1, "err Error set timeout task: 'parsing interval error'");
        return OS_INVALID;
    }
    interval = interval_json->valueint;

    next_timeout = now + interval;

    result = wdb_task_set_timeout_status(wdb, now, interval, &next_timeout);

    cJSON *response = cJSON_CreateObject();
    char *out = NULL;

    cJSON_AddNumberToObject(response, "error", result);
    if (result == OS_SUCCESS) {
        cJSON_AddNumberToObject(response, "timestamp", next_timeout);
    }
    out = cJSON_PrintUnformatted(response);

    snprintf(output, OS_MAXSTR + 1, "ok %s", out);

    os_free(out);
    cJSON_Delete(response);

    return result;
}

int wdb_parse_task_delete_old(wdb_t* wdb, const cJSON *parameters, char* output) {
    int result = OS_INVALID;
    int timestamp = OS_INVALID;

    cJSON *timestamp_json = cJSON_GetObjectItem(parameters, "timestamp");
    if (!timestamp_json || (timestamp_json->type != cJSON_Number)) {
        snprintf(output, OS_MAXSTR + 1, "err Error delete old task: 'parsing timestamp error'");
        return OS_INVALID;
    }
    timestamp = timestamp_json->valueint;

    result = wdb_task_delete_old_entries(wdb, timestamp);

    cJSON *response = cJSON_CreateObject();
    char *out = NULL;

    cJSON_AddNumberToObject(response, "error", result);
    out = cJSON_PrintUnformatted(response);

    snprintf(output, OS_MAXSTR + 1, "ok %s", out);

    os_free(out);
    cJSON_Delete(response);

    return result;
}
