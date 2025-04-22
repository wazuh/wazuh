/*
 * Wazuh SQLite integration
 * Copyright (C) 2015, Wazuh Inc.
 * June 06, 2016.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wdb.h"
#include "wazuh_modules/wmodules.h"
#include "wazuhdb_op.h"

#ifdef WAZUH_UNIT_TESTING
// Remove STATIC qualifier from tests
#define STATIC
#else
#define STATIC static
#endif

#ifdef WIN32
    #define getuid() 0
    #define chown(x, y, z) 0
    #define Privsep_GetUser(x) -1
    #define Privsep_GetGroup(x) -1
#endif

#define BUSY_SLEEP 1
#define MAX_ATTEMPTS 1000

// Router provider variables
ROUTER_PROVIDER_HANDLE router_agent_events_handle = NULL;

static const char *SQL_CREATE_TEMP_TABLE = "CREATE TEMP TABLE IF NOT EXISTS s(rowid INTEGER PRIMARY KEY, pageno INT);";
static const char *SQL_TRUNCATE_TEMP_TABLE = "DELETE FROM s;";
static const char *SQL_INSERT_INTO_TEMP_TABLE = "INSERT INTO s(pageno) SELECT pageno FROM dbstat ORDER BY path;";
static const char *SQL_SELECT_TEMP_TABLE = "SELECT sum(s1.pageno+1==s2.pageno)*1.0/count(*) FROM s AS s1, s AS s2 WHERE s1.rowid+1=s2.rowid;";
static const char *SQL_SELECT_PAGE_COUNT = "SELECT page_count FROM pragma_page_count();";
static const char *SQL_SELECT_PAGE_FREE = "SELECT freelist_count FROM pragma_freelist_count();";
static const char *SQL_VACUUM = "VACUUM;";
static const char *SQL_METADATA_UPDATE_FRAGMENTATION_DATA = "INSERT INTO metadata (key, value) VALUES ('last_vacuum_time', ?), ('last_vacuum_value', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value;";
static const char *SQL_METADATA_GET_FRAGMENTATION_DATA = "SELECT key, value FROM metadata WHERE key in ('last_vacuum_time', 'last_vacuum_value');";
static const char *SQL_INSERT_INFO = "INSERT INTO info (key, value) VALUES (?, ?);";
static const char *SQL_BEGIN = "BEGIN;";
static const char *SQL_COMMIT = "COMMIT;";
static const char *SQL_ROLLBACK = "ROLLBACK;";
static const char *SQL_STMT[] = {
    [WDB_STMT_FIM_LOAD] = "SELECT changes, size, perm, uid, gid, md5, sha1, uname, gname, mtime, inode, sha256, date, attributes, symbolic_path FROM fim_entry WHERE file = ?;",
    [WDB_STMT_FIM_FIND_ENTRY] = "SELECT 1 FROM fim_entry WHERE file = ?",
    [WDB_STMT_FIM_INSERT_ENTRY] = "INSERT INTO fim_entry (file, type, size, perm, uid, gid, md5, sha1, uname, gname, mtime, inode, sha256, attributes, symbolic_path, full_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
    [WDB_STMT_FIM_INSERT_ENTRY2] = "INSERT OR REPLACE INTO fim_entry (file, type, date, size, perm, uid, gid, md5, sha1, uname, gname, mtime, inode, sha256, attributes, symbolic_path, checksum, arch, value_name, value_type, full_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
    [WDB_STMT_FIM_UPDATE_ENTRY] = "UPDATE fim_entry SET date = strftime('%s', 'now'), changes = ?, size = ?, perm = ?, uid = ?, gid = ?, md5 = ?, sha1 = ?, uname = ?, gname = ?, mtime = ?, inode = ?, sha256 = ?, attributes = ?, symbolic_path = ? WHERE file = ?;",
    [WDB_STMT_FIM_DELETE] = "DELETE FROM fim_entry WHERE full_path = ?;",
    [WDB_STMT_FIM_UPDATE_DATE] = "UPDATE fim_entry SET date = strftime('%s', 'now') WHERE file = ?;",
    [WDB_STMT_FIM_FIND_DATE_ENTRIES] = "SELECT full_path, changes, size, perm, uid, gid, md5, sha1, uname, gname, mtime, inode, sha256, date, attributes, symbolic_path FROM fim_entry WHERE date < ?;",
    [WDB_STMT_FIM_GET_ATTRIBUTES] = "SELECT file, attributes from fim_entry WHERE attributes IS NOT '0';",
    [WDB_STMT_FIM_UPDATE_ATTRIBUTES] = "UPDATE fim_entry SET attributes = ? WHERE file = ?;",
    [WDB_STMT_OSINFO_INSERT] = "INSERT INTO sys_osinfo (scan_id, scan_time, hostname, architecture, os_name, os_version, os_codename, os_major, os_minor,  os_patch, os_build, os_platform, sysname, release, version, os_release, os_display_version, checksum, reference) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
    [WDB_STMT_OSINFO_INSERT2] = "INSERT OR REPLACE INTO sys_osinfo (scan_id, scan_time, hostname, architecture, os_name, os_version, os_codename, os_major, os_minor,  os_patch, os_build, os_platform, sysname, release, version, os_release, os_display_version, checksum, reference) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
    [WDB_STMT_OSINFO_DEL] = "DELETE FROM sys_osinfo;",
    [WDB_STMT_OSINFO_GET] = "SELECT * FROM sys_osinfo;",
    [WDB_STMT_PROGRAM_INSERT] = "INSERT INTO sys_programs (scan_id, scan_time, format, name, priority, section, size, vendor, install_time, version, architecture, multiarch, source, description, location, checksum, item_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
    [WDB_STMT_PROGRAM_INSERT2] = "INSERT OR REPLACE INTO sys_programs (scan_id, scan_time, format, name, priority, section, size, vendor, install_time, version, architecture, multiarch, source, description, location, checksum, item_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
    [WDB_STMT_PROGRAM_DEL] = "DELETE FROM sys_programs WHERE scan_id != ?;",
    [WDB_STMT_PROGRAM_UPD] = "UPDATE SYS_PROGRAMS SET CPE = ?, MSU_NAME = ? WHERE SCAN_ID = ? AND FORMAT IS ? AND NAME IS ? AND VENDOR IS ? AND VERSION IS ? AND ARCHITECTURE IS ?;",
    [WDB_STMT_PROGRAM_GET] = "SELECT CPE, MSU_NAME, FORMAT, NAME, VENDOR, VERSION, ARCHITECTURE FROM SYS_PROGRAMS WHERE SCAN_ID != ?;",
    [WDB_STMT_PROGRAM_FIND] = "SELECT 1 FROM sys_programs WHERE item_id = ?;",
    [WDB_STMT_HWINFO_INSERT] = "INSERT INTO sys_hwinfo (scan_id, scan_time, board_serial, cpu_name, cpu_cores, cpu_mhz, ram_total, ram_free, ram_usage, checksum) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
    [WDB_STMT_HWINFO_INSERT2] = "INSERT OR REPLACE INTO sys_hwinfo (scan_id, scan_time, board_serial, cpu_name, cpu_cores, cpu_mhz, ram_total, ram_free, ram_usage, checksum) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
    [WDB_STMT_HOTFIX_INSERT] = "INSERT INTO sys_hotfixes (scan_id, scan_time, hotfix, checksum) VALUES (?, ?, ?, ?);",
    [WDB_STMT_HOTFIX_INSERT2] = "INSERT OR REPLACE INTO sys_hotfixes (scan_id, scan_time, hotfix, checksum) VALUES (?, ?, ?, ?);",
    [WDB_STMT_HWINFO_DEL] = "DELETE FROM sys_hwinfo;",
    [WDB_STMT_HOTFIX_DEL] = "DELETE FROM sys_hotfixes WHERE scan_id != ?;",
    [WDB_STMT_PORT_INSERT] = "INSERT INTO sys_ports (scan_id, scan_time, protocol, local_ip, local_port, remote_ip, remote_port, tx_queue, rx_queue, inode, state, PID, process, checksum, item_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
    [WDB_STMT_PORT_INSERT2] = "INSERT OR REPLACE INTO sys_ports (scan_id, scan_time, protocol, local_ip, local_port, remote_ip, remote_port, tx_queue, rx_queue, inode, state, PID, process, checksum, item_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
    [WDB_STMT_PORT_DEL] = "DELETE FROM sys_ports WHERE scan_id != ?;",
    [WDB_STMT_PROC_INSERT] = "INSERT INTO sys_processes (scan_id, scan_time, pid, name, state, ppid, utime, stime, cmd, argvs, euser, ruser, suser, egroup, rgroup, sgroup, fgroup, priority, nice, size, vm_size, resident, share, start_time, pgrp, session, nlwp, tgid, tty, processor, checksum) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    [WDB_STMT_PROC_INSERT2] = "INSERT OR REPLACE INTO sys_processes (scan_id, scan_time, pid, name, state, ppid, utime, stime, cmd, argvs, euser, ruser, suser, egroup, rgroup, sgroup, fgroup, priority, nice, size, vm_size, resident, share, start_time, pgrp, session, nlwp, tgid, tty, processor, checksum) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    [WDB_STMT_PROC_DEL] = "DELETE FROM sys_processes WHERE scan_id != ?;",
    [WDB_STMT_NETINFO_INSERT] = "INSERT INTO sys_netiface (scan_id, scan_time, name, adapter, type, state, mtu, mac, tx_packets, rx_packets, tx_bytes, rx_bytes, tx_errors, rx_errors, tx_dropped, rx_dropped, checksum, item_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
    [WDB_STMT_NETINFO_INSERT2] = "INSERT OR REPLACE INTO sys_netiface (scan_id, scan_time, name, adapter, type, state, mtu, mac, tx_packets, rx_packets, tx_bytes, rx_bytes, tx_errors, rx_errors, tx_dropped, rx_dropped, checksum, item_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
    [WDB_STMT_PROTO_INSERT] = "INSERT INTO sys_netproto (scan_id, iface, type, gateway, dhcp, metric, checksum, item_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
    [WDB_STMT_PROTO_INSERT2] = "INSERT OR REPLACE INTO sys_netproto (scan_id, iface, type, gateway, dhcp, metric, checksum, item_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
    [WDB_STMT_ADDR_INSERT] = "INSERT INTO sys_netaddr (scan_id, iface, proto, address, netmask, broadcast, checksum, item_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
    [WDB_STMT_ADDR_INSERT2] = "INSERT OR REPLACE INTO sys_netaddr (scan_id, iface, proto, address, netmask, broadcast, checksum, item_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
    [WDB_STMT_NETINFO_DEL] = "DELETE FROM sys_netiface WHERE scan_id != ?;",
    [WDB_STMT_PROTO_DEL] = "DELETE FROM sys_netproto WHERE scan_id != ?;",
    [WDB_STMT_ADDR_DEL] = "DELETE FROM sys_netaddr WHERE scan_id != ?;",
    [WDB_STMT_CISCAT_INSERT] = "INSERT INTO ciscat_results (scan_id, scan_time, benchmark, profile, pass, fail, error, notchecked, unknown, score) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
    [WDB_STMT_CISCAT_DEL] = "DELETE FROM ciscat_results WHERE scan_id != ?;",
    [WDB_STMT_SCAN_INFO_UPDATEFS] = "UPDATE scan_info SET first_start = ?, start_scan = ? WHERE module = ?;",
    [WDB_STMT_SCAN_INFO_UPDATEFE] = "UPDATE scan_info SET first_end = ?, end_scan = ? WHERE module = ?;",
    [WDB_STMT_SCAN_INFO_UPDATESS] = "UPDATE scan_info SET start_scan = ? WHERE module = ?;",
    [WDB_STMT_SCAN_INFO_UPDATEES] = "UPDATE scan_info SET end_scan = ? WHERE module = ?;",
    [WDB_STMT_SCAN_INFO_UPDATE1C] = "UPDATE scan_info SET fim_first_check = ? WHERE module = ?;",
    [WDB_STMT_SCAN_INFO_UPDATE2C] = "UPDATE scan_info SET fim_second_check = ? WHERE module = ?;",
    [WDB_STMT_SCAN_INFO_UPDATE3C] = "UPDATE scan_info SET fim_third_check = ? WHERE module = ?;",
    [WDB_STMT_SCAN_INFO_GETFS] = "SELECT first_start FROM scan_info WHERE module = ?;",
    [WDB_STMT_SCAN_INFO_GETFE] = "SELECT first_end FROM scan_info WHERE module = ?;",
    [WDB_STMT_SCAN_INFO_GETSS] = "SELECT start_scan FROM scan_info WHERE module = ?;",
    [WDB_STMT_SCAN_INFO_GETES] = "SELECT end_scan FROM scan_info WHERE module = ?;",
    [WDB_STMT_SCAN_INFO_GET1C] = "SELECT fim_first_check FROM scan_info WHERE module = ?;",
    [WDB_STMT_SCAN_INFO_GET2C] = "SELECT fim_second_check FROM scan_info WHERE module = ?;",
    [WDB_STMT_SCAN_INFO_GET3C] = "SELECT fim_third_check FROM scan_info WHERE module = ?;",
    [WDB_STMT_SCA_FIND] = "SELECT id,result FROM sca_check WHERE id = ?;",
    [WDB_STMT_SCA_UPDATE] = "UPDATE sca_check SET scan_id = ?, result = ?, reason = ? WHERE id = ?;",
    [WDB_STMT_SCA_INSERT] = "INSERT INTO sca_check (id,scan_id,title,description,rationale,remediation,file,directory,process,registry,`references`,result,policy_id,command,reason,condition) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);",
    [WDB_STMT_SCA_SCAN_INFO_INSERT] = "INSERT INTO sca_scan_info (start_scan,end_scan,id,policy_id,pass,fail,invalid,total_checks,score,hash) VALUES (?,?,?,?,?,?,?,?,?,?);",
    [WDB_STMT_SCA_SCAN_INFO_UPDATE] = "UPDATE sca_scan_info SET start_scan = ?, end_scan = ?, id = ?, pass = ?, fail = ?, invalid = ?, total_checks = ?, score = ?, hash = ? WHERE policy_id = ?;",
    [WDB_STMT_SCA_INSERT_COMPLIANCE] = "INSERT INTO sca_check_compliance (id_check,`key`,`value`) VALUES(?,?,?);",
    [WDB_STMT_SCA_INSERT_RULES] = "INSERT INTO sca_check_rules (id_check,`type`, rule) VALUES(?,?,?);",
    [WDB_STMT_SCA_FIND_SCAN] = "SELECT policy_id,hash,id FROM sca_scan_info WHERE policy_id = ?;",
    [WDB_STMT_SCA_SCAN_INFO_UPDATE_START] = "UPDATE sca_scan_info SET start_scan = ?, end_scan = ?, id = ?, pass = ?, fail = ?, invalid = ?, total_checks = ?, score = ?, hash = ? WHERE policy_id = ?;",
    [WDB_STMT_SCA_POLICY_FIND] = "SELECT id FROM sca_policy WHERE id = ?;",
    [WDB_STMT_SCA_POLICY_SHA256] = "SELECT hash_file FROM sca_policy WHERE id = ?;",
    [WDB_STMT_SCA_POLICY_INSERT] = "INSERT INTO sca_policy (name,file,id,description,`references`,hash_file) VALUES(?,?,?,?,?,?);",
    [WDB_STMT_SCA_CHECK_GET_ALL_RESULTS] = "SELECT result FROM sca_check WHERE policy_id = ? ORDER BY id;",
    [WDB_STMT_SCA_POLICY_GET_ALL] = "SELECT id FROM sca_policy;",
    [WDB_STMT_SCA_POLICY_DELETE] = "DELETE FROM sca_policy WHERE id = ?;",
    [WDB_STMT_SCA_CHECK_DELETE] = "DELETE FROM sca_check WHERE policy_id = ?;",
    [WDB_STMT_SCA_SCAN_INFO_DELETE] = "DELETE FROM sca_scan_info WHERE policy_id = ?;",
    [WDB_STMT_SCA_CHECK_COMPLIANCE_DELETE] = "DELETE FROM sca_check_compliance WHERE id_check NOT IN ( SELECT id FROM sca_check);",
    [WDB_STMT_SCA_CHECK_RULES_DELETE] = "DELETE FROM sca_check_rules WHERE id_check NOT IN ( SELECT id FROM sca_check);",
    [WDB_STMT_SCA_CHECK_DELETE_DISTINCT] = "DELETE FROM sca_check WHERE scan_id != ? AND policy_id = ?;",
    [WDB_STMT_FIM_SELECT_CHECKSUM] = "SELECT checksum FROM fim_entry ORDER BY file;",
    [WDB_STMT_FIM_SELECT_CHECKSUM_RANGE] = "SELECT checksum FROM fim_entry WHERE file BETWEEN ? and ? ORDER BY file;",
    [WDB_STMT_FIM_DELETE_AROUND] = "DELETE FROM fim_entry WHERE file < ? OR file > ?;",
    [WDB_STMT_FIM_DELETE_RANGE] = "DELETE FROM fim_entry WHERE file > ? AND file < ?;",
    [WDB_STMT_FIM_DELETE_BY_PK] = "DELETE FROM fim_entry WHERE file = ?;",
    [WDB_STMT_FIM_CLEAR] = "DELETE FROM fim_entry;",
    [WDB_STMT_SYNC_UPDATE_ATTEMPT_LEGACY] = "UPDATE sync_info SET last_attempt = ? WHERE component = ?;",
    [WDB_STMT_SYNC_UPDATE_ATTEMPT] = "UPDATE sync_info SET last_attempt = ?, last_agent_checksum = ?, last_manager_checksum = ?, n_attempts = n_attempts + 1 WHERE component = ?;",
    [WDB_STMT_SYNC_UPDATE_COMPLETION] = "UPDATE sync_info SET last_attempt = ?, last_completion = ?, last_agent_checksum = ?, last_manager_checksum = ?, n_attempts = n_attempts + 1, n_completions = n_completions + 1 WHERE component = ?;",
    [WDB_STMT_SYNC_SET_COMPLETION] = "UPDATE sync_info SET last_completion = ? WHERE component = ?;",
    [WDB_STMT_SYNC_GET_INFO] = "SELECT * FROM sync_info WHERE component = ?;",
    [WDB_STMT_FIM_FILE_SELECT_CHECKSUM] = "SELECT checksum FROM fim_entry WHERE type='file' ORDER BY file;",
    [WDB_STMT_FIM_FILE_SELECT_CHECKSUM_RANGE] = "SELECT checksum FROM fim_entry WHERE type='file' AND file BETWEEN ? and ? ORDER BY file;",
    [WDB_STMT_FIM_FILE_CLEAR] = "DELETE FROM fim_entry WHERE type='file';",
    [WDB_STMT_FIM_FILE_DELETE_AROUND] = "DELETE FROM fim_entry WHERE type='file' AND (file < ? OR file > ?);",
    [WDB_STMT_FIM_FILE_DELETE_RANGE] = "DELETE FROM fim_entry WHERE type='file' AND (file > ? AND file < ?);",
    [WDB_STMT_FIM_FILE_DELETE_BY_PK] = "DELETE FROM fim_entry WHERE type='file' AND file = ?;",
    [WDB_STMT_FIM_REGISTRY_SELECT_CHECKSUM] = "SELECT checksum FROM fim_entry WHERE (type='registry_key' OR type='registry_value') ORDER BY full_path",
    [WDB_STMT_FIM_REGISTRY_SELECT_CHECKSUM_RANGE] = "SELECT checksum FROM fim_entry WHERE (type='registry_key' OR type='registry_value') AND full_path BETWEEN ? AND ? ORDER BY full_path",
    [WDB_STMT_FIM_REGISTRY_CLEAR] = "DELETE FROM fim_entry WHERE type='registry_key' OR type='registry_value';",
    [WDB_STMT_FIM_REGISTRY_DELETE_AROUND] = "DELETE FROM fim_entry WHERE (type='registry_key' OR type='registry_value') AND (full_path < ? OR full_path > ?);",
    [WDB_STMT_FIM_REGISTRY_DELETE_RANGE] = "DELETE FROM fim_entry WHERE (type='registry_key' OR type='registry_value') AND (full_path > ? AND full_path < ?);",
    [WDB_STMT_FIM_REGISTRY_KEY_SELECT_CHECKSUM] = "SELECT checksum FROM fim_entry WHERE type='registry_key' ORDER BY full_path",
    [WDB_STMT_FIM_REGISTRY_KEY_SELECT_CHECKSUM_RANGE] = "SELECT checksum FROM fim_entry WHERE type='registry_key' AND full_path BETWEEN ? AND ? ORDER BY full_path",
    [WDB_STMT_FIM_REGISTRY_KEY_CLEAR] = "DELETE FROM fim_entry WHERE type='registry_key';",
    [WDB_STMT_FIM_REGISTRY_KEY_DELETE_AROUND] = "DELETE FROM fim_entry WHERE type='registry_key' AND (full_path < ? OR full_path > ?);",
    [WDB_STMT_FIM_REGISTRY_KEY_DELETE_RANGE] = "DELETE FROM fim_entry WHERE type='registry_key' AND (full_path > ? AND full_path < ?);",
    [WDB_STMT_FIM_REGISTRY_VALUE_SELECT_CHECKSUM] = "SELECT checksum FROM fim_entry WHERE type='registry_value' ORDER BY full_path",
    [WDB_STMT_FIM_REGISTRY_VALUE_SELECT_CHECKSUM_RANGE] = "SELECT checksum FROM fim_entry WHERE type='registry_value' AND full_path BETWEEN ? AND ? ORDER BY full_path",
    [WDB_STMT_FIM_REGISTRY_VALUE_CLEAR] = "DELETE FROM fim_entry WHERE type='registry_value';",
    [WDB_STMT_FIM_REGISTRY_VALUE_DELETE_AROUND] = "DELETE FROM fim_entry WHERE type='registry_value' AND (full_path < ? OR full_path > ?);",
    [WDB_STMT_FIM_REGISTRY_VALUE_DELETE_RANGE] = "DELETE FROM fim_entry WHERE type='registry_value' AND (full_path > ? AND full_path < ?);",
    [WDB_STMT_FIM_REGISTRY_DELETE_BY_PK] = "DELETE FROM fim_entry WHERE (type='registry_key' OR type='registry_value') AND full_path = ?;",
    [WDB_STMT_ROOTCHECK_INSERT_PM] = "INSERT INTO pm_event (date_first, date_last, log, pci_dss, cis) VALUES (?, ?, ?, ?, ?);",
    [WDB_STMT_ROOTCHECK_UPDATE_PM] = "UPDATE pm_event SET date_last = ? WHERE log = ?;",
    [WDB_STMT_ROOTCHECK_DELETE_PM] = "DELETE FROM pm_event;",
    [WDB_STMT_GLOBAL_INSERT_AGENT] = "INSERT INTO agent (id, name, ip, register_ip, internal_key, date_add, `group`) VALUES (?,?,?,?,?,?,?);",
    [WDB_STMT_GLOBAL_UPDATE_AGENT_NAME] = "UPDATE agent SET name = ? WHERE id = ?;",
    [WDB_STMT_GLOBAL_UPDATE_AGENT_VERSION] = "UPDATE agent SET os_name = ?, os_version = ?, os_major = ?, os_minor = ?, os_codename = ?, os_platform = ?, os_build = ?, os_uname = ?, os_arch = ?, version = ?, config_sum = ?, merged_sum = ?, manager_host = ?, node_name = ?, last_keepalive = (CASE WHEN id = 0 THEN 253402300799 ELSE STRFTIME('%s', 'NOW') END), connection_status = ?, sync_status = ?, group_config_status = ? WHERE id = ?;",
    [WDB_STMT_GLOBAL_UPDATE_AGENT_VERSION_IP] = "UPDATE agent SET os_name = ?, os_version = ?, os_major = ?, os_minor = ?, os_codename = ?, os_platform = ?, os_build = ?, os_uname = ?, os_arch = ?, version = ?, config_sum = ?, merged_sum = ?, manager_host = ?, node_name = ?, last_keepalive = (CASE WHEN id = 0 THEN 253402300799 ELSE STRFTIME('%s', 'NOW') END), ip = ?, connection_status = ?, sync_status = ?, group_config_status = ? WHERE id = ?;",
    [WDB_STMT_GLOBAL_LABELS_GET] = "SELECT * FROM labels WHERE id = ?;",
    [WDB_STMT_GLOBAL_LABELS_DEL] = "DELETE FROM labels WHERE id = ?;",
    [WDB_STMT_GLOBAL_LABELS_SET] = "INSERT INTO labels (id, key, value) VALUES (?,?,?);",
    [WDB_STMT_GLOBAL_UPDATE_AGENT_KEEPALIVE] = "UPDATE agent SET last_keepalive = STRFTIME('%s', 'NOW'), connection_status = ?, sync_status = ?, disconnection_time = 0, status_code = 0 WHERE id = ?;",
    [WDB_STMT_GLOBAL_UPDATE_AGENT_CONNECTION_STATUS] = "UPDATE agent SET connection_status = ?, sync_status = ?, disconnection_time = ?, status_code = ? WHERE id = ?;",
    [WDB_STMT_GLOBAL_UPDATE_AGENT_STATUS_CODE] = "UPDATE agent SET status_code = ?, version = ?, sync_status = ? WHERE id = ?;",
    [WDB_STMT_GLOBAL_DELETE_AGENT] = "DELETE FROM agent WHERE id = ?;",
    [WDB_STMT_GLOBAL_SELECT_AGENT_NAME] = "SELECT name FROM agent WHERE id = ?;",
    [WDB_STMT_GLOBAL_FIND_AGENT] = "SELECT id FROM agent WHERE name = ? AND (register_ip = ? OR register_ip LIKE ? || '/_%');",
    [WDB_STMT_GLOBAL_FIND_GROUP] = "SELECT id FROM `group` WHERE name = ?;",
    [WDB_STMT_GLOBAL_UPDATE_AGENT_GROUPS_HASH] = "UPDATE agent SET group_hash = ? WHERE id = ?;",
    [WDB_STMT_GLOBAL_INSERT_AGENT_GROUP] = "INSERT INTO `group` (name) VALUES(?);",
    [WDB_STMT_GLOBAL_SELECT_GROUP_BELONG] = "SELECT name FROM belongs JOIN `group` ON id = id_group WHERE id_agent = ? order by priority;",
    [WDB_STMT_GLOBAL_INSERT_AGENT_BELONG] = "INSERT OR REPLACE INTO belongs (id_group, id_agent, priority) VALUES(?,?,?);",
    [WDB_STMT_GLOBAL_DELETE_AGENT_BELONG] = "DELETE FROM belongs WHERE id_agent = ?;",
    [WDB_STMT_GLOBAL_DELETE_TUPLE_BELONG] = "DELETE FROM belongs WHERE id_group = ? and id_agent = ?;",
    [WDB_STMT_GLOBAL_DELETE_GROUP] = "DELETE FROM `group` WHERE name = ?;",
    [WDB_STMT_GLOBAL_GROUP_BELONG_FIND] = "SELECT id_agent FROM belongs WHERE id_group = (SELECT id FROM 'group' WHERE name = ?);",
    [WDB_STMT_GLOBAL_GROUP_BELONG_GET] = "SELECT id_agent FROM belongs WHERE id_group = (SELECT id FROM 'group' WHERE name = ?) AND id_agent > ?;",
    [WDB_STMT_GLOBAL_SELECT_GROUPS] = "SELECT name FROM `group`;",
    [WDB_STMT_GLOBAL_SYNC_REQ_GET] = "SELECT id, name, ip, os_name, os_version, os_major, os_minor, os_codename, os_build, os_platform, os_uname, os_arch, version, config_sum, merged_sum, manager_host, node_name, last_keepalive, connection_status, disconnection_time, group_config_status, status_code FROM agent WHERE id > ? AND sync_status = 'syncreq' LIMIT 1;",
    [WDB_STMT_GLOBAL_SYNC_SET] = "UPDATE agent SET sync_status = ? WHERE id = ?;",
    [WDB_STMT_GLOBAL_GROUP_SYNC_REQ_GET] = "SELECT id FROM agent WHERE id > ? AND group_sync_status = 'syncreq' AND date_add < ? LIMIT 1;",
    [WDB_STMT_GLOBAL_GROUP_SYNC_ALL_GET] = "SELECT id FROM agent WHERE id > ? AND date_add < ? LIMIT 1;",
    [WDB_STMT_GLOBAL_GROUP_SYNCREQ_FIND] = "SELECT 1 FROM agent WHERE group_sync_status = 'syncreq';",
    [WDB_STMT_GLOBAL_AGENT_GROUPS_NUMBER_GET] = "SELECT count(id_group) groups_number from belongs WHERE id_agent = ?;",
    [WDB_STMT_GLOBAL_GROUP_SYNC_SET] = "UPDATE agent SET group_sync_status = ? WHERE id = ?;",
    [WDB_STMT_GLOBAL_GROUP_PRIORITY_GET] = "SELECT MAX(priority) FROM belongs WHERE id_agent=?;",
    [WDB_STMT_GLOBAL_GROUP_CSV_GET] = "SELECT `group` from agent where id = ?;",
    [WDB_STMT_GLOBAL_GROUP_CTX_SET] = "UPDATE agent SET 'group' = ?, group_hash = ?, group_sync_status = ? WHERE id = ?;",
    [WDB_STMT_GLOBAL_GROUP_HASH_GET] = "SELECT group_hash FROM agent WHERE id > 0 AND group_hash IS NOT NULL ORDER BY id;",
    [WDB_STMT_GLOBAL_GROUP_HASH_SET] = "UPDATE agent SET 'group' = ?, group_hash = ? WHERE id = ?;",
    [WDB_STMT_GLOBAL_UPDATE_AGENT_INFO] = "UPDATE agent SET config_sum = :config_sum, ip = :ip, manager_host = :manager_host, merged_sum = :merged_sum, name = :name, node_name = :node_name, os_arch = :os_arch, os_build = :os_build, os_codename = :os_codename, os_major = :os_major, os_minor = :os_minor, os_name = :os_name, os_platform = :os_platform, os_uname = :os_uname, os_version = :os_version, version = :version, last_keepalive = :last_keepalive, connection_status = :connection_status, disconnection_time = :disconnection_time, group_config_status = :group_config_status, status_code= :status_code, sync_status = :sync_status WHERE id = :id;",
    [WDB_STMT_GLOBAL_GET_GROUPS] = "SELECT DISTINCT `group`, group_hash from agent WHERE id > 0 AND group_hash > ? ORDER BY group_hash;",
    [WDB_STMT_GLOBAL_GET_AGENTS] = "SELECT id FROM agent WHERE id > ?;",
    [WDB_STMT_GLOBAL_GET_AGENTS_AND_GROUP] = "SELECT id, `group` FROM agent WHERE id > ?;",
    [WDB_STMT_GLOBAL_GET_AGENTS_CONTEXT] = "SELECT id,version,name,ip FROM agent;",
    [WDB_STMT_GLOBAL_GET_AGENTS_BY_CONNECTION_STATUS] = "SELECT id FROM agent WHERE id > ? AND connection_status = ?;",
    [WDB_STMT_GLOBAL_GET_AGENTS_BY_CONNECTION_STATUS_AND_NODE] = "SELECT id FROM agent WHERE id > ? AND connection_status = ? AND node_name = ? ORDER BY id LIMIT ?;",
    [WDB_STMT_GLOBAL_GET_AGENT_INFO] = "SELECT * FROM agent WHERE id = ?;",
    [WDB_STMT_GLOBAL_RESET_CONNECTION_STATUS] = "UPDATE agent SET connection_status = 'disconnected', status_code = ?, sync_status = ?, disconnection_time = STRFTIME('%s', 'NOW') where connection_status != 'disconnected' AND connection_status != 'never_connected' AND id != 0;",
    [WDB_STMT_GLOBAL_GET_AGENTS_TO_DISCONNECT] = "SELECT id FROM agent WHERE id > ? AND (connection_status = 'active' OR connection_status = 'pending') AND last_keepalive < ?;",
    [WDB_STMT_GLOBAL_AGENT_EXISTS] = "SELECT EXISTS(SELECT 1 FROM agent WHERE id=?);",
    [WDB_STMT_TASK_INSERT_TASK] = "INSERT INTO TASKS VALUES(NULL,?,?,?,?,?,?,?,?);",
    [WDB_STMT_TASK_GET_LAST_AGENT_TASK] = "SELECT *, MAX(CREATE_TIME) FROM TASKS WHERE AGENT_ID = ?;",
    [WDB_STMT_TASK_GET_LAST_AGENT_UPGRADE_TASK] = "SELECT *, MAX(CREATE_TIME) FROM TASKS WHERE AGENT_ID = ? AND (COMMAND = 'upgrade' OR COMMAND = 'upgrade_custom');",
    [WDB_STMT_TASK_UPDATE_TASK_STATUS] = "UPDATE TASKS SET STATUS = ?, LAST_UPDATE_TIME = ?, ERROR_MESSAGE = ? WHERE TASK_ID = ?;",
    [WDB_STMT_TASK_GET_TASK_BY_STATUS] = "SELECT * FROM TASKS WHERE STATUS = ?;",
    [WDB_STMT_TASK_DELETE_OLD_TASKS] = "DELETE FROM TASKS WHERE CREATE_TIME <= ?;",
    [WDB_STMT_TASK_DELETE_TASK] = "DELETE FROM TASKS WHERE TASK_ID = ?;",
    [WDB_STMT_TASK_CANCEL_PENDING_UPGRADE_TASKS] = "UPDATE TASKS SET STATUS = '" WM_TASK_STATUS_CANCELLED "', LAST_UPDATE_TIME = ? WHERE NODE = ? AND STATUS = '" WM_TASK_STATUS_PENDING "' AND (COMMAND = 'upgrade' OR COMMAND = 'upgrade_custom');",
    [WDB_STMT_PRAGMA_JOURNAL_WAL] = "PRAGMA journal_mode=WAL;",
    [WDB_STMT_PRAGMA_ENABLE_FOREIGN_KEYS] = "PRAGMA foreign_keys=ON;",
    [WDB_STMT_PRAGMA_SYNCHRONOUS_NORMAL] = "PRAGMA synchronous=1;",
    [WDB_STMT_SYSCOLLECTOR_PROCESSES_SELECT_CHECKSUM] = "SELECT checksum FROM sys_processes WHERE checksum != 'legacy' AND checksum != '' ORDER BY pid;",
    [WDB_STMT_SYSCOLLECTOR_PROCESSES_SELECT_CHECKSUM_RANGE] = "SELECT checksum FROM sys_processes WHERE pid BETWEEN ? and ? AND checksum != 'legacy' AND checksum != '' ORDER BY pid;",
    [WDB_STMT_SYSCOLLECTOR_PROCESSES_DELETE_AROUND] = "DELETE FROM sys_processes WHERE pid < ? OR pid > ? OR checksum = 'legacy' OR checksum = '';",
    [WDB_STMT_SYSCOLLECTOR_PROCESSES_DELETE_RANGE] = "DELETE FROM sys_processes WHERE pid > ? AND pid < ?;",
    [WDB_STMT_SYSCOLLECTOR_PROCESSES_DELETE_BY_PK] = "DELETE FROM sys_processes WHERE pid = ?;",
    [WDB_STMT_SYSCOLLECTOR_PROCESSES_CLEAR] = "DELETE FROM sys_processes;",
    [WDB_STMT_SYSCOLLECTOR_PACKAGES_SELECT_CHECKSUM] = "SELECT checksum FROM sys_programs WHERE checksum != 'legacy' AND checksum != '' ORDER BY item_id;",
    [WDB_STMT_SYSCOLLECTOR_PACKAGES_SELECT_CHECKSUM_RANGE] = "SELECT checksum FROM sys_programs WHERE item_id BETWEEN ? and ? AND checksum != 'legacy' AND checksum != '' ORDER BY item_id;",
    [WDB_STMT_SYSCOLLECTOR_PACKAGES_DELETE_AROUND] = "DELETE FROM sys_programs WHERE item_id < ? OR item_id > ? OR checksum = 'legacy' OR checksum = '' RETURNING name, version, architecture, format, location, item_id;",
    [WDB_STMT_SYSCOLLECTOR_PACKAGES_DELETE_RANGE] = "DELETE FROM sys_programs WHERE item_id > ? AND item_id < ? RETURNING name, version, architecture, format, location, item_id;",
    [WDB_STMT_SYSCOLLECTOR_PACKAGES_DELETE_BY_PK] = "DELETE FROM sys_programs WHERE item_id = ? RETURNING name, version, architecture, format, location, item_id;",
    [WDB_STMT_SYSCOLLECTOR_PACKAGES_CLEAR] = "DELETE FROM sys_programs;",
    [WDB_STMT_SYSCOLLECTOR_HOTFIXES_SELECT_CHECKSUM] = "SELECT checksum FROM sys_hotfixes WHERE checksum != 'legacy' AND checksum != '' ORDER BY hotfix;",
    [WDB_STMT_SYSCOLLECTOR_HOTFIXES_SELECT_CHECKSUM_RANGE] = "SELECT checksum FROM sys_hotfixes WHERE hotfix BETWEEN ? and ? AND checksum != 'legacy' AND checksum != '' ORDER BY hotfix;",
    [WDB_STMT_SYSCOLLECTOR_HOTFIXES_DELETE_AROUND] = "DELETE FROM sys_hotfixes WHERE hotfix < ? OR hotfix > ? OR checksum = 'legacy' OR checksum = '' RETURNING hotfix;",
    [WDB_STMT_SYSCOLLECTOR_HOTFIXES_DELETE_RANGE] = "DELETE FROM sys_hotfixes WHERE hotfix > ? AND hotfix < ? RETURNING hotfix;",
    [WDB_STMT_SYSCOLLECTOR_HOTFIXES_DELETE_BY_PK] = "DELETE FROM sys_hotfixes WHERE hotfix = ? RETURNING hotfix;",
    [WDB_STMT_SYSCOLLECTOR_HOTFIXES_CLEAR] = "DELETE FROM sys_hotfixes;",
    [WDB_STMT_SYSCOLLECTOR_PORTS_SELECT_CHECKSUM] = "SELECT checksum FROM sys_ports WHERE checksum != 'legacy' AND checksum != '' ORDER BY item_id;",
    [WDB_STMT_SYSCOLLECTOR_PORTS_SELECT_CHECKSUM_RANGE] = "SELECT checksum FROM sys_ports WHERE item_id BETWEEN ? and ? AND checksum != 'legacy' AND checksum != '' ORDER BY item_id;",
    [WDB_STMT_SYSCOLLECTOR_PORTS_DELETE_AROUND] = "DELETE FROM sys_ports WHERE item_id < ? OR item_id > ? OR checksum = 'legacy' OR checksum = '';",
    [WDB_STMT_SYSCOLLECTOR_PORTS_DELETE_RANGE] = "DELETE FROM sys_ports WHERE item_id > ? AND item_id < ?;",
    [WDB_STMT_SYSCOLLECTOR_PORTS_DELETE_BY_PK] = "DELETE FROM sys_ports WHERE item_id = ?;",
    [WDB_STMT_SYSCOLLECTOR_PORTS_CLEAR] = "DELETE FROM sys_ports;",
    [WDB_STMT_SYSCOLLECTOR_NETPROTO_SELECT_CHECKSUM] = "SELECT checksum FROM sys_netproto WHERE checksum != 'legacy' AND checksum != '' ORDER BY item_id;",
    [WDB_STMT_SYSCOLLECTOR_NETPROTO_SELECT_CHECKSUM_RANGE] = "SELECT checksum FROM sys_netproto WHERE item_id BETWEEN ? and ? AND checksum != 'legacy' AND checksum != '' ORDER BY item_id;",
    [WDB_STMT_SYSCOLLECTOR_NETPROTO_DELETE_AROUND] = "DELETE FROM sys_netproto WHERE item_id < ? OR item_id > ? OR checksum = 'legacy' OR checksum = '';",
    [WDB_STMT_SYSCOLLECTOR_NETPROTO_DELETE_RANGE] = "DELETE FROM sys_netproto WHERE item_id > ? AND item_id < ?;",
    [WDB_STMT_SYSCOLLECTOR_NETPROTO_DELETE_BY_PK] = "DELETE FROM sys_netproto WHERE item_id = ?;",
    [WDB_STMT_SYSCOLLECTOR_NETPROTO_CLEAR] = "DELETE FROM sys_netproto;",
    [WDB_STMT_SYSCOLLECTOR_NETADDRESS_SELECT_CHECKSUM] = "SELECT checksum FROM sys_netaddr WHERE checksum != 'legacy' AND checksum != '' ORDER BY item_id;",
    [WDB_STMT_SYSCOLLECTOR_NETADDRESS_SELECT_CHECKSUM_RANGE] = "SELECT checksum FROM sys_netaddr WHERE item_id BETWEEN ? and ? AND checksum != 'legacy' AND checksum != '' ORDER BY item_id;",
    [WDB_STMT_SYSCOLLECTOR_NETADDRESS_DELETE_AROUND] = "DELETE FROM sys_netaddr WHERE item_id < ? OR item_id > ? OR checksum = 'legacy' OR checksum = '';",
    [WDB_STMT_SYSCOLLECTOR_NETADDRESS_DELETE_RANGE] = "DELETE FROM sys_netaddr WHERE item_id > ? AND item_id < ?;",
    [WDB_STMT_SYSCOLLECTOR_NETADDRESS_DELETE_BY_PK] = "DELETE FROM sys_netaddr WHERE item_id = ?;",
    [WDB_STMT_SYSCOLLECTOR_NETADDRESS_CLEAR] = "DELETE FROM sys_netaddr;",
    [WDB_STMT_SYSCOLLECTOR_NETINFO_SELECT_CHECKSUM] = "SELECT checksum FROM sys_netiface WHERE checksum != 'legacy' AND checksum != '' ORDER BY item_id;",
    [WDB_STMT_SYSCOLLECTOR_NETINFO_SELECT_CHECKSUM_RANGE] = "SELECT checksum FROM sys_netiface WHERE item_id BETWEEN ? and ? AND checksum != 'legacy' AND checksum != '' ORDER BY item_id;",
    [WDB_STMT_SYSCOLLECTOR_NETINFO_DELETE_AROUND] = "DELETE FROM sys_netiface WHERE item_id < ? OR item_id > ? OR checksum = 'legacy' OR checksum = '';",
    [WDB_STMT_SYSCOLLECTOR_NETINFO_DELETE_RANGE] = "DELETE FROM sys_netiface WHERE item_id > ? AND item_id < ?;",
    [WDB_STMT_SYSCOLLECTOR_NETINFO_DELETE_BY_PK] = "DELETE FROM sys_netiface WHERE item_id = ?;",
    [WDB_STMT_SYSCOLLECTOR_NETINFO_CLEAR] = "DELETE FROM sys_netiface;",
    [WDB_STMT_SYSCOLLECTOR_HWINFO_SELECT_CHECKSUM] = "SELECT checksum FROM sys_hwinfo WHERE checksum != 'legacy' AND checksum != '' ORDER BY board_serial;",
    [WDB_STMT_SYSCOLLECTOR_HWINFO_SELECT_CHECKSUM_RANGE] = "SELECT checksum FROM sys_hwinfo WHERE board_serial BETWEEN ? and ? AND checksum != 'legacy' AND checksum != '' ORDER BY board_serial;",
    [WDB_STMT_SYSCOLLECTOR_HWINFO_DELETE_AROUND] = "DELETE FROM sys_hwinfo WHERE board_serial < ? OR board_serial > ? OR checksum = 'legacy' OR checksum = '';",
    [WDB_STMT_SYSCOLLECTOR_HWINFO_DELETE_RANGE] = "DELETE FROM sys_hwinfo WHERE board_serial > ? AND board_serial < ?;",
    [WDB_STMT_SYSCOLLECTOR_HWINFO_DELETE_BY_PK] = "DELETE FROM sys_hwinfo WHERE board_serial = ?;",
    [WDB_STMT_SYSCOLLECTOR_HWINFO_CLEAR] = "DELETE FROM sys_hwinfo;",
    [WDB_STMT_SYSCOLLECTOR_OSINFO_SELECT_CHECKSUM] = "SELECT checksum FROM sys_osinfo WHERE checksum != 'legacy' AND checksum != '' ORDER BY os_name;",
    [WDB_STMT_SYSCOLLECTOR_OSINFO_SELECT_CHECKSUM_RANGE] = "SELECT checksum FROM sys_osinfo WHERE os_name BETWEEN ? and ? AND checksum != 'legacy' AND checksum != '' ORDER BY os_name;",
    [WDB_STMT_SYSCOLLECTOR_OSINFO_DELETE_AROUND] = "DELETE FROM sys_osinfo WHERE os_name < ? OR os_name > ? OR checksum = 'legacy' OR checksum = '';",
    [WDB_STMT_SYSCOLLECTOR_OSINFO_DELETE_RANGE] = "DELETE FROM sys_osinfo WHERE os_name > ? AND os_name < ?;",
    [WDB_STMT_SYSCOLLECTOR_OSINFO_DELETE_BY_PK] = "DELETE FROM sys_osinfo WHERE os_name = ?;",
    [WDB_STMT_SYSCOLLECTOR_OSINFO_CLEAR] = "DELETE FROM sys_osinfo;",
    [WDB_STMT_SYS_HOTFIXES_GET] = "SELECT HOTFIX FROM SYS_HOTFIXES;",
    [WDB_STMT_SYS_PROGRAMS_GET] = "SELECT DISTINCT NAME, VERSION, ARCHITECTURE, VENDOR, FORMAT, SOURCE, CPE, MSU_NAME, ITEM_ID, DESCRIPTION, LOCATION, SIZE, INSTALL_TIME FROM SYS_PROGRAMS;",
};

/**
 * @brief Run a non-select query on the temporary table.
 *
 * @param[in] wdb Database to query for the table existence.
 * @param[in] query query to run.
 * @return Returns OS_SUCCESS on success or OS_INVALID on error.
 */
STATIC int wdb_execute_non_select_query(wdb_t * wdb, const char *query);

/**
 * @brief Run a select query on the temporary table.
 *
 * @param[in] wdb Database to query for the table existence.
 * @return Returns 0..100 on success or OS_INVALID on error.
 */
STATIC int wdb_select_from_temp_table(wdb_t * wdb);

/**
 * @brief Execute a select query that returns a single integer value.
 *
 * @param[in] wdb Database to query for the table existence.
 * @param[in] query Query to be executed.
 * @param[out] value Integer where the select value of the query will be stored.
 * @return Returns OS_SUCCESS on success or OS_INVALID on error.
 */
STATIC int wdb_execute_single_int_select_query(wdb_t * wdb, const char *query, int *value);

/**
 * @brief Get the fragmentation data of the last vacuum stored in the metadata table.
 *
 * @param[in] wdb Database to query for the table existence.
 * @param[out] last_vacuum_time Integer where the last_vacuum_time value will be stored.
 * @param[out] last_vacuum_value Integer where the last_vacuum_value value will be stored.
 * @return Returns OS_SUCCESS on success or OS_INVALID on error.
 */
STATIC int wdb_get_last_vacuum_data(wdb_t * wdb, int *last_vacuum_time, int *last_vacuum_value);

/**
 * @brief Execute any transaction
 * @param[in] wdb Database to query for the table existence.
 * @param[in] sql_transaction Query to be executed
 * @return 0 when succeed, !=0 otherwise.
*/
STATIC int wdb_any_transaction(wdb_t * wdb, const char* sql_transaction);

/**
 * @brief write the status of the transaction
 * @param[in] wdb Database to query for the table existence.
 * @param[in] state 1 when is Begin-transaction, 0 other transactions
 * @param[in] wdb_ptr_any_txn function that points to the transaction
 * @return 0 when succeed, !=0 otherwise.
*/
STATIC int wdb_write_state_transaction(wdb_t * wdb, uint8_t state, wdb_ptr_any_txn_t wdb_ptr_any_txn);

// Opens global database and stores it in DB pool. It returns a locked database or NULL
wdb_t * wdb_open_global(bool read) {
    char path[PATH_MAX + 1] = "";
    wdb_t * wdb = wdb_pool_get_or_create_global(WDB_GLOB_NAME, read);

    if (wdb->db == NULL) {
        // Try to open DB
        snprintf(path, sizeof(path), "%s/%s.db", WDB2_DIR, WDB_GLOB_NAME);

        if (sqlite3_open_v2(path, &wdb->db, SQLITE_OPEN_READWRITE, NULL)) {
            mdebug1("Global database not found, creating.");
            wdb_close(wdb, false);

            // Creating database
            if (OS_SUCCESS != wdb_create_global(path)) {
                merror("Couldn't create SQLite database '%s'", path);
                wdb_pool_leave_global(wdb);
                return NULL;
            }

            // Retry to open
            if (sqlite3_open_v2(path, &wdb->db, SQLITE_OPEN_READWRITE, NULL)) {
                merror("Can't open SQLite database '%s': %s", path, sqlite3_errmsg(wdb->db));
                wdb_close(wdb, false);
                wdb_pool_leave(wdb);
                return NULL;
            }
        } else {
            if (wdb_upgrade_global(wdb) == NULL || wdb->db == NULL) {
                wdb_pool_leave(wdb);
                return NULL;
            }
        }

        wdb_enable_foreign_keys(wdb->db);

        wdb_set_synchronous_normal(wdb);
    }

    return wdb;
}

wdb_t * wdb_open_mitre() {
    char path[PATH_MAX + 1];
    wdb_t * wdb = wdb_pool_get_or_create(WDB_MITRE_NAME);

    if (wdb->db != NULL) {
        return wdb;
    }

    // Try to open DB

    snprintf(path, sizeof(path), "%s/%s.db", WDB_DIR, WDB_MITRE_NAME);

    if (sqlite3_open_v2(path, &wdb->db, SQLITE_OPEN_READWRITE, NULL)) {
        merror("Can't open SQLite database '%s': %s", path, sqlite3_errmsg(wdb->db));
        wdb_close(wdb, false);
        wdb_pool_leave(wdb);
        return NULL;
    }

    return wdb;
}

// Open database for agent and store in DB pool. It returns a locked database or NULL
wdb_t * wdb_open_agent2(int agent_id) {
    char sagent_id[64];
    char path[PATH_MAX + 1];

    snprintf(sagent_id, sizeof(sagent_id), "%03d", agent_id);
    wdb_t * wdb = wdb_pool_get_or_create(sagent_id);

    if (wdb->db != NULL) {
        return wdb;
    }

    // Try to open DB

    snprintf(path, sizeof(path), "%s/%s.db", WDB2_DIR, sagent_id);

    if (sqlite3_open_v2(path, &wdb->db, SQLITE_OPEN_READWRITE, NULL)) {
        mdebug1("No SQLite database found for agent '%s', creating.", sagent_id);
        wdb_close(wdb, false);

        if (wdb_create_agent_db2(sagent_id) < 0) {
            merror("Couldn't create SQLite database '%s'", path);
            wdb_pool_leave(wdb);
            return NULL;
        }

        // Retry to open

        if (sqlite3_open_v2(path, &wdb->db, SQLITE_OPEN_READWRITE, NULL)) {
            merror("Can't open SQLite database '%s': %s", path, sqlite3_errmsg(wdb->db));
            wdb_close(wdb, false);
            wdb_pool_leave(wdb);
            return NULL;
        }
    } else {
        if (wdb_upgrade(wdb) == NULL) {
            wdb_pool_leave(wdb);
            return NULL;
        }
    }

    return wdb;
}

// Opens tasks database and stores it in DB pool. It returns a locked database or NULL
wdb_t * wdb_open_tasks() {
    char path[PATH_MAX + 1] = "";
    wdb_t * wdb = wdb_pool_get_or_create(WDB_TASK_NAME);

    if (wdb->db == NULL) {
        // Try to open DB
        snprintf(path, sizeof(path), "%s/%s.db", WDB_TASK_DIR, WDB_TASK_NAME);

        if (sqlite3_open_v2(path, &wdb->db, SQLITE_OPEN_READWRITE, NULL)) {
            mdebug1("Tasks database not found, creating.");
            wdb_close(wdb, false);

            // Creating database
            if (OS_SUCCESS != wdb_create_file(path, schema_task_manager_sql)) {
                merror("Couldn't create SQLite database '%s'", path);
                wdb_pool_leave(wdb);
                return NULL;
            }

            // Retry to open
            if (sqlite3_open_v2(path, &wdb->db, SQLITE_OPEN_READWRITE, NULL)) {
                merror("Can't open SQLite database '%s': %s", path, sqlite3_errmsg(wdb->db));
                wdb_close(wdb, false);
                wdb_pool_leave(wdb);
                return NULL;
            }
        }
    }

    return wdb;
}

/* Create database for agent from profile. Returns 0 on success or -1 on error. */
int wdb_create_agent_db2(const char * agent_id) {
    char path[OS_FLSIZE + 1];
    char path_temp[OS_FLSIZE + 1];
    char buffer[4096];
    FILE *source;
    FILE *dest;
    size_t nbytes;
    int result = 0;
    static pthread_mutex_t profile_mutex = PTHREAD_MUTEX_INITIALIZER;

    w_mutex_lock(&profile_mutex);

    if (!(source = wfopen(WDB_PROF_PATH, "r"))) {
        mdebug1("Profile database not found, creating.");

        if (wdb_create_profile() < 0) {
            w_mutex_unlock(&profile_mutex);
            return -1;
        }

        // Retry to open

        if (!(source = wfopen(WDB_PROF_PATH, "r"))) {
            w_mutex_unlock(&profile_mutex);
            merror("Couldn't open profile '%s'.", WDB_PROF_PATH);
            return -1;
        }
    }

    w_mutex_unlock(&profile_mutex);
    snprintf(path, OS_FLSIZE, "%s/%s.db", WDB2_DIR, agent_id);
    snprintf(path_temp, OS_FLSIZE, "%s.new", path);

    if (!(dest = wfopen(path_temp, "w"))) {
        merror("Couldn't create database '%s': %s (%d)", path, strerror(errno), errno);
        fclose(source);
        return -1;
    }

    while (nbytes = fread(buffer, 1, 4096, source), nbytes) {
        if (fwrite(buffer, 1, nbytes, dest) != nbytes) {
            unlink(path_temp);
            result = -1;
            break;
        }
    }

    fclose(source);
    if (fclose(dest) == -1) {
        merror("Couldn't create file %s completely", path_temp);
        return -1;
    }

    if (result < 0) {
        unlink(path_temp);
        return -1;
    }

    if (chmod(path_temp, 0640) < 0) {
        merror(CHMOD_ERROR, path_temp, errno, strerror(errno));
        unlink(path_temp);
        return -1;
    }

    if (OS_MoveFile(path_temp, path) < 0) {
        merror(RENAME_ERROR, path_temp, path, errno, strerror(errno));
        unlink(path_temp);
        return -1;
    }

    return 0;
}

/* Prepare SQL query with availability waiting */
int wdb_prepare(sqlite3 *db, const char *zSql, int nByte, sqlite3_stmt **stmt, const char **pzTail) {
    int result;
    int attempts;

    for (attempts = 0; (result = sqlite3_prepare_v2(db, zSql, nByte, stmt, pzTail)) == SQLITE_BUSY; attempts++) {
        if (attempts == MAX_ATTEMPTS) {
            mdebug1("Maximum attempts exceeded for sqlite3_prepare_v2()");
            return -1;
        }
    }

    return result;
}

/* Execute statement with availability waiting */
int wdb_step(sqlite3_stmt *stmt) {
    int result;
    int attempts;

    for (attempts = 0; (result = sqlite3_step(stmt)) == SQLITE_BUSY; attempts++) {
        if (attempts == MAX_ATTEMPTS) {
            mdebug1("Maximum attempts exceeded for sqlite3_step()");
            return -1;
        }
    }

    return result;
}

/* Begin transaction */
int wdb_begin(wdb_t * wdb) {
    return wdb_any_transaction(wdb, SQL_BEGIN);
}

int wdb_begin2(wdb_t * wdb) {
    return wdb_write_state_transaction(wdb, 1, wdb_begin);
}

/* Commit transaction */
int wdb_commit(wdb_t * wdb) {
    return wdb_any_transaction(wdb, SQL_COMMIT);
}

int wdb_commit2(wdb_t * wdb) {
    return wdb_write_state_transaction(wdb, 0, wdb_commit);
}

/* Rollback transaction */
int wdb_rollback(wdb_t * wdb) {
    return wdb_any_transaction(wdb, SQL_ROLLBACK);
}

int wdb_rollback2(wdb_t * wdb) {
    return wdb_write_state_transaction(wdb, 0, wdb_rollback);
}

/* Create global database */
int wdb_create_global(const char *path) {
    if (OS_SUCCESS != wdb_create_file(path, schema_global_sql))
        return OS_INVALID;
    else if (OS_SUCCESS != wdb_insert_info("openssl_support", "yes"))
        return OS_INVALID;
    else
        return OS_SUCCESS;
}

/* Create profile database */
int wdb_create_profile() {
    return wdb_create_file(WDB_PROF_PATH, schema_agents_sql);
}

/* Create new database file from SQL script */
int wdb_create_file(const char *path, const char *source) {
    const char *ROOT = "root";
    const char *sql;
    const char *tail;
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int result;
    uid_t uid;
    gid_t gid;

    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL)) {
        mdebug1("Couldn't create SQLite database '%s': %s", path, sqlite3_errmsg(db));
        sqlite3_close_v2(db);
        return OS_INVALID;
    }

    for (sql = source; sql && *sql; sql = tail) {
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, &tail) != SQLITE_OK) {
            mdebug1("Preparing statement: %s", sqlite3_errmsg(db));
            sqlite3_close_v2(db);
            return OS_INVALID;
        }

        result = wdb_step(stmt);

        switch (result) {
        case SQLITE_MISUSE:
        case SQLITE_ROW:
        case SQLITE_DONE:
            break;
        default:
            mdebug1("Stepping statement: %s", sqlite3_errmsg(db));
            sqlite3_finalize(stmt);
            sqlite3_close_v2(db);
            return OS_INVALID;

        }

        sqlite3_finalize(stmt);
    }

    sqlite3_close_v2(db);

    switch (getuid()) {
    case -1:
        merror("getuid(): %s (%d)", strerror(errno), errno);
        return OS_INVALID;

    case 0:
        uid = Privsep_GetUser(ROOT);
        gid = Privsep_GetGroup(GROUPGLOBAL);

        if (uid == (uid_t) - 1 || gid == (gid_t) - 1) {
            merror(USER_ERROR, ROOT, GROUPGLOBAL, strerror(errno), errno);
            return OS_INVALID;
        }

        if (chown(path, uid, gid) < 0) {
            merror(CHOWN_ERROR, path, errno, strerror(errno));
            return OS_INVALID;
        }

        break;

    default:
        mdebug1("Ignoring chown when creating file from SQL.");
        break;
    }

    if (chmod(path, 0640) < 0) {
        merror(CHMOD_ERROR, path, errno, strerror(errno));
        return OS_INVALID;
    }

    return OS_SUCCESS;
}

/* Rebuild database. Returns 0 on success or -1 on error. */
int wdb_vacuum(wdb_t * wdb) {
    sqlite3_stmt *stmt;
    int result;

    if (!wdb_prepare(wdb->db, SQL_VACUUM, -1, &stmt, NULL)) {
        result = wdb_step(stmt) == SQLITE_DONE ? 0 : -1;
        sqlite3_finalize(stmt);
    } else {
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        result = -1;
    }

    return result;
}

/* Calculate the fragmentation state of a db. Returns 0-100 on success or OS_INVALID on error. */
int wdb_get_db_state(wdb_t * wdb) {
    int result = OS_INVALID;

    if (wdb_execute_non_select_query(wdb, SQL_CREATE_TEMP_TABLE) == OS_INVALID) {
        mdebug1("Error creating temporary table.");
        return OS_INVALID;
    }

    if (wdb_execute_non_select_query(wdb, SQL_TRUNCATE_TEMP_TABLE) == OS_INVALID) {
        mdebug1("Error truncate temporary table.");
        return OS_INVALID;
    }

    if (wdb_execute_non_select_query(wdb, SQL_INSERT_INTO_TEMP_TABLE) != OS_INVALID) {
        if (result = wdb_select_from_temp_table(wdb), result == OS_INVALID) {
            mdebug1("Error in select from temporary table.");
        }
    } else {
        mdebug1("Error inserting into temporary table.");
        result = OS_INVALID;
    }

    return result;
}

/* Calculate the percentage of free pages of a db. Returns zero or greater than zero on success or OS_INVALID on error.*/
int wdb_get_db_free_pages_percentage(wdb_t * wdb) {
    int total_pages = 0;
    int free_pages = 0;

    if (wdb_execute_single_int_select_query(wdb, SQL_SELECT_PAGE_COUNT, &total_pages) != OS_SUCCESS) {
        mdebug1("Error getting total_pages for '%s' database.", wdb->id);
        return OS_INVALID;
    }

    if (wdb_execute_single_int_select_query(wdb, SQL_SELECT_PAGE_FREE, &free_pages) != OS_SUCCESS) {
        mdebug1("Error getting free_pages for '%s' database.", wdb->id);
        return OS_INVALID;
    }

    return (int)(((float)free_pages / (float)total_pages) * 100.00);
}

/* Execute a select query that returns a single integer value. Returns OS_SUCCESS on success or OS_INVALID on error. */
STATIC int wdb_execute_single_int_select_query(wdb_t * wdb, const char *query, int *value) {
    sqlite3_stmt *stmt = NULL;
    int result = OS_INVALID;

    if (query == NULL) {
        mdebug1("wdb_execute_single_int_select_query(): null query.");
        return OS_INVALID;
    }

    if (sqlite3_prepare_v2(wdb->db, query, -1, &stmt, NULL) != SQLITE_OK) {
        mdebug1("sqlite3_prepare_v2(): %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    if (wdb_step(stmt) == SQLITE_ROW) {
        *value = sqlite3_column_int(stmt, 0);
        result = OS_SUCCESS;
    } else {
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
    }

    sqlite3_finalize(stmt);

    return result;
}

/* Run a query without selecting any fields */
STATIC int wdb_execute_non_select_query(wdb_t * wdb, const char *query) {
    sqlite3_stmt *stmt = NULL;
    int result = OS_SUCCESS;

    if (query == NULL) {
        mdebug1("wdb_execute_non_select_query(): null query.");
        return OS_INVALID;
    }

    if (sqlite3_prepare_v2(wdb->db, query, -1, &stmt, NULL) != SQLITE_OK) {
        mdebug1("sqlite3_prepare_v2(): %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    if (result = wdb_step(stmt) != SQLITE_DONE, result) {
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        result = OS_INVALID;
    }

    sqlite3_finalize(stmt);
    return result;
}

/* Select from temp table */
STATIC int wdb_select_from_temp_table(wdb_t * wdb) {
    sqlite3_stmt *stmt = NULL;
    int result = 0;

    if (sqlite3_prepare_v2(wdb->db, SQL_SELECT_TEMP_TABLE, -1, &stmt, NULL) != SQLITE_OK) {
        mdebug1("sqlite3_prepare_v2(): %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    if (result = wdb_step(stmt), SQLITE_ROW == result) {
        result = 100 - (int)(sqlite3_column_double(stmt, 0) * 100);
    } else {
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        result = OS_INVALID;
    }

    sqlite3_finalize(stmt);

    return result;
}

/* Insert key-value pair into global.db info table */
int wdb_insert_info(const char *key, const char *value) {
    char path[PATH_MAX + 1] = "";
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int result = OS_SUCCESS;

    snprintf(path, sizeof(path), "%s/%s.db", WDB2_DIR, WDB_GLOB_NAME);

    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE, NULL)) {
        mdebug1("Couldn't open SQLite database '%s': %s", path, sqlite3_errmsg(db));
        sqlite3_close_v2(db);
        return OS_INVALID;
    }

    if (wdb_prepare(db, SQL_INSERT_INFO, -1, &stmt, NULL)) {
        mdebug1("SQLite: %s", sqlite3_errmsg(db));
        return OS_INVALID;
    }

    sqlite3_bind_text(stmt, 1, key, -1, NULL);
    sqlite3_bind_text(stmt, 2, value, -1, NULL);

    result = wdb_step(stmt) == SQLITE_DONE ? OS_SUCCESS : OS_INVALID;

    sqlite3_finalize(stmt);
    sqlite3_close_v2(db);

    return result;
}

wdb_t * wdb_init(const char * id) {
    wdb_t * wdb;
    os_calloc(1, sizeof(wdb_t), wdb);
    if (strcmp(id, WDB_GLOB_NAME) == 0) {
        w_rwlock_init(&wdb->rwlock, NULL);
    }
    else {
        w_mutex_init(&wdb->mutex, NULL);
    }
    os_strdup(id, wdb->id);
    wdb->enabled = true;
    return wdb;
}

void wdb_destroy(wdb_t * wdb) {
    os_free(wdb->id);
    w_mutex_destroy(&wdb->mutex);
    free(wdb);
}

void wdb_close_all() {
    char ** keys = wdb_pool_keys();

    for (int i = 0; keys[i]; i++) {
        wdb_t * node = wdb_pool_get(keys[i]);

        if (node != NULL && node->db != NULL) {
            wdb_close(node, true);
        }

        wdb_pool_leave(node);
    }

    free_strarray(keys);
}

void wdb_commit_old() {
    char ** keys = wdb_pool_keys();

    for (int i = 0; keys[i]; i++) {
        wdb_t * node = wdb_pool_get(keys[i]);

        if (node == NULL) {
            continue;
        }

        time_t cur_time = time(NULL);

        // Commit condition: more than commit_time_min seconds elapsed from the last query, or more than commit_time_max elapsed from the transaction began.

        if (node->transaction && (cur_time - node->last > wconfig.commit_time_min || cur_time - node->transaction_begin_time > wconfig.commit_time_max)) {
            struct timespec ts_start, ts_end;

            gettime(&ts_start);
            wdb_commit2(node);
            gettime(&ts_end);

            mdebug2("Agent '%s' database commited. Time: %.3f ms.", node->id, time_diff(&ts_start, &ts_end) * 1e3);
        }

        wdb_pool_leave(node);
    }

    free_strarray(keys);
}

void wdb_check_fragmentation() {
    char ** keys = wdb_pool_keys();

    for (int i = 0; keys[i]; i++) {
        int last_vacuum_time;
        int last_vacuum_value;
        int current_fragmentation;
        int current_free_pages_percentage;
        int fragmentation_after_vacuum;

        wdb_t * node = wdb_pool_get(keys[i]);

        if (node == NULL) {
            continue;
        }

        if (node->db == NULL) {
            wdb_pool_leave(node);
            continue;
        }

        current_fragmentation = wdb_get_db_state(node);
        current_free_pages_percentage = wdb_get_db_free_pages_percentage(node);
        if (current_fragmentation == OS_INVALID || current_free_pages_percentage == OS_INVALID) {
            merror("Couldn't get current state for the database '%s'", node->id);
        } else {
            if (wdb_get_last_vacuum_data(node, &last_vacuum_time, &last_vacuum_value) != OS_SUCCESS) {
                merror("Couldn't get last vacuum info for the database '%s'", node->id);
            } else {
                // conditions for running a vacuum:
                // 'current_free_pages_percentage >= wconfig.free_pages_percentage' is always necessary
                // one of the following conditions is also required:
                // 'current_fragmentation > wconfig.max_fragmentation'
                // OR
                // 'current_fragmentation > wconfig.fragmentation_threshold' AND 'last_vacuum_time == 0'
                // OR
                // 'current_fragmentation > wconfig.fragmentation_threshold' AND 'last_vacuum_time > 0' AND 'current_fragmentation > last_vacuum_value + wconfig.fragmentation_delta'
                if (current_free_pages_percentage >= wconfig.free_pages_percentage &&
                    (current_fragmentation > wconfig.max_fragmentation ||
                    (current_fragmentation > wconfig.fragmentation_threshold && (last_vacuum_time == 0  ||
                    (last_vacuum_time > 0 && current_fragmentation > last_vacuum_value + wconfig.fragmentation_delta))))) {
                    struct timespec ts_start, ts_end;

                    if (wdb_commit2(node) < 0) {
                        merror("Couldn't execute commit statement, before vacuum, for the database '%s'", node->id);
                        wdb_pool_leave(node);
                        continue;
                    }

                    wdb_finalize_all_statements(node);

                    gettime(&ts_start);
                    if (wdb_vacuum(node) < 0) {
                        merror("Couldn't execute vacuum for the database '%s'", node->id);
                        wdb_pool_leave(node);
                        continue;
                    }
                    gettime(&ts_end);
                    mdebug1("Vacuum executed on the '%s' database. Time: %.3f ms.", node->id, time_diff(&ts_start, &ts_end) * 1e3);

                    // save fragmentation after vacuum
                    if (fragmentation_after_vacuum = wdb_get_db_state(node), fragmentation_after_vacuum == OS_INVALID) {
                        merror("Couldn't get fragmentation after vacuum for the database '%s'", node->id);
                    } else {
                        char str_vacuum_time[OS_SIZE_128] = { '\0' };
                        char str_vacuum_value[OS_SIZE_128] = { '\0' };

                        snprintf(str_vacuum_time, OS_SIZE_128, "%ld", time(0));
                        snprintf(str_vacuum_value, OS_SIZE_128, "%d", fragmentation_after_vacuum);
                        if (wdb_update_last_vacuum_data(node, str_vacuum_time, str_vacuum_value) != OS_SUCCESS) {
                            merror("Couldn't update last vacuum info for the database '%s'", node->id);
                        }
                        // check after vacuum
                        if (fragmentation_after_vacuum >= current_fragmentation) {
                            mwarn("After vacuum, the database '%s' has become just as fragmented or worse", node->id);
                        }
                    }
                }
            }
        }

        wdb_pool_leave(node);
    }

    free_strarray(keys);
}

STATIC int wdb_get_last_vacuum_data(wdb_t * wdb, int *last_vacuum_time, int *last_vacuum_value) {
   int result = OS_INVALID;
   cJSON *data = NULL;

   if (data = wdb_exec(wdb->db, SQL_METADATA_GET_FRAGMENTATION_DATA), data) {
        int response_size = 0;
        int tmp_vacuum_time = -1;
        int tmp_vacuum_value = -1;

        if (response_size = cJSON_GetArraySize(data), response_size == 0) {
            mdebug2("No vacuum data in metadata table.");
            *last_vacuum_time = 0;
            *last_vacuum_value = 0;
            cJSON_Delete(data);
            return OS_SUCCESS;
        }

        for (int i = 0; i < response_size; i++) {
            cJSON *item;
            cJSON *key_json;
            cJSON *value_json;

            if (item = cJSON_GetArrayItem(data, i), item == NULL) {
                merror("It was not possible to get items from databes response.");
                cJSON_Delete(data);
                return OS_INVALID;
            }

            key_json = cJSON_GetObjectItem(item, "key");
            value_json = cJSON_GetObjectItem(item, "value");
            if (key_json == NULL || value_json == NULL) {
                merror("It was not possible to get key or value from database response.");
            } else {
                if (strcmp(key_json->valuestring, "last_vacuum_time") == 0) {
                    tmp_vacuum_time = atoi(value_json->valuestring);
                } else if (strcmp(key_json->valuestring, "last_vacuum_value") == 0) {
                    tmp_vacuum_value = atoi(value_json->valuestring);
                }
            }
        }

        if (tmp_vacuum_time != -1 && tmp_vacuum_value != -1) {
            *last_vacuum_time = tmp_vacuum_time;
            *last_vacuum_value = tmp_vacuum_value;
            result = OS_SUCCESS;
        } else {
            merror("Missing field last_vacuum_time or last_vacuum_value from metadata table.");
        }
        cJSON_Delete(data);
    }

    return result;
}

int wdb_update_last_vacuum_data(wdb_t * wdb, const char *last_vacuum_time, const char *last_vacuum_value) {
    sqlite3_stmt *stmt = NULL;
    int result = OS_INVALID;

    if (sqlite3_prepare_v2(wdb->db, SQL_METADATA_UPDATE_FRAGMENTATION_DATA, -1, &stmt, NULL) != SQLITE_OK) {
        mdebug1("sqlite3_prepare_v2(): %s", sqlite3_errmsg(wdb->db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, last_vacuum_time, -1, NULL);
    sqlite3_bind_text(stmt, 2, last_vacuum_value, -1, NULL);

    if (result = wdb_step(stmt),
        result != SQLITE_DONE && result != SQLITE_CONSTRAINT) {
        merror(DB_SQL_ERROR, sqlite3_errmsg(wdb->db));
        sqlite3_finalize(stmt);
        return OS_INVALID;
    }

    sqlite3_finalize(stmt);
    return OS_SUCCESS;
}

void wdb_close_old() {
    char ** keys = wdb_pool_keys();
    int closed = 0;

    for (int i = 0; keys[i] && (int)wdb_pool_size() - closed > wconfig.open_db_limit; i++) {
        wdb_t * node = wdb_pool_get(keys[i]);

        if (node == NULL) {
            continue;
        }

        if (node->db != NULL && node->refcount == 1 && strcmp(node->id, WDB_GLOB_NAME) != 0) {
            mdebug2("Closing database for agent %s", node->id);
            wdb_close(node, true);
            closed++;
        }

        wdb_pool_leave(node);

    }

    wdb_pool_clean();

    free_strarray(keys);
}

int wdb_exec_stmt_silent(sqlite3_stmt* stmt) {
    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
    case SQLITE_DONE:
        return OS_SUCCESS;
        break;
    default:
        mdebug1("SQL statement execution failed");
        return OS_INVALID;
    }
}

cJSON* wdb_exec_row_stmt(sqlite3_stmt* stmt, int* status, bool column_mode) {
    if (STMT_SINGLE_COLUMN == column_mode) {
        return wdb_exec_row_stmt_single_column(stmt, status);
    } else if (STMT_MULTI_COLUMN == column_mode) {
        return wdb_exec_row_stmt_multi_column(stmt, status);
    } else {
        mdebug2("Invalid column mode");
        return NULL;
    }
}

cJSON* wdb_exec_row_stmt_multi_column(sqlite3_stmt* stmt, int* status) {
    cJSON* result = NULL;

    int _status = wdb_step(stmt);
    if (SQLITE_ROW == _status) {
        int count = sqlite3_column_count(stmt);
        if (count > 0) {
            result = cJSON_CreateObject();

            for (int i = 0; i < count; i++) {
                switch (sqlite3_column_type(stmt, i)) {
                case SQLITE_INTEGER:
                case SQLITE_FLOAT:
                    cJSON_AddNumberToObject(result, sqlite3_column_name(stmt, i), sqlite3_column_double(stmt, i));
                    break;

                case SQLITE_TEXT:
                case SQLITE_BLOB:
                    cJSON_AddStringToObject(result, sqlite3_column_name(stmt, i), (const char *)sqlite3_column_text(stmt, i));
                    break;

                case SQLITE_NULL:
                default:
                    ;
                }
            }
        }
    }
    else if (SQLITE_DONE != _status) {
        mdebug1("SQL statement execution failed");
    }

    if (status) {
        *status = _status;
    }

    return result;
}

cJSON* wdb_exec_stmt_sized(sqlite3_stmt* stmt, const size_t max_size, int* status, bool column_mode) {
    if (!stmt) {
        mdebug1("Invalid SQL statement.");
        *status = SQLITE_ERROR;
        return NULL;
    }

    cJSON* result = cJSON_CreateArray();
    int result_size = 2; //'[]' json array
    cJSON* row = NULL;
    bool fit = true;
    while (fit && (row = wdb_exec_row_stmt(stmt, status, column_mode))) {
        char *row_str = cJSON_PrintUnformatted(row);
        size_t row_len = strlen(row_str)+1;
        //Check if new agent fits in response
        if (result_size+row_len < max_size) {
            cJSON_AddItemToArray(result, row);
            result_size += row_len;
        }
        else {
            fit = false;
            cJSON_Delete(row);
            row = NULL;
        }
        os_free(row_str);
    }

    if (*status != SQLITE_DONE && *status != SQLITE_ROW) {
        cJSON_Delete(result);
        result = NULL;
    }

    return result;
}

int wdb_exec_stmt_send(sqlite3_stmt* stmt, int peer) {
    if (!stmt) {
        mdebug1("Invalid SQL statement.");
        return OS_INVALID;
    }
    if (OS_SetSendTimeout(peer, WDB_BLOCK_SEND_TIMEOUT_S) < 0) {
        merror("Socket %d error setting timeout: %s (%d)", peer, strerror(errno), errno);
        return OS_SOCKTERR;
    }

    int status = OS_SUCCESS;
    int sql_status = SQLITE_ERROR;
    cJSON * row = NULL;
    char* response = NULL;
    // Every row will be the payload of a message with the format "due {payload}"
    const char* header = "due ";
    int header_size = strlen(header);
    // Allocating the memory where all the responses will be dumped, it will contain the header+payload
    os_calloc(OS_MAXSTR, sizeof(char), response);
    // Coping the "due" header into the response buffer
    memcpy(response, header, header_size);
    // Each row is dumped into the payload section of the buffer, so the pointer and the tailing available space for the payload are obtained
    char* payload = response + header_size;
    int payload_size = OS_MAXSTR - header_size;

    while ((row = wdb_exec_row_stmt(stmt, &sql_status, STMT_MULTI_COLUMN))) {
        bool row_fits = cJSON_PrintPreallocated(row, payload, payload_size, FALSE);
        cJSON_Delete(row);
        if (row_fits) {
            if (OS_SendSecureTCP(peer, strlen(response), response) < 0) {
                merror("Socket %d error: %s (%d)", peer, strerror(errno), errno);
                status = OS_SOCKTERR;
                break;
            }
        }
        else {
            merror("SQL row response for statement %s is too big to be sent", sqlite3_sql(stmt));
            status = OS_SIZELIM;
            break;
        }
    }
    if (status == OS_SUCCESS && sql_status != SQLITE_DONE) {
        status = OS_INVALID;
    }

    os_free(response);

    return status;
}

cJSON* wdb_exec_stmt(sqlite3_stmt* stmt) {
    cJSON * result;
    cJSON * row;

    if (!stmt) {
        mdebug1("Invalid SQL statement.");
        return NULL;
    }

    int status = SQLITE_ERROR;
    result = cJSON_CreateArray();
    while ((row = wdb_exec_row_stmt(stmt, &status, STMT_MULTI_COLUMN))) {
        cJSON_AddItemToArray(result, row);
    }

    if (status != SQLITE_DONE) {
        cJSON_Delete(result);
        result = NULL;
    }

    return result;
}

cJSON* wdb_exec_row_stmt_single_column(sqlite3_stmt* stmt, int* status) {
    cJSON* result = NULL;
    int _status = SQLITE_ERROR;

    if (!stmt) {
        mdebug1("Invalid SQL statement.");
        return NULL;
    }

    _status = wdb_step(stmt);
    if (SQLITE_ROW == _status) {
        int count = sqlite3_column_count(stmt);
        // Every step should return only one element. Extra columns will be ignored
        if (count > 0) {
            switch (sqlite3_column_type(stmt, 0)) {
            case SQLITE_INTEGER:
            case SQLITE_FLOAT:
                result = cJSON_CreateNumber(sqlite3_column_double(stmt, 0));
                break;

            case SQLITE_TEXT:
            case SQLITE_BLOB:
                result = cJSON_CreateString((const char *)sqlite3_column_text(stmt, 0));
                break;

            case SQLITE_NULL:
            default:
                ;
            }
        }
    } else if (_status != SQLITE_DONE) {
        mdebug1("SQL statement execution failed");
    }

    if (status) {
        *status = _status;
    }

    return result;
}

cJSON* wdb_exec(sqlite3* db, const char * sql) {
    sqlite3_stmt * stmt = NULL;
    cJSON * result = NULL;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        mdebug1("sqlite3_prepare_v2(): %s", sqlite3_errmsg(db));
        mdebug2("SQL: %s", sql);
        return NULL;
    }

    result = wdb_exec_stmt(stmt);

    if (!result) {
        mdebug1("wdb_exec_stmt(): %s", sqlite3_errmsg(db));
    }

    sqlite3_finalize(stmt);
    return result;
}

int wdb_close(wdb_t * wdb, bool commit) {
    int result;

    if (wdb->transaction && commit) {
        wdb_commit2(wdb);
    }

    wdb_finalize_all_statements(wdb);
    result = sqlite3_close_v2(wdb->db);

    if (result == SQLITE_OK) {
        wdb->db = NULL;
        return OS_SUCCESS;
    } else {
        merror("DB(%s) wdb_close(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
}

void wdb_finalize_all_statements(wdb_t * wdb) {
    for (int i = 0; i < WDB_STMT_SIZE; i++) {
        if (wdb->stmt[i]) {
            sqlite3_finalize(wdb->stmt[i]);
            wdb->stmt[i] = NULL;
        }
    }

    struct stmt_cache_list *node_stmt = wdb->cache_list;
    struct stmt_cache_list *temp = NULL;
    while (node_stmt) {
        if (node_stmt->value.stmt) {
            // value.stmt would be free in sqlite3_finalize.
            sqlite3_finalize(node_stmt->value.stmt);
            node_stmt->value.stmt = NULL;
        }
        os_free(node_stmt->value.query);
        node_stmt->value.query = NULL;
        temp = node_stmt->next;
        os_free(node_stmt);
        node_stmt = temp;
    }

    wdb->cache_list = NULL;
}

int wdb_stmt_cache(wdb_t * wdb, int index) {
    if (index >= WDB_STMT_SIZE) {
        merror("DB(%s) SQL statement index (%d) out of bounds", wdb->id, index);
        return -1;
    }
    if (!wdb->stmt[index]) {
        if (sqlite3_prepare_v2(wdb->db, SQL_STMT[index], -1, wdb->stmt + index, NULL) != SQLITE_OK) {
            merror("DB(%s) sqlite3_prepare_v2() stmt(%d): %s", wdb->id, index, sqlite3_errmsg(wdb->db));
            return -1;
        }
    } else {
        sqlite3_reset(wdb->stmt[index]);
        sqlite3_clear_bindings(wdb->stmt[index]);
    }

    return 0;
}

// Execute SQL script into an database
int wdb_sql_exec(wdb_t *wdb, const char *sql_exec) {
    char *sql_error;
    int result = 0;

    sqlite3_exec(wdb->db, sql_exec, NULL, NULL, &sql_error);

    if (sql_error) {
        mwarn("DB(%s) wdb_sql_exec returned error: '%s'", wdb->id, sql_error);
        sqlite3_free(sql_error);
        result = -1;
    }

    return result;
}

/* Delete a database file */
int wdb_remove_database(const char * agent_id) {
    char path[PATH_MAX];

    snprintf(path, PATH_MAX, "%s/%s.db", WDB2_DIR, agent_id);
    int result = unlink(path);

    if (result == -1) {
        mdebug1(UNLINK_ERROR, path, errno, strerror(errno));
    }

    return result;
}

cJSON *wdb_remove_multiple_agents(char *agent_list) {
    cJSON *response = NULL;
    cJSON *json_agents = NULL;
    wdb_t *wdb;
    char **agents;
    char *next;
    char *json_formated;
    char path[PATH_MAX];
    char agent[OS_SIZE_128];
    long int agent_id;
    int n = 0;

    if (!agent_list || strcmp(agent_list, "") == 0 || strcmp(agent_list, " ") == 0) {
        return json_agents;
    }

    response = cJSON_CreateObject();
    cJSON_AddItemToObject(response, "agents", json_agents = cJSON_CreateObject());

    // Get agents id separated by whitespace
    agents = w_strtok(agent_list);

    for (n = 0; agents && agents[n]; n++) {
        if (strcmp(agents[n], "") != 0) {
            next = agents[n + 1];
            agent_id = strtol(agents[n], &next, 10);
            const char * result = "ok";

            // Check for valid ID
            if ((errno == ERANGE) || (errno == EINVAL) || *next) {
                mwarn("Invalid agent ID when deleting database '%s'\n", agents[n]);
                result = "Invalid agent ID";
            } else {
                snprintf(path, PATH_MAX, "%s/%03ld.db", WDB2_DIR, agent_id);
                snprintf(agent, OS_SIZE_128, "%03ld", agent_id);

                // Close the database only if it was open

                wdb = wdb_pool_get(agent);
                if (wdb) {
                    if (wdb_close(wdb, FALSE) < 0) {
                        result = "Can't close";
                    }
                    wdb_pool_leave(wdb);
                }

                mdebug1("Removing db for agent '%s'", agent);

                if (wdb_remove_database(agent) < 0) {
                    result = "Can't delete";
                }
            }

            cJSON_AddStringToObject(json_agents, agent, result);
        }
    }

    free_strarray(agents);
    json_formated = cJSON_PrintUnformatted(response);
    mdebug1("Deleting databases. JSON output: %s", json_formated);
    os_free(json_formated);
    return response;
}

// Set the database journal mode to write-ahead logging
int wdb_journal_wal(sqlite3 *db) {
    char *sql_error = NULL;

    sqlite3_exec(db, SQL_STMT[WDB_STMT_PRAGMA_JOURNAL_WAL], NULL, NULL, &sql_error);

    if (sql_error != NULL) {
        merror("Cannot set database journaling mode to WAL: '%s'", sql_error);
        sqlite3_free(sql_error);
        return -1;
    }

    return 0;
}

int wdb_enable_foreign_keys(sqlite3 *db) {
    char *sql_error = NULL;

    sqlite3_exec(db, SQL_STMT[WDB_STMT_PRAGMA_ENABLE_FOREIGN_KEYS], NULL, NULL, &sql_error);

    if (sql_error != NULL) {
        merror("Cannot enable foreign keys: '%s'", sql_error);
        sqlite3_free(sql_error);
        return -1;
    }

    return 0;
}

sqlite3_stmt* wdb_init_stmt_in_cache(wdb_t * wdb, wdb_stmt statement_index) {
    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return NULL;
    }

    if (wdb_stmt_cache(wdb, statement_index) < 0) {
        mdebug1("Cannot cache statement");
        return NULL;
    }

    return wdb->stmt[statement_index];
}

sqlite3_stmt * wdb_get_cache_stmt(wdb_t * wdb, char const *query) {
    sqlite3_stmt * ret_val = NULL;
    if (NULL != wdb && NULL != query) {
        struct stmt_cache_list *node_stmt = NULL;
        for (node_stmt = wdb->cache_list; node_stmt ; node_stmt=node_stmt->next) {
            if (node_stmt->value.query) {
                if (strcmp(node_stmt->value.query, query) == 0)
                {
                    if (sqlite3_reset(node_stmt->value.stmt) != SQLITE_OK || sqlite3_clear_bindings(node_stmt->value.stmt) != SQLITE_OK) {
                        mdebug1("DB(%s) sqlite3_reset() stmt(%s): %s", wdb->id, sqlite3_sql(node_stmt->value.stmt), sqlite3_errmsg(wdb->db));
                    }
                    ret_val = node_stmt->value.stmt;
                    break;
                }
            }
        }
        bool is_first_element = true;
        if (NULL == ret_val) {
            struct stmt_cache_list *new_item = NULL;
            if (NULL == wdb->cache_list) {
                os_malloc(sizeof(struct stmt_cache_list), wdb->cache_list);
                new_item = wdb->cache_list;
            } else {
                node_stmt = wdb->cache_list;
                while (node_stmt->next) {
                    node_stmt = node_stmt->next;
                }
                is_first_element = false;
                os_malloc(sizeof(struct stmt_cache_list), node_stmt->next);
                //Add element in the end list
                new_item = node_stmt->next;
            }
            new_item->next = NULL;
            os_malloc(strlen(query) + 1, new_item->value.query);
            strcpy(new_item->value.query, query);

            if (sqlite3_prepare_v2(wdb->db, new_item->value.query, -1, &new_item->value.stmt, NULL) != SQLITE_OK) {
                merror("DB(%s) sqlite3_prepare_v2() : %s", wdb->id, sqlite3_errmsg(wdb->db));
                os_free(new_item->value.query);
                if (is_first_element) {
                    os_free(wdb->cache_list);
                    wdb->cache_list = NULL;
                } else {
                    os_free(node_stmt->next);
                    node_stmt->next = NULL;
                }
            } else {
                ret_val = new_item->value.stmt;
            }
        }
    }
    return ret_val;
}

cJSON* wdb_get_internal_config() {
    cJSON* wazuh_db_config = cJSON_CreateObject();
    cJSON *root = cJSON_CreateObject();

    cJSON_AddNumberToObject(wazuh_db_config, "commit_time_max", wconfig.commit_time_max);
    cJSON_AddNumberToObject(wazuh_db_config, "commit_time_min", wconfig.commit_time_min);
    cJSON_AddNumberToObject(wazuh_db_config, "open_db_limit", wconfig.open_db_limit);
    cJSON_AddNumberToObject(wazuh_db_config, "worker_pool_size", wconfig.worker_pool_size);
    cJSON_AddNumberToObject(wazuh_db_config, "fragmentation_threshold", wconfig.fragmentation_threshold);
    cJSON_AddNumberToObject(wazuh_db_config, "fragmentation_delta", wconfig.fragmentation_delta);
    cJSON_AddNumberToObject(wazuh_db_config, "free_pages_percentage", wconfig.free_pages_percentage);
    cJSON_AddNumberToObject(wazuh_db_config, "max_fragmentation", wconfig.max_fragmentation);
    cJSON_AddNumberToObject(wazuh_db_config, "check_fragmentation_interval", wconfig.check_fragmentation_interval);

    cJSON_AddItemToObject(root, "wazuh_db", wazuh_db_config);

    return root;
}

cJSON* wdb_get_config() {
    cJSON *root = cJSON_CreateObject();
    cJSON* wdb_config = cJSON_CreateObject();
    cJSON* j_wdb_backup = cJSON_CreateArray();

    for (int i = 0; i < WDB_LAST_BACKUP; i++) {
        cJSON* j_wdb_backup_settings_node = cJSON_CreateObject();

        switch (i) {
            case WDB_GLOBAL_BACKUP:
                cJSON_AddStringToObject(j_wdb_backup_settings_node, "database", "global");
                break;
            default:
                break;
        }

        cJSON_AddBoolToObject(j_wdb_backup_settings_node, "enabled", wconfig.wdb_backup_settings[i]->enabled);
        cJSON_AddNumberToObject(j_wdb_backup_settings_node, "interval", wconfig.wdb_backup_settings[i]->interval);
        cJSON_AddNumberToObject(j_wdb_backup_settings_node, "max_files", wconfig.wdb_backup_settings[i]->max_files);

        cJSON_AddItemToArray(j_wdb_backup, j_wdb_backup_settings_node);
    }

    cJSON_AddItemToObject(wdb_config, "backup", j_wdb_backup);
    cJSON_AddItemToObject(root, "wdb", wdb_config);

    return root;
}

bool wdb_check_backup_enabled() {
    bool result = false;

    for (int i = 0; i < WDB_LAST_BACKUP; i++) {
        if (wconfig.wdb_backup_settings[i]->enabled) {
            result = true;
            break;
        }
    }

    return result;
}

STATIC int wdb_any_transaction(wdb_t * wdb, const char* sql_transaction) {
    sqlite3_stmt *stmt = NULL;
    int result = 0;

    if (sqlite3_prepare_v2(wdb->db, sql_transaction, -1, &stmt, NULL) != SQLITE_OK) {
        mdebug1("sqlite3_prepare_v2(): %s", sqlite3_errmsg(wdb->db));
        return -1;
    }

    if (result = wdb_step(stmt) != SQLITE_DONE, result) {
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        result = -1;
    }

    sqlite3_finalize(stmt);
    return result;
}

STATIC int wdb_write_state_transaction(wdb_t * wdb, uint8_t state, wdb_ptr_any_txn_t wdb_ptr_any_txn) {
    if (wdb != NULL) {
        if (((state == 1) ? wdb->transaction : !wdb->transaction)) {
            return 0;
        }

        if (wdb_ptr_any_txn != NULL) {
            if (wdb_ptr_any_txn(wdb) == -1) {
                return -1;
            }
        }

        wdb->transaction = state;
        if (1 == state) {
            wdb->transaction_begin_time = time(NULL);
        }
    }
    return 0;
}

int wdb_set_synchronous_normal(wdb_t * wdb) {
    int returnState = 0;
    char * sqlError = NULL;

    sqlite3_exec(wdb->db, SQL_STMT[WDB_STMT_PRAGMA_SYNCHRONOUS_NORMAL], NULL, NULL, &sqlError);

    if (sqlError != NULL) {
        merror("Cannot set synchronous mode: '%s'", sqlError);
        sqlite3_free(sqlError);
        returnState = -1;
    }

    return returnState;
}
