/*
 * Wazuh SQLite integration
 * Copyright (C) 2015-2020, Wazuh Inc.
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

#ifdef WIN32
#define getuid() 0
#define chown(x, y, z) 0
#endif

#define BUSY_SLEEP 1
#define MAX_ATTEMPTS 1000

/// Strings used with wdbc_result.
const char* WDBC_RESULT[] = {
    [WDBC_OK]      = "ok",
    [WDBC_DUE]     = "due",
    [WDBC_ERROR]   = "err",
    [WDBC_IGNORE]  = "ign",
    [WDBC_UNKNOWN] = "unk"
};

static const char *SQL_VACUUM = "VACUUM;";
static const char *SQL_INSERT_INFO = "INSERT INTO info (key, value) VALUES (?, ?);";
static const char *SQL_BEGIN = "BEGIN;";
static const char *SQL_COMMIT = "COMMIT;";
static const char *SQL_STMT[] = {
    [WDB_STMT_FIM_LOAD] = "SELECT changes, size, perm, uid, gid, md5, sha1, uname, gname, mtime, inode, sha256, date, attributes, symbolic_path FROM fim_entry WHERE file = ?;",
    [WDB_STMT_FIM_FIND_ENTRY] = "SELECT 1 FROM fim_entry WHERE file = ?",
    [WDB_STMT_FIM_INSERT_ENTRY] = "INSERT INTO fim_entry (file, type, size, perm, uid, gid, md5, sha1, uname, gname, mtime, inode, sha256, attributes, symbolic_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
    [WDB_STMT_FIM_INSERT_ENTRY2] = "INSERT OR REPLACE INTO fim_entry (file, type, date, size, perm, uid, gid, md5, sha1, uname, gname, mtime, inode, sha256, attributes, symbolic_path, checksum) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
    [WDB_STMT_FIM_UPDATE_ENTRY] = "UPDATE fim_entry SET date = strftime('%s', 'now'), changes = ?, size = ?, perm = ?, uid = ?, gid = ?, md5 = ?, sha1 = ?, uname = ?, gname = ?, mtime = ?, inode = ?, sha256 = ?, attributes = ?, symbolic_path = ? WHERE file = ?;",
    [WDB_STMT_FIM_DELETE] = "DELETE FROM fim_entry WHERE file = ?;",
    [WDB_STMT_FIM_UPDATE_DATE] = "UPDATE fim_entry SET date = strftime('%s', 'now') WHERE file = ?;",
    [WDB_STMT_FIM_FIND_DATE_ENTRIES] = "SELECT file, changes, size, perm, uid, gid, md5, sha1, uname, gname, mtime, inode, sha256, date, attributes, symbolic_path FROM fim_entry WHERE date < ?;",
    [WDB_STMT_FIM_GET_ATTRIBUTES] = "SELECT file, attributes from fim_entry WHERE attributes IS NOT '0';",
    [WDB_STMT_FIM_UPDATE_ATTRIBUTES] = "UPDATE fim_entry SET attributes = ? WHERE file = ?;",
    [WDB_STMT_OSINFO_INSERT] = "INSERT INTO sys_osinfo (scan_id, scan_time, hostname, architecture, os_name, os_version, os_codename, os_major, os_minor, os_build, os_platform, sysname, release, version, os_release) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
    [WDB_STMT_OSINFO_DEL] = "DELETE FROM sys_osinfo;",
    [WDB_STMT_PROGRAM_INSERT] = "INSERT INTO sys_programs (scan_id, scan_time, format, name, priority, section, size, vendor, install_time, version, architecture, multiarch, source, description, location, triaged) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
    [WDB_STMT_PROGRAM_DEL] = "DELETE FROM sys_programs WHERE scan_id != ?;",
    [WDB_STMT_PROGRAM_UPD] = "UPDATE SYS_PROGRAMS SET CPE = ?, MSU_NAME = ?, TRIAGED = ? WHERE SCAN_ID = ? AND FORMAT IS ? AND NAME IS ? AND VENDOR IS ? AND VERSION IS ? AND ARCHITECTURE IS ?;",
    [WDB_STMT_PROGRAM_GET] = "SELECT CPE, MSU_NAME, TRIAGED, FORMAT, NAME, VENDOR, VERSION, ARCHITECTURE FROM SYS_PROGRAMS WHERE SCAN_ID != ?;",
    [WDB_STMT_HWINFO_INSERT] = "INSERT INTO sys_hwinfo (scan_id, scan_time, board_serial, cpu_name, cpu_cores, cpu_mhz, ram_total, ram_free, ram_usage) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);",
    [WDB_STMT_HOTFIX_INSERT] = "INSERT INTO sys_hotfixes (scan_id, scan_time, hotfix) VALUES (?, ?, ?);",
    [WDB_STMT_HWINFO_DEL] = "DELETE FROM sys_hwinfo;",
    [WDB_STMT_HOTFIX_DEL] = "DELETE FROM sys_hotfixes WHERE scan_id != ?;",
    [WDB_STMT_SET_HOTFIX_MET] = "UPDATE vuln_metadata SET HOTFIX_SCAN_ID = ?;",
    [WDB_STMT_PORT_INSERT] = "INSERT INTO sys_ports (scan_id, scan_time, protocol, local_ip, local_port, remote_ip, remote_port, tx_queue, rx_queue, inode, state, PID, process) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
    [WDB_STMT_PORT_DEL] = "DELETE FROM sys_ports WHERE scan_id != ?;",
    [WDB_STMT_PROC_INSERT] = "INSERT INTO sys_processes (scan_id, scan_time, pid, name, state, ppid, utime, stime, cmd, argvs, euser, ruser, suser, egroup, rgroup, sgroup, fgroup, priority, nice, size, vm_size, resident, share, start_time, pgrp, session, nlwp, tgid, tty, processor) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    [WDB_STMT_PROC_DEL] = "DELETE FROM sys_processes WHERE scan_id != ?;",
    [WDB_STMT_NETINFO_INSERT] = "INSERT INTO sys_netiface (scan_id, scan_time, name, adapter, type, state, mtu, mac, tx_packets, rx_packets, tx_bytes, rx_bytes, tx_errors, rx_errors, tx_dropped, rx_dropped) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
    [WDB_STMT_PROTO_INSERT] = "INSERT INTO sys_netproto (scan_id, iface, type, gateway, dhcp, metric) VALUES (?, ?, ?, ?, ?, ?);",
    [WDB_STMT_ADDR_INSERT] = "INSERT INTO sys_netaddr (scan_id, iface, proto, address, netmask, broadcast) VALUES (?, ?, ?, ?, ?, ?);",
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
    [WDB_STMT_SCA_FIND] = "SELECT id,result,status FROM sca_check WHERE id = ?;",
    [WDB_STMT_SCA_UPDATE] = "UPDATE sca_check SET result = ?, scan_id = ?, status = ?, reason = ? WHERE id = ?;",
    [WDB_STMT_SCA_INSERT] = "INSERT INTO sca_check (id,scan_id,title,description,rationale,remediation,file,directory,process,registry,`references`,result,policy_id,command,status,reason,condition) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);",
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
    [WDB_STMT_SCA_CHECK_FIND] = "SELECT id FROM sca_check WHERE policy_id = ?;",
    [WDB_STMT_SCA_CHECK_DELETE_DISTINCT] = "DELETE FROM sca_check WHERE scan_id != ? AND policy_id = ?;",
    [WDB_STMT_FIM_SELECT_CHECKSUM_RANGE] = "SELECT checksum FROM fim_entry WHERE file BETWEEN ? and ? ORDER BY file;",
    [WDB_STMT_FIM_DELETE_AROUND] = "DELETE FROM fim_entry WHERE file < ? OR file > ?;",
    [WDB_STMT_FIM_DELETE_RANGE] = "DELETE FROM fim_entry WHERE file > ? AND file < ?;",
    [WDB_STMT_FIM_CLEAR] = "DELETE FROM fim_entry;",
    [WDB_STMT_SYNC_UPDATE_ATTEMPT] = "UPDATE sync_info SET last_attempt = ?, n_attempts = n_attempts + 1 WHERE component = ?;",
    [WDB_STMT_SYNC_UPDATE_COMPLETION] = "UPDATE sync_info SET last_attempt = ?, last_completion = ?, n_attempts = n_attempts + 1, n_completions = n_completions + 1 WHERE component = ?;",
    [WDB_STMT_MITRE_NAME_GET] = "SELECT name FROM attack WHERE id = ?;",
    [WDB_STMT_ROOTCHECK_INSERT_PM] = "INSERT INTO pm_event (date_first, date_last, log, pci_dss, cis) VALUES (?, ?, ?, ?, ?);",
    [WDB_STMT_ROOTCHECK_UPDATE_PM] = "UPDATE pm_event SET date_last = ? WHERE log = ?;",
    [WDB_STMT_ROOTCHECK_DELETE_PM] = "DELETE FROM pm_event;",
    [WDB_STMT_GLOBAL_INSERT_AGENT] = "INSERT INTO agent (id, name, ip, register_ip, internal_key, date_add, `group`) VALUES (?,?,?,?,?,?,?);",
    [WDB_STMT_GLOBAL_UPDATE_AGENT_NAME] = "UPDATE agent SET name = ? WHERE id = ?;",
    [WDB_STMT_GLOBAL_UPDATE_AGENT_VERSION] = "UPDATE agent SET os_name = ?, os_version = ?, os_major = ?, os_minor = ?, os_codename = ?, os_platform = ?, os_build = ?, os_uname = ?, os_arch = ?, version = ?, config_sum = ?, merged_sum = ?, manager_host = ?, node_name = ?, last_keepalive = (CASE WHEN id = 0 THEN 253402300799 ELSE STRFTIME('%s', 'NOW') END), sync_status = ? WHERE id = ?;",
    [WDB_STMT_GLOBAL_UPDATE_AGENT_VERSION_IP] = "UPDATE agent SET os_name = ?, os_version = ?, os_major = ?, os_minor = ?, os_codename = ?, os_platform = ?, os_build = ?, os_uname = ?, os_arch = ?, version = ?, config_sum = ?, merged_sum = ?, manager_host = ?, node_name = ?, last_keepalive = (CASE WHEN id = 0 THEN 253402300799 ELSE STRFTIME('%s', 'NOW') END), ip = ?, sync_status = ? WHERE id = ?;",
    [WDB_STMT_GLOBAL_LABELS_GET] = "SELECT * FROM labels WHERE id = ?;",
    [WDB_STMT_GLOBAL_LABELS_DEL] = "DELETE FROM labels WHERE id = ?;",
    [WDB_STMT_GLOBAL_LABELS_SET] = "INSERT INTO labels (id, key, value) VALUES (?,?,?);",
    [WDB_STMT_GLOBAL_UPDATE_AGENT_KEEPALIVE] = "UPDATE agent SET last_keepalive = CASE WHEN last_keepalive IS NULL THEN 0 ELSE STRFTIME('%s', 'NOW') END, sync_status = ? WHERE id = ?;",
    [WDB_STMT_GLOBAL_DELETE_AGENT] = "DELETE FROM agent WHERE id = ?;",
    [WDB_STMT_GLOBAL_SELECT_AGENT_NAME] = "SELECT name FROM agent WHERE id = ?;",
    [WDB_STMT_GLOBAL_SELECT_AGENT_GROUP] = "SELECT `group` FROM agent WHERE id = ?;",
    [WDB_STMT_GLOBAL_FIND_AGENT] = "SELECT id FROM agent WHERE name = ? AND (register_ip = ? OR register_ip LIKE ? || '/_%');",
    [WDB_STMT_GLOBAL_SELECT_AGENT_STATUS] = "SELECT status FROM agent WHERE id = ?;",
    [WDB_STMT_GLOBAL_UPDATE_AGENT_STATUS] = "UPDATE agent SET status = ? WHERE id = ?;",
    [WDB_STMT_GLOBAL_FIND_GROUP] = "SELECT id FROM `group` WHERE name = ?;",
    [WDB_STMT_GLOBAL_UPDATE_AGENT_GROUP] = "UPDATE agent SET `group` = ? WHERE id = ?;",
    [WDB_STMT_GLOBAL_INSERT_AGENT_GROUP] = "INSERT INTO `group` (name) VALUES(?);",
    [WDB_STMT_GLOBAL_INSERT_AGENT_BELONG] = "INSERT INTO belongs (id_group, id_agent) VALUES(?,?);",
    [WDB_STMT_GLOBAL_DELETE_AGENT_BELONG] = "DELETE FROM belongs WHERE id_agent = ?;",
    [WDB_STMT_GLOBAL_DELETE_GROUP_BELONG] = "DELETE FROM belongs WHERE id_group = (SELECT id FROM 'group' WHERE name = ?);",
    [WDB_STMT_GLOBAL_DELETE_GROUP] = "DELETE FROM `group` WHERE name = ?;",
    [WDB_STMT_GLOBAL_SELECT_GROUPS] = "SELECT name FROM `group`;",
    [WDB_STMT_GLOBAL_SELECT_AGENT_KEEPALIVE] = "SELECT last_keepalive FROM agent WHERE name = ? AND (register_ip = ? OR register_ip LIKE ? || '/_%');",
    [WDB_STMT_GLOBAL_SYNC_REQ_GET] = "SELECT id, name, ip, os_name, os_version, os_major, os_minor, os_codename, os_build, os_platform, os_uname, os_arch, version, config_sum, merged_sum, manager_host, node_name, last_keepalive FROM agent WHERE id > ? AND sync_status = 'syncreq' LIMIT 1;",
    [WDB_STMT_GLOBAL_SYNC_SET] = "UPDATE agent SET sync_status = ? WHERE id = ?;",
    [WDB_STMT_GLOBAL_UPDATE_AGENT_INFO] = "UPDATE agent SET config_sum = :config_sum, ip = :ip, manager_host = :manager_host, merged_sum = :merged_sum, name = :name, node_name = :node_name, os_arch = :os_arch, os_build = :os_build, os_codename = :os_codename, os_major = :os_major, os_minor = :os_minor, os_name = :os_name, os_platform = :os_platform, os_uname = :os_uname, os_version = :os_version, version = :version, last_keepalive = :last_keepalive, sync_status = :sync_status WHERE id = :id;",
    [WDB_STMT_GLOBAL_GET_AGENTS] = "SELECT id FROM agent WHERE id > ? LIMIT 1;",
    [WDB_STMT_GLOBAL_GET_AGENTS_BY_GREATER_KEEPALIVE] = "SELECT id FROM agent WHERE id > ? AND last_keepalive > ? LIMIT 1;",
    [WDB_STMT_GLOBAL_GET_AGENTS_BY_LESS_KEEPALIVE] = "SELECT id FROM agent WHERE id > ? AND last_keepalive < ? LIMIT 1;",
    [WDB_STMT_GLOBAL_GET_AGENT_INFO] = "SELECT * FROM agent WHERE id = ?;",
    [WDB_STMT_GLOBAL_CHECK_MANAGER_KEEPALIVE] = "SELECT COUNT(*) FROM agent WHERE id=0 AND last_keepalive=253402300799;",
    [WDB_STMT_PRAGMA_JOURNAL_WAL] = "PRAGMA journal_mode=WAL;",
};

wdb_config wconfig;
pthread_mutex_t pool_mutex = PTHREAD_MUTEX_INITIALIZER;
wdb_t * db_pool_begin;
wdb_t * db_pool_last;
int db_pool_size;
OSHash * open_dbs;

// Opens global database and stores it in DB pool. It returns a locked database or NULL
wdb_t * wdb_open_global() {
    char path[PATH_MAX + 1] = "";
    sqlite3 *db = NULL;
    wdb_t * wdb = NULL;

    w_mutex_lock(&pool_mutex);

    // Finds DB in pool
    if (wdb = (wdb_t *)OSHash_Get(open_dbs, WDB_GLOB_NAME), wdb) {
        // The corresponding w_mutex_unlock(&wdb->mutex) is called in wdb_leave(wdb_t * wdb)
        w_mutex_lock(&wdb->mutex);
        wdb->refcount++;
        w_mutex_unlock(&pool_mutex);
        return wdb;
    } else {
        // Try to open DB
        snprintf(path, sizeof(path), "%s/%s.db", WDB2_DIR, WDB_GLOB_NAME);

        if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE, NULL)) {
            mdebug1("Global database not found, creating.");
            sqlite3_close_v2(db);

            // Creating database
            if (OS_SUCCESS != wdb_create_global(path)) {
                merror("Couldn't create SQLite database '%s'", path);
                w_mutex_unlock(&pool_mutex);
                return wdb;
            }

            // Retry to open
            if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE, NULL)) {
                merror("Can't open SQLite database '%s': %s", path, sqlite3_errmsg(db));
                sqlite3_close_v2(db);
                w_mutex_unlock(&pool_mutex);
                return wdb;
            }

            wdb = wdb_init(db, WDB_GLOB_NAME);
            wdb_pool_append(wdb);

        }
        else {
            wdb = wdb_init(db, WDB_GLOB_NAME);
            wdb_pool_append(wdb);
            wdb = wdb_upgrade_global(wdb);
        }
    }

    // The corresponding w_mutex_unlock(&wdb->mutex) is called in wdb_leave(wdb_t * wdb)
    w_mutex_lock(&wdb->mutex);
    wdb->refcount++;

    w_mutex_unlock(&pool_mutex);
    return wdb;
}

wdb_t * wdb_open_mitre() {
    char path[PATH_MAX + 1];
    sqlite3 *db;
    wdb_t * wdb = NULL;

    // Find BD in pool

    w_mutex_lock(&pool_mutex);

    if (wdb = (wdb_t *)OSHash_Get(open_dbs, WDB_MITRE_NAME), wdb) {
        goto success;
    }

    // Try to open DB

    snprintf(path, sizeof(path), "%s/%s.db", WDB_DIR, WDB_MITRE_NAME);

    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE, NULL)) {
        merror("Can't open SQLite database '%s': %s", path, sqlite3_errmsg(db));
        sqlite3_close_v2(db);
        goto end;

    } else {
        wdb = wdb_init(db, WDB_MITRE_NAME);
        wdb_pool_append(wdb);
    }

success:
    w_mutex_lock(&wdb->mutex);
    wdb->refcount++;

end:
    w_mutex_unlock(&pool_mutex);
    return wdb;
}

/* Open database for agent */
sqlite3* wdb_open_agent(int id_agent, const char *name) {
    char dir[OS_FLSIZE + 1];
    sqlite3 *db;

    snprintf(dir, OS_FLSIZE, "%s%s/agents/%03d-%s.db", isChroot() ? "/" : "", WDB_DIR, id_agent, name);

    if (sqlite3_open_v2(dir, &db, SQLITE_OPEN_READWRITE, NULL)) {
        mdebug1("No SQLite database found for agent '%s', creating.", name);
        sqlite3_close_v2(db);

        if (wdb_create_agent_db(id_agent, name) < 0) {
            merror("Couldn't create SQLite database '%s'", dir);
            return NULL;
        }

        // Retry to open

        if (sqlite3_open_v2(dir, &db, SQLITE_OPEN_READWRITE, NULL)) {
            merror("Can't open SQLite database '%s': %s", dir, sqlite3_errmsg(db));
            sqlite3_close_v2(db);
            return NULL;
        }

        if (wdb_journal_wal(db) == -1) {
            merror("Cannot open database '%s': error setting the journalig mode.", dir);
            sqlite3_close_v2(db);
            return NULL;
        }
    }

    sqlite3_busy_timeout(db, BUSY_SLEEP);
    return db;
}

// Open database for agent and store in DB pool. It returns a locked database or NULL
wdb_t * wdb_open_agent2(int agent_id) {
    char sagent_id[64];
    char path[PATH_MAX + 1];
    sqlite3 * db;
    wdb_t * wdb = NULL;

    snprintf(sagent_id, sizeof(sagent_id), "%03d", agent_id);

    // Find BD in pool

    w_mutex_lock(&pool_mutex);

    if (wdb = (wdb_t *)OSHash_Get(open_dbs, sagent_id), wdb) {
        goto success;
    }

    // Try to open DB

    snprintf(path, sizeof(path), "%s/%s.db", WDB2_DIR, sagent_id);

    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE, NULL)) {
        mdebug1("No SQLite database found for agent '%s', creating.", sagent_id);
        sqlite3_close_v2(db);

        if (wdb_create_agent_db2(sagent_id) < 0) {
            merror("Couldn't create SQLite database '%s'", path);
            goto end;
        }

        // Retry to open

        if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE, NULL)) {
            merror("Can't open SQLite database '%s': %s", path, sqlite3_errmsg(db));
            sqlite3_close_v2(db);
            goto end;
        }

        wdb = wdb_init(db, sagent_id);
        wdb_pool_append(wdb);
    }
    else {
        wdb = wdb_init(db, sagent_id);
        wdb_pool_append(wdb);
        wdb = wdb_upgrade(wdb);

        if (wdb == NULL) {
            goto end;
        }
    }

success:
    w_mutex_lock(&wdb->mutex);
    wdb->refcount++;

end:
    w_mutex_unlock(&pool_mutex);
    return wdb;
}

/* Create database for agent from profile. Returns 0 on success or -1 on error. */
int wdb_create_agent_db2(const char * agent_id) {
    char path[OS_FLSIZE + 1];
    char buffer[4096];
    FILE *source;
    FILE *dest;
    size_t nbytes;
    int result = 0;

    snprintf(path, OS_FLSIZE, "%s/%s", WDB2_DIR, WDB_PROF_NAME);

    if (!(source = fopen(path, "r"))) {
        mdebug1("Profile database not found, creating.");

        if (wdb_create_profile(path) < 0)
            return -1;

        // Retry to open

        if (!(source = fopen(path, "r"))) {
            merror("Couldn't open profile '%s'.", path);
            return -1;
        }
    }

    snprintf(path, OS_FLSIZE, "%s/%s.db", WDB2_DIR, agent_id);

    if (!(dest = fopen(path, "w"))) {
        merror("Couldn't create database '%s': %s (%d)", path, strerror(errno), errno);
        fclose(source);
        return -1;
    }

    while (nbytes = fread(buffer, 1, 4096, source), nbytes) {
        if (fwrite(buffer, 1, nbytes, dest) != nbytes) {
            unlink(path);
            result = -1;
            break;
        }
    }

    fclose(source);
    if (fclose(dest) == -1) {
        merror("Couldn't create file %s completely ", path);
        return -1;
    }

    if (result < 0) {
        unlink(path);
        return -1;
    }

    if (chmod(path, 0640) < 0) {
        merror(CHMOD_ERROR, path, errno, strerror(errno));
        unlink(path);
        return -1;
    }

    return 0;
}

/* Get agent name from location string */
char* wdb_agent_loc2name(const char *location) {
    char *name;
    char *end;

    switch (location[0]) {
    case 'r':
    case 's':
        if (!(strncmp(location, "syscheck", 8) && strncmp(location, "rootcheck", 9)))
            return strdup("localhost");
            else
            return NULL;

    case '(':
        name = strdup(location + 1);

        if ((end = strchr(name, ')')))
            *end = '\0';
        else {
            free(name);
            name = NULL;
        }

        return name;

    default:
        return NULL;
    }
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
int wdb_begin(sqlite3 *db) {
    sqlite3_stmt *stmt = NULL;
    int result = 0;

    if (sqlite3_prepare_v2(db, SQL_BEGIN, -1, &stmt, NULL) != SQLITE_OK) {
        mdebug1("sqlite3_prepare_v2(): %s", sqlite3_errmsg(db));
        return -1;
    }

    if (result = wdb_step(stmt) != SQLITE_DONE, result) {
        mdebug1("wdb_step(): %s", sqlite3_errmsg(db));
        result = -1;
    }

    sqlite3_finalize(stmt);
    return result;
}

int wdb_begin2(wdb_t * wdb) {
    if (wdb->transaction) {
        return 0;
    }

    if (wdb_begin(wdb->db) == -1) {
        return -1;
    }

    wdb->transaction = 1;
    wdb->transaction_begin_time = time(NULL);

    return 0;
}

/* Commit transaction */
int wdb_commit(sqlite3 *db) {
    sqlite3_stmt * stmt = NULL;
    int result = 0;

    if (sqlite3_prepare_v2(db, SQL_COMMIT, -1, &stmt, NULL) != SQLITE_OK) {
        mdebug1("sqlite3_prepare_v2(): %s", sqlite3_errmsg(db));
        return -1;
    }

    if (result = wdb_step(stmt) != SQLITE_DONE, result) {
        mdebug1("wdb_step(): %s", sqlite3_errmsg(db));
        result = -1;
    }

    sqlite3_finalize(stmt);
    return result;
}

int wdb_commit2(wdb_t * wdb) {
    if (!wdb->transaction) {
        return 0;
    }

    if (wdb_commit(wdb->db) == -1) {
        return -1;
    }

    wdb->transaction = 0;
    return 0;
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
int wdb_create_profile(const char *path) {
    return wdb_create_file(path, schema_agents_sql);
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

        result = sqlite3_step(stmt);

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

    if (chmod(path, 0660) < 0) {
        merror(CHMOD_ERROR, path, errno, strerror(errno));
        return OS_INVALID;
    }

    return OS_SUCCESS;
}

/* Rebuild database. Returns 0 on success or -1 on error. */
int wdb_vacuum(sqlite3 *db) {
    sqlite3_stmt *stmt;
    int result;

    if (!wdb_prepare(db, SQL_VACUUM, -1, &stmt, NULL)) {
        result = wdb_step(stmt) == SQLITE_DONE ? 0 : -1;
        sqlite3_finalize(stmt);
    } else {
        mdebug1("SQLite: %s", sqlite3_errmsg(db));
        result = -1;
    }

    sqlite3_close_v2(db);
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

wdb_t * wdb_init(sqlite3 * db, const char * id) {
    wdb_t * wdb;
    os_calloc(1, sizeof(wdb_t), wdb);
    wdb->db = db;
    w_mutex_init(&wdb->mutex, NULL);
    os_strdup(id, wdb->id);
    return wdb;
}

void wdb_destroy(wdb_t * wdb) {
    os_free(wdb->id);
    w_mutex_destroy(&wdb->mutex);
    free(wdb);
}

void wdb_pool_append(wdb_t * wdb) {
    int r;

    if (db_pool_begin) {
        db_pool_last->next = wdb;
        db_pool_last = wdb;
    } else {
        db_pool_begin = db_pool_last = wdb;
    }

    db_pool_size++;

    if (r = OSHash_Add(open_dbs, wdb->id, wdb), r != 2) {
        merror_exit("OSHash_Add(%s) returned %d.", wdb->id, r);
    }
}

void wdb_pool_remove(wdb_t * wdb) {
    wdb_t * prev;

    if (!OSHash_Delete(open_dbs, wdb->id)) {
        merror("Database for agent '%s' was not in hash table.", wdb->id);
    }

    if (wdb == db_pool_begin) {
        db_pool_begin = wdb->next;

        if (wdb == db_pool_last) {
            db_pool_last = NULL;
        }

        db_pool_size--;
    } else if (prev = wdb_pool_find_prev(wdb), prev) {
        prev->next = wdb->next;

        if (wdb == db_pool_last) {
            db_pool_last = prev;
        }

        db_pool_size--;
    } else {
        merror("Database for agent '%s' not found in the pool.", wdb->id);
    }
}

void wdb_close_all() {
    wdb_t * node;

    mdebug1("Closing all databases...");
    w_mutex_lock(&pool_mutex);

    while (node = db_pool_begin, node) {
        mdebug2("Closing database for agent %s", node->id);

        if (wdb_close(node, TRUE) < 0) {
            merror("Couldn't close DB for agent %s", node->id);

        }
    }

    w_mutex_unlock(&pool_mutex);
}

void wdb_commit_old() {
    wdb_t * node;

    w_mutex_lock(&pool_mutex);

    for (node = db_pool_begin; node; node = node->next) {
        w_mutex_lock(&node->mutex);
        time_t cur_time = time(NULL);

        // Commit condition: more than commit_time_min seconds elapsed from the last query, or more than commit_time_max elapsed from the transaction began.

        if (node->transaction && (cur_time - node->last > wconfig.commit_time_min || cur_time - node->transaction_begin_time > wconfig.commit_time_max)) {
            struct timespec ts_start, ts_end;

            gettime(&ts_start);
            wdb_commit2(node);
            gettime(&ts_end);

            mdebug2("Agent '%s' database commited. Time: %.3f ms.", node->id, time_diff(&ts_start, &ts_end) * 1e3);
        }

        w_mutex_unlock(&node->mutex);
    }

    w_mutex_unlock(&pool_mutex);
}

void wdb_close_old() {
    wdb_t * node;
    wdb_t * next;

    w_mutex_lock(&pool_mutex);

    for (node = db_pool_begin; node && db_pool_size > wconfig.open_db_limit; node = next) {
        next = node->next;

        if (node->refcount == 0 && !node->transaction) {
            mdebug2("Closing database for agent %s", node->id);
            wdb_close(node, FALSE);
        }
    }

    w_mutex_unlock(&pool_mutex);
}

cJSON * wdb_exec_stmt(sqlite3_stmt * stmt) {
    int r;
    int count;
    int i;
    cJSON * result;
    cJSON * row;

    if (!stmt) {
        mdebug1("Invalid SQL statement.");
        return NULL;
    }

    result = cJSON_CreateArray();

    while (r = sqlite3_step(stmt), r == SQLITE_ROW) {
        if (count = sqlite3_column_count(stmt), count > 0) {
            row = cJSON_CreateObject();

            for (i = 0; i < count; i++) {
                switch (sqlite3_column_type(stmt, i)) {
                case SQLITE_INTEGER:
                case SQLITE_FLOAT:
                    cJSON_AddNumberToObject(row, sqlite3_column_name(stmt, i), sqlite3_column_double(stmt, i));
                    break;

                case SQLITE_TEXT:
                case SQLITE_BLOB:
                    cJSON_AddStringToObject(row, sqlite3_column_name(stmt, i), (const char *)sqlite3_column_text(stmt, i));
                    break;

                case SQLITE_NULL:
                default:
                    ;
                }
            }

            cJSON_AddItemToArray(result, row);
        }
    }

    if (r != SQLITE_DONE) {
        mdebug1("SQL statement execution failed");
        cJSON_Delete(result);
        result = NULL;
    }

    return result;
}

cJSON * wdb_exec(sqlite3 * db, const char * sql) {
    sqlite3_stmt * stmt = NULL;
    cJSON * result = NULL;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        mdebug1("sqlite3_prepare_v2(): %s", sqlite3_errmsg(db));
        mdebug2("SQL: %s", sql);
        return NULL;
    }

    result = wdb_exec_stmt(stmt);

    if (!result) {
        mdebug1("sqlite3_step(): %s", sqlite3_errmsg(db));
    }

    sqlite3_finalize(stmt);
    return result;
}

int wdb_close(wdb_t * wdb, bool commit) {
    int result;
    int i;

    if (wdb->refcount == 0) {
        if (wdb->transaction && commit) {
            wdb_commit2(wdb);
        }

        for (i = 0; i < WDB_STMT_SIZE; i++) {
            if (wdb->stmt[i]) {
                sqlite3_finalize(wdb->stmt[i]);
            }
        }

        result = sqlite3_close_v2(wdb->db);

        if (result == SQLITE_OK) {
            wdb_pool_remove(wdb);
            wdb_destroy(wdb);
            return 0;
        } else {
            merror("DB(%s) wdb_close(): %s", wdb->id, sqlite3_errmsg(wdb->db));
            return -1;
        }
    } else {
        mdebug1("Couldn't close database for agent %s: refcount = %u", wdb->id, wdb->refcount);
        return -1;
    }
}

void wdb_leave(wdb_t * wdb) {
    wdb->refcount--;
    wdb->last = time(NULL);
    w_mutex_unlock(&wdb->mutex);
}

wdb_t * wdb_pool_find_prev(wdb_t * wdb) {
    wdb_t * node;

    for (node = db_pool_begin; node && node->next; node = node->next) {
        if (node->next == wdb) {
            return node;
        }
    }

    return NULL;
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
    } else if (sqlite3_reset(wdb->stmt[index]) != SQLITE_OK || sqlite3_clear_bindings(wdb->stmt[index]) != SQLITE_OK) {
        mdebug1("DB(%s) sqlite3_reset() stmt(%d): %s", wdb->id, index, sqlite3_errmsg(wdb->db));

        // Retry to prepare

        sqlite3_finalize(wdb->stmt[index]);

        if (sqlite3_prepare_v2(wdb->db, SQL_STMT[index], -1, wdb->stmt + index, NULL) != SQLITE_OK) {
            merror("DB(%s) sqlite3_prepare_v2() stmt(%d): %s", wdb->id, index, sqlite3_errmsg(wdb->db));
            return -1;
        }
    }

    return 0;
}

// Execute SQL script into an database
int wdb_sql_exec(wdb_t *wdb, const char *sql_exec) {
    char *sql_error;
    int result = 0;

    sqlite3_exec(wdb->db, sql_exec, NULL, NULL, &sql_error);

    if(sql_error) {
        mwarn("DB(%s) wdb_sql_exec returned error: '%s'", wdb->id, sql_error);
        sqlite3_free(sql_error);
        result = -1;
    }

    return result;
}

/* Delete a database file */
int wdb_remove_database(const char * agent_id) {
    char path[PATH_MAX];

    snprintf(path, PATH_MAX, "%s%s/%s.db", isChroot() ? "/" : "", WDB2_DIR, agent_id);
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
    agents = wm_strtok(agent_list);

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

                w_mutex_lock(&pool_mutex);

                wdb = (wdb_t *)OSHash_Get(open_dbs, agent);
                if (wdb) {
                    if (wdb_close(wdb, FALSE) < 0) {
                        result = "Can't close";
                    }
                }

                w_mutex_unlock(&pool_mutex);

                mdebug1("Removing db for agent '%s'", agent);

                if (wdb_remove_database(agent) < 0) {
                    result = "Can't delete";
                }
            }

            cJSON_AddStringToObject(json_agents, agent, result);
        }
    }

    free(agents);
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

/**
 * @brief Frees agent_info_data struct memory.
 *
 * @param[in] agent_data Pointer to the struct to be freed.
 */
void wdb_free_agent_info_data(agent_info_data *agent_data) {
    if (agent_data) {
        os_free(agent_data->version);
        os_free(agent_data->config_sum);
        os_free(agent_data->merged_sum);
        os_free(agent_data->manager_host);
        os_free(agent_data->node_name);
        os_free(agent_data->agent_ip);
        os_free(agent_data->labels);
        os_free(agent_data->sync_status);
        if (agent_data->osd) {
            os_free(agent_data->osd->os_name);
            os_free(agent_data->osd->os_version);
            os_free(agent_data->osd->os_major);
            os_free(agent_data->osd->os_minor);
            os_free(agent_data->osd->os_codename);
            os_free(agent_data->osd->os_platform);
            os_free(agent_data->osd->os_build);
            os_free(agent_data->osd->os_uname);
            os_free(agent_data->osd->os_arch);
            os_free(agent_data->osd);
        }
        os_free(agent_data);
    }
}
