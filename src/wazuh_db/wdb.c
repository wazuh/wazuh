/*
 * Wazuh SQLite integration
 * Copyright (C) 2015-2019, Wazuh Inc.
 * June 06, 2016.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wdb.h"

#ifdef WIN32
#define getuid() 0
#define chown(x, y, z) 0
#endif

#define BUSY_SLEEP 1
#define MAX_ATTEMPTS 1000

static const char *SQL_VACUUM = "VACUUM;";
static const char *SQL_INSERT_INFO = "INSERT INTO info (key, value) VALUES (?, ?);";
static const char *SQL_BEGIN = "BEGIN;";
static const char *SQL_COMMIT = "COMMIT;";
static const char *SQL_STMT[] = {
    "SELECT changes, size, perm, uid, gid, md5, sha1, uname, gname, mtime, inode, sha256, date, attributes FROM fim_entry WHERE file = ?;",
    "SELECT 1 FROM fim_entry WHERE file = ?",
    "INSERT INTO fim_entry (file, type, size, perm, uid, gid, md5, sha1, uname, gname, mtime, inode, sha256, attributes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
    "UPDATE fim_entry SET date = strftime('%s', 'now'), changes = ?, size = ?, perm = ?, uid = ?, gid = ?, md5 = ?, sha1 = ?, uname = ?, gname = ?, mtime = ?, inode = ?, sha256 = ?, attributes = ? WHERE file = ?;",
    "DELETE FROM fim_entry WHERE file = ?;",
    "UPDATE fim_entry SET date = strftime('%s', 'now') WHERE file = ?;",
    "SELECT file, changes, size, perm, uid, gid, md5, sha1, uname, gname, mtime, inode, sha256, date, attributes FROM fim_entry WHERE date < ?;",
    "INSERT INTO sys_osinfo (scan_id, scan_time, hostname, architecture, os_name, os_version, os_codename, os_major, os_minor, os_build, os_platform, sysname, release, version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
    "DELETE FROM sys_osinfo;",
    "INSERT INTO sys_programs (scan_id, scan_time, format, name, priority, section, size, vendor, install_time, version, architecture, multiarch, source, description, location, triaged) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
    "DELETE FROM sys_programs WHERE scan_id != ?;",
    "UPDATE SYS_PROGRAMS SET TRIAGED = 1 WHERE SCAN_ID = ? AND EXISTS(SELECT OLD.SCAN_ID FROM SYS_PROGRAMS OLD WHERE OLD.SCAN_ID != SYS_PROGRAMS.SCAN_ID AND OLD.TRIAGED = 1 AND OLD.FORMAT = SYS_PROGRAMS.FORMAT AND OLD.NAME = SYS_PROGRAMS.NAME AND OLD.VENDOR = SYS_PROGRAMS.VENDOR AND OLD.VERSION = SYS_PROGRAMS.VERSION AND OLD.ARCHITECTURE = SYS_PROGRAMS.ARCHITECTURE);",
    "INSERT INTO sys_hwinfo (scan_id, scan_time, board_serial, cpu_name, cpu_cores, cpu_mhz, ram_total, ram_free, ram_usage) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);",
    "DELETE FROM sys_hwinfo;",
    "INSERT INTO sys_ports (scan_id, scan_time, protocol, local_ip, local_port, remote_ip, remote_port, tx_queue, rx_queue, inode, state, PID, process) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
    "DELETE FROM sys_ports WHERE scan_id != ?;",
    "INSERT INTO sys_processes (scan_id, scan_time, pid, name, state, ppid, utime, stime, cmd, argvs, euser, ruser, suser, egroup, rgroup, sgroup, fgroup, priority, nice, size, vm_size, resident, share, start_time, pgrp, session, nlwp, tgid, tty, processor) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    "DELETE FROM sys_processes WHERE scan_id != ?;",
    "INSERT INTO sys_netiface (scan_id, scan_time, name, adapter, type, state, mtu, mac, tx_packets, rx_packets, tx_bytes, rx_bytes, tx_errors, rx_errors, tx_dropped, rx_dropped) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
    "INSERT INTO sys_netproto (scan_id, iface, type, gateway, dhcp) VALUES (?, ?, ?, ?, ?);",
    "INSERT INTO sys_netaddr (scan_id, iface, proto, address, netmask, broadcast) VALUES (?, ?, ?, ?, ?, ?);",
    "DELETE FROM sys_netiface WHERE scan_id != ?;",
    "DELETE FROM sys_netproto WHERE scan_id != ?;",
    "DELETE FROM sys_netaddr WHERE scan_id != ?;",
    "INSERT INTO ciscat_results (scan_id, scan_time, benchmark, profile, pass, fail, error, notchecked, unknown, score) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
    "DELETE FROM ciscat_results WHERE scan_id != ?;",
    "SELECT first_start, first_end, start_scan, end_scan, first_check, second_check, third_check FROM scan_info WHERE module = ?;",
    "INSERT INTO scan_info (module, first_start, first_end, start_scan, end_scan, fim_first_check, fim_second_check, fim_third_check) VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
    "UPDATE scan_info SET first_start = ?, start_scan = ? WHERE module = ?;",
    "UPDATE scan_info SET first_end = ?, end_scan = ? WHERE module = ?;",
    "UPDATE scan_info SET start_scan = ? WHERE module = ?;",
    "UPDATE scan_info SET end_scan = ? WHERE module = ?;",
    "UPDATE scan_info SET fim_first_check = ? WHERE module = ?;",
    "UPDATE scan_info SET fim_second_check = ? WHERE module = ?;",
    "UPDATE scan_info SET fim_third_check = ? WHERE module = ?;",
    "SELECT first_start FROM scan_info WHERE module = ?;",
    "SELECT first_end FROM scan_info WHERE module = ?;",
    "SELECT start_scan FROM scan_info WHERE module = ?;",
    "SELECT end_scan FROM scan_info WHERE module = ?;",
    "SELECT fim_first_check FROM scan_info WHERE module = ?;",
    "SELECT fim_second_check FROM scan_info WHERE module = ?;",
    "SELECT fim_third_check FROM scan_info WHERE module = ?;"
};

sqlite3 *wdb_global = NULL;
wdb_config config;
pthread_mutex_t pool_mutex = PTHREAD_MUTEX_INITIALIZER;
wdb_t * db_pool_begin;
wdb_t * db_pool_last;
int db_pool_size;
OSHash * open_dbs;

/* Open global database. Returns 0 on success or -1 on failure. */
int wdb_open_global() {
    char dir[OS_FLSIZE + 1];

    if (!wdb_global) {
        // Database dir
        snprintf(dir, OS_FLSIZE, "%s%s/%s", isChroot() ? "/" : "", WDB_DIR, WDB_GLOB_NAME);

        // Connect to the database

        if (sqlite3_open_v2(dir, &wdb_global, SQLITE_OPEN_READWRITE, NULL)) {
            mdebug1("Global database not found, creating.");
            sqlite3_close_v2(wdb_global);
            wdb_global = NULL;

            if (wdb_create_global(dir) < 0) {
                wdb_global = NULL;
                return -1;
            }

            // Retry to open

            if (sqlite3_open_v2(dir, &wdb_global, SQLITE_OPEN_READWRITE, NULL)) {
                merror("Can't open SQLite database '%s': %s", dir, sqlite3_errmsg(wdb_global));
                sqlite3_close_v2(wdb_global);
                wdb_global = NULL;
                return -1;
            }
        }

        sqlite3_busy_timeout(wdb_global, BUSY_SLEEP);
    }

    return 0;
}

/* Close global database */
void wdb_close_global() {
    sqlite3_close_v2(wdb_global);
    wdb_global = NULL;
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
    wdb_t * new_wdb = NULL;

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

        if (wdb_metadata_initialize(wdb) < 0) {
            mwarn("Couldn't initialize metadata table in '%s'", path);
        }
        if (wdb_scan_info_init(wdb) < 0) {
            mwarn("Couldn't initialize scan_info table in '%s'", path);
        }

        wdb_pool_append(wdb);
    }
    else {
        wdb = wdb_init(db, sagent_id);
        wdb_pool_append(wdb);

        if (new_wdb = wdb_upgrade(wdb), new_wdb != NULL) {
            // If I had to generate backup and change DB
            wdb = new_wdb;
            wdb_pool_append(wdb);
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
    if (!wdb_begin(wdb->db)) {
        wdb->transaction = 1;
        return 0;
    } else {
        return -1;
    }
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
if (!wdb_commit(wdb->db)) {
    wdb->transaction = 0;
    return 0;
} else {
    return -1;
}
}

/* Create global database */
int wdb_create_global(const char *path) {
    char max_agents[16];
    snprintf(max_agents, 15, "%d", MAX_AGENTS);

    if (wdb_create_file(path, schema_global_sql) < 0)
        return -1;
    else if (wdb_insert_info("max_agents", max_agents) < 0)
        return -1;
    else if (wdb_insert_info("openssl_support", "yes") < 0)
        return -1;
    else
        return 0;
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
        return -1;
    }

    for (sql = source; sql && *sql; sql = tail) {
        if (sqlite3_prepare_v2(db, sql, -1, &stmt, &tail) != SQLITE_OK) {
            mdebug1("Preparing statement: %s", sqlite3_errmsg(db));
            sqlite3_close_v2(db);
            return -1;
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
            return -1;

        }

        sqlite3_finalize(stmt);
    }

    sqlite3_close_v2(db);

    switch (getuid()) {
    case -1:
        merror("getuid(): %s (%d)", strerror(errno), errno);
        return -1;

    case 0:
        uid = Privsep_GetUser(ROOT);
        gid = Privsep_GetGroup(GROUPGLOBAL);

        if (uid == (uid_t) - 1 || gid == (gid_t) - 1) {
            merror(USER_ERROR, ROOT, GROUPGLOBAL);
            return -1;
        }

        if (chown(path, uid, gid) < 0) {
            merror(CHOWN_ERROR, path, errno, strerror(errno));
            return -1;
        }

        break;

    default:
        mdebug1("Ignoring chown when creating file from SQL.");
        break;
    }

    if (chmod(path, 0660) < 0) {
        merror(CHMOD_ERROR, path, errno, strerror(errno));
        return -1;
    }

    return 0;
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

/* Insert key-value pair into info table */
int wdb_insert_info(const char *key, const char *value) {
    int result = 0;
    sqlite3_stmt *stmt;

    if (wdb_open_global() < 0)
        return -1;

    if (wdb_prepare(wdb_global, SQL_INSERT_INFO, -1, &stmt, NULL)) {
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb_global));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, key, -1, NULL);
    sqlite3_bind_text(stmt, 2, value, -1, NULL);

    result = wdb_step(stmt) == SQLITE_DONE ? 0 : -1;
    sqlite3_finalize(stmt);
    wdb_close_global();
    return result;
}

wdb_t * wdb_init(sqlite3 * db, const char * agent_id) {
    wdb_t * wdb;
    os_calloc(1, sizeof(wdb_t), wdb);
    wdb->db = db;
    pthread_mutex_init(&wdb->mutex, NULL);
    os_strdup(agent_id, wdb->agent_id);
    return wdb;
}

void wdb_destroy(wdb_t * wdb) {
    free(wdb->agent_id);
    pthread_mutex_destroy(&wdb->mutex);
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

    if (r = OSHash_Add(open_dbs, wdb->agent_id, wdb), r != 2) {
        merror_exit("OSHash_Add(%s) returned %d.", wdb->agent_id, r);
    }
}

void wdb_pool_remove(wdb_t * wdb) {
    wdb_t * prev;

    if (!OSHash_Delete(open_dbs, wdb->agent_id)) {
        merror("Database for agent '%s' was not in hash table.", wdb->agent_id);
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
        merror("Database for agent '%s' not found in the pool.", wdb->agent_id);
    }
}

void wdb_close_all() {
    wdb_t * node;

    mdebug1("Closing all databases...");
    w_mutex_lock(&pool_mutex);

    while (node = db_pool_begin, node) {
        mdebug2("Closing database for agent %s", node->agent_id);

        if (wdb_close(node) < 0) {
            merror("Couldn't close DB for agent %s", node->agent_id);
        }
    }

    w_mutex_unlock(&pool_mutex);
}

void wdb_commit_old() {
    wdb_t * node;

    w_mutex_lock(&pool_mutex);

    for (node = db_pool_begin; node; node = node->next) {
        w_mutex_lock(&node->mutex);

        if (node->transaction && time(NULL) - node->last > config.commit_time) {
            mdebug2("Committing database for agent %s", node->agent_id);
            wdb_commit2(node);
        }

        w_mutex_unlock(&node->mutex);
    }

    w_mutex_unlock(&pool_mutex);
}

void wdb_close_old() {
    wdb_t * node;
    wdb_t * next;

    w_mutex_lock(&pool_mutex);

    for (node = db_pool_begin; node && db_pool_size > config.open_db_limit; node = next) {
        next = node->next;

        if (node->refcount == 0 && !node->transaction) {
            mdebug2("Closing database for agent %s", node->agent_id);
            wdb_close(node);
        }
    }

    w_mutex_unlock(&pool_mutex);
}

cJSON * wdb_exec(sqlite3 * db, const char * sql) {
    int r;
    int count;
    int i;
    sqlite3_stmt * stmt;
    cJSON * result;
    cJSON * row;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        mdebug1("sqlite3_prepare_v2(): %s", sqlite3_errmsg(db));
        mdebug2("SQL: %s", sql);
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
        mdebug1("sqlite3_step(): %s", sqlite3_errmsg(db));
        cJSON_Delete(result);
        result = NULL;
    }

    sqlite3_finalize(stmt);
    return result;
}

int wdb_close(wdb_t * wdb) {
    int result;
    int i;

    if (wdb->refcount == 0) {
        if (wdb->transaction) {
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
            merror("DB(%s) wdb_close(): %s", wdb->agent_id, sqlite3_errmsg(wdb->db));
            return -1;
        }
    } else {
        merror("Couldn't close database for agent %s: refcount = %u", wdb->agent_id, wdb->refcount);
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
        merror("DB(%s) SQL statement index (%d) out of bounds", wdb->agent_id, index);
        return -1;
    }
    if (!wdb->stmt[index]) {
        if (sqlite3_prepare_v2(wdb->db, SQL_STMT[index], -1, wdb->stmt + index, NULL) != SQLITE_OK) {
            merror("DB(%s) sqlite3_prepare_v2() stmt(%d): %s", wdb->agent_id, index, sqlite3_errmsg(wdb->db));
            return -1;
        }
    } else if (sqlite3_reset(wdb->stmt[index]) != SQLITE_OK) {
        mdebug1("DB(%s) sqlite3_reset() stmt(%d): %s", wdb->agent_id, index, sqlite3_errmsg(wdb->db));

        // Retry to prepare

        sqlite3_finalize(wdb->stmt[index]);

        if (sqlite3_prepare_v2(wdb->db, SQL_STMT[index], -1, wdb->stmt + index, NULL) != SQLITE_OK) {
            merror("DB(%s) sqlite3_prepare_v2() stmt(%d): %s", wdb->agent_id, index, sqlite3_errmsg(wdb->db));
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
        mwarn("DB(%s) wdb_sql_exec returned error: '%s'", wdb->agent_id, sql_error);
        sqlite3_free(sql_error);
        result = -1;
    }

    return result;
}