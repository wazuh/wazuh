/*
 * Wazuh SQLite integration
 * Copyright (C) 2017 Wazuh Inc.
 * August 30, 2017.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wdb.h"

static const char * SQL_INSERT_NET_IFACE = "INSERT INTO netiface (name, adapter, type, state, mtu, mac, tx_packets, rx_packets, tx_bytes, rx_bytes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";
static const char * SQL_INSERT_NET_ADDR = "INSERT INTO netaddr (address, netmask, broadcast, gateway, dhcp) VALUES (?, ?, ?, ?, ?);";
static const char * SQL_UPDATE_NET_ADDR_IPV4 = "UPDATE netiface SET id_ipv4 = ? WHERE name = ?;";
static const char * SQL_UPDATE_NET_ADDR_IPV6 = "UPDATE netiface SET id_ipv6 = ? WHERE name = ?;";
static const char * SQL_DELETE_NET_IFACE = "DELETE FROM netiface;";
static const char * SQL_DELETE_NET_ADDR = "DELETE FROM netaddr;";
static const char * SQL_INSERT_OS_INFO = "INSERT INTO osinfo (os_name, os_version, node_name, machine, os_major, os_minor, os_build, os_platform, sysname, release, version) VALUES (?, ?, ;?, ?, ?, ?, ?, ?, ?, ?, ?);";
static const char * SQL_DELETE_OS_INFO = "DELETE FROM osinfo;";
static const char * SQL_INSERT_HW_INFO = "INSERT INTO hwinfo (board_serial, cpu_name, cpu_cores, cpu_mhz, ram_total, ram_free) VALUES (?, ?, ?, ?, ?, ?);";
static const char * SQL_DELETE_HW_INFO = "DELETE FROM hwinfo;";

// Insert network tuple. Return ID on success or -1 on error.
int wdb_insert_net_iface(sqlite3 * db, const char * name, const char * adapter, const char * type, const char * state, int mtu, const char * mac, long tx_packets, long rx_packets, long tx_bytes, long rx_bytes) {
    sqlite3_stmt *stmt = NULL;
    int result;

    if (wdb_prepare(db, SQL_INSERT_NET_IFACE, -1, &stmt, NULL)) {
        mdebug1("SQLite: %s", sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, name, -1, NULL);
    sqlite3_bind_text(stmt, 2, adapter, -1, NULL);
    sqlite3_bind_text(stmt, 3, type, -1, NULL);
    sqlite3_bind_text(stmt, 4, state, -1, NULL);
    sqlite3_bind_int(stmt, 5, mtu);
    sqlite3_bind_text(stmt, 6, mac, -1, NULL);
    sqlite3_bind_int64(stmt, 7, tx_packets);
    sqlite3_bind_int64(stmt, 8, rx_packets);
    sqlite3_bind_int64(stmt, 9, tx_bytes);
    sqlite3_bind_int64(stmt, 10, rx_bytes);

    if (wdb_step(stmt) == SQLITE_DONE)
        result = (int)sqlite3_last_insert_rowid(db);
    else {
        mdebug1("SQLite: %s", sqlite3_errmsg(db));
        result = -1;
    }

    sqlite3_finalize(stmt);
    return result;
}

// Insert network address tuple. Return ID on success or -1 on error.
int wdb_insert_net_addr(sqlite3 * db, const char * name, int type, const char * address, const char * netmask, const char * broadcast, const char * gateway, const char * dhcp) {
    sqlite3_stmt *stmt = NULL;
    int result;

    if (wdb_prepare(db, SQL_INSERT_NET_ADDR, -1, &stmt, NULL)) {
        mdebug1("SQLite: %s", sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, address, -1, NULL);
    sqlite3_bind_text(stmt, 2, netmask, -1, NULL);
    sqlite3_bind_text(stmt, 3, broadcast, -1, NULL);
    sqlite3_bind_text(stmt, 4, gateway, -1, NULL);
    sqlite3_bind_text(stmt, 5, dhcp, -1, NULL);

    if (wdb_step(stmt) == SQLITE_DONE)
        result = (int)sqlite3_last_insert_rowid(db);
    else {
        mdebug1("SQLite: %s", sqlite3_errmsg(db));
        result = -1;
    }

    sqlite3_finalize(stmt);

    if (result < 0) {
        return -1;
    }

    // Update reference at netiface table

    if (wdb_prepare(db, type == WDB_NETINFO_IPV4 ? SQL_UPDATE_NET_ADDR_IPV4 : SQL_UPDATE_NET_ADDR_IPV6, -1, &stmt, NULL)) {
        mdebug1("SQLite: %s", sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_int(stmt, 1, result);
    sqlite3_bind_text(stmt, 2, name, -1, NULL);

    if (wdb_step(stmt) == SQLITE_DONE)
        result = (int)sqlite3_last_insert_rowid(db);
    else {
        mdebug1("SQLite: %s", sqlite3_errmsg(db));
        result = -1;
    }

    result = wdb_step(stmt) == SQLITE_DONE ? sqlite3_changes(db) : -1;

    if (wdb_step(stmt) != SQLITE_DONE) {
        result = -1;
    }

    sqlite3_finalize(stmt);
    return result;
}

// Clean network tables. Return number of affected rows on success or -1 on error.
int wdb_delete_network(sqlite3 * db) {
    sqlite3_stmt *stmt = NULL;
    int result;

    if (wdb_prepare(db, SQL_DELETE_NET_IFACE, -1, &stmt, NULL)) {
        mdebug1("SQLite: %s", sqlite3_errmsg(db));
        return -1;
    }

    result = wdb_step(stmt) == SQLITE_DONE ? sqlite3_changes(db) : -1;
    sqlite3_finalize(stmt);

    if (wdb_prepare(db, SQL_DELETE_NET_ADDR, -1, &stmt, NULL)) {
        mdebug1("SQLite: %s", sqlite3_errmsg(db));
        return -1;
    }

    result = wdb_step(stmt) == SQLITE_DONE ? sqlite3_changes(db) : -1;

    if (wdb_step(stmt) == SQLITE_DONE) {
        result += sqlite3_changes(db);
    } else {
        result = -1;
    }

    sqlite3_finalize(stmt);
    return result;
}

// Insert OS info tuple. Return ID on success or -1 on error.
int wdb_insert_osinfo(sqlite3 * db, const char * os_name, const char * os_version, const char * node_name, const char * machine, const char * os_major, const char * os_minor, const char * os_build, const char * os_platform, const char * sysname, const char * release, const char * version) {
    sqlite3_stmt *stmt = NULL;
    int result;

    if (wdb_prepare(db, SQL_INSERT_OS_INFO, -1, &stmt, NULL)) {
        mdebug1("SQLite: %s", sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, os_name, -1, NULL);
    sqlite3_bind_text(stmt, 2, os_version, -1, NULL);
    sqlite3_bind_text(stmt, 3, node_name, -1, NULL);
    sqlite3_bind_text(stmt, 4, machine, -1, NULL);
    sqlite3_bind_text(stmt, 5, os_major, -1, NULL);
    sqlite3_bind_text(stmt, 6, os_minor, -1, NULL);
    sqlite3_bind_text(stmt, 7, os_build, -1, NULL);
    sqlite3_bind_text(stmt, 8, os_platform, -1, NULL);
    sqlite3_bind_text(stmt, 9, sysname, -1, NULL);
    sqlite3_bind_text(stmt, 10, release, -1, NULL);
    sqlite3_bind_text(stmt, 11, version, -1, NULL);

    if (wdb_step(stmt) == SQLITE_DONE)
        result = (int)sqlite3_last_insert_rowid(db);
    else {
        mdebug1("SQLite: %s", sqlite3_errmsg(db));
        result = -1;
    }

    sqlite3_finalize(stmt);
    return result;
}

// Clean OS info table. Return number of affected rows on success or -1 on error.
int wdb_delete_osinfo(sqlite3 * db) {
    sqlite3_stmt *stmt = NULL;
    int result;

    if (wdb_prepare(db, SQL_DELETE_OS_INFO, -1, &stmt, NULL)) {
        mdebug1("SQLite: %s", sqlite3_errmsg(db));
        return -1;
    }

    result = wdb_step(stmt) == SQLITE_DONE ? sqlite3_changes(db) : -1;
    sqlite3_finalize(stmt);
    return result;
}

// Insert hardware info tuple. Return ID on success or -1 on error.
int wdb_insert_hwinfo(sqlite3 * db, const char * board_serial, const char * cpu_name, int cpu_cores, double cpu_mhz, long ram_total, long ram_free) {
    sqlite3_stmt *stmt = NULL;
    int result;

    if (wdb_prepare(db, SQL_INSERT_HW_INFO, -1, &stmt, NULL)) {
        mdebug1("SQLite: %s", sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, board_serial, -1, NULL);
    sqlite3_bind_text(stmt, 2, cpu_name, -1, NULL);
    sqlite3_bind_int(stmt, 3, cpu_cores);
    sqlite3_bind_double(stmt, 4, cpu_mhz);
    sqlite3_bind_int64(stmt, 5, ram_total);
    sqlite3_bind_int64(stmt, 6, ram_free);

    if (wdb_step(stmt) == SQLITE_DONE)
        result = (int)sqlite3_last_insert_rowid(db);
    else {
        mdebug1("SQLite: %s", sqlite3_errmsg(db));
        result = -1;
    }

    sqlite3_finalize(stmt);
    return result;
}

// Clean hardware info table. Return number of affected rows on success or -1 on error.
int wdb_delete_hwinfo(sqlite3 * db) {
    sqlite3_stmt *stmt = NULL;
    int result;

    if (wdb_prepare(db, SQL_DELETE_HW_INFO, -1, &stmt, NULL)) {
        mdebug1("SQLite: %s", sqlite3_errmsg(db));
        return -1;
    }

    result = wdb_step(stmt) == SQLITE_DONE ? sqlite3_changes(db) : -1;
    sqlite3_finalize(stmt);
    return result;
}
