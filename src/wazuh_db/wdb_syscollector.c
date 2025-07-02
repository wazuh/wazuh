/*
 * Wazuh SQLite integration
 * Copyright (C) 2015, Wazuh Inc.
 * August 30, 2017.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wdb.h"
#include "wdb_agents.h"

#define MAX_USER_LENGHT 256

// Function to save Network info into the DB. Return 0 on success or -1 on error.
int wdb_netinfo_save(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * name, const char * adapter,
                     const char * type, const char * state, int mtu, const char * mac, long tx_packets, long rx_packets,
                     long tx_bytes, long rx_bytes, long tx_errors, long rx_errors, long tx_dropped, long rx_dropped,
                     const char * checksum, const char * item_id, const bool replace) {

    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("at wdb_netinfo_save(): cannot begin transaction");
        return OS_INVALID;
    }

    if (wdb_netinfo_insert(wdb,
        scan_id,
        scan_time,
        name,
        adapter,
        type,
        state,
        mtu,
        mac,
        tx_packets,
        rx_packets,
        tx_bytes,
        rx_bytes,
        tx_errors,
        rx_errors,
        tx_dropped,
        rx_dropped,
        checksum,
        item_id,
        replace) < 0) {

        return OS_INVALID;
    }

    return OS_SUCCESS;
}

// Insert Network info tuple. Return 0 on success or -1 on error.
int wdb_netinfo_insert(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * name, const char * adapter,
                       const char * type, const char * state, int mtu, const char * mac, long tx_packets, long rx_packets,
                       long tx_bytes, long rx_bytes, long tx_errors, long rx_errors, long tx_dropped, long rx_dropped,
                       const char * checksum, const char * item_id, const bool replace) {
    sqlite3_stmt *stmt = NULL;

    if (NULL == name) {
        if(checksum && 0 != strcmp(SYSCOLLECTOR_LEGACY_CHECKSUM_VALUE, checksum)) {
            wdbi_remove_by_pk(wdb, WDB_SYSCOLLECTOR_NETINFO, item_id);
        }
    }

    if (wdb_stmt_cache(wdb, replace ? WDB_STMT_NETINFO_INSERT2 : WDB_STMT_NETINFO_INSERT) < 0) {
        mdebug1("at wdb_netinfo_insert(): cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[replace ? WDB_STMT_NETINFO_INSERT2 : WDB_STMT_NETINFO_INSERT];

    sqlite3_bind_text(stmt, 1, scan_id, -1, NULL);
    sqlite3_bind_text(stmt, 2, scan_time, -1, NULL);
    sqlite3_bind_text(stmt, 3, name, -1, NULL);
    sqlite3_bind_text(stmt, 4, adapter, -1, NULL);
    sqlite3_bind_text(stmt, 5, type, -1, NULL);
    sqlite3_bind_text(stmt, 6, state, -1, NULL);

    if (mtu > 0) {
        sqlite3_bind_int(stmt, 7, mtu);
    } else {
        sqlite3_bind_null(stmt, 7);
    }

    sqlite3_bind_text(stmt, 8, mac, -1, NULL);

    if (tx_packets >= 0) {
        sqlite3_bind_int64(stmt, 9, tx_packets);
    } else {
        sqlite3_bind_null(stmt, 9);
    }
    if (rx_packets >= 0) {
        sqlite3_bind_int64(stmt, 10, rx_packets);
    } else {
        sqlite3_bind_null(stmt, 10);
    }
    if (tx_bytes >= 0) {
        sqlite3_bind_int64(stmt, 11, tx_bytes);
    } else {
        sqlite3_bind_null(stmt, 11);
    }
    if (rx_bytes >= 0) {
        sqlite3_bind_int64(stmt, 12, rx_bytes);
    } else {
        sqlite3_bind_null(stmt, 12);
    }
    if (tx_errors >= 0) {
        sqlite3_bind_int64(stmt, 13, tx_errors);
    } else {
        sqlite3_bind_null(stmt, 13);
    }
    if (rx_errors >= 0) {
        sqlite3_bind_int64(stmt, 14, rx_errors);
    } else {
        sqlite3_bind_null(stmt, 14);
    }
    if (tx_dropped >= 0) {
        sqlite3_bind_int64(stmt, 15, tx_dropped);
    } else {
        sqlite3_bind_null(stmt, 15);
    }
    if (rx_dropped >= 0) {
        sqlite3_bind_int64(stmt, 16, rx_dropped);
    } else {
        sqlite3_bind_null(stmt, 16);
    }
    sqlite3_bind_text(stmt, 17, checksum, -1, NULL);
    sqlite3_bind_text(stmt, 18, item_id, -1, NULL);

    switch (wdb_step(stmt)) {
        case SQLITE_DONE:
            return OS_SUCCESS;
        case SQLITE_CONSTRAINT:
            if (!strncmp(sqlite3_errmsg(wdb->db), "UNIQUE", 6)) {
                mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
                return OS_SUCCESS;
            } else {
                merror("SQLite: %s", sqlite3_errmsg(wdb->db));
                return OS_INVALID;
            }
        default:
            merror("SQLite: %s", sqlite3_errmsg(wdb->db));
            return OS_INVALID;
    }
}

// Save IPv4/IPv6 protocol info into DB.
int wdb_netproto_save(wdb_t * wdb, const char * scan_id, const char * iface, int type, const char * gateway, const char * dhcp,
                      int metric, const char * checksum, const char * item_id, const bool replace) {

    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("at wdb_netproto_save(): cannot begin transaction");
        return OS_INVALID;
    }

    if (wdb_netproto_insert(wdb,
        scan_id,
        iface,
        type,
        gateway,
        dhcp,
        metric,
        checksum,
        item_id,
        replace) < 0) {

        return OS_INVALID;
    }

    return OS_SUCCESS;
}

// Insert IPv4/IPv6 protocol info tuple. Return 0 on success or -1 on error.
int wdb_netproto_insert(wdb_t * wdb, const char * scan_id, const char * iface, int type, const char * gateway, const char * dhcp,
                        int metric, const char * checksum, const char * item_id, const bool replace) {
    sqlite3_stmt *stmt = NULL;

    if (NULL == iface) {
        if(checksum && 0 != strcmp(SYSCOLLECTOR_LEGACY_CHECKSUM_VALUE, checksum)) {
            wdbi_remove_by_pk(wdb, WDB_SYSCOLLECTOR_NETPROTO, item_id);
        }
    }

    if (wdb_stmt_cache(wdb, replace ? WDB_STMT_PROTO_INSERT2 : WDB_STMT_PROTO_INSERT) < 0) {
        mdebug1("at wdb_netproto_insert(): cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[replace ? WDB_STMT_PROTO_INSERT2 : WDB_STMT_PROTO_INSERT];

    sqlite3_bind_text(stmt, 1, scan_id, -1, NULL);
    sqlite3_bind_text(stmt, 2, iface, -1, NULL);

    if (type == WDB_NETADDR_IPV4)
        sqlite3_bind_text(stmt, 3, "ipv4", -1, NULL);
    else
        sqlite3_bind_text(stmt, 3, "ipv6", -1, NULL);

    sqlite3_bind_text(stmt, 4, gateway, -1, NULL);
    sqlite3_bind_text(stmt, 5, dhcp, -1, NULL);

    if (metric >= 0) {
        sqlite3_bind_int64(stmt, 6, metric);
    } else {
        sqlite3_bind_null(stmt, 6);
    }
    sqlite3_bind_text(stmt, 7, checksum, -1, NULL);
    sqlite3_bind_text(stmt, 8, item_id, -1, NULL);

    switch (wdb_step(stmt)) {
        case SQLITE_DONE:
            return OS_SUCCESS;
        case SQLITE_CONSTRAINT:
            if (!strncmp(sqlite3_errmsg(wdb->db), "UNIQUE", 6)) {
                mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
                return OS_SUCCESS;
            } else {
                merror("SQLite: %s", sqlite3_errmsg(wdb->db));
                return OS_INVALID;
            }
        default:
            merror("SQLite: %s", sqlite3_errmsg(wdb->db));
            return OS_INVALID;
    }
}

// Save IPv4/IPv6 address info into DB.
int wdb_netaddr_save(wdb_t * wdb, const char * scan_id, const char * iface, int proto, const char * address, const char * netmask,
                     const char * broadcast, const char * checksum, const char * item_id, const bool replace) {

    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("at wdb_netaddr_save(): cannot begin transaction");
        return -1;
    }

    if (wdb_netaddr_insert(wdb,
        scan_id,
		iface,
        proto,
        address,
        netmask,
        broadcast,
        checksum,
        item_id,
        replace) < 0) {

        return -1;
    }

    return 0;
}

// Insert IPv4/IPv6 address info tuple. Return 0 on success or -1 on error.
int wdb_netaddr_insert(wdb_t * wdb, const char * scan_id, const char * iface, int proto, const char * address, const char * netmask,
                       const char * broadcast, const char * checksum, const char * item_id, const bool replace) {
    sqlite3_stmt *stmt = NULL;

    if (NULL == iface || NULL == address) {
        if(checksum && 0 != strcmp(SYSCOLLECTOR_LEGACY_CHECKSUM_VALUE, checksum)) {
            wdbi_remove_by_pk(wdb, WDB_SYSCOLLECTOR_NETADDRESS, item_id);
        }
    }

    if (wdb_stmt_cache(wdb, replace ? WDB_STMT_ADDR_INSERT2 : WDB_STMT_ADDR_INSERT) < 0) {
        mdebug1("at wdb_netaddr_insert(): cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[replace ? WDB_STMT_ADDR_INSERT2 : WDB_STMT_ADDR_INSERT];

    sqlite3_bind_text(stmt, 1, scan_id, -1, NULL);
    sqlite3_bind_text(stmt, 2, iface, -1, NULL);

    if (proto == WDB_NETADDR_IPV4)
        sqlite3_bind_text(stmt, 3, "ipv4", -1, NULL);
    else
        sqlite3_bind_text(stmt, 3, "ipv6", -1, NULL);

    sqlite3_bind_text(stmt, 4, address, -1, NULL);
    sqlite3_bind_text(stmt, 5, netmask, -1, NULL);
    sqlite3_bind_text(stmt, 6, broadcast, -1, NULL);
    sqlite3_bind_text(stmt, 7, checksum, -1, NULL);
    sqlite3_bind_text(stmt, 8, item_id, -1, NULL);

    if (wdb_step(stmt) == SQLITE_DONE){
        return OS_SUCCESS;
    } else {
        merror("SQLite: %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
}

// Function to delete old Network information from DB. Return 0 on success or -1 on error.
int wdb_netinfo_delete(wdb_t * wdb, const char * scan_id) {

    sqlite3_stmt *stmt = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("at wdb_netinfo_delete(): cannot begin transaction");
        return -1;
    }

    // Delete 'sys_netiface' table

    if (wdb_stmt_cache(wdb, WDB_STMT_NETINFO_DEL) < 0) {
        mdebug1("at wdb_netinfo_delete(): cannot cache statement");
        return -1;
    }
    stmt = wdb->stmt[WDB_STMT_NETINFO_DEL];
    sqlite3_bind_text(stmt, 1, scan_id, -1, NULL);

    if (wdb_step(stmt) != SQLITE_DONE) {
        merror("Deleting old information from 'sys_netiface' table: %s", sqlite3_errmsg(wdb->db));
        return -1;
    }

    // Delete 'sys_netproto' table

    if (wdb_stmt_cache(wdb, WDB_STMT_PROTO_DEL) < 0) {
        mdebug1("at wdb_netinfo_delete(): cannot cache statement");
        return -1;
    }
    stmt = wdb->stmt[WDB_STMT_PROTO_DEL];
    sqlite3_bind_text(stmt, 1, scan_id, -1, NULL);

    if (wdb_step(stmt) != SQLITE_DONE) {
        merror("Deleting old information from 'sys_netproto' table: %s", sqlite3_errmsg(wdb->db));
        return -1;
    }

    // Delete 'sys_netaddr' table

    if (wdb_stmt_cache(wdb, WDB_STMT_ADDR_DEL) < 0) {
        mdebug1("at wdb_netinfo_delete(): cannot cache statement");
        return -1;
    }
    stmt = wdb->stmt[WDB_STMT_ADDR_DEL];
    sqlite3_bind_text(stmt, 1, scan_id, -1, NULL);

    if (wdb_step(stmt) != SQLITE_DONE) {
        merror("Deleting old information from 'sys_netaddr' table: %s", sqlite3_errmsg(wdb->db));
        return -1;
    }

    return 0;
}

// Function to delete old Hotfix information from DB. Return 0 on success or -1 on error.
int wdb_hotfix_delete(wdb_t * wdb, const char * scan_id) {

    sqlite3_stmt *stmt = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("at wdb_hotfix_delete(): cannot begin transaction");
        return -1;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_HOTFIX_DEL) < 0) {
        mdebug1("at wdb_hotfix_delete(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_HOTFIX_DEL];

    sqlite3_bind_text(stmt, 1, scan_id, -1, NULL);

    if (wdb_step(stmt) != SQLITE_DONE) {
        merror("Deleting old information from 'sys_hotfixes' table: %s", sqlite3_errmsg(wdb->db));
        return -1;
    }

    return 0;
}

// Function to save OS info into the DB. Return 0 on success or -1 on error.
int wdb_osinfo_save(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * hostname, const char * architecture,
                    const char * os_name, const char * os_version, const char * os_codename, const char * os_major,
                    const char * os_minor, const char * os_patch, const char * os_build, const char * os_platform,
                    const char * sysname, const char * release, const char * version, const char * os_release,
                    const char * os_display_version, const char * checksum, const bool replace) {
    sqlite3_stmt *stmt_del = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("at wdb_osinfo_save(): cannot begin transaction");
        return -1;
    }

    /* Delete old OS information before insert the new scan */
    if (wdb_stmt_cache(wdb, WDB_STMT_OSINFO_DEL) < 0) {
        mdebug1("at wdb_osinfo_save(): cannot cache statement (%d)", WDB_STMT_OSINFO_DEL);
        return -1;
    }

    stmt_del = wdb->stmt[WDB_STMT_OSINFO_DEL];

    if (wdb_step(stmt_del) != SQLITE_DONE) {
        merror("Deleting old information from 'sys_osinfo' table: %s", sqlite3_errmsg(wdb->db));
        return -1;
    }

    // Calculating OS reference
    os_sha1 hexdigest;
    wdbi_strings_hash(hexdigest,
                      architecture ? architecture : "",
                      os_name ? os_name : "",
                      os_version ? os_version : "",
                      os_codename ? os_codename : "",
                      os_major ? os_major : "",
                      os_minor ? os_minor : "",
                      os_patch ? os_patch : "",
                      os_build ? os_build : "",
                      os_platform ? os_platform : "",
                      sysname ? sysname : "",
                      release ? release : "",
                      version ? version : "",
                      os_release ? os_release : "",
                      NULL);

    if (wdb_osinfo_insert(wdb,
        scan_id,
        scan_time,
        hostname,
        architecture,
        os_name,
        os_version,
        os_codename,
        os_major,
        os_minor,
        os_patch,
        os_build,
        os_platform,
        sysname,
        release,
        version,
        os_release,
        os_display_version,
        checksum,
        replace,
        hexdigest) < 0) {

        return -1;
    }

    return 0;
}

// Insert OS info tuple. Return 0 on success or -1 on error. (v2)
int wdb_osinfo_insert(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * hostname, const char * architecture,
                      const char * os_name, const char * os_version, const char * os_codename, const char * os_major,
                      const char * os_minor, const char * os_patch, const char * os_build, const char * os_platform,
                      const char * sysname, const char * release, const char * version, const char * os_release,
                      const char * os_display_version, const char * checksum, const bool replace, os_sha1 hexdigest) {
    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, replace ? WDB_STMT_OSINFO_INSERT2 : WDB_STMT_OSINFO_INSERT) < 0) {
        mdebug1("at wdb_osinfo_insert(): cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[replace ? WDB_STMT_OSINFO_INSERT2 : WDB_STMT_OSINFO_INSERT];

    sqlite3_bind_text(stmt, 1, scan_id, -1, NULL);
    sqlite3_bind_text(stmt, 2, scan_time, -1, NULL);
    sqlite3_bind_text(stmt, 3, hostname, -1, NULL);
    sqlite3_bind_text(stmt, 4, architecture, -1, NULL);
    sqlite3_bind_text(stmt, 5, os_name, -1, NULL);
    sqlite3_bind_text(stmt, 6, os_version, -1, NULL);
    sqlite3_bind_text(stmt, 7, os_codename, -1, NULL);
    sqlite3_bind_text(stmt, 8, os_major, -1, NULL);
    sqlite3_bind_text(stmt, 9, os_minor, -1, NULL);
    sqlite3_bind_text(stmt, 10, os_patch, -1, NULL);
    sqlite3_bind_text(stmt, 11, os_build, -1, NULL);
    sqlite3_bind_text(stmt, 12, os_platform, -1, NULL);
    sqlite3_bind_text(stmt, 13, sysname, -1, NULL);
    sqlite3_bind_text(stmt, 14, release, -1, NULL);
    sqlite3_bind_text(stmt, 15, version, -1, NULL);
    sqlite3_bind_text(stmt, 16, os_release, -1, NULL);
    sqlite3_bind_text(stmt, 17, os_display_version, -1, NULL);
    sqlite3_bind_text(stmt, 18, checksum, -1, NULL);
    sqlite3_bind_text(stmt, 19, hexdigest, -1, NULL);

    if (wdb_step(stmt) == SQLITE_DONE){
        return OS_SUCCESS;
    } else {
        merror("SQLite: %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

}

// Function to save Package info into the DB. Return 0 on success or -1 on error.
int wdb_package_save(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * format, const char * name,
                     const char * priority, const char * section, long size, const char * vendor, const char * install_time,
                     const char * version, const char * architecture, const char * multiarch, const char * source,
                     const char * description, const char * location, const char * checksum, const char * item_id, const bool replace) {

    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("at wdb_package_save(): cannot begin transaction");
        return -1;
    }

    if (wdb_package_insert(wdb,
        scan_id,
        scan_time,
        format,
        name,
        priority,
        section,
        size,
        vendor,
        install_time,
        version,
        architecture,
        multiarch,
        source,
        description,
        location,
        checksum,
        item_id,
        replace) < 0) {

        return -1;
    }

    return 0;
}

// Function to save Hotfix info into the DB. Return 0 on success or -1 on error.
int wdb_hotfix_save(wdb_t * wdb, const char * scan_id, const char * scan_time, const char *hotfix, const char* checksum, const bool replace) {
    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("at wdb_hotfix_save(): cannot begin transaction");
        return -1;
    }

    if (wdb_hotfix_insert(wdb, scan_id, scan_time, hotfix, checksum, replace) < 0) {
        return -1;
    }

    return 0;
}

// Insert Package info tuple. Return 0 on success or -1 on error.
int wdb_package_insert(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * format, const char * name,
                       const char * priority, const char * section, long size, const char * vendor, const char * install_time,
                       const char * version, const char * architecture, const char * multiarch, const char * source,
                       const char * description, const char * location, const char * checksum, const char * item_id, const bool replace) {
    sqlite3_stmt *stmt = NULL;

    if (NULL == name || NULL == version || NULL == architecture) {
        if(checksum && 0 != strcmp(SYSCOLLECTOR_LEGACY_CHECKSUM_VALUE, checksum)) {
            wdbi_remove_by_pk(wdb, WDB_SYSCOLLECTOR_PACKAGES, item_id);
        }
    }

    if (wdb_stmt_cache(wdb, replace ? WDB_STMT_PROGRAM_INSERT2 : WDB_STMT_PROGRAM_INSERT) < 0) {
        mdebug1("at wdb_package_insert(): cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[replace ? WDB_STMT_PROGRAM_INSERT2 : WDB_STMT_PROGRAM_INSERT];

    sqlite3_bind_text(stmt, 1, scan_id, -1, NULL);
    sqlite3_bind_text(stmt, 2, scan_time, -1, NULL);
    sqlite3_bind_text(stmt, 3, NULL != format ? format : "", -1, NULL); // Avoid bind NULL for agents older than 4.5.2
    sqlite3_bind_text(stmt, 4, name, -1, NULL);
    sqlite3_bind_text(stmt, 5, priority, -1, NULL);
    sqlite3_bind_text(stmt, 6, section, -1, NULL);
    if (size >= 0) {
        sqlite3_bind_int64(stmt, 7, size);
    } else {
        sqlite3_bind_null(stmt, 7);
    }
    sqlite3_bind_text(stmt, 8, vendor, -1, NULL);
    sqlite3_bind_text(stmt, 9, install_time, -1, NULL);
    sqlite3_bind_text(stmt, 10, version, -1, NULL);
    sqlite3_bind_text(stmt, 11, architecture, -1, NULL);
    sqlite3_bind_text(stmt, 12, multiarch, -1, NULL);
    sqlite3_bind_text(stmt, 13, source, -1, NULL);
    sqlite3_bind_text(stmt, 14, description, -1, NULL);
    sqlite3_bind_text(stmt, 15, NULL != location ? location : "", -1, NULL); // Avoid bind NULL for agents older than 4.5.2
    sqlite3_bind_text(stmt, 16, checksum, -1, NULL);
    sqlite3_bind_text(stmt, 17, item_id, -1, NULL);

    switch (wdb_step(stmt)) {
        case SQLITE_DONE:
            return OS_SUCCESS;
        case SQLITE_CONSTRAINT:
            if (!strncmp(sqlite3_errmsg(wdb->db), "UNIQUE", 6)) {
                mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
                return OS_SUCCESS;
            } else {
                merror("SQLite: %s", sqlite3_errmsg(wdb->db));
                return OS_INVALID;
            }
        default:
            merror("SQLite: %s", sqlite3_errmsg(wdb->db));
            return OS_INVALID;
    }
}

// Insert hotfix info tuple. Return 0 on success or -1 on error.
int wdb_hotfix_insert(wdb_t * wdb, const char * scan_id, const char * scan_time, const char *hotfix, const char* checksum, const bool replace) {
    sqlite3_stmt *stmt = NULL;

    if (NULL == hotfix) {
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, replace ? WDB_STMT_HOTFIX_INSERT2 : WDB_STMT_HOTFIX_INSERT) < 0) {
        mdebug1("at wdb_hotfix_insert(): cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[replace ? WDB_STMT_HOTFIX_INSERT2 : WDB_STMT_HOTFIX_INSERT];

    sqlite3_bind_text(stmt, 1, scan_id, -1, NULL);
    sqlite3_bind_text(stmt, 2, scan_time, -1, NULL);
    sqlite3_bind_text(stmt, 3, hotfix, -1, NULL);
    sqlite3_bind_text(stmt, 4, checksum, -1, NULL);

    if (wdb_step(stmt) == SQLITE_DONE){
        return OS_SUCCESS;
    } else {
        merror("SQLite: %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
}

// Function to update old Package information from DB. Return 0 on success or -1 on error.
int wdb_package_update(wdb_t * wdb, const char * scan_id) {
    sqlite3_stmt *stmt_get = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("at wdb_package_update(): cannot begin transaction");
        return -1;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_PROGRAM_GET) < 0) {
        mdebug1("at wdb_package_update(): cannot cache get statement");
        return -1;
    }

    stmt_get = wdb->stmt[WDB_STMT_PROGRAM_GET];
    sqlite3_bind_text(stmt_get, 1, scan_id, -1, NULL);

    int result;
    while (result = wdb_step(stmt_get), result == SQLITE_ROW) {
        const char *cpe = (const char *) sqlite3_column_text(stmt_get, 0);
        const char *msu_name = (const char *) sqlite3_column_text(stmt_get, 1);
        const char *format = (const char *) sqlite3_column_text(stmt_get, 2);
        const char *name = (const char *) sqlite3_column_text(stmt_get, 3);
        const char *vendor = (const char *) sqlite3_column_text(stmt_get, 4);
        const char *version = (const char *) sqlite3_column_text(stmt_get, 5);
        const char *arch = (const char *) sqlite3_column_text(stmt_get, 6);

        sqlite3_stmt *stmt_update = NULL;
        if (wdb_stmt_cache(wdb, WDB_STMT_PROGRAM_UPD) < 0) {
            mdebug1("at wdb_package_update(): cannot cache update statement");
            return -1;
        }

        stmt_update = wdb->stmt[WDB_STMT_PROGRAM_UPD];
        sqlite3_bind_text(stmt_update, 1, cpe, -1, NULL);
        sqlite3_bind_text(stmt_update, 2, msu_name, -1, NULL);
        sqlite3_bind_text(stmt_update, 3, scan_id, -1, NULL);
        sqlite3_bind_text(stmt_update, 4, format, -1, NULL);
        sqlite3_bind_text(stmt_update, 5, name, -1, NULL);
        sqlite3_bind_text(stmt_update, 6, vendor, -1, NULL);
        sqlite3_bind_text(stmt_update, 7, version, -1, NULL);
        sqlite3_bind_text(stmt_update, 8, arch, -1, NULL);

        if (wdb_step(stmt_update) != SQLITE_DONE) {
            goto error;
        }
    }

    if (result != SQLITE_DONE) {
        goto error;
    }

    return 0;
error:
    merror("Unable to update the 'sys_programs' table: %s", sqlite3_errmsg(wdb->db));
    return -1;
}

// Function to delete old Package information from DB. Return 0 on success or -1 on error.
int wdb_package_delete(wdb_t * wdb, const char * scan_id) {

    sqlite3_stmt *stmt = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("at wdb_package_delete(): cannot begin transaction");
        return -1;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_PROGRAM_DEL) < 0) {
        mdebug1("at wdb_package_delete(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_PROGRAM_DEL];

    sqlite3_bind_text(stmt, 1, scan_id, -1, NULL);

    if (wdb_step(stmt) != SQLITE_DONE) {
        merror("Deleting old information from 'sys_programs' table: %s", sqlite3_errmsg(wdb->db));
        return -1;
    }

    return 0;
}

// Function to save hardware info into the DB. Return 0 on success or -1 on error.
int wdb_hardware_save(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * serial, const char * cpu_name,
                      int cpu_cores, double cpu_mhz, uint64_t ram_total, uint64_t ram_free, int ram_usage, const char * checksum,
                      const bool replace) {

    sqlite3_stmt *stmt = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("at wdb_hardware_save(): cannot begin transaction");
        return -1;
    }

    /* Delete old hardware information before insert the new scan */
    if (wdb_stmt_cache(wdb, WDB_STMT_HWINFO_DEL) < 0) {
        mdebug1("at wdb_hardware_save(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_HWINFO_DEL];

    if (wdb_step(stmt) != SQLITE_DONE) {
        merror("Deleting old information from 'sys_hwinfo' table: %s", sqlite3_errmsg(wdb->db));
        return -1;
    }

    if (wdb_hardware_insert(wdb,
        scan_id,
        scan_time,
        serial,
        cpu_name,
        cpu_cores,
        cpu_mhz,
        ram_total,
        ram_free,
        ram_usage,
        checksum,
        replace) < 0) {

        return -1;
    }

    return 0;
}

// Insert HW info tuple. Return 0 on success or -1 on error.
int wdb_hardware_insert(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * serial, const char * cpu_name,
                        int cpu_cores, double cpu_mhz, uint64_t ram_total, uint64_t ram_free, int ram_usage, const char * checksum,
                        const bool replace) {
    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, replace ? WDB_STMT_HWINFO_INSERT2 : WDB_STMT_HWINFO_INSERT) < 0) {
        mdebug1("at wdb_hardware_insert(): cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[replace ? WDB_STMT_HWINFO_INSERT2 : WDB_STMT_HWINFO_INSERT];

    sqlite3_bind_text(stmt, 1, scan_id, -1, NULL);
    sqlite3_bind_text(stmt, 2, scan_time, -1, NULL);
    sqlite3_bind_text(stmt, 3, serial, -1, NULL);
    sqlite3_bind_text(stmt, 4, cpu_name, -1, NULL);

    if (cpu_cores > 0) {
        sqlite3_bind_int(stmt, 5, cpu_cores);
    } else {
        sqlite3_bind_null(stmt, 5);
    }

    if (cpu_mhz > 0) {
        sqlite3_bind_double(stmt, 6, cpu_mhz);
    } else {
        sqlite3_bind_null(stmt, 6);
    }

    if (ram_total > 0) {
        sqlite3_bind_int64(stmt, 7, ram_total);
    } else {
        sqlite3_bind_null(stmt, 7);
    }

    if (ram_free > 0) {
        sqlite3_bind_int64(stmt, 8, ram_free);
    } else {
        sqlite3_bind_null(stmt, 8);
    }

    if (ram_usage > 0 && ram_usage <= 100) {
        sqlite3_bind_int(stmt, 9, ram_usage);
    } else {
        sqlite3_bind_null(stmt, 9);
    }
    sqlite3_bind_text(stmt, 10, checksum, -1, NULL);

    if (wdb_step(stmt) == SQLITE_DONE){
        return OS_SUCCESS;
    } else {
        merror("SQLite: %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
}

// Function to save Port info into the DB. Return 0 on success or -1 on error.
int wdb_port_save(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * protocol, const char * local_ip,
                  int local_port, const char * remote_ip, int remote_port, int tx_queue, int rx_queue, long long inode,
                  const char * state, int pid, const char * process, const char * checksum, const char * item_id, const bool replace) {

    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("at wdb_port_save(): cannot begin transaction");
        return -1;
    }

    if (wdb_port_insert(wdb,
        scan_id,
        scan_time,
        protocol,
        local_ip,
        local_port,
        remote_ip,
        remote_port,
        tx_queue,
        rx_queue,
        inode,
        state,
        pid,
        process,
        checksum,
        item_id,
        replace) < 0) {

        return -1;
    }

    return 0;
}

// Insert port info tuple. Return 0 on success or -1 on error.
int wdb_port_insert(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * protocol, const char * local_ip,
                    int local_port, const char * remote_ip, int remote_port, int tx_queue, int rx_queue, long long inode,
                    const char * state, int pid, const char * process, const char * checksum, const char * item_id, const bool replace) {
    sqlite3_stmt *stmt = NULL;

    if (NULL == protocol || NULL == local_ip || local_port < 0 || inode < 0) {
        if(checksum && 0 != strcmp(SYSCOLLECTOR_LEGACY_CHECKSUM_VALUE, checksum)) {
            wdbi_remove_by_pk(wdb, WDB_SYSCOLLECTOR_PORTS, item_id);
        }
    }

    if (wdb_stmt_cache(wdb, replace ? WDB_STMT_PORT_INSERT2 : WDB_STMT_PORT_INSERT) < 0) {
        mdebug1("at wdb_port_insert(): cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[replace ? WDB_STMT_PORT_INSERT2 : WDB_STMT_PORT_INSERT];

    sqlite3_bind_text(stmt, 1, scan_id, -1, NULL);
    sqlite3_bind_text(stmt, 2, scan_time, -1, NULL);
    sqlite3_bind_text(stmt, 3, protocol, -1, NULL);
    sqlite3_bind_text(stmt, 4, local_ip, -1, NULL);

    if (local_port >= 0) {
        sqlite3_bind_int(stmt, 5, local_port);
    } else {
        sqlite3_bind_null(stmt, 5);
    }

    sqlite3_bind_text(stmt, 6, remote_ip, -1, NULL);

    if (remote_port >= 0) {
        sqlite3_bind_int(stmt, 7, remote_port);
    } else {
        sqlite3_bind_null(stmt, 7);
    }

    if (tx_queue >= 0) {
        sqlite3_bind_int(stmt, 8, tx_queue);
    } else {
        sqlite3_bind_null(stmt, 8);
    }

    if (rx_queue >= 0) {
        sqlite3_bind_int(stmt, 9, rx_queue);
    } else {
        sqlite3_bind_null(stmt, 9);
    }

    if (inode >= 0) {
        sqlite3_bind_int64(stmt, 10, (sqlite_int64) inode);
    } else {
        sqlite3_bind_null(stmt, 10);
    }

    sqlite3_bind_text(stmt, 11, state, -1, NULL);
    if (pid >= 0) {
        sqlite3_bind_int(stmt, 12, pid);
    } else {
        sqlite3_bind_null(stmt, 12);
    }
    sqlite3_bind_text(stmt, 13, process, -1, NULL);
    sqlite3_bind_text(stmt, 14, checksum, -1, NULL);
    sqlite3_bind_text(stmt, 15, item_id, -1, NULL);

    if (wdb_step(stmt) == SQLITE_DONE){
        return OS_SUCCESS;
    } else {
        merror("SQLite: %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
}

// Function to delete old port information from DB. Return 0 on success or -1 on error.
int wdb_port_delete(wdb_t * wdb, const char * scan_id) {

    sqlite3_stmt *stmt = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("at wdb_port_delete(): cannot begin transaction");
        return -1;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_PORT_DEL) < 0) {
        mdebug1("at wdb_port_delete(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_PORT_DEL];

    sqlite3_bind_text(stmt, 1, scan_id, -1, NULL);

    if (wdb_step(stmt) != SQLITE_DONE) {
        merror("Deleting old information from 'sys_ports' table: %s", sqlite3_errmsg(wdb->db));
        return -1;
    }

    return 0;
}

// Function to save process info into the DB. Return 0 on success or -1 on error.
int wdb_process_save(wdb_t * wdb, const char * scan_id, const char * scan_time, int pid, const char * name, const char * state,
                     int ppid, int utime, int stime, const char * cmd, const char * argvs, const char * euser, const char * ruser,
                     const char * suser, const char * egroup, const char * rgroup, const char * sgroup, const char * fgroup,
                     int priority, int nice, int size, int vm_size, int resident, int share, long long start_time, int pgrp,
                     int session, int nlwp, int tgid, int tty, int processor, const char* checksum, const bool replace) {

    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("at wdb_process_save(): cannot begin transaction");
        return -1;
    }

    if (wdb_process_insert(wdb,
        scan_id,
        scan_time,
        pid,
        name,
        state,
        ppid,
        utime,
        stime,
        cmd,
        argvs,
        euser,
        ruser,
        suser,
        egroup,
        rgroup,
        sgroup,
        fgroup,
        priority,
        nice,
        size,
        vm_size,
        resident,
        share,
        start_time,
        pgrp,
        session,
        nlwp,
        tgid,
        tty,
        processor,
        checksum,
        replace) < 0) {

        return -1;
    }

    return 0;
}

// Insert process info tuple. Return 0 on success or -1 on error.
int wdb_process_insert(wdb_t * wdb, const char * scan_id, const char * scan_time, int pid, const char * name, const char * state,
                       int ppid, int utime, int stime, const char * cmd, const char * argvs, const char * euser, const char * ruser,
                       const char * suser, const char * egroup, const char * rgroup, const char * sgroup, const char * fgroup,
                       int priority, int nice, int size, int vm_size, int resident, int share, long long start_time, int pgrp,
                       int session, int nlwp, int tgid, int tty, int processor, const char * checksum, const bool replace) {
    sqlite3_stmt *stmt = NULL;

    if (pid < 0) {
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, replace ? WDB_STMT_PROC_INSERT2 : WDB_STMT_PROC_INSERT) < 0) {
        mdebug1("at wdb_process_insert(): cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[replace ? WDB_STMT_PROC_INSERT2 : WDB_STMT_PROC_INSERT];

    sqlite3_bind_text(stmt, 1, scan_id, -1, NULL);
    sqlite3_bind_text(stmt, 2, scan_time, -1, NULL);
    if (pid >= 0)
        sqlite3_bind_int(stmt, 3, pid);
    else
        sqlite3_bind_null(stmt, 3);
    sqlite3_bind_text(stmt, 4, name, -1, NULL);
    sqlite3_bind_text(stmt, 5, state, -1, NULL);
    if (ppid >= 0)
        sqlite3_bind_int(stmt, 6, ppid);
    else
        sqlite3_bind_null(stmt, 6);
    if (utime >= 0)
        sqlite3_bind_int(stmt, 7, utime);
    else
        sqlite3_bind_null(stmt, 7);
    if (stime >= 0)
        sqlite3_bind_int(stmt, 8, stime);
    else
        sqlite3_bind_null(stmt, 8);
    sqlite3_bind_text(stmt, 9, cmd, -1, NULL);
    sqlite3_bind_text(stmt, 10, argvs, -1, NULL);
    sqlite3_bind_text(stmt, 11, euser, -1, NULL);
    sqlite3_bind_text(stmt, 12, ruser, -1, NULL);
    sqlite3_bind_text(stmt, 13, suser, -1, NULL);
    sqlite3_bind_text(stmt, 14, egroup, -1, NULL);
    sqlite3_bind_text(stmt, 15, rgroup, -1, NULL);
    sqlite3_bind_text(stmt, 16, sgroup, -1, NULL);
    sqlite3_bind_text(stmt, 17, fgroup, -1, NULL);
    if (priority >= 0) {
        sqlite3_bind_int(stmt, 18, priority);
    } else {
        sqlite3_bind_null(stmt, 18);
    }
    sqlite3_bind_int(stmt, 19, nice);
    if (size >= 0)
        sqlite3_bind_int(stmt, 20, size);
    else
        sqlite3_bind_null(stmt, 20);
    if (vm_size >= 0)
        sqlite3_bind_int(stmt, 21, vm_size);
    else
        sqlite3_bind_null(stmt, 21);
    if (resident >= 0)
        sqlite3_bind_int(stmt, 22, resident);
    else
        sqlite3_bind_null(stmt, 22);
    if (share >= 0)
        sqlite3_bind_int(stmt, 23, share);
    else
        sqlite3_bind_null(stmt, 23);
    if (start_time >= 0)
        sqlite3_bind_int64(stmt, 24, (sqlite_int64) start_time);
    else
        sqlite3_bind_null(stmt, 24);
    if (pgrp >= 0)
        sqlite3_bind_int(stmt, 25, pgrp);
    else
        sqlite3_bind_null(stmt, 25);
    if (session >= 0)
        sqlite3_bind_int(stmt, 26, session);
    else
        sqlite3_bind_null(stmt, 26);
    if (nlwp >= 0)
        sqlite3_bind_int(stmt, 27, nlwp);
    else
        sqlite3_bind_null(stmt, 27);
    if (tgid >= 0)
        sqlite3_bind_int(stmt, 28, tgid);
    else
        sqlite3_bind_null(stmt, 28);
    if (tty >= 0)
        sqlite3_bind_int(stmt, 29, tty);
    else
        sqlite3_bind_null(stmt, 29);
    if (processor >= 0)
        sqlite3_bind_int(stmt, 30, processor);
    else
        sqlite3_bind_null(stmt, 30);

    sqlite3_bind_text(stmt, 31, checksum, -1, NULL);

    if (wdb_step(stmt) == SQLITE_DONE){
        return OS_SUCCESS;
    } else {
        merror("SQLite: %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
}

// Function to delete old processes information from DB. Return 0 on success or -1 on error.
int wdb_process_delete(wdb_t * wdb, const char * scan_id) {

    sqlite3_stmt *stmt = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("at wdb_process_delete(): cannot begin transaction");
        return -1;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_PROC_DEL) < 0) {
        mdebug1("at wdb_process_delete(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_PROC_DEL];

    sqlite3_bind_text(stmt, 1, scan_id, -1, NULL);

    if (wdb_step(stmt) != SQLITE_DONE) {
        merror("Deleting old information from 'sys_processes' table: %s", sqlite3_errmsg(wdb->db));
        return -1;
    }

    return 0;
}

// Function to save users info into the DB. Return 0 on success or -1 on error.
int wdb_users_save(wdb_t * wdb, const user_record_t * user_record, const bool replace)
{
    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("at wdb_users_save(): cannot begin transaction");
        return -1;
    }


    if (wdb_users_insert(wdb, user_record, replace)) {
        return -1;
    }

    return 0;
}

// Insert user info tuple. Return 0 on success or -1 on error.
int wdb_users_insert(wdb_t * wdb, const user_record_t * user_record, const bool replace)
{
    sqlite3_stmt *stmt = NULL;

    if (NULL == user_record->user_name ||
        strlen(user_record->user_name) == 0) {
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, replace ? WDB_STMT_USER_INSERT2 : WDB_STMT_USER_INSERT) < 0) {
        mdebug1("at wdb_users_insert(): cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[replace ? WDB_STMT_USER_INSERT2 : WDB_STMT_USER_INSERT];

    sqlite3_bind_text(stmt, 1, user_record->scan_id, -1, NULL);
    sqlite3_bind_text(stmt, 2, user_record->scan_time, -1, NULL);
    sqlite3_bind_text(stmt, 3, user_record->user_name, -1, NULL);
    sqlite3_bind_text(stmt, 4, user_record->user_full_name, -1, NULL);
    sqlite3_bind_text(stmt, 5, user_record->user_home, -1, NULL);
    if (user_record->user_id >= 0) {
        sqlite3_bind_int64(stmt, 6, user_record->user_id);
    } else {
        sqlite3_bind_null(stmt, 6);
    }
    sqlite3_bind_int64(stmt, 7, user_record->user_uid_signed);
    sqlite3_bind_text(stmt, 8, user_record->user_uuid, -1, NULL);
    sqlite3_bind_text(stmt, 9, user_record->user_groups, -1, NULL);
    if (user_record->user_group_id >= 0) {
        sqlite3_bind_int64(stmt, 10, user_record->user_group_id);
    } else {
        sqlite3_bind_null(stmt, 10);
    }
    sqlite3_bind_int64(stmt, 11, user_record->user_group_id_signed);
    if (user_record->user_created > 0) {
        sqlite3_bind_double(stmt, 12, user_record->user_created);
    } else {
        sqlite3_bind_null(stmt, 12);
    }
    sqlite3_bind_text(stmt, 13, user_record->user_roles, -1, NULL);
    sqlite3_bind_text(stmt, 14, user_record->user_shell, -1, NULL);
    sqlite3_bind_text(stmt, 15, user_record->user_type, -1, NULL);
    sqlite3_bind_int(stmt, 16, user_record->user_is_hidden);
    sqlite3_bind_int(stmt, 17, user_record->user_is_remote);
    if (user_record->user_last_login > 0) {
        sqlite3_bind_int64(stmt, 18, user_record->user_last_login);
    } else {
        sqlite3_bind_null(stmt, 18);
    }
    if (user_record->user_auth_failed_count >= 0) {
        sqlite3_bind_int64(stmt, 19, user_record->user_auth_failed_count);
    } else {
        sqlite3_bind_null(stmt, 19);
    }
    if (user_record->user_auth_failed_timestamp > 0) {
        sqlite3_bind_double(stmt, 20, user_record->user_auth_failed_timestamp);
    } else {
        sqlite3_bind_null(stmt, 20);
    }
    if (user_record->user_password_last_set_time > 0) {
        sqlite3_bind_double(stmt, 21, user_record->user_password_last_set_time);
    } else {
        sqlite3_bind_null(stmt, 21);
    }
    if (user_record->user_password_expiration_date > 0) {
        sqlite3_bind_int(stmt, 22, user_record->user_password_expiration_date);
    } else {
        sqlite3_bind_null(stmt, 22);
    }
    sqlite3_bind_text(stmt, 23, user_record->user_password_hash_algorithm, -1, NULL);
    if (user_record->user_password_inactive_days >= 0) {
        sqlite3_bind_int(stmt, 24, user_record->user_password_inactive_days);
    } else {
        sqlite3_bind_null(stmt, 24);
    }
    if (user_record->user_password_last_change >= 0) {
        sqlite3_bind_int(stmt, 25, user_record->user_password_last_change);
    } else {
        sqlite3_bind_null(stmt, 25);
    }
    if (user_record->user_password_max_days_between_changes >= 0) {
        sqlite3_bind_int(stmt, 26, user_record->user_password_max_days_between_changes);
    } else {
        sqlite3_bind_null(stmt, 26);
    }
    if (user_record->user_password_min_days_between_changes >= 0) {
        sqlite3_bind_int(stmt, 27, user_record->user_password_min_days_between_changes);
    } else {
        sqlite3_bind_null(stmt, 27);
    }
    sqlite3_bind_text(stmt, 28, user_record->user_password_status, -1, NULL);
    if (user_record->user_password_warning_days_before_expiration >= 0) {
        sqlite3_bind_int(stmt, 29, user_record->user_password_warning_days_before_expiration);
    } else {
        sqlite3_bind_null(stmt, 29);
    }
    if (user_record->process_pid >= 0) {
        sqlite3_bind_int64(stmt, 30, user_record->process_pid);
    } else {
        sqlite3_bind_null(stmt, 30);
    }
    sqlite3_bind_text(stmt, 31, user_record->host_ip, -1, NULL);
    sqlite3_bind_int(stmt, 32, user_record->login_status);
    sqlite3_bind_text(stmt, 33, user_record->login_type, -1, NULL);
    sqlite3_bind_text(stmt, 34, user_record->login_tty, -1, NULL);
    sqlite3_bind_text(stmt, 35, user_record->checksum, -1, NULL);

    if (wdb_step(stmt) == SQLITE_DONE){
        return OS_SUCCESS;
    } else {
        merror("SQLite: %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
}

// Function to save groups info into the DB. Return 0 on success or -1 on error.
int wdb_groups_save(wdb_t * wdb, const char * scan_id, const char * scan_time, long long group_id, const char * group_name,
                    const char * group_description, long long group_id_signed, const char * group_uuid, const bool group_is_hidden,
                    const char * group_users, const char * checksum, const bool replace)
{
    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("at wdb_groups_save(): cannot begin transaction");
        return -1;
    }

    if (wdb_groups_insert(wdb, scan_id, scan_time, group_id, group_name, group_description, group_id_signed, group_uuid,
                          group_is_hidden, group_users, checksum, replace)) {
        return -1;
    }

    return 0;
}

// Insert group info tuple. Return 0 on success or -1 on error.
int wdb_groups_insert(wdb_t * wdb, const char * scan_id, const char * scan_time, long long group_id, const char * group_name,
                      const char * group_description, long long group_id_signed, const char * group_uuid, const bool group_is_hidden,
                      const char * group_users, const char * checksum, const bool replace){
    sqlite3_stmt *stmt = NULL;

    if (NULL == group_name || strlen(group_name) == 0){
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, replace ? WDB_STMT_GROUP_INSERT2 : WDB_STMT_GROUP_INSERT) < 0) {
        mdebug1("at wdb_groups_insert(): cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[replace ? WDB_STMT_GROUP_INSERT2 : WDB_STMT_GROUP_INSERT];

    sqlite3_bind_text(stmt, 1, scan_id, -1, NULL);
    sqlite3_bind_text(stmt, 2, scan_time, -1, NULL);
    if (group_id >= 0) {
        sqlite3_bind_int64(stmt, 3, group_id);
    } else {
        sqlite3_bind_null(stmt, 3);
    }
    sqlite3_bind_text(stmt, 4, group_name, -1, NULL);
    sqlite3_bind_text(stmt, 5, group_description, -1, NULL);
    sqlite3_bind_int64(stmt, 6, group_id_signed);
    sqlite3_bind_text(stmt, 7, group_uuid, -1, NULL);
    sqlite3_bind_int(stmt, 8, group_is_hidden);
    sqlite3_bind_text(stmt, 9, group_users, -1, NULL);
    sqlite3_bind_text(stmt, 10, checksum, -1, NULL);

    if (wdb_step(stmt) == SQLITE_DONE){
        return OS_SUCCESS;
    } else {
        merror("SQLite: %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
}

int wdb_syscollector_processes_save2(wdb_t * wdb, const cJSON * attributes)
{
    const char * scan_id = "0";
    const char * scan_time = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "scan_time"));
    const int pid = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "pid")) ? strtol(cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "pid")),NULL,10) : -1;
    const char * name = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "name"));
    const char * state = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "state"));
    const int ppid = cJSON_GetObjectItem(attributes, "ppid") ? cJSON_GetObjectItem(attributes, "ppid")->valueint : 0;
    const int utime = cJSON_GetObjectItem(attributes, "utime") ? cJSON_GetObjectItem(attributes, "utime")->valueint : 0;
    const int stime = cJSON_GetObjectItem(attributes, "stime") ? cJSON_GetObjectItem(attributes, "stime")->valueint : 0;
    const char * cmd = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "cmd"));
    const char * argvs = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "argvs"));
    const char * euser = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "euser"));
    const char * ruser = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "ruser"));
    const char * suser = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "suser"));
    const char * egroup = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "egroup"));
    const char * rgroup = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "rgroup"));
    const char * sgroup = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "sgroup"));
    const char * fgroup = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "fgroup"));
    const int priority = cJSON_GetObjectItem(attributes, "priority") ? cJSON_GetObjectItem(attributes, "priority")->valueint : 0;
    const int nice = cJSON_GetObjectItem(attributes, "nice") ? cJSON_GetObjectItem(attributes, "nice")->valueint : 0;
    const int size = cJSON_GetObjectItem(attributes, "size") ? cJSON_GetObjectItem(attributes, "size")->valueint : 0;
    const int vm_size = cJSON_GetObjectItem(attributes, "vm_size") ? cJSON_GetObjectItem(attributes, "vm_size")->valueint : 0;
    const int resident = cJSON_GetObjectItem(attributes, "resident") ? cJSON_GetObjectItem(attributes, "resident")->valueint : 0;
    const int share = cJSON_GetObjectItem(attributes, "share") ? cJSON_GetObjectItem(attributes, "share")->valueint : 0;
    const long long start_time = cJSON_GetObjectItem(attributes, "start_time") ? (long long) cJSON_GetObjectItem(attributes, "start_time")->valuedouble : 0;
    const int pgrp = cJSON_GetObjectItem(attributes, "pgrp") ? cJSON_GetObjectItem(attributes, "pgrp")->valueint : 0;
    const int session = cJSON_GetObjectItem(attributes, "session") ? cJSON_GetObjectItem(attributes, "session")->valueint : 0;
    const int nlwp = cJSON_GetObjectItem(attributes, "nlwp") ? cJSON_GetObjectItem(attributes, "nlwp")->valueint : 0;
    const int tgid = cJSON_GetObjectItem(attributes, "tgid") ? cJSON_GetObjectItem(attributes, "tgid")->valueint : 0;
    const int tty = cJSON_GetObjectItem(attributes, "tty") ? cJSON_GetObjectItem(attributes, "tty")->valueint : 0;
    const int processor = cJSON_GetObjectItem(attributes, "processor") ? cJSON_GetObjectItem(attributes, "processor")->valueint : 0;
    const char * checksum = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "checksum"));
    return wdb_process_save(wdb, scan_id, scan_time, pid, name, state, ppid, utime, stime, cmd, argvs, euser, ruser, suser, egroup,
                            rgroup, sgroup, fgroup, priority, nice, size, vm_size, resident, share, start_time, pgrp, session, nlwp,
                            tgid, tty, processor, checksum, TRUE);
}


int wdb_syscollector_package_save2(wdb_t * wdb, const cJSON * attributes)
{
    const char * scan_id = "0";
    const char * scan_time = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "scan_time"));
    const char * format = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "format"));
    const char * name = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "name"));
    const char * priority = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "priority"));
    const char * section = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "groups"));
    const int size = cJSON_GetObjectItem(attributes, "size") ? cJSON_GetObjectItem(attributes, "size")->valueint : 0;
    const char * vendor = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "vendor"));
    const char * install_time = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "install_time"));
    const char * version = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "version"));
    const char * architecture = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "architecture"));
    const char * multiarch = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "multiarch"));
    const char * source = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "source"));
    const char * description = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "description"));
    const char * location = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "location"));
    const char * checksum = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "checksum"));
    const char * item_id = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "item_id"));
    return wdb_package_save(wdb, scan_id, scan_time, format, name, priority, section, size, vendor, install_time, version,
                            architecture, multiarch, source, description, location, checksum, item_id, TRUE);
}

int wdb_syscollector_hotfix_save2(wdb_t * wdb, const cJSON * attributes)
{
    const char * scan_id = "0";
    const char * scan_time = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "scan_time"));
    const char * hotfix = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "hotfix"));
    const char * checksum = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "checksum"));
    return wdb_hotfix_save(wdb, scan_id, scan_time, hotfix, checksum, TRUE);
}

int wdb_syscollector_port_save2(wdb_t * wdb, const cJSON * attributes)
{
    const char * scan_id = "0";
    const char * scan_time = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "scan_time"));
    const char * protocol = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "protocol"));
    const char * local_ip = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "local_ip"));
    const int local_port = cJSON_GetObjectItem(attributes, "local_port") ? cJSON_GetObjectItem(attributes, "local_port")->valueint : 0;
    const char * remote_ip = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "remote_ip"));
    const int remote_port = cJSON_GetObjectItem(attributes, "remote_port") ? cJSON_GetObjectItem(attributes, "remote_port")->valueint : 0;
    const int tx_queue = cJSON_GetObjectItem(attributes, "tx_queue") ? cJSON_GetObjectItem(attributes, "tx_queue")->valueint : 0;
    const int rx_queue = cJSON_GetObjectItem(attributes, "rx_queue") ? cJSON_GetObjectItem(attributes, "rx_queue")->valueint : 0;
    const long long inode = cJSON_GetObjectItem(attributes, "inode") ? (long long) cJSON_GetObjectItem(attributes, "inode")->valuedouble: 0;
    const char * state = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "state"));
    const int pid = cJSON_GetObjectItem(attributes, "pid") ? cJSON_GetObjectItem(attributes, "pid")->valueint : 0;
    const char * process = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "process"));
    const char * checksum = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "checksum"));
    const char * item_id = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "item_id"));
    return wdb_port_save(wdb, scan_id, scan_time, protocol, local_ip, local_port, remote_ip, remote_port, tx_queue, rx_queue, inode,
                         state, pid, process, checksum, item_id, TRUE);
}

int wdb_syscollector_netproto_save2(wdb_t * wdb, const cJSON * attributes)
{
    const char * scan_id = "0";
    const char * iface = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "iface"));
    const char * type_string = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "type"));
    const int type = type_string ? (strcmp(type_string, "ipv6") == 0 ? 1 : 0) : 0;
    const char * gateway = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "gateway"));
    const char * dhcp = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "dhcp"));
    const int metric = cJSON_GetObjectItem(attributes, "metric") ? cJSON_GetObjectItem(attributes, "metric")->valueint : 0;
    const char * checksum = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "checksum"));
    const char * item_id = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "item_id"));
    return wdb_netproto_save(wdb, scan_id, iface, type, gateway, dhcp, metric, checksum, item_id, TRUE);
}

int wdb_syscollector_netaddr_save2(wdb_t * wdb, const cJSON * attributes)
{
    const char * scan_id = "0";
    const char * iface = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "iface"));
    const int proto = cJSON_GetObjectItem(attributes, "proto") ? cJSON_GetObjectItem(attributes, "proto")->valueint : 0;
    const char * address = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "address"));
    const char * netmask = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "netmask"));
    const char * broadcast = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "broadcast"));
    const char * checksum = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "checksum"));
    const char * item_id = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "item_id"));
    return wdb_netaddr_save(wdb, scan_id, iface, proto, address, netmask, broadcast, checksum, item_id, TRUE);
}

int wdb_syscollector_netinfo_save2(wdb_t * wdb, const cJSON * attributes)
{
    const char * scan_id = "0";
    const char * scan_time = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "scan_time"));
    const char * name = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "name"));
    const char * adapter = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "adapter"));
    const char * type = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "type"));
    const char * state = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "state"));
    const int mtu = cJSON_GetObjectItem(attributes, "mtu") ? cJSON_GetObjectItem(attributes, "mtu")->valueint : 0;
    const char * mac = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "mac"));
    const long tx_packets = cJSON_GetObjectItem(attributes, "tx_packets") ? cJSON_GetObjectItem(attributes, "tx_packets")->valueint : 0;
    const long rx_packets = cJSON_GetObjectItem(attributes, "rx_packets") ? cJSON_GetObjectItem(attributes, "rx_packets")->valueint : 0;
    const long tx_bytes = cJSON_GetObjectItem(attributes, "tx_bytes") ? cJSON_GetObjectItem(attributes, "tx_bytes")->valueint : 0;
    const long rx_bytes = cJSON_GetObjectItem(attributes, "rx_bytes") ? cJSON_GetObjectItem(attributes, "rx_bytes")->valueint : 0;
    const long tx_errors = cJSON_GetObjectItem(attributes, "tx_errors") ? cJSON_GetObjectItem(attributes, "tx_errors")->valueint : 0;
    const long rx_errors = cJSON_GetObjectItem(attributes, "rx_errors") ? cJSON_GetObjectItem(attributes, "rx_errors")->valueint : 0;
    const long tx_dropped = cJSON_GetObjectItem(attributes, "tx_dropped") ? cJSON_GetObjectItem(attributes, "tx_dropped")->valueint : 0;
    const long rx_dropped = cJSON_GetObjectItem(attributes, "rx_dropped") ? cJSON_GetObjectItem(attributes, "rx_dropped")->valueint : 0;
    const char * checksum = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "checksum"));
    const char * item_id = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "item_id"));
    return wdb_netinfo_save(wdb, scan_id, scan_time, name, adapter, type, state, mtu, mac, tx_packets, rx_packets, tx_bytes, rx_bytes,
                            tx_errors, rx_errors, tx_dropped, rx_dropped, checksum, item_id, TRUE);
}

int wdb_syscollector_hwinfo_save2(wdb_t * wdb, const cJSON * attributes)
{
    const char * scan_id = "0";
    const char * scan_time = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "scan_time"));
    const char * serial = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "board_serial"));
    const char * cpu_name = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "cpu_name"));
    const int cpu_cores = cJSON_GetObjectItem(attributes, "cpu_cores") ? cJSON_GetObjectItem(attributes, "cpu_cores")->valueint : 0;
    const double cpu_mhz = cJSON_GetObjectItem(attributes, "cpu_mhz") ? cJSON_GetObjectItem(attributes, "cpu_mhz")->valuedouble : 0.0;
    const long ram_total = cJSON_GetObjectItem(attributes, "ram_total") ? cJSON_GetObjectItem(attributes, "ram_total")->valueint : 0;
    const long ram_free = cJSON_GetObjectItem(attributes, "ram_free") ? cJSON_GetObjectItem(attributes, "ram_free")->valueint : 0;
    const long ram_usage = cJSON_GetObjectItem(attributes, "ram_usage") ? cJSON_GetObjectItem(attributes, "ram_usage")->valueint : 0;
    const char * checksum = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "checksum"));
    return wdb_hardware_save(wdb, scan_id, scan_time, serial, cpu_name, cpu_cores, cpu_mhz, ram_total, ram_free, ram_usage, checksum, TRUE);
}

int wdb_syscollector_osinfo_save2(wdb_t * wdb, const cJSON * attributes)
{
    const char * scan_id = "0";
    const char * scan_time = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "scan_time"));
    const char * hostname = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "hostname"));
    const char * architecture = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "architecture"));
    const char * os_name = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "os_name"));
    const char * os_version = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "os_version"));
    const char * os_codename = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "os_codename"));
    const char * os_major = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "os_major"));
    const char * os_minor = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "os_minor"));
    const char * os_patch = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "os_patch"));
    const char * os_build = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "os_build"));
    const char * os_platform = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "os_platform"));
    const char * sysname = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "sysname"));
    const char * release = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "release"));
    const char * version = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "version"));
    const char * os_release = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "os_release"));
    const char * os_display_version = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "os_display_version"));
    const char * checksum = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "checksum"));
    return wdb_osinfo_save(wdb, scan_id, scan_time, hostname, architecture, os_name, os_version, os_codename, os_major, os_minor,
                           os_patch, os_build, os_platform, sysname, release, version, os_release, os_display_version, checksum, TRUE);
}

int wdb_syscollector_users_save2(wdb_t * wdb, const cJSON * attributes)
{
    const char * scan_id = "0";
    const char * scan_time = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "scan_time"));
    const char * user_name = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "user_name"));
    const char * user_full_name = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "user_full_name"));
    const char * user_home = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "user_home"));
    const long long user_id = cJSON_GetObjectItem(attributes, "user_id") ? cJSON_GetObjectItem(attributes, "user_id")->valuedouble : 0;
    const long long user_uid_signed = cJSON_GetObjectItem(attributes, "user_uid_signed") ? cJSON_GetObjectItem(attributes, "user_uid_signed")->valuedouble : 0;
    const char * user_uuid = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "user_uuid"));
    const char * user_groups = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "user_groups"));
    const long long user_group_id =  cJSON_GetObjectItem(attributes, "user_group_id") ? cJSON_GetObjectItem(attributes, "user_group_id")->valuedouble : 0;
    const long long user_group_id_signed =  cJSON_GetObjectItem(attributes, "user_group_id_signed") ? cJSON_GetObjectItem(attributes, "user_group_id_signed")->valuedouble : 0;
    const double user_created = cJSON_GetObjectItem(attributes, "user_created") ? cJSON_GetObjectItem(attributes, "user_created")->valuedouble : 0.0;
    const char * user_roles = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "user_roles"));
    const char * user_shell = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "user_shell"));
    const char * user_type = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "user_type"));
    const bool user_is_hidden = cJSON_GetObjectItem(attributes, "user_is_hidden") ? cJSON_GetObjectItem(attributes, "user_is_hidden")->valueint : false;
    const bool user_is_remote = cJSON_GetObjectItem(attributes, "user_is_remote") ? cJSON_GetObjectItem(attributes, "user_is_remote")->valueint : false;
    const long long user_last_login = cJSON_GetObjectItem(attributes, "user_last_login") ? cJSON_GetObjectItem(attributes, "user_last_login")->valuedouble : 0;
    const long long user_auth_failed_count = cJSON_GetObjectItem(attributes, "user_auth_failed_count") ? cJSON_GetObjectItem(attributes, "user_auth_failed_count") ->valuedouble : 0;
    const double user_auth_failed_timestamp = cJSON_GetObjectItem(attributes, "user_auth_failed_timestamp") ? cJSON_GetObjectItem(attributes, "user_auth_failed_timestamp") ->valuedouble : 0.0;
    const double user_password_last_set_time = cJSON_GetObjectItem(attributes, "user_password_last_set_time") ? cJSON_GetObjectItem(attributes, "user_password_last_set_time")->valuedouble : 0.0;
    const int user_password_expiration_date = cJSON_GetObjectItem(attributes, "user_password_expiration_date") ? cJSON_GetObjectItem(attributes, "user_password_expiration_date")->valueint : 0;
    const char * user_password_hash_algorithm = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "user_password_hash_algorithm"));
    const int user_password_inactive_days = cJSON_GetObjectItem(attributes, "user_password_inactive_days") ? cJSON_GetObjectItem(attributes, "user_password_inactive_days")->valueint : 0;
    const int user_password_last_change = cJSON_GetObjectItem(attributes, "user_password_last_change") ? cJSON_GetObjectItem(attributes, "user_password_last_change")->valueint : 0;
    const int user_password_max_days_between_changes = cJSON_GetObjectItem(attributes, "user_password_max_days_between_changes") ? cJSON_GetObjectItem(attributes, "user_password_max_days_between_changes")->valueint : 0;
    const int user_password_min_days_between_changes = cJSON_GetObjectItem(attributes, "user_password_min_days_between_changes") ? cJSON_GetObjectItem(attributes, "user_password_min_days_between_changes")->valueint : 0;
    const char * user_password_status = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "user_password_status"));
    const int user_password_warning_days_before_expiration = cJSON_GetObjectItem(attributes, "user_password_warning_days_before_expiration") ? cJSON_GetObjectItem(attributes, "user_password_warning_days_before_expiration")->valueint : 0;
    const long long process_pid = cJSON_GetObjectItem(attributes, "process_pid") ? cJSON_GetObjectItem(attributes, "process_pid")->valuedouble : 0;
    const char * host_ip = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "host_ip"));
    const bool login_status = cJSON_GetObjectItem(attributes, "login_status") ? cJSON_GetObjectItem(attributes, "login_status")->valueint : false;
    const char * login_type = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "login_type"));
    const char * login_tty = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "login_tty"));
    const char * checksum = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "checksum"));

    user_record_t user_record = {
        .scan_id = scan_id, .scan_time = scan_time, .user_name = user_name,
        .user_full_name = user_full_name, .user_home = user_home, .user_id = user_id, .user_uid_signed = user_uid_signed,
        .user_uuid = user_uuid, .user_groups = user_groups, .user_group_id = user_group_id, .user_group_id_signed = user_group_id_signed,
        .user_created = user_created, .user_roles = user_roles, .user_shell = user_shell, .user_type = user_type,
        .user_is_hidden = user_is_hidden, .user_is_remote = user_is_remote, .user_last_login = user_last_login,
        .user_auth_failed_count = user_auth_failed_count, .user_auth_failed_timestamp = user_auth_failed_timestamp,
        .user_password_last_set_time = user_password_last_set_time, .user_password_expiration_date = user_password_expiration_date,
        .user_password_hash_algorithm = user_password_hash_algorithm, .user_password_inactive_days = user_password_inactive_days,
        .user_password_last_change = user_password_last_change, .user_password_max_days_between_changes = user_password_max_days_between_changes,
        .user_password_min_days_between_changes = user_password_min_days_between_changes, .user_password_status = user_password_status,
        .user_password_warning_days_before_expiration = user_password_warning_days_before_expiration, .process_pid = process_pid,
        .host_ip = host_ip, .login_status = login_status, .login_type = login_type, .login_tty = login_tty, .checksum = checksum};

    return wdb_users_save(wdb, &user_record, TRUE);
}

int wdb_syscollector_groups_save2(wdb_t * wdb, const cJSON * attributes)
{
    const char * scan_id = "0";
    const char * scan_time = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "scan_time"));
    const long long group_id = cJSON_GetObjectItem(attributes, "group_id") ? cJSON_GetObjectItem(attributes, "group_id")->valuedouble : 0;
    const char * group_name = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "group_name"));
    const char * group_description = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "group_description"));
    const long long group_id_signed = cJSON_GetObjectItem(attributes, "group_id_signed") ? cJSON_GetObjectItem(attributes, "group_id_signed")->valuedouble : 0;
    const char * group_uuid = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "group_uuid"));
    const bool group_is_hidden = cJSON_GetObjectItem(attributes, "group_is_hidden") ? cJSON_GetObjectItem(attributes, "group_is_hidden")->valueint : false;
    const char * group_users = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "group_users"));
    const char * checksum = cJSON_GetStringValue(cJSON_GetObjectItem(attributes, "checksum"));
    return wdb_groups_save(wdb, scan_id, scan_time, group_id, group_name, group_description, group_id_signed, group_uuid, group_is_hidden,
                           group_users, checksum, TRUE);
}

int wdb_syscollector_save2(wdb_t * wdb, wdb_component_t component, const char * payload)
{
    int result = -1;
    cJSON * data = cJSON_Parse(payload);
    if(!data)
    {
        mdebug1("at wdb_syscollector_save2(): no payload");
        return -1;
    }
    cJSON * attributes = cJSON_GetObjectItem(data, "attributes");
    if(!attributes)
    {
        cJSON_Delete(data);
        mdebug1("at wdb_syscollector_save2(): no attributes");
        return -1;
    }
    if(component == WDB_SYSCOLLECTOR_PROCESSES)
    {
        result = wdb_syscollector_processes_save2(wdb, attributes);
    }
    else if(component == WDB_SYSCOLLECTOR_PACKAGES)
    {
        result = wdb_syscollector_package_save2(wdb, attributes);
    }
    else if(component == WDB_SYSCOLLECTOR_HOTFIXES)
    {
        result = wdb_syscollector_hotfix_save2(wdb, attributes);
    }
    else if(component == WDB_SYSCOLLECTOR_PORTS)
    {
        result = wdb_syscollector_port_save2(wdb, attributes);
    }
    else if(component == WDB_SYSCOLLECTOR_NETPROTO)
    {
        result = wdb_syscollector_netproto_save2(wdb, attributes);
    }
    else if(component == WDB_SYSCOLLECTOR_NETADDRESS)
    {
        result = wdb_syscollector_netaddr_save2(wdb, attributes);
    }
    else if(component == WDB_SYSCOLLECTOR_NETINFO)
    {
        result = wdb_syscollector_netinfo_save2(wdb, attributes);
    }
    else if(component == WDB_SYSCOLLECTOR_HWINFO)
    {
        result = wdb_syscollector_hwinfo_save2(wdb, attributes);
    }
    else if(component == WDB_SYSCOLLECTOR_OSINFO)
    {
        result = wdb_syscollector_osinfo_save2(wdb, attributes);
    }
    else if(component == WDB_SYSCOLLECTOR_USERS)
    {
        result = wdb_syscollector_users_save2(wdb, attributes);
    }
    else if(component == WDB_SYSCOLLECTOR_GROUPS)
    {
        result = wdb_syscollector_groups_save2(wdb, attributes);
    }
    else
    {
        mdebug1("at wdb_syscollector_save2(): Invalid component.");
        result = OS_INVALID;
    }

    cJSON_Delete(data);
    return result;
}
