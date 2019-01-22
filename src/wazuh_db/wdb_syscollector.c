/*
 * Wazuh SQLite integration
 * Copyright (C) 2015-2019, Wazuh Inc.
 * August 30, 2017.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wdb.h"


// Function to save Network info into the DB. Return 0 on success or -1 on error.
int wdb_netinfo_save(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * name, const char * adapter, const char * type, const char * state, int mtu, const char * mac, long tx_packets, long rx_packets, long tx_bytes, long rx_bytes, long tx_errors, long rx_errors, long tx_dropped, long rx_dropped) {

    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("at wdb_netinfo_save(): cannot begin transaction");
        return -1;
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
        rx_dropped) < 0) {

        return -1;
    }

    return 0;
}

// Insert Network info tuple. Return 0 on success or -1 on error.
int wdb_netinfo_insert(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * name, const char * adapter, const char * type, const char * state, int mtu, const char * mac, long tx_packets, long rx_packets, long tx_bytes, long rx_bytes, long tx_errors, long rx_errors, long tx_dropped, long rx_dropped) {
    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_NETINFO_INSERT) < 0) {
        mdebug1("at wdb_netinfo_insert(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_NETINFO_INSERT];

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

    if (sqlite3_step(stmt) == SQLITE_DONE){
        return 0;
    }
    else {
        merror("at wdb_netinfo_insert(): sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

// Save IPv4/IPv6 protocol info into DB.
int wdb_netproto_save(wdb_t * wdb, const char * scan_id, const char * iface, int type, const char * gateway, const char * dhcp) {

    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("at wdb_netproto_save(): cannot begin transaction");
        return -1;
    }

    if (wdb_netproto_insert(wdb,
        scan_id,
        iface,
        type,
        gateway,
        dhcp) < 0) {

        return -1;
    }

    return 0;
}

// Insert IPv4/IPv6 protocol info tuple. Return 0 on success or -1 on error.
int wdb_netproto_insert(wdb_t * wdb, const char * scan_id, const char * iface, int type, const char * gateway, const char * dhcp) {

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_PROTO_INSERT) < 0) {
        mdebug1("at wdb_netproto_insert(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_PROTO_INSERT];

    sqlite3_bind_text(stmt, 1, scan_id, -1, NULL);
    sqlite3_bind_text(stmt, 2, iface, -1, NULL);

    if (type == WDB_NETADDR_IPV4)
        sqlite3_bind_text(stmt, 3, "ipv4", -1, NULL);
    else
        sqlite3_bind_text(stmt, 3, "ipv6", -1, NULL);

    sqlite3_bind_text(stmt, 4, gateway, -1, NULL);
    sqlite3_bind_text(stmt, 5, dhcp, -1, NULL);

    if (sqlite3_step(stmt) == SQLITE_DONE){
        return 0;
    }
    else {
        merror("at wdb_netproto_insert(): sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

// Save IPv4/IPv6 address info into DB.
int wdb_netaddr_save(wdb_t * wdb, const char * scan_id, const char * iface, int proto, const char * address, const char * netmask, const char * broadcast) {

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
        broadcast) < 0) {

        return -1;
    }

    return 0;
}

// Insert IPv4/IPv6 address info tuple. Return 0 on success or -1 on error.
int wdb_netaddr_insert(wdb_t * wdb, const char * scan_id, const char * iface, int proto, const char * address, const char * netmask, const char * broadcast) {

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_ADDR_INSERT) < 0) {
        mdebug1("at wdb_netaddr_insert(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_ADDR_INSERT];

    sqlite3_bind_text(stmt, 1, scan_id, -1, NULL);
    sqlite3_bind_text(stmt, 2, iface, -1, NULL);

    if (proto == WDB_NETADDR_IPV4)
        sqlite3_bind_text(stmt, 3, "ipv4", -1, NULL);
    else
        sqlite3_bind_text(stmt, 3, "ipv6", -1, NULL);

    sqlite3_bind_text(stmt, 4, address, -1, NULL);
    sqlite3_bind_text(stmt, 5, netmask, -1, NULL);
    sqlite3_bind_text(stmt, 6, broadcast, -1, NULL);

    if (sqlite3_step(stmt) == SQLITE_DONE){
        return 0;
    }
    else {
        merror("at wdb_netaddr_insert(): sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        return -1;
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

    if (sqlite3_step(stmt) != SQLITE_DONE) {
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

    if (sqlite3_step(stmt) != SQLITE_DONE) {
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

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        merror("Deleting old information from 'sys_netaddr' table: %s", sqlite3_errmsg(wdb->db));
        return -1;
    }

    return 0;
}

// Function to save OS info into the DB. Return 0 on success or -1 on error.
int wdb_osinfo_save(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * hostname, const char * architecture, const char * os_name, const char * os_version, const char * os_codename, const char * os_major, const char * os_minor, const char * os_build, const char * os_platform, const char * sysname, const char * release, const char * version) {

    sqlite3_stmt *stmt = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("at wdb_osinfo_save(): cannot begin transaction");
        return -1;
    }

    /* Delete old OS information before insert the new scan */
    if (wdb_stmt_cache(wdb, WDB_STMT_OSINFO_DEL) < 0) {
        mdebug1("at wdb_osinfo_save(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_OSINFO_DEL];

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        merror("Deleting old information from 'sys_osinfo' table: %s", sqlite3_errmsg(wdb->db));
        return -1;
    }

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
        os_build,
        os_platform,
        sysname,
        release,
        version) < 0) {

        return -1;
    }

    return 0;
}

// Insert OS info tuple. Return 0 on success or -1 on error. (v2)
int wdb_osinfo_insert(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * hostname, const char * architecture, const char * os_name, const char * os_version, const char * os_codename, const char * os_major, const char * os_minor, const char * os_build, const char * os_platform, const char * sysname, const char * release, const char * version) {
    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_OSINFO_INSERT) < 0) {
        mdebug1("at wdb_osinfo_insert(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_OSINFO_INSERT];

    sqlite3_bind_text(stmt, 1, scan_id, -1, NULL);
    sqlite3_bind_text(stmt, 2, scan_time, -1, NULL);
    sqlite3_bind_text(stmt, 3, hostname, -1, NULL);
    sqlite3_bind_text(stmt, 4, architecture, -1, NULL);
    sqlite3_bind_text(stmt, 5, os_name, -1, NULL);
    sqlite3_bind_text(stmt, 6, os_version, -1, NULL);
    sqlite3_bind_text(stmt, 7, os_codename, -1, NULL);
    sqlite3_bind_text(stmt, 8, os_major, -1, NULL);
    sqlite3_bind_text(stmt, 9, os_minor, -1, NULL);
    sqlite3_bind_text(stmt, 10, os_build, -1, NULL);
    sqlite3_bind_text(stmt, 11, os_platform, -1, NULL);
    sqlite3_bind_text(stmt, 12, sysname, -1, NULL);
    sqlite3_bind_text(stmt, 13, release, -1, NULL);
    sqlite3_bind_text(stmt, 14, version, -1, NULL);

    if (sqlite3_step(stmt) == SQLITE_DONE){
        return 0;
    }
    else {
        merror("at wdb_osinfo_insert(): sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        return -1;
    }

}

// Function to save Package info into the DB. Return 0 on success or -1 on error.
int wdb_package_save(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * format, const char * name, const char * priority, const char * section, long size, const char * vendor, const char * install_time, const char * version, const char * architecture, const char * multiarch, const char * source, const char * description, const char * location) {

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
        0) < 0) {

        return -1;
    }

    return 0;
}

// Insert Package info tuple. Return 0 on success or -1 on error.
int wdb_package_insert(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * format, const char * name, const char * priority, const char * section, long size, const char * vendor, const char * install_time, const char * version, const char * architecture, const char * multiarch, const char * source, const char * description, const char * location, const char triaged) {
    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_PROGRAM_INSERT) < 0) {
        mdebug1("at wdb_package_insert(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_PROGRAM_INSERT];

    sqlite3_bind_text(stmt, 1, scan_id, -1, NULL);
    sqlite3_bind_text(stmt, 2, scan_time, -1, NULL);
    sqlite3_bind_text(stmt, 3, format, -1, NULL);
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
    sqlite3_bind_text(stmt, 15, location, -1, NULL);
    sqlite3_bind_int(stmt, 16, triaged);

    switch (sqlite3_step(stmt)) {
        case SQLITE_DONE:
            return 0;
        case SQLITE_CONSTRAINT:
            if (!strncmp(sqlite3_errmsg(wdb->db), "UNIQUE", 6)) {
                mdebug1("at wdb_package_insert(): sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
                return 0;
            } else {
                merror("at wdb_package_insert(): sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
                return -1;
            }
        default:
            merror("at wdb_package_insert(): sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
            return -1;
    }
}

// Function to update old Package information from DB. Return 0 on success or -1 on error.
int wdb_package_update(wdb_t * wdb, const char * scan_id) {

    sqlite3_stmt *stmt = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("at wdb_package_update(): cannot begin transaction");
        return -1;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_PROGRAM_UPD) < 0) {
        mdebug1("at wdb_package_update(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_PROGRAM_UPD];

    sqlite3_bind_text(stmt, 1, scan_id, -1, NULL);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        merror("Unable to update the 'sys_programs' table: %s", sqlite3_errmsg(wdb->db));
        return -1;
    }

    return 0;
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

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        merror("Deleting old information from 'sys_programs' table: %s", sqlite3_errmsg(wdb->db));
        return -1;
    }

    return 0;
}

// Function to save OS info into the DB. Return 0 on success or -1 on error.
int wdb_hardware_save(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * serial, const char * cpu_name, int cpu_cores, const char * cpu_mhz, uint64_t ram_total, uint64_t ram_free, int ram_usage) {

    sqlite3_stmt *stmt = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("at wdb_hardware_save(): cannot begin transaction");
        return -1;
    }

    /* Delete old OS information before insert the new scan */
    if (wdb_stmt_cache(wdb, WDB_STMT_HWINFO_DEL) < 0) {
        mdebug1("at wdb_hardware_save(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_HWINFO_DEL];

    if (sqlite3_step(stmt) != SQLITE_DONE) {
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
        ram_usage) < 0) {

        return -1;
    }

    return 0;
}

// Insert HW info tuple. Return 0 on success or -1 on error.
int wdb_hardware_insert(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * serial, const char * cpu_name, int cpu_cores, const char * cpu_mhz, uint64_t ram_total, uint64_t ram_free, int ram_usage) {
    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_HWINFO_INSERT) < 0) {
        mdebug1("at wdb_hardware_insert(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_HWINFO_INSERT];

    sqlite3_bind_text(stmt, 1, scan_id, -1, NULL);
    sqlite3_bind_text(stmt, 2, scan_time, -1, NULL);
    sqlite3_bind_text(stmt, 3, serial, -1, NULL);
    sqlite3_bind_text(stmt, 4, cpu_name, -1, NULL);

    if (cpu_cores > 0) {
        sqlite3_bind_int(stmt, 5, cpu_cores);
    } else {
        sqlite3_bind_null(stmt, 5);
    }

    sqlite3_bind_text(stmt, 6, cpu_mhz, -1, NULL);

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

    if (ram_usage > 0) {
        sqlite3_bind_int(stmt, 9, ram_usage);
    } else {
        sqlite3_bind_null(stmt, 9);
    }

    if (sqlite3_step(stmt) == SQLITE_DONE){
        return 0;
    }
    else {
        merror("at wdb_hardware_insert(): sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

// Function to save Port info into the DB. Return 0 on success or -1 on error.
int wdb_port_save(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * protocol, const char * local_ip, int local_port, const char * remote_ip, int remote_port, int tx_queue, int rx_queue, int inode, const char * state, int pid, const char * process) {

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
        process) < 0) {

        return -1;
    }

    return 0;
}

// Insert port info tuple. Return 0 on success or -1 on error.
int wdb_port_insert(wdb_t * wdb, const char * scan_id, const char * scan_time, const char * protocol, const char * local_ip, int local_port, const char * remote_ip, int remote_port, int tx_queue, int rx_queue, int inode, const char * state, int pid, const char * process) {
    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_PORT_INSERT) < 0) {
        mdebug1("at wdb_port_insert(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_PORT_INSERT];

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
        sqlite3_bind_int(stmt, 10, inode);
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

    if (sqlite3_step(stmt) == SQLITE_DONE){
        return 0;
    }
    else {
        merror("at wdb_port_insert(): sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        return -1;
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

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        merror("Deleting old information from 'sys_ports' table: %s", sqlite3_errmsg(wdb->db));
        return -1;
    }

    return 0;
}

// Function to save process info into the DB. Return 0 on success or -1 on error.
int wdb_process_save(wdb_t * wdb, const char * scan_id, const char * scan_time, int pid, const char * name, const char * state, int ppid, int utime, int stime, const char * cmd, const char * argvs, const char * euser, const char * ruser, const char * suser, const char * egroup, const char * rgroup, const char * sgroup, const char * fgroup, int priority, int nice, int size, int vm_size, int resident, int share, int start_time, int pgrp, int session, int nlwp, int tgid, int tty, int processor) {

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
        processor) < 0) {

        return -1;
    }

    return 0;
}

// Insert process info tuple. Return 0 on success or -1 on error.
int wdb_process_insert(wdb_t * wdb, const char * scan_id, const char * scan_time, int pid, const char * name, const char * state, int ppid, int utime, int stime, const char * cmd, const char * argvs, const char * euser, const char * ruser, const char * suser, const char * egroup, const char * rgroup, const char * sgroup, const char * fgroup, int priority, int nice, int size, int vm_size, int resident, int share, int start_time, int pgrp, int session, int nlwp, int tgid, int tty, int processor) {
    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_PROC_INSERT) < 0) {
        mdebug1("at wdb_process_insert(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_PROC_INSERT];

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
        sqlite3_bind_int(stmt, 24, start_time);
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

    if (sqlite3_step(stmt) == SQLITE_DONE){
        return 0;
    }
    else {
        merror("at wdb_process_insert(): sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        return -1;
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

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        merror("Deleting old information from 'sys_processes' table: %s", sqlite3_errmsg(wdb->db));
        return -1;
    }

    return 0;
}
