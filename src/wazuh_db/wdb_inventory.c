/*
 * Wazuh SQLite integration
 * Copyright (C) 2015-2019, Wazuh Inc.
 * December 13, 2019.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wdb.h"

#define DEFAULT_SCAN_ID "1"

/* Get the information to save a HW entry in the DB. */
int wdb_inventory_save_hw(wdb_t * wdb, const char * payload) {
    int result = 0;

    cJSON * data = cJSON_Parse(payload);

    if (data == NULL) {
        mdebug1("DB(%s): cannot parse inventory payload: '%s'", wdb->id, payload);
        return -1;
    }

    char * scan_time = cJSON_GetStringValue(cJSON_GetObjectItem(data, "timestamp"));

    if (scan_time == NULL) {
        merror("DB(%s) HW save request with no timestamp path argument.", wdb->id);
        cJSON_Delete(data);
        return -1;
    }

    cJSON * attributes = cJSON_GetObjectItem(data, "attributes");

    if (!cJSON_IsObject(attributes)) {
        merror("DB(%s) HW save request with no attributes argument.", wdb->id);
        cJSON_Delete(data);
        return -1;
    }

    cJSON * attribute = NULL;
    attribute = cJSON_GetObjectItem(attributes, "board_serial");
    char * serial = attribute ? attribute->valuestring : NULL;
    attribute = cJSON_GetObjectItem(attributes, "cpu_name");
    char * cpu_name = attribute ? attribute->valuestring : NULL;
    attribute = cJSON_GetObjectItem(attributes, "cpu_cores");
    int cpu_cores = attribute ? attribute->valueint : -1;
    attribute = cJSON_GetObjectItem(attributes, "cpu_MHz");
    char * cpu_mhz = NULL;
    if (attribute) {
        os_calloc(20, sizeof(char), cpu_mhz);
        snprintf(cpu_mhz, 19, "%0.1f", attribute->valuedouble);
    }
    attribute = cJSON_GetObjectItem(attributes, "ram_total");
    long ram_total = attribute ? (long)attribute->valuedouble : -1;
    attribute = cJSON_GetObjectItem(attributes, "ram_free");
    long ram_free = attribute ? (long)attribute->valuedouble : -1;
    attribute = cJSON_GetObjectItem(attributes, "ram_usage");
    int ram_usage = attribute ? attribute->valueint : -1;

    if (result = wdb_hardware_save(wdb, DEFAULT_SCAN_ID, scan_time, serial, cpu_name, cpu_cores, cpu_mhz, ram_total, ram_free, ram_usage), result < 0) {
        mdebug1("Cannot save HW information.");
    }

    if (cpu_mhz) {
        free(cpu_mhz);
    }
    cJSON_Delete(data);
    return result;
}

/* Get the information to save an OS entry in the DB. */
int wdb_inventory_save_os(wdb_t * wdb, const char * payload) {
    int result = 0;

    cJSON * data = cJSON_Parse(payload);

    if (data == NULL) {
        mdebug1("DB(%s): cannot parse inventory payload: '%s'", wdb->id, payload);
        return -1;
    }

    char * scan_time = cJSON_GetStringValue(cJSON_GetObjectItem(data, "timestamp"));

    if (scan_time == NULL) {
        merror("DB(%s) OS save request with no timestamp path argument.", wdb->id);
        cJSON_Delete(data);
        return -1;
    }

    cJSON * attributes = cJSON_GetObjectItem(data, "attributes");

    if (!cJSON_IsObject(attributes)) {
        merror("DB(%s) OS save request with no attributes argument.", wdb->id);
        cJSON_Delete(data);
        return -1;
    }

    cJSON * attribute = NULL;
    attribute = cJSON_GetObjectItem(attributes, "hostname");
    char * hostname = attribute ? attribute->valuestring : NULL;
    attribute = cJSON_GetObjectItem(attributes, "architecture");
    char * architecture = attribute ? attribute->valuestring : NULL;
    attribute = cJSON_GetObjectItem(attributes, "os_name");
    char * os_name = attribute ? attribute->valuestring : NULL;
    attribute = cJSON_GetObjectItem(attributes, "os_release");
    char * os_release = attribute ? attribute->valuestring : NULL;
    attribute = cJSON_GetObjectItem(attributes, "os_version");
    char * os_version = attribute ? attribute->valuestring : NULL;
    attribute = cJSON_GetObjectItem(attributes, "os_codename");
    char * os_codename = attribute ? attribute->valuestring : NULL;
    attribute = cJSON_GetObjectItem(attributes, "os_major");
    char * os_major = attribute ? attribute->valuestring : NULL;
    attribute = cJSON_GetObjectItem(attributes, "os_minor");
    char * os_minor = attribute ? attribute->valuestring : NULL;
    attribute = cJSON_GetObjectItem(attributes, "os_build");
    char * os_build = attribute ? attribute->valuestring : NULL;
    attribute = cJSON_GetObjectItem(attributes, "os_platform");
    char * os_platform = attribute ? attribute->valuestring : NULL;
    attribute = cJSON_GetObjectItem(attributes, "sysname");
    char * sysname = attribute ? attribute->valuestring : NULL;
    attribute = cJSON_GetObjectItem(attributes, "release");
    char * release = attribute ? attribute->valuestring : NULL;
    attribute = cJSON_GetObjectItem(attributes, "version");
    char * version = attribute ? attribute->valuestring : NULL;

    if (result = wdb_osinfo_save(wdb, DEFAULT_SCAN_ID, scan_time, hostname, architecture, os_name, os_version, os_codename, os_major, os_minor, os_build, os_platform, sysname, release, version, os_release), result < 0) {
        mdebug1("Cannot save OS information.");
    }

    cJSON_Delete(data);
    return result;
}

/* Get the information to save a network entry in the DB. */
int wdb_inventory_save_network(wdb_t * wdb, const char * payload) {
    int result = 0;

    cJSON * data = cJSON_Parse(payload);

    if (data == NULL) {
        mdebug1("DB(%s): cannot parse inventory payload: '%s'", wdb->id, payload);
        return -1;
    }

    char * scan_time = cJSON_GetStringValue(cJSON_GetObjectItem(data, "timestamp"));

    if (scan_time == NULL) {
        merror("DB(%s) network save request with no timestamp path argument.", wdb->id);
        cJSON_Delete(data);
        return -1;
    }

    cJSON * attributes = cJSON_GetObjectItem(data, "attributes");

    if (!cJSON_IsObject(attributes)) {
        merror("DB(%s) network save request with no attributes argument.", wdb->id);
        cJSON_Delete(data);
        return -1;
    }

    cJSON * attribute = NULL;
    attribute = cJSON_GetObjectItem(attributes, "name");
    char * name = attribute ? attribute->valuestring : NULL;
    attribute = cJSON_GetObjectItem(attributes, "adapter");
    char * adapter = attribute ? attribute->valuestring : NULL;
    attribute = cJSON_GetObjectItem(attributes, "type");
    char * type = attribute ? attribute->valuestring : NULL;
    attribute = cJSON_GetObjectItem(attributes, "state");
    char * state = attribute ? attribute->valuestring : NULL;
    attribute = cJSON_GetObjectItem(attributes, "mtu");
    int mtu = attribute ? attribute->valueint : -1;
    attribute = cJSON_GetObjectItem(attributes, "mac");
    char * mac = attribute ? attribute->valuestring : NULL;
    attribute = cJSON_GetObjectItem(attributes, "tx_packets");
    long tx_packets = attribute ? (long)attribute->valuedouble : -1;
    attribute = cJSON_GetObjectItem(attributes, "rx_packets");
    long rx_packets = attribute ? (long)attribute->valuedouble : -1;
    attribute = cJSON_GetObjectItem(attributes, "tx_bytes");
    long tx_bytes = attribute ? (long)attribute->valuedouble : -1;
    attribute = cJSON_GetObjectItem(attributes, "rx_bytes");
    long rx_bytes = attribute ? (long)attribute->valuedouble : -1;
    attribute = cJSON_GetObjectItem(attributes, "tx_errors");
    long tx_errors = attribute ? (long)attribute->valuedouble : -1;
    attribute = cJSON_GetObjectItem(attributes, "rx_errors");
    long rx_errors = attribute ? (long)attribute->valuedouble : -1;
    attribute = cJSON_GetObjectItem(attributes, "tx_dropped");
    long tx_dropped = attribute ? (long)attribute->valuedouble : -1;
    attribute = cJSON_GetObjectItem(attributes, "rx_dropped");
    long rx_dropped = attribute ? (long)attribute->valuedouble : -1;

    if (result = wdb_netinfo_save(wdb, DEFAULT_SCAN_ID, scan_time, name, adapter, type, state, mtu, mac, tx_packets, rx_packets, tx_bytes, rx_bytes, tx_errors, rx_errors, tx_dropped, rx_dropped), result < 0) {
        mdebug1("Cannot save netinfo information.");
    }
    else {
        cJSON * ip = NULL;
        if (ip = cJSON_GetObjectItem(attributes, "IPv4"), ip) {
            int proto = 0;
            attribute = cJSON_GetObjectItem(ip, "gateway");
            char * gateway = attribute ? attribute->valuestring : NULL;
            attribute = cJSON_GetObjectItem(ip, "metric");
            int metric = attribute ? attribute->valueint : -1;
            attribute = cJSON_GetObjectItem(ip, "dhcp");
            char * dhcp = attribute ? attribute->valuestring : NULL;

            if (result = wdb_netproto_save(wdb, DEFAULT_SCAN_ID, name, proto, gateway, dhcp, metric), result < 0) {
                mdebug1("Cannot save netproto information.");
            }
            else {
                cJSON * addr = NULL;
                if (addr = cJSON_GetObjectItem(ip, "address"), addr) {
                    cJSON * nmask = cJSON_GetObjectItem(ip, "netmask");
                    cJSON * bcast = cJSON_GetObjectItem(ip, "broadcast");

                    int i;
                    for (i = 0; i < cJSON_GetArraySize(addr); i++) {
                        attribute = cJSON_GetArrayItem(addr, i);
                        char * address = attribute ? attribute->valuestring : NULL;
                        attribute = cJSON_GetArrayItem(nmask, i);
                        char * netmask = attribute ? attribute->valuestring : NULL;
                        attribute = cJSON_GetArrayItem(bcast, i);
                        char * broadcast = attribute ? attribute->valuestring : NULL;

                        if (result = wdb_netaddr_save(wdb, DEFAULT_SCAN_ID, name, proto, address, netmask, broadcast), result < 0) {
                            mdebug1("Cannot save netaddr information.");
                        }
                    }
                }
            }
        }
        if (ip = cJSON_GetObjectItem(attributes, "IPv6"), ip) {
            int proto = 1;
            attribute = cJSON_GetObjectItem(ip, "gateway");
            char * gateway = attribute ? attribute->valuestring : NULL;
            attribute = cJSON_GetObjectItem(ip, "metric");
            int metric = attribute ? attribute->valueint : -1;
            attribute = cJSON_GetObjectItem(ip, "dhcp");
            char * dhcp = attribute ? attribute->valuestring : NULL;

            if (result = wdb_netproto_save(wdb, DEFAULT_SCAN_ID, name, proto, gateway, dhcp, metric), result < 0) {
                mdebug1("Cannot save netproto information.");
            }
            else {
                cJSON * addr = NULL;
                if (addr = cJSON_GetObjectItem(ip, "address"), addr) {
                    cJSON * nmask = cJSON_GetObjectItem(ip, "netmask");
                    cJSON * bcast = cJSON_GetObjectItem(ip, "broadcast");

                    int i;
                    for (i = 0; i < cJSON_GetArraySize(addr); i++) {
                        attribute = cJSON_GetArrayItem(addr, i);
                        char * address = attribute ? attribute->valuestring : NULL;
                        attribute = cJSON_GetArrayItem(nmask, i);
                        char * netmask = attribute ? attribute->valuestring : NULL;
                        attribute = cJSON_GetArrayItem(bcast, i);
                        char * broadcast = attribute ? attribute->valuestring : NULL;

                        if (result = wdb_netaddr_save(wdb, DEFAULT_SCAN_ID, name, proto, address, netmask, broadcast), result < 0) {
                            mdebug1("Cannot save netaddr information.");
                        }
                    }
                }
            }
        }
    }

    cJSON_Delete(data);
    return result;
}

/* Get the information to delete a network entry from the DB. */
int wdb_inventory_delete_network(wdb_t * wdb, const char * payload) {
    int result = 0;

    cJSON * data = cJSON_Parse(payload);

    if (data == NULL) {
        mdebug1("DB(%s): cannot parse inventory payload: '%s'", wdb->id, payload);
        return -1;
    }

    cJSON * attributes = cJSON_GetObjectItem(data, "attributes");

    if (!cJSON_IsObject(attributes)) {
        merror("DB(%s) network delete request with no attributes argument.", wdb->id);
        cJSON_Delete(data);
        return -1;
    }

    cJSON * attribute = NULL;
    attribute = cJSON_GetObjectItem(attributes, "name");
    char * name = attribute ? attribute->valuestring : NULL;

    if (result = wdb_netinfo_delete2(wdb, name), result < 0) {
        mdebug1("Cannot delete old network entry.");
    }

    cJSON_Delete(data);
    return result;
}

/* Get the information to save a program entry in the DB. */
int wdb_inventory_save_program(wdb_t * wdb, const char * payload) {
    int result = 0;

    cJSON * data = cJSON_Parse(payload);

    if (data == NULL) {
        mdebug1("DB(%s): cannot parse inventory payload: '%s'", wdb->id, payload);
        return -1;
    }

    char * scan_time = cJSON_GetStringValue(cJSON_GetObjectItem(data, "timestamp"));

    if (scan_time == NULL) {
        merror("DB(%s) program save request with no timestamp path argument.", wdb->id);
        cJSON_Delete(data);
        return -1;
    }

    cJSON * attributes = cJSON_GetObjectItem(data, "attributes");

    if (!cJSON_IsObject(attributes)) {
        merror("DB(%s) program save request with no attributes argument.", wdb->id);
        cJSON_Delete(data);
        return -1;
    }

    cJSON * attribute = NULL;
    attribute = cJSON_GetObjectItem(attributes, "format");
    char * format = attribute ? attribute->valuestring : NULL;
    attribute = cJSON_GetObjectItem(attributes, "name");
    char * name = attribute ? attribute->valuestring : NULL;
    attribute = cJSON_GetObjectItem(attributes, "priority");
    char * priority = attribute ? attribute->valuestring : NULL;
    attribute = cJSON_GetObjectItem(attributes, "group");
    char * section = attribute ? attribute->valuestring : NULL;
    attribute = cJSON_GetObjectItem(attributes, "size");
    long size = attribute ? (long)attribute->valuedouble : -1;
    attribute = cJSON_GetObjectItem(attributes, "vendor");
    char * vendor = attribute ? attribute->valuestring : NULL;
    attribute = cJSON_GetObjectItem(attributes, "install_time");
    char * install_time = attribute ? attribute->valuestring : NULL;
    attribute = cJSON_GetObjectItem(attributes, "version");
    char * version = attribute ? attribute->valuestring : NULL;
    attribute = cJSON_GetObjectItem(attributes, "architecture");
    char * architecture = attribute ? attribute->valuestring : NULL;
    attribute = cJSON_GetObjectItem(attributes, "multi-arch");
    char * multiarch = attribute ? attribute->valuestring : NULL;
    attribute = cJSON_GetObjectItem(attributes, "source");
    char * source = attribute ? attribute->valuestring : NULL;
    attribute = cJSON_GetObjectItem(attributes, "description");
    char * description = attribute ? attribute->valuestring : NULL;
    attribute = cJSON_GetObjectItem(attributes, "location");
    char * location = attribute ? attribute->valuestring : NULL;

    if (result = wdb_package_save(wdb, DEFAULT_SCAN_ID, scan_time, format, name, priority, section, size, vendor, install_time, version, architecture, multiarch, source, description, location), result < 0) {
        mdebug1("Cannot save Package information.");
    }

    cJSON_Delete(data);
    return result;
}

/* Get the information to delete a program entry from the DB. */
int wdb_inventory_delete_program(wdb_t * wdb, const char * payload) {
    int result = 0;

    cJSON * data = cJSON_Parse(payload);

    if (data == NULL) {
        mdebug1("DB(%s): cannot parse inventory payload: '%s'", wdb->id, payload);
        return -1;
    }

    cJSON * attributes = cJSON_GetObjectItem(data, "attributes");

    if (!cJSON_IsObject(attributes)) {
        merror("DB(%s) program delete request with no attributes argument.", wdb->id);
        cJSON_Delete(data);
        return -1;
    }

    cJSON * attribute = NULL;
    attribute = cJSON_GetObjectItem(attributes, "name");
    char * name = attribute ? attribute->valuestring : NULL;
    attribute = cJSON_GetObjectItem(attributes, "version");
    char * version = attribute ? attribute->valuestring : NULL;
    attribute = cJSON_GetObjectItem(attributes, "architecture");
    char * architecture = attribute ? attribute->valuestring : NULL;

    if (result = wdb_package_delete2(wdb, name, version, architecture), result < 0) {
        mdebug1("Cannot delete old Package information.");
    }

    cJSON_Delete(data);
    return result;
}

/* Get the information to save a hotfix entry in the DB. */
int wdb_inventory_save_hotfix(wdb_t * wdb, const char * payload) {
    int result = 0;

    cJSON * data = cJSON_Parse(payload);

    if (data == NULL) {
        mdebug1("DB(%s): cannot parse inventory payload: '%s'", wdb->id, payload);
        return -1;
    }

    char * scan_time = cJSON_GetStringValue(cJSON_GetObjectItem(data, "timestamp"));

    if (scan_time == NULL) {
        merror("DB(%s) hotfix save request with no timestamp path argument.", wdb->id);
        cJSON_Delete(data);
        return -1;
    }

    cJSON * attributes = cJSON_GetObjectItem(data, "attributes");

    if (!cJSON_IsObject(attributes)) {
        merror("DB(%s) hotfix save request with no attributes argument.", wdb->id);
        cJSON_Delete(data);
        return -1;
    }

    cJSON * attribute = NULL;
    attribute = cJSON_GetObjectItem(attributes, "hotfix");
    char * hotfix = attribute ? attribute->valuestring : NULL;

    if (result = wdb_hotfix_save(wdb, DEFAULT_SCAN_ID, scan_time, hotfix), result < 0) {
        mdebug1("Cannot save Hotfix information.");
    }

    wdb_set_hotfix_metadata(wdb, DEFAULT_SCAN_ID);

    cJSON_Delete(data);
    return result;
}

/* Get the information to delete a hotfix entry from the DB. */
int wdb_inventory_delete_hotfix(wdb_t * wdb, const char * payload) {
    int result = 0;

    cJSON * data = cJSON_Parse(payload);

    if (data == NULL) {
        mdebug1("DB(%s): cannot parse inventory payload: '%s'", wdb->id, payload);
        return -1;
    }

    cJSON * attributes = cJSON_GetObjectItem(data, "attributes");

    if (!cJSON_IsObject(attributes)) {
        merror("DB(%s) hotfix delete request with no attributes argument.", wdb->id);
        cJSON_Delete(data);
        return -1;
    }

    cJSON * attribute = NULL;
    attribute = cJSON_GetObjectItem(attributes, "hotfix");
    char * hotfix = attribute ? attribute->valuestring : NULL;

    if (result = wdb_hotfix_delete2(wdb, hotfix), result < 0) {
        mdebug1("Cannot delete old Hotfix information.");
    }

    cJSON_Delete(data);
    return result;
}

/* Get the information to save a port entry in the DB. */
int wdb_inventory_save_port(wdb_t * wdb, const char * payload) {
    int result = 0;

    cJSON * data = cJSON_Parse(payload);

    if (data == NULL) {
        mdebug1("DB(%s): cannot parse inventory payload: '%s'", wdb->id, payload);
        return -1;
    }

    char * scan_time = cJSON_GetStringValue(cJSON_GetObjectItem(data, "timestamp"));

    if (scan_time == NULL) {
        merror("DB(%s) port save request with no timestamp path argument.", wdb->id);
        cJSON_Delete(data);
        return -1;
    }

    cJSON * attributes = cJSON_GetObjectItem(data, "attributes");

    if (!cJSON_IsObject(attributes)) {
        merror("DB(%s) port save request with no attributes argument.", wdb->id);
        cJSON_Delete(data);
        return -1;
    }

    cJSON * attribute = NULL;
    attribute = cJSON_GetObjectItem(attributes, "protocol");
    char * protocol = attribute ? attribute->valuestring : NULL;
    attribute = cJSON_GetObjectItem(attributes, "local_ip");
    char * local_ip = attribute ? attribute->valuestring : NULL;
    attribute = cJSON_GetObjectItem(attributes, "local_port");
    int local_port = attribute ? attribute->valueint : -1;
    attribute = cJSON_GetObjectItem(attributes, "remote_ip");
    char * remote_ip = attribute ? attribute->valuestring : NULL;
    attribute = cJSON_GetObjectItem(attributes, "remote_port");
    int remote_port = attribute ? attribute->valueint : -1;
    attribute = cJSON_GetObjectItem(attributes, "tx_queue");
    int tx_queue = attribute ? attribute->valueint : -1;
    attribute = cJSON_GetObjectItem(attributes, "rx_queue");
    int rx_queue = attribute ? attribute->valueint : -1;
    attribute = cJSON_GetObjectItem(attributes, "inode");
    int inode = attribute ? attribute->valueint : -1;
    attribute = cJSON_GetObjectItem(attributes, "state");
    char * state = attribute ? attribute->valuestring : NULL;
    attribute = cJSON_GetObjectItem(attributes, "pid");
    int pid = attribute ? attribute->valueint : -1;
    attribute = cJSON_GetObjectItem(attributes, "process");
    char * process = attribute ? attribute->valuestring : NULL;

    if (result = wdb_port_save(wdb, DEFAULT_SCAN_ID, scan_time, protocol, local_ip, local_port, remote_ip, remote_port, tx_queue, rx_queue, inode, state, pid, process), result < 0) {
        mdebug1("Cannot save Port information.");
    }

    cJSON_Delete(data);
    return result;
}

/* Get the information to delete a port entry from the DB. */
int wdb_inventory_delete_port(wdb_t * wdb, const char * payload) {
    int result = 0;

    cJSON * data = cJSON_Parse(payload);

    if (data == NULL) {
        mdebug1("DB(%s): cannot parse inventory payload: '%s'", wdb->id, payload);
        return -1;
    }

    cJSON * attributes = cJSON_GetObjectItem(data, "attributes");

    if (!cJSON_IsObject(attributes)) {
        merror("DB(%s) port delete request with no attributes argument.", wdb->id);
        cJSON_Delete(data);
        return -1;
    }

    cJSON * attribute = NULL;
    attribute = cJSON_GetObjectItem(attributes, "protocol");
    char * protocol = attribute ? attribute->valuestring : NULL;
    attribute = cJSON_GetObjectItem(attributes, "local_ip");
    char * local_ip = attribute ? attribute->valuestring : NULL;
    attribute = cJSON_GetObjectItem(attributes, "local_port");
    int local_port = attribute ? attribute->valueint : -1;
    attribute = cJSON_GetObjectItem(attributes, "pid");
    int pid = attribute ? attribute->valueint : -1;

    if (result = wdb_port_delete2(wdb, protocol, local_ip, local_port, pid), result < 0) {
        mdebug1("Cannot delete old Port entry.");
    }

    cJSON_Delete(data);
    return result;
}

/* Get the information to save a process entry in the DB. */
int wdb_inventory_save_process(wdb_t * wdb, const char * payload) {
    int result = 0;

    cJSON * data = cJSON_Parse(payload);

    if (data == NULL) {
        mdebug1("DB(%s): cannot parse inventory payload: '%s'", wdb->id, payload);
        return -1;
    }

    char * scan_time = cJSON_GetStringValue(cJSON_GetObjectItem(data, "timestamp"));

    if (scan_time == NULL) {
        merror("DB(%s) process save request with no timestamp path argument.", wdb->id);
        cJSON_Delete(data);
        return -1;
    }

    cJSON * attributes = cJSON_GetObjectItem(data, "attributes");

    if (!cJSON_IsObject(attributes)) {
        merror("DB(%s) process save request with no attributes argument.", wdb->id);
        cJSON_Delete(data);
        return -1;
    }

    cJSON * attribute = NULL;
    attribute = cJSON_GetObjectItem(attributes, "pid");
    int pid = attribute ? attribute->valueint : -1;
    attribute = cJSON_GetObjectItem(attributes, "ppid");
    int ppid = attribute ? attribute->valueint : -1;
    attribute = cJSON_GetObjectItem(attributes, "utime");
    long utime = attribute ? (long)attribute->valuedouble : -1;
    attribute = cJSON_GetObjectItem(attributes, "stime");
    long stime = attribute ? (long)attribute->valuedouble : -1;
    attribute = cJSON_GetObjectItem(attributes, "priority");
    int priority = attribute ? attribute->valueint : -1;
    attribute = cJSON_GetObjectItem(attributes, "nice");
    int nice = attribute ? attribute->valueint : -1;
    attribute = cJSON_GetObjectItem(attributes, "size");
    long size = attribute ? (long)attribute->valuedouble : -1;
    attribute = cJSON_GetObjectItem(attributes, "vm_size");
    long vm_size = attribute ? (long)attribute->valuedouble : -1;
    attribute = cJSON_GetObjectItem(attributes, "resident");
    long resident = attribute ? (long)attribute->valuedouble : -1;
    attribute = cJSON_GetObjectItem(attributes, "share");
    long share = attribute ? (long)attribute->valuedouble : -1;
    attribute = cJSON_GetObjectItem(attributes, "start_time");
    long start_time = attribute ? (long)attribute->valuedouble : -1;
    attribute = cJSON_GetObjectItem(attributes, "pgrp");
    int pgrp = attribute ? attribute->valueint : -1;
    attribute = cJSON_GetObjectItem(attributes, "session");
    int session = attribute ? attribute->valueint : -1;
    attribute = cJSON_GetObjectItem(attributes, "nlwp");
    int nlwp = attribute ? attribute->valueint : -1;
    attribute = cJSON_GetObjectItem(attributes, "tgid");
    int tgid = attribute ? attribute->valueint : -1;
    attribute = cJSON_GetObjectItem(attributes, "tty");
    int tty = attribute ? attribute->valueint : -1;
    attribute = cJSON_GetObjectItem(attributes, "processor");
    int processor = attribute ? attribute->valueint : -1;
    attribute = cJSON_GetObjectItem(attributes, "name");
    char * name = attribute ? attribute->valuestring : NULL;
    attribute = cJSON_GetObjectItem(attributes, "state");
    char * state = attribute ? attribute->valuestring : NULL;
    attribute = cJSON_GetObjectItem(attributes, "cmd");
    char * cmd = attribute ? attribute->valuestring : NULL;
    cJSON * argvs_array = NULL;
    char * argvs = NULL;
    if (argvs_array = cJSON_GetObjectItem(attributes, "argvs"), argvs_array) {
        int i;
        for (i = 0; i < cJSON_GetArraySize(argvs_array); i++) {
            wm_strcat(&argvs, cJSON_GetArrayItem(argvs_array, i)->valuestring, ',');
        }
    }
    attribute = cJSON_GetObjectItem(attributes, "euser");
    char * euser = attribute ? attribute->valuestring : NULL;
    attribute = cJSON_GetObjectItem(attributes, "ruser");
    char * ruser = attribute ? attribute->valuestring : NULL;
    attribute = cJSON_GetObjectItem(attributes, "suser");
    char * suser = attribute ? attribute->valuestring : NULL;
    attribute = cJSON_GetObjectItem(attributes, "egroup");
    char * egroup = attribute ? attribute->valuestring : NULL;
    attribute = cJSON_GetObjectItem(attributes, "rgroup");
    char * rgroup = attribute ? attribute->valuestring : NULL;
    attribute = cJSON_GetObjectItem(attributes, "sgroup");
    char * sgroup = attribute ? attribute->valuestring : NULL;
    attribute = cJSON_GetObjectItem(attributes, "fgroup");
    char * fgroup = attribute ? attribute->valuestring : NULL;

    if (result = wdb_process_save(wdb, DEFAULT_SCAN_ID, scan_time, pid, name, state, ppid, utime, stime, cmd, argvs, euser, ruser, suser, egroup, rgroup, sgroup, fgroup, priority, nice, size, vm_size, resident, share, start_time, pgrp, session, nlwp, tgid, tty, processor), result < 0) {
        mdebug1("Cannot save Process information.");
    }

    if (argvs) {
        free(argvs);
    }
    cJSON_Delete(data);
    return result;
}

/* Get the information to delete a process entry from the DB. */
int wdb_inventory_delete_process(wdb_t * wdb, const char * payload) {
    int result = 0;

    cJSON * data = cJSON_Parse(payload);

    if (data == NULL) {
        mdebug1("DB(%s): cannot parse inventory payload: '%s'", wdb->id, payload);
        return -1;
    }

    cJSON * attributes = cJSON_GetObjectItem(data, "attributes");

    if (!cJSON_IsObject(attributes)) {
        merror("DB(%s) process delete request with no attributes argument.", wdb->id);
        cJSON_Delete(data);
        return -1;
    }

    cJSON * attribute = NULL;
    attribute = cJSON_GetObjectItem(attributes, "pid");
    int pid = attribute ? attribute->valueint : -1;
    attribute = cJSON_GetObjectItem(attributes, "name");
    char * name = attribute ? attribute->valuestring : NULL;

    if (result = wdb_process_delete2(wdb, pid, name), result < 0) {
        mdebug1("Cannot delete old Process entry.");
    }

    cJSON_Delete(data);
    return result;
}

/* Get the information to save a scan entry in the DB. */
int wdb_inventory_save_scan_info(wdb_t * wdb, const char * inventory, const char * payload) {
    int result = 0;

    cJSON * data = cJSON_Parse(payload);

    if (data == NULL) {
        mdebug1("DB(%s): cannot parse inventory scan info payload: '%s'", wdb->id, payload);
        return -1;
    }

    cJSON * attribute = NULL;
    attribute = cJSON_GetObjectItem(data, "timestamp");
    long timestamp = attribute ? (long)attribute->valuedouble : -1;
    attribute = cJSON_GetObjectItem(data, "items");
    int items = attribute ? attribute->valueint : -1;

    if (result = wdb_sys_scan_info_save(wdb, inventory, timestamp, items), result < 0) {
        mdebug1("Cannot save scan information.");
    }

    cJSON_Delete(data);
    return result;
}
