/*
 * Wazuh Module for System inventory for Linux
 * Copyright (C) 2015-2020, Wazuh Inc.
 * Aug, 2017.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
*/

#include "syscollector.h"

#if defined(__linux__) || defined(__MACH__) || defined (__FreeBSD__) || defined (__OpenBSD__)
#include <ifaddrs.h>
#include <net/if.h>
#endif

#if defined(__linux__)

#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if_arp.h>
#include <netinet/tcp.h>
#include <linux/if_packet.h>
#include "external/procps/readproc.h"
#include "external/libdb/build_unix/db.h"

void get_system_linux(hw_entry * info);    // Get system information
char* get_serial_number();                      // Get Motherboard serial number
char* get_if_type(char *ifa_name);              // Get interface type
char* get_oper_state(char *ifa_name);           // Get operational state
char* get_mtu(char *ifa_name);                  // Get MTU
char* check_dhcp(char *ifa_name, int family);   // Check DHCP status for network interfaces
char* get_default_gateway(char *ifa_name);      // Get Default Gateway for network interfaces

// Get port state

char* get_port_state(int state){

    char *port_state;
    os_calloc(STATE_LENGTH, sizeof(char), port_state);

    switch(state){
        case TCP_ESTABLISHED:
            snprintf(port_state, STATE_LENGTH, "%s", "established");
            break;
        case TCP_SYN_SENT:
            snprintf(port_state, STATE_LENGTH, "%s", "syn_sent");
            break;
        case TCP_SYN_RECV:
            snprintf(port_state, STATE_LENGTH, "%s", "syn_recv");
            break;
        case TCP_FIN_WAIT1:
            snprintf(port_state, STATE_LENGTH, "%s", "fin_wait1");
            break;
        case TCP_FIN_WAIT2:
            snprintf(port_state, STATE_LENGTH, "%s", "fin_wait2");
            break;
        case TCP_TIME_WAIT:
            snprintf(port_state, STATE_LENGTH, "%s", "time_wait");
            break;
        case TCP_CLOSE:
            snprintf(port_state, STATE_LENGTH, "%s", "close");
            break;
        case TCP_CLOSE_WAIT:
            snprintf(port_state, STATE_LENGTH, "%s", "close_wait");
            break;
        case TCP_LAST_ACK:
            snprintf(port_state, STATE_LENGTH, "%s", "last_ack");
            break;
        case TCP_LISTEN:
            snprintf(port_state, STATE_LENGTH, "%s", "listening");
            break;
        case TCP_CLOSING:
            snprintf(port_state, STATE_LENGTH, "%s", "closing");
            break;
        default:
            snprintf(port_state, STATE_LENGTH, "%s", "unknown");
            break;
    }
    return port_state;
}

// Get opened ports related to IPv4 sockets

void get_ipv4_ports(int queue_fd, const char* LOCATION, const char* protocol, const char* timestamp, int check_all){

    unsigned long rxq, txq, time_len, retr, inode;
    int local_port, rem_port, d, state, uid, timer_run, timeout;
    int local_addr, rem_addr;
    struct in_addr local, remote;
    char *laddress, *raddress;
    char read_buff[OS_MAXSTR];
    char file[OS_MAXSTR];
    FILE *fp;
    int first_line = 1;
    int listening;

    // Define time to sleep between messages sent
    int usec = 1000000 / wm_max_eps;

    snprintf(file, OS_MAXSTR, "%s%s", WM_SYS_NET_DIR, protocol);

    os_calloc(NI_MAXHOST, sizeof(char), laddress);
    os_calloc(NI_MAXHOST, sizeof(char), raddress);

    memset(read_buff, 0, OS_MAXSTR);

    if ((fp = fopen(file, "r"))){

        while(fgets(read_buff, OS_MAXSTR - 1, fp) != NULL){

            port_entry_data * entry_data = NULL;

            listening = 0;

            if (first_line){
                first_line = 0;
                continue;
            }

            sscanf(read_buff,
                "%d: %8X:%X %8X:%X %X %lX:%lX %X:%lX %lX %d %d %lu %*s\n",
                &d, &local_addr, &local_port, &rem_addr, &rem_port, &state, &txq, &rxq,
                &timer_run, &time_len, &retr, &uid, &timeout, &inode);

            local.s_addr = local_addr;
            remote.s_addr = rem_addr;

            snprintf(laddress, NI_MAXHOST, "%s", inet_ntoa(local));
            snprintf(raddress, NI_MAXHOST, "%s", inet_ntoa(remote));

            entry_data = init_port_data_entry();

            os_strdup(protocol, entry_data->protocol);

            os_strdup(laddress, entry_data->local_ip);
            entry_data->local_port = local_port;
            os_strdup(raddress, entry_data->remote_ip);
            entry_data->remote_port = rem_port;

            entry_data->tx_queue = txq;
            entry_data->rx_queue = rxq;
            entry_data->inode = inode;

            if (!strncmp(protocol, "tcp", 3)){
                char *port_state;
                port_state = get_port_state(state);
                os_strdup(port_state, entry_data->state);
                if (!strcmp(port_state, "listening")) {
                    listening = 1;
                }
                free(port_state);
            }

            if (check_all || listening) {

                // Check if it is necessary to create a port event
                char * string = NULL;
                if (string = analyze_port(entry_data, timestamp), string) {
                    mtdebug2(WM_SYS_LOGTAG, "sys_ports_linux() sending '%s'", string);
                    wm_sendmsg(usec, queue_fd, string, LOCATION, SYSCOLLECTOR_MQ);
                    free(string);
                }

            } else {
                free_port_data(entry_data);
            }

        }
        fclose(fp);
    }else{
        mtdebug1(WM_SYS_LOGTAG, "Unable to get list of %s opened ports.", protocol);
    }
    free(laddress);
    free(raddress);
}

// Get opened ports related to IPv6 sockets

void get_ipv6_ports(int queue_fd, const char* LOCATION, const char* protocol, const char * timestamp, int check_all){

    unsigned long rxq, txq, time_len, retr, inode;
    int local_port, rem_port, d, state, uid, timer_run, timeout;
    char local_addr[ADDR6_LENGTH], rem_addr[ADDR6_LENGTH];
    char laddress[INET6_ADDRSTRLEN];
    char raddress[INET6_ADDRSTRLEN];
    struct in6_addr local;
    struct in6_addr rem;
    char read_buff[OS_MAXSTR];
    char file[PATH_LENGTH];
    FILE *fp;
    int first_line = 1;
    int listening;

    // Define time to sleep between messages sent
    int usec = 1000000 / wm_max_eps;

    snprintf(file, PATH_LENGTH - 1, "%s%s", WM_SYS_NET_DIR, protocol);
    memset(read_buff, 0, OS_MAXSTR);

    if ((fp = fopen(file, "r"))){

        while(fgets(read_buff, OS_MAXSTR - 1, fp) != NULL){

            port_entry_data * entry_data = NULL;

            listening = 0;

            if (first_line){
                first_line = 0;
                continue;
            }

            sscanf(read_buff,
                "%d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %X %lX:%lX %X:%lX %lX %d %d %lu %*s\n",
                &d, local_addr, &local_port, rem_addr, &rem_port, &state, &txq, &rxq,
                &timer_run, &time_len, &retr, &uid, &timeout, &inode);

            sscanf(local_addr, "%08X%08X%08X%08X",
                &local.s6_addr32[0], &local.s6_addr32[1],
                &local.s6_addr32[2], &local.s6_addr32[3]);
            inet_ntop(AF_INET6, &local, laddress, sizeof(laddress));

            sscanf(rem_addr, "%08X%08X%08X%08X",
                &rem.s6_addr32[0], &rem.s6_addr32[1],
                &rem.s6_addr32[2], &rem.s6_addr32[3]);
            inet_ntop(AF_INET6, &rem, raddress, sizeof(raddress));

            entry_data = init_port_data_entry();

            os_strdup(protocol, entry_data->protocol);

            os_strdup(laddress, entry_data->local_ip);
            entry_data->local_port = local_port;
            os_strdup(raddress, entry_data->remote_ip);
            entry_data->remote_port = rem_port;

            entry_data->tx_queue = txq;
            entry_data->rx_queue = rxq;
            entry_data->inode = inode;

            if (!strncmp(protocol, "tcp6", 4)){
                char *port_state;
                port_state = get_port_state(state);
                os_strdup(port_state, entry_data->state);
                if (!strcmp(port_state, "listening")) {
                    listening = 1;
                }
                free(port_state);
            }

            if (check_all || listening) {

                // Check if it is necessary to create a port event
                char * string = NULL;
                if (string = analyze_port(entry_data, timestamp), string) {
                    mtdebug2(WM_SYS_LOGTAG, "sys_ports_linux() sending '%s'", string);
                    wm_sendmsg(usec, queue_fd, string, LOCATION, SYSCOLLECTOR_MQ);
                    free(string);
                }

            } else {
                free_port_data(entry_data);
            }

        }
        fclose(fp);
    }else{
        mtdebug1(WM_SYS_LOGTAG, "Unable to get list of %s opened ports.", protocol);
    }
}

// Opened ports inventory

void sys_ports_linux(int queue_fd, const char* WM_SYS_LOCATION, int check_all){

    char *protocol;
    char *timestamp = w_get_timestamp(time(NULL));

    mtdebug1(WM_SYS_LOGTAG, "Starting ports inventory.");

    os_calloc(PROTO_LENGTH + 1, sizeof(char), protocol);

    /* TCP opened ports inventory */
    snprintf(protocol, PROTO_LENGTH, "%s", "tcp");
    get_ipv4_ports(queue_fd, WM_SYS_LOCATION, protocol, timestamp, check_all);

    if (check_all) {
        /* UDP opened ports inventory */
        snprintf(protocol, PROTO_LENGTH, "%s", "udp");
        get_ipv4_ports(queue_fd, WM_SYS_LOCATION, protocol, timestamp, check_all);
    }

    /* TCP6 opened ports inventory */
    snprintf(protocol, PROTO_LENGTH, "%s", "tcp6");
    get_ipv6_ports(queue_fd, WM_SYS_LOCATION, protocol, timestamp, check_all);

    if (check_all) {
        /* UDP6 opened ports inventory */
        snprintf(protocol, PROTO_LENGTH, "%s", "udp6");
        get_ipv6_ports(queue_fd, WM_SYS_LOCATION, protocol, timestamp, check_all);
    }

    free(protocol);
    free(timestamp);

    // Checking for closed ports
    check_closed_ports();
}

// Get installed programs inventory

void sys_packages_linux(int queue_fd, const char* LOCATION) {

    DIR *dir;

    /* Set positive random ID for each event */

    mtdebug1(WM_SYS_LOGTAG, "Starting installed packages inventory.");

    if ((dir = opendir("/var/lib/dpkg/"))){
        closedir(dir);
        sys_deb_packages(queue_fd, LOCATION);
    }
    if ((dir = opendir("/var/lib/rpm/"))){
        closedir(dir);
        sys_rpm_packages(queue_fd, LOCATION);
    }

    // Checking for uninstalled programs
    check_uninstalled_programs();
}

void sys_rpm_packages(int queue_fd, const char* LOCATION){

    char *format = "rpm";
    char *timestamp = w_get_timestamp(time(NULL));

    DBT key, data;
    DBC *cursor;
    DB *dbp;
    int ret, skip;
    int i;
    u_int8_t* bytes;
    u_int8_t* store;
    int index, offset;
    rpm_data *info;
    rpm_data *next_info;
    rpm_data *head;
    int epoch;
    char version[TYPE_LENGTH];
    char release[TYPE_LENGTH];
    char final_version[V_LENGTH];

    // Define time to sleep between messages sent
    int usec = 1000000 / wm_max_eps;

    if ((ret = db_create(&dbp, NULL, 0)) != 0) {
        mterror(WM_SYS_LOGTAG, "Failed to initialize the DB handler: %s", db_strerror(ret));
        free(timestamp);
        return;
    }

    // Set Little-endian order by default
    if (ret = dbp->set_lorder(dbp, 1234), ret != 0) {
        mtwarn(WM_SYS_LOGTAG, "Error setting byte-order.");
    }

    if ((ret = dbp->open(dbp, NULL, RPM_DATABASE, NULL, DB_HASH, DB_RDONLY, 0)) != 0) {
        mterror(WM_SYS_LOGTAG, "Failed to open database '%s': %s", RPM_DATABASE, db_strerror(ret));
        free(timestamp);
        return;
    }

    if ((ret = dbp->cursor(dbp, NULL, &cursor, 0)) != 0) {
        mterror(WM_SYS_LOGTAG, "Error creating cursor: %s", db_strerror(ret));
        free(timestamp);
        return;
    }

    memset(&key, 0, sizeof(DBT));
    memset(&data, 0, sizeof(DBT));

    int j;

    for (j = 0; ret = cursor->c_get(cursor, &key, &data, DB_NEXT), ret == 0; j++) {

        program_entry_data * entry_data = NULL;

        // First header is not a package

        if (j == 0) {
            continue;
        }

        bytes = (u_int8_t*)data.data;

        // Read number of index entries (First 4 bytes)

        index = four_bytes_to_int32(bytes);

        // Set offset to first index entry

        offset = 8;
        bytes = &bytes[offset];

        os_calloc(1, sizeof(rpm_data), info);
        head = info;

        // Read all indexes

        for (i = 0; i < index; i++) {
            offset = 16;
            if ((ret = read_entry(bytes, info)), ret == 0) {
                os_calloc(1, sizeof(rpm_data), info->next);
                info = info->next;
            }
            bytes = &bytes[offset];
        }

        // Start reading the data

        store = bytes;
        epoch = 0;
        skip = 0;

        entry_data = init_program_data_entry();

        os_strdup(format, entry_data->format);

        for (info = head; info; info = next_info) {
            next_info = info->next;
            bytes = &store[info->offset];
            char * read;
            int result;

            switch(info->type) {
                case 0:
                    break;
                case 6:   // String
                    read = read_string(bytes);

                    if (!strncmp(info->tag, "name", 4)) {
                        os_strdup(read, entry_data->name);
                        if (!strncmp(read, "gpg-pubkey", 10)) {
                            skip = 1;
                        }
                    } else if (!strncmp(info->tag, "version", 7)) {
                        snprintf(version, TYPE_LENGTH - 1, "%s", read);
                    } else if (!strncmp(info->tag, "release", 7)) {
                        snprintf(release, TYPE_LENGTH - 1, "%s", read);
                    } else if (!strncmp(info->tag, "vendor", 6)) {
                        os_strdup(read, entry_data->vendor);
                    } else if (!strncmp(info->tag, "architecture", 12)) {
                        os_strdup(read, entry_data->architecture);
                    } else {
                        mtdebug2(WM_SYS_LOGTAG, "Unknown package tag: '%s'", info->tag);
                    }
                    free(read);
                    break;

                case 4:   // int32
                    result = four_bytes_to_int32(bytes);

                    if (!strncmp(info->tag, "size", 4)) {
                        result = result / 1024;   // Bytes to KBytes
                        entry_data->size = result;
                    }
                    else if (!strncmp(info->tag, "install_time", 12)) {    // Format date
                        char *installt = w_get_timestamp(result);
                        os_strdup(installt, entry_data->install_time);
                        free(installt);
                    } else if (!strncmp(info->tag, "epoch", 5)) {
                        epoch = result;
                    } else {
                        mtdebug2(WM_SYS_LOGTAG, "Unknown package tag: '%s'", info->tag);
                    }
                    break;

                case 9:   // Vector of strings
                    read = read_string(bytes);

                    if (!strncmp(info->tag, "group", 5)) {
                        os_strdup(read, entry_data->group);
                    } else if (!strncmp(info->tag, "description", 11)) {
                        os_strdup(read, entry_data->description);
                    } else {
                        mtdebug2(WM_SYS_LOGTAG, "Unknown package tag: '%s'", info->tag);
                    }
                    free(read);
                    break;

                default:
                    mterror(WM_SYS_LOGTAG, "Unknown type of data: %d", info->type);
            }
        }

        if (epoch) {
            snprintf(final_version, V_LENGTH, "%d:%s-%s", epoch, version, release);
        } else {
            snprintf(final_version, V_LENGTH, "%s-%s", version, release);
        }
        os_strdup(final_version, entry_data->version);

        // Send RPM package information to the manager

        if (skip) {
            free_program_data(entry_data);
        } else {
            // Check if it is necessary to create a program event
            char * string = NULL;
            if (string = analyze_program(entry_data, timestamp), string) {
                mtdebug2(WM_SYS_LOGTAG, "sys_rpm_packages() sending '%s'", string);
                wm_sendmsg(usec, queue_fd, string, LOCATION, SYSCOLLECTOR_MQ);
                free(string);
            }
        }

        // Free resources

        for (info = head; info; info = next_info) {
            next_info = info->next;
            free(info->tag);
            free(info);
        }
    }

    if (ret == DB_NOTFOUND && j <= 1) {
        mtwarn(WM_SYS_LOGTAG, "Not found any record in database '%s'", RPM_DATABASE);
    }

    cursor->c_close(cursor);
    dbp->close(dbp, 0);

    free(timestamp);
}

void sys_deb_packages(int queue_fd, const char* LOCATION){

    const char * format = "deb";
    char file[PATH_LENGTH] = "/var/lib/dpkg/status";
    char read_buff[OS_MAXSTR];
    FILE *fp;
    size_t length;
    int i;
    char *timestamp = w_get_timestamp(time(NULL));

    // Define time to sleep between messages sent
    int usec = 1000000 / wm_max_eps;

    memset(read_buff, 0, OS_MAXSTR);

    if ((fp = fopen(file, "r"))) {
        w_file_cloexec(fp);

        program_entry_data * entry_data = NULL;

        entry_data = init_program_data_entry();

        while(fgets(read_buff, OS_MAXSTR, fp) != NULL) {

            // Remove '\n' from the read line
            length = strlen(read_buff);
            read_buff[length - 1] = '\0';

            if (!strncmp(read_buff, "Package: ", 9)) {

                if (entry_data) {
                    free_program_data(entry_data);
                    entry_data = NULL;
                }

                entry_data = init_program_data_entry();

                os_strdup(format, entry_data->format);

                char ** parts = NULL;
                parts = OS_StrBreak(' ', read_buff, 2);
                os_strdup(parts[1], entry_data->name);

                for (i=0; parts[i]; i++){
                    free(parts[i]);
                }
                free(parts);

            } else if (!strncmp(read_buff, "Status: ", 8)) {

                if (!entry_data) {
                    entry_data = init_program_data_entry();
                }

                if (strstr(read_buff, "install ok installed"))
                    entry_data->installed = 1;
                else
                    entry_data->installed = 0;

            } else if (!strncmp(read_buff, "Priority: ", 10)) {

                if (!entry_data) {
                    entry_data = init_program_data_entry();
                }

                char ** parts = NULL;
                parts = OS_StrBreak(' ', read_buff, 2);
                os_strdup(parts[1], entry_data->priority);

                for (i=0; parts[i]; i++){
                    free(parts[i]);
                }
                free(parts);

            } else if (!strncmp(read_buff, "Section: ", 9)) {

                if (!entry_data) {
                    entry_data = init_program_data_entry();
                }

                char ** parts = NULL;
                parts = OS_StrBreak(' ', read_buff, 2);
                os_strdup(parts[1], entry_data->group);

                for (i=0; parts[i]; i++){
                    free(parts[i]);
                }
                free(parts);

            } else if (!strncmp(read_buff, "Installed-Size: ", 16)) {

                if (!entry_data) {
                    entry_data = init_program_data_entry();
                }

                char ** parts = NULL;
                parts = OS_StrBreak(' ', read_buff, 2);
                entry_data->size = atoi(parts[1]);

                for (i=0; parts[i]; i++){
                    free(parts[i]);
                }
                free(parts);

            } else if (!strncmp(read_buff, "Maintainer: ", 12)) {

                if (!entry_data) {
                    entry_data = init_program_data_entry();
                }

                char ** parts = NULL;
                parts = OS_StrBreak(' ', read_buff, 2);
                os_strdup(parts[1], entry_data->vendor);

                for (i=0; parts[i]; i++){
                    free(parts[i]);
                }
                free(parts);

            } else if (!strncmp(read_buff, "Architecture: ", 14)) {

                if (!entry_data) {
                    entry_data = init_program_data_entry();
                }

                char ** parts = NULL;
                parts = OS_StrBreak(' ', read_buff, 2);
                os_strdup(parts[1], entry_data->architecture);

                for (i=0; parts[i]; i++){
                    free(parts[i]);
                }
                free(parts);

            } else if (!strncmp(read_buff, "Multi-Arch: ", 12)) {

                if (!entry_data) {
                    entry_data = init_program_data_entry();
                }

                char ** parts = NULL;
                parts = OS_StrBreak(' ', read_buff, 2);
                os_strdup(parts[1], entry_data->multi_arch);

                for (i=0; parts[i]; i++){
                    free(parts[i]);
                }
                free(parts);

            } else if (!strncmp(read_buff, "Source: ", 8)) {

                if (!entry_data) {
                    entry_data = init_program_data_entry();
                }

                char ** parts = NULL;
                parts = OS_StrBreak(' ', read_buff, 2);
                os_strdup(parts[1], entry_data->source);

                for (i=0; parts[i]; i++){
                    free(parts[i]);
                }
                free(parts);

            } else if (!strncmp(read_buff, "Version: ", 9)) {

                if (!entry_data) {
                    entry_data = init_program_data_entry();
                }

                char ** parts = NULL;
                parts = OS_StrBreak(' ', read_buff, 2);
                os_strdup(parts[1], entry_data->version);

                for (i=0; parts[i]; i++){
                    free(parts[i]);
                }
                free(parts);

            } else if (!strncmp(read_buff, "Description: ", 13)) {

                if (!entry_data) {
                    entry_data = init_program_data_entry();
                }

                char ** parts = NULL;
                parts = OS_StrBreak(' ', read_buff, 2);
                os_strdup(parts[1], entry_data->description);

                for (i=0; parts[i]; i++){
                    free(parts[i]);
                }
                free(parts);

                // Send message to the queue

                if (entry_data->installed) {
                    // Check if it is necessary to create a program event
                    char * string = NULL;
                    if (string = analyze_program(entry_data, timestamp), string) {
                        mtdebug2(WM_SYS_LOGTAG, "sys_deb_packages() sending '%s'", string);
                        wm_sendmsg(usec, queue_fd, string, LOCATION, SYSCOLLECTOR_MQ);
                        free(string);
                    }
                } else {
                    free_program_data(entry_data);
                }
                entry_data = NULL;
            }
        }

        if (entry_data) {
            free_program_data(entry_data);
        }

        fclose(fp);

    } else {

        mterror(WM_SYS_LOGTAG, "Unable to open the file '%s'", file);
    }

    free(timestamp);
}

// Get Hardware inventory

void sys_hw_linux(int queue_fd, const char* LOCATION){

    char *timestamp;

    hw_entry * hw_data = NULL;

    timestamp = w_get_timestamp(time(NULL));

    mtdebug1(WM_SYS_LOGTAG, "Starting Hardware inventory.");

    hw_data = init_hw_data();

    /* Motherboard serial-number */
    char *serial;
    serial = get_serial_number();
    os_strdup(serial, hw_data->board_serial);
    free(serial);

    /* Get CPU and memory information */
    get_system_linux(hw_data);

    // Check if it is necessary to create a hardware event
    char * string = NULL;
    if (string = analyze_hw(hw_data, timestamp), string) {
        mtdebug2(WM_SYS_LOGTAG, "sys_hw_linux() sending '%s'", string);
        SendMSG(queue_fd, string, LOCATION, SYSCOLLECTOR_MQ);
        free(string);
    }

    free(timestamp);
}

#endif /* __linux__ */

// Get OS inventory

void sys_os_unix(int queue_fd, const char* LOCATION){

    char *timestamp;

    os_entry * os_data = NULL;

    timestamp = w_get_timestamp(time(NULL));

    mtdebug1(WM_SYS_LOGTAG, "Starting Operating System inventory.");

    os_data = init_os_data();

    os_info * info = get_unix_version();
    if (info->nodename && (strcmp(info->nodename, "unknown") != 0)) {
        os_strdup(info->nodename, os_data->hostname);
    }
    if (info->machine && (strcmp(info->machine, "unknown") != 0)) {
        os_strdup(info->machine, os_data->architecture);
    }
    if (info->os_name && (strcmp(info->os_name, "unknown") != 0)) {
        os_strdup(info->os_name, os_data->os_name);
    }
    if (info->os_release) {
        os_strdup(info->os_release, os_data->os_release);
    }
    if (info->os_version && (strcmp(info->os_version, "unknown") != 0)) {
        os_strdup(info->os_version, os_data->os_version);
    }
    if (info->os_codename) {
        os_strdup(info->os_codename, os_data->os_codename);
    }
    if (info->os_major) {
        os_strdup(info->os_major, os_data->os_major);
    }
    if (info->os_minor) {
        os_strdup(info->os_minor, os_data->os_minor);
    }
    if (info->os_build) {
        os_strdup(info->os_build, os_data->os_build);
    }
    if (info->os_platform) {
        os_strdup(info->os_platform, os_data->os_platform);
    }
    if (info->sysname) {
        os_strdup(info->sysname, os_data->sysname);
    }
    if (info->release) {
        os_strdup(info->release, os_data->release);
    }
    if (info->version) {
        os_strdup(info->version, os_data->version);
    }
    free_osinfo(info);

    // Check if it is necessary to create a operative system event
    char * string = NULL;
    if (string = analyze_os(os_data, timestamp), string) {
        mtdebug2(WM_SYS_LOGTAG, "sys_os_unix() sending '%s'", string);
        SendMSG(queue_fd, string, LOCATION, SYSCOLLECTOR_MQ);
        free(string);
    }

    free(timestamp);
}

#if defined(__linux__)

/* Get broadcast address from IPv4 address and netmask */
char* get_broadcast_addr(char* ip, char* netmask){

    struct in_addr host, mask, broadcast;
    char * broadcast_addr;

    os_calloc(NI_MAXHOST, sizeof(char), broadcast_addr);
    strncpy(broadcast_addr, "unknown", NI_MAXHOST);

    if (inet_pton(AF_INET, ip, &host) == 1 && inet_pton(AF_INET, netmask, &mask) == 1){

        broadcast.s_addr = host.s_addr | ~mask.s_addr;
        inet_ntop(AF_INET, &broadcast, broadcast_addr, NI_MAXHOST);

    }

    return broadcast_addr;
}

// Get network inventory

void sys_network_linux(int queue_fd, const char* LOCATION){

    char ** ifaces_list;
    int i = 0, size_ifaces = 0;
    struct ifaddrs *ifaddr = NULL, *ifa;
    char *timestamp;

    // Define time to sleep between messages sent
    int usec = 1000000 / wm_max_eps;

    timestamp = w_get_timestamp(time(NULL));

    mtdebug1(WM_SYS_LOGTAG, "Starting network inventory.");

    if (getifaddrs(&ifaddr) == -1) {
        if (ifaddr) {
            freeifaddrs(ifaddr);
        }
        mterror(WM_SYS_LOGTAG, "Extracting the interfaces of the system.");
        free(timestamp);
        return;
    }

    for (ifa = ifaddr; ifa; ifa = ifa->ifa_next){
        i++;
    }

    if (i == 0) {
        mterror(WM_SYS_LOGTAG, "No interface found. Network inventory suspended.");
        free(timestamp);
        return;
    }

    os_calloc(i, sizeof(char *), ifaces_list);

    /* Create interfaces list */
    size_ifaces = getIfaceslist(ifaces_list, ifaddr);

    if(!ifaces_list[0]){
        mtinfo(WM_SYS_LOGTAG, "No interface found. Network inventory suspended.");
        free(ifaces_list);
        freeifaddrs(ifaddr);
        free(timestamp);
        return;
    }

    /* Collect all information for each interface */
    for (i=0; i < size_ifaces; i++){

        interface_entry_data * entry_data = NULL;

        if (entry_data = getNetworkIface_linux(ifaces_list[i], ifaddr), entry_data) {
            // Check if it is necessary to create an interface event
            char * string = NULL;
            if (string = analyze_interface(entry_data, timestamp), string) {
                mtdebug2(WM_SYS_LOGTAG, "sys_network_linux() sending '%s'", string);
                wm_sendmsg(usec, queue_fd, string, LOCATION, SYSCOLLECTOR_MQ);
                free(string);
            }
        } else {
            mdebug2("Couldn't get the data of the interface: '%s'", ifaces_list[i]);
        }
    }

    freeifaddrs(ifaddr);
    for (i=0; ifaces_list[i]; i++){
        free(ifaces_list[i]);
    }
    free(ifaces_list);
    free(timestamp);

    // Checking for disabled interfaces
    check_disabled_interfaces();
}

/* Get System information */
void get_system_linux(hw_entry * info) {

    FILE *fp;
    char string[OS_MAXSTR];
    char *saveptr;
    char *end;

    if (!(fp = fopen("/proc/cpuinfo", "r"))) {
        mterror(WM_SYS_LOGTAG, "Unable to read the CPU name.");
        info->cpu_name = strdup("unknown");
    } else {
        char *aux_string = NULL;
        while (fgets(string, OS_MAXSTR, fp) != NULL){
            if ((aux_string = strstr(string, "model name")), aux_string != NULL){

                char *cpuname;
                strtok_r(string, ":", &saveptr);
                cpuname = strtok_r(NULL, "\n", &saveptr);
                if (cpuname[0] == '\"' && (end = strchr(++cpuname, '\"'), end)) {
                    *end = '\0';
                }

                free(info->cpu_name);
                info->cpu_name = strdup(cpuname);
            } else if ((aux_string = strstr(string, "cpu MHz")), aux_string != NULL){

                char *frec;
                strtok_r(string, ":", &saveptr);
                frec = strtok_r(NULL, "\n", &saveptr);
                if (frec[0] == '\"' && (end = strchr(++frec, '\"'), end)) {
                    *end = '\0';
                }
                info->cpu_MHz = atof(frec);
            }
        }
        if (!info->cpu_name) {
            info->cpu_name = strdup("unknown");
        }
        fclose(fp);
    }

    info->cpu_cores = get_nproc();

    if (!(fp = fopen("/proc/meminfo", "r"))) {
        mterror(WM_SYS_LOGTAG, "Unable to read the RAM memory information.");
    } else {
        while (fgets(string, OS_MAXSTR, fp) != NULL){
            char *aux_string = NULL;

            if ((aux_string = strstr(string, "MemTotal")), aux_string != NULL){

                char *end_string = NULL;
                strtok_r(string, ":", &saveptr);
                aux_string = strtok_r(NULL, "\n", &saveptr);
                if (aux_string) {
                    if (aux_string[0] == '\"' && (end = strchr(++aux_string, '\"'), end)) {
                        *end = '\0';
                    }
                    info->ram_total = strtol(aux_string, &end_string, 10);
                } else {
                    info->ram_total = 0;
                }
            } else if ((aux_string = strstr(string, "MemFree")), aux_string != NULL){

                char *end_string = NULL;
                strtok_r(string, ":", &saveptr);
                aux_string = strtok_r(NULL, "\n", &saveptr);
                if (aux_string) {
                    if (aux_string[0] == '\"' && (end = strchr(++aux_string, '\"'), end)) {
                        *end = '\0';
                    }
                    info->ram_free = strtol(aux_string, &end_string, 10);
                } else {
                    info->ram_free = 0;
                }
            }
        }

        if (info->ram_total > 0) {
            info->ram_usage = 100 - (info->ram_free * 100 / info->ram_total);
        }
        fclose(fp);
    }
}

/* Get Motherboard Serial Number */
char* get_serial_number(){

    char file[PATH_LENGTH];

    FILE *fp;
    char serial_str[SERIAL_LENGTH] = "";
    char * serial;
    char ** parts;
    int i;

    os_calloc(SERIAL_LENGTH + 1, sizeof(char), serial);

    snprintf(serial, SERIAL_LENGTH, "%s", "unknown");
    snprintf(file, PATH_LENGTH - 1, "%s/%s", WM_SYS_HW_DIR, "board_serial");

    if((fp = fopen(file, "r"))){
        if (fgets(serial_str, SERIAL_LENGTH, fp) != NULL){

            parts = OS_StrBreak('\n', serial_str, 2);
            snprintf(serial, SERIAL_LENGTH, "%s", parts[0]);
            for (i = 0; parts[i]; i++){
                free(parts[i]);
            }
            free(parts);
        }
        fclose(fp);
    }
    return serial;
}

/* Get interface type */
char* get_if_type(char *ifa_name){

    char file[PATH_LENGTH];

    FILE *fp;
    char type_str[6];
    int type_int;
    char * type;
    os_calloc(TYPE_LENGTH + 1, sizeof(char), type);

    snprintf(type, TYPE_LENGTH, "%s", "unknown");
    snprintf(file, PATH_LENGTH - 1, "%s%s/%s", WM_SYS_IFDATA_DIR, ifa_name, "type");

    if((fp = fopen(file, "r"))){
        if (fgets(type_str, 6, fp) != NULL){

            type_int = atoi(type_str);

            switch (type_int){
                case ARPHRD_ETHER:
                    snprintf(type, TYPE_LENGTH, "%s", "ethernet");
                    break;
                case ARPHRD_PRONET:
                    snprintf(type, TYPE_LENGTH, "%s", "token ring");
                    break;
                case ARPHRD_PPP:
                    snprintf(type, TYPE_LENGTH, "%s", "point-to-point");
                    break;
                case ARPHRD_ATM:
                    snprintf(type, TYPE_LENGTH, "%s", "ATM");
                    break;
                case ARPHRD_IEEE1394:
                    snprintf(type, TYPE_LENGTH, "%s", "firewire");
                    break;
                default:
                    if (type_int >= 768 && type_int <= 783){
                        snprintf(type, TYPE_LENGTH, "%s", "tunnel");
                    }else if (type_int >= 784 && type_int <= 799){
                        snprintf(type, TYPE_LENGTH, "%s", "fibrechannel");
                    }else if (type_int >= 800 && type_int <=805){
                        snprintf(type, TYPE_LENGTH, "%s", "wireless");
                    }else{
                        snprintf(type, TYPE_LENGTH, "%s", "unknown");
                    }
                    break;
            }
        }
        fclose(fp);
    }
    return type;
}

/* Get operation state of a network interface */
char* get_oper_state(char *ifa_name){

    char file[PATH_LENGTH];

    FILE *fp;
    char state_str[STATE_LENGTH] = "";
    char * state;
    char ** parts;
    int i;

    os_calloc(STATE_LENGTH + 1, sizeof(char), state);

    snprintf(state, STATE_LENGTH, "%s", "unknown");
    snprintf(file, PATH_LENGTH, "%s%s/%s", WM_SYS_IFDATA_DIR, ifa_name, "operstate");

    if((fp = fopen(file, "r"))){
        if (fgets(state_str, STATE_LENGTH, fp) != NULL){

            parts = OS_StrBreak('\n', state_str, 2);
            snprintf(state, STATE_LENGTH, "%s", parts[0]);
            for (i = 0; parts[i]; i++){
                free(parts[i]);
            }
            free(parts);
        }
        fclose(fp);
    }
    return state;
}

/* Get MTU of a network interface */
char* get_mtu(char *ifa_name){

    char file[PATH_LENGTH];

    FILE *fp;
    char mtu_str[20] = "";
    char * mtu;
    char ** parts;
    int i;

    os_calloc(MTU_LENGTH + 1, sizeof(char), mtu);

    snprintf(mtu, MTU_LENGTH, "%s", "unknown");
    snprintf(file, PATH_LENGTH, "%s%s/%s", WM_SYS_IFDATA_DIR, ifa_name, "mtu");

    if((fp = fopen(file, "r"))){
        if (fgets(mtu_str, 20, fp) != NULL){

            parts = OS_StrBreak('\n', mtu_str, 2);
            snprintf(mtu, MTU_LENGTH, "%s", parts[0]);
            for (i = 0; parts[i]; i++){
                free(parts[i]);
            }
            free(parts);
        }
        fclose(fp);
    }
    return mtu;
}

/* Check DHCP status for IPv4 and IPv6 addresses in each interface */
char* check_dhcp(char *ifa_name, int family){

    char file[IFNAME_LENGTH];
    char file_location[PATH_LENGTH];
    FILE *fp;
    DIR *dir;
    char string[OS_MAXSTR];
    char * iface_string = NULL;
    char * aux_string = NULL;
    int spaces;
    char * dhcp;
    os_calloc(DHCP_LENGTH + 1, sizeof(char), dhcp);

    snprintf(dhcp, DHCP_LENGTH, "%s", "unknown");
    snprintf(file_location, PATH_LENGTH, "%s", WM_SYS_IF_FILE);

    /* Check DHCP configuration for Debian based systems */
    if ((fp = fopen(file_location, "r"))){

        while (fgets(string, OS_MAXSTR, fp) != NULL){

            if ((aux_string = strstr(string, "iface")) != NULL){

                spaces = strspn(aux_string, " \t");

                if ((iface_string = strstr(aux_string + 5 + spaces, ifa_name)) != NULL){

                    spaces = strspn(iface_string, " \t");
                    int ifa_length = strlen(ifa_name);

                    switch (family){

                        case AF_INET:
                            if ((aux_string = strstr(iface_string + ifa_length + spaces, "inet")) != NULL){

                                spaces = strspn(aux_string, " \t");
                                if (strstr(aux_string + 4 + spaces, "static") || strstr(aux_string + 4 + spaces, "manual")){
                                    snprintf(dhcp, DHCP_LENGTH, "%s", "disabled");
                                    fclose(fp);
                                    return dhcp;
                                }else if (strstr(aux_string + 4 + spaces, "dhcp")){
                                    snprintf(dhcp, DHCP_LENGTH, "%s", "enabled");
                                    fclose(fp);
                                    return dhcp;
                                }
                            }else{

                                snprintf(dhcp, DHCP_LENGTH, "%s", "enabled");
                                fclose(fp);
                                return dhcp;
                            }
                            break;

                        case AF_INET6:

                            if ((aux_string = strstr(iface_string + ifa_length + spaces, "inet6")) != NULL){

                                spaces = strspn(aux_string, " \t");
                                if (strstr(aux_string + 5 + spaces, "static") || strstr(aux_string + 5 + spaces, "manual")){
                                    snprintf(dhcp, DHCP_LENGTH, "%s", "disabled");
                                    fclose(fp);
                                    return dhcp;
                                }else if (strstr(aux_string + 5 + spaces, "dhcp")){
                                    snprintf(dhcp, DHCP_LENGTH, "%s", "enabled");
                                    fclose(fp);
                                    return dhcp;
                                }
                            }else{

                                snprintf(dhcp, DHCP_LENGTH, "%s", "enabled");
                                fclose(fp);
                                return dhcp;
                            }
                            break;

                        default:
                            mtdebug1(WM_SYS_LOGTAG, "Unknown DHCP configuration for interface '%s'", ifa_name);
                            break;
                    }
                }

            }
        }
        snprintf(dhcp, DHCP_LENGTH, "%s", "enabled");
        fclose(fp);

    }else{

        /* Check DHCP configuration for Red Hat based systems and SUSE distributions */
        snprintf(file, IFNAME_LENGTH - 1, "%s%s", "ifcfg-", ifa_name);

        if ((dir = opendir(WM_SYS_IF_DIR_RH))){
            snprintf(file_location, PATH_LENGTH, "%s%s", WM_SYS_IF_DIR_RH, file);
            snprintf(dhcp, DHCP_LENGTH, "%s", "enabled");
            closedir(dir);
        }

        /* For SUSE Linux distributions */
        if ((dir = opendir(WM_SYS_IF_DIR_SUSE))){
        snprintf(file_location, PATH_LENGTH, "%s%s", WM_SYS_IF_DIR_SUSE, file);
            snprintf(dhcp, DHCP_LENGTH, "%s", "enabled");
            closedir(dir);
        }

        if ((fp = fopen(file_location, "r"))){

            switch (family){
                case AF_INET:

                    while (fgets(string, OS_MAXSTR, fp) != NULL){

                        if (strstr(string, "BOOTPROTO") != NULL){

                            if (strstr(string, "static") || strstr(string, "none")){
                                snprintf(dhcp, DHCP_LENGTH, "%s", "disabled");
                                fclose(fp);
                                return dhcp;
                            }else if (strstr(string, "bootp")){
                                snprintf(dhcp, DHCP_LENGTH, "%s", "BOOTP");
                                fclose(fp);
                                return dhcp;
                            }else if (strstr(string, "dhcp")){
                                snprintf(dhcp, DHCP_LENGTH, "%s", "enabled");
                                fclose(fp);
                                return dhcp;
                            }else{
                                snprintf(dhcp, DHCP_LENGTH, "%s", "unknown");
                                fclose(fp);
                                return dhcp;
                            }
                        }
                    }
                    break;

                case AF_INET6:

                    while (fgets(string, OS_MAXSTR, fp) != NULL){

                        if (strstr(string, "DHCPV6C") != NULL){
                            if (strstr(string, "no")){
                                snprintf(dhcp, DHCP_LENGTH, "%s", "disabled");
                                fclose(fp);
                                return dhcp;
                            }else if (strstr(string, "yes")){
                                snprintf(dhcp, DHCP_LENGTH, "%s", "enabled");
                                fclose(fp);
                                return dhcp;
                            }else {
                                snprintf(dhcp, DHCP_LENGTH, "%s", "unknown");
                                fclose(fp);
                                return dhcp;
                            }
                        }
                    }
                    break;

                default:
                    mtdebug1(WM_SYS_LOGTAG, "Unknown DHCP configuration for interface '%s'", ifa_name);
                    break;
            }
            fclose(fp);
        }
    }

    return dhcp;
}

// Returns default gateway for an interface and its metric in the format: "192.168.1.1|1200"
char* get_default_gateway(char *ifa_name){

    FILE *fp;
    char file_location[PATH_LENGTH];
    char interface[IFNAME_LENGTH] = "";
    char if_name[IFNAME_LENGTH] = "";
    char string[OS_MAXSTR];
    struct in_addr address;
    int destination, gateway, flags, ref, use, metric;
    char * def_gateway;
    bool is_first_line = true;
    bool starts_with_default_gw = false;
    os_calloc(V_LENGTH, sizeof(char) + 1, def_gateway);

    strncpy(interface, ifa_name, sizeof(interface) - 1);
    snprintf(file_location, PATH_LENGTH, "%s%s", WM_SYS_NET_DIR, "route");
    snprintf(def_gateway, V_LENGTH, "%s", "unknown");

    if ((fp = fopen(file_location, "r"))) {

        while (fgets(string, OS_MAXSTR, fp) != NULL) {
            if (sscanf(string, "%s %8x %8x %d %d %d %d", if_name, &destination, &gateway, &flags, &ref, &use, &metric) == 7) {
                if (is_first_line) {
                    is_first_line = false;
                    starts_with_default_gw = (destination == 0);
                }

                if (starts_with_default_gw && destination != 0) {
                    break;
                }

                if (!strcmp(if_name, interface)) {
                    address.s_addr = gateway;
                    snprintf(def_gateway, V_LENGTH, "%s|%d", inet_ntoa(*(struct in_addr *) &address), metric);
                    fclose(fp);
                    return def_gateway;
                }
            }

        }
        fclose(fp);
    }

    return def_gateway;

}


void sys_proc_linux(int queue_fd, const char* LOCATION) {

    char *timestamp = w_get_timestamp(time(NULL));

    // Define time to sleep between messages sent
    int usec = 1000000 / wm_max_eps;

    PROCTAB* proc = openproc(PROC_FILLMEM | PROC_FILLSTAT | PROC_FILLSTATUS | PROC_FILLARG | PROC_FILLGRP | PROC_FILLUSR | PROC_FILLCOM | PROC_FILLENV);

    proc_t * proc_info;

    if (!proc) {
        mterror(WM_SYS_LOGTAG, "Running process inventory: could not create libproc context.");
        free(timestamp);
        return;
    }

    mtdebug1(WM_SYS_LOGTAG, "Starting running processes inventory.");

    while (proc_info = readproc(proc, NULL), proc_info != NULL) {
        int i;
        int pos = 0;

        process_entry_data * entry_data = NULL;

        entry_data = init_process_data_entry(entry_data);

        entry_data->pid = proc_info->tid;
        entry_data->ppid = proc_info->ppid;

        if (proc_info->cmd) {
            os_strdup(proc_info->cmd, entry_data->name);
        }

        if (&proc_info->state) {
            os_strdup(&proc_info->state, entry_data->state);
        }

        os_malloc(sizeof(char *), entry_data->argvs);
        if (proc_info->cmdline && proc_info->cmdline[0]) {
            os_strdup(proc_info->cmdline[0], entry_data->cmd);
            for (i = 1; proc_info->cmdline[i]; i++) {
                if (!strlen(proc_info->cmdline[i]) == 0) {
                    os_strdup(proc_info->cmdline[i], entry_data->argvs[pos]);
                    os_realloc(entry_data->argvs, (pos + 2) * sizeof(char *), entry_data->argvs);
                    pos++;
                }
            }
        }
        entry_data->argvs[pos] = NULL;

        if (proc_info->euser) {
            os_strdup(proc_info->euser, entry_data->euser);
        }

        if (proc_info->ruser) {
            os_strdup(proc_info->ruser, entry_data->ruser);
        }

        if (proc_info->suser) {
            os_strdup(proc_info->suser, entry_data->suser);
        }

        if (proc_info->egroup) {
            os_strdup(proc_info->egroup, entry_data->egroup);
        }

        if (proc_info->rgroup) {
            os_strdup(proc_info->rgroup, entry_data->rgroup);
        }

        if (proc_info->sgroup) {
            os_strdup(proc_info->sgroup, entry_data->sgroup);
        }

        if (proc_info->fgroup) {
            os_strdup(proc_info->fgroup, entry_data->fgroup);
        }

        entry_data->priority = proc_info->priority;
        entry_data->nice = proc_info->nice;

        entry_data->size = proc_info->size;
        entry_data->vm_size = proc_info->vm_size;
        entry_data->resident = proc_info->resident;
        entry_data->share = proc_info->share;

        entry_data->start_time =  proc_info->start_time;
        entry_data->utime = proc_info->utime;
        entry_data->stime = proc_info->stime;

        entry_data->pgrp = proc_info->pgrp;
        entry_data->session = proc_info->session;
        entry_data->nlwp = proc_info->nlwp;
        entry_data->tgid = proc_info->tgid;
        entry_data->tty = proc_info->tty;
        entry_data->processor = proc_info->processor;

        freeproc(proc_info);

        // Check if it is necessary to create a process event
        char * string = NULL;
        if (string = analyze_process(entry_data, timestamp), string) {
            mtdebug2(WM_SYS_LOGTAG, "sys_proc_linux() sending '%s'", string);
            wm_sendmsg(usec, queue_fd, string, LOCATION, SYSCOLLECTOR_MQ);
            free(string);
        }
    }
    closeproc(proc);
    free(timestamp);

    // Checking for terminated processes
    check_terminated_processes();
}

// Read string from a byte array until find a NULL byte
char* read_string(u_int8_t* bytes) {

    char * data;
    char hex[10];
    int i = 0;

    os_calloc(OS_MAXSTR, sizeof(char), data);

    while (bytes[i]) {
        sprintf(hex, "%c", bytes[i]);
        strcat(data, hex);
        i++;
    }

    return data;

}

// Read four bytes and retrieve its decimal value
int four_bytes_to_int32(u_int8_t* bytes){

    int result = (int)bytes[3] | (int)bytes[2] << 8 | (int)bytes[1] << 16 | (int)bytes[0] << 24;
    return result;

}

// Read index entry from a RPM header
int read_entry(u_int8_t* bytes, rpm_data *info) {

    u_int8_t* entry;
    int tag;
    char* tag_name = NULL;

    // Read 4 first bytes looking for a known tag
    tag = four_bytes_to_int32(bytes);

    switch(tag) {
        case TAG_NAME:
            tag_name = "name";
            break;
        case TAG_VERSION:
            tag_name = "version";
            break;
        case TAG_RELEASE:
            tag_name = "release";
            break;
        case TAG_EPOCH:
            tag_name = "epoch";
            break;
        case TAG_SUMMARY:
            tag_name = "description";
            break;
        case TAG_ITIME:
            tag_name = "install_time";
            break;
        case TAG_SIZE:
            tag_name = "size";
            break;
        case TAG_VENDOR:
            tag_name = "vendor";
            break;
        case TAG_GROUP:
            tag_name = "group";
            break;
        case TAG_SOURCE:
            tag_name = "source";
            break;
        case TAG_ARCH:
            tag_name = "architecture";
            break;
        default:
            return -1;
    }

    os_strdup(tag_name, info->tag);

    // Read next 4 bytes (type)

    entry = &bytes[4];
    info->type = four_bytes_to_int32(entry);

    // Read next 4 bytes (offset)

    entry = &bytes[8];
    info->offset = four_bytes_to_int32(entry);

    // Last 4 bytes (count of elements of the entry)
    entry = &bytes[12];
    info->count = four_bytes_to_int32(entry);

    return 0;

}

interface_entry_data * getNetworkIface_linux(char *iface_name, struct ifaddrs *ifaddr){

    struct ifaddrs *ifa;
    int k = 0;
    int family = 0;

    interface_entry_data * entry_data = init_interface_data_entry();

    os_strdup(iface_name, entry_data->name);

    /* Interface type */
    char *type;
    type = get_if_type(iface_name);
    os_strdup(type, entry_data->type);
    free(type);

    /* Operational state */
    char *state;
    state = get_oper_state(iface_name);
    os_strdup(state, entry_data->state);
    free(state);

    /* Get MAC address */
    char addr_path[PATH_LENGTH] = {'\0'};
    snprintf(addr_path, PATH_LENGTH, "%s%s/address", WM_SYS_IFDATA_DIR, iface_name);
    FILE *fs_if_addr = fopen(addr_path, "r");
    if (fs_if_addr != NULL) {
        char mac[MAC_LENGTH] = {'\0'};
        if (fgets(mac, sizeof(mac), fs_if_addr)) {
            char * newline = strchr(mac, '\n');
            if (newline) {
                *newline = '\0';
            }
            os_strdup(mac, entry_data->mac);
        } else {
            mtdebug1(WM_SYS_LOGTAG, "Invalid MAC address length for interface '%s' at '%s': file is empty.", iface_name, addr_path);
        }
        fclose(fs_if_addr);
    } else {
        mtdebug1(WM_SYS_LOGTAG, "Unable to read MAC address for interface '%s' from '%s': %s (%d)", iface_name, addr_path, strerror(errno), errno);
    }

    entry_data->ipv4 = init_net_addr();
    os_malloc(sizeof(char *), entry_data->ipv4->address);
    os_malloc(sizeof(char *), entry_data->ipv4->netmask);
    os_malloc(sizeof(char *), entry_data->ipv4->broadcast);
    int addr4 = 0, nmask4 = 0, bcast4 = 0;

    entry_data->ipv6 = init_net_addr();
    os_malloc(sizeof(char *), entry_data->ipv6->address);
    os_malloc(sizeof(char *), entry_data->ipv6->netmask);
    os_malloc(sizeof(char *), entry_data->ipv6->broadcast);
    int addr6 = 0, nmask6 = 0, bcast6 = 0;

    for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {

        if (strcmp(iface_name, ifa->ifa_name)){
            continue;
        }
        if (ifa->ifa_flags & IFF_LOOPBACK) {
            continue;
        }

        if (ifa->ifa_addr) {
            family = ifa->ifa_addr->sa_family;

            if (family == AF_INET) {

                /* Get IPv4 address */
                char host[NI_MAXHOST] = "";
                int result = getnameinfo(ifa->ifa_addr,
                        sizeof(struct sockaddr_in),
                        host, NI_MAXHOST,
                        NULL, 0, NI_NUMERICHOST);
                if (result == 0) {
                    os_strdup(host, entry_data->ipv4->address[addr4]);
                    os_realloc(entry_data->ipv4->address, (addr4 + 2) * sizeof(char *), entry_data->ipv4->address);
                    addr4++;
                } else {
                    mterror(WM_SYS_LOGTAG, "Can't obtain the IPv4 address for interface '%s': %s\n", iface_name, gai_strerror(result));
                }

                /* Get Netmask for IPv4 address */
                if (ifa->ifa_netmask != NULL) {
                    char netmask[NI_MAXHOST] = "";
                    result = getnameinfo(ifa->ifa_netmask,
                        sizeof(struct sockaddr_in),
                        netmask, NI_MAXHOST,
                        NULL, 0, NI_NUMERICHOST);

                    if (result == 0) {
                        os_strdup(netmask, entry_data->ipv4->netmask[nmask4]);
                        os_realloc(entry_data->ipv4->netmask, (nmask4 + 2) * sizeof(char *), entry_data->ipv4->netmask);
                        nmask4++;
                    } else {
                        mterror(WM_SYS_LOGTAG, "Can't obtain the IPv4 netmask for interface '%s': %s\n", iface_name, gai_strerror(result));
                    }

                    /* Get broadcast address (or destination address in a Point to Point connection) */
                    if (ifa->ifa_ifu.ifu_broadaddr != NULL){
                        char broadaddr[NI_MAXHOST];
                        result = getnameinfo(ifa->ifa_ifu.ifu_broadaddr,
                            sizeof(struct sockaddr_in),
                            broadaddr, NI_MAXHOST,
                            NULL, 0, NI_NUMERICHOST);

                        if (result == 0) {
                            os_strdup(broadaddr, entry_data->ipv4->broadcast[bcast4]);
                            os_realloc(entry_data->ipv4->broadcast, (bcast4 + 2) * sizeof(char *), entry_data->ipv4->broadcast);
                            bcast4++;
                        } else {
                            mterror(WM_SYS_LOGTAG, "Can't obtain the IPv4 broadcast for interface '%s': %s\n", iface_name, gai_strerror(result));
                        }
                    } else if ((host[0] != '\0') && (netmask[0] != '\0')) {
                        char * broadaddr;
                        broadaddr = get_broadcast_addr(host, netmask);
                        if (strncmp(broadaddr, "unknown", 7)) {
                            os_strdup(broadaddr, entry_data->ipv4->broadcast[bcast4]);
                            os_realloc(entry_data->ipv4->broadcast, (bcast4 + 2) * sizeof(char *), entry_data->ipv4->broadcast);
                            bcast4++;
                        } else {
                            mterror(WM_SYS_LOGTAG, "Failed getting broadcast addr for '%s'", host);
                        }
                        free(broadaddr);
                    }
                }

            } else if (family == AF_INET6) {

                /* Get IPv6 address */
                char host[NI_MAXHOST];
                int result = getnameinfo(ifa->ifa_addr,
                        sizeof(struct sockaddr_in6),
                        host, NI_MAXHOST,
                        NULL, 0, NI_NUMERICHOST);
                if (result == 0) {
                    char ** parts = NULL;
                    char *ip_addrr;
                    parts = OS_StrBreak('%', host, 2);
                    if(parts) {
                        ip_addrr = w_strtrim(parts[0]);
                        os_strdup(ip_addrr, entry_data->ipv6->address[addr6]);
                        os_realloc(entry_data->ipv6->address, (addr6 + 2) * sizeof(char *), entry_data->ipv6->address);
                        addr6++;
                        for (k=0; parts[k]; k++){
                            free(parts[k]);
                        }
                        free(parts);
                    }
                } else {
                    mterror(WM_SYS_LOGTAG, "Can't obtain the IPv6 address for interface '%s': %s\n", iface_name, gai_strerror(result));
                }

                /* Get Netmask for IPv6 address */
                if (ifa->ifa_netmask != NULL) {
                    char netmask6[NI_MAXHOST];
                    result = getnameinfo(ifa->ifa_netmask,
                        sizeof(struct sockaddr_in6),
                        netmask6, NI_MAXHOST,
                        NULL, 0, NI_NUMERICHOST);

                    if (result == 0) {
                        os_strdup(netmask6, entry_data->ipv6->netmask[nmask6]);
                        os_realloc(entry_data->ipv6->netmask, (nmask6 + 2) * sizeof(char *), entry_data->ipv6->netmask);
                        nmask6++;
                    } else {
                        mterror(WM_SYS_LOGTAG, "Can't obtain the IPv6 netmask for interface '%s': %s\n", iface_name, gai_strerror(result));
                    }
                }

                /* Get broadcast address (or destination address in a Point to Point connection) for IPv6*/
                if (ifa->ifa_ifu.ifu_broadaddr != NULL){
                    char broadaddr6[NI_MAXHOST];
                    result = getnameinfo(ifa->ifa_ifu.ifu_broadaddr,
                        sizeof(struct sockaddr_in6),
                        broadaddr6, NI_MAXHOST,
                        NULL, 0, NI_NUMERICHOST);

                    if (result == 0) {
                        os_strdup(broadaddr6, entry_data->ipv6->broadcast[bcast6]);
                        os_realloc(entry_data->ipv6->broadcast, (bcast6 + 2) * sizeof(char *), entry_data->ipv6->broadcast);
                        bcast6++;
                    } else {
                        mterror(WM_SYS_LOGTAG, "Can't obtain the IPv6 broadcast for interface '%s': %s\n", iface_name, gai_strerror(result));
                    }
                }

            } else if (family == AF_PACKET && ifa->ifa_data != NULL){

                /* Get stats of interface */
                struct link_stats *stats = ifa->ifa_data;
                entry_data->tx_packets = stats->tx_packets;
                entry_data->rx_packets = stats->rx_packets;
                entry_data->tx_bytes = stats->tx_bytes;
                entry_data->rx_bytes = stats->rx_bytes;
                entry_data->tx_errors = stats->tx_errors;
                entry_data->rx_errors = stats->rx_errors;
                entry_data->tx_dropped = stats->tx_dropped;
                entry_data->rx_dropped = stats->rx_dropped;

                /* MTU */
                char *mtu;
                int mtu_value;
                mtu = get_mtu(iface_name);
                mtu_value = atoi(mtu);
                entry_data->mtu = mtu_value;
                free(mtu);
            }
        }
    }

    entry_data->ipv4->address[addr4] = NULL;
    entry_data->ipv4->netmask[nmask4] = NULL;
    entry_data->ipv4->broadcast[bcast4] = NULL;
    entry_data->ipv6->address[addr6] = NULL;
    entry_data->ipv6->netmask[nmask6] = NULL;
    entry_data->ipv6->broadcast[bcast6] = NULL;

    /* Get Default Gateway */
    char *gateway;
    char *metric = NULL;
    char *end = NULL;

    gateway = get_default_gateway(iface_name);

    if (metric = end = strchr(gateway, '|'), metric) {
        metric++;
        entry_data->ipv4->metric = atoi(metric);
        *end = '\0';
    }

    os_strdup(gateway, entry_data->ipv4->gateway);
    free(gateway);

    /* Get DHCP status for IPv4 */
    char *dhcp_v4;
    dhcp_v4 = check_dhcp(iface_name, AF_INET);
    os_strdup(dhcp_v4, entry_data->ipv4->dhcp);
    free(dhcp_v4);

    /* Get DHCP status for IPv6 */
    char *dhcp_v6;
    dhcp_v6 = check_dhcp(iface_name, AF_INET6);
    os_strdup(dhcp_v6, entry_data->ipv6->dhcp);
    free(dhcp_v6);

    return entry_data;
}

#endif /* __linux__ */

#if defined(__linux__) || defined(__MACH__) || defined (__FreeBSD__) || defined (__OpenBSD__)
int getIfaceslist(char **ifaces_list, struct ifaddrs *ifaddr){

    int found;
    struct ifaddrs *ifa;
    int i = 0, size = 0;

    for (ifa = ifaddr; ifa; ifa = ifa->ifa_next){
        found = 0;
        for (i=0; i<=size; i++){
            if (!ifaces_list[i]){
                if (ifa->ifa_flags & IFF_LOOPBACK)
                    found = 1;

                break;

            }else if (!strcmp(ifaces_list[i], ifa->ifa_name)){
                    found = 1;
                    break;
            }
        }
        if (!found){
            os_calloc(IFNAME_LENGTH, sizeof(char), ifaces_list[size]);
            strncpy(ifaces_list[size], ifa->ifa_name, IFNAME_LENGTH - 1);
            ifaces_list[size][IFNAME_LENGTH - 1] = '\0';
            size++;
        }
    }

    return size;

}

#endif
