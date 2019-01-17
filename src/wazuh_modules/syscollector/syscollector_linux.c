/*
 * Wazuh Module for System inventory for Linux
 * Copyright (C) 2015-2019, Wazuh Inc.
 * Aug, 2017.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
*/

#include "syscollector.h"

#if defined(__linux__)

#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <netinet/tcp.h>
#include <ifaddrs.h>
#include <linux/if_packet.h>
#include "external/procps/readproc.h"
#include "external/libdb/build_unix/db.h"

hw_info *get_system_linux();                    // Get system information
char* get_serial_number();                      // Get Motherboard serial number
char* get_if_type(char *ifa_name);              // Get interface type
char* get_oper_state(char *ifa_name);           // Get operational state
char* get_mtu(char *ifa_name);                  // Get MTU
char* check_dhcp(char *ifa_name, int family);   // Check DHCP status for network interfaces
char* get_default_gateway(char *ifa_name);      // Get Default Gatewat for network interfaces

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

void get_ipv4_ports(int queue_fd, const char* LOCATION, const char* protocol, int random_id, const char* timestamp, int check_all){

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

            cJSON *object = cJSON_CreateObject();
            cJSON *port = cJSON_CreateObject();
            cJSON_AddStringToObject(object, "type", "port");
            cJSON_AddNumberToObject(object, "ID", random_id);
            cJSON_AddStringToObject(object, "timestamp", timestamp);
            cJSON_AddItemToObject(object, "port", port);
            cJSON_AddStringToObject(port, "protocol", protocol);
            cJSON_AddStringToObject(port, "local_ip", laddress);
            cJSON_AddNumberToObject(port, "local_port", local_port);
            cJSON_AddStringToObject(port, "remote_ip", raddress);
            cJSON_AddNumberToObject(port, "remote_port", rem_port);
            cJSON_AddNumberToObject(port, "tx_queue", txq);
            cJSON_AddNumberToObject(port, "rx_queue", rxq);
            cJSON_AddNumberToObject(port, "inode", inode);

            if (!strncmp(protocol, "tcp", 3)){
                char *port_state;
                port_state = get_port_state(state);
                cJSON_AddStringToObject(port, "state", port_state);
                if (!strcmp(port_state, "listening")) {
                    listening = 1;
                }
                free(port_state);
            }

            if (check_all || listening) {

                char *string;
                string = cJSON_PrintUnformatted(object);
                mtdebug2(WM_SYS_LOGTAG, "sys_ports_linux() sending '%s'", string);
                wm_sendmsg(usec, queue_fd, string, LOCATION, SYSCOLLECTOR_MQ);
                cJSON_Delete(object);
                free(string);

            } else
                cJSON_Delete(object);

        }
        fclose(fp);
    }else{
        mterror(WM_SYS_LOGTAG, "Unable to get list of %s opened ports.", protocol);
    }
    free(laddress);
    free(raddress);
}

// Get opened ports related to IPv6 sockets

void get_ipv6_ports(int queue_fd, const char* LOCATION, const char* protocol, int random_id, const char * timestamp, int check_all){

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

            cJSON *object = cJSON_CreateObject();
            cJSON *port = cJSON_CreateObject();
            cJSON_AddStringToObject(object, "type", "port");
            cJSON_AddNumberToObject(object, "ID", random_id);
            cJSON_AddStringToObject(object, "timestamp", timestamp);
            cJSON_AddItemToObject(object, "port", port);
            cJSON_AddStringToObject(port, "protocol", protocol);
            cJSON_AddStringToObject(port, "local_ip", laddress);
            cJSON_AddNumberToObject(port, "local_port", local_port);
            cJSON_AddStringToObject(port, "remote_ip", raddress);
            cJSON_AddNumberToObject(port, "remote_port", rem_port);
            cJSON_AddNumberToObject(port, "tx_queue", txq);
            cJSON_AddNumberToObject(port, "rx_queue", rxq);
            cJSON_AddNumberToObject(port, "inode", inode);

            if (!strncmp(protocol, "tcp6", 4)){
                char *port_state;
                port_state = get_port_state(state);
                cJSON_AddStringToObject(port, "state", port_state);
                if (!strcmp(port_state, "listening")) {
                    listening = 1;
                }
                free(port_state);
            }

            if (check_all || listening) {

                char *string;
                string = cJSON_PrintUnformatted(object);
                mtdebug2(WM_SYS_LOGTAG, "sys_ports_linux() sending '%s'", string);
                wm_sendmsg(usec, queue_fd, string, LOCATION, SYSCOLLECTOR_MQ);
                cJSON_Delete(object);
                free(string);

            } else
                cJSON_Delete(object);

        }
        fclose(fp);
    }else{
        mterror(WM_SYS_LOGTAG, "Unable to get list of %s opened ports.", protocol);
    }
}

// Opened ports inventory

void sys_ports_linux(int queue_fd, const char* WM_SYS_LOCATION, int check_all){

    char *protocol;
    int random_id = os_random();
    char *timestamp;
    time_t now;
    struct tm localtm;

    now = time(NULL);
    localtime_r(&now, &localtm);

    os_calloc(TIME_LENGTH, sizeof(char), timestamp);

    snprintf(timestamp,TIME_LENGTH - 1,"%d/%02d/%02d %02d:%02d:%02d",
            localtm.tm_year + 1900, localtm.tm_mon + 1,
            localtm.tm_mday, localtm.tm_hour, localtm.tm_min, localtm.tm_sec);

    if (random_id < 0)
        random_id = -random_id;

    mtdebug1(WM_SYS_LOGTAG, "Starting ports inventory.");

    os_calloc(PROTO_LENGTH + 1, sizeof(char), protocol);

    /* TCP opened ports inventory */
    snprintf(protocol, PROTO_LENGTH, "%s", "tcp");
    get_ipv4_ports(queue_fd, WM_SYS_LOCATION, protocol, random_id, timestamp, check_all);

    if (check_all) {
        /* UDP opened ports inventory */
        snprintf(protocol, PROTO_LENGTH, "%s", "udp");
        get_ipv4_ports(queue_fd, WM_SYS_LOCATION, protocol, random_id, timestamp, check_all);
    }

    /* TCP6 opened ports inventory */
    snprintf(protocol, PROTO_LENGTH, "%s", "tcp6");
    get_ipv6_ports(queue_fd, WM_SYS_LOCATION, protocol, random_id, timestamp, check_all);

    if (check_all) {
        /* UDP6 opened ports inventory */
        snprintf(protocol, PROTO_LENGTH, "%s", "udp6");
        get_ipv6_ports(queue_fd, WM_SYS_LOCATION, protocol, random_id, timestamp, check_all);
    }

    free(protocol);

    cJSON *object = cJSON_CreateObject();
    cJSON_AddStringToObject(object, "type", "port_end");
    cJSON_AddNumberToObject(object, "ID", random_id);
    cJSON_AddStringToObject(object, "timestamp", timestamp);

    char *string;
    string = cJSON_PrintUnformatted(object);
    mtdebug2(WM_SYS_LOGTAG, "sys_ports_linux() sending '%s'", string);
    SendMSG(queue_fd, string, WM_SYS_LOCATION, SYSCOLLECTOR_MQ);
    cJSON_Delete(object);
    free(string);
    free(timestamp);
}

// Get installed programs inventory

void sys_packages_linux(int queue_fd, const char* LOCATION) {

    DIR *dir;
    int random_id = os_random();
    char * end_dpkg = NULL;
    char * end_rpm = NULL;

    // Define time to sleep between messages sent
    int usec = 1000000 / wm_max_eps;

    /* Set positive random ID for each event */

    if (random_id < 0)
        random_id = -random_id;

    mtdebug1(WM_SYS_LOGTAG, "Starting installed packages inventory.");

    if ((dir = opendir("/var/lib/dpkg/"))){
        closedir(dir);
        if (end_dpkg = sys_deb_packages(queue_fd, LOCATION, random_id), !end_dpkg) {
            mterror(WM_SYS_LOGTAG, "Unable to get debian packages due to: %s", strerror(errno));
        }
    }
    if ((dir = opendir("/var/lib/rpm/"))){
        closedir(dir);
        if (end_rpm = sys_rpm_packages(queue_fd, LOCATION, random_id), !end_rpm) {
            mterror(WM_SYS_LOGTAG, "Unable to get rpm packages due to: %s", strerror(errno));
        }
    }

    if (end_rpm) {
        mtdebug2(WM_SYS_LOGTAG, "sys_packages_linux() sending '%s'", end_rpm);
        wm_sendmsg(usec, queue_fd, end_rpm, LOCATION, SYSCOLLECTOR_MQ);

        free(end_rpm);
        if (end_dpkg) {
            free(end_dpkg);
        }
    } else if (end_dpkg) {
        mtdebug2(WM_SYS_LOGTAG, "sys_packages_linux() sending '%s'", end_dpkg);
        wm_sendmsg(usec, queue_fd, end_dpkg, LOCATION, SYSCOLLECTOR_MQ);
        free(end_dpkg);
    }
}

char * sys_rpm_packages(int queue_fd, const char* LOCATION, int random_id){

    char *format = "rpm";
    char *timestamp;
    time_t now;
    struct tm localtm;
    cJSON *object = NULL;
    cJSON *package = NULL;

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

    // Set timestamp

    now = time(NULL);
    localtime_r(&now, &localtm);

    os_calloc(TIME_LENGTH, sizeof(char), timestamp);

    snprintf(timestamp,TIME_LENGTH-1,"%d/%02d/%02d %02d:%02d:%02d",
            localtm.tm_year + 1900, localtm.tm_mon + 1,
            localtm.tm_mday, localtm.tm_hour, localtm.tm_min, localtm.tm_sec);

    if ((ret = db_create(&dbp, NULL, 0)) != 0) {
        mterror(WM_SYS_LOGTAG, "sys_rpm_packages(): failed to initialize the DB handler: %s", db_strerror(ret));
        free(timestamp);
        return NULL;
    }

    // Set Little-endian order by default
    if ((ret = dbp->set_lorder(dbp, 1234)) != 0) {
        mtwarn(WM_SYS_LOGTAG, "sys_rpm_packages(): Error setting byte-order.");
    }

    if ((ret = dbp->open(dbp, NULL, RPM_DATABASE, NULL, DB_HASH, DB_RDONLY, 0)) != 0) {
        mterror(WM_SYS_LOGTAG, "sys_rpm_packages(): Failed to open database '%s': %s", RPM_DATABASE, db_strerror(ret));
        free(timestamp);
        return NULL;
    }

    if ((ret = dbp->cursor(dbp, NULL, &cursor, 0)) != 0) {
        mterror(WM_SYS_LOGTAG, "sys_rpm_packages(): Error creating cursor: %s", db_strerror(ret));
        free(timestamp);
        return NULL;
    }

    memset(&key, 0, sizeof(DBT));
    memset(&data, 0, sizeof(DBT));

    int j;

    for (j = 0; ret = cursor->c_get(cursor, &key, &data, DB_NEXT), ret == 0; j++) {

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
            if ((ret = read_entry(bytes, info)) == 0) {
                os_calloc(1, sizeof(rpm_data), info->next);
                info = info->next;
            }
            bytes = &bytes[offset];
        }

        // Start reading the data

        store = bytes;
        epoch = 0;
        skip = 0;

        object = cJSON_CreateObject();
        package = cJSON_CreateObject();
        cJSON_AddStringToObject(object, "type", "program");
        cJSON_AddNumberToObject(object, "ID", random_id);
        cJSON_AddStringToObject(object, "timestamp", timestamp);
        cJSON_AddItemToObject(object, "program", package);
        cJSON_AddStringToObject(package, "format", format);

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

                    if (!strncmp(info->tag, "name", 4) && !strncmp(read, "gpg-pubkey", 10))
                        skip = 1;

                    if (!strncmp(info->tag, "version", 7)) {
                        snprintf(version, TYPE_LENGTH - 1, "%s", read);
                    } else if (!strncmp(info->tag, "release", 7)) {
                        snprintf(release, TYPE_LENGTH - 1, "%s", read);
                    } else {
                        cJSON_AddStringToObject(package, info->tag, read);
                    }
                    free(read);
                    break;

                case 4:   // int32
                    result = four_bytes_to_int32(bytes);

                    if (!strncmp(info->tag, "size", 4)) {
                        result = result / 1024;   // Bytes to KBytes
                    }

                    if (!strncmp(info->tag, "install_time", 12)) {    // Format date
                        char installt[TIME_LENGTH];
                        struct tm itime;
                        time_t dateint = result;
                        localtime_r(&dateint, &itime);

                        snprintf(installt,TIME_LENGTH - 1,"%d/%02d/%02d %02d:%02d:%02d",
                                itime.tm_year + 1900, itime.tm_mon + 1,
                                itime.tm_mday, itime.tm_hour, itime.tm_min, itime.tm_sec);

                        cJSON_AddStringToObject(package, info->tag, installt);
                    } else if (!strncmp(info->tag, "epoch", 5)) {
                        epoch = result;
                    } else {
                        cJSON_AddNumberToObject(package, info->tag, result);
                    }

                    break;

                case 9:   // Vector of strings
                    read = read_string(bytes);
                    cJSON_AddStringToObject(package, info->tag, read);
                    free(read);
                    break;

                default:
                    mterror(WM_SYS_LOGTAG, "sys_rpm_packages(): Unknown type of data: %d", info->type);
            }
        }

        if (epoch) {
            snprintf(final_version, V_LENGTH - 1, "%d:%s-%s", epoch, version, release);
        } else {
            snprintf(final_version, V_LENGTH - 1, "%s-%s", version, release);
        }
        cJSON_AddStringToObject(package, "version", final_version);

        // Send RPM package information to the manager

        if (skip) {
            cJSON_Delete(object);
        } else {
            char *string;
            string = cJSON_PrintUnformatted(object);
            mtdebug2(WM_SYS_LOGTAG, "sys_rpm_packages() sending '%s'", string);
            wm_sendmsg(usec, queue_fd, string, LOCATION, SYSCOLLECTOR_MQ);
            cJSON_Delete(object);
            free(string);
        }

        // Free resources

        for (info = head; info; info = next_info) {
            next_info = info->next;
            free(info->tag);
            free(info);
        }
    }

    if (ret == DB_NOTFOUND && j <= 1) {
        mtwarn(WM_SYS_LOGTAG, "sys_rpm_packages(): Not found any record in database '%s'", RPM_DATABASE);
    }

    cursor->c_close(cursor);
    dbp->close(dbp, 0);

    object = cJSON_CreateObject();
    cJSON_AddStringToObject(object, "type", "program_end");
    cJSON_AddNumberToObject(object, "ID", random_id);
    cJSON_AddStringToObject(object, "timestamp", timestamp);

    char *end_msg;
    end_msg = cJSON_PrintUnformatted(object);
    cJSON_Delete(object);
    free(timestamp);

    return end_msg;

}

char * sys_deb_packages(int queue_fd, const char* LOCATION, int random_id){

    const char * format = "deb";
    char file[PATH_LENGTH] = "/var/lib/dpkg/status";
    char read_buff[OS_MAXSTR];
    FILE *fp;
    size_t length;
    int i, installed = 1;
    char *timestamp;
    time_t now;
    struct tm localtm;
    cJSON *object = NULL;
    cJSON *package = NULL;

    // Define time to sleep between messages sent
    int usec = 1000000 / wm_max_eps;

    // Set timestamp

    now = time(NULL);
    localtime_r(&now, &localtm);

    os_calloc(TIME_LENGTH, sizeof(char), timestamp);

    snprintf(timestamp,TIME_LENGTH-1,"%d/%02d/%02d %02d:%02d:%02d",
            localtm.tm_year + 1900, localtm.tm_mon + 1,
            localtm.tm_mday, localtm.tm_hour, localtm.tm_min, localtm.tm_sec);

    memset(read_buff, 0, OS_MAXSTR);

    if ((fp = fopen(file, "r"))) {

        while(fgets(read_buff, OS_MAXSTR, fp) != NULL){

            // Remove '\n' from the read line
            length = strlen(read_buff);
            read_buff[length - 1] = '\0';

            if (!strncmp(read_buff, "Package: ", 9)) {

                object = cJSON_CreateObject();
                package = cJSON_CreateObject();
                cJSON_AddStringToObject(object, "type", "program");
                cJSON_AddNumberToObject(object, "ID", random_id);
                cJSON_AddStringToObject(object, "timestamp", timestamp);
                cJSON_AddItemToObject(object, "program", package);
                cJSON_AddStringToObject(package, "format", format);

                char ** parts = NULL;
                parts = OS_StrBreak(' ', read_buff, 2);
                cJSON_AddStringToObject(package, "name", parts[1]);

                for (i=0; parts[i]; i++){
                    free(parts[i]);
                }
                free(parts);

            } else if (!strncmp(read_buff, "Status: ", 8)) {

                if (strstr(read_buff, "install ok installed"))
                    installed = 1;
                else
                    installed = 0;

            } else if (!strncmp(read_buff, "Priority: ", 10)) {

                char ** parts = NULL;
                parts = OS_StrBreak(' ', read_buff, 2);
                cJSON_AddStringToObject(package, "priority", parts[1]);

                for (i=0; parts[i]; i++){
                    free(parts[i]);
                }
                free(parts);

            } else if (!strncmp(read_buff, "Section: ", 9)) {

                char ** parts = NULL;
                parts = OS_StrBreak(' ', read_buff, 2);
                cJSON_AddStringToObject(package, "group", parts[1]);

                for (i=0; parts[i]; i++){
                    free(parts[i]);
                }
                free(parts);

            } else if (!strncmp(read_buff, "Installed-Size: ", 16)) {

                char ** parts = NULL;
                parts = OS_StrBreak(' ', read_buff, 2);
                cJSON_AddNumberToObject(package, "size", atoi(parts[1]));

                for (i=0; parts[i]; i++){
                    free(parts[i]);
                }
                free(parts);

            } else if (!strncmp(read_buff, "Maintainer: ", 12)) {

                char ** parts = NULL;
                parts = OS_StrBreak(' ', read_buff, 2);
                cJSON_AddStringToObject(package, "vendor", parts[1]);

                for (i=0; parts[i]; i++){
                    free(parts[i]);
                }
                free(parts);

            } else if (!strncmp(read_buff, "Architecture: ", 14)) {

                char ** parts = NULL;
                parts = OS_StrBreak(' ', read_buff, 2);
                cJSON_AddStringToObject(package, "architecture", parts[1]);

                for (i=0; parts[i]; i++){
                    free(parts[i]);
                }
                free(parts);

            } else if (!strncmp(read_buff, "Multi-Arch: ", 12)) {

                char ** parts = NULL;
                parts = OS_StrBreak(' ', read_buff, 2);
                cJSON_AddStringToObject(package, "multi-arch", parts[1]);

                for (i=0; parts[i]; i++){
                    free(parts[i]);
                }
                free(parts);

            } else if (!strncmp(read_buff, "Source: ", 8)) {

                char ** parts = NULL;
                parts = OS_StrBreak(' ', read_buff, 2);
                cJSON_AddStringToObject(package, "source", parts[1]);

                for (i=0; parts[i]; i++){
                    free(parts[i]);
                }
                free(parts);

            } else if (!strncmp(read_buff, "Version: ", 9)) {

                char ** parts = NULL;
                parts = OS_StrBreak(' ', read_buff, 2);
                cJSON_AddStringToObject(package, "version", parts[1]);

                for (i=0; parts[i]; i++){
                    free(parts[i]);
                }
                free(parts);

            } else if (!strncmp(read_buff, "Description: ", 13)) {

                char ** parts = NULL;
                parts = OS_StrBreak(' ', read_buff, 2);
                cJSON_AddStringToObject(package, "description", parts[1]);

                for (i=0; parts[i]; i++){
                    free(parts[i]);
                }
                free(parts);

                // Send message to the queue

                if (installed) {

                    installed = 0;

                    char *string;
                    string = cJSON_PrintUnformatted(object);
                    mtdebug2(WM_SYS_LOGTAG, "sys_deb_packages() sending '%s'", string);
                    wm_sendmsg(usec, queue_fd, string, LOCATION, SYSCOLLECTOR_MQ);
                    cJSON_Delete(object);
                    free(string);

                } else {
                    cJSON_Delete(object);
                    continue;
                }

            }
        }

        fclose(fp);

    } else {

        mterror(WM_SYS_LOGTAG, "Unable to open the file '%s'", file);
        free(timestamp);
        return NULL;

    }

    object = cJSON_CreateObject();
    cJSON_AddStringToObject(object, "type", "program_end");
    cJSON_AddNumberToObject(object, "ID", random_id);
    cJSON_AddStringToObject(object, "timestamp", timestamp);

    char *end_msg;
    end_msg = cJSON_PrintUnformatted(object);
    cJSON_Delete(object);
    free(timestamp);

    return end_msg;

}

// Get Hardware inventory

void sys_hw_linux(int queue_fd, const char* LOCATION){

    char *string;
    int random_id = os_random();
    char *timestamp;
    time_t now;
    struct tm localtm;

    now = time(NULL);
    localtime_r(&now, &localtm);

    os_calloc(TIME_LENGTH, sizeof(char), timestamp);

    snprintf(timestamp,TIME_LENGTH-1,"%d/%02d/%02d %02d:%02d:%02d",
            localtm.tm_year + 1900, localtm.tm_mon + 1,
            localtm.tm_mday, localtm.tm_hour, localtm.tm_min, localtm.tm_sec);

    if (random_id < 0)
        random_id = -random_id;

    mtdebug1(WM_SYS_LOGTAG, "Starting Hardware inventory.");

    cJSON *object = cJSON_CreateObject();
    cJSON *hw_inventory = cJSON_CreateObject();
    cJSON_AddStringToObject(object, "type", "hardware");
    cJSON_AddNumberToObject(object, "ID", random_id);
    cJSON_AddStringToObject(object, "timestamp", timestamp);
    cJSON_AddItemToObject(object, "inventory", hw_inventory);

    /* Motherboard serial-number */
    char *serial;
    serial = get_serial_number();
    cJSON_AddStringToObject(hw_inventory, "board_serial", serial);
    free(serial);

    /* Get CPU and memory information */
    hw_info *sys_info;
    if (sys_info = get_system_linux(), sys_info){
        cJSON_AddStringToObject(hw_inventory, "cpu_name", w_strtrim(sys_info->cpu_name));
        cJSON_AddNumberToObject(hw_inventory, "cpu_cores", sys_info->cpu_cores);
        cJSON_AddNumberToObject(hw_inventory, "cpu_MHz", sys_info->cpu_MHz);
        cJSON_AddNumberToObject(hw_inventory, "ram_total", sys_info->ram_total);
        cJSON_AddNumberToObject(hw_inventory, "ram_free", sys_info->ram_free);
        cJSON_AddNumberToObject(hw_inventory, "ram_usage", sys_info->ram_usage);

        free(sys_info->cpu_name);
        free(sys_info);
    }

    /* Send interface data in JSON format */
    string = cJSON_PrintUnformatted(object);
    mtdebug2(WM_SYS_LOGTAG, "sys_hw_linux() sending '%s'", string);
    SendMSG(queue_fd, string, LOCATION, SYSCOLLECTOR_MQ);
    cJSON_Delete(object);

    free(string);
    free(timestamp);

}

#endif /* __linux__ */

// Get OS inventory

void sys_os_unix(int queue_fd, const char* LOCATION){

    char *string;
    int random_id = os_random();
    char *timestamp;
    time_t now;
    struct tm localtm;

    now = time(NULL);
    localtime_r(&now, &localtm);

    os_calloc(TIME_LENGTH, sizeof(char), timestamp);

    snprintf(timestamp,TIME_LENGTH-1,"%d/%02d/%02d %02d:%02d:%02d",
            localtm.tm_year + 1900, localtm.tm_mon + 1,
            localtm.tm_mday, localtm.tm_hour, localtm.tm_min, localtm.tm_sec);

    if (random_id < 0)
        random_id = -random_id;

    mtdebug1(WM_SYS_LOGTAG, "Starting Operating System inventory.");

    cJSON *object = cJSON_CreateObject();
    cJSON_AddStringToObject(object, "type", "OS");
    cJSON_AddNumberToObject(object, "ID", random_id);
    cJSON_AddStringToObject(object, "timestamp", timestamp);

    cJSON *os_inventory = getunameJSON();

    if (os_inventory != NULL)
        cJSON_AddItemToObject(object, "inventory", os_inventory);

    /* Send interface data in JSON format */
    string = cJSON_PrintUnformatted(object);
    mtdebug2(WM_SYS_LOGTAG, "sys_os_unix() sending '%s'", string);
    SendMSG(queue_fd, string, LOCATION, SYSCOLLECTOR_MQ);
    cJSON_Delete(object);
    free(timestamp);
    free(string);
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
    int i = 0, j = 0, k = 0, found;
    int family = 0;
    struct ifaddrs *ifaddr, *ifa;
    int random_id = os_random();
    char *timestamp;
    time_t now;
    struct tm localtm;

    // Define time to sleep between messages sent
    int usec = 1000000 / wm_max_eps;

    now = time(NULL);
    localtime_r(&now, &localtm);

    os_calloc(TIME_LENGTH, sizeof(char), timestamp);

    snprintf(timestamp,TIME_LENGTH-1,"%d/%02d/%02d %02d:%02d:%02d",
            localtm.tm_year + 1900, localtm.tm_mon + 1,
            localtm.tm_mday, localtm.tm_hour, localtm.tm_min, localtm.tm_sec);

    if (random_id < 0)
        random_id = -random_id;

    mtdebug1(WM_SYS_LOGTAG, "Starting network inventory.");

    if (getifaddrs(&ifaddr) == -1) {
        mterror(WM_SYS_LOGTAG, "getifaddrs() failed.");
        free(timestamp);
        return;
    }

    for (ifa = ifaddr; ifa; ifa = ifa->ifa_next){
        i++;
    }
    os_calloc(i, sizeof(char *), ifaces_list);

    /* Create interfaces list */
    for (ifa = ifaddr; ifa; ifa = ifa->ifa_next){
        found = 0;
        for (i=0; i<=j; i++){
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
            os_calloc(IFNAME_LENGTH, sizeof(char), ifaces_list[j]);
            strncpy(ifaces_list[j], ifa->ifa_name, IFNAME_LENGTH - 1);
            ifaces_list[j][IFNAME_LENGTH - 1] = '\0';
            j++;
        }
    }

    if(!ifaces_list[0]){
        mterror(WM_SYS_LOGTAG, "No interface found. Network inventory suspended.");
        free(ifaces_list);
        free(timestamp);
        return;
    }

    /* Collect all information for each interface */
    for (i=0; i<j; i++){

        char *string;

        cJSON *object = cJSON_CreateObject();
        cJSON *interface = cJSON_CreateObject();
        cJSON_AddStringToObject(object, "type", "network");
        cJSON_AddNumberToObject(object, "ID", random_id);
        cJSON_AddStringToObject(object, "timestamp", timestamp);
        cJSON_AddItemToObject(object, "iface", interface);
        cJSON_AddStringToObject(interface, "name", ifaces_list[i]);

        /* Interface type */
        char *type;
        type = get_if_type(ifaces_list[i]);
        cJSON_AddStringToObject(interface, "type", type);
        free(type);

        /* Operational state */
        char *state;
        state = get_oper_state(ifaces_list[i]);
        cJSON_AddStringToObject(interface, "state", state);
        free(state);

        cJSON *ipv4 = cJSON_CreateObject();
        cJSON *ipv4_addr = cJSON_CreateArray();
        cJSON *ipv4_netmask = cJSON_CreateArray();
        cJSON *ipv4_broadcast = cJSON_CreateArray();

        cJSON *ipv6 = cJSON_CreateObject();
        cJSON *ipv6_addr = cJSON_CreateArray();
        cJSON *ipv6_netmask = cJSON_CreateArray();
        cJSON *ipv6_broadcast = cJSON_CreateArray();

        for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {

            if (strcmp(ifaces_list[i], ifa->ifa_name)){
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
                        cJSON_AddItemToArray(ipv4_addr, cJSON_CreateString(host));
                    } else {
                        mterror(WM_SYS_LOGTAG, "getnameinfo() failed: %s\n", gai_strerror(result));
                    }

                    /* Get Netmask for IPv4 address */
                    if (ifa->ifa_netmask != NULL) {
                        char netmask[NI_MAXHOST] = "";
                        result = getnameinfo(ifa->ifa_netmask,
                            sizeof(struct sockaddr_in),
                            netmask, NI_MAXHOST,
                            NULL, 0, NI_NUMERICHOST);

                        if (result == 0) {
                            cJSON_AddItemToArray(ipv4_netmask, cJSON_CreateString(netmask));
                        } else {
                            mterror(WM_SYS_LOGTAG, "getnameinfo() failed: %s\n", gai_strerror(result));
                        }

                        /* Get broadcast address (or destination address in a Point to Point connection) */
                        if (ifa->ifa_ifu.ifu_broadaddr != NULL){
                            char broadaddr[NI_MAXHOST];
                            result = getnameinfo(ifa->ifa_ifu.ifu_broadaddr,
                                sizeof(struct sockaddr_in),
                                broadaddr, NI_MAXHOST,
                                NULL, 0, NI_NUMERICHOST);

                            if (result == 0) {
                                cJSON_AddItemToArray(ipv4_broadcast, cJSON_CreateString(broadaddr));
                            } else {
                                mterror(WM_SYS_LOGTAG, "getnameinfo() failed: %s\n", gai_strerror(result));
                            }
                        } else if ((host[0] != '\0') && (netmask[0] != '\0')) {
                            char * broadaddr;
                            broadaddr = get_broadcast_addr(host, netmask);
                            if (strncmp(broadaddr, "unknown", 7)) {
                                cJSON_AddItemToArray(ipv4_broadcast, cJSON_CreateString(broadaddr));
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
                        ip_addrr = w_strtrim(parts[0]);
                        cJSON_AddItemToArray(ipv6_addr, cJSON_CreateString(ip_addrr));
                        for (k=0; parts[k]; k++){
                            free(parts[k]);
                        }
                        free(parts);
                    } else {
                        mterror(WM_SYS_LOGTAG, "getnameinfo() failed: %s\n", gai_strerror(result));
                    }

                    /* Get Netmask for IPv6 address */
                    if (ifa->ifa_netmask != NULL) {
                        char netmask6[NI_MAXHOST];
                        result = getnameinfo(ifa->ifa_netmask,
                            sizeof(struct sockaddr_in6),
                            netmask6, NI_MAXHOST,
                            NULL, 0, NI_NUMERICHOST);

                        if (result == 0) {
                            cJSON_AddItemToArray(ipv6_netmask, cJSON_CreateString(netmask6));
                        } else {
                            mterror(WM_SYS_LOGTAG, "getnameinfo() failed: %s\n", gai_strerror(result));
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
                            cJSON_AddItemToArray(ipv6_broadcast, cJSON_CreateString(broadaddr6));
                        } else {
                            mterror(WM_SYS_LOGTAG, "getnameinfo() failed: %s\n", gai_strerror(result));
                        }
                    }

                } else if (family == AF_PACKET && ifa->ifa_data != NULL){

                    /* Get MAC address and stats */
                    char MAC[MAC_LENGTH];
                    struct link_stats *stats = ifa->ifa_data;
                    struct sockaddr_ll *addr = (struct sockaddr_ll*)ifa->ifa_addr;
                    snprintf(MAC, MAC_LENGTH, "%02X:%02X:%02X:%02X:%02X:%02X", addr->sll_addr[0], addr->sll_addr[1], addr->sll_addr[2], addr->sll_addr[3], addr->sll_addr[4], addr->sll_addr[5]);
                    cJSON_AddStringToObject(interface, "MAC", MAC);
                    cJSON_AddNumberToObject(interface, "tx_packets", stats->tx_packets);
                    cJSON_AddNumberToObject(interface, "rx_packets", stats->rx_packets);
                    cJSON_AddNumberToObject(interface, "tx_bytes", stats->tx_bytes);
                    cJSON_AddNumberToObject(interface, "rx_bytes", stats->rx_bytes);
                    cJSON_AddNumberToObject(interface, "tx_errors", stats->tx_errors);
                    cJSON_AddNumberToObject(interface, "rx_errors", stats->rx_errors);
                    cJSON_AddNumberToObject(interface, "tx_dropped", stats->tx_dropped);
                    cJSON_AddNumberToObject(interface, "rx_dropped", stats->rx_dropped);

                    /* MTU */
                    char *mtu;
                    int mtu_value;
                    mtu = get_mtu(ifaces_list[i]);
                    mtu_value = atoi(mtu);
                    cJSON_AddNumberToObject(interface, "MTU", mtu_value);
                    free(mtu);
                }
            }
        }

        /* Add address information to the structure */

        if (cJSON_GetArraySize(ipv4_addr) > 0) {
            cJSON_AddItemToObject(ipv4, "address", ipv4_addr);
            if (cJSON_GetArraySize(ipv4_netmask) > 0) {
                cJSON_AddItemToObject(ipv4, "netmask", ipv4_netmask);
            } else {
                cJSON_Delete(ipv4_netmask);
            }
            if (cJSON_GetArraySize(ipv4_broadcast) > 0) {
                cJSON_AddItemToObject(ipv4, "broadcast", ipv4_broadcast);
            } else {
                cJSON_Delete(ipv4_broadcast);
            }

            /* Get Default Gateway */
            char *gateway;
            gateway = get_default_gateway(ifaces_list[i]);
            cJSON_AddStringToObject(ipv4, "gateway", gateway);
            free(gateway);

            /* Get DHCP status for IPv4 */
            char *dhcp_v4;
            dhcp_v4 = check_dhcp(ifaces_list[i], AF_INET);
            cJSON_AddStringToObject(ipv4, "DHCP", dhcp_v4);
            free(dhcp_v4);

            cJSON_AddItemToObject(interface, "IPv4", ipv4);

        } else {
            cJSON_Delete(ipv4_addr);
            cJSON_Delete(ipv4_netmask);
            cJSON_Delete(ipv4_broadcast);
            cJSON_Delete(ipv4);
        }

        if (cJSON_GetArraySize(ipv6_addr) > 0) {
            cJSON_AddItemToObject(ipv6, "address", ipv6_addr);
            if (cJSON_GetArraySize(ipv6_netmask) > 0) {
                cJSON_AddItemToObject(ipv6, "netmask", ipv6_netmask);
            } else {
                cJSON_Delete(ipv6_netmask);
            }
            if (cJSON_GetArraySize(ipv6_broadcast) > 0) {
                cJSON_AddItemToObject(ipv6, "broadcast", ipv6_broadcast);
            } else {
                cJSON_Delete(ipv6_broadcast);
            }

            /* Get DHCP status for IPv6 */
            char *dhcp_v6;
            dhcp_v6 = check_dhcp(ifaces_list[i], AF_INET6);
            cJSON_AddStringToObject(ipv6, "DHCP", dhcp_v6);
            free(dhcp_v6);

            cJSON_AddItemToObject(interface, "IPv6", ipv6);
        } else {
            cJSON_Delete(ipv6_addr);
            cJSON_Delete(ipv6_netmask);
            cJSON_Delete(ipv6_broadcast);
            cJSON_Delete(ipv6);
        }

        /* Send interface data in JSON format */
        string = cJSON_PrintUnformatted(object);
        mtdebug2(WM_SYS_LOGTAG, "sys_network_linux() sending '%s'", string);
        wm_sendmsg(usec, queue_fd, string, LOCATION, SYSCOLLECTOR_MQ);
        cJSON_Delete(object);

        free(string);
    }

    freeifaddrs(ifaddr);
    for (i=0; ifaces_list[i]; i++){
        free(ifaces_list[i]);
    }
    free(ifaces_list);

    cJSON *object = cJSON_CreateObject();
    cJSON_AddStringToObject(object, "type", "network_end");
    cJSON_AddNumberToObject(object, "ID", random_id);
    cJSON_AddStringToObject(object, "timestamp", timestamp);

    char *string;
    string = cJSON_PrintUnformatted(object);
    mtdebug2(WM_SYS_LOGTAG, "sys_network_linux() sending '%s'", string);
    wm_sendmsg(usec, queue_fd, string, LOCATION, SYSCOLLECTOR_MQ);
    cJSON_Delete(object);
    free(string);
    free(timestamp);
}

/* Get System information */
hw_info *get_system_linux(){

    FILE *fp;
    hw_info *info;
    char string[OS_MAXSTR];

    char *end;

    os_calloc(1, sizeof(hw_info), info);

    if (!(fp = fopen("/proc/cpuinfo", "r"))) {
        mterror(WM_SYS_LOGTAG, "Unable to read cpuinfo file.");
        info->cpu_name = strdup("unknown");
    } else {
        char *aux_string = NULL;
        while (fgets(string, OS_MAXSTR, fp) != NULL){
            if ((aux_string = strstr(string, "model name")) != NULL){

                char *cpuname;
                cpuname = strtok(string, ":");
                cpuname = strtok(NULL, "\n");
                if (cpuname[0] == '\"' && (end = strchr(++cpuname, '\"'), end)) {
                    *end = '\0';
                }

                free(info->cpu_name);
                info->cpu_name = strdup(cpuname);
            } else if ((aux_string = strstr(string, "cpu MHz")) != NULL){

                char *frec;
                frec = strtok(string, ":");
                frec = strtok(NULL, "\n");
                if (frec[0] == '\"' && (end = strchr(++frec, '\"'), end)) {
                    *end = '\0';
                }
                info->cpu_MHz = atof(frec);
            }
        }
        free(aux_string);
        fclose(fp);
    }

    info->cpu_cores = get_nproc();

    if (!(fp = fopen("/proc/meminfo", "r"))) {
        mterror(WM_SYS_LOGTAG, "Unable to read meminfo file.");
    } else {
        char *aux_string = NULL;
        while (fgets(string, OS_MAXSTR, fp) != NULL){
            if ((aux_string = strstr(string, "MemTotal")) != NULL){

                char *end_string;
                aux_string = strtok(string, ":");
                aux_string = strtok(NULL, "\n");
                if (aux_string[0] == '\"' && (end = strchr(++aux_string, '\"'), end)) {
                    *end = '\0';
                }
                info->ram_total = strtol(aux_string, &end_string, 10);

            } else if ((aux_string = strstr(string, "MemFree")) != NULL){

                char *end_string;
                aux_string = strtok(string, ":");
                aux_string = strtok(NULL, "\n");
                if (aux_string[0] == '\"' && (end = strchr(++aux_string, '\"'), end)) {
                    *end = '\0';
                }
                info->ram_free = strtol(aux_string, &end_string, 10);

            }
        }

        if (info->ram_total > 0) {
            info->ram_usage = 100 - (info->ram_free * 100 / info->ram_total);
        }
        free(aux_string);
        fclose(fp);
    }

    return info;
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

char* get_default_gateway(char *ifa_name){

    FILE *fp;
    char file_location[PATH_LENGTH];
    char interface[IFNAME_LENGTH] = "";
    char if_name[IFNAME_LENGTH] = "";
    char string[OS_MAXSTR];
    struct in_addr address;
    int destination, gateway;
    char * def_gateway;
    os_calloc(NI_MAXHOST, sizeof(char) + 1, def_gateway);

    strncpy(interface, ifa_name, sizeof(interface) - 1);
    snprintf(file_location, PATH_LENGTH, "%s%s", WM_SYS_NET_DIR, "route");
    snprintf(def_gateway, NI_MAXHOST, "%s", "unknown");

    if ((fp = fopen(file_location, "r"))){

        while (fgets(string, OS_MAXSTR, fp) != NULL){

            if (sscanf(string, "%s %8x %8x", if_name, &destination, &gateway) == 3){
                if (destination == 00000000 && !strcmp(if_name, interface)){
                    address.s_addr = gateway;
                    snprintf(def_gateway, NI_MAXHOST, "%s", inet_ntoa(*(struct in_addr *) &address));
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

    char *timestamp;
    time_t now;
    struct tm localtm;
    int random_id = os_random();

    if (random_id < 0)
        random_id = -random_id;

    // Define time to sleep between messages sent
    int usec = 1000000 / wm_max_eps;

    now = time(NULL);
    localtime_r(&now, &localtm);

    os_calloc(TIME_LENGTH, sizeof(char), timestamp);

    snprintf(timestamp,TIME_LENGTH-1,"%d/%02d/%02d %02d:%02d:%02d",
            localtm.tm_year + 1900, localtm.tm_mon + 1,
            localtm.tm_mday, localtm.tm_hour, localtm.tm_min, localtm.tm_sec);

    PROCTAB* proc = openproc(PROC_FILLMEM | PROC_FILLSTAT | PROC_FILLSTATUS | PROC_FILLARG | PROC_FILLGRP | PROC_FILLUSR | PROC_FILLCOM | PROC_FILLENV);

    proc_t * proc_info;
    char *string;

    if (!proc) {
        mterror(WM_SYS_LOGTAG, "Running process inventory: could not create libproc context.");
        free(timestamp);
        return;
    }

    int i = 0;
    cJSON *item;
    cJSON *proc_array = cJSON_CreateArray();

    mtdebug1(WM_SYS_LOGTAG, "Starting running processes inventory.");

    while (proc_info = readproc(proc, NULL), proc_info != NULL) {
        cJSON *object = cJSON_CreateObject();
        cJSON *process = cJSON_CreateObject();
        cJSON_AddStringToObject(object, "type", "process");
        cJSON_AddNumberToObject(object, "ID", random_id);
        cJSON_AddStringToObject(object, "timestamp", timestamp);
        cJSON_AddItemToObject(object, "process", process);
        cJSON_AddNumberToObject(process,"pid",proc_info->tid);
        cJSON_AddStringToObject(process,"name",proc_info->cmd);
        cJSON_AddStringToObject(process,"state",&proc_info->state);
        cJSON_AddNumberToObject(process,"ppid",proc_info->ppid);
        cJSON_AddNumberToObject(process,"utime",proc_info->utime);
        cJSON_AddNumberToObject(process,"stime",proc_info->stime);
        if (proc_info->cmdline && proc_info->cmdline[0]) {
            cJSON *argvs = cJSON_CreateArray();
            cJSON_AddStringToObject(process, "cmd", proc_info->cmdline[0]);
            for (i = 1; proc_info->cmdline[i]; i++) {
                if (!strlen(proc_info->cmdline[i])==0) {
                    cJSON_AddItemToArray(argvs, cJSON_CreateString(proc_info->cmdline[i]));
                }
            }
            if (cJSON_GetArraySize(argvs) > 0) {
                cJSON_AddItemToObject(process, "argvs", argvs);
            } else {
                cJSON_Delete(argvs);
            }
        }
        cJSON_AddStringToObject(process,"euser",proc_info->euser);
        cJSON_AddStringToObject(process,"ruser",proc_info->ruser);
        cJSON_AddStringToObject(process,"suser",proc_info->suser);
        cJSON_AddStringToObject(process,"egroup",proc_info->egroup);
        cJSON_AddStringToObject(process,"rgroup",proc_info->rgroup);
        cJSON_AddStringToObject(process,"sgroup",proc_info->sgroup);
        cJSON_AddStringToObject(process,"fgroup",proc_info->fgroup);
        cJSON_AddNumberToObject(process,"priority",proc_info->priority);
        cJSON_AddNumberToObject(process,"nice",proc_info->nice);
        cJSON_AddNumberToObject(process,"size",proc_info->size);
        cJSON_AddNumberToObject(process,"vm_size",proc_info->vm_size);
        cJSON_AddNumberToObject(process,"resident",proc_info->resident);
        cJSON_AddNumberToObject(process,"share",proc_info->share);
        cJSON_AddNumberToObject(process,"start_time",proc_info->start_time);
        cJSON_AddNumberToObject(process,"pgrp",proc_info->pgrp);
        cJSON_AddNumberToObject(process,"session",proc_info->session);
        cJSON_AddNumberToObject(process,"nlwp",proc_info->nlwp);
        cJSON_AddNumberToObject(process,"tgid",proc_info->tgid);
        cJSON_AddNumberToObject(process,"tty",proc_info->tty);
        cJSON_AddNumberToObject(process,"processor",proc_info->processor);

        cJSON_AddItemToArray(proc_array, object);
        freeproc(proc_info);
    }

    cJSON_ArrayForEach(item, proc_array) {
        string = cJSON_PrintUnformatted(item);
        mtdebug2(WM_SYS_LOGTAG, "sys_proc_linux() sending '%s'", string);
        wm_sendmsg(usec, queue_fd, string, LOCATION, SYSCOLLECTOR_MQ);
        free(string);
    }

    cJSON_Delete(proc_array);
    closeproc(proc);

    cJSON *object = cJSON_CreateObject();
    cJSON_AddStringToObject(object, "type", "process_end");
    cJSON_AddNumberToObject(object, "ID", random_id);
    cJSON_AddStringToObject(object, "timestamp", timestamp);

    char *end_msg;
    end_msg = cJSON_PrintUnformatted(object);
    mtdebug2(WM_SYS_LOGTAG, "sys_proc_linux() sending '%s'", end_msg);
    wm_sendmsg(usec, queue_fd, end_msg, LOCATION, SYSCOLLECTOR_MQ);
    cJSON_Delete(object);
    free(end_msg);
    free(timestamp);

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

#endif /* __linux__ */
