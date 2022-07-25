/*
* Copyright (C) 2015, Wazuh Inc.
* August 30, 2017.
*
* This program is free software; you can redistribute it
* and/or modify it under the terms of the GNU General Public
* License (version 2) as published by the FSF - Free Software
* Foundation.
*/

/* Syscollector decoder */

#include "config.h"
#include "eventinfo.h"
#include "alerts/alerts.h"
#include "decoder.h"
#include "external/cJSON/cJSON.h"
#include "plugin_decoders.h"
#include "os_net/os_net.h"
#include "string_op.h"
#include "buffer_op.h"
#include <time.h>
#include "wazuhdb_op.h"
#include "wazuh_db/wdb.h"

static int error_package = 0;
static int prev_package_id = 0;
static int error_port = 0;
static int prev_port_id = 0;
static int error_process = 0;
static int prev_process_id = 0;

static int decode_netinfo( Eventinfo *lf, cJSON * logJSON, int *socket);
static int decode_osinfo( Eventinfo *lf, cJSON * logJSON, int *socket);
static int decode_hardware( Eventinfo *lf, cJSON * logJSON, int *socket);
static int decode_package( Eventinfo *lf, cJSON * logJSON, int *socket);
static int decode_hotfix(Eventinfo *lf, cJSON * logJSON, int *socket);
static int decode_port( Eventinfo *lf, cJSON * logJSON, int *socket);
static int decode_process( Eventinfo *lf, cJSON * logJSON, int *socket);
static int decode_dbsync( Eventinfo *lf, char *msg_type, cJSON * logJSON, int *socket);

static OSDecoderInfo *sysc_decoder = NULL;


//
// The following deltas_fields_match_list structs (key-value) represent a 1:1 matching between upcoming agent syscollector
// data fields and their corresponding table.
// This will be use to generate the needed events once the EventInfo struct is filled.
// Note: the fields which have "" in the value mean that no event will be generated for that specific field.
//

static struct deltas_fields_match_list const HOTFIXES_FIELDS[] = {
    { .current = { "scan_time", "" }, .next = &HOTFIXES_FIELDS[1]},
    { .current = { "hotfix", "hotfix" }, .next = &HOTFIXES_FIELDS[2]},
    { .current = { "checksum", "" }, .next = NULL},
};

static struct deltas_fields_match_list const PACKAGES_FIELDS[] = {
    { .current = { "scan_time", "" }, .next = &PACKAGES_FIELDS[1]},
    { .current = { "format", "program.format" }, .next = &PACKAGES_FIELDS[2]},
    { .current = { "name", "program.name" }, .next = &PACKAGES_FIELDS[3]},
    { .current = { "priority", "program.priority" }, .next = &PACKAGES_FIELDS[4]},
    { .current = { "groups", "" }, .next = &PACKAGES_FIELDS[5]},
    { .current = { "size", "program.size" }, .next = &PACKAGES_FIELDS[6]},
    { .current = { "vendor", "program.vendor" }, .next = &PACKAGES_FIELDS[7]},
    { .current = { "install_time", "program.install_time" }, .next = &PACKAGES_FIELDS[8]},
    { .current = { "version", "program.version" }, .next = &PACKAGES_FIELDS[9]},
    { .current = { "architecture", "program.architecture" }, .next = &PACKAGES_FIELDS[10]},
    { .current = { "multiarch", "program.multiarch" }, .next = &PACKAGES_FIELDS[11]},
    { .current = { "source", "program.source" }, .next = &PACKAGES_FIELDS[12]},
    { .current = { "description", "program.description" }, .next = &PACKAGES_FIELDS[13]},
    { .current = { "location", "program.location" }, .next = &PACKAGES_FIELDS[14]},
    { .current = { "triaged", "" }, .next = &PACKAGES_FIELDS[15]},
    { .current = { "cpe", "" }, .next = &PACKAGES_FIELDS[16]},
    { .current = { "msu_name", "" }, .next = &PACKAGES_FIELDS[17]},
    { .current = { "checksum", "" }, .next = &PACKAGES_FIELDS[18]},
    { .current = { "item_id", "" }, .next = NULL},
};

static struct deltas_fields_match_list const PROCESSES_FIELDS[] = {
    { .current = { "scan_time", "" }, .next = &PROCESSES_FIELDS[1]},
    { .current = { "pid", "process.pid" }, .next = &PROCESSES_FIELDS[2]},
    { .current = { "name", "process.name" }, .next = &PROCESSES_FIELDS[3]},
    { .current = { "state", "process.state" }, .next = &PROCESSES_FIELDS[4]},
    { .current = { "ppid", "process.ppid" }, .next = &PROCESSES_FIELDS[5]},
    { .current = { "utime", "process.utime" }, .next = &PROCESSES_FIELDS[6]},
    { .current = { "stime", "process.stime" }, .next = &PROCESSES_FIELDS[7]},
    { .current = { "cmd", "process.cmd" }, .next = &PROCESSES_FIELDS[8]},
    { .current = { "argvs", "process.args" }, .next = &PROCESSES_FIELDS[9]},
    { .current = { "euser", "process.euser" }, .next = &PROCESSES_FIELDS[10]},
    { .current = { "ruser", "process.ruser" }, .next = &PROCESSES_FIELDS[11]},
    { .current = { "suser", "process.suser" }, .next = &PROCESSES_FIELDS[12]},
    { .current = { "egroup", "process.egroup" }, .next = &PROCESSES_FIELDS[13]},
    { .current = { "rgroup", "process.rgroup" }, .next = &PROCESSES_FIELDS[14]},
    { .current = { "sgroup", "process.sgroup" }, .next = &PROCESSES_FIELDS[15]},
    { .current = { "fgroup", "process.fgroup" }, .next = &PROCESSES_FIELDS[16]},
    { .current = { "priority", "process.priority" }, .next = &PROCESSES_FIELDS[17]},
    { .current = { "nice", "process.nice" }, .next = &PROCESSES_FIELDS[18]},
    { .current = { "size", "process.size" }, .next = &PROCESSES_FIELDS[19]},
    { .current = { "vm_size", "process.vm_size" }, .next = &PROCESSES_FIELDS[20]},
    { .current = { "resident", "process.resident" }, .next = &PROCESSES_FIELDS[21]},
    { .current = { "share", "process.share" }, .next = &PROCESSES_FIELDS[22]},
    { .current = { "start_time", "process.start_time" }, .next = &PROCESSES_FIELDS[23]},
    { .current = { "pgrp", "process.pgrp" }, .next = &PROCESSES_FIELDS[24]},
    { .current = { "session", "process.session" }, .next = &PROCESSES_FIELDS[25]},
    { .current = { "nlwp", "process.nlwp" }, .next = &PROCESSES_FIELDS[26]},
    { .current = { "tgid", "process.tgid" }, .next = &PROCESSES_FIELDS[27]},
    { .current = { "tty", "process.tty" }, .next = &PROCESSES_FIELDS[28]},
    { .current = { "processor", "process.processor" }, .next = &PROCESSES_FIELDS[29]},
    { .current = { "checksum", "" }, .next = NULL},
};

static struct deltas_fields_match_list const PORTS_FIELDS[] = {
    { .current = { "scan_time", "" }, .next = &PORTS_FIELDS[1]},
    { .current = { "protocol", "port.protocol" }, .next = &PORTS_FIELDS[2]},
    { .current = { "local_ip", "port.local_ip" }, .next = &PORTS_FIELDS[3]},
    { .current = { "local_port", "port.local_port" }, .next = &PORTS_FIELDS[4]},
    { .current = { "remote_ip", "port.remote_ip" }, .next = &PORTS_FIELDS[5]},
    { .current = { "remote_port", "port.remote_port" }, .next = &PORTS_FIELDS[6]},
    { .current = { "tx_queue", "port.tx_queue" }, .next = &PORTS_FIELDS[7]},
    { .current = { "rx_queue", "port.rx_queue" }, .next = &PORTS_FIELDS[8]},
    { .current = { "inode", "port.inode" }, .next = &PORTS_FIELDS[9]},
    { .current = { "state", "port.state" }, .next = &PORTS_FIELDS[10]},
    { .current = { "pid", "port.pid" }, .next = &PORTS_FIELDS[11]},
    { .current = { "process", "port.process" }, .next = &PORTS_FIELDS[12]},
    { .current = { "checksum", "" }, .next = &PORTS_FIELDS[13]},
    { .current = { "item_id", "" }, .next = NULL},
};

static struct deltas_fields_match_list const NETWORK_IFACE_FIELDS[] = {
    { .current = { "scan_time", "" }, .next = &NETWORK_IFACE_FIELDS[1]},
    { .current = { "name", "netinfo.iface.name" }, .next = &NETWORK_IFACE_FIELDS[2]},
    { .current = { "adapter", "netinfo.iface.adapter" }, .next = &NETWORK_IFACE_FIELDS[3]},
    { .current = { "type", "netinfo.iface.type" }, .next = &NETWORK_IFACE_FIELDS[4]},
    { .current = { "state", "netinfo.iface.state" }, .next = &NETWORK_IFACE_FIELDS[5]},
    { .current = { "mtu", "netinfo.iface.mtu" }, .next = &NETWORK_IFACE_FIELDS[6]},
    { .current = { "mac", "netinfo.iface.mac" }, .next = &NETWORK_IFACE_FIELDS[7]},
    { .current = { "tx_packets", "netinfo.iface.tx_packets" }, .next = &NETWORK_IFACE_FIELDS[8]},
    { .current = { "rx_packets", "netinfo.iface.rx_packets" }, .next = &NETWORK_IFACE_FIELDS[9]},
    { .current = { "tx_bytes", "netinfo.iface.tx_bytes" }, .next = &NETWORK_IFACE_FIELDS[10]},
    { .current = { "rx_bytes", "netinfo.iface.rx_bytes" }, .next = &NETWORK_IFACE_FIELDS[11]},
    { .current = { "tx_errors", "netinfo.iface.tx_errors" }, .next = &NETWORK_IFACE_FIELDS[12]},
    { .current = { "rx_errors", "netinfo.iface.rx_errors" }, .next = &NETWORK_IFACE_FIELDS[13]},
    { .current = { "tx_dropped", "netinfo.iface.tx_dropped" }, .next = &NETWORK_IFACE_FIELDS[14]},
    { .current = { "rx_dropped", "netinfo.iface.rx_dropped" }, .next = &NETWORK_IFACE_FIELDS[15]},
    { .current = { "checksum", "" }, .next = &NETWORK_IFACE_FIELDS[16]},
    { .current = { "item_id", "" }, .next = NULL},
};

static struct deltas_fields_match_list const NETWORK_PROTOCOL_FIELDS[] = {
    { .current = { "iface", "netinfo.proto.iface" }, .next = &NETWORK_PROTOCOL_FIELDS[1]},
    { .current = { "type", "netinfo.proto.type" }, .next = &NETWORK_PROTOCOL_FIELDS[2]},
    { .current = { "gateway", "netinfo.proto.gateway" }, .next = &NETWORK_PROTOCOL_FIELDS[3]},
    { .current = { "dhcp", "netinfo.proto.dhcp" }, .next = &NETWORK_PROTOCOL_FIELDS[4]},
    { .current = { "metric", "netinfo.proto.metric" }, .next = &NETWORK_PROTOCOL_FIELDS[5]},
    { .current = { "checksum", "" }, .next = &NETWORK_PROTOCOL_FIELDS[6]},
    { .current = { "item_id", "" }, .next = NULL},
};

static struct deltas_fields_match_list const NETWORK_ADDRESS_FIELDS[] = {
    { .current = { "iface", "netinfo.addr.iface" }, .next = &NETWORK_ADDRESS_FIELDS[1]},
    { .current = { "proto", "netinfo.addr.proto" }, .next = &NETWORK_ADDRESS_FIELDS[2]},
    { .current = { "address", "netinfo.addr.address" }, .next = &NETWORK_ADDRESS_FIELDS[3]},
    { .current = { "netmask", "netinfo.addr.netmask" }, .next = &NETWORK_ADDRESS_FIELDS[4]},
    { .current = { "broadcast", "netinfo.addr.broadcast" }, .next = &NETWORK_ADDRESS_FIELDS[5]},
    { .current = { "checksum", "" }, .next = &NETWORK_ADDRESS_FIELDS[6]},
    { .current = { "item_id", "" }, .next = NULL},
};

static struct deltas_fields_match_list const HARDWARE_FIELDS[] = {
    { .current = { "scan_time", "" }, .next = &HARDWARE_FIELDS[1]},
    { .current = { "board_serial", "hardware.serial" }, .next = &HARDWARE_FIELDS[2]},
    { .current = { "cpu_name", "hardware.cpu_name" }, .next = &HARDWARE_FIELDS[3]},
    { .current = { "cpu_cores", "hardware.cpu_cores" }, .next = &HARDWARE_FIELDS[4]},
    { .current = { "cpu_mhz", "hardware.cpu_mhz" }, .next = &HARDWARE_FIELDS[5]},
    { .current = { "ram_total", "hardware.ram_total" }, .next = &HARDWARE_FIELDS[6]},
    { .current = { "ram_free", "hardware.ram_free" }, .next = &HARDWARE_FIELDS[7]},
    { .current = { "ram_usage", "hardware.ram_usage" }, .next = &HARDWARE_FIELDS[8]},
    { .current = { "checksum", "" }, .next = NULL},
};

static struct deltas_fields_match_list const OS_FIELDS[] = {
    { .current = { "scan_time", "" }, .next = &OS_FIELDS[1]},
    { .current = { "hostname", "os.hostname" }, .next = &OS_FIELDS[2]},
    { .current = { "architecture", "os.architecture" }, .next = &OS_FIELDS[3]},
    { .current = { "os_name", "os.name" }, .next = &OS_FIELDS[4]},
    { .current = { "os_version", "os.version" }, .next = &OS_FIELDS[5]},
    { .current = { "os_codename", "os.codename" }, .next = &OS_FIELDS[6]},
    { .current = { "os_major", "os.major" }, .next = &OS_FIELDS[7]},
    { .current = { "os_minor", "os.minor" }, .next = &OS_FIELDS[8]},
    { .current = { "os_patch", "os.patch" }, .next = &OS_FIELDS[9]},
    { .current = { "os_build", "os.build" }, .next = &OS_FIELDS[10]},
    { .current = { "os_platform", "os.platform" }, .next = &OS_FIELDS[11]},
    { .current = { "sysname", "os.sysname" }, .next = &OS_FIELDS[12]},
    { .current = { "release", "os.release" }, .next = &OS_FIELDS[13]},
    { .current = { "version", "os.version" }, .next = &OS_FIELDS[14]},
    { .current = { "os_release", "os.os_release" }, .next = &OS_FIELDS[15]},
    { .current = { "checksum", "" }, .next = &OS_FIELDS[16]},
    { .current = { "os_display_version", "os.display_version" }, .next = &OS_FIELDS[17]},
    { .current = { "triaged", "" }, .next = &OS_FIELDS[18]},
    { .current = { "reference", "" }, .next = NULL},
};

void SyscollectorInit(){

    os_calloc(1, sizeof(OSDecoderInfo), sysc_decoder);
    sysc_decoder->id = getDecoderfromlist(SYSCOLLECTOR_MOD, &os_analysisd_decoder_store);
    sysc_decoder->name = SYSCOLLECTOR_MOD;
    sysc_decoder->type = OSSEC_RL;
    sysc_decoder->fts = 0;

    mdebug1("SyscollectorInit completed.");
}

/* Special decoder for syscollector */
int DecodeSyscollector(Eventinfo *lf,int *socket)
{
    cJSON *logJSON;
    cJSON *json_type;
    char *msg_type = NULL;

    lf->decoder_info = sysc_decoder;

    // Check location
    if (lf->location[0] == '(') {
        char* search;
        search = strchr(lf->location, '>');
        if (!search) {
            mdebug1("Invalid received event.");
            return (0);
        }
        else if (strcmp(search + 1, "syscollector") != 0) {
            mdebug1("Invalid received event. Not syscollector.");
            return (0);
        }
    } else if (strcmp(lf->location, "syscollector") != 0) {
        mdebug1("Invalid received event. (Location)");
        return (0);
    }

    // Parsing event.

    const char *jsonErrPtr;
    logJSON = cJSON_ParseWithOpts(lf->log, &jsonErrPtr, 0);
    if (!logJSON) {
        mdebug1("Error parsing JSON event.");
        mdebug2("Input JSON: '%s", lf->log);
        return (0);
    }

    // Detect message type
    json_type = cJSON_GetObjectItem(logJSON, "type");
    if (!(json_type && (msg_type = json_type->valuestring))) {
        mdebug1("Invalid message. Type not found.");
        cJSON_Delete (logJSON);
        return (0);
    }

    fillData(lf,"type",msg_type);
    if (strcmp(msg_type, "port") == 0 || strcmp(msg_type, "port_end") == 0) {
        if (decode_port(lf, logJSON,socket) < 0) {
            mdebug1("Unable to send ports information to Wazuh DB.");
            cJSON_Delete (logJSON);
            return (0);
        }
    }
    else if (strcmp(msg_type, "program") == 0 || strcmp(msg_type, "program_end") == 0) {
        if (decode_package(lf, logJSON,socket) < 0) {
            mdebug1("Unable to send packages information to Wazuh DB.");
            cJSON_Delete (logJSON);
            return (0);
        }
    }
    else if (strcmp(msg_type, "hotfix") == 0 || strcmp(msg_type, "hotfix_end") == 0) {
        if (decode_hotfix(lf, logJSON, socket) < 0) {
            mdebug1("Unable to send hotfixes information to Wazuh DB.");
            cJSON_Delete (logJSON);
            return (0);
        }
    }
    else if (strcmp(msg_type, "hardware") == 0) {
        if (decode_hardware(lf, logJSON,socket) < 0) {
            mdebug1("Unable to send hardware information to Wazuh DB.");
            cJSON_Delete (logJSON);
            return (0);
        }
    }
    else if (strcmp(msg_type, "OS") == 0) {
        if (decode_osinfo(lf, logJSON,socket) < 0) {
            mdebug1("Unable to send osinfo message to Wazuh DB.");
            cJSON_Delete (logJSON);
            return (0);
        }
    }
    else if (strcmp(msg_type, "network") == 0 || strcmp(msg_type, "network_end") == 0) {
        if (decode_netinfo(lf, logJSON, socket) < 0) {
            merror("Unable to send netinfo message to Wazuh DB.");
            cJSON_Delete (logJSON);
            return (0);
        }
    }
    else if (strcmp(msg_type, "process") == 0 || strcmp(msg_type, "process_end") == 0) {
        if (decode_process(lf, logJSON,socket) < 0) {
            mdebug1("Unable to send processes information to Wazuh DB.");
            cJSON_Delete (logJSON);
            return (0);
        }
    }
    else if (strncmp(msg_type, "dbsync_", 7) == 0) {
        if (decode_dbsync(lf, msg_type, logJSON, socket) < 0) {
            mdebug1(UNABLE_TO_SEND_INFORMATION_TO_WDB);
            cJSON_Delete (logJSON);
            return (0);
        }
    }
    else {
        mdebug1("Invalid message type: %s.", msg_type);
        cJSON_Delete (logJSON);
        return (0);
    }

    cJSON_Delete (logJSON);
    return (1);
}

int decode_netinfo(Eventinfo *lf, cJSON * logJSON, int *socket) {

    char *msg;
    char *response;
    cJSON * iface;
    char id[OS_SIZE_1024];
    int i;
    int retval = -1;

    os_calloc(OS_SIZE_6144, sizeof(char), msg);
    os_calloc(OS_SIZE_6144, sizeof(char), response);

    if (iface = cJSON_GetObjectItem(logJSON, "iface"), iface) {
        cJSON * scan_id = cJSON_GetObjectItem(logJSON, "ID");
        cJSON * scan_time = cJSON_GetObjectItem(logJSON, "timestamp");
        cJSON * name = cJSON_GetObjectItem(iface, "name");
        cJSON * adapter = cJSON_GetObjectItem(iface, "adapter");
        cJSON * type = cJSON_GetObjectItem(iface, "type");
        cJSON * state = cJSON_GetObjectItem(iface, "state");
        cJSON * mac = cJSON_GetObjectItem(iface, "MAC");
        cJSON * tx_packets = cJSON_GetObjectItem(iface, "tx_packets");
        cJSON * rx_packets = cJSON_GetObjectItem(iface, "rx_packets");
        cJSON * tx_bytes = cJSON_GetObjectItem(iface, "tx_bytes");
        cJSON * rx_bytes = cJSON_GetObjectItem(iface, "rx_bytes");
        cJSON * tx_errors = cJSON_GetObjectItem(iface, "tx_errors");
        cJSON * rx_errors = cJSON_GetObjectItem(iface, "rx_errors");
        cJSON * tx_dropped = cJSON_GetObjectItem(iface, "tx_dropped");
        cJSON * rx_dropped = cJSON_GetObjectItem(iface, "rx_dropped");
        cJSON * mtu = cJSON_GetObjectItem(iface, "MTU");

        snprintf(msg, OS_SIZE_6144 - 1, "agent %s netinfo save", lf->agent_id);

        if (scan_id) {
            snprintf(id, OS_SIZE_1024 - 1, "%d", scan_id->valueint);
            wm_strcat(&msg, id, ' ');
        } else {
            wm_strcat(&msg, "NULL", ' ');
        }

        if (scan_time) {
            wm_strcat(&msg, scan_time->valuestring, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (name) {
            wm_strcat(&msg, name->valuestring, '|');
            fillData(lf,"netinfo.iface.name",name->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (adapter) {
            wm_strcat(&msg, adapter->valuestring, '|');
            fillData(lf,"netinfo.iface.adapter",adapter->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (type) {
            wm_strcat(&msg, type->valuestring, '|');
            fillData(lf,"netinfo.iface.type",type->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (state) {
            wm_strcat(&msg, state->valuestring, '|');
            fillData(lf,"netinfo.iface.state",state->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (mtu) {
            char _mtu[OS_SIZE_128];
            snprintf(_mtu, OS_SIZE_128 - 1, "%d", mtu->valueint);
            fillData(lf,"netinfo.iface.mtu",_mtu);
            wm_strcat(&msg, _mtu, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (mac) {
            wm_strcat(&msg, mac->valuestring, '|');
            fillData(lf,"netinfo.iface.mac",mac->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (tx_packets) {
            char txpack[OS_SIZE_512];
            snprintf(txpack, OS_SIZE_512 - 1, "%d", tx_packets->valueint);
            fillData(lf,"netinfo.iface.tx_packets",txpack);
            wm_strcat(&msg, txpack, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (rx_packets) {
            char rxpack[OS_SIZE_512];
            snprintf(rxpack, OS_SIZE_512 - 1, "%d", rx_packets->valueint);
            fillData(lf,"netinfo.iface.rx_packets",rxpack);
            wm_strcat(&msg, rxpack, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (tx_bytes) {
            char txbytes[OS_SIZE_512];
            snprintf(txbytes, OS_SIZE_512 - 1, "%d", tx_bytes->valueint);
            fillData(lf,"netinfo.iface.tx_bytes",txbytes);
            wm_strcat(&msg, txbytes, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (rx_bytes) {
            char rxbytes[OS_SIZE_512];
            snprintf(rxbytes, OS_SIZE_512 - 1, "%d", rx_bytes->valueint);
            fillData(lf,"netinfo.iface.rx_bytes",rxbytes);
            wm_strcat(&msg, rxbytes, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (tx_errors) {
            char txerrors[OS_SIZE_512];
            snprintf(txerrors, OS_SIZE_512 - 1, "%d", tx_errors->valueint);
            fillData(lf,"netinfo.iface.tx_errors",txerrors);
            wm_strcat(&msg, txerrors, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (rx_errors) {
            char rxerrors[OS_SIZE_512];
            snprintf(rxerrors, OS_SIZE_512 - 1, "%d", rx_errors->valueint);
            fillData(lf,"netinfo.iface.rx_errors",rxerrors);
            wm_strcat(&msg, rxerrors, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (tx_dropped) {
            char txdropped[OS_SIZE_512];
            snprintf(txdropped, OS_SIZE_512 - 1, "%d", tx_dropped->valueint);
            fillData(lf,"netinfo.iface.tx_dropped",txdropped);
            wm_strcat(&msg, txdropped, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (rx_dropped) {
            char rxdropped[OS_SIZE_512];
            snprintf(rxdropped, OS_SIZE_512 - 1, "%d", rx_dropped->valueint);
            fillData(lf,"netinfo.iface.rx_dropped",rxdropped);
            wm_strcat(&msg, rxdropped, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        char *message;
        if (wdbc_query_ex(socket, msg, response, OS_SIZE_6144) == 0) {
            if (wdbc_parse_result(response, &message) == WDBC_OK) {
                cJSON * ip;

                if (ip = cJSON_GetObjectItem(iface, "IPv4"), ip) {

                    cJSON * address = cJSON_GetObjectItem(ip, "address");
                    cJSON * netmask = cJSON_GetObjectItem(ip, "netmask");
                    cJSON * broadcast = cJSON_GetObjectItem(ip, "broadcast");
                    cJSON * gateway = cJSON_GetObjectItem(ip, "gateway");
                    cJSON * dhcp = cJSON_GetObjectItem(ip, "dhcp");
                    cJSON * metric = cJSON_GetObjectItem(ip, "metric");

                    snprintf(msg, OS_SIZE_6144 - 1, "agent %s netproto save", lf->agent_id);

                    if (scan_id) {
                        wm_strcat(&msg, id, ' ');
                    } else {
                        wm_strcat(&msg, "NULL", ' ');
                    }

                    if (name) {
                        wm_strcat(&msg, name->valuestring, '|');
                    } else {
                        wm_strcat(&msg, "NULL", '|');
                    }

                    // Information about an IPv4 interface
                    wm_strcat(&msg, "0", '|');

                    if (gateway) {
                        wm_strcat(&msg, gateway->valuestring, '|');
                        fillData(lf,"netinfo.iface.ipv4.gateway",gateway->valuestring);
                    } else {
                        wm_strcat(&msg, "NULL", '|');
                    }

                    if (dhcp) {
                        wm_strcat(&msg, dhcp->valuestring, '|');
                        fillData(lf,"netinfo.iface.ipv4.dhcp",dhcp->valuestring);
                    } else {
                        wm_strcat(&msg, "NULL", '|');
                    }

                    if (metric) {
                        char _metric[OS_SIZE_128];
                        snprintf(_metric, OS_SIZE_128 - 1, "%d", metric->valueint);
                        fillData(lf,"netinfo.iface.ipv4.metric", _metric);
                        wm_strcat(&msg, _metric, '|');
                    } else {
                        wm_strcat(&msg, "NULL", '|');
                    }

                    char *message;
                    if (wdbc_query_ex(socket, msg, response, OS_SIZE_6144) == 0) {
                        if (wdbc_parse_result(response, &message) != WDBC_OK) {
                            goto end;
                        }
                    } else {
                        goto end;
                    }

                    // Save addresses information into 'sys_netaddr' table

                    if (address) {
                        char *ip4_address = NULL;
                        char *ip4_netmask = NULL;
                        char *ip4_broadcast = NULL;
                        for (i = 0; i < cJSON_GetArraySize(address); i++) {

                            snprintf(msg, OS_SIZE_6144 - 1, "agent %s netaddr save", lf->agent_id);

                            if (scan_id) {
                                wm_strcat(&msg, id, ' ');
                            } else {
                                wm_strcat(&msg, "NULL", ' ');
                            }

                            if (name) {
                                wm_strcat(&msg, name->valuestring, '|');
                            } else {
                                wm_strcat(&msg, "NULL", '|');
                            }

                            // Information about an IPv4 address
                            wm_strcat(&msg, "0", '|');

                            wm_strcat(&msg, cJSON_GetArrayItem(address,i)->valuestring, '|');
                            if(i == 0){
                                os_strdup(cJSON_GetArrayItem(address,i)->valuestring, ip4_address);
                            } else {
                                wm_strcat(&ip4_address, cJSON_GetArrayItem(address,i)->valuestring, ',');
                            }

                            if (cJSON_GetArrayItem(netmask,i) != NULL) {
                                wm_strcat(&msg, cJSON_GetArrayItem(netmask,i)->valuestring, '|');
                                if(i == 0){
                                    os_strdup(cJSON_GetArrayItem(netmask,i)->valuestring, ip4_netmask);
                                } else {
                                    wm_strcat(&ip4_netmask, cJSON_GetArrayItem(netmask,i)->valuestring, ',');
                                }
                            } else {
                                wm_strcat(&msg, "NULL", '|');
                            }

                            if (cJSON_GetArrayItem(broadcast,i) != NULL) {
                                wm_strcat(&msg, cJSON_GetArrayItem(broadcast,i)->valuestring, '|');
                                if(i == 0){
                                    os_strdup(cJSON_GetArrayItem(broadcast,i)->valuestring, ip4_broadcast);
                                } else {
                                    wm_strcat(&ip4_broadcast, cJSON_GetArrayItem(broadcast,i)->valuestring, ',');
                                }
                            } else {
                                wm_strcat(&msg, "NULL", '|');
                            }

                            char *message;
                            if (wdbc_query_ex(socket, msg, response, OS_SIZE_6144) == 0) {
                                if (wdbc_parse_result(response, &message) != WDBC_OK) {
                                    if (ip4_address) {
                                        free(ip4_address);
                                    }
                                    if(ip4_netmask) {
                                        free(ip4_netmask);
                                    }
                                    if(ip4_broadcast) {
                                        free(ip4_broadcast);
                                    }
                                    goto end;
                                }
                            } else {
                                if (ip4_address) {
                                    free(ip4_address);
                                }
                                if(ip4_netmask) {
                                    free(ip4_netmask);
                                }
                                if(ip4_broadcast) {
                                    free(ip4_broadcast);
                                }
                                goto end;
                            }
                        }

                        char *array_buffer = NULL;
                        if (ip4_address) {
                            csv_list_to_json_str_array(ip4_address, &array_buffer);
                            fillData(lf,"netinfo.iface.ipv4.address", array_buffer);
                            os_free(array_buffer);
                            free(ip4_address);
                        }
                        if(ip4_netmask) {
                            csv_list_to_json_str_array(ip4_netmask, &array_buffer);
                            fillData(lf,"netinfo.iface.ipv4.netmask", array_buffer);
                            os_free(array_buffer);
                            free(ip4_netmask);
                        }
                        if(ip4_broadcast) {
                            csv_list_to_json_str_array(ip4_broadcast, &array_buffer);
                            fillData(lf,"netinfo.iface.ipv4.broadcast", array_buffer);
                            os_free(array_buffer);
                            free(ip4_broadcast);
                        }
                    }
                }

                if (ip = cJSON_GetObjectItem(iface, "IPv6"), ip) {
                    cJSON * address = cJSON_GetObjectItem(ip, "address");
                    cJSON * netmask = cJSON_GetObjectItem(ip, "netmask");
                    cJSON * broadcast = cJSON_GetObjectItem(ip, "broadcast");
                    cJSON * metric = cJSON_GetObjectItem(ip, "metric");
                    cJSON * gateway = cJSON_GetObjectItem(ip, "gateway");
                    cJSON * dhcp = cJSON_GetObjectItem(ip, "dhcp");

                    snprintf(msg, OS_SIZE_6144 - 1, "agent %s netproto save", lf->agent_id);

                    if (scan_id) {
                        wm_strcat(&msg, id, ' ');
                    } else {
                        wm_strcat(&msg, "NULL", ' ');
                    }

                    if (name) {
                        wm_strcat(&msg, name->valuestring, '|');
                    } else {
                        wm_strcat(&msg, "NULL", '|');
                    }

                    // Information about an IPv6 interface
                    wm_strcat(&msg, "1", '|');

                    if (gateway) {
                        wm_strcat(&msg, gateway->valuestring, '|');
                        fillData(lf, "netinfo.iface.ipv6.gateway",gateway->valuestring);
                    } else {
                        wm_strcat(&msg, "NULL", '|');
                    }

                    if (dhcp) {
                        wm_strcat(&msg, dhcp->valuestring, '|');
                        fillData(lf, "netinfo.iface.ipv6.dhcp",dhcp->valuestring);
                    } else {
                        wm_strcat(&msg, "NULL", '|');
                    }

                    if (metric) {
                        char _metric[OS_SIZE_128];
                        snprintf(_metric, OS_SIZE_128 - 1, "%d", metric->valueint);
                        fillData(lf,"netinfo.iface.ipv6.metric",_metric);
                        wm_strcat(&msg, _metric, '|');
                    } else {
                        wm_strcat(&msg, "NULL", '|');
                    }

                    char *message;
                    if (wdbc_query_ex(socket, msg, response, OS_SIZE_6144) == 0) {
                        if (wdbc_parse_result(response, &message) != WDBC_OK) {
                            goto end;
                        }
                    } else {
                        goto end;
                    }

                    if (address) {
                        char *ip6_address = NULL;
                        char *ip6_netmask = NULL;
                        char *ip6_broadcast = NULL;
                        for (i = 0; i < cJSON_GetArraySize(address); i++) {

                            snprintf(msg, OS_SIZE_6144 - 1, "agent %s netaddr save", lf->agent_id);

                            if (scan_id) {
                                wm_strcat(&msg, id, ' ');
                            } else {
                                wm_strcat(&msg, "NULL", ' ');
                            }

                            if (name) {
                                wm_strcat(&msg, name->valuestring, '|');
                            } else {
                                wm_strcat(&msg, "NULL", '|');
                            }

                            // Information about an IPv6 address
                            wm_strcat(&msg, "1", '|');

                            wm_strcat(&msg, cJSON_GetArrayItem(address,i)->valuestring, '|');
                            if(i == 0){
                                os_strdup(cJSON_GetArrayItem(address,i)->valuestring,ip6_address);
                            } else {
                                wm_strcat(&ip6_address, cJSON_GetArrayItem(address,i)->valuestring, ',');
                            }

                            if (cJSON_GetArrayItem(netmask,i) != NULL) {
                                wm_strcat(&msg, cJSON_GetArrayItem(netmask,i)->valuestring, '|');
                                if(i == 0){
                                    os_strdup(cJSON_GetArrayItem(netmask,i)->valuestring,ip6_netmask);
                                } else {
                                    wm_strcat(&ip6_netmask, cJSON_GetArrayItem(netmask,i)->valuestring, ',');
                                }
                            } else {
                                wm_strcat(&msg, "NULL", '|');
                            }

                            if (cJSON_GetArrayItem(broadcast,i) != NULL) {
                                wm_strcat(&msg, cJSON_GetArrayItem(broadcast,i)->valuestring, '|');
                                if(i == 0){
                                    os_strdup(cJSON_GetArrayItem(broadcast,i)->valuestring, ip6_broadcast);
                                } else {
                                    wm_strcat(&ip6_broadcast, cJSON_GetArrayItem(broadcast,i)->valuestring, ',');
                                }
                            } else {
                                wm_strcat(&msg, "NULL", '|');
                            }

                            char *message;
                            if (wdbc_query_ex(socket, msg, response, OS_SIZE_6144) == 0) {
                                if (wdbc_parse_result(response, &message) != WDBC_OK) {
                                    if (ip6_address) {
                                        free(ip6_address);
                                    }
                                    if(ip6_netmask) {
                                        free(ip6_netmask);
                                    }
                                    if(ip6_broadcast) {
                                        free(ip6_broadcast);
                                    }
                                    goto end;
                                }
                            } else {
                                if (ip6_address) {
                                    free(ip6_address);
                                }
                                if(ip6_netmask) {
                                    free(ip6_netmask);
                                }
                                if(ip6_broadcast) {
                                    free(ip6_broadcast);
                                }
                                goto end;
                            }
                        }

                        char *array_buffer = NULL;
                        if (ip6_address) {
                            csv_list_to_json_str_array(ip6_address, &array_buffer);
                            fillData(lf,"netinfo.iface.ipv6.address", array_buffer);
                            os_free(array_buffer);
                            free(ip6_address);
                        }
                        if(ip6_netmask) {
                            csv_list_to_json_str_array(ip6_netmask, &array_buffer);
                            fillData(lf,"netinfo.iface.ipv6.netmask", array_buffer);
                            os_free(array_buffer);
                            free(ip6_netmask);
                        }
                        if(ip6_broadcast) {
                            csv_list_to_json_str_array(ip6_broadcast, &array_buffer);
                            fillData(lf,"netinfo.iface.ipv6.broadcast", array_buffer);
                            os_free(array_buffer);
                            free(ip6_broadcast);
                        }
                    }
                }
            } else {
                goto end;
            }
        } else {
            goto end;
        }
    } else {
        // Looking for 'end' message.
        char * msg_type = NULL;

        msg_type = cJSON_GetObjectItem(logJSON, "type")->valuestring;

        if (!msg_type) {
            merror("Invalid message. Type not found.");
            goto end;
        } else if (strcmp(msg_type, "network_end") == 0) {

            cJSON * scan_id = cJSON_GetObjectItem(logJSON, "ID");
            snprintf(msg, OS_SIZE_6144 - 1, "agent %s netinfo del %d", lf->agent_id, scan_id->valueint);

            char *message;
            if (wdbc_query_ex(socket, msg, response, OS_SIZE_6144) == 0) {
                if (wdbc_parse_result(response, &message) != WDBC_OK) {
                    goto end;
                }
            } else {
                goto end;
            }
        } else {
            merror("at decode_netinfo(): unknown type found.");
            goto end;
        }
    }

    retval = 0;
end:
    free(response);
    free(msg);
    return retval;
}

int decode_osinfo( Eventinfo *lf, cJSON * logJSON,int *socket) {
    cJSON * inventory;
    char *msg = NULL;
    char *response = NULL;
    int retval = -1;

    if (inventory = cJSON_GetObjectItem(logJSON, "inventory"), inventory) {
        cJSON * scan_id = cJSON_GetObjectItem(logJSON, "ID");
        cJSON * scan_time = cJSON_GetObjectItem(logJSON, "timestamp");
        cJSON * os_name = cJSON_GetObjectItem(inventory, "os_name");
        cJSON * os_version = cJSON_GetObjectItem(inventory, "os_version");
        cJSON * os_codename = cJSON_GetObjectItem(inventory, "os_codename");
        cJSON * hostname = cJSON_GetObjectItem(inventory, "hostname");
        cJSON * architecture = cJSON_GetObjectItem(inventory, "architecture");
        cJSON * os_major = cJSON_GetObjectItem(inventory, "os_major");
        cJSON * os_minor = cJSON_GetObjectItem(inventory, "os_minor");
        cJSON * os_build = cJSON_GetObjectItem(inventory, "os_build");
        cJSON * os_platform = cJSON_GetObjectItem(inventory, "os_platform");
        cJSON * sysname = cJSON_GetObjectItem(inventory, "sysname");
        cJSON * release = cJSON_GetObjectItem(inventory, "release");
        cJSON * version = cJSON_GetObjectItem(inventory, "version");
        cJSON * os_release = cJSON_GetObjectItem(inventory, "os_release");
        cJSON * os_patch = cJSON_GetObjectItem(inventory, "os_patch");
        cJSON * os_display_version = cJSON_GetObjectItem(inventory, "os_display_version");

        os_calloc(OS_SIZE_6144, sizeof(char), msg);

        snprintf(msg, OS_SIZE_6144 - 1, "agent %s osinfo set", lf->agent_id);

        if (scan_id) {
            char id[OS_SIZE_1024];
            snprintf(id, OS_SIZE_1024 - 1, "%d", scan_id->valueint);
            wm_strcat(&msg, id, ' ');
        } else {
            wm_strcat(&msg, "NULL", ' ');
        }

        if (scan_time) {
            wm_strcat(&msg, scan_time->valuestring, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (hostname) {
            wm_strcat(&msg, hostname->valuestring, '|');
            fillData(lf,"os.hostname",hostname->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (architecture) {
            wm_strcat(&msg, architecture->valuestring, '|');
            fillData(lf,"os.architecture",architecture->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (os_name) {
            wm_strcat(&msg, os_name->valuestring, '|');
            fillData(lf,"os.name",os_name->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (os_version) {
            wm_strcat(&msg, os_version->valuestring, '|');
            fillData(lf,"os.version",os_version->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (os_codename) {
            wm_strcat(&msg, os_codename->valuestring, '|');
            fillData(lf,"os.codename",os_codename->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (os_major) {
            wm_strcat(&msg, os_major->valuestring, '|');
            fillData(lf,"os.major",os_major->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (os_minor) {
            wm_strcat(&msg, os_minor->valuestring, '|');
            fillData(lf,"os.minor",os_minor->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (os_build) {
            wm_strcat(&msg, os_build->valuestring, '|');
            fillData(lf,"os.build",os_build->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (os_platform) {
            wm_strcat(&msg, os_platform->valuestring, '|');
            fillData(lf,"os.platform",os_platform->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (sysname) {
            wm_strcat(&msg, sysname->valuestring, '|');
            fillData(lf,"os.sysname",sysname->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (release) {
            wm_strcat(&msg, release->valuestring, '|');
            fillData(lf,"os.release",release->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (version) {
            wm_strcat(&msg, version->valuestring, '|');
            fillData(lf,"os.release_version",version->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (os_release) {
            wm_strcat(&msg, os_release->valuestring, '|');
            fillData(lf,"os.os_release",os_release->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (os_patch) {
            wm_strcat(&msg, os_patch->valuestring, '|');
            fillData(lf,"os.patch",os_patch->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (os_display_version) {
            wm_strcat(&msg, os_display_version->valuestring, '|');
            fillData(lf,"os.display_version",os_display_version->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        char *message;
        os_calloc(OS_SIZE_6144, sizeof(char), response);
        if (wdbc_query_ex(socket, msg, response, OS_SIZE_6144) == 0) {
            if (wdbc_parse_result(response, &message) != WDBC_OK) {
                goto end;
            }
        } else {
            goto end;
        }
    }

    retval = 0;
end:
    free(response);
    free(msg);
    return retval;
}

int decode_port( Eventinfo *lf, cJSON * logJSON,int *socket) {

    char * msg = NULL;
    char * response = NULL;
    int retval = -1;
    cJSON * scan_id;

    if (scan_id = cJSON_GetObjectItem(logJSON, "ID"), !scan_id) {
        return -1;
    }

    os_calloc(OS_SIZE_6144, sizeof(char), msg);
    os_calloc(OS_SIZE_6144, sizeof(char), response);

    cJSON * inventory;

    if (inventory = cJSON_GetObjectItem(logJSON, "port"), inventory) {
        if (error_port) {
            if (scan_id->valueint == prev_port_id) {
                retval = 0;
                goto end;
            } else {
                error_port = 0;
            }
        }
        cJSON * scan_time = cJSON_GetObjectItem(logJSON, "timestamp");
        cJSON * protocol = cJSON_GetObjectItem(inventory, "protocol");
        cJSON * local_ip = cJSON_GetObjectItem(inventory, "local_ip");
        cJSON * local_port = cJSON_GetObjectItem(inventory, "local_port");
        cJSON * remote_ip = cJSON_GetObjectItem(inventory, "remote_ip");
        cJSON * remote_port = cJSON_GetObjectItem(inventory, "remote_port");
        cJSON * tx_queue = cJSON_GetObjectItem(inventory, "tx_queue");
        cJSON * rx_queue = cJSON_GetObjectItem(inventory, "rx_queue");
        cJSON * inode = cJSON_GetObjectItem(inventory, "inode");
        cJSON * state = cJSON_GetObjectItem(inventory, "state");
        cJSON * pid = cJSON_GetObjectItem(inventory, "PID");
        cJSON * process = cJSON_GetObjectItem(inventory, "process");

        snprintf(msg, OS_SIZE_6144 - 1, "agent %s port save", lf->agent_id);

        char id[OS_SIZE_1024];
        snprintf(id, OS_SIZE_1024 - 1, "%d", scan_id->valueint);
        wm_strcat(&msg, id, ' ');

        if (scan_time) {
            wm_strcat(&msg, scan_time->valuestring, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (protocol) {
            wm_strcat(&msg, protocol->valuestring, '|');
            fillData(lf,"port.protocol",protocol->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (local_ip) {
            wm_strcat(&msg, local_ip->valuestring, '|');
            fillData(lf,"port.local_ip",local_ip->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (local_port) {
            char lport[OS_SIZE_128];
            snprintf(lport, OS_SIZE_128 - 1, "%d", local_port->valueint);
            fillData(lf,"port.local_port",lport);
            wm_strcat(&msg, lport, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (remote_ip) {
            wm_strcat(&msg, remote_ip->valuestring, '|');
            fillData(lf,"port.remote_ip",remote_ip->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (remote_port) {
            char rport[OS_SIZE_128];
            snprintf(rport, OS_SIZE_128 - 1, "%d", remote_port->valueint);
            fillData(lf,"port.remote_port",rport);
            wm_strcat(&msg, rport, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (tx_queue) {
            char txq[OS_SIZE_512];
            snprintf(txq, OS_SIZE_512 - 1, "%d", tx_queue->valueint);
            fillData(lf,"port.tx_queue",txq);
            wm_strcat(&msg, txq, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (rx_queue) {
            char rxq[OS_SIZE_512];
            snprintf(rxq, OS_SIZE_512 - 1, "%d", rx_queue->valueint);
            fillData(lf,"port.rx_queue",rxq);
            wm_strcat(&msg, rxq, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (inode) {
            char _inode[OS_SIZE_512];
            snprintf(_inode, OS_SIZE_512 - 1, "%d", inode->valueint);
            fillData(lf,"port.inode",_inode);
            wm_strcat(&msg, _inode, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (state) {
            wm_strcat(&msg, state->valuestring, '|');
            fillData(lf,"port.state",state->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (pid) {
            char _pid[OS_SIZE_512];
            snprintf(_pid, OS_SIZE_512 - 1, "%d", pid->valueint);
            fillData(lf,"port.pid",_pid);
            wm_strcat(&msg, _pid, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (process) {
            wm_strcat(&msg, process->valuestring, '|');
            fillData(lf,"port.process",process->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        char *message;
        if (wdbc_query_ex(socket, msg, response, OS_SIZE_6144) == 0) {
            if (wdbc_parse_result(response, &message) != WDBC_OK) {
                error_port = 1;
                prev_port_id = scan_id->valueint;
                goto end;
            }
        } else {
            error_port = 1;
            prev_port_id = scan_id->valueint;
            goto end;
        }
    } else {
        // Looking for 'end' message.
        char * msg_type = NULL;

        msg_type = cJSON_GetObjectItem(logJSON, "type")->valuestring;

        if (!msg_type) {
            merror("Invalid message. Type not found.");
            goto end;
        } else if (strcmp(msg_type, "port_end") == 0) {
            if (error_port) {
                if (scan_id->valueint == prev_port_id) {
                    retval = 0;
                    goto end;
                } else {
                    error_port = 0;
                }
            }

            snprintf(msg, OS_SIZE_6144 - 1, "agent %s port del %d", lf->agent_id, scan_id->valueint);

            char *message;
            if (wdbc_query_ex(socket, msg, response, OS_SIZE_6144) == 0) {
                if (wdbc_parse_result(response, &message) != WDBC_OK) {
                    error_port = 1;
                    prev_port_id = scan_id->valueint;
                    goto end;
                }
            } else {
                error_port = 1;
                prev_port_id = scan_id->valueint;
                goto end;
            }
        }
    }

    retval = 0;
end:
    free(response);
    free(msg);
    return retval;
}

int decode_hardware( Eventinfo *lf, cJSON * logJSON,int *socket) {
    cJSON * inventory;
    int retval = -1;
    char *msg = NULL;
    char *response = NULL;

    if (inventory = cJSON_GetObjectItem(logJSON, "inventory"), inventory) {
        cJSON * scan_id = cJSON_GetObjectItem(logJSON, "ID");
        cJSON * scan_time = cJSON_GetObjectItem(logJSON, "timestamp");
        cJSON * serial = cJSON_GetObjectItem(inventory, "board_serial");
        cJSON * cpu_name = cJSON_GetObjectItem(inventory, "cpu_name");
        cJSON * cpu_cores = cJSON_GetObjectItem(inventory, "cpu_cores");
        cJSON * cpu_mhz = cJSON_GetObjectItem(inventory, "cpu_mhz");
        cJSON * ram_total = cJSON_GetObjectItem(inventory, "ram_total");
        cJSON * ram_free = cJSON_GetObjectItem(inventory, "ram_free");
        cJSON * ram_usage = cJSON_GetObjectItem(inventory, "ram_usage");

        os_calloc(OS_SIZE_6144, sizeof(char), msg);

        snprintf(msg, OS_SIZE_6144 - 1, "agent %s hardware save", lf->agent_id);

        if (scan_id) {
            char id[OS_SIZE_1024];
            snprintf(id, OS_SIZE_1024 - 1, "%d", scan_id->valueint);
            wm_strcat(&msg, id, ' ');
        } else {
            wm_strcat(&msg, "NULL", ' ');
        }

        if (scan_time) {
            wm_strcat(&msg, scan_time->valuestring, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (serial) {
            wm_strcat(&msg, serial->valuestring, '|');
            fillData(lf,"hardware.serial",serial->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (cpu_name) {
            wm_strcat(&msg, cpu_name->valuestring, '|');
            fillData(lf,"hardware.cpu_name",cpu_name->valuestring);

        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (cpu_cores) {
            char cores[OS_SIZE_128];
            snprintf(cores, OS_SIZE_128 - 1, "%d", cpu_cores->valueint);
            fillData(lf,"hardware.cpu_cores",cores);
            wm_strcat(&msg, cores, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (cpu_mhz) {
            char freq[OS_SIZE_512];
            snprintf(freq, OS_SIZE_512 - 1, "%f", cpu_mhz->valuedouble);
            fillData(lf,"hardware.cpu_mhz",freq);
            wm_strcat(&msg, freq, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (ram_total) {
            char total[OS_SIZE_512];
            snprintf(total, OS_SIZE_512 - 1, "%f", ram_total->valuedouble);
            fillData(lf,"hardware.ram_total",total);
            wm_strcat(&msg, total, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (ram_free) {
            char rfree[OS_SIZE_512];
            snprintf(rfree, OS_SIZE_512 - 1, "%f", ram_free->valuedouble);
            fillData(lf,"hardware.ram_free",rfree);
            wm_strcat(&msg, rfree, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (ram_usage) {
            char usage[OS_SIZE_128];
            snprintf(usage, OS_SIZE_128 - 1, "%d", ram_usage->valueint);
            fillData(lf,"hardware.ram_usage",usage);
            wm_strcat(&msg, usage, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        char *message;
        os_calloc(OS_SIZE_6144, sizeof(char), response);
        if (wdbc_query_ex(socket, msg, response, OS_SIZE_6144) == 0) {
            if (wdbc_parse_result(response, &message) != WDBC_OK) {
                goto end;
            }
        } else {
            goto end;
        }
    }

    retval = 0;
end:
    free(response);
    free(msg);
    return retval;
}

int decode_package( Eventinfo *lf,cJSON * logJSON,int *socket) {
    char * msg = NULL;
    char * response = NULL;
    cJSON * package;
    cJSON * scan_id;
    int retval = -1;

    if (scan_id = cJSON_GetObjectItem(logJSON, "ID"), !scan_id) {
        return -1;
    }

    os_calloc(OS_SIZE_6144, sizeof(char), msg);
    os_calloc(OS_SIZE_6144, sizeof(char), response);

    if (package = cJSON_GetObjectItem(logJSON, "program"), package) {
        if (error_package) {
            if (scan_id->valueint == prev_package_id) {
                retval = 0;
                goto end;
            } else {
                error_package = 0;
            }
        }

        cJSON * scan_time = cJSON_GetObjectItem(logJSON, "timestamp");
        cJSON * format = cJSON_GetObjectItem(package, "format");
        cJSON * name = cJSON_GetObjectItem(package, "name");
        cJSON * priority = cJSON_GetObjectItem(package, "priority");
        cJSON * section = cJSON_GetObjectItem(package, "group");
        cJSON * size = cJSON_GetObjectItem(package, "size");
        cJSON * vendor = cJSON_GetObjectItem(package, "vendor");
        cJSON * version = cJSON_GetObjectItem(package, "version");
        cJSON * architecture = cJSON_GetObjectItem(package, "architecture");
        cJSON * multiarch = cJSON_GetObjectItem(package, "multi-arch");
        cJSON * source = cJSON_GetObjectItem(package, "source");
        cJSON * description = cJSON_GetObjectItem(package, "description");
        cJSON * installtime = cJSON_GetObjectItem(package, "install_time");
        cJSON * location = cJSON_GetObjectItem(package, "location");

        snprintf(msg, OS_SIZE_6144 - 1, "agent %s package save", lf->agent_id);

        char id[OS_SIZE_1024];
        snprintf(id, OS_SIZE_1024 - 1, "%d", scan_id->valueint);
        wm_strcat(&msg, id, ' ');

        if (scan_time) {
            wm_strcat(&msg, scan_time->valuestring, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (format) {
            wm_strcat(&msg, format->valuestring, '|');
            fillData(lf,"program.format",format->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (name) {
            wm_strcat(&msg, name->valuestring, '|');
            fillData(lf,"program.name",name->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (priority) {
            wm_strcat(&msg, priority->valuestring, '|');
            fillData(lf,"program.priority",priority->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (section) {
            wm_strcat(&msg, section->valuestring, '|');
            fillData(lf,"program.section",section->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (size) {
            char _size[OS_SIZE_512];
            snprintf(_size, OS_SIZE_512 - 1, "%d", size->valueint);
            fillData(lf,"program.size",_size);
            wm_strcat(&msg, _size, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (vendor) {
            wm_strcat(&msg, vendor->valuestring, '|');
            fillData(lf,"program.vendor",vendor->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (installtime) {
            wm_strcat(&msg, installtime->valuestring, '|');
            fillData(lf,"program.install_time",installtime->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (version) {
            wm_strcat(&msg, version->valuestring, '|');
            fillData(lf,"program.version",version->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (architecture) {
            wm_strcat(&msg, architecture->valuestring, '|');
            fillData(lf,"program.architecture",architecture->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (multiarch) {
            wm_strcat(&msg, multiarch->valuestring, '|');
            fillData(lf,"program.multiarch",multiarch->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (source) {
            wm_strcat(&msg, source->valuestring, '|');
            fillData(lf,"program.source",source->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (description) {
            wm_strcat(&msg, description->valuestring, '|');
            fillData(lf,"program.description",description->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (location) {
            wm_strcat(&msg, location->valuestring, '|');
            fillData(lf,"program.location",location->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        // The reference for packages is calculated with the name, version and architecture
        os_sha1 hexdigest;
        wdbi_strings_hash(hexdigest,
                          name && name->valuestring ? name->valuestring : "",
                          version && version->valuestring ? version->valuestring : "",
                          architecture && architecture->valuestring ? architecture->valuestring : "",
                          NULL);

        wm_strcat(&msg, hexdigest, '|');

        char *message;
        if (wdbc_query_ex(socket, msg, response, OS_SIZE_6144) == 0) {
            if (wdbc_parse_result(response, &message) != WDBC_OK) {
                error_package = 1;
                prev_package_id = scan_id->valueint;
                goto end;
            }
        } else {
            error_package = 1;
            prev_package_id = scan_id->valueint;
            goto end;
        }
    } else {
        // Looking for 'end' message.
        char * msg_type = NULL;

        msg_type = cJSON_GetObjectItem(logJSON, "type")->valuestring;

        if (!msg_type) {
            merror("Invalid message. Type not found.");
            goto end;
        } else if (strcmp(msg_type, "program_end") == 0) {
            if (error_package) {
                if (scan_id->valueint == prev_package_id) {
                    retval = 0;
                    goto end;
                } else {
                    error_package = 0;
                }
            }

            snprintf(msg, OS_SIZE_6144 - 1, "agent %s package del %d", lf->agent_id, scan_id->valueint);

            char *message;
            if (wdbc_query_ex(socket, msg, response, OS_SIZE_6144) == 0) {
                if (wdbc_parse_result(response, &message) != WDBC_OK) {
                    error_package = 1;
                    prev_package_id = scan_id->valueint;
                    goto end;
                }
            } else {
                error_package = 1;
                prev_package_id = scan_id->valueint;
                goto end;
            }
        }
    }

    retval = 0;
end:
    free(response);
    free(msg);
    return retval;
}

int decode_hotfix(Eventinfo *lf, cJSON * logJSON, int *socket) {
    char * msg = NULL;
    cJSON * hotfix;
    cJSON * scan_id;
    cJSON * scan_time;
    char response[4096];

    if (scan_id = cJSON_GetObjectItem(logJSON, "ID"), !scan_id) {
        return -1;
    }

    os_calloc(OS_SIZE_1024, sizeof(char), msg);

    if (hotfix = cJSON_GetObjectItem(logJSON, "hotfix"), hotfix) {
        scan_time = cJSON_GetObjectItem(logJSON, "timestamp");

        snprintf(msg, OS_SIZE_1024, "agent %s hotfix save %d|%s|%s|",
                lf->agent_id,
                scan_id->valueint,
                scan_time->valuestring,
                hotfix->valuestring);

        fillData(lf, "hotfix", hotfix->valuestring);
        if (wdbc_query_ex(socket, msg, response, sizeof(response)) != 0 || wdbc_parse_result(response, NULL) != WDBC_OK) {
            free(msg);
            return -1;
        }
    } else {
        // Looking for 'end' message.
        char * msg_type = NULL;

        msg_type = cJSON_GetObjectItem(logJSON, "type")->valuestring;

        if (!msg_type) {
            merror("Invalid message. Type not found.");
            free(msg);
            return -1;
        } else if (strcmp(msg_type, "hotfix_end") == 0) {
            snprintf(msg, OS_SIZE_1024 - 1, "agent %s hotfix del %d", lf->agent_id, scan_id->valueint);

            if (wdbc_query_ex(socket, msg, response, sizeof(response)) != 0 || wdbc_parse_result(response, NULL) != WDBC_OK) {
                free(msg);
                return -1;
            }
        }
    }

    free(msg);

    return 0;
}

int decode_process(Eventinfo *lf, cJSON * logJSON,int *socket) {

    int i;
    char * msg = NULL;
    char * response = NULL;
    cJSON * scan_id;
    int retval = -1;

    if (scan_id = cJSON_GetObjectItem(logJSON, "ID"), !scan_id) {
        return -1;
    }

    os_calloc(OS_SIZE_6144, sizeof(char), msg);
    os_calloc(OS_SIZE_6144, sizeof(char), response);

    cJSON * inventory;

    if (inventory = cJSON_GetObjectItem(logJSON, "process"), inventory) {
        if (error_process) {
            if (scan_id->valueint == prev_process_id) {
                retval = 0;
                goto end;
            } else {
                error_process = 0;
            }
        }
        cJSON * scan_time = cJSON_GetObjectItem(logJSON, "timestamp");
        cJSON * pid = cJSON_GetObjectItem(inventory, "pid");
        cJSON * name = cJSON_GetObjectItem(inventory, "name");
        cJSON * state = cJSON_GetObjectItem(inventory, "state");
        cJSON * ppid = cJSON_GetObjectItem(inventory, "ppid");
        cJSON * utime = cJSON_GetObjectItem(inventory, "utime");
        cJSON * stime = cJSON_GetObjectItem(inventory, "stime");
        cJSON * cmd = cJSON_GetObjectItem(inventory, "cmd");
        cJSON * argvs = cJSON_GetObjectItem(inventory, "argvs");
        cJSON * euser = cJSON_GetObjectItem(inventory, "euser");
        cJSON * ruser = cJSON_GetObjectItem(inventory, "ruser");
        cJSON * suser = cJSON_GetObjectItem(inventory, "suser");
        cJSON * egroup = cJSON_GetObjectItem(inventory, "egroup");
        cJSON * rgroup = cJSON_GetObjectItem(inventory, "rgroup");
        cJSON * sgroup = cJSON_GetObjectItem(inventory, "sgroup");
        cJSON * fgroup = cJSON_GetObjectItem(inventory, "fgroup");
        cJSON * priority = cJSON_GetObjectItem(inventory, "priority");
        cJSON * nice = cJSON_GetObjectItem(inventory, "nice");
        cJSON * size = cJSON_GetObjectItem(inventory, "size");
        cJSON * vm_size = cJSON_GetObjectItem(inventory, "vm_size");
        cJSON * resident = cJSON_GetObjectItem(inventory, "resident");
        cJSON * share = cJSON_GetObjectItem(inventory, "share");
        cJSON * start_time = cJSON_GetObjectItem(inventory, "start_time");
        cJSON * pgrp = cJSON_GetObjectItem(inventory, "pgrp");
        cJSON * session = cJSON_GetObjectItem(inventory, "session");
        cJSON * nlwp = cJSON_GetObjectItem(inventory, "nlwp");
        cJSON * tgid = cJSON_GetObjectItem(inventory, "tgid");
        cJSON * tty = cJSON_GetObjectItem(inventory, "tty");
        cJSON * processor = cJSON_GetObjectItem(inventory, "processor");

        snprintf(msg, OS_SIZE_6144 - 1, "agent %s process save", lf->agent_id);

        char id[OS_SIZE_1024];
        snprintf(id, OS_SIZE_1024 - 1, "%d", scan_id->valueint);
        wm_strcat(&msg, id, ' ');

        if (scan_time) {
            wm_strcat(&msg, scan_time->valuestring, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (pid) {
            char _pid[OS_SIZE_128];
            snprintf(_pid, OS_SIZE_128 - 1, "%d", pid->valueint);
            fillData(lf,"process.pid",_pid);
            wm_strcat(&msg, _pid, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (name) {
            wm_strcat(&msg, name->valuestring, '|');
            fillData(lf,"process.name",name->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (state) {
            wm_strcat(&msg, state->valuestring, '|');
            fillData(lf,"process.state",state->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (ppid) {
            char _ppid[OS_SIZE_128];
            snprintf(_ppid, OS_SIZE_128 - 1, "%d", ppid->valueint);
            fillData(lf,"process.ppid",_ppid);
            wm_strcat(&msg, _ppid, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (utime) {
            char _utime[OS_SIZE_128];
            snprintf(_utime, OS_SIZE_128 - 1, "%d", utime->valueint);
            fillData(lf,"process.utime",_utime);
            wm_strcat(&msg, _utime, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (stime) {
            char _stime[OS_SIZE_128];
            snprintf(_stime, OS_SIZE_128 - 1, "%d", stime->valueint);
            fillData(lf,"process.stime",_stime);
            wm_strcat(&msg, _stime, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (cmd) {
            wm_strcat(&msg, cmd->valuestring, '|');
            fillData(lf,"process.cmd",cmd->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (argvs) {
            char * args = NULL;
            for (i = 0; i < cJSON_GetArraySize(argvs); i++){
                wm_strcat(&args, cJSON_GetArrayItem(argvs,i)->valuestring, ',');
            }
            char *array_buffer = cJSON_Print(argvs);
            fillData(lf, "process.args", array_buffer);
            os_free(array_buffer);
            wm_strcat(&msg, args, '|');
            free(args);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (euser) {
            wm_strcat(&msg, euser->valuestring, '|');
            fillData(lf,"process.euser",euser->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (ruser) {
            wm_strcat(&msg, ruser->valuestring, '|');
            fillData(lf,"process.ruser",ruser->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (suser) {
            wm_strcat(&msg, suser->valuestring, '|');
            fillData(lf,"process.suser",suser->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (egroup) {
            wm_strcat(&msg, egroup->valuestring, '|');
            fillData(lf,"process.egroup",egroup->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (rgroup) {
            wm_strcat(&msg, rgroup->valuestring, '|');
            fillData(lf,"process.rgroup",rgroup->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (sgroup) {
            wm_strcat(&msg, sgroup->valuestring, '|');
            fillData(lf,"process.sgroup",sgroup->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (fgroup) {
            wm_strcat(&msg, fgroup->valuestring, '|');
            fillData(lf,"process.fgroup",fgroup->valuestring);
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (priority) {
            char prior[OS_SIZE_128];
            snprintf(prior, OS_SIZE_128 - 1, "%d", priority->valueint);
            fillData(lf,"process.priority",prior);
            wm_strcat(&msg, prior, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (nice) {
            char _nice[OS_SIZE_128];
            snprintf(_nice, OS_SIZE_128 - 1, "%d", nice->valueint);
            fillData(lf,"process.nice",_nice);
            wm_strcat(&msg, _nice, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (size) {
            char _size[OS_SIZE_512];
            snprintf(_size, OS_SIZE_512 - 1, "%d", size->valueint);
            fillData(lf,"process.size",_size);
            wm_strcat(&msg, _size, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (vm_size) {
            char vms[OS_SIZE_512];
            snprintf(vms, OS_SIZE_512 - 1, "%d", vm_size->valueint);
            fillData(lf,"process.vm_size",vms);
            wm_strcat(&msg, vms, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (resident) {
            char _resident[OS_SIZE_512];
            snprintf(_resident, OS_SIZE_512 - 1, "%d", resident->valueint);
            fillData(lf,"process.resident",_resident);
            wm_strcat(&msg, _resident, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (share) {
            char _share[OS_SIZE_512];
            snprintf(_share, OS_SIZE_512 - 1, "%d", share->valueint);
            fillData(lf,"process.share",_share);
            wm_strcat(&msg, _share, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (start_time) {
            char start[OS_SIZE_512];
            snprintf(start, OS_SIZE_512 - 1, "%d", start_time->valueint);
            fillData(lf,"process.start_time",start);
            wm_strcat(&msg, start, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (pgrp) {
            char _pgrp[OS_SIZE_512];
            snprintf(_pgrp, OS_SIZE_512 - 1, "%d", pgrp->valueint);
            fillData(lf,"process.pgrp",_pgrp);
            wm_strcat(&msg, _pgrp, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (session) {
            char _session[OS_SIZE_512];
            snprintf(_session, OS_SIZE_512 - 1, "%d", session->valueint);
            fillData(lf,"process.session",_session);
            wm_strcat(&msg, _session, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (nlwp) {
            char _nlwp[OS_SIZE_512];
            snprintf(_nlwp, OS_SIZE_512 - 1, "%d", nlwp->valueint);
            fillData(lf,"process.nlwp",_nlwp);
            wm_strcat(&msg, _nlwp, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (tgid) {
            char _tgid[OS_SIZE_512];
            snprintf(_tgid, OS_SIZE_512 - 1, "%d", tgid->valueint);
            fillData(lf,"process.tgid",_tgid);
            wm_strcat(&msg, _tgid, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (tty) {
            char _tty[OS_SIZE_512];
            snprintf(_tty, OS_SIZE_512 - 1, "%d", tty->valueint);
            fillData(lf,"process.tty",_tty);
            wm_strcat(&msg, _tty, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (processor) {
            char proc[OS_SIZE_512];
            snprintf(proc, OS_SIZE_512 - 1, "%d", processor->valueint);
            fillData(lf,"process.processor",proc);
            wm_strcat(&msg, proc, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        char *message;
        if (wdbc_query_ex(socket, msg, response, OS_SIZE_6144) == 0) {
            if (wdbc_parse_result(response, &message) != WDBC_OK) {
                error_process = 1;
                prev_process_id = scan_id->valueint;
                goto end;
            }
        } else {
            error_process = 1;
            prev_process_id = scan_id->valueint;
            goto end;
        }
    } else {
        // Looking for 'end' message.
        char * msg_type = NULL;

        msg_type = cJSON_GetObjectItem(logJSON, "type")->valuestring;

        if (!msg_type) {
            merror("Invalid message. Type not found.");
            goto end;
        } else if (strcmp(msg_type, "process_end") == 0) {

            if (error_process) {
                if (scan_id->valueint == prev_process_id) {
                    retval = 0;
                    goto end;
                } else {
                    error_process = 0;
                }
            }

            snprintf(msg, OS_SIZE_6144 - 1, "agent %s process del %d", lf->agent_id, scan_id->valueint);

            char *message;
            if (wdbc_query_ex(socket, msg, response, OS_SIZE_6144) == 0) {
                if (wdbc_parse_result(response, &message) != WDBC_OK) {
                    error_process = 1;
                    prev_process_id = scan_id->valueint;
                    goto end;
                }
            } else {
                error_process = 1;
                prev_process_id = scan_id->valueint;
                goto end;
            }
        }
    }

    retval = 0;
end:
    free(response);
    free(msg);
    return retval;
}

static const struct deltas_fields_match_list * get_field_list(const char *type) {
    const struct deltas_fields_match_list * ret_val = NULL;
    // 'type' will not be NULL because this function is being called after checking the type value
    if (strcmp(type, "hotfixes") == 0) {
        ret_val = HOTFIXES_FIELDS;
    } else if(strcmp(type, "packages") == 0) {
        ret_val = PACKAGES_FIELDS;
    } else if(strcmp(type, "processes") == 0) {
        ret_val = PROCESSES_FIELDS;
    } else if(strcmp(type, "ports") == 0) {
        ret_val = PORTS_FIELDS;
    } else if(strcmp(type, "network_iface") == 0) {
        ret_val = NETWORK_IFACE_FIELDS;
    } else if(strcmp(type, "network_protocol") == 0) {
        ret_val = NETWORK_PROTOCOL_FIELDS;
    } else if(strcmp(type, "network_address") == 0) {
        ret_val = NETWORK_ADDRESS_FIELDS;
    } else if(strcmp(type, "hwinfo") == 0) {
        ret_val = HARDWARE_FIELDS;
    } else if(strcmp(type, "osinfo") == 0) {
        ret_val = OS_FIELDS;
    } else {
        merror(INVALID_TYPE, type);
    }
    return ret_val;
}

static void fill_data_dbsync(cJSON *data, const struct deltas_fields_match_list * field_list, buffer_t * const msg, bool force_dbsync_filling) {
    static const int NULL_TEXT_LENGTH = 4;
    static const int SEPARATOR_LENGTH = 1;
    struct deltas_fields_match_list const * head = field_list;

    while (NULL != head) {
        const cJSON *key = cJSON_GetObjectItem(data, head->current.key);
        if (NULL != key) {
            if (cJSON_IsNumber(key)) {
                char value[OS_SIZE_128] = { 0 };
                int value_size = 0;
                // Check if key was originally a double or integer value
                if ((double) key->valueint == key->valuedouble) {
                    value_size = os_snprintf(value, OS_SIZE_128 - 1, "%d", key->valueint);
                } else {
                    value_size = os_snprintf(value, OS_SIZE_128 - 1, "%lf", key->valuedouble);
                }
                buffer_push(msg, value, value_size);
            } else if (cJSON_IsString(key)) {
                if(strlen(key->valuestring) == 0) {
                    buffer_push(msg, "NULL", NULL_TEXT_LENGTH);
                } else {
                    char *value_string = wstr_replace(key->valuestring, FIELD_SEPARATOR_DBSYNC,
                                                      FIELD_SEPARATOR_DBSYNC_ESCAPE);
                    char *final_text_value = wstr_replace(value_string, "NULL", "_NULL_");
                    os_free(value_string);
                    buffer_push(msg, final_text_value, strlen(final_text_value));
                    os_free(final_text_value);
                }
            } else if (!cJSON_IsNull(key)) {
                buffer_push(msg, "NULL", NULL_TEXT_LENGTH);
            }
        } else if (force_dbsync_filling) {
            buffer_push(msg, "NULL", NULL_TEXT_LENGTH);
        }
        // Message separated by \0, includes the values to be processed in the wazuhdb
        // this must maintain order and must always be completed, and the values that
        // do not correspond will not be proccessed in wazuh-db
        buffer_push(msg, FIELD_SEPARATOR_DBSYNC, SEPARATOR_LENGTH);
        head = head->next;
    }
}

static void fill_event_alert(Eventinfo * lf, const struct deltas_fields_match_list * field_list, const char * operation,
                      char * response) {
    const bool have_a_escaped_pipe = strstr(response, FIELD_SEPARATOR_DBSYNC_ESCAPE);

    const size_t separator_count = os_strcnt(response, *FIELD_SEPARATOR_DBSYNC);
    const size_t field_values_size = sizeof(char *) * (separator_count > 0 ? separator_count : 1);

    char ** field_values = NULL;
    os_calloc(1, field_values_size + sizeof(char *), field_values);

    char ** field_values_iterator = field_values;

    // Create a copy of the string to make it null-separated and reference each part in field_value
    char * null_separated_str = NULL;
    os_strdup(response, null_separated_str);
    char * null_separated_str_iterator = null_separated_str;

    // In case the response does not have a separator
    *field_values = null_separated_str;
    char * separator_location = strchr(null_separated_str, *FIELD_SEPARATOR_DBSYNC);

    // Iterate through and point each chunk between separators
    while (NULL != separator_location) {
        *field_values_iterator = null_separated_str_iterator;
        *separator_location++ = '\0';

        null_separated_str_iterator = separator_location;
        separator_location = strchr(null_separated_str_iterator, *FIELD_SEPARATOR_DBSYNC);
        ++field_values_iterator;
    }

    field_values_iterator = field_values;
    struct deltas_fields_match_list const * head = field_list;
    while (NULL != head && NULL != *field_values_iterator) {
        if (strlen(head->current.value) != 0) {
            if (have_a_escaped_pipe) {
                char * value =
                    wstr_replace(*field_values_iterator, FIELD_SEPARATOR_DBSYNC_ESCAPE, FIELD_SEPARATOR_DBSYNC);
                fillData(lf, head->current.value, value);
                os_free(value);
            } else if (strcmp(*field_values_iterator, "NULL") != 0) {
                fillData(lf, head->current.value, *field_values_iterator);
            }
        }
        ++field_values_iterator;
        head = head->next;
    }
    fillData(lf, "operation_type", operation);

    os_free(field_values);
    os_free(null_separated_str);
}

static int decode_dbsync( Eventinfo * lf, char *msg_type, cJSON *logJSON, int *socket) {
    int ret_val = OS_INVALID;
    if (NULL != lf->agent_id) {
        char * type = NULL;
        strtok_r(msg_type, "_", &type);

        if (strlen(type) > 0) {
            cJSON * operation_object = cJSON_GetObjectItem(logJSON, "operation");
            cJSON * data = cJSON_GetObjectItem(logJSON, "data");
            if (cJSON_IsString(operation_object) && cJSON_IsObject(data)) {
                const struct deltas_fields_match_list * field_list = get_field_list(type);

                if (NULL != field_list) {
                    char *response = NULL;
                    os_calloc(OS_SIZE_6144, sizeof(char), response);
                    char header[OS_SIZE_256] = { 0 };
                    char * operation = cJSON_GetStringValue(operation_object);
                    int header_size = snprintf(header, OS_SIZE_256 - 1, "agent %s dbsync %s %s ", lf->agent_id, type, operation);

                    buffer_t *msg = buffer_initialize(OS_SIZE_6144);
                    buffer_push(msg, header, header_size);

                    const bool is_inserted_operation = strcmp(operation, "INSERTED") == 0;
                    fill_data_dbsync(data, field_list, msg, !is_inserted_operation);

                    if (msg->status) {
                        ret_val = wdbc_query_ex(socket, msg->data, response, OS_SIZE_6144);
                        if (ret_val != 0 || strncmp(response, "err", 3) == 0) {
                            mdebug1(A_QUERY_ERROR);
                        } else {
                            if (is_inserted_operation) {
                                fill_event_alert(lf, field_list, operation, msg->data + header_size);
                            } else {
                                char *response_data = NULL;
                                strtok_r(response, " ", &response_data);
                                if (strlen(response_data) > 0) {
                                    fill_event_alert(lf, field_list, operation, response_data);
                                } else {
                                    merror(INVALID_RESPONSE);
                                }
                            }
                        }
                    } else {
                        mdebug2(MESSAGE_TOO_LONG);
                    }

                    buffer_free(msg);
                    os_free(response);
                }
            } else {
                merror(INVALID_OPERATION, type);
            }
        } else {
            merror(INVALID_PREFIX, msg_type);
        }
    }
    return ret_val;
}
