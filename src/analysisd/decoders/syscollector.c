/*
* Copyright (C) 2017 Wazuh Inc.
* August 30, 2017.
*
* This program is a free software; you can redistribute it
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
#include "wazuh_modules/wmodules.h"
#include "os_net/os_net.h"
#include <time.h>

#define SYSCOLLECTOR_DIR    "/queue/syscollector"

static int sc_send_db(char * msg);
static int decode_osinfo(char *agent_id, cJSON * logJSON);
static int decode_hardware(char *agent_id, cJSON * logJSON);
static int decode_program(char *agent_id, cJSON * logJSON);
static int decode_port(char *agent_id, cJSON * logJSON);
static int decode_process(char *agent_id, cJSON * logJSON);

/* Special decoder for syscollector */
int DecodeSyscollector(Eventinfo *lf)
{
    cJSON *logJSON;
    char *msg_type = NULL;

    // Decoding JSON
    JSON_Decoder_Exec(lf);

    // Check location
    if (lf->location[0] == '(') {
        char* search;
        search = strchr(lf->location, '>') + 1;
        if (!search) {
            mdebug1("Invalid received event.");
            return (0);
        }
        else if (strcmp(search, "syscollector") != 0) {
            mdebug1("Invalid received event. Not syscollector.");
            return (0);
        }
    } else if (strcmp(lf->location, "syscollector") != 0) {
        mdebug1("Invalid received event. (Location)");
        return (0);
    }

    // Parsing event.
    logJSON = cJSON_Parse(lf->log);
    if (!logJSON) {
        mdebug1("Error parsing JSON event. %s", cJSON_GetErrorPtr());
        return (0);
    }

    // Detect message type
    msg_type = cJSON_GetObjectItem(logJSON, "type")->valuestring;
    if (!msg_type) {
        mdebug1("Invalid message. Type not found.");
        return (0);
    }

    if (strcmp(msg_type, "port") == 0 || strcmp(msg_type, "port_end") == 0) {
        if (decode_port(lf->agent_id, logJSON) < 0) {
            mdebug1("Unable to send ports information to Wazuh DB.");
            return (0);
        }
    }
    else if (strcmp(msg_type, "program") == 0 || strcmp(msg_type, "program_end") == 0) {
        if (decode_program(lf->agent_id, logJSON) < 0) {
            mdebug1("Unable to send programs information to Wazuh DB.");
            return (0);
        }
    }
    else if (strcmp(msg_type, "hardware") == 0) {
        if (decode_hardware(lf->agent_id, logJSON) < 0) {
            mdebug1("Unable to send hardware information to Wazuh DB.");
            return (0);
        }
    }
    else if (strcmp(msg_type, "OS") == 0) {
        if (decode_osinfo(lf->agent_id, logJSON) < 0) {
            mdebug1("Unable to send osinfo message to Wazuh DB.");
            return (0);
        }
    }
    else if (strcmp(msg_type, "network") == 0 || strcmp(msg_type, "network_end") == 0) {
        return (1);
    }
    else if (strcmp(msg_type, "process") == 0 || strcmp(msg_type, "process_list") == 0  || strcmp(msg_type, "process_end") == 0) {
        if (decode_process(lf->agent_id, logJSON) < 0) {
            mdebug1("Unable to send processes information to Wazuh DB.");
            return (0);
        }
    }
    else {
        mdebug1("Invalid message type: %s.", msg_type);
        return (0);
    }

    cJSON_Delete (logJSON);
    return (1);
}

int decode_osinfo(char *agent_id, cJSON * logJSON) {

    char * msg = NULL;

    os_calloc(OS_MAXSTR, sizeof(char), msg);

    cJSON * inventory;

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

        snprintf(msg, OS_MAXSTR - 1, "agent %s osinfo save", agent_id);


        if (scan_id) {
            char id[OS_MAXSTR];
            snprintf(id, OS_MAXSTR - 1, "%d", scan_id->valueint);
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
        } else {
                wm_strcat(&msg, "NULL", '|');
        }

        if (architecture) {
            wm_strcat(&msg, architecture->valuestring, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (os_name) {
            wm_strcat(&msg, os_name->valuestring, '|');
        } else {
                wm_strcat(&msg, "NULL", '|');
        }

        if (os_version) {
            wm_strcat(&msg, os_version->valuestring, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (os_codename) {
            wm_strcat(&msg, os_codename->valuestring, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (os_major) {
            wm_strcat(&msg, os_major->valuestring, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (os_minor) {
            wm_strcat(&msg, os_minor->valuestring, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (os_build) {
            wm_strcat(&msg, os_build->valuestring, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (os_platform) {
            wm_strcat(&msg, os_platform->valuestring, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (sysname) {
            wm_strcat(&msg, sysname->valuestring, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (release) {
            wm_strcat(&msg, release->valuestring, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (version) {
            wm_strcat(&msg, version->valuestring, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (sc_send_db(msg) < 0) {
            return -1;
        }

    }

    return 0;
}

int decode_port(char *agent_id, cJSON * logJSON) {

    char * msg = NULL;

    os_calloc(OS_MAXSTR, sizeof(char), msg);

    cJSON * inventory;

    if (inventory = cJSON_GetObjectItem(logJSON, "port"), inventory) {
        cJSON * scan_id = cJSON_GetObjectItem(logJSON, "ID");
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

        snprintf(msg, OS_MAXSTR - 1, "agent %s port save", agent_id);

        if (scan_id) {
            char id[OS_MAXSTR];
            snprintf(id, OS_MAXSTR - 1, "%d", scan_id->valueint);
            wm_strcat(&msg, id, ' ');
        } else {
            wm_strcat(&msg, "NULL", ' ');
        }

        if (scan_time) {
            wm_strcat(&msg, scan_time->valuestring, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (protocol) {
            wm_strcat(&msg, protocol->valuestring, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (local_ip) {
            wm_strcat(&msg, local_ip->valuestring, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (local_port) {
            char lport[OS_MAXSTR];
            snprintf(lport, OS_MAXSTR - 1, "%d", local_port->valueint);
            wm_strcat(&msg, lport, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (remote_ip) {
            wm_strcat(&msg, remote_ip->valuestring, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (remote_port) {
            char rport[OS_MAXSTR];
            snprintf(rport, OS_MAXSTR - 1, "%d", remote_port->valueint);
            wm_strcat(&msg, rport, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (tx_queue) {
            char txq[OS_MAXSTR];
            snprintf(txq, OS_MAXSTR - 1, "%d", tx_queue->valueint);
            wm_strcat(&msg, txq, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (rx_queue) {
            char rxq[OS_MAXSTR];
            snprintf(rxq, OS_MAXSTR - 1, "%d", rx_queue->valueint);
            wm_strcat(&msg, rxq, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (inode) {
            char _inode[OS_MAXSTR];
            snprintf(_inode, OS_MAXSTR - 1, "%d", inode->valueint);
            wm_strcat(&msg, _inode, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (state) {
            wm_strcat(&msg, state->valuestring, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (pid) {
            char _pid[OS_MAXSTR];
            snprintf(_pid, OS_MAXSTR - 1, "%d", pid->valueint);
            wm_strcat(&msg, _pid, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (process) {
            wm_strcat(&msg, process->valuestring, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (sc_send_db(msg) < 0) {
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
        } else if (strcmp(msg_type, "port_end") == 0) {

            cJSON * scan_id = cJSON_GetObjectItem(logJSON, "ID");
            snprintf(msg, OS_MAXSTR - 1, "agent %s port del %d", agent_id, scan_id->valueint);

            if (sc_send_db(msg) < 0) {
                return -1;
            }
        }
    }

    return 0;
}

int decode_hardware(char *agent_id, cJSON * logJSON) {

    char * msg = NULL;

    os_calloc(OS_MAXSTR, sizeof(char), msg);

    cJSON * inventory;

    if (inventory = cJSON_GetObjectItem(logJSON, "inventory"), inventory) {
        cJSON * scan_id = cJSON_GetObjectItem(logJSON, "ID");
        cJSON * scan_time = cJSON_GetObjectItem(logJSON, "timestamp");
        cJSON * serial = cJSON_GetObjectItem(inventory, "board_serial");
        cJSON * cpu_name = cJSON_GetObjectItem(inventory, "cpu_name");
        cJSON * cpu_cores = cJSON_GetObjectItem(inventory, "cpu_cores");
        cJSON * cpu_mhz = cJSON_GetObjectItem(inventory, "cpu_mhz");
        cJSON * ram_total = cJSON_GetObjectItem(inventory, "ram_total");
        cJSON * ram_free = cJSON_GetObjectItem(inventory, "ram_free");

        snprintf(msg, OS_MAXSTR - 1, "agent %s hardware save", agent_id);

        if (scan_id) {
            char id[OS_MAXSTR];
            snprintf(id, OS_MAXSTR - 1, "%d", scan_id->valueint);
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
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (cpu_name) {
            wm_strcat(&msg, cpu_name->valuestring, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (cpu_cores) {
            char cores[OS_MAXSTR];
            snprintf(cores, OS_MAXSTR - 1, "%d", cpu_cores->valueint);
            wm_strcat(&msg, cores, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (cpu_mhz) {
            char freq[OS_MAXSTR];
            snprintf(freq, OS_MAXSTR - 1, "%f", cpu_mhz->valuedouble);
            wm_strcat(&msg, freq, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (ram_total) {
            char total[OS_MAXSTR];
            snprintf(total, OS_MAXSTR - 1, "%d", ram_total->valueint);
            wm_strcat(&msg, total, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (ram_free) {
            char rfree[OS_MAXSTR];
            snprintf(rfree, OS_MAXSTR - 1, "%d", ram_free->valueint);
            wm_strcat(&msg, rfree, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (sc_send_db(msg) < 0) {
            return -1;
        }
    }

    return 0;
}

int decode_program(char *agent_id, cJSON * logJSON) {

    char * msg = NULL;

    os_calloc(OS_MAXSTR, sizeof(char), msg);

    cJSON * program;

    if (program = cJSON_GetObjectItem(logJSON, "program"), program) {
        cJSON * scan_id = cJSON_GetObjectItem(logJSON, "ID");
        cJSON * scan_time = cJSON_GetObjectItem(logJSON, "timestamp");
        cJSON * format = cJSON_GetObjectItem(program, "format");
        cJSON * name = cJSON_GetObjectItem(program, "name");
        cJSON * vendor = cJSON_GetObjectItem(program, "vendor");
        cJSON * version = cJSON_GetObjectItem(program, "version");
        cJSON * architecture = cJSON_GetObjectItem(program, "architecture");
        cJSON * description = cJSON_GetObjectItem(program, "description");

        snprintf(msg, OS_MAXSTR - 1, "agent %s program save", agent_id);


        if (scan_id) {
            char id[OS_MAXSTR];
            snprintf(id, OS_MAXSTR - 1, "%d", scan_id->valueint);
            wm_strcat(&msg, id, ' ');
        } else {
            wm_strcat(&msg, "NULL", ' ');
        }

        if (scan_time) {
            wm_strcat(&msg, scan_time->valuestring, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (format) {
            wm_strcat(&msg, format->valuestring, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (name) {
            wm_strcat(&msg, name->valuestring, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (vendor) {
            wm_strcat(&msg, vendor->valuestring, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (version) {
            wm_strcat(&msg, version->valuestring, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (architecture) {
            wm_strcat(&msg, architecture->valuestring, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (description) {
            wm_strcat(&msg, description->valuestring, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (sc_send_db(msg) < 0) {
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
        } else if (strcmp(msg_type, "program_end") == 0) {

            cJSON * scan_id = cJSON_GetObjectItem(logJSON, "ID");
            snprintf(msg, OS_MAXSTR - 1, "agent %s program del %d", agent_id, scan_id->valueint);

            if (sc_send_db(msg) < 0) {
                return -1;
            }
        }
    }

    return 0;
}

int decode_process(char *agent_id, cJSON * logJSON) {

    char * msg = NULL;
    int i;

    os_calloc(OS_MAXSTR, sizeof(char), msg);

    cJSON * inventory;

    if (inventory = cJSON_GetObjectItem(logJSON, "process"), inventory) {
        cJSON * scan_id = cJSON_GetObjectItem(logJSON, "ID");
        cJSON * scan_time = cJSON_GetObjectItem(logJSON, "timestamp");
        cJSON * pid = cJSON_GetObjectItem(logJSON, "pid");
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

        snprintf(msg, OS_MAXSTR - 1, "agent %s process save", agent_id);

        if (scan_id) {
            char id[OS_MAXSTR];
            snprintf(id, OS_MAXSTR - 1, "%d", scan_id->valueint);
            wm_strcat(&msg, id, ' ');
        } else {
            wm_strcat(&msg, "NULL", ' ');
        }

        if (scan_time) {
            wm_strcat(&msg, scan_time->valuestring, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (pid) {
            char _pid[OS_MAXSTR];
            snprintf(_pid, OS_MAXSTR - 1, "%d", pid->valueint);
            wm_strcat(&msg, _pid, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (name) {
            wm_strcat(&msg, name->valuestring, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (state) {
            wm_strcat(&msg, state->valuestring, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (ppid) {
            char _ppid[OS_MAXSTR];
            snprintf(_ppid, OS_MAXSTR - 1, "%d", ppid->valueint);
            wm_strcat(&msg, _ppid, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (utime) {
            char _utime[OS_MAXSTR];
            snprintf(_utime, OS_MAXSTR - 1, "%d", utime->valueint);
            wm_strcat(&msg, _utime, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (stime) {
            char _stime[OS_MAXSTR];
            snprintf(_stime, OS_MAXSTR - 1, "%d", stime->valueint);
            wm_strcat(&msg, _stime, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (cmd) {
            wm_strcat(&msg, cmd->valuestring, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (argvs) {
            char * args = NULL;
            for (i = 0; i < cJSON_GetArraySize(argvs); i++){
                wm_strcat(&args, cJSON_GetArrayItem(argvs,i)->valuestring, ',');
            }
            wm_strcat(&msg, args, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (euser) {
            wm_strcat(&msg, euser->valuestring, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (ruser) {
            wm_strcat(&msg, ruser->valuestring, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (suser) {
            wm_strcat(&msg, suser->valuestring, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (egroup) {
            wm_strcat(&msg, egroup->valuestring, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (rgroup) {
            wm_strcat(&msg, rgroup->valuestring, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (sgroup) {
            wm_strcat(&msg, sgroup->valuestring, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (fgroup) {
            wm_strcat(&msg, fgroup->valuestring, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (priority) {
            char prior[OS_MAXSTR];
            snprintf(prior, OS_MAXSTR - 1, "%d", priority->valueint);
            wm_strcat(&msg, prior, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (nice) {
            char _nice[OS_MAXSTR];
            snprintf(_nice, OS_MAXSTR - 1, "%d", nice->valueint);
            wm_strcat(&msg, _nice, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (size) {
            char _size[OS_MAXSTR];
            snprintf(_size, OS_MAXSTR - 1, "%d", size->valueint);
            wm_strcat(&msg, _size, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (vm_size) {
            char vms[OS_MAXSTR];
            snprintf(vms, OS_MAXSTR - 1, "%d", vm_size->valueint);
            wm_strcat(&msg, vms, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (resident) {
            char _resident[OS_MAXSTR];
            snprintf(_resident, OS_MAXSTR - 1, "%d", resident->valueint);
            wm_strcat(&msg, _resident, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (share) {
            char _share[OS_MAXSTR];
            snprintf(_share, OS_MAXSTR - 1, "%d", share->valueint);
            wm_strcat(&msg, _share, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (start_time) {
            char start[OS_MAXSTR];
            snprintf(start, OS_MAXSTR - 1, "%d", start_time->valueint);
            wm_strcat(&msg, start, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (pgrp) {
            char _pgrp[OS_MAXSTR];
            snprintf(_pgrp, OS_MAXSTR - 1, "%d", pgrp->valueint);
            wm_strcat(&msg, _pgrp, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (session) {
            char _session[OS_MAXSTR];
            snprintf(_session, OS_MAXSTR - 1, "%d", session->valueint);
            wm_strcat(&msg, _session, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (nlwp) {
            char _nlwp[OS_MAXSTR];
            snprintf(_nlwp, OS_MAXSTR - 1, "%d", nlwp->valueint);
            wm_strcat(&msg, _nlwp, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (tgid) {
            char _tgid[OS_MAXSTR];
            snprintf(_tgid, OS_MAXSTR - 1, "%d", tgid->valueint);
            wm_strcat(&msg, _tgid, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (tty) {
            char _tty[OS_MAXSTR];
            snprintf(_tty, OS_MAXSTR - 1, "%d", tty->valueint);
            wm_strcat(&msg, _tty, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (processor) {
            char proc[OS_MAXSTR];
            snprintf(proc, OS_MAXSTR - 1, "%d", processor->valueint);
            wm_strcat(&msg, proc, '|');
        } else {
            wm_strcat(&msg, "NULL", '|');
        }

        if (sc_send_db(msg) < 0) {
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
        } else if (strcmp(msg_type, "process_end") == 0) {

            cJSON * scan_id = cJSON_GetObjectItem(logJSON, "ID");
            snprintf(msg, OS_MAXSTR - 1, "agent %s process del %d", agent_id, scan_id->valueint);

            if (sc_send_db(msg) < 0) {
                return -1;
            }
        }
    }

    return 0;
}

int sc_send_db(char * msg) {
    static int sock = -1;
    char response[OS_MAXSTR];
    ssize_t length;
    fd_set fdset;
    struct timeval timeout = {0, 1000};
    int size = strlen(msg);
    int retval = -1;
    static time_t last_attempt = 0;
    time_t mtime;

    // Connect to socket if disconnected

    if (sock < 0) {
        if (mtime = time(NULL), mtime > last_attempt + 10) {
            if (sock = OS_ConnectUnixDomain(WDB_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR), sock < 0) {
                last_attempt = mtime;
                merror("Unable to connect to socket '%s': %s (%d)", WDB_LOCAL_SOCK, strerror(errno), errno);
                goto end;
            }
        } else {
            // Return silently
            goto end;
        }
    }

    // Send msg to Wazuh DB

    if (send(sock, msg, size + 1, MSG_DONTWAIT) < size) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            merror("Syscollector decoder: database socket is full");
        } else if (errno == EPIPE) {
            if (mtime = time(NULL), mtime > last_attempt + 10) {
                // Retry to connect
                mwarn("Connection with wazuh-db lost. Reconnecting.");

                if (sock = OS_ConnectUnixDomain(WDB_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR), sock < 0) {
                    last_attempt = mtime;
                    merror("Unable to connect to socket '%s': %s (%d)", WDB_LOCAL_SOCK, strerror(errno), errno);
                    goto end;
                }

                if (send(sock, msg, size + 1, MSG_DONTWAIT) < size) {
                    last_attempt = mtime;
                    merror("at sc_send_db(): at send() (retry): %s (%d)", strerror(errno), errno);
                    goto end;
                }
            } else {
                // Return silently
                goto end;
            }

        } else {
            merror("at sc_send_db(): at send(): %s (%d)", strerror(errno), errno);
            goto end;
        }
    }

    // Wait for socket

    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);

    if (select(sock + 1, &fdset, NULL, NULL, &timeout) < 0) {
        merror("at sc_send_db(): at select(): %s (%d)", strerror(errno), errno);
        goto end;
    }

    // Receive response from socket

    length = recv(sock, response, OS_MAXSTR, 0);

    switch (length) {
        case -1:
            merror("at sc_send_db(): at recv(): %s (%d)", strerror(errno), errno);
            goto end;

        default:
            response[length] = '\0';

            if (strcmp(response, "ok")) {
                merror("at sc_send_db(): received: '%s'", response);
                goto end;
            }
    }

    retval = 0;

end:
    free(msg);
    return retval;
}
