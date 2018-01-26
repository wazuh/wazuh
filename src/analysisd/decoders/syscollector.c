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

#define SYSCOLLECTOR_DIR    "/queue/syscollector"

static int decode_osinfo(char *agent_id, cJSON * logJSON, int sock);

/* Special decoder for syscollector */
int DecodeSyscollector(Eventinfo *lf, int sock)
{
    cJSON *logJSON;
    FILE *fp;
    int file_status = 0;
    char file_name[OS_SIZE_1024 + 1];
    char file_name_lock[OS_SIZE_1024 + 1];
    char *msg_type = NULL;

    // Decoding JSON
    JSON_Decoder_Exec(lf);

    // Check location
    if (lf->location[0] == '(') {
        char* search;
        search = strchr(lf->location, '>') + 1;
        if (!search) {
            merror("Invalid received event.");
            return (0);
        }
        else if (strcmp(search, "syscollector") != 0) {
            merror("Invalid received event. Not syscollector.");
            return (0);
        }
    } else if (strcmp(lf->location, "syscollector") != 0) {
        merror("Invalid received event. (Location)");
        return (0);
    }

    // Parsing event.
    logJSON = cJSON_Parse(lf->log);
    if (!logJSON) {
        merror("Error parsing JSON event. %s", cJSON_GetErrorPtr());
        return (0);
    }

    // Detect message type
    msg_type = cJSON_GetObjectItem(logJSON, "type")->valuestring;
    if (!msg_type) {
        merror("Invalid message. Type not found.");
        return (0);
    }

    if (strcmp(msg_type, "port") == 0 || strcmp(msg_type, "port_end") == 0) {
        snprintf(file_name, OS_SIZE_1024, "%s/ports/%s", SYSCOLLECTOR_DIR, lf->agent_id);
    }
    else if (strcmp(msg_type, "program") == 0 || strcmp(msg_type, "program_end") == 0) {
        snprintf(file_name, OS_SIZE_1024, "%s/programs/%s", SYSCOLLECTOR_DIR, lf->agent_id);
    }
    else if (strcmp(msg_type, "hardware") == 0 || strcmp(msg_type, "hardware_end") == 0) {
        snprintf(file_name, OS_SIZE_1024, "%s/hardware/%s", SYSCOLLECTOR_DIR, lf->agent_id);
    }
    else if (strcmp(msg_type, "OS") == 0) {
        snprintf(file_name, OS_SIZE_1024, "%s/os/%s", SYSCOLLECTOR_DIR, lf->agent_id);
        if (decode_osinfo(lf->agent_id, logJSON, sock) < 0) {
            merror("Unable to send osinfo message to Wazuh DB.");
            return (0);
        }
    }
    else if (strcmp(msg_type, "network") == 0 || strcmp(msg_type, "network_end") == 0) {
        snprintf(file_name, OS_SIZE_1024, "%s/network/%s", SYSCOLLECTOR_DIR, lf->agent_id);
    }
    else if (strcmp(msg_type, "process") == 0 || strcmp(msg_type, "process_list") == 0  || strcmp(msg_type, "process_end") == 0) {
        snprintf(file_name, OS_SIZE_1024, "%s/processes/%s", SYSCOLLECTOR_DIR, lf->agent_id);
    }
    else {
        merror("Invalid message type: %s.", msg_type);
        return (0);
    }

    if (strcmp(&msg_type[strlen(msg_type) - 3], "end") == 0) {
        mtdebug2(ARGV0, "Scan finished message received: %s ", msg_type);
        file_status = 1;
    }

    // Opening syscollector file
    if (IsFile(file_name) == 0) { // File already exists
        if (file_status == 1) { // Lock file
            snprintf(file_name_lock, OS_SIZE_1024, "%s.lock", file_name);
            mtdebug2(ARGV0, "Locking file: %s ", file_name);
            if (!rename(file_name, file_name_lock) == 0) {
                merror(file_name_lock, errno, strerror(errno));
                return (0);
            }
        }
        else { // Append message
            fp = fopen(file_name, "a");
            if (!fp) {
                merror(FOPEN_ERROR, file_name, errno, strerror(errno));
                return (0);
            }
            fprintf(fp, "%s\n", lf->log);
            fclose(fp);
        }
    }
    else {
        if (!file_status) {
            fp = fopen(file_name, "w");
            if (!fp) {
                merror(FOPEN_ERROR, file_name, errno, strerror(errno));
                return (0);
            }
            fprintf(fp, "%s\n", lf->log);
            fclose(fp);
        }
        else {
            merror("Invalid message. File already locked.");
            return (0);
        }
    }
    cJSON_Delete (logJSON);
    return (1);
}

int decode_osinfo(char *agent_id, cJSON * logJSON, int sock) {

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
            char * id;
            os_calloc(OS_MAXSTR, sizeof(char), id);
            snprintf(id, OS_MAXSTR - 1, "%d", scan_id->valueint);
            wm_strcat(&msg, id, ' ');
            free(id);
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

        int size = strlen(msg);

        if (send(sock, msg, size + 1, 0) < size) {
            merror("At decode_osinfo(): '%s'.", strerror(errno));
            free(msg);
            return -1;
        }

        free(msg);
    }

    return 0;
}
