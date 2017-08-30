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

#define SYSCOLLECTOR_DIR    "/queue/syscollector"


/* Special decoder for syscollector */
int DecodeSyscollector(Eventinfo *lf)
{
    cJSON *arrayJSON;
    cJSON *readedJSON;
    cJSON *logJSON;
    FILE *fp;
    char file_name[OS_SIZE_1024 + 1];
    char temp_file_name[OS_SIZE_1024 + 1];
    char *lf_type = NULL, *rd_type = NULL;
    char *lf_iface_name = NULL, *rd_iface_name = NULL;
    char buffer[OS_SIZE_2048 + 1];

    // Decoding JSON
    JSON_Decoder_Exec(&lf);
    if (strcmp(lf->location, "syscollector") != 0) {
        merror("Invalid Syscollector received event.");
        return (0);
    }

    // Opening syscollector file
    snprintf(file_name, OS_SIZE_1024, "%s/%s", SYSCOLLECTOR_DIR, lf->agent_id);

    if (fp = fopen(file_name, "r"), fp) { // File already exists
        // Zero buffer
        buffer[0] = '\0';
        buffer[OS_SIZE_2048] = '\0';

        // Parsing event.
        logJSON = cJSON_Parse(lf->log);
        if (!logJSON) {
            merror("Error parsing JSON event. %s", cJSON_GetErrorPtr());
            return (0);
        }
        lf_type = cJSON_GetObjectItem(logJSON, "type")->valuestring;
        if (strcmp(rd_type, "network") == 0) {
            lf_iface_name = cJSON_GetObjectItem(cJSON_GetObjectItem(logJSON, "iface"), "name")->valuestring;
        }

        // Reads the file and generate the JSON array
        arrayJSON = cJSON_CreateArray();
        while (fgets(buffer, OS_SIZE_2048 - 1, fp) != NULL) {
            // Ignore blank lines and lines with a comment
            if (buffer[0] == '\n' || buffer[0] == '#') {
                continue;
            }

            // Parse JSON line and add it to the array
            readedJSON = cJSON_Parse(buffer);
            if (!readedJSON)
                merror("Error parsing JSON string from database. %s", cJSON_GetErrorPtr());
            cJSON_AddItemToArray(arrayJSON, readedJSON);
        }

        // Closing syscollector file
        fclose(fp);

        // Opening syscollector temp file
        snprintf(temp_file_name, OS_SIZE_1024, "%s/%s_tmp", SYSCOLLECTOR_DIR, lf->agent_id);
        fp = fopen(temp_file_name, "w");
        if (!fp) {
            merror("Error handling syscollector database.");
            return (0);
        }

        // Generating new updated file
        cJSON_ArrayForEach(readedJSON, arrayJSON) {
            rd_type = (cJSON_GetObjectItem(readedJSON, "type")->valuestring);
            if ((strcmp(lf_type, rd_type) == 0) && (strcmp(rd_type, "network") == 0)) {
                rd_iface_name = cJSON_GetObjectItem(cJSON_GetObjectItem(readedJSON, "iface"), "name")->valuestring;
                if (strcmp(lf_iface_name, rd_iface_name) == 0) {
                    fprintf(fp, "%s\n", cJSON_Print(logJSON));
                }
            }
            else if ((strcmp(lf_type, rd_type) == 0) && (strcmp(rd_type, "network") != 0)) {
                fprintf(fp, "%s\n", cJSON_Print(logJSON));
            }
            else {
                fprintf(fp, "%s\n", cJSON_Print(readedJSON));
            }
        }

        fclose(fp);

        // Replacing file
        if (remove(file_name) == 0) {
            rename(temp_file_name, file_name);
        }
        else {
            remove(temp_file_name);
        }

        // Cleaning
        cJSON_Delete (arrayJSON);
        cJSON_Delete (logJSON);

    }
    else {
        fp = fopen(temp_file_name, "w");
        if (!fp) {
            merror("Error handling syscollector database.");
            return (0);
        }
        fprintf(fp, "%s\n", lf->log);
        fclose(fp);
    }

    return (1);
}
