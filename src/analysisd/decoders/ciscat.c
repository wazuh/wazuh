/*
* Copyright (C) 2017 Wazuh Inc.
* April 23, 2018.
*
* This program is a free software; you can redistribute it
* and/or modify it under the terms of the GNU General Public
* License (version 2) as published by the FSF - Free Software
* Foundation.
*/

/* CIS-CAT decoder */

#include "eventinfo.h"
#include "decoder.h"
#include "external/cJSON/cJSON.h"
#include "plugin_decoders.h"
#include "wazuh_modules/wmodules.h"
#include "string_op.h"

#define VAR_LENGTH  32

/* Special decoder for CIS-CAT events */
int DecodeCiscat(Eventinfo *lf)
{
    cJSON *logJSON;
    char *msg_type = NULL;

    // Parsing event.
    logJSON = cJSON_Parse(lf->log);
    if (!logJSON) {
        mdebug1("Error parsing JSON event. %s", cJSON_GetErrorPtr());
        return -1;
    }

    // Detect message type
    msg_type = cJSON_GetObjectItem(logJSON, "type")->valuestring;
    if (!msg_type) {
        mdebug1("Invalid message. Type not found.");
        return -1;
    }

    if (strcmp(msg_type, "scan_info") == 0) {

        char *msg = NULL;
        cJSON * cis_data;

        os_calloc(OS_MAXSTR, sizeof(char), msg);

        if (cis_data = cJSON_GetObjectItem(logJSON, "cis"), cis_data) {
            cJSON * scan_id = cJSON_GetObjectItem(logJSON, "scan_id");
            cJSON * scan_time = cJSON_GetObjectItem(cis_data, "timestamp");
            cJSON * benchmark = cJSON_GetObjectItem(cis_data, "benchmark");
            cJSON * pass = cJSON_GetObjectItem(cis_data, "pass");
            cJSON * fail = cJSON_GetObjectItem(cis_data, "fail");
            cJSON * error = cJSON_GetObjectItem(cis_data, "error");
            cJSON * notchecked = cJSON_GetObjectItem(cis_data, "notchecked");
            cJSON * unknown = cJSON_GetObjectItem(cis_data, "unknown");
            cJSON * score = cJSON_GetObjectItem(cis_data, "score");

            snprintf(msg, OS_MAXSTR - 1, "agent %s ciscat save", lf->agent_id);

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

            if (benchmark) {
                wm_strcat(&msg, benchmark->valuestring, '|');
            } else {
                wm_strcat(&msg, "NULL", '|');
            }

            if (pass) {
                char _pass[VAR_LENGTH];
                snprintf(_pass, VAR_LENGTH - 1, "%d", pass->valueint);
                wm_strcat(&msg, _pass, '|');
            } else {
                wm_strcat(&msg, "NULL", '|');
            }

            if (fail) {
                char _fail[VAR_LENGTH];
                snprintf(_fail, VAR_LENGTH - 1, "%d", fail->valueint);
                wm_strcat(&msg, _fail, '|');
            } else {
                wm_strcat(&msg, "NULL", '|');
            }

            if (error) {
                char _error[VAR_LENGTH];
                snprintf(_error, VAR_LENGTH - 1, "%d", error->valueint);
                wm_strcat(&msg, _error, '|');
            } else {
                wm_strcat(&msg, "NULL", '|');
            }

            if (notchecked) {
                char _notchecked[VAR_LENGTH];
                snprintf(_notchecked, VAR_LENGTH - 1, "%d", notchecked->valueint);
                wm_strcat(&msg, _notchecked, '|');
            } else {
                wm_strcat(&msg, "NULL", '|');
            }

            if (unknown) {
                char _unknown[VAR_LENGTH];
                snprintf(_unknown, VAR_LENGTH - 1, "%d", unknown->valueint);
                wm_strcat(&msg, _unknown, '|');
            } else {
                wm_strcat(&msg, "NULL", '|');
            }

            if (score) {
                char *endptr;
                char _score[VAR_LENGTH];
                int score_i = strtoul(score->valuestring, &endptr, 10);
                snprintf(_score, VAR_LENGTH - 1, "%d", score_i);
                wm_strcat(&msg, _score, '|');
            } else {
                wm_strcat(&msg, "NULL", '|');
            }

            if (sc_send_db(msg) < 0) {
                return -1;
            }

        } else if (cis_data = cJSON_GetObjectItem(logJSON, "cis-data"), cis_data) {
            cJSON * scan_id = cJSON_GetObjectItem(logJSON, "scan_id");
            cJSON * scan_time = cJSON_GetObjectItem(cis_data, "timestamp");
            cJSON * benchmark = cJSON_GetObjectItem(cis_data, "benchmark");
            cJSON * score = cJSON_GetObjectItem(cis_data, "score");

            snprintf(msg, OS_MAXSTR - 1, "agent %s ciscat save", lf->agent_id);

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

            if (benchmark) {
                wm_strcat(&msg, benchmark->valuestring, '|');
            } else {
                wm_strcat(&msg, "NULL", '|');
            }

            for (int i = 0; i<5; i++) {
                wm_strcat(&msg, "NULL", '|');
            }

            if (score) {
                char _score[VAR_LENGTH];
                snprintf(_score, VAR_LENGTH - 1, "%d", score->valueint);
                wm_strcat(&msg, _score, '|');
            } else {
                wm_strcat(&msg, "NULL", '|');
            }

            if (sc_send_db(msg) < 0) {
                return -1;
            }
        } else {
            mdebug1("Unable to parse CIS-CAT event for agent '%s'", lf->agent_id);
            return -1;
        }
    }
    else {
        mdebug1("Invalid message type: %s.", msg_type);
        return -1;
    }

    cJSON_Delete (logJSON);
    return 0;
}
