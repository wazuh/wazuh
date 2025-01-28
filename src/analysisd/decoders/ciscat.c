/*
* Copyright (C) 2015, Wazuh Inc.
* April 23, 2018.
*
* This program is free software; you can redistribute it
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
#include "wazuhdb_op.h"

static OSDecoderInfo *ciscat_decoder = NULL;

extern OSStore *os_analysisd_decoder_store;

#define VAR_LENGTH  32

void CiscatInit(){

    os_calloc(1, sizeof(OSDecoderInfo), ciscat_decoder);
    ciscat_decoder->id = getDecoderfromlist(CISCAT_MOD, &os_analysisd_decoder_store);
    ciscat_decoder->name = CISCAT_MOD;
    ciscat_decoder->type = OSSEC_RL;
    ciscat_decoder->fts = 0;

    mdebug1("CiscatInit completed.");
}

/* Special decoder for CIS-CAT events */
int DecodeCiscat(Eventinfo *lf, int *socket)
{
    cJSON *logJSON;
    char *msg_type = NULL;

    // Decode JSON
    JSON_Decoder_Exec(lf, NULL);

    lf->decoder_info = ciscat_decoder;

    // Check location
    if (lf->location[0] == '(') {
        char* search;
        search = strchr(lf->location, '>');
        if (!search) {
            mdebug1("Invalid received event.");
            return (0);
        }
        else if (strcmp(search + 1, "wodle_cis-cat") != 0) {
            mdebug1("Invalid received event. Not CIS-CAT.");
            return (0);
        }
    } else if (strcmp(lf->location, "wodle_cis-cat") != 0) {
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
    msg_type = cJSON_GetStringValue(cJSON_GetObjectItem(logJSON, "type"));
    if (!msg_type) {
        mdebug1("Invalid message. Type not found or not a string.");
        cJSON_Delete(logJSON);
        return (0);
    }

    if (strcmp(msg_type, "scan_info") == 0) {
        char *msg = NULL;
        cJSON * cis_data;

        os_calloc(OS_MAXSTR, sizeof(char), msg);

        if (cis_data = cJSON_GetObjectItem(logJSON, "cis"), cis_data) {
            cJSON * scan_id = cJSON_GetObjectItem(logJSON, "scan_id");
            cJSON * scan_time = cJSON_GetObjectItem(cis_data, "timestamp");
            cJSON * benchmark = cJSON_GetObjectItem(cis_data, "benchmark");
            cJSON * profile = cJSON_GetObjectItem(cis_data, "profile");
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

            if (scan_time && cJSON_IsString(scan_time)) {
                wm_strcat(&msg, scan_time->valuestring, '|');
            } else {
                wm_strcat(&msg, "NULL", '|');
            }

            if (benchmark && cJSON_IsString(benchmark)) {
                wm_strcat(&msg, benchmark->valuestring, '|');
            } else {
                wm_strcat(&msg, "NULL", '|');
            }

            if (profile && cJSON_IsString(profile)) {
                wm_strcat(&msg, profile->valuestring, '|');
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

            if (score && cJSON_IsString(score)) {
                char *endptr;
                char _score[VAR_LENGTH];
                int score_i = strtoul(score->valuestring, &endptr, 10);
                snprintf(_score, VAR_LENGTH - 1, "%d", score_i);
                wm_strcat(&msg, _score, '|');
            } else {
                wm_strcat(&msg, "NULL", '|');
            }

            char *response;
            char *message;
            os_calloc(OS_SIZE_6144, sizeof(char), response);
            if (wdbc_query_ex(socket, msg, response, OS_SIZE_6144) == 0) {
                if (wdbc_parse_result(response, &message) != WDBC_OK) {
                    cJSON_Delete(logJSON);
                    free(response);
                    return (0);
                }
            } else {
                cJSON_Delete(logJSON);
                free(response);
                return (0);
            }
            free(response);
            free(msg);
        } else {
            mdebug1("Unable to parse CIS-CAT event for agent '%s'", lf->agent_id);
            cJSON_Delete(logJSON);
            free(msg);
            return (0);
        }
    }

    cJSON_Delete (logJSON);
    return (1);
}
