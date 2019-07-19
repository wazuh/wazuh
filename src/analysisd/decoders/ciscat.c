/*
* Copyright (C) 2015-2019, Wazuh Inc.
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

static OSDecoderInfo *ciscat_decoder = NULL;

#define VAR_LENGTH  32

void CiscatInit(){

    os_calloc(1, sizeof(OSDecoderInfo), ciscat_decoder);
    ciscat_decoder->id = getDecoderfromlist(CISCAT_MOD);
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
    msg_type = cJSON_GetObjectItem(logJSON, "type")->valuestring;
    if (!msg_type) {
        mdebug1("Invalid message. Type not found.");
        cJSON_Delete(logJSON);
        return (0);
    }

    fillData(lf,"cis.type",msg_type);

    if (strcmp(msg_type, "scan_info") == 0) {
        char *msg = NULL;
        cJSON * cis_data;

        os_calloc(OS_MAXSTR, sizeof(char), msg);

        cis_data = cJSON_GetObjectItem(logJSON, "cis");
        if(!cis_data) {
            cis_data = cJSON_GetObjectItem(logJSON, "cis-data");
        }

        if (cis_data) {
            cJSON * scan_id = cJSON_GetObjectItem(logJSON, "scan_id");
            cJSON * scan_time = cJSON_GetObjectItem(cis_data, "timestamp");
            cJSON * benchmark = cJSON_GetObjectItem(cis_data, "benchmark");
            cJSON * profile = cJSON_GetObjectItem(cis_data, "profile");
            cJSON * hostname = cJSON_GetObjectItem(cis_data, "hostname");
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
                fillData(lf,"cis.scan_id",id);
                wm_strcat(&msg, id, ' ');
            }

            if (scan_time) {
                fillData(lf,"cis.scan_time",scan_time->valuestring);
                wm_strcat(&msg, scan_time->valuestring, '|');
            } else {
                wm_strcat(&msg, "NULL", '|');
            }

            if (benchmark) {
                fillData(lf,"cis.benchmark",benchmark->valuestring);
                wm_strcat(&msg, benchmark->valuestring, '|');
            } else {
                wm_strcat(&msg, "NULL", '|');
            }

            if (profile) {
                fillData(lf,"cis.profile",profile->valuestring);
                wm_strcat(&msg, profile->valuestring, '|');
            } else {
                wm_strcat(&msg, "NULL", '|');
            }

            if (hostname) {
                fillData(lf,"cis.hostname",hostname->valuestring);
                wm_strcat(&msg, hostname->valuestring, '|');
            } else {
                wm_strcat(&msg, "NULL", '|');
            }

            if (pass) {
                char _pass[VAR_LENGTH];
                snprintf(_pass, VAR_LENGTH - 1, "%d", pass->valueint);
                fillData(lf,"cis.pass",_pass);
                wm_strcat(&msg, _pass, '|');
            } else {
                wm_strcat(&msg, "NULL", '|');
            }

            if (fail) {
                char _fail[VAR_LENGTH];
                snprintf(_fail, VAR_LENGTH - 1, "%d", fail->valueint);
                fillData(lf,"cis.fail",_fail);
                wm_strcat(&msg, _fail, '|');
            } else {
                wm_strcat(&msg, "NULL", '|');
            }

            if (error) {
                char _error[VAR_LENGTH];
                snprintf(_error, VAR_LENGTH - 1, "%d", error->valueint);
                fillData(lf,"cis.error",_error);
                wm_strcat(&msg, _error, '|');
            } else {
                wm_strcat(&msg, "NULL", '|');
            }


            if (notchecked) {
                char _notchecked[VAR_LENGTH];
                snprintf(_notchecked, VAR_LENGTH - 1, "%d", notchecked->valueint);
                fillData(lf,"cis.notchecked",_notchecked);
                wm_strcat(&msg, _notchecked, '|');
            } else {
                wm_strcat(&msg, "NULL", '|');
            }


            if (unknown) {
                char _unknown[VAR_LENGTH];
                snprintf(_unknown, VAR_LENGTH - 1, "%d", unknown->valueint);
                fillData(lf,"cis.unknown",_unknown);
                wm_strcat(&msg, _unknown, '|');
            } else {
                wm_strcat(&msg, "NULL", '|');
            }


            if (score) {
                char *endptr;
                char _score[VAR_LENGTH];
                int score_i = strtoul(score->valuestring, &endptr, 10);
                snprintf(_score, VAR_LENGTH - 1, "%d", score_i);
                fillData(lf,"cis.score",_score);
                wm_strcat(&msg, _score, '|');
            } else {
                wm_strcat(&msg, "NULL", '|');
            }

            if (sc_send_db(msg, socket) < 0) {
                cJSON_Delete(logJSON);
                return (0);
            }
        } else {
            mdebug1("Unable to parse CIS-CAT event for agent '%s'", lf->agent_id);
            cJSON_Delete(logJSON);
            free(msg);
            return (0);
        }
    }
    else if (strcmp(msg_type, "scan_result") == 0) {

        cJSON * cis_data;

        cis_data = cJSON_GetObjectItem(logJSON, "cis");
        if(!cis_data) {
            cis_data = cJSON_GetObjectItem(logJSON, "cis-data");
        }

        if (cis_data) {
            cJSON * scan_id = cJSON_GetObjectItem(logJSON, "scan_id");
            cJSON * rule_id = cJSON_GetObjectItem(cis_data, "rule_id");
            cJSON * rule_title = cJSON_GetObjectItem(cis_data, "rule_title");
            cJSON * group = cJSON_GetObjectItem(cis_data, "group");
            cJSON * description = cJSON_GetObjectItem(cis_data, "description");
            cJSON * rationale = cJSON_GetObjectItem(cis_data, "rationale");
            cJSON * remediation = cJSON_GetObjectItem(cis_data, "remediation");
            cJSON * result = cJSON_GetObjectItem(cis_data, "result");

            if (scan_id) {
                char id[OS_MAXSTR];
                snprintf(id, OS_MAXSTR - 1, "%d", scan_id->valueint);
                fillData(lf,"cis.scan_id",id);
            }

            if (rule_id) {
                fillData(lf,"cis.rule_id",rule_id->valuestring);
            }

            if (rule_title) {
                fillData(lf,"cis.rule_title",rule_title->valuestring);
            }

            if (group) {
                fillData(lf,"cis.group",group->valuestring);
            }

            if (description) {
                fillData(lf,"cis.description",description->valuestring);
            }

            if (rationale) {
                fillData(lf,"cis.rationale",rationale->valuestring);
            }

            if (remediation) {
                fillData(lf,"cis.remediation",remediation->valuestring);
            }

            if (result) {
               fillData(lf,"cis.result",result->valuestring);
            }
        } else {
            mdebug1("Unable to parse CIS-CAT event for agent '%s'", lf->agent_id);
            cJSON_Delete(logJSON);
            return (0);
        }
    }

    cJSON_Delete (logJSON);
    return (1);
}
