/* Copyright (C) 2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
*/

#include "cloud_limits.h"

#ifdef WAZUH_UNIT_TESTING
#undef OSSEC_LIMITS
#define OSSEC_LIMITS  "./limits.conf"
#endif


static time_t last_mod_date = 0;

// load json objects from limits.conf file.

int load_limits_file(const char *daemon_name, cJSON ** daemon_obj) {

    if (!daemon_name) {
        mdebug2("Invalid daemon name is null");
        return LIMITS_NULL_NAME;
    }

    time_t cur_mod_date = 0;
    if ((cur_mod_date = File_DateofChange(OSSEC_LIMITS)) == -1) {
        mdebug2("File %s not found", OSSEC_LIMITS);
        last_mod_date = 0;
        return LIMITS_FILE_NOT_FOUND;
    }

    if (cur_mod_date == last_mod_date) {
        mdebug2("File %s hasn't changed", OSSEC_LIMITS);
        return LIMITS_FILE_DOESNT_CHANGE;
    }

    FILE *fp;
    if (fp = fopen(OSSEC_LIMITS, "r"), !fp) {
        mdebug2("Could not open file '%s'", OSSEC_LIMITS);
        last_mod_date = 0;
        return LIMITS_OPEN_FILE_FAIL;
    }

    char buf[OS_MAXSTR + 1];
    memset(buf, '\0', OS_MAXSTR);
    if (fgets(buf, OS_MAXSTR, fp) == NULL) {
        mdebug2("Could not read file '%s'", OSSEC_LIMITS);
        fclose(fp);
        last_mod_date = 0;
        return LIMITS_READ_FILE_FAIL;
    }

    last_mod_date = cur_mod_date;

    cJSON *file_json = NULL;
    const char *json_err;
    if (file_json = cJSON_ParseWithOpts(buf, &json_err, 0), !file_json) {
        mdebug2("Invalid format file '%s', json '%s'", OSSEC_LIMITS, json_err);
        fclose(fp);
        return LIMITS_JSON_FORMAT_FAIL;
    }
    fclose(fp);

    if (!strcmp(daemon_name, "file")) {
        if (daemon_obj) {
            *daemon_obj = file_json;
        }
        return LIMITS_SUCCESS;
    }

    cJSON *limits_json = cJSON_GetObjectItem(file_json, "limits");
    if (!cJSON_IsObject(limits_json)) {
        mdebug2("Limits object not found in '%s'", OSSEC_LIMITS);
        cJSON_Delete(file_json);
        return LIMITS_JSON_LIMIT_NOT_FOUND;
    }

    if (!strcmp(daemon_name, "limits")) {
        if (daemon_obj) {
            *daemon_obj = limits_json;
        }
        return LIMITS_SUCCESS;
    }

    cJSON *daemon_json = cJSON_GetObjectItem(limits_json, daemon_name);
    if (!cJSON_IsObject(daemon_json)) {
        mdebug2("Daemon '%s' not found in '%s'", daemon_name, OSSEC_LIMITS);
        cJSON_Delete(file_json);
        return LIMITS_JSON_DAEMON_NOT_FOUND;
    }

    if (daemon_obj) {
        *daemon_obj = daemon_json;
    }

    return LIMITS_SUCCESS;
}

