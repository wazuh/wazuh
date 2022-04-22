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
#define static
#undef OSSEC_LIMITS
#define OSSEC_LIMITS  "./limits.conf"
#endif

time_t last_mod_date = 0;

/*
 * load json objects from limits.conf file.
 */
cJSON *load_limits_file(const char *object_name) {

    if (!object_name) {
        mdebug1("Invalid deamon name is null");
        return NULL;
    }

    struct stat limit_attrib;
    stat(OSSEC_LIMITS, &limit_attrib);

    if (limit_attrib.st_ctime == last_mod_date) {
        mdebug2("File %s doesn't change", OSSEC_LIMITS);
        return NULL;
    }
    last_mod_date = limit_attrib.st_ctime;

    FILE *fp;
    if (fp = fopen(OSSEC_LIMITS, "r"), !fp) {
        mdebug1("Could not open file '%s'",OSSEC_LIMITS);
        return NULL;
    }

    char buf[OS_MAXSTR + 1];
    memset(buf, '\0', OS_MAXSTR);
    if (fgets(buf, OS_MAXSTR, fp) == NULL) {
        mdebug1("Could not read file '%s'",OSSEC_LIMITS);
        fclose(fp);
        return NULL;
    }

    cJSON *file_json = NULL;
    const char *json_err;
    if (file_json = cJSON_ParseWithOpts(buf, &json_err, 0), !file_json) {
        mdebug1("Invalid format file '%s', json '%s'",OSSEC_LIMITS, json_err);
        cJSON_Delete(file_json);
        fclose(fp);
        return NULL;
    }
    fclose(fp);

    if (!strcmp(object_name, "file")) {
        return file_json;
    }

    cJSON *limits_json = cJSON_GetObjectItem(file_json, "limits");
    if (!cJSON_IsObject(limits_json)) {
        mdebug1("limits object doesn't found into '%s'", OSSEC_LIMITS);
        cJSON_Delete(limits_json);
        cJSON_Delete(file_json);
        return NULL;
    }

    if (!strcmp(object_name, "limits")) {
        return limits_json;
    }

    cJSON *deamon_json = cJSON_GetObjectItem(limits_json, object_name);
    if (!cJSON_IsObject(deamon_json)) {
        mdebug1("deamon '%s' doesn't found into '%s'",object_name, OSSEC_LIMITS);
        cJSON_Delete(deamon_json);
        cJSON_Delete(limits_json);
        cJSON_Delete(file_json);
        return NULL;
    }

    return deamon_json;
}

