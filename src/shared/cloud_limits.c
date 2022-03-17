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


cJSON *file_json = NULL;
cJSON *limits_json = NULL;

/*
 * load json objects from limits.conf file.
 */
int load_limits_file(void) {

    FILE *fp;
    if (fp = fopen(OSSEC_LIMITS, "r"), !fp) {
        mdebug1("Could not open file '%s'",OSSEC_LIMITS);
        return OS_INVALID;
    }

    char buf[OS_MAXSTR + 1];
    memset(buf, '\0', OS_MAXSTR);
    if (fgets(buf, OS_MAXSTR, fp) == NULL) {
        mdebug1("Could not read file '%s'",OSSEC_LIMITS);
        fclose(fp);
        return OS_INVALID;
    }

    cJSON *local_file_json = NULL;
    const char *json_err;
    if (local_file_json = cJSON_ParseWithOpts(buf, &json_err, 0), !local_file_json) {
        mdebug1("Invalid format file '%s', json '%s'",OSSEC_LIMITS, json_err);
        fclose(fp);
        return OS_INVALID;
    }

    cJSON *local_limits_json = cJSON_GetObjectItem(local_file_json, "limits");
    if (!cJSON_IsObject(local_limits_json)) {
        mdebug1("limits object doesn't found into '%s'", OSSEC_LIMITS);
        cJSON_Delete(local_limits_json);
        cJSON_Delete(local_file_json);
        fclose(fp);
        return OS_INVALID;
    }

    if (limits_json) {
        cJSON_Delete(limits_json);
    }
    limits_json = local_limits_json;

    if (file_json) {
        cJSON_free(file_json);
    }
    file_json = local_file_json;
    fclose(fp);

    return OS_SUCCESS;
}

/*
 * clean json objects.
 */
void clean_limits_objects(void) {

    if (limits_json) {
        cJSON_Delete(limits_json);
    }
    if (file_json) {
        cJSON_free(file_json);
    }
}


/*
 * get a json object from a deamon name string.
 */
cJSON * get_deamon_limits(const char *deamon_name) {

    if (!deamon_name) {
        mdebug1("Invalid deamon name");
        return NULL;
    }

    cJSON *deamon_json = cJSON_GetObjectItem(limits_json, deamon_name);
    if (!cJSON_IsObject(deamon_json)) {
        mdebug1("deamon '%s' doesn't found into '%s'",deamon_name, OSSEC_LIMITS);
        cJSON_Delete(deamon_json);
        return NULL;
    }

    return deamon_json;
}


