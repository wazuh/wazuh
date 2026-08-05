/*
 * Module-tagged config and stats reports
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "module_report.h"

void module_report_merge(cJSON *body, cJSON *section) {
    cJSON *member = NULL;

    if (!section) {
        return;
    }

    if (!body) {
        cJSON_Delete(section); /* Still consumed, as the contract promises. */
        return;
    }

    while (member = section->child, member) {
        /* cJSON_AddItemToObject copies the key before releasing the item's own
         * name, so handing it member->string is safe. */
        cJSON_DetachItemViaPointer(section, member);
        cJSON_AddItemToObject(body, member->string, member);
    }

    cJSON_Delete(section);
}

void module_report_add(cJSON *report, const char *module, cJSON *body) {
    if (!report || !module || !body) {
        cJSON_Delete(body);
        return;
    }

    if (!body->child) {
        cJSON_Delete(body);
        return;
    }

    cJSON_AddItemToObject(report, module, body);
}

size_t module_report_reply(cJSON *report, char **output) {
    char *json_str = NULL;

    if (!output) {
        cJSON_Delete(report);
        return 0;
    }

    if (json_str = cJSON_PrintUnformatted(report), !json_str) {
        cJSON_Delete(report);
        os_strdup("err Could not serialize the module report", *output);
        return strlen(*output);
    }

    os_strdup("ok", *output);
    wm_strcat(output, json_str, ' ');
    os_free(json_str);
    cJSON_Delete(report);
    return strlen(*output);
}
