/*
 * Label data cache
 * Copyright (C) 2017 Wazuh Inc.
 * February 27, 2017.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "headers/shared.h"
#include "eventinfo.h"
#include "config.h"
#include "labels.h"

static OSHash *label_cache;

/* Initialize label cache */
void labels_init() {
    label_cache = OSHash_Create();
}

/* Find the label array for an agent. Returns NULL if no such agent file found. */
const wlabel_t* labels_find(const Eventinfo *lf) {
    char path[PATH_MAX];
    char hostname[OS_MAXSTR];
    char *ip;
    char *end;
    wlabel_data_t *data;

    if (strcmp(lf->agent_id, "000") == 0) {
        return Config.labels;
    }

    if (lf->hostname[0] != '(') {
        return NULL;
    }

    strncpy(hostname, lf->hostname + 1, OS_MAXSTR - 1);

    if (!(ip = strstr(hostname, ") "))) {
        return NULL;
    }

    *ip = '\0';

    if ((end = strchr(ip += 2, '-'))) {
        *end = '\0';
    }

    if (snprintf(path, PATH_MAX, AGENTINFO_DIR "/%s-%s", hostname, ip) >= PATH_MAX) {
        merror("%s: ERROR: at labels_find(): path too long.", __local_name);
        return NULL;
    }

    data = (wlabel_data_t*)OSHash_Get(label_cache, path);

    if (!data) {
        // Data not cached

        os_calloc(1, sizeof(wlabel_data_t), data);
        data->labels = labels_parse(path);

        if (!data->labels) {
            debug1("%s: INFO: labels for agent %s (%s) not yet available.", __local_name, hostname, ip);
            free(data);
            return NULL;
        }

        data->mtime = File_DateofChange(path);

        if (data->mtime == -1) {
            merror("%s: ERROR: getting stats for agent %s (%s). Getting old data.", __local_name, hostname, ip);
            labels_free(data->labels);
            free(data);
            return NULL;
        }

        if (OSHash_Add(label_cache, path, data) < 2) {
            merror("%s: ERROR: couldn't store labels for agent %s (%s) on cache.", __local_name, hostname, ip);
            labels_free(data->labels);
            free(data);
            return NULL;
        }
    } else {
        // Data cached, check modification time

        wlabel_data_t *new_data;
        time_t mtime = File_DateofChange(path);;

        if (mtime == -1) {
            merror("%s: ERROR: getting stats for agent %s (%s). Getting old data.", __local_name, hostname, ip);
        } else if (mtime > data->mtime + Config.label_cache_maxage) {
            // Update file, keep old to return in case of error

            os_calloc(1, sizeof(wlabel_data_t), new_data);
            new_data->labels = labels_parse(path);
            new_data->mtime = mtime;

            if (!OSHash_Update(label_cache, path, new_data)) {
                merror("%s: ERROR: couldn't update labels for agent %s (%s) on cache.", __local_name, hostname, ip);
                labels_free(new_data->labels);
                free(new_data);
                return NULL;
            }

            labels_free(data->labels);
            free(data);
            data = new_data;
        }
    }

    return data->labels;
}
