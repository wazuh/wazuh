/*
 * Label data cache
 * Copyright (C) 2015-2019, Wazuh Inc.
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
static pthread_mutex_t label_mutex;

/* Free label cache */
void free_label_cache(wlabel_data_t *data) {
    if (data->labels) labels_free(data->labels);
    free(data);
}

/* Initialize label cache */
int labels_init() {
    label_cache = OSHash_Create();
    if (!label_cache) {
        merror(MEM_ERROR, errno, strerror(errno));
        return (0);
    }

    OSHash_SetFreeDataPointer(label_cache, (void (*)(void *))free_label_cache);

    label_mutex = (pthread_mutex_t) PTHREAD_MUTEX_INITIALIZER;
    return (1);
}

/* Find the label array for an agent. Returns NULL if no such agent file found. */
wlabel_t* labels_find(const Eventinfo *lf) {
    char path[PATH_MAX];
    char hostname[OS_MAXSTR];
    char *ip;
    char *end;
    wlabel_data_t *data;
    wlabel_t *ret_labels;

    if (strcmp(lf->agent_id, "000") == 0) {
        return Config.labels;
    }

    if (lf->location[0] != '(') {
        return NULL;
    }

    strncpy(hostname, lf->location + 1, OS_MAXSTR - 1);
    hostname[OS_MAXSTR - 1] = '\0';

    if (!(ip = strstr(hostname, ") "))) {
        return NULL;
    }

    *ip = '\0';

    if ((end = strchr(ip += 2, '-'))) {
        *end = '\0';
    }

    if (snprintf(path, PATH_MAX, AGENTINFO_DIR "/%s-%s", hostname, ip) >= PATH_MAX) {
        merror("at labels_find(): path too long.");
        return NULL;
    }

    w_mutex_lock(&label_mutex);
    if (data = (wlabel_data_t*)OSHash_Get(label_cache, path), !data) {
        // Data not cached

        os_calloc(1, sizeof(wlabel_data_t), data);
        data->labels = labels_parse(path);

        if (!data->labels) {
            mdebug1("Couldn't parse labels for agent %s (%s). Info file may not exist.", hostname, ip);
            free(data);
            w_mutex_unlock(&label_mutex);
            return NULL;
        }

        data->mtime = File_DateofChange(path);

        if (data->mtime == -1) {
            merror("Getting stats for agent %s (%s). Cannot parse labels.", hostname, ip);
            labels_free(data->labels);
            free(data);
            w_mutex_unlock(&label_mutex);
            return NULL;
        }

        if (OSHash_Add(label_cache, path, data) != 2) {
            merror("Couldn't store labels for agent %s (%s) on cache.", hostname, ip);
            labels_free(data->labels);
            free(data);
            w_mutex_unlock(&label_mutex);
            return NULL;
        }
    } else {
        // Data cached, check modification time

        wlabel_data_t *new_data;
        time_t mtime = File_DateofChange(path);;

        if (mtime == -1) {
            if (!data->error_flag) {
                minfo("Cannot get agent-info file for agent %s (%s). Using old labels.", hostname, ip);
                data->error_flag = 1;
            }
        } else if (mtime > data->mtime + Config.label_cache_maxage) {
            // Update file, keep old to return in case of error

            os_calloc(1, sizeof(wlabel_data_t), new_data);
            new_data->labels = labels_parse(path);
            new_data->mtime = mtime;

            if (!OSHash_Update(label_cache, path, new_data)) {
                merror("Couldn't update labels for agent %s (%s) on cache.", hostname, ip);
                labels_free(new_data->labels);
                free(new_data);
                w_mutex_unlock(&label_mutex);
                return NULL;
            }

            data = new_data;
            data->error_flag = 0;
        }
    }
    ret_labels = labels_dup(data->labels);
    w_mutex_unlock(&label_mutex);

    return ret_labels;
}
