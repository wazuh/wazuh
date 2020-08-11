/*
 * Label data cache
 * Copyright (C) 2015-2020, Wazuh Inc.
 * February 27, 2017.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "headers/shared.h"
#include "wazuh_db/wdb.h"
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

wlabel_t* labels_find(const Eventinfo *lf) {
    char hostname[OS_BUFFER_SIZE] = "";
    char *ip = NULL;
    char *end = NULL;
    wlabel_data_t *data = NULL;
    wlabel_t *ret_labels = NULL;

    if (strcmp(lf->agent_id, "000") == 0) {
        return Config.labels;
    }

    if (lf->location[0] != '(') {
        return NULL;
    }

    strncpy(hostname, lf->location + 1, OS_BUFFER_SIZE - 1);
    hostname[OS_BUFFER_SIZE - 1] = '\0';

    if (!(ip = strstr(hostname, ") "))) {
        return NULL;
    }

    *ip = '\0';

    if ((end = strchr(ip += 2, '-'))) {
        *end = '\0';
    }

    w_mutex_lock(&label_mutex);
    if (data = (wlabel_data_t*)OSHash_Get(label_cache, lf->agent_id), !data) {
        // Data not cached

        os_calloc(1, sizeof(wlabel_data_t), data);
        data->labels = labels_parse(atoi(lf->agent_id));

        if (!data->labels) {
            mdebug1("Couldn't parse labels for agent %s.", lf->agent_id);
            free(data);
            w_mutex_unlock(&label_mutex);
            return NULL;
        }

        data->mtime = wdb_get_agent_keepalive(hostname, ip);

        if (data->mtime == -1) {
            merror("Getting last keepalive for agent %s. Cannot update labels.", lf->agent_id);
            labels_free(data->labels);
            free(data);
            w_mutex_unlock(&label_mutex);
            return NULL;
        }

        if (OSHash_Add(label_cache, lf->agent_id, data) != 2) {
            merror("Couldn't store labels for agent %s on cache.", lf->agent_id);
            labels_free(data->labels);
            free(data);
            w_mutex_unlock(&label_mutex);
            return NULL;
        }
    } else {
        // Data cached, check modification time

        wlabel_data_t *new_data;
        time_t mtime = time(NULL);

        if (mtime == -1) {
            if (!data->error_flag) {
                minfo("Can't determine current time to compare with last keepalive for agent %s. Using old labels.", lf->agent_id);
                data->error_flag = 1;
            }
        } else if (mtime > data->mtime + Config.label_cache_maxage) {
            // Update file, keep old to return in case of error

            os_calloc(1, sizeof(wlabel_data_t), new_data);
            new_data->labels = labels_parse(atoi(lf->agent_id));
            new_data->mtime = wdb_get_agent_keepalive(hostname, ip);

            if (!OSHash_Update(label_cache, lf->agent_id, new_data)) {
                merror("Couldn't update labels for agent %s on cache.", lf->agent_id);
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
