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
static pthread_mutex_t label_cache_mutex;

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

    label_cache_mutex = (pthread_mutex_t) PTHREAD_MUTEX_INITIALIZER;
    return (1);
}

wlabel_data_t * labels_cache_update(char *agent_id, int *sock) {
    wlabel_t *labels = NULL;
    wlabel_data_t *data = NULL;

    // Requesting labels to Wazuh DB
    cJSON *labels_json = wdb_get_agent_labels(atoi(agent_id), sock);

    if (labels_json == NULL) {
        return NULL;
    }

    labels = labels_parse(labels_json);
    free(labels_json);

    // Cleaning labels from cache
    if (data = OSHash_Delete(label_cache, agent_id), data) {
        labels_free(data->labels);
        os_free(data);
    }

    // Adding new labels to the cache
    os_calloc(1, sizeof(wlabel_data_t), data);
    data->labels = labels;
    data->mtime = time(NULL);
    if (OSHash_Add(label_cache, agent_id, data) != 2) {
        merror("Cannot cache labels.");
        labels_free(data->labels);
        os_free(data);
    }

    return data;
}

wlabel_t * labels_find(char *agent_id, int *sock) {
    wlabel_t *ret_labels = NULL;
    wlabel_data_t *data = NULL;

    if (strcmp(agent_id, "000") == 0) {
        return Config.labels;
    }

    w_mutex_lock(&label_cache_mutex);
    data = (wlabel_data_t*)OSHash_Get(label_cache, agent_id);
    if (data == NULL || (time(NULL) > data->mtime + Config.label_cache_maxage)) {
        data = labels_cache_update(agent_id, sock);
    }

    if (data != NULL) {
        ret_labels = labels_dup(data->labels);
    }
    w_mutex_unlock(&label_cache_mutex);

    return ret_labels;
}
