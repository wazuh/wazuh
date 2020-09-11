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

wlabel_t* labels_find(const Eventinfo *lf) {
    cJSON *json_labels = NULL;
    wlabel_data_t *data = NULL;
    time_t mtime = 0;
    time_t last_update = 0;
    wlabel_t *ret_labels = NULL;
    int first_update = 0;
    int error_flag = 0;
    int ret = 0;

    if (strcmp(lf->agent_id, "000") == 0) {
        return Config.labels;
    }

    // Getting last labels update time from cache
    w_mutex_lock(&label_cache_mutex);
    data = (wlabel_data_t*)OSHash_Get(label_cache, lf->agent_id);
    w_mutex_unlock(&label_cache_mutex);

    if (data) {
        // The labels information was saved in the cache at least one time
        // for this agent. Reading when it was the last labels update.
        w_rwlock_rdlock(&data->labels_rwlock);
        last_update = data->mtime;
        w_rwlock_unlock(&data->labels_rwlock);
    }
    else {
        // The labels were never saved in the cache for this agent.
        // Initializing and saving the structure.
        os_calloc(1, sizeof(wlabel_data_t), data);

        w_mutex_lock(&label_cache_mutex);
        ret = OSHash_Add(label_cache, lf->agent_id, data);

        if (2 == ret) {
            first_update = 1;
            w_rwlock_wrlock(&data->labels_rwlock);
            w_mutex_unlock(&label_cache_mutex);
        }
        else if (1 == ret) {
            // This could happen if more than one thread tries to insert the labels
            // data structure for the first time in the labels cache. We need to release
            // the memory and request the labels from cache again.
            mdebug2("Labels already in cache for agent %s. Updating.", lf->agent_id);
            free(data);

            data = (wlabel_data_t*)OSHash_Get(label_cache, lf->agent_id);
            w_mutex_unlock(&label_cache_mutex);

            // The labels information was saved in the cache at least one time
            // for this agent. Reading when it was the last labels update.
            w_rwlock_rdlock(&data->labels_rwlock);
            last_update = data->mtime;
            w_rwlock_unlock(&data->labels_rwlock);
        }
        else {
            // In this case we allow the execution to get the labels from Wazuh DB
            // but the data will not be saved in the labels cache
            w_mutex_unlock(&label_cache_mutex);
            merror("Adding labels to cache for agent %s.", lf->agent_id);
            error_flag = 1;
        }
    }

    // Checking if we must update labels or get them from the cache
    mtime = time(NULL);

    // There are three possible situations here:
    // 1- There was an error adding the labels structure to cache. We will just
    //    get the labels from Wazuh DB and return them.
    // 2- We don't have data to determine if the cache timeout has expired. We
    //    will get the labels from Wazuh DB and perform the update in the cache anyways.
    // 3- The cache timeout expired. We will get the labels
    //    from Wazuh DB and perform the update in the cache.
    if (error_flag || (!last_update || mtime == -1) ||
        (mtime > last_update + Config.label_cache_maxage)) {
        // We perform the update either if we can't determine the decision by 
        // time, or if the time difference is greater than the configured.
        mdebug1("Updating labels for agent %s.", lf->agent_id);

        // Update labels
        json_labels = wdb_get_agent_labels(atoi(lf->agent_id));

        if (!json_labels) {
            mdebug1("No labels in Wazuh DB for agent %s.", lf->agent_id);
            // We don't return because we must update the cache with labels NULL.
        }
        else {
            ret_labels = labels_parse(json_labels);
            cJSON_Delete(json_labels);

            if (error_flag) {
                return ret_labels;
            }
        }

        // Adding/updating labels data. If this is not the first
        // update, we should take the write lock before.
        if (!first_update) {
            w_rwlock_wrlock(&data->labels_rwlock);
        }

        labels_free(data->labels);
        data->labels = labels_dup(ret_labels);
        data->mtime = mtime;
    } else {
        // Getting data from cache
        w_rwlock_rdlock(&data->labels_rwlock);
        ret_labels = labels_dup(data->labels);
    }

    w_rwlock_unlock(&data->labels_rwlock);

    return ret_labels;
}
