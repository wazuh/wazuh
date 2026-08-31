/*
 * Cluster identity of this manager node, read from the effective etc/wazuh-manager.yml.
 * Copyright (C) 2015, Wazuh Inc.
 * October 26, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef CLIENT

#include "shared.h"
#include <cJSON.h>
#include "mconf_hook.h"

/* The `cluster` section of the effective document through the hook libconfig registers
 * (mconf_hook.h). NULL without provider or document: libwazuhshared.so as the engine loads it, or a
 * process that never loaded its configuration -- the getters then answer as they always did when the
 * configuration file could not be read. */
static cJSON *cluster_section(void) {
    return w_mconf_hook_section("cluster");
}

static const char *string_item(const cJSON *object, const char *key) {
    const cJSON *item = object != NULL ? cJSON_GetObjectItem(object, key) : NULL;
    return item != NULL && cJSON_IsString(item) && item->valuestring != NULL && item->valuestring[0] != '\0' ? item->valuestring : NULL;
}

int w_is_worker(void) {
    cJSON *cluster = cluster_section();
    int is_worker = OS_INVALID;

    if (cluster != NULL) {
        // node_type defaults to "master" when not explicitly defined
        const char *node_type = string_item(cluster, "node_type");
        is_worker = node_type != NULL && strcmp(node_type, "worker") == 0 ? 1 : 0;
    }

    cJSON_Delete(cluster);
    return is_worker;
}

int w_is_single_node(int* is_worker) {
    cJSON *cluster = cluster_section();
    int _is_worker = OS_INVALID;
    int is_single_node = OS_INVALID;

    if (cluster != NULL) {
        const char *node_type = string_item(cluster, "node_type");

        if (node_type != NULL) {
            // Since cluster is always enabled, if we have cluster config with node_type, it's not a single node
            is_single_node = 0;
            _is_worker = strcmp(node_type, "worker") == 0 ? 1 : 0;
        } else {
            is_single_node = 1;
        }
    }

    cJSON_Delete(cluster);

    if (is_worker) {
        *is_worker = _is_worker;
    }

    return is_single_node;
}

static char *dup_or_undefined(const char *key) {
    cJSON *cluster = cluster_section();
    const char *value = string_item(cluster, key);
    char *result = strdup(value != NULL ? value : "undefined");

    cJSON_Delete(cluster);
    return result;
}

char *get_node_name(void) {
    return dup_or_undefined("node_name");
}

char *get_cluster_name(void) {
    return dup_or_undefined("name");
}

#endif /* CLIENT */
