/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "container_baseline_fim_bridge.h"

#include "shared.h"
#include "syscheck.h"

#include <unistd.h>

int fim_collect_k8s_monitored_paths(cb_monitored_path_t** out_paths, size_t* out_count)
{
    if (out_paths == NULL || out_count == NULL) {
        return -1;
    }

    *out_paths = NULL;
    *out_count = 0U;

    if (syscheck.directories == NULL || !syscheck.enable_synchronization) {
        return 0;
    }

    size_t count = 0U;
    for (OSListNode* it = OSList_GetFirstNode(syscheck.directories); it != NULL;
         it = OSList_GetNext(syscheck.directories, it)) {
        const directory_t* path = (const directory_t*)it->data;
        if (path != NULL && path->path != NULL && path->tag != NULL && strcmp(path->tag, "kubernetes") == 0) {
            ++count;
        }
    }

    if (count == 0U) {
        return 0;
    }

    cb_monitored_path_t* paths = (cb_monitored_path_t*)calloc(count, sizeof(cb_monitored_path_t));
    if (paths == NULL) {
        return -1;
    }

    size_t index = 0U;
    for (OSListNode* it = OSList_GetFirstNode(syscheck.directories); it != NULL;
         it = OSList_GetNext(syscheck.directories, it)) {
        const directory_t* path = (const directory_t*)it->data;
        if (path == NULL || path->path == NULL || path->tag == NULL || strcmp(path->tag, "kubernetes") != 0) {
            continue;
        }

        paths[index].internal_path = path->path;
        paths[index].recursion_level = path->recursion_level;
        paths[index].max_files = 20000;
        paths[index].max_hash_bytes = 104857600;
        ++index;
    }

    *out_paths = paths;
    *out_count = index;

    return 0;
}

void fim_free_k8s_monitored_paths(cb_monitored_path_t* paths)
{
    free(paths);
}

/* wazuh-modulesd starts container_instances concurrently with wazuh-syscheckd
 * and only binds its IPC socket once the module is up - typically well under
 * a second, but with no ordering guarantee between the two daemons. Poll
 * briefly instead of failing on the first check, so a one-shot baseline at
 * FIM startup doesn't lose the race by chance. */
#define K8S_BASELINE_SOCKET_WAIT_TOTAL_MS 5000
#define K8S_BASELINE_SOCKET_POLL_INTERVAL_MS 200

int fim_k8s_container_baseline_available(const char* socket_path)
{
    if (socket_path == NULL) {
        mdebug1("container_instances module not running (no socket path configured), skipping k8s FIM baseline.");
        return 0;
    }

    int waited_ms = 0;
    while (access(socket_path, F_OK) != 0) {
        if (waited_ms >= K8S_BASELINE_SOCKET_WAIT_TOTAL_MS) {
            mdebug1("container_instances module not running (socket '%s' not found after %dms), skipping k8s FIM baseline.",
                    socket_path, waited_ms);
            return 0;
        }
        usleep(K8S_BASELINE_SOCKET_POLL_INTERVAL_MS * 1000);
        waited_ms += K8S_BASELINE_SOCKET_POLL_INTERVAL_MS;
    }

    return 1;
}

void fim_report_k8s_container_baseline_result(int baselined)
{
    minfo("Container FIM baseline finished (%d container(s) baselined).", baselined);
}

void fim_persist_baseline_row(const char* id, int operation, const char* index, const char* json, uint64_t version)
{
    cJSON* msg = cJSON_Parse(json);
    if (msg == NULL) {
        mdebug1("Container FIM baseline: dropping row '%s' - failed to parse JSON.", id);
        return;
    }

    persist_syscheck_msg(id, (Operation_t)operation, index, msg, version);
    cJSON_Delete(msg);
}
