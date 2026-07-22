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

#include <stdio.h>
#include <time.h>
#include <unistd.h>

static void copy_if_present(cJSON* source, cJSON* target, const char* source_key, const char* target_key)
{
    cJSON* item = cJSON_GetObjectItem(source, source_key);
    if (item == NULL) {
        return;
    }

    cJSON* dup = cJSON_Duplicate(item, 1);
    if (dup != NULL) {
        cJSON_AddItemToObject(target, target_key, dup);
    }
}

static void copy_number_as_string_if_present(cJSON* source, cJSON* target, const char* source_key, const char* target_key)
{
    cJSON* item = cJSON_GetObjectItem(source, source_key);
    if (item == NULL) {
        return;
    }

    if (cJSON_IsString(item) && item->valuestring != NULL) {
        cJSON_AddStringToObject(target, target_key, item->valuestring);
    } else if (cJSON_IsNumber(item)) {
        char numeric_buf[64];
        snprintf(numeric_buf, sizeof(numeric_buf), "%.0f", item->valuedouble);
        cJSON_AddStringToObject(target, target_key, numeric_buf);
    }
}

static void copy_mtime_to_iso8601_if_present(cJSON* source, cJSON* target)
{
    cJSON* mtime = cJSON_GetObjectItem(source, "mtime");
    if (mtime == NULL) {
        return;
    }

    if (cJSON_IsString(mtime) && mtime->valuestring != NULL) {
        cJSON_AddStringToObject(target, "mtime", mtime->valuestring);
        return;
    }

    if (cJSON_IsNumber(mtime)) {
        time_t timestamp = (time_t)mtime->valuedouble;
        struct tm tm_info;
        char iso[32] = {0};

        if (gmtime_r(&timestamp, &tm_info) && strftime(iso, sizeof(iso), "%Y-%m-%dT%H:%M:%S.000Z", &tm_info) > 0) {
            cJSON_AddStringToObject(target, "mtime", iso);
        } else {
            cJSON_AddNumberToObject(target, "mtime", mtime->valuedouble);
        }
    }
}

static void normalize_container_fim_row(cJSON* msg)
{
    if (msg == NULL || !cJSON_IsObject(msg)) {
        return;
    }

    cJSON* file_obj = cJSON_GetObjectItem(msg, "file");
    if (file_obj == NULL || !cJSON_IsObject(file_obj)) {
        file_obj = cJSON_CreateObject();
        if (file_obj == NULL) {
            return;
        }
        cJSON_AddItemToObject(msg, "file", file_obj);
    }

    copy_if_present(msg, file_obj, "path", "path");
    copy_if_present(msg, file_obj, "permissions", "permissions");
    copy_if_present(msg, file_obj, "uid", "uid");
    copy_if_present(msg, file_obj, "gid", "gid");
    copy_if_present(msg, file_obj, "owner", "owner");
    copy_if_present(msg, file_obj, "group_", "group");
    copy_if_present(msg, file_obj, "size", "size");
    copy_number_as_string_if_present(msg, file_obj, "inode", "inode");
    copy_number_as_string_if_present(msg, file_obj, "device", "device");
    copy_mtime_to_iso8601_if_present(msg, file_obj);

    cJSON* file_hash_obj = cJSON_GetObjectItem(file_obj, "hash");
    if (file_hash_obj == NULL || !cJSON_IsObject(file_hash_obj)) {
        file_hash_obj = cJSON_CreateObject();
        if (file_hash_obj != NULL) {
            cJSON_AddItemToObject(file_obj, "hash", file_hash_obj);
        }
    }

    if (file_hash_obj != NULL) {
        copy_if_present(msg, file_hash_obj, "hash_md5", "md5");
        copy_if_present(msg, file_hash_obj, "hash_sha1", "sha1");
        copy_if_present(msg, file_hash_obj, "hash_sha256", "sha256");
    }

    // Remove flat fields not accepted by the strict fim-files schema.
    cJSON_DeleteItemFromObject(msg, "path");
    cJSON_DeleteItemFromObject(msg, "permissions");
    cJSON_DeleteItemFromObject(msg, "uid");
    cJSON_DeleteItemFromObject(msg, "gid");
    cJSON_DeleteItemFromObject(msg, "owner");
    cJSON_DeleteItemFromObject(msg, "group_");
    cJSON_DeleteItemFromObject(msg, "mtime");
    cJSON_DeleteItemFromObject(msg, "size");
    cJSON_DeleteItemFromObject(msg, "inode");
    cJSON_DeleteItemFromObject(msg, "device");
    cJSON_DeleteItemFromObject(msg, "hash_md5");
    cJSON_DeleteItemFromObject(msg, "hash_sha1");
    cJSON_DeleteItemFromObject(msg, "hash_sha256");
    cJSON_DeleteItemFromObject(msg, "is_symlink");
}

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

    normalize_container_fim_row(msg);

    // Keep parity with host FIM stateful rows by adding checksum/state envelope
    // fields before persistence.
    cJSON* checksum_obj = cJSON_GetObjectItem(msg, "checksum");
    if (checksum_obj == NULL || !cJSON_IsObject(checksum_obj)) {
        checksum_obj = cJSON_CreateObject();
        if (checksum_obj != NULL) {
            cJSON_AddItemToObject(msg, "checksum", checksum_obj);
        }
    }

    if (checksum_obj != NULL) {
        cJSON* hash_obj = cJSON_GetObjectItem(checksum_obj, "hash");
        if (hash_obj == NULL || !cJSON_IsObject(hash_obj)) {
            hash_obj = cJSON_CreateObject();
            if (hash_obj != NULL) {
                cJSON_AddItemToObject(checksum_obj, "hash", hash_obj);
            }
        }

        if (hash_obj != NULL) {
            const char* sha1_value = NULL;

            cJSON* top_sha1 = cJSON_GetObjectItem(msg, "hash_sha1");
            if (top_sha1 != NULL && cJSON_IsString(top_sha1) && top_sha1->valuestring != NULL) {
                sha1_value = top_sha1->valuestring;
            } else {
                cJSON* file_obj = cJSON_GetObjectItem(msg, "file");
                if (file_obj != NULL && cJSON_IsObject(file_obj)) {
                    cJSON* file_hash_obj = cJSON_GetObjectItem(file_obj, "hash");
                    if (file_hash_obj != NULL && cJSON_IsObject(file_hash_obj)) {
                        cJSON* file_sha1 = cJSON_GetObjectItem(file_hash_obj, "sha1");
                        if (file_sha1 != NULL && cJSON_IsString(file_sha1) && file_sha1->valuestring != NULL) {
                            sha1_value = file_sha1->valuestring;
                        }
                    }
                }
            }

            if (sha1_value != NULL) {
                cJSON_DeleteItemFromObject(hash_obj, "sha1");
                cJSON_AddStringToObject(hash_obj, "sha1", sha1_value);
            }
        }
    }

    cJSON* state_obj = cJSON_GetObjectItem(msg, "state");
    if (state_obj == NULL || !cJSON_IsObject(state_obj)) {
        state_obj = cJSON_CreateObject();
        if (state_obj != NULL) {
            cJSON_AddItemToObject(msg, "state", state_obj);
        }
    }

    if (state_obj != NULL) {
        char modified_at_time[32];
        get_iso8601_utc_time(modified_at_time, sizeof(modified_at_time));
        cJSON_DeleteItemFromObject(state_obj, "modified_at");
        cJSON_DeleteItemFromObject(state_obj, "document_version");
        cJSON_AddStringToObject(state_obj, "modified_at", modified_at_time);
        cJSON_AddNumberToObject(state_obj, "document_version", (double)version);
    }

    char item_desc[128];
    snprintf(item_desc, sizeof(item_desc), "container FIM baseline row %s", id ? id : "<null>");
    validate_and_persist_fim_event(msg,
                                   id,
                                   (Operation_t)operation,
                                   index,
                                   version,
                                   item_desc,
                                   false,
                                   NULL,
                                   NULL,
                                   1);

    cJSON_Delete(msg);
}
