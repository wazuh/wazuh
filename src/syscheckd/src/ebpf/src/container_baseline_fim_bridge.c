/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "container_baseline_fim_bridge.h"

#include "file.h"
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

    // Lift container_json column → container/kubernetes top-level blocks.
    const cJSON* container_json_item = cJSON_GetObjectItem(msg, "container_json");
    if (container_json_item != NULL && cJSON_IsString(container_json_item) &&
        container_json_item->valuestring != NULL && container_json_item->valuestring[0] != '\0') {
        cJSON* ctx = cJSON_Parse(container_json_item->valuestring);
        if (ctx != NULL) {
            cJSON* container_block = cJSON_DetachItemFromObject(ctx, "container");
            if (container_block != NULL) {
                cJSON_DeleteItemFromObject(msg, "container");
                cJSON_AddItemToObject(msg, "container", container_block);
            }
            cJSON* kubernetes_block = cJSON_DetachItemFromObject(ctx, "kubernetes");
            if (kubernetes_block != NULL) {
                cJSON_DeleteItemFromObject(msg, "kubernetes");
                cJSON_AddItemToObject(msg, "kubernetes", kubernetes_block);
            }
            cJSON_Delete(ctx);
        }
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
    // dbsync-only columns: not part of the stateful event schema.
    cJSON_DeleteItemFromObject(msg, "container_id");
    cJSON_DeleteItemFromObject(msg, "container_json");
    cJSON_DeleteItemFromObject(msg, "checksum");
    cJSON_DeleteItemFromObject(msg, "sync");
    cJSON_DeleteItemFromObject(msg, "version");
    cJSON_DeleteItemFromObject(msg, "attributes");
}

/* Hard cap on rows produced per monitored path (NFR3). There is no dedicated
 * config knob yet; when one is added it should replace this constant rather
 * than another literal appearing at the call site. */
#define CONTAINER_BASELINE_MAX_FILES_PER_PATH 20000

/* True when `tags` — a COMMA-SEPARATED list, per the <directories tags="...">
 * attribute — contains "container" as one of its tokens.
 *
 * A plain strcmp() against the whole attribute only matched when "container"
 * was the sole tag, so an ordinary tags="container,prod" silently selected
 * nothing and the whole container FIM baseline no-op'd with no warning. */
static int fim_tags_contain_container(const char* tags)
{
    static const char TOKEN[] = "container";
    static const size_t TOKEN_LEN = sizeof(TOKEN) - 1;

    if (tags == NULL) {
        return 0;
    }

    for (const char* cursor = tags; *cursor != '\0';) {
        /* Skip leading separators and whitespace of this token. */
        while (*cursor == ',' || *cursor == ' ' || *cursor == '\t') {
            ++cursor;
        }

        const char* start = cursor;
        while (*cursor != '\0' && *cursor != ',') {
            ++cursor;
        }

        /* Trim trailing whitespace of this token. */
        const char* end = cursor;
        while (end > start && (end[-1] == ' ' || end[-1] == '\t')) {
            --end;
        }

        if ((size_t)(end - start) == TOKEN_LEN && strncmp(start, TOKEN, TOKEN_LEN) == 0) {
            return 1;
        }
    }

    return 0;
}

/* Longest-prefix match of a CONTAINER-internal path against the configured
 * <directories> entries, restricted to the container-tagged ones.
 *
 * Deliberately not fim_configuration_directory(): that one searches every
 * entry, so with
 *
 *     <directories tags="container">/etc</directories>
 *     <directories>/etc/ssl</directories>          <!-- host only -->
 *
 * a container row for /etc/ssl/cert.pem would resolve to the host-only entry
 * and take ITS check options and tag. A container row can only have come from a
 * container-tagged root — fim_collect_container_monitored_paths() below is what
 * selects them — so that is the set to resolve against.
 *
 * Also matches on dir_it->path rather than fim_get_real_path(dir_it), for the
 * same reason fim_collect_container_monitored_paths() passes path->path as the
 * internal_path: symlink resolution is a property of the HOST filesystem, and
 * the host's resolved target means nothing inside a container's mount
 * namespace. */
static const directory_t* fim_container_configuration_directory(const char* path)
{
    char full_path[OS_SIZE_4096 + 1] = {'\0'};
    char full_entry[OS_SIZE_4096 + 1] = {'\0'};
    const directory_t* best = NULL;
    int top = 0;
    OSListNode* node_it;

    if (path == NULL || *path == '\0' || syscheck.directories == NULL) {
        return NULL;
    }

    trail_path_separator(full_path, path, sizeof(full_path));

    OSList_foreach(node_it, syscheck.directories) {
        const directory_t* dir_it = (const directory_t*)node_it->data;

        if (dir_it == NULL || dir_it->path == NULL || !fim_tags_contain_container(dir_it->tag)) {
            continue;
        }

        trail_path_separator(full_entry, dir_it->path, sizeof(full_entry));

        const int match = w_compare_str(full_entry, full_path);

        /* match is 0 when full_entry is not a prefix of full_path, so the
         * full_path[match - 1] read below only happens for match >= 1. Same
         * idiom as fim_configuration_directory(). */
        if (top < match && full_path[match - 1] == PATH_SEP) {
            best = dir_it;
            top = match;
        }
    }

    return best;
}

int fim_collect_container_monitored_paths(cb_monitored_path_t** out_paths, size_t* out_count)
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
        if (path != NULL && path->path != NULL && fim_tags_contain_container(path->tag)) {
            ++count;
        }
    }

    if (count == 0U) {
        mdebug1("No <directories> entry is tagged \"container\"; skipping the container FIM baseline.");
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
        if (path == NULL || path->path == NULL || !fim_tags_contain_container(path->tag)) {
            continue;
        }

        paths[index].internal_path = path->path;
        paths[index].recursion_level = path->recursion_level;
        paths[index].max_files = CONTAINER_BASELINE_MAX_FILES_PER_PATH;

        /* Reuse FIM's own size limit rather than a private literal: files above
         * it are not hashed at all, exactly as the host walk treats them. */
        paths[index].max_hash_bytes = syscheck.file_max_size;

        /* Honour the per-directory hash selection instead of always computing
         * all three digests. */
        paths[index].hash_md5 = (path->options & CHECK_MD5SUM) ? 1 : 0;
        paths[index].hash_sha1 = (path->options & CHECK_SHA1SUM) ? 1 : 0;
        paths[index].hash_sha256 = (path->options & CHECK_SHA256SUM) ? 1 : 0;

        ++index;
    }

    *out_paths = paths;
    *out_count = index;

    mdebug1("Container FIM baseline will walk %zu monitored path(s).", index);

    return 0;
}

void fim_free_container_monitored_paths(cb_monitored_path_t* paths)
{
    free(paths);
}

/* wazuh-modulesd starts container_instances concurrently with wazuh-syscheckd
 * and only binds its IPC socket once the module is up - typically well under
 * a second, but with no ordering guarantee between the two daemons. Poll
 * briefly instead of failing on the first check, so a one-shot baseline at
 * FIM startup doesn't lose the race by chance. */
#define CONTAINER_BASELINE_SOCKET_WAIT_TOTAL_MS 5000
#define CONTAINER_BASELINE_SOCKET_POLL_INTERVAL_MS 200

int fim_container_baseline_available(const char* socket_path)
{
    if (socket_path == NULL) {
        mdebug1("container_instances module not running (no socket path configured), skipping container FIM baseline.");
        return 0;
    }

    int waited_ms = 0;
    while (access(socket_path, F_OK) != 0) {
        if (waited_ms >= CONTAINER_BASELINE_SOCKET_WAIT_TOTAL_MS) {
            mdebug1("container_instances module not running (socket '%s' not found after %dms), skipping container FIM baseline.",
                    socket_path, waited_ms);
            return 0;
        }
        usleep(CONTAINER_BASELINE_SOCKET_POLL_INTERVAL_MS * 1000);
        waited_ms += CONTAINER_BASELINE_SOCKET_POLL_INTERVAL_MS;
    }

    return 1;
}

void fim_report_container_baseline_result(int baselined, size_t rows, size_t partial, size_t stale, size_t known)
{
    minfo("Container FIM baseline finished: %d container(s) scanned, %zu row(s), %zu partial scan(s), "
          "%zu stale container(s) cleaned, %zu container(s) known.",
          baselined, rows, partial, stale, known);

    if (partial > 0) {
        mdebug1("Container FIM baseline: %zu container(s) had an incomplete scan; delete detection was "
                "skipped for those so absent files are not reported as removed.",
                partial);
    }
}

void fim_container_baseline_log_debug(const char* message)
{
    if (message != NULL) {
        mdebug1("%s", message);
    }
}

void fim_container_baseline_log_warn(const char* message)
{
    if (message != NULL) {
        mwarn("%s", message);
    }
}

void fim_container_baseline_log_error(const char* message)
{
    if (message != NULL) {
        merror("%s", message);
    }
}

int fim_container_baseline_abspath(const char* relative, char* out, size_t out_size)
{
    if (relative == NULL || out == NULL || out_size == 0) {
        return -1;
    }

    out[0] = '\0';

    if (abspath(relative, out, out_size) == NULL) {
        mdebug1("Container eBPF drain: could not resolve '%s' against the install directory.", relative);
        return -1;
    }

    return 0;
}

void fim_container_baseline_rate_limit(void)
{
    check_max_fps();
}

void fim_compute_row_checksum(const char* row_json, char out_sha1[41])
{
    if (row_json == NULL || out_sha1 == NULL) {
        return;
    }
    OS_SHA1_Str(row_json, (ssize_t)strlen(row_json), out_sha1);
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

/* Host FIM's own alert vocabulary. Duplicated from file.c's static table
 * rather than exported from it: three string literals are not worth widening
 * that file's interface for, and the schema they name is fixed. */
static const char* CONTAINER_FIM_EVENT_TYPE[] = {
    "added",    /* OPERATION_CREATE */
    "modified", /* OPERATION_MODIFY */
    "deleted"   /* OPERATION_DELETE */
};

/* Host FIM has `notify_scan`, flipped to 1 by fim_scan.c once the first scan
 * ends, so the first walk of a host does not alert on every file it finds
 * unless <notify_first_scan> says otherwise. The container walk needs the same
 * suppression and cannot borrow that flag: it runs one-shot from main() before
 * the host's first scan has necessarily finished, so `notify_scan`'s value at
 * that moment says nothing about whether the CONTAINER baseline is a first
 * scan.
 *
 * Written on syscheckd's main thread by fim_container_events_release() — the
 * point that already means "the baseline walk committed, the reconcile consumer
 * is now live" — and read on that consumer thread. Not a data race, and not by
 * luck: release() goes on to take the staging buffer's mutex, and the consumer
 * may not touch file_entry at all until it observes that release, so the write
 * here happens-before every read of it. */
static int container_notify_scan = -1;

static int container_should_report_events(void)
{
    if (container_notify_scan < 0) {
        container_notify_scan = syscheck.notify_first_scan ? 1 : 0;
    }

    return container_notify_scan;
}

void fim_container_baseline_first_scan_done(void)
{
    container_notify_scan = 1;
}

/* Lifts the container_json column onto `target` as top-level container /
 * kubernetes blocks. Same placement normalize_container_fim_row() uses for the
 * stateful document, so an analyst reads the same field names on both sides. */
static void add_container_context(const cJSON* row_data, cJSON* target)
{
    const cJSON* container_json_item = cJSON_GetObjectItem(row_data, "container_json");

    if (container_json_item == NULL || !cJSON_IsString(container_json_item) ||
        container_json_item->valuestring == NULL || container_json_item->valuestring[0] == '\0') {
        return;
    }

    cJSON* ctx = cJSON_Parse(container_json_item->valuestring);
    if (ctx == NULL) {
        return;
    }

    cJSON* container_block = cJSON_DetachItemFromObject(ctx, "container");
    if (container_block != NULL) {
        cJSON_AddItemToObject(target, "container", container_block);
    }

    cJSON* kubernetes_block = cJSON_DetachItemFromObject(ctx, "kubernetes");
    if (kubernetes_block != NULL) {
        cJSON_AddItemToObject(target, "kubernetes", kubernetes_block);
    }

    cJSON_Delete(ctx);
}

void fim_send_container_stateless_event(const cJSON* row_data,
                                        const cJSON* old_data,
                                        int operation,
                                        int origin)
{
    if (row_data == NULL || !container_should_report_events()) {
        return;
    }

    if (operation != OPERATION_CREATE && operation != OPERATION_MODIFY && operation != OPERATION_DELETE) {
        return;
    }

    const cJSON* path_json = cJSON_GetObjectItem(row_data, "path");
    if (path_json == NULL || !cJSON_IsString(path_json) || path_json->valuestring == NULL) {
        return;
    }
    const char* path = path_json->valuestring;

    const directory_t* config = fim_container_configuration_directory(path);
    if (config == NULL) {
        /* The reconcile driver only ever submits paths under a configured
         * container root, so this means the configuration changed under a
         * reload between the walk and the callback. Nothing to attribute the
         * alert's check options to, so there is no alert to build. */
        mdebug2(FIM_CONFIGURATION_NOTFOUND, "container file", path);
        return;
    }

    cJSON* changed_attributes = NULL;
    cJSON* old_attributes = NULL;

    if (old_data != NULL) {
        changed_attributes = cJSON_CreateArray();
        old_attributes = cJSON_CreateObject();

        fim_calculate_dbsync_difference(config, old_data, changed_attributes, old_attributes);

        if (cJSON_GetArraySize(changed_attributes) == 0) {
            /* DBSync saw the row change, but only in a column none of this
             * entry's configured checks look at. file.c takes the same exit
             * (FIM_EMPTY_CHANGED_ATTRIBUTES) rather than raise an alert with an
             * empty changed_fields.
             *
             * Unlike file.c this does NOT also suppress the stateful document:
             * the row really did change and the stored state should say so.
             * Only the alert is withheld. */
            mdebug2(FIM_EMPTY_CHANGED_ATTRIBUTES, path);
            cJSON_Delete(changed_attributes);
            cJSON_Delete(old_attributes);
            return;
        }
    }

    cJSON* stateless_event = cJSON_CreateObject();
    if (stateless_event == NULL) {
        cJSON_Delete(changed_attributes); // LCOV_EXCL_LINE
        cJSON_Delete(old_attributes);     // LCOV_EXCL_LINE
        return;                           // LCOV_EXCL_LINE
    }

    cJSON_AddStringToObject(stateless_event, "collector", "file");
    cJSON_AddStringToObject(stateless_event, "module", "fim");

    cJSON* data = cJSON_CreateObject();
    cJSON_AddItemToObject(stateless_event, "data", data);

    cJSON* event = cJSON_CreateObject();
    cJSON_AddItemToObject(data, "event", event);

    char iso_time[32];
    get_iso8601_utc_time(iso_time, sizeof(iso_time));
    cJSON_AddStringToObject(event, "created", iso_time);
    cJSON_AddStringToObject(event, "type", CONTAINER_FIM_EVENT_TYPE[operation]);

    /* A deleted file has no live attributes left to report: the row DBSync
     * hands back is the state the file HAD, and reporting it as current would
     * be a lie. Host FIM's handle_orphaned_delete() sends the same path/mode
     * pair and nothing else.
     *
     * Container rows have no fim_file_data struct, so this always takes
     * fim_attributes_json()'s JSON-only mode (data == NULL) — which reads the
     * named columns and ignores container_id/container_json. */
    cJSON* file_stateless = (operation == OPERATION_DELETE)
        ? cJSON_CreateObject()
        : fim_attributes_json(row_data, NULL, config);
    cJSON_AddItemToObject(data, "file", file_stateless);

    cJSON_AddStringToObject(file_stateless, "path", path);
    cJSON_AddStringToObject(file_stateless,
                            "mode",
                            origin == CB_FIM_ORIGIN_EVENT ? "whodata" : "scheduled");

    if (config->tag != NULL) {
        cJSON_AddStringToObject(file_stateless, "tags", config->tag);
    }

    if (changed_attributes != NULL) {
        cJSON_AddItemToObject(file_stateless, "previous", old_attributes);
        cJSON_AddItemToObject(event, "changed_fields", changed_attributes);
    }

    add_container_context(row_data, data);

    send_syscheck_msg(stateless_event);

    cJSON_Delete(stateless_event);
}
