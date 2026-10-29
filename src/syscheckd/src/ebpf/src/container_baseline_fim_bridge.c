/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "container_baseline_fim_bridge.h"
#include "container_baseline_host_api.h"

#include "container_doc_budget.h"

#include "db.h"
#include "file.h"
#include "shared.h"
#include "syscheck.h"

#include <stdio.h>
#include <time.h>
#include <unistd.h>

/* Everything this library borrows from the daemon that links it. See
 * container_baseline_host_api.h for why none of it can simply be called. */
static fim_container_host_api_t g_host = {0};

void fim_container_baseline_set_host_api(const fim_container_host_api_t* api)
{
    if (api == NULL) {
        memset(&g_host, 0, sizeof(g_host));
        return;
    }

    g_host = *api;
}

/* The daemon's live configuration, or NULL before registration. Every caller
 * checks: unregistered behaves as "nothing configured", which is the same
 * answer an agent with no <container_security> block gives. */
static const syscheck_config* host_config(void)
{
    return g_host.config;
}

/* The daemon's synced-document lock. Container counts share it with the host's
 * on purpose, so this must be the daemon's own mutex; before registration there
 * is nothing to share with and nothing running that could race. */
static void synced_docs_lock(void)
{
    if (g_host.synced_docs_mutex != NULL) {
        w_mutex_lock(g_host.synced_docs_mutex);
    }
}

static void synced_docs_unlock(void)
{
    if (g_host.synced_docs_mutex != NULL) {
        w_mutex_unlock(g_host.synced_docs_mutex);
    }
}

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

    // Lift the container_json column to the top-level "container" block. Since
    // D15 the Kubernetes context is nested INSIDE that block at
    // container.kubernetes, so it rides along with this one detach -- there is
    // no second block to lift. BuildContainerContextJson() is what wrote this
    // column, so the shape here is whatever StampContainerContext() produced.
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
            // Defensive: a column written before D15 carries a sibling
            // "kubernetes". Drop it rather than lift it, so a database that
            // survived the change cannot emit the retired two-block shape.
            cJSON_DeleteItemFromObject(msg, "kubernetes");
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

/* Longest-prefix match of a CONTAINER-internal path against the configured
 * <container_security><syscheck><directories> entries.
 *
 * Deliberately not fim_configuration_directory(): that one searches the host
 * list, so with
 *
 *     <container_security><syscheck><directories>/etc</directories></syscheck></container_security>
 *     <syscheck><directories>/etc/ssl</directories></syscheck>     <!-- host only -->
 *
 * a container row for /etc/ssl/cert.pem would resolve to the host-only entry
 * and take ITS check options and tag. A container row can only have come from a
 * container-scoped root, so that is the set to resolve against — and since the
 * two lists are now separate, the separation is structural rather than a filter
 * this function has to remember to apply.
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

    if (path == NULL || *path == '\0' || host_config() == NULL || host_config()->container_directories == NULL) {
        return NULL;
    }

    trail_path_separator(full_path, path, sizeof(full_path));

    OSList_foreach(node_it, host_config()->container_directories) {
        const directory_t* dir_it = (const directory_t*)node_it->data;

        if (dir_it == NULL || dir_it->path == NULL) {
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

    if (host_config() == NULL || host_config()->container_directories == NULL
        || !host_config()->enable_synchronization) {
        return 0;
    }

    size_t count = 0U;
    for (OSListNode* it = OSList_GetFirstNode(host_config()->container_directories); it != NULL;
         it = OSList_GetNext(host_config()->container_directories, it)) {
        const directory_t* path = (const directory_t*)it->data;
        if (path != NULL && path->path != NULL) {
            ++count;
        }
    }

    if (count == 0U) {
        mdebug1("No <container_security><syscheck><directories> entry is configured; skipping the container FIM "
                "baseline.");
        return 0;
    }

    cb_monitored_path_t* paths = (cb_monitored_path_t*)calloc(count, sizeof(cb_monitored_path_t));
    if (paths == NULL) {
        return -1;
    }

    size_t index = 0U;
    for (OSListNode* it = OSList_GetFirstNode(host_config()->container_directories); it != NULL;
         it = OSList_GetNext(host_config()->container_directories, it)) {
        const directory_t* path = (const directory_t*)it->data;
        if (path == NULL || path->path == NULL) {
            continue;
        }

        paths[index].internal_path = path->path;
        paths[index].recursion_level = path->recursion_level;
        paths[index].max_files = CONTAINER_BASELINE_MAX_FILES_PER_PATH;

        /* Reuse FIM's own size limit rather than a private literal: files above
         * it are not hashed at all, exactly as the host walk treats them. */
        paths[index].max_hash_bytes = host_config()->file_max_size;

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

static size_t container_docs_refused = 0;

void fim_container_doc_budget_report(void)
{
    synced_docs_lock();
    const size_t refused = container_docs_refused;
    container_docs_refused = 0;
    synced_docs_unlock();
    if (refused > 0) {
        mwarn("Container FIM: %zu reporting attempt(s) withheld by fim.container_file_limit. "
              "Their file state remains stored locally; reporting resumes when space is available.",
              refused);
    }
}

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

void fim_report_container_baseline_result(int baselined,
                                          size_t rows,
                                          size_t refused,
                                          size_t partial,
                                          size_t stale,
                                          size_t known,
                                          size_t withheld)
{
    minfo("Container FIM baseline finished: %d container(s) scanned, %zu row(s) stored, "
          "%zu row(s) refused, %zu partial scan(s), %zu stale container(s) cleaned, "
          "%zu container(s) known.",
          baselined, rows, refused, partial, stale, known);

    fim_container_doc_budget_report();

    if (refused > 0) {
        /* The number an operator needs to act on, at a level they will see.
         * A row that was offered and turned away is file state the manager will
         * never receive, and the only previous trace of it was this same line
         * reporting the rows OFFERED as though they had all been kept. */
        mwarn("Container FIM: %zu row(s) could not be stored and will not reach the manager. "
              "Raise <container_security><syscheck><file_limit> for a single container's share, "
              "or <syscheck><file_limit><entries> for the agent's whole file database.",
              refused);

        /* Upward, following the only pattern that exists for telling a manager
         * an agent is saturated -- fim_check_db_state()'s "wazuh: FIM DB:"
         * message on LOCALFILE_MQ (fim_scan.c).
         *
         * Worth knowing before relying on it: that pattern has NO decoder or
         * rule in this repository, so this reaches the manager's archives and
         * nothing acts on it. Making it actionable is ruleset work on the
         * server side, not something the agent can do alone. It is sent anyway
         * because an operator grepping archives can find it, and because a
         * saturated agent that says nothing upward is how this defect went
         * unnoticed in the first place. */
        cJSON* event = cJSON_CreateObject();

        if (event != NULL) {
            cJSON_AddStringToObject(event, "fim_db_table", "file_entry");
            cJSON_AddStringToObject(event, "scope", "container");
            cJSON_AddStringToObject(event, "alert_type", "rows_refused");
            cJSON_AddNumberToObject(event, "rows_refused", (double)refused);
            cJSON_AddNumberToObject(event, "rows_stored", (double)rows);
            cJSON_AddNumberToObject(event, "container_file_entry_limit",
                                    fim_container_baseline_row_limit());
            cJSON_AddNumberToObject(event, "file_entry_limit",
                                    fim_container_baseline_node_row_limit());

            char* plain = cJSON_PrintUnformatted(event);

            if (plain != NULL) {
                char alert_msg[OS_SIZE_256];
                snprintf(alert_msg, OS_SIZE_256, "wazuh: FIM DB: %s", plain);
                if (g_host.send_log != NULL) {
                    g_host.send_log(alert_msg);
                }
                os_free(plain);
            }

            cJSON_Delete(event);
        }
    }

    if (withheld > 0) {
        /* Which containers the manager is NOT being told about. Silence here
         * reads, to anyone looking at the dashboard, exactly like a node that
         * runs only the containers it can see -- so the count has to be said
         * out loud even though nothing is wrong. */
        minfo("Container FIM: %zu of %zu container(s) are reporting; %zu withheld by containers.synced_limit. "
              "The withheld containers are still monitored and their file state is still stored locally -- "
              "it is not sent to the manager. Raise the limit to report more.",
              known - withheld, known, withheld);

        /* Upward, in the same envelope and with the same caveat as the refusal
         * above: no decoder or rule exists for it in this repository, so it
         * reaches archives and nothing acts on it. Sent because an agent whose
         * coverage is deliberately partial should not be the only thing that
         * knows. */
        cJSON* event = cJSON_CreateObject();

        if (event != NULL) {
            cJSON_AddStringToObject(event, "fim_db_table", "file_entry");
            cJSON_AddStringToObject(event, "scope", "container");
            cJSON_AddStringToObject(event, "alert_type", "containers_withheld");
            cJSON_AddNumberToObject(event, "containers_withheld", (double)withheld);
            cJSON_AddNumberToObject(event, "containers_reporting", (double)(known - withheld));
            cJSON_AddNumberToObject(event, "containers_known", (double)known);

            char* plain = cJSON_PrintUnformatted(event);

            if (plain != NULL) {
                char alert_msg[OS_SIZE_256];
                snprintf(alert_msg, OS_SIZE_256, "wazuh: FIM DB: %s", plain);
                if (g_host.send_log != NULL) {
                    g_host.send_log(alert_msg);
                }
                os_free(plain);
            }

            cJSON_Delete(event);
        }
    }

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

int fim_container_baseline_row_limit(void)
{
    return (host_config() != NULL) ? host_config()->container_file_entry_limit : 0;
}

int fim_container_baseline_node_row_limit(void)
{
    return (host_config() != NULL) ? host_config()->file_entry_limit : 0;
}

void fim_container_baseline_rate_limit(void)
{
    if (g_host.rate_limit == NULL) {
        /* Unset means nobody registered it -- the walk runs unthrottled rather
         * than not at all. Failing open here matches the rest of this path: a
         * missing budget costs I/O, a refused walk costs coverage. */
        return;
    }

    g_host.rate_limit();
}

void fim_compute_row_checksum(const char* row_json, char out_sha1[41])
{
    if (row_json == NULL || out_sha1 == NULL) {
        return;
    }
    OS_SHA1_Str(row_json, (ssize_t)strlen(row_json), out_sha1);
}

/* Per-container document counts: container id -> int*.
 *
 * PER CONTAINER is the decision (#37532 / O10), so the count has to be too. A
 * single total would let one container spend the rest's allowance and decide by
 * scan order which of them reported -- measured on a real node, one container
 * produced 25% of the node's rows.
 *
 * Guarded by synced_docs_mutex, the same lock the host counters use, so the two
 * populations cannot interleave an update. */
static OSHash* container_doc_counts = NULL;

/* Returns the container's count slot, creating it at zero, or NULL if it could
 * not be created. Caller holds synced_docs_mutex. */
static int* container_doc_count_slot(const char* container_id)
{
    if (container_doc_counts == NULL) {
        container_doc_counts = OSHash_Create();
        if (container_doc_counts == NULL) {
            return NULL;
        }
        OSHash_SetFreeDataPointer(container_doc_counts, free);
    }

    int* slot = (int*)OSHash_Get(container_doc_counts, container_id);
    if (slot != NULL) {
        return slot;
    }

    os_calloc(1, sizeof(int), slot);
    if (OSHash_Add(container_doc_counts, container_id, slot) != 2) {
        os_free(slot);
        return NULL;
    }
    return slot;
}

void fim_container_doc_budget_release(const char* container_id)
{
    if (container_id == NULL || *container_id == '\0') {
        return;
    }

    synced_docs_lock();
    if (container_doc_counts != NULL) {
        int* slot = (int*)OSHash_Delete(container_doc_counts, container_id);
        os_free(slot);
    }
    synced_docs_unlock();
}

void fim_container_doc_budget_initialize(const char* container_id)
{
    synced_docs_lock();
    const int initialized = container_doc_counts != NULL && OSHash_Get(container_doc_counts, container_id) != NULL;
    synced_docs_unlock();
    if (initialized) {
        return;
    }

    /* Read before opening a scoped transaction, never from its row callback. */
    const int count = fim_db_count_synced_container_docs(container_id);
    if (count < 0) {
        merror("Container FIM: could not initialize document count for '%s'.", container_id);
        return;
    }

    synced_docs_lock();
    if (container_doc_counts != NULL && OSHash_Get(container_doc_counts, container_id) != NULL) {
        synced_docs_unlock();
        return;
    }
    int* slot = container_doc_count_slot(container_id);
    if (slot != NULL) {
        *slot = count;
    } else {
        merror("Container FIM: could not initialize document count for '%s'.", container_id);
    }
    synced_docs_unlock();
}

/* What one listing decided, in the three states a container can actually be
 * in. NULL means "not told yet", which reads as admit-everything -- see
 * fim_container_is_admitted().
 *
 * THREE sets rather than one, because absence from the admitted set has three
 * opposite causes and silencing a container is the wrong answer to two of them:
 *
 *   refused       the cap ranked it and said no. Stays withheld.
 *   not heard of  it started after the listing was taken. Not refused at all,
 *                 and reading it as refused is what left it silent for the life
 *                 of the process -- fim_container_admission_is_stale() spots
 *                 this and the caller retakes the listing.
 *   unrankable    the connector knows it exists but cannot key it, so it never
 *                 entered the ranking the cap applies. Nothing refused it
 *                 either, and waiting for it to be keyed before deciding
 *                 anything is what froze admission for the whole node.
 *
 * The last one is why a container nobody can key must still appear in `known`:
 * leaving it out would make every one of its row batches read as stale and
 * retake the listing, which is the cost the known set exists to avoid.
 *
 * Guarded by synced_docs_mutex, like the counts above, so a reconcile cannot
 * replace the sets while a row is being decided against them. */
static OSHash* container_admitted = NULL;
static OSHash* container_known = NULL;
static OSHash* container_unkeyed = NULL;
static int container_admission_known = 0;

/* A set of container ids, or NULL when it could not be built. */
static OSHash* container_id_set(const char** container_ids, size_t count)
{
    OSHash* set = OSHash_Create();
    if (set == NULL) {
        return NULL;
    }
    OSHash_SetFreeDataPointer(set, free);

    for (size_t i = 0; i < count; ++i) {
        if (container_ids[i] == NULL || *container_ids[i] == '\0') {
            continue;
        }

        int* marker = NULL;
        os_calloc(1, sizeof(int), marker);
        *marker = 1;
        if (OSHash_Add(set, container_ids[i], marker) != 2) {
            os_free(marker);
        }
    }

    return set;
}

void fim_container_set_admission(const char** known_ids,
                                 size_t known_count,
                                 const char** admitted_ids,
                                 size_t admitted_count,
                                 const char** unkeyed_ids,
                                 size_t unkeyed_count)
{
    if ((known_ids == NULL && known_count > 0) || (admitted_ids == NULL && admitted_count > 0)
            || (unkeyed_ids == NULL && unkeyed_count > 0)) {
        return;
    }

    OSHash* known_set = container_id_set(known_ids, known_count);
    OSHash* admitted_set = container_id_set(admitted_ids, admitted_count);
    OSHash* unkeyed_set = container_id_set(unkeyed_ids, unkeyed_count);

    if (known_set == NULL || admitted_set == NULL || unkeyed_set == NULL) {
        /* Fail OPEN. A set we could not build is not grounds for silencing
         * every container -- the same reasoning as the count slot below.
         * All three or none: a known set without its admitted set would read
         * every container as refused, and without its unkeyed set every
         * container the resolver cannot key would read the same way. */
        merror("Container FIM: could not build the admitted container set; retaining previous admission.");
        if (known_set != NULL) {
            OSHash_Free(known_set);
        }
        if (admitted_set != NULL) {
            OSHash_Free(admitted_set);
        }
        if (unkeyed_set != NULL) {
            OSHash_Free(unkeyed_set);
        }
        return;
    }

    synced_docs_lock();
    OSHash* previous_known = container_known;
    OSHash* previous_admitted = container_admitted;
    OSHash* previous_unkeyed = container_unkeyed;
    container_known = known_set;
    container_admitted = admitted_set;
    container_unkeyed = unkeyed_set;
    container_admission_known = 1;
    synced_docs_unlock();

    if (previous_known != NULL) {
        OSHash_Free(previous_known);
    }
    if (previous_admitted != NULL) {
        OSHash_Free(previous_admitted);
    }
    if (previous_unkeyed != NULL) {
        OSHash_Free(previous_unkeyed);
    }

    fim_container_reconcile_admission();
}

void fim_container_set_admitted(const char** container_ids, size_t count)
{
    /* Everything this caller knows of, it admits -- so nothing is unrankable. */
    fim_container_set_admission(container_ids, count, container_ids, count, NULL, 0);
}

int fim_container_admission_is_stale(const char* container_id)
{
    if (container_id == NULL || *container_id == '\0') {
        return 0; /* Not a container row; no admission to be stale about. */
    }

    synced_docs_lock();
    /* Before the first listing nothing is stale: everything reports already,
     * so there is no silence to break. */
    const int stale = container_admission_known != 0 && container_known != NULL
                      && OSHash_Get(container_known, container_id) == NULL;
    synced_docs_unlock();

    return stale;
}

int fim_container_is_admitted(const char* container_id)
{
    if (container_id == NULL || *container_id == '\0') {
        return 1; /* Not a container row; nothing to withhold. */
    }

    synced_docs_lock();
    /* Admitted outright, or never ranked in the first place.
     *
     * A container the connector knows of but cannot key is in `known` and in
     * neither `admitted` nor the ranking that produced it: the cap weighs
     * containers the connector can publish, and this one it cannot. Reading
     * that as a refusal withheld the container's documents on the strength of
     * a decision that was never taken about it -- and because the whole
     * snapshot used to wait for every container to be keyed, one that never is
     * froze admission for the node and silenced every container that started
     * afterwards (#37532). Fail open here, which is the same direction as the
     * not-told-yet case above it, and leave the cap to rank what it can. */
    const int admitted = (container_admission_known == 0 || container_admitted == NULL)
                         ? 1
                         : (OSHash_Get(container_admitted, container_id) != NULL
                            || (container_unkeyed != NULL
                                && OSHash_Get(container_unkeyed, container_id) != NULL));
    synced_docs_unlock();

    return admitted;
}

/* Applies container_budget_decide() to one row, owning the lock and the count
 * it decides against. The rule itself lives in container_doc_budget.h so it can
 * be tested without a daemon; this is only the plumbing. */
static int container_row_sync_flag(const cJSON* row, int operation)
{
    const cJSON* id_json = cJSON_GetObjectItem(row, "container_id");
    const int has_container = (id_json != NULL && cJSON_IsString(id_json)
                               && id_json->valuestring != NULL && *id_json->valuestring != '\0');

    /* Whether this container may report AT ALL, which is a different question
     * from how much it may report -- and it is asked first, because it holds
     * even when no document limit is configured. Putting it after the limit
     * check below would make the container cap silently depend on
     * container_file_limit being set, which is not what configures it.
     *
     * Deletes are exempt: container_budget_decide() answers a delete with the
     * row's own stored flag, so a row the manager never saw still reports no
     * deletion, and one it did see is still withdrawn. Suppressing that would
     * strand the row on the manager with nothing left to remove it. */
    const cJSON* sync_json = cJSON_GetObjectItem(row, "sync");
    const int stored_sync = cJSON_IsNumber(sync_json) ? sync_json->valueint : 0;

    if (has_container && operation != OPERATION_DELETE
            && !fim_container_is_admitted(id_json->valuestring)) {
        /* Withhold the document -- but a row the manager ALREADY holds may not
         * be demoted on the strength of this check.
         *
         * Returning 0 writes that 0 to the stored column, and it is a 1 -> 0
         * with no DELETE behind it: updateContainerReporting() retracts by
         * selecting sync=1, so the row drops out of the only query that could
         * ever withdraw it and the manager keeps the document for good. The
         * budget never does this -- container_budget_decide() keeps a modified
         * reported row reported -- so this gate was the one way it could
         * happen, and admission now changes at run time from the resolver
         * thread, so a file event lands inside that window routinely
         * (#37532 / R6, and N7 of the previous round).
         *
         * Leave the column alone instead. The reconciliation that follows the
         * de-admission still sees sync=1 and retracts the row properly, which
         * is the DELETE that pairs the demotion. */
        return (stored_sync == 1) ? FIM_CONTAINER_SYNC_UNCHANGED : 0;
    }

    const int limit = (host_config() != NULL) ? host_config()->container_file_limit : 0;

    if (has_container && operation == OPERATION_DELETE && stored_sync == 0) {
        return 0;
    }

    if (limit <= 0) {
        return 1; /* Unlimited: today's behaviour, and the default. */
    }

    if (!has_container) {
        /* No container to charge it to. Report it rather than withhold it: a row
         * we cannot attribute is not evidence that a budget was exceeded. */
        return 1;
    }

    /* The stored row's own flag, where DBSync gave us one: absent on a fresh
     * insert, present on rows a scoped transaction reports as deleted. */
    /* Check-then-apply must be atomic for the same reason it must be on the
     * host path: the scheduled baseline and an event-driven reconcile reach
     * this concurrently. */
    synced_docs_lock();
    int* slot = container_doc_count_slot(id_json->valuestring);
    int granted = 1;

    if (slot != NULL) {
        const container_budget_decision_t decision =
            container_budget_decide(limit, *slot, stored_sync,
                                    operation == OPERATION_DELETE);
        *slot += decision.count_delta;
        if (*slot < 0) {
            *slot = 0;
        }
        granted = decision.sync_flag;
        if (!granted && operation != OPERATION_DELETE) {
            ++container_docs_refused;
        }
    }
    /* slot == NULL means the table could not be grown. Fail OPEN: a counter we
     * could not keep is not grounds for withholding a container's state. */
    synced_docs_unlock();

    return granted;
}

int fim_persist_baseline_row(const char* id, int operation, const char* index, const char* json, uint64_t version)
{
    if (g_host.validate_and_persist == NULL) {
        merror("Container FIM: persistence API is not registered.");
        return -1;
    }
    cJSON* msg = cJSON_Parse(json);
    if (msg == NULL) {
        mdebug1("Container FIM baseline: dropping row '%s' - failed to parse JSON.", id);
        return -1;
    }

    /* BEFORE normalisation: the stored row's own "sync" column is what the
     * accounting reads, and normalisation reshapes the row for the schema. */
    const int sync_flag = container_row_sync_flag(msg, operation);

    /* The integrity check compares the agent's checksum over the stored rows'
     * "checksum" column with the manager's over each document's
     * checksum.hash.sha1, so the document must carry the row checksum, as host
     * FIM documents do. Normalisation deletes it, so keep a copy first. */
    char* row_checksum = NULL;
    const char* stored_checksum = cJSON_GetStringValue(cJSON_GetObjectItem(msg, "checksum"));
    if (stored_checksum != NULL && *stored_checksum != '\0') {
        os_strdup(stored_checksum, row_checksum);
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

        if (hash_obj != NULL && row_checksum != NULL) {
            cJSON_DeleteItemFromObject(hash_obj, "sha1");
            cJSON_AddStringToObject(hash_obj, "sha1", row_checksum);
        }
    }
    os_free(row_checksum);

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
    /* Not "was it persisted": validate_and_persist() returns whether the document
     * passed its index schema, and a row the budget withheld passes and returns
     * true. False means the document was rejected, which is the one case where the
     * decision below must not be written back. */
    const bool validated = g_host.validate_and_persist(msg,
                                                       id,
                                                       (Operation_t)operation,
                                                       index,
                                                       version,
                                                       item_desc,
                                                       false,
                                                       NULL,
                                                       NULL,
                                                       sync_flag);

    if (!validated) {
        /* The schema failure itself is already logged, with its errors, by
         * validate_and_persist(). What is not logged anywhere else is that the
         * budget charged for a row the manager never saw, so say that and undo it:
         * a slot spent on a rejected document is a slot the cap can never return. */
        cJSON* original = cJSON_Parse(json);
        const cJSON* stored = cJSON_GetObjectItem(original, "sync");
        const int previous_sync = cJSON_IsNumber(stored) ? stored->valueint : 0;
        const char* container_id = cJSON_GetStringValue(cJSON_GetObjectItem(original, "container_id"));
        mdebug1("Container FIM: returning the budget charged for rejected row '%s'.", id);
        if (container_id && host_config() && host_config()->container_file_limit > 0) {
            const int delta = operation == OPERATION_DELETE ? (previous_sync ? -1 : 0)
                              : (sync_flag && !previous_sync ? 1 : 0);
            synced_docs_lock();
            int* slot = container_doc_counts ? OSHash_Get(container_doc_counts, container_id) : NULL;
            if (slot) {
                *slot -= delta;
            }
            synced_docs_unlock();
        }
        cJSON_Delete(original);
        cJSON_Delete(msg);
        return -1;
    }

    cJSON_Delete(msg);
    return sync_flag;
}

int fim_container_recover_row(const cJSON* row)
{
    const char* container_id = cJSON_GetStringValue(cJSON_GetObjectItem(row, "container_id"));
    const char* path = cJSON_GetStringValue(cJSON_GetObjectItem(row, "path"));
    const cJSON* version = cJSON_GetObjectItem(row, "version");

    if (container_id == NULL || *container_id == '\0' || path == NULL || !cJSON_IsNumber(version)) {
        mdebug1("Container FIM recovery: skipping a row with missing fields.");
        return -1;
    }

    /* The counterpart of recovery's host orphan guard, resolved against the
     * container list for the reason fim_container_configuration_directory()
     * gives. */
    if (fim_container_configuration_directory(path) == NULL) {
        mdebug2("Container FIM recovery: skipping '%s:%s', no longer covered by the container configuration.",
                container_id, path);
        return 0;
    }

    char* json = cJSON_PrintUnformatted(row);
    if (json == NULL) {
        return -1;
    }

    const size_t id_len = strlen(container_id) + strlen(path) + 2;
    char* id = NULL;
    os_calloc(id_len, sizeof(char), id);
    snprintf(id, id_len, "%s:%s", container_id, path);

    /* A sync=1 row is a refresh to the document budget, so re-sending it
     * charges nothing; a container that lost admission is still withheld. */
    const int result = fim_persist_baseline_row(id,
                                                OPERATION_CREATE,
                                                "wazuh-states-fim-files",
                                                json,
                                                (uint64_t)cJSON_GetNumberValue(version));
    os_free(id);
    cJSON_free(json);

    /* Recovery is the one caller for which "withheld" does NOT mean the manager
     * may still hold the document: it re-sends into an index the manager has
     * just cleared, so a row withheld here is a row the manager does not have,
     * and sync=0 is simply the truth. FIM_CONTAINER_SYNC_UNCHANGED exists to
     * protect a document that is still out there, which on this path there is
     * not -- and passing it up would make recovery log a failure and demote the
     * row anyway, for a case that is neither a failure nor a surprise. */
    return (result == FIM_CONTAINER_SYNC_UNCHANGED) ? 0 : result;
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
        container_notify_scan = (host_config() != NULL && host_config()->notify_first_scan) ? 1 : 0;
    }

    return container_notify_scan;
}

void fim_container_baseline_first_scan_done(void)
{
    container_notify_scan = 1;
}

/* Lifts the container_json column onto `target` as the top-level "container"
 * block, Kubernetes context nested inside it at container.kubernetes (D15).
 * Same placement normalize_container_fim_row() uses for the stateful document,
 * so an analyst reads the same field names on both sides. */
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

        if (g_host.calculate_dbsync_difference != NULL) {
            g_host.calculate_dbsync_difference(config, old_data, changed_attributes, old_attributes);
        }

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
    cJSON* file_stateless = (operation == OPERATION_DELETE || g_host.attributes_json == NULL)
        ? cJSON_CreateObject()
        : g_host.attributes_json(row_data, NULL, config);
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

    if (g_host.send_event != NULL) {
        g_host.send_event(stateless_event);
    }

    cJSON_Delete(stateless_event);
}
