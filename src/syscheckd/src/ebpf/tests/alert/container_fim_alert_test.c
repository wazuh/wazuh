/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * The container FIM stateless alert (#37532, WP2 of 14-spike-integration-plan).
 *
 * Container rows were persisted into wazuh-states-fim-files and never alerted
 * on, so a file changing inside a container produced no FIM alert at all. This
 * pins the alert now that it exists:
 *
 *   1. Nothing is sent before the first-scan boundary. The whole-node baseline
 *      inserts EVERY file in EVERY container; alerting on all of them is a
 *      startup flood, not information. This case must run FIRST, because
 *      fim_container_baseline_first_scan_done() is one-way.
 *   2. A create carries attributes and no changed_fields.
 *   3. A modify carries changed_fields plus the previous values.
 *   4. A delete carries path and mode only — the row DBSync hands back is the
 *      state the file HAD, and reporting it as current would be a lie.
 *   5. A change only in a column no configured check covers sends nothing.
 *   6. A container row resolves against the CONTAINER-tagged <directories>
 *      entry even when an untagged host-only entry is a longer prefix. That is
 *      the whole reason fim_container_configuration_directory() exists rather
 *      than a call to fim_configuration_directory().
 *
 * Written in C, not C++, on purpose: syscheck.h has no extern "C" guard of its
 * own and reaches real C++ headers (<atomic>) transitively, so a C++ test
 * cannot wrap it and cannot leave it unwrapped either — see the include-ordering
 * trap recorded in 12 §12.13 step 4. In C the question does not arise.
 *
 * Standalone, for the same reason as tests/txn/: it must be runnable wherever
 * the tree builds. `make check` in this directory.
 *
 * send_syscheck_msg(), validate_and_persist_fim_event() and check_max_fps() are
 * stubbed below so the alert can be inspected instead of queued. Everything the
 * alert's SHAPE comes from is real: fim_attributes_json() and
 * fim_calculate_dbsync_difference() are linked out of the built syscheckd
 * library, which is the point — an alert that drifts from a host FIM alert is
 * the defect this test exists to catch.
 */

#include "container_baseline_fim_bridge.h"
#include "shared.h"
#include "syscheck.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------------------------------------------------------------- stubs ---- */

/* syscheckd's global configuration, normally defined in syscheck.c. Defined
 * here so run_check.o / syscheck.o are not pulled out of the archive. */
syscheck_config syscheck;

#define MAX_CAPTURED 16
static char* g_sent[MAX_CAPTURED];
static size_t g_sent_count;

void send_syscheck_msg(const cJSON* msg)
{
    if (g_sent_count >= MAX_CAPTURED) {
        return;
    }
    g_sent[g_sent_count++] = cJSON_PrintUnformatted(msg);
}

bool validate_and_persist_fim_event(const cJSON* stateful_event,
                                    const char* id,
                                    Operation_t operation,
                                    const char* index,
                                    uint64_t document_version,
                                    const char* item_description,
                                    bool mark_for_deletion,
                                    OSList* failed_list,
                                    void* failed_item_data,
                                    int sync_flag)
{
    (void)stateful_event; (void)id; (void)operation; (void)index;
    (void)document_version; (void)item_description; (void)mark_for_deletion;
    (void)failed_list; (void)failed_item_data; (void)sync_flag;
    return true;
}

void check_max_fps(void)
{
}

/* -------------------------------------------------------------- harness ---- */

static int g_failures = 0;

static void Check(int condition, const char* what)
{
    printf("  %-70s %s\n", what, condition ? "OK" : "FAIL");
    if (!condition) {
        ++g_failures;
    }
}

static cJSON* g_parsed;

/* data.<section>[.<key>] of the most recent alert; key may be NULL. */
static cJSON* AlertNode(const char* section, const char* key)
{
    cJSON_Delete(g_parsed);
    g_parsed = (g_sent_count == 0) ? NULL : cJSON_Parse(g_sent[g_sent_count - 1]);

    cJSON* data = cJSON_GetObjectItem(g_parsed, "data");
    cJSON* node = cJSON_GetObjectItem(data, section);

    return (key == NULL) ? node : cJSON_GetObjectItem(node, key);
}

static int AlertStringIs(const char* section, const char* key, const char* expected)
{
    const char* value = cJSON_GetStringValue(AlertNode(section, key));
    return value != NULL && strcmp(value, expected) == 0;
}

/* ------------------------------------------------------------- fixtures ---- */

/* One dbsync row in the column shape container_baseline emits. */
static cJSON* Row(const char* path, int size, const char* sha256)
{
    cJSON* row = cJSON_CreateObject();
    cJSON_AddStringToObject(row, "path", path);
    cJSON_AddStringToObject(row, "container_id", "cid-a");
    cJSON_AddStringToObject(row, "container_json",
                            "{\"container\":{\"id\":\"cid-a\",\"name\":\"web\"},"
                            "\"kubernetes\":{\"pod\":{\"name\":\"web-0\"}}}");
    cJSON_AddNumberToObject(row, "size", size);
    cJSON_AddStringToObject(row, "permissions", "rw-r--r--");
    cJSON_AddStringToObject(row, "uid", "0");
    cJSON_AddStringToObject(row, "gid", "0");
    cJSON_AddStringToObject(row, "owner", "root");
    cJSON_AddStringToObject(row, "group_", "root");
    cJSON_AddNumberToObject(row, "mtime", 1757000000);
    cJSON_AddStringToObject(row, "hash_sha256", sha256);
    cJSON_AddStringToObject(row, "checksum", "0000000000000000000000000000000000000000");
    cJSON_AddNumberToObject(row, "version", 1);
    return row;
}

/* Built by hand rather than with fim_create_directory(), which lives in
 * libconfig.a alongside every wodle's parser and drags all of them into the
 * link. directory_t is a plain struct and only these four fields matter here. */
static directory_t* Directory(const char* path, int options, const char* tag)
{
    directory_t* dir = (directory_t*)calloc(1, sizeof(directory_t));

    dir->path = strdup(path);
    dir->options = options;
    dir->tag = (tag == NULL) ? NULL : strdup(tag);
    dir->recursion_level = 8;
    dir->diff_size_limit = -1;

    return dir;
}

static void ConfigureDirectories(void)
{
    syscheck.directories = OSList_Create();

    /* Container-tagged: size + sha256 + mtime. */
    OSList_AddData(syscheck.directories,
                   Directory("/etc", CHECK_SIZE | CHECK_SHA256SUM | CHECK_MTIME, "container,prod"));

    /* A LONGER prefix, host-only: no "container" tag and a different check set.
     * fim_configuration_directory() would pick this one for /etc/ssl/cert.pem. */
    OSList_AddData(syscheck.directories, Directory("/etc/ssl", CHECK_PERM, NULL));
}

/* ---------------------------------------------------------------- cases ---- */

/* MUST run first: the first-scan latch is one-way. */
static void CaseBaselineIsSilent(void)
{
    printf("case 1: the whole-node baseline does not alert\n");

    cJSON* row = Row("/etc/profile", 100, "aaa");
    fim_send_container_stateless_event(row, NULL, OPERATION_CREATE, CB_FIM_ORIGIN_SCAN);
    cJSON_Delete(row);

    Check(g_sent_count == 0, "no alert before the first-scan boundary");

    /* The boundary. fim_container_events_release() calls this for real. */
    fim_container_baseline_first_scan_done();
}

static void CaseCreate(void)
{
    printf("case 2: a create alerts, with attributes and no changed_fields\n");

    const size_t before = g_sent_count;
    cJSON* row = Row("/etc/e2e-new.conf", 100, "aaa");
    fim_send_container_stateless_event(row, NULL, OPERATION_CREATE, CB_FIM_ORIGIN_EVENT);
    cJSON_Delete(row);

    Check(g_sent_count == before + 1, "one alert sent");
    Check(AlertStringIs("event", "type", "added"), "event.type == added");
    Check(AlertStringIs("file", "path", "/etc/e2e-new.conf"), "data.file.path");
    Check(AlertStringIs("file", "mode", "whodata"), "data.file.mode == whodata (event-driven)");
    Check(AlertStringIs("file", "tags", "container,prod"), "data.file.tags from the tagged entry");
    Check(AlertNode("event", "changed_fields") == NULL, "no changed_fields on a create");

    cJSON* size = AlertNode("file", "size");
    Check(cJSON_IsNumber(size) && size->valueint == 100, "data.file.size == 100");

    cJSON* hash = AlertNode("file", "hash");
    Check(cJSON_GetObjectItem(hash, "sha256") != NULL,
          "data.file.hash.sha256 (CHECK_SHA256SUM is configured)");

    /* The container-scope columns are enrichment, not file attributes. */
    Check(AlertStringIs("container", "name", "web"), "data.container.name from container_json");
    Check(AlertNode("kubernetes", "pod") != NULL, "data.kubernetes from container_json");
    Check(AlertNode("file", "container_id") == NULL, "container_id is NOT a file attribute");
}

static void CaseModify(void)
{
    printf("case 3: a modify alerts, with changed_fields and previous values\n");

    const size_t before = g_sent_count;
    cJSON* row = Row("/etc/profile", 240, "bbb");

    /* DBSync's "old" object carries exactly the columns that changed. */
    cJSON* old_data = cJSON_CreateObject();
    cJSON_AddNumberToObject(old_data, "size", 100);
    cJSON_AddStringToObject(old_data, "hash_sha256", "aaa");

    fim_send_container_stateless_event(row, old_data, OPERATION_MODIFY, CB_FIM_ORIGIN_EVENT);
    cJSON_Delete(old_data);
    cJSON_Delete(row);

    Check(g_sent_count == before + 1, "one alert sent");
    Check(AlertStringIs("event", "type", "modified"), "event.type == modified");

    cJSON* changed = AlertNode("event", "changed_fields");
    Check(cJSON_IsArray(changed), "event.changed_fields is an array");

    int has_size = 0;
    int has_sha256 = 0;
    cJSON* item = NULL;
    cJSON_ArrayForEach(item, changed) {
        const char* field = cJSON_GetStringValue(item);
        if (field != NULL && strcmp(field, "file.size") == 0) {
            has_size = 1;
        }
        if (field != NULL && strcmp(field, "file.hash.sha256") == 0) {
            has_sha256 = 1;
        }
    }
    Check(has_size, "changed_fields contains file.size");
    Check(has_sha256, "changed_fields contains file.hash.sha256");

    cJSON* previous = AlertNode("file", "previous");
    cJSON* prev_size = cJSON_GetObjectItem(previous, "size");
    Check(prev_size != NULL && prev_size->valueint == 100, "data.file.previous.size == 100");

    cJSON* now_size = AlertNode("file", "size");
    Check(now_size != NULL && now_size->valueint == 240, "data.file.size == 240 (the new value)");
}

static void CaseDelete(void)
{
    printf("case 4: a delete alerts with path and mode only\n");

    const size_t before = g_sent_count;
    cJSON* row = Row("/etc/issue", 100, "aaa");
    fim_send_container_stateless_event(row, NULL, OPERATION_DELETE, CB_FIM_ORIGIN_SCAN);
    cJSON_Delete(row);

    Check(g_sent_count == before + 1, "one alert sent");
    Check(AlertStringIs("event", "type", "deleted"), "event.type == deleted");
    Check(AlertStringIs("file", "path", "/etc/issue"), "data.file.path");
    Check(AlertStringIs("file", "mode", "scheduled"), "data.file.mode == scheduled (walk-driven)");
    Check(AlertNode("file", "size") == NULL, "no size on a delete");
    Check(AlertNode("file", "hash") == NULL, "no hash on a delete");
    Check(AlertNode("container", "name") != NULL, "the container block is still attached");
}

static void CaseUncheckedColumnIsSilent(void)
{
    printf("case 5: a change in an unchecked column sends nothing\n");

    const size_t before = g_sent_count;
    cJSON* row = Row("/etc/profile", 240, "bbb");

    /* CHECK_PERM and CHECK_OWNER are not set on the /etc entry, so neither of
     * these reaches changed_fields and there is nothing to report. */
    cJSON* old_data = cJSON_CreateObject();
    cJSON_AddStringToObject(old_data, "permissions", "rwxr-xr-x");
    cJSON_AddStringToObject(old_data, "owner", "nobody");

    fim_send_container_stateless_event(row, old_data, OPERATION_MODIFY, CB_FIM_ORIGIN_EVENT);
    cJSON_Delete(old_data);
    cJSON_Delete(row);

    Check(g_sent_count == before, "no alert with an empty changed_fields");
}

static void CaseTaggedEntryWinsOverLongerHostEntry(void)
{
    printf("case 6: a container row resolves against the container-tagged entry\n");

    const size_t before = g_sent_count;
    cJSON* row = Row("/etc/ssl/cert.pem", 512, "ccc");
    fim_send_container_stateless_event(row, NULL, OPERATION_CREATE, CB_FIM_ORIGIN_EVENT);
    cJSON_Delete(row);

    Check(g_sent_count == before + 1, "one alert sent");
    Check(AlertStringIs("file", "tags", "container,prod"),
          "took /etc's tag, not /etc/ssl's (untagged)");

    /* /etc checks size+sha256, /etc/ssl checks permissions. Which attributes
     * appear is the observable proof of which entry was resolved. */
    Check(AlertNode("file", "size") != NULL, "size present (from /etc's CHECK_SIZE)");
    Check(AlertNode("file", "permissions") == NULL, "permissions absent (/etc/ssl not used)");
}

int main(void)
{
    ConfigureDirectories();

    CaseBaselineIsSilent();
    CaseCreate();
    CaseModify();
    CaseDelete();
    CaseUncheckedColumnIsSilent();
    CaseTaggedEntryWinsOverLongerHostEntry();

    printf("\n%s\n", g_failures == 0 ? "ALL OK" : "FAILURES");
    return g_failures == 0 ? 0 : 1;
}
