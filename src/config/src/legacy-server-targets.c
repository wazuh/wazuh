/* Copyright (C) Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "legacy-server-targets.h"
#include "legacy-target-name.h"

/* Room for the list of dropped targets in the warning. A 4.x failover list is a handful
 * of addresses; whatever does not fit is left out and the list ends in ", ...". */
#define LEGACY_TARGETS_LIST_SIZE OS_SIZE_1024

/* Kept free at the end of the list, so the cut mark always fits whole. */
static const char LEGACY_TARGETS_CUT[] = ", ...";

void w_legacy_targets_add(w_legacy_targets_t *targets, const char *value, bool is_endpoint)
{
    w_legacy_target_t *target = NULL;

    os_realloc(targets->items, (targets->count + 1) * sizeof(w_legacy_target_t), targets->items);
    target = &targets->items[targets->count++];
    os_strdup(value, target->value);
    w_legacy_name_target(value, is_endpoint, &target->dialed, &target->key);
    target->is_endpoint = is_endpoint;
}

/* Last match from the end: an <endpoint> carries the whole target, so it wins over any
 * <address>, wherever it appears. */
static bool w_legacy_targets_find_last(const w_legacy_targets_t *targets, bool is_endpoint,
                                       size_t *index)
{
    for (size_t i = targets->count; i > 0; i--) {
        if (targets->items[i - 1].is_endpoint == is_endpoint) {
            *index = i - 1;
            return true;
        }
    }

    return false;
}

bool w_legacy_targets_chosen(const w_legacy_targets_t *targets, size_t *index)
{
    return w_legacy_targets_find_last(targets, true, index) ||
           w_legacy_targets_find_last(targets, false, index);
}

/* A target already in the list, or the one in use, adds nothing to the warning. Compared
 * by key, so by what the agent would dial, not by how it is written. */
static bool w_legacy_targets_is_repeat(const w_legacy_targets_t *targets, size_t i,
                                       const char *in_use)
{
    if (strcmp(targets->items[i].key, in_use) == 0) {
        return true;
    }

    for (size_t j = 0; j < i; j++) {
        if (strcmp(targets->items[j].key, targets->items[i].key) == 0) {
            return true;
        }
    }

    return false;
}

/* Append ", 'value'" (no comma for the first one) to list, if it fits next to the room
 * kept for the cut mark. */
static bool w_legacy_targets_append(char *list, size_t *len, const char *value)
{
    const char *separator = (*len > 0) ? ", " : "";
    const size_t needed = strlen(separator) + strlen(value) + 2;

    if (*len + needed + sizeof(LEGACY_TARGETS_CUT) > LEGACY_TARGETS_LIST_SIZE) {
        return false;
    }

    *len += (size_t)snprintf(list + *len, LEGACY_TARGETS_LIST_SIZE - *len, "%s'%s'", separator, value);
    return true;
}

/* Quote every target other than the one whose key is in_use, once each. A value too long to fit is left out
 * and the next ones are still tried, so one long value cannot hide the others.
 * Returns false when there is nothing to list. */
static bool w_legacy_targets_list(const w_legacy_targets_t *targets, const char *in_use,
                                  char list[LEGACY_TARGETS_LIST_SIZE])
{
    size_t len = 0;
    bool any = false;
    bool cut = false;

    list[0] = '\0';

    for (size_t i = 0; i < targets->count; i++) {
        if (!w_legacy_targets_is_repeat(targets, i, in_use)) {
            any = true;
            cut |= !w_legacy_targets_append(list, &len, targets->items[i].dialed);
        }
    }

    if (cut) {
        snprintf(list + len, LEGACY_TARGETS_LIST_SIZE - len, "%s", (len > 0) ? LEGACY_TARGETS_CUT : "...");
    }

    return any;
}

void w_legacy_targets_warn_ignored(const w_legacy_targets_t *targets, size_t chosen)
{
    const w_legacy_target_t *used = &targets->items[chosen];
    char list[LEGACY_TARGETS_LIST_SIZE];

    if (w_legacy_targets_list(targets, used->key, list)) {
        mwarn("The legacy <client> block names more than one manager, and only one is "
              "supported. Using '%s', ignoring %s.", used->dialed, list);
    }
}

void w_legacy_targets_warn_skipped(const w_legacy_targets_t *targets, const agent_server *in_use)
{
    char list[LEGACY_TARGETS_LIST_SIZE];
    char *dialed = NULL;
    char *key = NULL;

    w_legacy_name_server(in_use, &dialed, &key);

    if (w_legacy_targets_list(targets, key, list)) {
        mwarn("<server> inside the legacy <client> block is ignored: the manager is already "
              "set to '%s'. Ignoring %s.", dialed, list);
    }

    os_free(dialed);
    os_free(key);
}

void w_legacy_targets_defer(agent *logr, w_legacy_targets_t *targets, int managers)
{
    w_legacy_targets_t *deferred = logr->legacy_deferred;

    if (!deferred) {
        os_calloc(1, sizeof(w_legacy_targets_t), deferred);
        logr->legacy_deferred = deferred;
    }

    os_realloc(deferred->items, (deferred->count + targets->count + 1) * sizeof(w_legacy_target_t),
               deferred->items);
    memcpy(deferred->items + deferred->count, targets->items, targets->count * sizeof(w_legacy_target_t));
    deferred->count += targets->count;
    logr->legacy_deferred_managers = managers;

    os_free(targets->items);
    targets->count = 0;
}

void w_legacy_targets_report_deferred(agent *logr)
{
    if (!logr->legacy_deferred || --logr->legacy_deferred_managers > 0) {
        return;
    }

    w_legacy_targets_warn_skipped(logr->legacy_deferred, &logr->server[0]);
    w_legacy_targets_free_deferred(logr);
}

void w_legacy_targets_free_deferred(agent *logr)
{
    if (logr->legacy_deferred) {
        w_legacy_targets_free(logr->legacy_deferred);
        os_free(logr->legacy_deferred);
    }

    logr->legacy_deferred_managers = 0;
}

void w_legacy_targets_free(w_legacy_targets_t *targets)
{
    for (size_t i = 0; i < targets->count; i++) {
        os_free(targets->items[i].value);
        os_free(targets->items[i].dialed);
        os_free(targets->items[i].key);
    }

    os_free(targets->items);
    targets->count = 0;
}
