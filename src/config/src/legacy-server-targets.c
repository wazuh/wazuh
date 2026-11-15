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

void w_legacy_targets_add(w_legacy_targets_t *targets, const char *value, bool is_endpoint)
{
    w_legacy_target_t *target = NULL;

    os_realloc(targets->items, (targets->count + 1) * sizeof(w_legacy_target_t), targets->items);
    target = &targets->items[targets->count++];
    os_strdup(value, target->value);
    target->is_endpoint = is_endpoint;
}

void w_legacy_targets_end_block(w_legacy_targets_t *targets)
{
    if (targets->first_block == 0) {
        targets->first_block = targets->count;
    }
}

/* An <endpoint> carries the whole target, so the last one wins over any <address>,
 * wherever it appears in the first block. */
static bool w_legacy_targets_find_last(const w_legacy_targets_t *targets, bool is_endpoint,
                                       size_t *index)
{
    for (size_t i = targets->first_block; i > 0; i--) {
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

/* A value already named, or the one in use, adds nothing to the warning. */
static bool w_legacy_targets_leaves_out(const w_legacy_targets_t *targets, size_t i, const char *except)
{
    if (except && strcmp(targets->items[i].value, except) == 0) {
        return true;
    }

    for (size_t j = 0; j < i; j++) {
        if (strcmp(targets->items[j].value, targets->items[i].value) == 0) {
            return true;
        }
    }

    return false;
}

static void w_legacy_targets_append_quoted(char **list, const char *value)
{
    wm_strcat(list, *list ? ", '" : "'", '\0');
    wm_strcat(list, value, '\0');
    wm_strcat(list, "'", '\0');
}

char *w_legacy_targets_quote(const w_legacy_targets_t *targets, const char *except)
{
    char *list = NULL;

    for (size_t i = 0; i < targets->count; i++) {
        if (!w_legacy_targets_leaves_out(targets, i, except)) {
            w_legacy_targets_append_quoted(&list, targets->items[i].value);
        }
    }

    return list;
}

void w_legacy_targets_free(w_legacy_targets_t *targets)
{
    for (size_t i = 0; i < targets->count; i++) {
        os_free(targets->items[i].value);
    }

    os_free(targets->items);
    targets->count = 0;
    targets->first_block = 0;
}
