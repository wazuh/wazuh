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
    os_realloc(targets->items, (targets->count + 1) * sizeof(w_legacy_target_t), targets->items);
    os_strdup(value, targets->items[targets->count].value);
    targets->items[targets->count].is_endpoint = is_endpoint;
    targets->count++;
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

void w_legacy_targets_free(w_legacy_targets_t *targets)
{
    for (size_t i = 0; i < targets->count; i++) {
        os_free(targets->items[i].value);
    }

    os_free(targets->items);
    targets->count = 0;
}
