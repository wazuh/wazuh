/* Copyright (C) Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef LEGACY_SERVER_TARGETS_H
#define LEGACY_SERVER_TARGETS_H

#include <stdbool.h>
#include <stddef.h>

/* One manager target written under a legacy <client><server>: the raw text of an
 * <address> or an <endpoint>. */
typedef struct {
    char *value;
    bool is_endpoint;
} w_legacy_target_t;

/* Every target a legacy <client> block names, in the order they appear. 4.x read
 * several <server> blocks as a failover list; 5.x connects to one of them (#37702). */
typedef struct {
    w_legacy_target_t *items;
    size_t count;
} w_legacy_targets_t;

/**
 * @brief Append a target. The value is copied.
 */
void w_legacy_targets_add(w_legacy_targets_t *targets, const char *value, bool is_endpoint);

/**
 * @brief Find the target the agent connects to: the last <endpoint>, else the last
 *        <address>.
 *
 * @param index Receives the position of that target in targets->items.
 * @return false when there is no target at all.
 */
bool w_legacy_targets_chosen(const w_legacy_targets_t *targets, size_t *index);

/**
 * @brief Release every value and reset the list.
 */
void w_legacy_targets_free(w_legacy_targets_t *targets);

#endif /* LEGACY_SERVER_TARGETS_H */
