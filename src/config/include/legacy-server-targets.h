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

/* One manager target written under a legacy <client><server>: the text of an <address>
 * or an <endpoint>, as written. */
typedef struct {
    char *value;
    bool is_endpoint;
} w_legacy_target_t;

/* The targets of the legacy <client> blocks, in the order they appear. 4.x read several
 * <server> blocks as a failover list; 5.x connects to one of them. */
typedef struct w_legacy_targets {
    w_legacy_target_t *items;
    size_t count;
    size_t first_block; ///< Targets of the first <client> block that named any; it decides the manager.
} w_legacy_targets_t;

/**
 * @brief Append a target. The value is copied.
 */
void w_legacy_targets_add(w_legacy_targets_t *targets, const char *value, bool is_endpoint);

/**
 * @brief Mark the end of a <client> block. The first block that named a target is the one
 *        the manager comes from; the targets of later blocks are only named in a warning.
 */
void w_legacy_targets_end_block(w_legacy_targets_t *targets);

/**
 * @brief Find the target the agent connects to: the last <endpoint>, else the last
 *        <address>, of the first <client> block that named any.
 *
 * @param index Receives the position of that target in targets->items.
 * @return false when there is no target at all.
 */
bool w_legacy_targets_chosen(const w_legacy_targets_t *targets, size_t *index);

/**
 * @brief Quote every value as written, for a warning: "'a', 'b'". Each value is named once,
 *        and `except`, the one in use, not at all.
 *
 * @param except Value left out; NULL leaves none out.
 * @return The list, allocated; NULL when nothing is left to name.
 */
char *w_legacy_targets_quote(const w_legacy_targets_t *targets, const char *except);

/**
 * @brief Release every value and reset the list.
 */
void w_legacy_targets_free(w_legacy_targets_t *targets);

#endif /* LEGACY_SERVER_TARGETS_H */
