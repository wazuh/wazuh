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

#include "client-config.h"

/* One manager target written under a legacy <client><server>: the raw text of an
 * <address> or an <endpoint>, how the warnings name it, and the key two targets are
 * compared by (see legacy-target-name.h). */
typedef struct {
    char *value;
    char *dialed;
    char *key;
    bool is_endpoint;
} w_legacy_target_t;

/* Every target a legacy <client> block names, in the order they appear. 4.x read
 * several <server> blocks as a failover list; 5.x connects to one of them (#37702). */
typedef struct w_legacy_targets {
    w_legacy_target_t *items;
    size_t count;
} w_legacy_targets_t;

/**
 * @brief Append a target. The value is copied, and parsed without logging to name it.
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
 * @brief Warn about the targets dropped in favour of the chosen one, naming both.
 *
 * Targets are compared by what the agent would dial, so the same manager written twice, or
 * as an <address> and an <endpoint>, is named once and never as both used and ignored.
 * Nothing is logged when no other target is left.
 */
void w_legacy_targets_warn_ignored(const w_legacy_targets_t *targets, size_t chosen);

/**
 * @brief Warn that a <client> block's targets were all skipped, because <agent> or an
 *        earlier <client> already set the manager. Names the one in use and the dropped ones.
 *
 * @param in_use The manager entry already configured.
 */
void w_legacy_targets_warn_skipped(const w_legacy_targets_t *targets, const agent_server *in_use);

/**
 * @brief Keep a <client> block's targets on logr until the <agent><manager> blocks later in
 *        the file are read, so the warning can name the manager they set. targets is left
 *        empty; an earlier block's deferred targets are kept in front of them.
 *
 * @param managers How many <manager> blocks the file's <agent> blocks hold.
 */
void w_legacy_targets_defer(agent *logr, w_legacy_targets_t *targets, int managers);

/**
 * @brief Called each time an <agent><manager> sets the manager. After the last one the file
 *        holds, warns that the deferred <client> targets are ignored, naming the manager in
 *        use and the dropped ones, and releases them.
 */
void w_legacy_targets_report_deferred(agent *logr);

/**
 * @brief Release logr's deferred targets, if a failed read left any.
 */
void w_legacy_targets_free_deferred(agent *logr);

/**
 * @brief Release every value and reset the list.
 */
void w_legacy_targets_free(w_legacy_targets_t *targets);

#endif /* LEGACY_SERVER_TARGETS_H */
