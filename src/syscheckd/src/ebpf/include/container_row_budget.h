/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef CONTAINER_ROW_BUDGET_H
#define CONTAINER_ROW_BUDGET_H

#include <stdbool.h>
#include <stddef.h>

/* The two rules behind the per-container row ceiling (#37532 / O10), kept apart
 * from the transaction that applies them so they can be tested without a
 * database.
 *
 * A row budget is a different layer from a document budget: a document budget
 * gates the sync flag and the row is stored either way, so it cannot bound the
 * database. This one refuses the store. Measured on a real node, 50 containers
 * filled the shared 100,000-row file_entry table; 4 of them ended with no rows
 * at all and which 4 was decided by walk order -- see
 * 23-nfr3-container-limits.md.
 */

/**
 * @brief Whether one more row may be stored for this container.
 *
 * @param limit  Rows this container may store; <= 0 means unlimited.
 * @param synced Rows it has stored in this baseline already.
 *
 * A baseline rewrites a container's whole row set, so `synced` within one
 * transaction IS that container's row count. No persistent counter is needed
 * and none can drift.
 */
static inline bool container_row_admitted(int limit, size_t synced)
{
    if (limit <= 0)
    {
        return true;
    }

    return synced < (size_t)limit;
}

/**
 * @brief Whether a container's scan must be treated as incomplete.
 *
 * **This is D11 rule 4 — never let a partial view delete.**
 *
 * `walker_partial` is the walker's own verdict, reached before a single row
 * touches the database: a row cap in the walk, an unreadable rootfs, a rejected
 * path. `refused` counts rows the DATABASE would not store, either because this
 * container reached its own ceiling or because the node-wide one was already
 * full.
 *
 * Both mean the stored row set is a subset of the container's real files, and a
 * delete detection over a subset deletes everything it cannot see. Until this
 * existed only the first was carried: measured on a real node, 8,643 rows were
 * refused while every scan in the window reported "0 partial scan(s)".
 */
static inline bool container_scan_is_partial(bool walker_partial, size_t refused)
{
    return walker_partial || refused > 0;
}

#endif /* CONTAINER_ROW_BUDGET_H */
