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

/* The two rules behind the per-container row ceiling, kept apart
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
 * @param limit          Rows this container may store; <= 0 means unlimited.
 * @param held           Rows this container would hold if its scan stopped now
 *                       without delete detection: what it stored before the scan
 *                       began, plus the NEW rows stored since.
 * @param already_stored The row refreshes one the container holds already.
 *
 * `held` cannot be "rows synced in this pass". A pass the ceiling cut short used
 * to suppress delete detection, so the rows it did not refresh survived next to
 * the ones it did, and the next pass stored up to `limit` again from zero: a
 * container capped at L held L+1 rows after one new file, and more after each.
 *
 * A refresh never adds a row, so it is always admitted. Only a row the container
 * does not hold yet can be refused, and that is what keeps delete detection safe
 * after the ceiling bites -- see container_scan_is_partial().
 */
static inline bool container_row_admitted(int limit, size_t held, bool already_stored)
{
    if (limit <= 0 || already_stored)
    {
        return true;
    }

    return held < (size_t)limit;
}

/**
 * @brief Whether a container's scan must be treated as incomplete.
 *
 * **This is D11 rule 4 — never let a partial view delete.**
 *
 * `walker_partial` is the walker's own verdict, reached before a single row
 * touches the database: a row cap in the walk, an unreadable rootfs, a rejected
 * path. `unstored` counts rows the DATABASE failed to store -- the node-wide
 * ceiling or an error -- which may include refreshes of rows already held.
 *
 * Both mean the stored row set is a subset of the container's real files, and a
 * delete detection over a subset deletes everything it cannot see. Until this
 * existed only the first was carried: measured on a real node, 8,643 rows were
 * refused while every scan in the window reported "0 partial scan(s)".
 *
 * Rows refused by the container's own ceiling are NOT counted here. That ceiling
 * only ever refuses a row the container does not hold, so every row a delete
 * detection removes afterwards is one the walker did not see at all.
 */
static inline bool container_scan_is_partial(bool walker_partial, size_t unstored)
{
    return walker_partial || unstored > 0;
}

#endif /* CONTAINER_ROW_BUDGET_H */
