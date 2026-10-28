/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef CONTAINER_DOC_BUDGET_H
#define CONTAINER_DOC_BUDGET_H

/* The container FIM document budget's decision rule, separated from the
 * globals and the mutex it runs against (#37532 / O10).
 *
 * It is here, pure and header-only, for the reason the staging buffer and the
 * reconcile plan are: a rule that lives inside a .c beside a process-global
 * counter and a pthread mutex is reachable only by running the daemon, and a
 * budget nobody can test is how the host path's own accounting drifted.
 *
 * The caller owns the lock and the counter; this decides only what the row is
 * worth. Measured on a real node, this budget is what stops a node's containers
 * spending the agent's own FIM allowance -- see 23-nfr3-container-limits.md.
 *
 * NOTE it governs REPORTING, not storage: a row denied here is still written to
 * file_entry, exactly as a host row over its budget is. Bounding the table is a
 * different control.
 */

typedef struct container_budget_decision_t
{
    int sync_flag;   /* 1 = report this row to the manager, 0 = withhold it. */
    int count_delta; /* How the caller must move the container-scope counter. */
} container_budget_decision_t;

/**
 * @brief Decide whether one container FIM row may be reported.
 *
 * @param limit       The container-scope budget; <= 0 means unlimited.
 * @param current     Documents already counted against that budget.
 * @param stored_sync The row's own stored sync flag (0 when it has none).
 * @param is_delete   Non-zero when the row is being deleted.
 */
static inline container_budget_decision_t container_budget_decide(int limit,
                                                                  int current,
                                                                  int stored_sync,
                                                                  int is_delete)
{
    container_budget_decision_t out;
    out.sync_flag = 1;
    out.count_delta = 0;

    if (limit <= 0)
    {
        /* Unlimited is the default and must stay free of accounting: an agent
         * whose manager never sends a budget must behave exactly as before,
         * including keeping the counter at rest. */
        out.sync_flag = 1;
        return out;
    }

    if (is_delete)
    {
        /* Only a row that was counted releases its slot. Deleting a withheld
         * row must not credit the budget, or the count drifts upward by one
         * per withheld deletion until it reports space that does not exist. */
        out.sync_flag = stored_sync;
        out.count_delta = (stored_sync == 1) ? -1 : 0;
        return out;
    }

    if (stored_sync == 1)
    {
        /* Already counted: a modification of a reported row stays reported and
         * must not be counted twice. */
        out.sync_flag = 1;
        return out;
    }

    if (current < limit)
    {
        out.sync_flag = 1;
        out.count_delta = 1;
        return out;
    }

    out.sync_flag = 0;
    return out;
}

#endif /* CONTAINER_DOC_BUDGET_H */
