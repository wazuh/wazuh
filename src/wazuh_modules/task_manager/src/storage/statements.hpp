/*
 * Wazuh task manager module
 * Copyright (C) 2015, Wazuh Inc.
 * September 1, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _TASK_MANAGER_STORAGE_STATEMENTS_HPP
#define _TASK_MANAGER_STORAGE_STATEMENTS_HPP

#include <array>
#include <cstddef>

namespace task_manager::storage
{
    /**
     * @brief Every prepared statement, prepared once per connection at open.
     *
     * The SQL is carried over from wazuh-db's WDB_STMT_* catalogue unchanged, so the query plans
     * the second schema audit measured still hold. Three statements are new, and all three exist
     * only because owning the database makes them possible: MtMinPendingNextAttempt and
     * SchedMinNextRun let the scheduler sleep until the exact moment work becomes eligible instead
     * of polling, and the metadata pair lets the VACUUM interval survive a restart.
     *
     * Deliberately NOT used anywhere: RETURNING (SQLite 3.35) and DELETE ... LIMIT
     * (SQLITE_ENABLE_UPDATE_DELETE_LIMIT). The build can import a precompiled libsqlite3 whose
     * version and compile flags we do not control, so both are out; the two-statement and
     * IN (SELECT ... LIMIT ?) forms below are what replace them.
     */
    enum class Stmt : std::size_t
    {
        // ---- agent tasks -------------------------------------------------------------------
        AgentTaskInsert = 0,
        AgentTaskGetPending,
        AgentTaskMarkDelivered,
        AgentTaskExpire,
        AgentTaskDeleteOld,

        // ---- manager tasks: create and claim ------------------------------------------------
        MtFindPendingByAgent,
        MtCountPendingByType,
        MtInsert,
        MtSelectClaimable,
        MtClaim,

        // ---- manager tasks: re-queue and outcome --------------------------------------------
        MtFindCompetingPending,
        MtInheritCounters,
        MtSupersede,
        MtRequeue,
        MtSetResult,

        // ---- manager tasks: reads ------------------------------------------------------------
        MtGet,
        MtGetByAgent,
        MtPollDue,
        MtMinPendingNextAttempt,
        MtSelectClaimedByOwner,
        MtSelectClaimedAny,
        MtListByType,
        MtListByTypeStatus,
        MtCountByTypeStatus,
        MtPendingTypes,

        // ---- manager tasks: reaping and retention -------------------------------------------
        MtFailByType,
        MtDeleteTerminalOld,
        MtDeleteDeadLetterOld,
        MtScheduleIds,
        MtTrimScheduleHistory,
        MtCountAll,
        MtEvict,

        // ---- schedules -----------------------------------------------------------------------
        SchedGet,
        SchedInsert,
        SchedUpdate,
        SchedSetNextRun,
        SchedListDue,
        SchedHasActive,
        SchedMinNextRun,

        // ---- metadata ------------------------------------------------------------------------
        MetaGet,
        MetaSet,

        Count
    };

    constexpr std::size_t STATEMENT_COUNT {static_cast<std::size_t>(Stmt::Count)};

    /// @brief SQL text, indexed by Stmt. Order must match the enum exactly.
    constexpr std::array<const char*, STATEMENT_COUNT> STATEMENT_SQL {
        // -------------------------------------------------------------------------------------
        // Agent tasks
        // -------------------------------------------------------------------------------------
        /* AgentTaskInsert */
        "INSERT INTO TASKS (TASK_ID, AGENT_ID, TASK_TYPE, PAYLOAD, CREATE_TIME, STATUS) "
        "VALUES (?, ?, ?, ?, ?, 'pending');",

        /* AgentTaskGetPending */
        "SELECT TASK_ID, TASK_TYPE, PAYLOAD, CREATE_TIME FROM TASKS "
        "WHERE AGENT_ID = ? AND STATUS = 'pending' ORDER BY CREATE_TIME ASC LIMIT ?;",

        /* AgentTaskMarkDelivered -- run inside the same transaction as the select above, once per
           returned row. That is N statement executions but ONE commit, where the retired C path
           spent a whole wazuh-db connect/query/close cycle per task. */
        "UPDATE TASKS SET STATUS = 'delivered', DELIVERY_TIME = ? WHERE TASK_ID = ?;",

        /* AgentTaskExpire -- agent tasks DO age out while pending. Manager tasks deliberately do
           not; see MtDeleteTerminalOld. */
        "UPDATE TASKS SET STATUS = 'expired' WHERE STATUS = 'pending' AND CREATE_TIME < ?;",

        /* AgentTaskDeleteOld -- the cutoff binds twice, once per branch. */
        "DELETE FROM TASKS WHERE (STATUS = 'expired' AND CREATE_TIME < ?) "
        "OR (STATUS = 'delivered' AND DELIVERY_TIME < ?);",

        // -------------------------------------------------------------------------------------
        // Manager tasks: create and claim
        //
        // TASK_TYPE is opaque to storage. Nothing here validates it against a list of known types,
        // which is what lets a new manager task be a registry descriptor and nothing else.
        // -------------------------------------------------------------------------------------
        /* MtFindPendingByAgent -- the coalesce probe. Only run for types that opt in. */
        "SELECT TASK_ID FROM MANAGER_TASKS "
        "WHERE AGENT_ID = ? AND TASK_TYPE = ? AND STATUS = 'pending' LIMIT 1;",

        /* MtCountPendingByType -- the admission bound. Exact rather than approximate because it
           shares a transaction with the insert that follows it. */
        "SELECT COUNT(*) FROM MANAGER_TASKS WHERE TASK_TYPE = ? AND STATUS = 'pending';",

        /* MtInsert */
        "INSERT INTO MANAGER_TASKS (TASK_ID, TASK_TYPE, PAYLOAD, CREATE_TIME, AGENT_ID, STATUS, "
        "NEXT_ATTEMPT_AT, SCHEDULE_ID, SCHEDULED_RUN_AT) VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, ?);",

        /* MtSelectClaimable -- ORDER BY NEXT_ATTEMPT_AT alone. Ordering is mandatory or a row can
           starve, but a (, CREATE_TIME, TASK_ID) tiebreak would force a temp b-tree sort over the
           eligible set on every claim, because the index is (TASK_TYPE, NEXT_ATTEMPT_AT). Since
           NEXT_ATTEMPT_AT is seeded from CREATE_TIME it already encodes arrival order; ties are
           same-second rows that are equally eligible. */
        "SELECT TASK_ID, TASK_TYPE, AGENT_ID, PAYLOAD, ATTEMPTS, DEFER_COUNT FROM MANAGER_TASKS "
        "WHERE TASK_TYPE = ? AND STATUS = 'pending' AND NEXT_ATTEMPT_AT <= ? "
        "ORDER BY NEXT_ATTEMPT_AT LIMIT 1;",

        /* MtClaim */
        "UPDATE MANAGER_TASKS SET STATUS = 'claimed', OWNER = ?, CLAIM_TIME = ? WHERE TASK_ID = ?;",

        // -------------------------------------------------------------------------------------
        // Manager tasks: re-queue and outcome
        // -------------------------------------------------------------------------------------
        /* MtFindCompetingPending -- no "which row is newer" rule is needed. The row being
           re-queued was claimed BEFORE the competing row could have been created, since create
           skips insertion whenever a pending row already exists. The survivor is always the one
           still pending; the re-queued row loses by construction. */
        "SELECT TASK_ID, ATTEMPTS, DEFER_COUNT FROM MANAGER_TASKS "
        "WHERE AGENT_ID = ? AND TASK_TYPE = ? AND STATUS = 'pending' AND TASK_ID <> ? LIMIT 1;",

        /* MtInheritCounters -- the survivor takes the MAXIMUM of both rows' counters. Without
           that, a coalescing type can never reach dead_letter under load: against a permanently
           broken consumer, every timed-out row is superseded by a fresh row starting at zero, no
           row accumulates a budget, and nothing terminates. It fails quietly, which is worse than
           either outcome the budget chooses between. This is the only path on which ATTEMPTS
           changes other than by increment. */
        "UPDATE MANAGER_TASKS SET ATTEMPTS = ?, DEFER_COUNT = ? WHERE TASK_ID = ?;",

        /* MtSupersede */
        "UPDATE MANAGER_TASKS SET STATUS = 'superseded', LAST_ERROR = ?, OWNER = NULL, "
        "CLAIM_TIME = NULL, END_TIME = ? WHERE TASK_ID = ?;",

        /* MtRequeue -- END_TIME back to NULL: the row is live again, and retention keys on it. */
        "UPDATE MANAGER_TASKS SET STATUS = 'pending', NEXT_ATTEMPT_AT = ?, ATTEMPTS = ?, "
        "DEFER_COUNT = ?, LAST_ERROR = ?, OWNER = NULL, CLAIM_TIME = NULL, END_TIME = NULL "
        "WHERE TASK_ID = ?;",

        /* MtSetResult */
        "UPDATE MANAGER_TASKS SET STATUS = ?, LAST_ERROR = ?, ATTEMPTS = ?, DEFER_COUNT = ?, "
        "OWNER = NULL, CLAIM_TIME = NULL, END_TIME = ? WHERE TASK_ID = ?;",

        // -------------------------------------------------------------------------------------
        // Manager tasks: reads
        // -------------------------------------------------------------------------------------
        /* MtGet */
        "SELECT TASK_ID, TASK_TYPE, AGENT_ID, PAYLOAD, CREATE_TIME, STATUS, OWNER, CLAIM_TIME, "
        "ATTEMPTS, DEFER_COUNT, LAST_ERROR, NEXT_ATTEMPT_AT, SCHEDULE_ID, SCHEDULED_RUN_AT, "
        "END_TIME FROM MANAGER_TASKS WHERE TASK_ID = ?;",

        /* MtGetByAgent -- same column list and order as MtGet, so both feed one row reader. */
        "SELECT TASK_ID, TASK_TYPE, AGENT_ID, PAYLOAD, CREATE_TIME, STATUS, OWNER, CLAIM_TIME, "
        "ATTEMPTS, DEFER_COUNT, LAST_ERROR, NEXT_ATTEMPT_AT, SCHEDULE_ID, SCHEDULED_RUN_AT, "
        "END_TIME FROM MANAGER_TASKS WHERE AGENT_ID = ? AND TASK_TYPE = ? "
        "ORDER BY CREATE_TIME DESC LIMIT 1;",

        /* MtPollDue -- which types have pending work, and when their earliest becomes eligible.
           Walks the pending partial index without touching the table; SQLite has no loose index
           scan, so it traverses every pending entry, which the creation caps bound. Used to seed
           the executor's ready set at startup and after a sweep, NOT on a timer. */
        "SELECT TASK_TYPE, MIN(NEXT_ATTEMPT_AT) FROM MANAGER_TASKS WHERE STATUS = 'pending' "
        "GROUP BY TASK_TYPE;",

        /* MtMinPendingNextAttempt -- the whole reason the 5 s poll loop is gone. The scheduler
           sleeps until exactly this instant, or until an in-process producer signals it. */
        "SELECT MIN(NEXT_ATTEMPT_AT) FROM MANAGER_TASKS WHERE STATUS = 'pending';",

        /* MtSelectClaimedByOwner / MtSelectClaimedAny -- the ownership sweep. Both page on
           TASK_ID rather than OFFSET: rows are written concurrently, and an offset walk would
           skip or repeat rows as the result set shifts under it. */
        "SELECT TASK_ID, TASK_TYPE, AGENT_ID, OWNER, CLAIM_TIME, ATTEMPTS, DEFER_COUNT "
        "FROM MANAGER_TASKS WHERE STATUS = 'claimed' AND OWNER = ? AND TASK_ID > ? "
        "ORDER BY TASK_ID LIMIT ?;",

        "SELECT TASK_ID, TASK_TYPE, AGENT_ID, OWNER, CLAIM_TIME, ATTEMPTS, DEFER_COUNT "
        "FROM MANAGER_TASKS WHERE STATUS = 'claimed' AND TASK_ID > ? ORDER BY TASK_ID LIMIT ?;",

        /* MtListByType / MtListByTypeStatus -- a deliberately compact projection. These list a
           whole task type; the point is to see WHAT failed and why, not to page whole payloads. */
        "SELECT TASK_ID, AGENT_ID, STATUS, CREATE_TIME, LAST_ERROR FROM MANAGER_TASKS "
        "WHERE TASK_TYPE = ? AND TASK_ID > ? ORDER BY TASK_ID LIMIT ?;",

        "SELECT TASK_ID, AGENT_ID, STATUS, CREATE_TIME, LAST_ERROR FROM MANAGER_TASKS "
        "WHERE TASK_TYPE = ? AND STATUS = ? AND TASK_ID > ? ORDER BY TASK_ID LIMIT ?;",

        /* MtCountByTypeStatus */
        "SELECT COUNT(*) FROM MANAGER_TASKS WHERE TASK_TYPE = ? AND STATUS = ?;",

        /* MtPendingTypes -- the orphaned-type reaper works in two steps because only the registry
           knows which types exist. Keeping that list out of storage is what lets a new task type
           be added without touching this file. */
        "SELECT DISTINCT TASK_TYPE FROM MANAGER_TASKS WHERE STATUS = 'pending';",

        // -------------------------------------------------------------------------------------
        // Manager tasks: reaping and retention
        // -------------------------------------------------------------------------------------
        /* MtFailByType */
        "UPDATE MANAGER_TASKS SET STATUS = 'failed', LAST_ERROR = ?, OWNER = NULL, "
        "CLAIM_TIME = NULL, END_TIME = ? WHERE TASK_TYPE = ? AND STATUS = 'pending';",

        /* MtDeleteTerminalOld -- only terminal rows are ever removed. A pending manager task is
           NEVER expired by age: doing so would destroy exactly the long-outage work the queue
           exists to survive. That is the opposite of AgentTaskExpire above, and the difference is
           deliberate. */
        "DELETE FROM MANAGER_TASKS WHERE STATUS IN ('completed', 'failed', 'superseded') "
        "AND END_TIME < ?;",

        /* MtDeleteDeadLetterOld -- dead letters outlive ordinary terminal rows because they are
           the only record of work that was abandoned. */
        "DELETE FROM MANAGER_TASKS WHERE STATUS = 'dead_letter' AND END_TIME < ?;",

        /* MtScheduleIds */
        "SELECT DISTINCT SCHEDULE_ID FROM MANAGER_TASKS WHERE SCHEDULE_ID IS NOT NULL;",

        /* MtTrimScheduleHistory -- excludes dead_letter deliberately: a repeatedly failing
           schedule produces mostly dead-letter rows, and a flat "keep the last N" would evict them
           long before their own longer window expires. */
        "DELETE FROM MANAGER_TASKS WHERE SCHEDULE_ID = ? "
        "AND STATUS IN ('completed', 'failed', 'superseded') AND TASK_ID NOT IN "
        "(SELECT TASK_ID FROM MANAGER_TASKS WHERE SCHEDULE_ID = ? "
        "AND STATUS IN ('completed', 'failed', 'superseded') "
        "ORDER BY SCHEDULED_RUN_AT DESC, TASK_ID DESC LIMIT ?);",

        /* MtCountAll */
        "SELECT COUNT(*) FROM MANAGER_TASKS;",

        /* MtEvict -- the hard ceiling MUST be able to evict everything eventually or it is not a
           ceiling, so dead_letter is protected by eviction ORDER rather than by exemption: it goes
           last. Reaching the ceiling with only dead letters left is itself worth an error log. */
        "DELETE FROM MANAGER_TASKS WHERE TASK_ID IN (SELECT TASK_ID FROM MANAGER_TASKS "
        "WHERE STATUS IN ('completed', 'superseded', 'failed', 'dead_letter') "
        "ORDER BY CASE STATUS WHEN 'completed' THEN 0 WHEN 'superseded' THEN 1 "
        "WHEN 'failed' THEN 2 ELSE 3 END, END_TIME, TASK_ID LIMIT ?);",

        // -------------------------------------------------------------------------------------
        // Schedules
        // -------------------------------------------------------------------------------------
        /* SchedGet */
        "SELECT SCHEDULE_ID, NEXT_RUN_AT, ENABLED FROM MANAGER_TASK_SCHEDULES WHERE SCHEDULE_ID = ?;",

        /* SchedInsert */
        "INSERT INTO MANAGER_TASK_SCHEDULES (SCHEDULE_ID, NEXT_RUN_AT, ENABLED) VALUES (?, ?, ?);",

        /* SchedUpdate */
        "UPDATE MANAGER_TASK_SCHEDULES SET NEXT_RUN_AT = ?, ENABLED = ? WHERE SCHEDULE_ID = ?;",

        /* SchedSetNextRun */
        "UPDATE MANAGER_TASK_SCHEDULES SET NEXT_RUN_AT = ? WHERE SCHEDULE_ID = ?;",

        /* SchedListDue */
        "SELECT SCHEDULE_ID, NEXT_RUN_AT FROM MANAGER_TASK_SCHEDULES "
        "WHERE ENABLED = 1 AND NEXT_RUN_AT <= ? ORDER BY NEXT_RUN_AT;",

        /* SchedHasActive -- the overlap check: a schedule does not spawn a new instance while a
           previous one is still running. Served by idx_manager_tasks_schedule. */
        "SELECT 1 FROM MANAGER_TASKS WHERE SCHEDULE_ID = ? AND STATUS IN ('pending', 'claimed') "
        "LIMIT 1;",

        /* SchedMinNextRun -- feeds the scheduler's exact sleep, alongside
           MtMinPendingNextAttempt. */
        "SELECT MIN(NEXT_RUN_AT) FROM MANAGER_TASK_SCHEDULES WHERE ENABLED = 1;",

        // -------------------------------------------------------------------------------------
        // Metadata
        // -------------------------------------------------------------------------------------
        /* MetaGet */
        "SELECT value FROM metadata WHERE key = ?;",

        /* MetaSet */
        "INSERT INTO metadata (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value;",
    };
} // namespace task_manager::storage

#endif // _TASK_MANAGER_STORAGE_STATEMENTS_HPP
