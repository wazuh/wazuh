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

#ifndef _TASK_MANAGER_STORAGE_SCHEMA_HPP
#define _TASK_MANAGER_STORAGE_SCHEMA_HPP

namespace task_manager::storage
{
    /// @brief The schema version this build expects. Bumping it requires a migration step in
    ///        SqliteTaskStore::migrate(); the DDL below is applied with IF NOT EXISTS on every
    ///        open and therefore cannot alter an existing table's shape.
    constexpr int SCHEMA_VERSION {1};

    /*
     * The DDL, moved here from wazuh_db/schemas/schema_task_manager.sql when this module took
     * ownership of tasks.db.
     *
     * That file was embedded by a CMake step that COLLAPSED it -- string(REPLACE "\n" "") -- so
     * `--` comments were forbidden, every continuation line had to start with whitespace, and no
     * statement could rely on a line break as a token separator. None of that applies here. The
     * tables, the CHECK list and all six MANAGER_TASKS indexes are otherwise unchanged; every one
     * of those indexes was measured with EXPLAIN QUERY PLAN against a realistic steady state and
     * found to be used.
     */
    constexpr auto SCHEMA_DDL = R"SQL(
-- ---------------------------------------------------------------------------------------------
-- Agent tasks: work STORED for an agent to pick up. The manager never learns what came of one.
-- ---------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS TASKS (
    TASK_ID       TEXT PRIMARY KEY,
    AGENT_ID      TEXT    NOT NULL,
    TASK_TYPE     TEXT    NOT NULL,
    PAYLOAD       TEXT    NOT NULL,
    CREATE_TIME   INTEGER NOT NULL,
    DELIVERY_TIME INTEGER,
    STATUS        TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_agent_status ON TASKS (AGENT_ID, STATUS);
CREATE INDEX IF NOT EXISTS idx_create_time  ON TASKS (CREATE_TIME);
CREATE INDEX IF NOT EXISTS idx_status       ON TASKS (STATUS);

-- ---------------------------------------------------------------------------------------------
-- Manager tasks: work the manager owes ITSELF. Unlike TASKS, whose STATUS means "handed to a
-- consumer", a row here is claimed, executed and retired with an OUTCOME, and is retried until it
-- reaches one. The two tables stay separate so the agent-delivery path is untouched by any of it.
-- ---------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS MANAGER_TASKS (
    TASK_ID          TEXT PRIMARY KEY,
    TASK_TYPE        TEXT    NOT NULL,
    PAYLOAD          TEXT    NOT NULL,
    CREATE_TIME      INTEGER NOT NULL,
    AGENT_ID         TEXT,
    STATUS           TEXT    NOT NULL,
    OWNER            TEXT,
    CLAIM_TIME       INTEGER,
    ATTEMPTS         INTEGER NOT NULL DEFAULT 0,
    DEFER_COUNT      INTEGER NOT NULL DEFAULT 0,
    LAST_ERROR       TEXT,

    -- Set by the creator, never left to default to 0. With a zero default and a claim ordered by
    -- this column, every never-attempted row would sort ahead of every retried row -- whose value
    -- is a real past timestamp -- so under sustained admission a retried row would be permanently
    -- last. Seeding it from CREATE_TIME keeps arrival order for fresh rows and puts a backed-off
    -- row in line the moment it becomes eligible.
    NEXT_ATTEMPT_AT  INTEGER NOT NULL,

    SCHEDULE_ID      TEXT,
    SCHEDULED_RUN_AT INTEGER,

    -- When the row reached a terminal state. Retention is measured from here, not from
    -- CREATE_TIME: a task created eight days ago and completed a minute ago would otherwise be
    -- evicted immediately by a seven-day window.
    END_TIME         INTEGER,

    CHECK (STATUS IN ('pending', 'claimed', 'completed', 'failed', 'dead_letter', 'superseded'))
);

-- The claim SEEKS on this. Partial, so it holds only the eligible set.
CREATE INDEX IF NOT EXISTS idx_manager_tasks_claim
    ON MANAGER_TASKS (TASK_TYPE, NEXT_ATTEMPT_AT) WHERE STATUS = 'pending';

-- Per-schedule run history, and the schedule overlap check.
CREATE INDEX IF NOT EXISTS idx_manager_tasks_schedule
    ON MANAGER_TASKS (SCHEDULE_ID, SCHEDULED_RUN_AT);

-- Two single-row lookups: the coalesce probe on create, and the competing-row check on re-queue.
CREATE INDEX IF NOT EXISTS idx_manager_tasks_agent
    ON MANAGER_TASKS (AGENT_ID, TASK_TYPE, STATUS);

-- Admission counts and the operator-facing status filter. Neither index above serves them: the
-- claim index is partial on STATUS = 'pending' so it misses 'claimed', and the agent index leads
-- on AGENT_ID.
CREATE INDEX IF NOT EXISTS idx_manager_tasks_type_status
    ON MANAGER_TASKS (TASK_TYPE, STATUS);

-- The ownership sweep. Nothing above leads on STATUS, so without this the sweep is a table scan or
-- one seek per registered type. Partial keeps it to the in-flight set, which is a handful of rows.
CREATE INDEX IF NOT EXISTS idx_manager_tasks_claimed
    ON MANAGER_TASKS (OWNER) WHERE STATUS = 'claimed';

-- Retention. Without this, retiring terminal rows is a full table scan on every cleanup pass --
-- measured at ~10 ms per pass on a table at the 100k row ceiling WITH NOTHING TO DELETE.
--
-- Not partial, unlike the two above, because it serves both age rules: the three-status IN list
-- and the dead-letter sweep. It costs about 1.6 us per task lifecycle on the claim-and-complete
-- path, so it pays for itself below roughly twenty manager tasks per second sustained.
CREATE INDEX IF NOT EXISTS idx_manager_tasks_status_end
    ON MANAGER_TASKS (STATUS, END_TIME);

-- There is DELIBERATELY no unique index coalescing pending rows per (AGENT_ID, TASK_TYPE). It
-- looks like the natural way to express "one pending scan per agent", and it would break a state
-- this design creates on purpose: a new pending row is allowed while an earlier one for the same
-- agent is claimed, and then every path returning that row to pending -- retry, timeout, busy,
-- not_ready, incomplete, the sweep -- fails with SQLITE_CONSTRAINT. Coalescing is done by the
-- create operation instead, and a displaced row becomes 'superseded'.

-- ---------------------------------------------------------------------------------------------
-- Recurring task definitions.
--
-- TASK_TYPE, INTERVAL and NODE_SCOPE are code constants in the built-in schedule table; only the
-- mutable state is persisted. ENABLED is stored rather than read from configuration alone because
-- a disabled-to-enabled transition can straddle a restart, and that transition is the only signal
-- that NEXT_RUN_AT must be recomputed.
-- ---------------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS MANAGER_TASK_SCHEDULES (
    SCHEDULE_ID TEXT PRIMARY KEY,
    NEXT_RUN_AT INTEGER NOT NULL,
    ENABLED     INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_manager_task_schedules_next_run
    ON MANAGER_TASK_SCHEDULES (NEXT_RUN_AT);

-- Module bookkeeping. Inherited from wazuh-db's generic vacuum accounting, and now the module's
-- own: it records when the last VACUUM ran so the interval survives a restart.
CREATE TABLE IF NOT EXISTS metadata (
    key   TEXT PRIMARY KEY,
    value TEXT
);
)SQL";
} // namespace task_manager::storage

#endif // _TASK_MANAGER_STORAGE_SCHEMA_HPP
