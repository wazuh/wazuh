/*
 * SQL Schema for task manager database
 * Copyright (C) 2015, Wazuh Inc.
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
 */

PRAGMA user_version = 1;

CREATE TABLE IF NOT EXISTS TASKS (
    TASK_ID TEXT PRIMARY KEY,
    AGENT_ID TEXT NOT NULL,
    TASK_TYPE TEXT NOT NULL,
    PAYLOAD TEXT NOT NULL,
    CREATE_TIME INTEGER NOT NULL,
    DELIVERY_TIME INTEGER,
    STATUS TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_agent_status ON TASKS (AGENT_ID, STATUS);

CREATE INDEX IF NOT EXISTS idx_create_time ON TASKS (CREATE_TIME);

CREATE INDEX IF NOT EXISTS idx_status ON TASKS (STATUS);

/* Manager-side tasks. Unlike TASKS, whose STATUS means "handed to a consumer", a row here
   tracks execution to an outcome: it is claimed by a dispatcher lane, executed, and retired
   with a result. The two tables are kept separate so the agent-delivery path is untouched.
   Note the build embeds this file by deleting newlines, so every continuation line must begin
   with whitespace and comments must use this form rather than a double dash. */
CREATE TABLE IF NOT EXISTS MANAGER_TASKS (
    TASK_ID TEXT PRIMARY KEY,
    TASK_TYPE TEXT NOT NULL,
    PAYLOAD TEXT NOT NULL,
    CREATE_TIME INTEGER NOT NULL,
    AGENT_ID TEXT,
    STATUS TEXT NOT NULL,
    OWNER TEXT,
    CLAIM_TIME INTEGER,
    ATTEMPTS INTEGER NOT NULL DEFAULT 0,
    DEFER_COUNT INTEGER NOT NULL DEFAULT 0,
    LAST_ERROR TEXT,
    NEXT_ATTEMPT_AT INTEGER NOT NULL,
    SCHEDULE_ID TEXT,
    SCHEDULED_RUN_AT INTEGER,
    /* When the row reached a terminal state. Retention is measured from here rather than from
       CREATE_TIME, or a task created eight days ago and completed a minute ago would be evicted
       immediately by a seven-day window. TASKS solves the same problem with DELIVERY_TIME. */
    END_TIME INTEGER,
    CHECK (STATUS IN ('pending', 'claimed', 'completed', 'failed', 'dead_letter', 'superseded'))
);

/* The claim seeks on this. The scheduler's poll walks it -- SQLite has no loose index scan, so
   its GROUP BY traverses every pending entry -- but never touches the table. */
CREATE INDEX IF NOT EXISTS idx_manager_tasks_claim
    ON MANAGER_TASKS (TASK_TYPE, NEXT_ATTEMPT_AT) WHERE STATUS = 'pending';

/* Per-schedule run history. */
CREATE INDEX IF NOT EXISTS idx_manager_tasks_schedule
    ON MANAGER_TASKS (SCHEDULE_ID, SCHEDULED_RUN_AT);

/* Two single-row lookups: authd's pending-purge hit check, and the re-queue competing-row check. */
CREATE INDEX IF NOT EXISTS idx_manager_tasks_agent
    ON MANAGER_TASKS (AGENT_ID, TASK_TYPE, STATUS);

/* authd's startup seed and its pending-delete count. Neither index above serves them: the claim
   index is partial on STATUS = 'pending' so it misses 'claimed', and the agent index leads on
   AGENT_ID. */
CREATE INDEX IF NOT EXISTS idx_manager_tasks_type_status
    ON MANAGER_TASKS (TASK_TYPE, STATUS);

/* The ownership sweep. Nothing above leads on STATUS, so without this the sweep is a table scan
   or one seek per registered type. Partial keeps it to the in-flight set. */
CREATE INDEX IF NOT EXISTS idx_manager_tasks_claimed
    ON MANAGER_TASKS (OWNER) WHERE STATUS = 'claimed';

/* There is deliberately no unique index coalescing pending rows per (AGENT_ID, TASK_TYPE): every
   path returning a claimed row to pending would then fail with SQLITE_CONSTRAINT whenever a newer
   pending row exists, which the design creates on purpose. Coalescing is done by the create
   operation instead, and a displaced row becomes 'superseded'. */

/* Recurring task definitions. TASK_TYPE, INTERVAL and NODE_SCOPE live in the built-in schedule
   table in code; only the mutable state is persisted here. ENABLED is stored, not just read from
   configuration, because a disabled-to-enabled transition can straddle a restart and is the only
   signal that NEXT_RUN_AT must be recomputed. */
CREATE TABLE IF NOT EXISTS MANAGER_TASK_SCHEDULES (
    SCHEDULE_ID TEXT PRIMARY KEY,
    NEXT_RUN_AT INTEGER NOT NULL,
    ENABLED INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_manager_task_schedules_next_run
    ON MANAGER_TASK_SCHEDULES (NEXT_RUN_AT);

CREATE TABLE IF NOT EXISTS metadata (
    key   TEXT PRIMARY KEY,
    value TEXT
);
