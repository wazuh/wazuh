/*
 * SQL Schema for task manager database
 * Copyright (C) 2015, Wazuh Inc.
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
 */

PRAGMA user_version = 2;

BEGIN;

CREATE TABLE IF NOT EXISTS TASKS (
    TASK_ID TEXT PRIMARY KEY,              -- Deterministic hash-based UUID
    AGENT_ID TEXT NOT NULL,                -- TEXT to support non-numeric agent IDs
    TASK_TYPE TEXT NOT NULL,               -- active_response, remote_upgrade, agent_restart, agent_reload
    PAYLOAD TEXT NOT NULL,                 -- Complete JSON payload for agent
    CREATE_TIME INTEGER NOT NULL,          -- Unix timestamp (seconds)
    DELIVERY_TIME INTEGER,                 -- When delivered to agent (NULL if not delivered yet)
    STATUS TEXT NOT NULL                   -- pending, delivered, expired
);

-- Optimized indexes for new query patterns
CREATE INDEX IF NOT EXISTS idx_agent_status ON TASKS (AGENT_ID, STATUS);
CREATE INDEX IF NOT EXISTS idx_create_time ON TASKS (CREATE_TIME);
CREATE INDEX IF NOT EXISTS idx_status ON TASKS (STATUS);

CREATE TABLE IF NOT EXISTS metadata (
    key   TEXT PRIMARY KEY,
    value TEXT
);

END;
