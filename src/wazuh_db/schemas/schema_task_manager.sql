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

CREATE TABLE IF NOT EXISTS metadata (
    key   TEXT PRIMARY KEY,
    value TEXT
);
