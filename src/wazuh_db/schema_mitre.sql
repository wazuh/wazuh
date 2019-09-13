/*
 * SQL Schema for mitre database
 * Copyright (C) 2015-2019, Wazuh Inc.
 * September 13, 2019.
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
 */

DROP TABLE IF EXISTS attack;
DROP TABLE IF EXISTS has_phase;
DROP TABLE IF EXISTS has_platform;

CREATE TABLE IF NOT EXISTS attack
    (
    id TEXT PRIMARY KEY, 
    json TEXT
    );

CREATE TABLE IF NOT EXISTS has_phase
    (
    attack_id TEXT, 
    phase_name TEXT,
    FOREIGN KEY(attack_id) REFERENCES attack(id),
    PRIMARY KEY (attack_id, phase_name)
    );

CREATE TABLE IF NOT EXISTS has_platform
    (
    attack_id TEXT, 
    platform_name TEXT,
    FOREIGN KEY(attack_id) REFERENCES attack(id),
    PRIMARY KEY (attack_id, platform_name)
    );

PRAGMA journal_mode=WAL;
