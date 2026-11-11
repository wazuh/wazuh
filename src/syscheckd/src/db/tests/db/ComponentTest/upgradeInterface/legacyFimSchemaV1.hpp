/*
 * Wazuh Syscheck
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _LEGACY_FIM_SCHEMA_V1_HPP
#define _LEGACY_FIM_SCHEMA_V1_HPP

#include <string>

/// The FIM schema exactly as released 5.0.0 created it, at
/// PRAGMA user_version = 1.
///
/// A FROZEN COPY, taken from origin/5.0.0's fimDB.hpp. It is deliberately NOT
/// derived from the current constants in that header, and it must never be:
/// deriving it is the obvious tidy-up, and it would silently neuter every test
/// that uses it, because the current file_entry already carries container_id in
/// its primary key -- the one thing the migration exists to add.
///
/// db_status_field_dm is absent here on purpose. SQLiteDBEngine adds it lazily,
/// per table, on first use in a transaction, so tests add it themselves to
/// reproduce what a live agent looks like.
inline std::string legacyFimSchemaV1()
{
    std::string schema
    {
        R"(CREATE TABLE IF NOT EXISTS file_entry (
    path TEXT NOT NULL,
    checksum TEXT NOT NULL,
    device INTEGER,
    inode INTEGER,
    size INTEGER,
    permissions TEXT,
    attributes TEXT,
    uid TEXT,
    gid TEXT,
    owner TEXT,
    group_ TEXT,
    hash_md5 TEXT,
    hash_sha1 TEXT,
    hash_sha256 TEXT,
    mtime INTEGER,
    version INTEGER NOT NULL DEFAULT 1,
    sync INTEGER DEFAULT 0,
    PRIMARY KEY(path)) WITHOUT ROWID;
    CREATE INDEX IF NOT EXISTS path_index ON file_entry (path);
    CREATE INDEX IF NOT EXISTS inode_index ON file_entry (device, inode);
CREATE TABLE IF NOT EXISTS table_metadata (
    table_name TEXT PRIMARY KEY,
    last_sync_time INTEGER NOT NULL
    );)"
    };

#ifdef WIN32
    schema += R"(CREATE TABLE IF NOT EXISTS registry_key (
    path TEXT NOT NULL,
    permissions TEXT,
    uid TEXT,
    gid TEXT,
    owner TEXT,
    group_ TEXT,
    mtime INTEGER,
    architecture TEXT CHECK (architecture IN ('[x32]', '[x64]')),
    checksum TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    sync INTEGER DEFAULT 0,
    PRIMARY KEY (architecture, path)) WITHOUT ROWID;
    CREATE INDEX IF NOT EXISTS path_index ON registry_key (path);
CREATE TABLE IF NOT EXISTS registry_data (
    path TEXT,
    architecture TEXT CHECK (architecture IN ('[x32]', '[x64]')),
    value TEXT NOT NULL,
    type INTEGER,
    size INTEGER,
    hash_md5 TEXT,
    hash_sha1 TEXT,
    hash_sha256 TEXT,
    checksum TEXT NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    sync INTEGER DEFAULT 0,
    PRIMARY KEY(path, architecture, value)
    FOREIGN KEY (path) REFERENCES registry_key(path)
    FOREIGN KEY (architecture) REFERENCES registry_key(architecture)) WITHOUT ROWID;
    CREATE INDEX IF NOT EXISTS key_name_index ON registry_data (path, value);)";
#endif

    return schema;
}

#define LEGACY_FIM_V1_SCHEMA (legacyFimSchemaV1())

#endif // _LEGACY_FIM_SCHEMA_V1_HPP
