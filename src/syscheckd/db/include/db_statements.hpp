/**
 * @file db_statement.hpp
 * @brief Definition of FIM database statements.
 * @date 2021-09-06
 *
 * @copyright Copyright (C) 2015-2021 Wazuh, Inc.
 */

constexpr auto DATABASE_TEMP {"queue/fim/db/fim_dbsync.db"};

constexpr auto CREATE_FILE_DB_STATEMENT
{
    R"(CREATE TABLE IF NOT EXISTS file_entry (
    path TEXT NOT NULL,
    mode INTEGER,
    last_event INTEGER,
    scanned INTEGER,
    options INTEGER,
    checksum TEXT NOT NULL,
    dev INTEGER,
    inode INTEGER,
    size INTEGER,
    perm TEXT,
    attributes TEXT,
    uid INTEGER,
    gid INTEGER,
    user_name TEXT,
    group_name TEXT,
    hash_md5 TEXT,
    hash_sha1 TEXT,
    hash_sha256 TEXT,
    mtime INTEGER,
    PRIMARY KEY(path));)"
};

constexpr auto CREATE_REGISTRY_KEY_DB_STATEMENT
{
    R"(CREATE TABLE IF NOT EXISTS registry_key (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    path TEXT NOT NULL,
    perm TEXT,
    uid INTEGER,
    gid INTEGER,
    user_name TEXT,
    group_name TEXT,
    mtime INTEGER,
    arch TEXT CHECK (arch IN ('[x32]', '[x64]')),
    scanned INTEGER,
    last_event INTEGER,
    checksum TEXT NOT NULL,
    UNIQUE (arch, path));)"
};

constexpr auto CREATE_REGISTRY_VALUE_DB_STATEMENT
{
    R"(CREATE TABLE IF NOT EXISTS registry_data (
    key_id INTEGER,
    name TEXT,
    type INTEGER,
    size INTEGER,
    hash_md5 TEXT,
    hash_sha1 TEXT,
    hash_sha256 TEXT,
    scanned INTEGER,
    last_event INTEGER,
    checksum TEXT NOT NULL,

    PRIMARY KEY(key_id, name)
    FOREIGN KEY (key_id) REFERENCES registry_key(id));)"
};
