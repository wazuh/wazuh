/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 * August 27, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _RPM_DB_SQLITE_READER_HPP
#define _RPM_DB_SQLITE_READER_HPP

#include "rpmHeaderBlobParser.hpp"

#include "sqlite3.h"

#include <array>
#include <cstring>
#include <string>
#include <vector>

/// @brief Retrieval of RPM header blobs from the sqlite backend.
///
/// The sqlite backend is the default since rpm 4.16 and is what the current Red Hat,
/// Fedora and Amazon Linux families ship. The database is `rpmdb.sqlite` and the blobs
/// live in the `Packages` table, one per row; parsing them is the shared work in
/// RpmHeaderBlob.
///
/// The database is never written: from a file it is opened immutable, and from memory it
/// is deserialized read only. Neither path creates the `-wal` or `-shm` side files.
namespace RpmDbSqlite
{
    /// @brief The 16 byte magic every sqlite file starts with, terminator included.
    constexpr auto DATABASE_MAGIC { "SQLite format 3" };
    constexpr std::size_t DATABASE_MAGIC_SIZE { 16 };

    /// @brief True when the bytes are a sqlite database, checked before opening them.
    static inline bool isDatabase(const void* data, std::size_t size)
    {
        return data != nullptr && size >= DATABASE_MAGIC_SIZE &&
               std::memcmp(data, DATABASE_MAGIC, DATABASE_MAGIC_SIZE) == 0;
    }

    /// @brief Hand every header blob in an open database to the callback.
    /// @return False when the database carries no readable `Packages` table.
    static inline bool readPackages(sqlite3* database, const RpmHeaderBlob::BlobCallback& callback)
    {
        sqlite3_stmt* statement { nullptr };

        if (sqlite3_prepare_v2(database, "SELECT blob FROM Packages ORDER BY hnum;", -1, &statement, nullptr) != SQLITE_OK)
        {
            // Not an rpm database, or a schema this reader does not know.
            return false;
        }

        while (sqlite3_step(statement) == SQLITE_ROW)
        {
            const auto* blob { static_cast<const uint8_t*>(sqlite3_column_blob(statement, 0)) };
            const auto size { sqlite3_column_bytes(statement, 0) };

            if (blob != nullptr && size > 0)
            {
                callback(blob, static_cast<std::size_t>(size));
            }
        }

        sqlite3_finalize(statement);
        return true;
    }

    /// @brief Offsets of the file format version bytes in the sqlite header.
    constexpr std::size_t WRITE_VERSION_OFFSET { 18 };
    constexpr std::size_t READ_VERSION_OFFSET { 19 };
    constexpr unsigned char VERSION_ROLLBACK_JOURNAL { 1 };
    constexpr unsigned char VERSION_WRITE_AHEAD_LOG { 2 };
    constexpr std::array<std::size_t, 2> VERSION_OFFSETS { WRITE_VERSION_OFFSET, READ_VERSION_OFFSET };

    /// @brief Read a database held in memory.
    /// @param data Full content of `rpmdb.sqlite`.
    /// @param size Bytes available from @p data.
    /// @param callback Called once per header blob.
    /// @return False when the bytes are not a readable rpm sqlite database.
    ///
    /// rpm keeps its database in write-ahead log mode, and a database handed to sqlite as
    /// bytes cannot be in that mode: the log lives in a second file this reader does not
    /// have. The copy taken here is therefore marked as using a rollback journal, which
    /// is what lets the main database file be read on its own. What the log holds is not
    /// visible, so a database whose log was never checkpointed is read as of its last
    /// checkpoint. Images are committed quiesced, so their log is empty.
    static inline bool readFromMemory(const void* data, std::size_t size, const RpmHeaderBlob::BlobCallback& callback)
    {
        if (!isDatabase(data, size) || size <= READ_VERSION_OFFSET)
        {
            return false;
        }

        const auto* bytes { static_cast<const unsigned char*>(data) };
        std::vector<unsigned char> buffer { bytes, bytes + size };

        // Each byte is normalized on its own, and only the write-ahead log value is
        // rewritten: a larger value means a file format this sqlite does not know, which
        // must keep being refused rather than be read as something it is not.
        for (const auto offset : VERSION_OFFSETS)
        {
            if (buffer[offset] == VERSION_WRITE_AHEAD_LOG)
            {
                buffer[offset] = VERSION_ROLLBACK_JOURNAL;
            }
        }

        sqlite3* database { nullptr };

        if (sqlite3_open_v2(":memory:", &database, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) != SQLITE_OK)
        {
            sqlite3_close_v2(database);
            return false;
        }

        const auto deserialized
        {
            sqlite3_deserialize(database,
                                "main",
                                buffer.data(),
                                static_cast<sqlite3_int64>(buffer.size()),
                                static_cast<sqlite3_int64>(buffer.size()),
                                SQLITE_DESERIALIZE_READONLY)
        };

        const bool read = deserialized == SQLITE_OK && readPackages(database, callback);

        sqlite3_close_v2(database);
        return read;
    }

    /// @brief Read a database stored at a location.
    /// @param path Path of `rpmdb.sqlite`.
    /// @param callback Called once per header blob.
    /// @return False when the file is not a readable rpm sqlite database.
    ///
    /// Opened through the `immutable=1` URI so no lock is taken and no journal is
    /// created, which is what lets a database be read while rpm itself is using it.
    static inline bool readFromLocation(const std::string& path, const RpmHeaderBlob::BlobCallback& callback)
    {
        std::string uri { "file:" };

        // A URI path takes percent encoding, and '?' and '#' would otherwise start the
        // query and the fragment.
        for (const auto character : path)
        {
            if (character == '?' || character == '#' || character == '%')
            {
                constexpr auto DIGITS { "0123456789ABCDEF" };
                uri += '%';
                uri += DIGITS[(static_cast<unsigned char>(character) >> 4) & 0xF];
                uri += DIGITS[static_cast<unsigned char>(character) & 0xF];
            }
            else
            {
                uri += character;
            }
        }

        uri += "?immutable=1";

        sqlite3* database { nullptr };

        if (sqlite3_open_v2(uri.c_str(), &database, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, nullptr) != SQLITE_OK)
        {
            sqlite3_close_v2(database);
            return false;
        }

        const auto read { readPackages(database, callback) };

        sqlite3_close_v2(database);
        return read;
    }
} // namespace RpmDbSqlite

#endif // _RPM_DB_SQLITE_READER_HPP
