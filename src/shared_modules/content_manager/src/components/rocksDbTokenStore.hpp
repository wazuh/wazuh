/*
 * Wazuh content manager
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _ROCKSDB_TOKEN_STORE_HPP
#define _ROCKSDB_TOKEN_STORE_HPP

#include "contentTokenStore.hpp"
#include "loggerHelper.h"
#include "sharedDefs.hpp"
#include "utils/rocksDBWrapper.hpp"
#include "utils/timeHelper.h"
#include <ctime>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>

/**
 * @brief The token store hosts without one of their own get: a column in a per-topic RocksDB.
 *
 * The token is an append-only log of `compact-timestamp -> token` rows in `current_offset`, read
 * back with a `SeekToLast`.
 *
 * @note @ref clear appends `"0"`; it does not delete, because an empty column reads as "no row" and
 *       the store could then not tell a clear from a first run. `load` maps a stored `"0"` back to "",
 *       which is what makes the cursor detector choose a full reload. The column grows by one row per
 *       write and is not pruned.
 */
class RocksDbTokenStore final : public content_manager::IContentTokenStore
{
public:
    /// Column holding the token rows.
    static constexpr auto COLUMN {"current_offset"};

    /**
     * @brief Open (or create) the token database of a topic, rebuilding it if what is on disk cannot
     *        be opened.
     *
     * `RocksDBWrapper` attempts its own repair first; this is the second line of defence, for when
     * that fails too. Discarding the file is safe here in a way it would not be for content: the
     * database holds only the token, and losing it costs one full re-download.
     *
     * @param databasePath Directory holding the token databases.
     * @param topicName Topic name; part of the database file name.
     * @return The store.
     * @throws std::exception if the database cannot be opened even after being rebuilt.
     */
    static std::shared_ptr<RocksDbTokenStore> open(const std::string& databasePath, const std::string& topicName)
    {
        std::filesystem::create_directories(databasePath);
        const auto databaseFile = databasePath + "/updater_" + topicName + "_metadata";

        std::shared_ptr<Utils::RocksDBWrapper> database;
        try
        {
            database = std::make_shared<Utils::RocksDBWrapper>(databaseFile);
        }
        catch (const std::exception& e)
        {
            logWarn(WM_CONTENTUPDATER,
                    "The content token database for '%s' could not be opened or repaired (%s); it will be rebuilt "
                    "and the next cycle will perform a full reload.",
                    topicName.c_str(),
                    e.what());

            std::error_code errorCode;
            std::filesystem::remove_all(databaseFile, errorCode);
            if (errorCode)
            {
                throw std::runtime_error {"Could not remove the unusable content token database '" + databaseFile +
                                          "': " + errorCode.message()};
            }
            database = std::make_shared<Utils::RocksDBWrapper>(databaseFile);
        }

        if (!database->columnExists(COLUMN))
        {
            database->createColumn(COLUMN);
        }
        return std::make_shared<RocksDbTokenStore>(std::move(database));
    }

    /**
     * @brief Build a store over an already-open database.
     *
     * @param database The token database, one per topic: the topic argument of the interface
     *                 methods only names it in log lines.
     */
    explicit RocksDbTokenStore(std::shared_ptr<Utils::RocksDBWrapper> database)
        : m_database {std::move(database)}
    {
    }

    std::string load(std::string_view topic) noexcept override
    {
        try
        {
            // A missing column and an empty one both read back as "no token", which costs a full
            // re-download. The empty one is the ordinary first run and stays quiet; a missing one
            // means something removed it from under us, and that has to be visible.
            if (!m_database->columnExists(COLUMN))
            {
                logWarn(WM_CONTENTUPDATER,
                        "The content token column is missing for '%s'; the next cycle will perform a full reload.",
                        std::string {topic}.c_str());
                return {};
            }

            auto value = m_database->getLastKeyValue(COLUMN).second;
            return value == "0" ? std::string {} : value;
        }
        catch (const std::exception&)
        {
            // Empty column: nothing has ever been committed for this topic.
            return {};
        }
    }

    bool store(std::string_view topic, std::string_view token) noexcept override
    {
        return write(topic, std::string {token});
    }

    bool clear(std::string_view topic) noexcept override
    {
        return write(topic, "0");
    }

private:
    bool write(std::string_view topic, const std::string& value) noexcept
    {
        try
        {
            m_database->put(Utils::getCompactTimestamp(std::time(nullptr)), value, COLUMN);
            return true;
        }
        catch (const std::exception& e)
        {
            logWarn(WM_CONTENTUPDATER,
                    "Failed to persist the content token for '%s': %s",
                    std::string {topic}.c_str(),
                    e.what());
            return false;
        }
    }

    std::shared_ptr<Utils::RocksDBWrapper> m_database;
};

#endif // _ROCKSDB_TOKEN_STORE_HPP
