/*
 * Wazuh content manager
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INITIAL_LOAD_STATE_HPP
#define _INITIAL_LOAD_STATE_HPP

#include "rocksDBWrapper.hpp"
#include <exception>
#include <filesystem>
#include <string>

/**
 * @brief The updater-DB marker IndexerDownloader keeps while an initial load has started and its completion
 *        has not been accepted, and a read-only check for consumers that decide at startup whether to keep
 *        the updater state.
 */
namespace InitialLoadState
{
    constexpr auto PENDING_COLUMN {"initial_load_pending"}; ///< Updater DB column of the marker.
    constexpr auto PENDING_KEY {"pending"};                 ///< Key of the marker in that column.

    /**
     * @brief Name of a topic's updater DB inside the configured `databasePath`.
     */
    inline std::string updaterDatabaseName(const std::string& topicName)
    {
        return "updater_" + topicName + "_metadata";
    }

    /**
     * @brief Whether the updater DB of @p topicName under @p databasePath records a pending initial load.
     *
     * Opens the DB only when it exists; must run before the content updater opens it.
     *
     * @return false when there is no DB, no marker, or the DB cannot be read.
     */
    inline bool isPending(const std::string& databasePath, const std::string& topicName)
    {
        const auto path = std::filesystem::path {databasePath} / updaterDatabaseName(topicName);
        if (!std::filesystem::exists(path / "CURRENT"))
        {
            return false;
        }
        try
        {
            Utils::RocksDBWrapper database(path.string(), true, false);
            std::string value;
            return database.columnExists(PENDING_COLUMN) && database.get(PENDING_KEY, value, PENDING_COLUMN);
        }
        catch (const std::exception&)
        {
            return false;
        }
    }
} // namespace InitialLoadState

#endif // _INITIAL_LOAD_STATE_HPP
