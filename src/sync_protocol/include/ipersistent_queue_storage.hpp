/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <vector>
#include "ipersistent_queue.hpp"

/// @brief Interface for persistent storage backend used by PersistentQueue.
///
/// Implementations of this interface are responsible for saving, retrieving,
/// and deleting queued messages from a persistent store (e.g., SQLite).
class IPersistentQueueStorage
{
    public:
        /// @brief Virtual destructor.
        virtual ~IPersistentQueueStorage() = default;

        /// @brief Saves a new message entry into the persistent storage.
        /// @param module The module identifier.
        /// @param data The message data to persist.
        virtual void save(const std::string& module, const PersistedData& data) = 0;

        /// @brief Deletes a specific message from persistent storage.
        /// @param module The module identifier.
        /// @param sequence The sequence number of the message to delete.
        virtual void remove(const std::string& module, uint64_t sequence) = 0;

        /// @brief Deletes all messages belonging to a specific module.
        /// @param module The module whose messages will be removed.
        virtual void removeAll(const std::string& module) = 0;

        /// @brief Loads all persisted messages for the given module.
        /// @param module The module to load messages for.
        /// @return A vector containing all messages found.
        virtual std::vector<PersistedData> loadAll(const std::string& module) = 0;
};
