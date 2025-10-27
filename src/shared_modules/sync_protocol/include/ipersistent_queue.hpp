/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include "agent_sync_protocol_c_interface_types.h"

#include <cstdint>
#include <string>
#include <optional>
#include <vector>

/// @brief Defines the type of modification operation.
enum class Operation : int
{
    CREATE = OPERATION_CREATE,  ///< The operation is to create a new record.
    MODIFY = OPERATION_MODIFY,  ///< The operation is to modify an existing record.
    DELETE_ = OPERATION_DELETE, ///< The operation is to delete a record.
    NO_OP  = OPERATION_NO_OP    ///< No specific operation is being synchronized. Represents a neutral state.
};

/// @brief Defines the type of synchronization mode.
enum class Mode : int
{
    FULL  = MODE_FULL,               ///< Full synchronization mode.
    DELTA = MODE_DELTA,              ///< Delta synchronization mode.
    CHECK = MODE_CHECK,              ///< Integrity check mode.
    METADATA_DELTA = MODE_METADATA_DELTA, ///< Metadata delta synchronization mode.
    METADATA_CHECK = MODE_METADATA_CHECK, ///< Metadata integrity check mode.
    GROUP_DELTA = MODE_GROUP_DELTA,       ///< Group delta synchronization mode.
    GROUP_CHECK = MODE_GROUP_CHECK        ///< Group integrity check mode.
};

/// @brief Defines additional synchronization options.
enum class Option : int
{
    SYNC    = OPTION_SYNC,     ///< Standard synchronization option.
    VDFIRST = OPTION_VD_FIRST, ///< Virtual data first synchronization option.
    VDSYNC  = OPTION_VD_SYNC,  ///< Virtual data synchronization option.
    VDCLEAN = OPTION_VD_CLEAN  ///< Virtual data cleanup synchronization option.
};

/// @brief Represents a persisted message used in module synchronization.
///
/// This structure encapsulates the minimal data required to represent a
/// stateful message that can be stored, replayed, or synchronized.
struct PersistedData
{
    /// @brief Sequence number of the message (scoped per module).
    uint64_t seq;

    /// @brief Unique identifier of the message.
    std::string id;

    /// @brief Logical index
    std::string index;

    /// @brief Serialized content of the message.
    std::string data;

    /// @brief Type of operation (CREATE, MODIFY, DELETE).
    Operation operation;

    /// @brief Version of the data.
    uint64_t version;
};

/// @brief Interface for persistent message queues.
///
/// This abstraction allows storing, retrieving, and deleting messages
/// tied to individual agent modules (e.g., FIM, SCA).
/// It decouples in-memory logic from the actual storage backend.
class IPersistentQueue
{
    public:
        /// @brief Virtual destructor.
        virtual ~IPersistentQueue() = default;

        /// @brief Adds a new message to the queue and returns its assigned sequence number.
        /// @param id The message ID.
        /// @param index The message grouping key.
        /// @param data The serialized payload of the message.
        /// @param operation The type of operation (CREATE, MODIFY, DELETE).
        /// @param version Version of the data.
        virtual void submit(const std::string& id,
                            const std::string& index,
                            const std::string& data,
                            Operation operation,
                            uint64_t version) = 0;

        /// @brief Fetches a batch of pending messages and marks them for synchronization.
        /// @return A vector of messages now marked as SYNCING.
        virtual std::vector<PersistedData> fetchAndMarkForSync() = 0;

        /// @brief Clears items that were successfully synchronized.
        virtual void clearSyncedItems() = 0;

        /// @brief Resets items that failed to synchronize.
        virtual void resetSyncingItems() = 0;

        /// @brief Clears all items belonging to a specific index.
        /// @param index The index for which all items should be cleared.
        virtual void clearItemsByIndex(const std::string& index) = 0;

        /// @brief Deletes the database file.
        /// This method closes the database connection and removes the database file from disk.
        virtual void deleteDatabase() = 0;
};
