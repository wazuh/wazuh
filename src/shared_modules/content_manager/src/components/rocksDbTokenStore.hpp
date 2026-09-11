/*
 * Wazuh content manager
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ROCKSDB_TOKEN_STORE_HPP
#define _ROCKSDB_TOKEN_STORE_HPP

#include "componentsHelper.hpp"
#include "contentTokenStore.hpp"
#include "loggerHelper.h"
#include "sharedDefs.hpp"
#include "utils/timeHelper.h"
#include <ctime>
#include <memory>
#include <utility>

// See executionContext.hpp: `defs.h`'s USER macro collides with rocksdb's USER enumerator, so any
// header of ours that reaches for rocksdb has to shield the include rather than rely on being the
// first one to get there.
#pragma push_macro("USER")
#undef USER
#include "utils/rocksDBWrapper.hpp"
#pragma pop_macro("USER")

/**
 * @brief The token store hosts without one of their own get: a column in the updater's RocksDB.
 *
 * The on-disk format is the one that already exists and is deliberately unchanged — an append-only
 * log of `compact-timestamp -> token` rows in `current_offset`, read back with `getLastKeyValue`
 * (a `SeekToLast`). Deployed updater databases are readable by this class byte for byte, so no
 * migration is needed.
 *
 * @note @ref clear appends `"0"`; it does not delete. `getLastKeyValue` **throws** on an empty
 *       column, so an actual delete would break every subsequent @ref load. `load` maps a stored
 *       `"0"` back to "" — which is what makes the cursor detector choose a full reload. The
 *       consequence is that the column grows by one row per write and is never pruned. That is
 *       pre-existing behaviour, recorded here as a known wart rather than silently inherited;
 *       bounding it is a separate piece of work.
 */
class RocksDbTokenStore final : public content_manager::IContentTokenStore
{
public:
    /**
     * @brief Build a store over an already-open database.
     *
     * @param database The updater database. One per topic, so the topic argument of the interface
     *                 methods is informational here.
     */
    explicit RocksDbTokenStore(std::shared_ptr<Utils::RocksDBWrapper> database)
        : m_database {std::move(database)}
    {
    }

    std::string load(std::string_view topic) noexcept override
    {
        if (!m_database)
        {
            return {};
        }

        try
        {
            // `getLastKeyValue` throws the same way for an empty column and for a missing one, and
            // both read back as "no token" — which silently costs a full re-download of the whole
            // feed. The first is the ordinary first-run case and must stay quiet; the second means
            // something removed the column from under us, and an operator has no other way to find
            // out why the feed rebuilt itself.
            if (!m_database->columnExists(Components::Columns::CURRENT_OFFSET))
            {
                logWarn(WM_CONTENTUPDATER,
                        "The content token column is missing for '%s'; the next cycle will perform a full reload.",
                        std::string {topic}.c_str());
                return {};
            }

            auto value = m_database->getLastKeyValue(Components::Columns::CURRENT_OFFSET).second.ToString();
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
        if (token.empty())
        {
            // Nothing to record. Writing "" would be read back as "no token" anyway, so this is not
            // a failure — it is a no-op the caller must not treat as a persistence error.
            return true;
        }
        return write(topic, std::string {token});
    }

    bool clear(std::string_view topic) noexcept override
    {
        return write(topic, "0");
    }

private:
    bool write(std::string_view topic, const std::string& value) noexcept
    {
        if (!m_database)
        {
            return false;
        }

        try
        {
            m_database->put(Utils::getCompactTimestamp(std::time(nullptr)),
                            value,
                            Components::Columns::CURRENT_OFFSET);
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
