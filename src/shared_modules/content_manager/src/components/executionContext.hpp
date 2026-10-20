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

#ifndef _EXECUTION_CONTEXT_HPP
#define _EXECUTION_CONTEXT_HPP

// Deliberately NOT `defs.h`. That is a C header: no `extern "C"`, no namespace, just unqualified
// object macros — TRUE, FALSE, READ, WRITE, USER, LOGLEVEL_DEBUG and friends — dumped into the
// global scope of whatever includes it. In C++ that collides with real identifiers, and it did
// twice here: `LOGLEVEL_DEBUG` against `loggerHelper.h`'s `constexpr` variables of the same names,
// and `USER` against rocksdb's enumerators. It was included for exactly one thing, the
// `__wazuh_version` string, to build an HTTP User-Agent that nothing ever read.
#include "componentsHelper.hpp"
#include "contentTopicSpec.hpp"
#include "loggerHelper.h"
#include "sharedDefs.hpp"
#include <cstdint>
#include <filesystem>
#include <json.hpp>
#include <memory>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

// Kept as a guard, not as a fix: nothing here includes `defs.h` any more, but this header is not in
// a position to know what its includers pulled in first, and a `USER` macro in force makes rocksdb's
// Env::Priority and ThreadStatus::ThreadType enumerators fail to parse — surfacing as a few hundred
// errors deep inside rocksdb headers that say nothing about the actual cause.
#pragma push_macro("USER")
#undef USER
#include "utils/rocksDBWrapper.hpp"
#pragma pop_macro("USER")

/**
 * @brief Opens whatever storage a registration asks for.
 *
 * Validation used to live here too, as a set of checks against the raw parameters; it moved to
 * @ref TopicSpecParser (D2), which turns them into the typed model every stage reads, so this class
 * is left with the one thing that touches the filesystem.
 */
class ExecutionContext final
{
public:
    std::shared_ptr<Utils::RocksDBWrapper> database; ///< Updater database, or null when unused.

    /**
     * @brief Open the registration's token database, if it has one.
     *
     * @param spec The parsed registration.
     * @param topicName Topic name; part of the database file name.
     * @return The prepared context.
     * @throws std::exception if the database cannot be opened even after being rebuilt.
     */
    static ExecutionContext prepare(const content_manager::TopicSpec& spec, const std::string& topicName)
    {
        ExecutionContext context;
        if (!spec.state.databasePath.empty())
        {
            context.database = openDatabase(spec.state.databasePath, topicName);
        }
        return context;
    }

private:
    /**
     * @brief Open the updater database, rebuilding it if what is on disk cannot be opened.
     *
     * `RocksDBWrapper` already attempts its own repair first (`repairIfCorrupt` defaults to true),
     * so this is the second line of defence, for when that repair fails too. It matters because the
     * failure mode is otherwise a *host that will not start*: the open throws, the registration
     * constructor propagates it, and the vulnerability scanner dies with it. That used to be
     * survivable only by accident — the scanner deleted this whole directory before registering, a
     * reach-in that no longer exists.
     *
     * Discarding the file is the right answer here in a way it would not be for content: this
     * database holds one thing, the change-detection token, and losing it costs exactly one full
     * re-download — which is also precisely what a database that could not be repaired needs.
     *
     * @param databasePath Directory holding the updater databases.
     * @param topicName Topic name; part of the database file name.
     * @return The open database.
     * @throws std::exception if it cannot be opened even after being rebuilt.
     */
    static std::shared_ptr<Utils::RocksDBWrapper> openDatabase(const std::string& databasePath,
                                                               const std::string& topicName)
    {
        if (!std::filesystem::exists(databasePath))
        {
            std::filesystem::create_directories(databasePath);
        }

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

            // Left to throw: a rebuild that fails too is not a recoverable state, and starting with
            // no token store at all would silently re-download the whole feed on every cycle
            // forever, which is worse than refusing to register.
            database = std::make_shared<Utils::RocksDBWrapper>(databaseFile);
        }

        if (!database->columnExists(Components::Columns::CURRENT_OFFSET))
        {
            logDebug1(WM_CONTENTUPDATER,
                      "Column '%s' doesn't exist so it will be created",
                      Components::Columns::CURRENT_OFFSET.c_str());
            database->createColumn(Components::Columns::CURRENT_OFFSET);
        }

        return database;
    }
};

#endif // _EXECUTION_CONTEXT_HPP
