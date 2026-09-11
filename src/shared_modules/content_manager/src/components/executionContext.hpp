/*
 * Wazuh content manager
 * Copyright (C) 2015, Wazuh Inc.
 * May 23, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _EXECUTION_CONTEXT_HPP
#define _EXECUTION_CONTEXT_HPP

#include "componentsHelper.hpp"
#include "defs.h"
#include "loggerHelper.h"
#include "sharedDefs.hpp"
#include <filesystem>
#include <json.hpp>
#include <memory>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

// `defs.h` defines USER as a string macro, and rocksdb spells USER as an enumerator in both
// Env::Priority and ThreadStatus::ThreadType. Whichever the preprocessor sees first wins, and with
// the macro in force those two enums fail to parse — which surfaces as a few hundred errors deep
// inside rocksdb headers that say nothing about the actual cause. Shield the include and put the
// macro back, so this holds however our own includers happen to be ordered.
#pragma push_macro("USER")
#undef USER
#include "utils/rocksDBWrapper.hpp"
#pragma pop_macro("USER")

/**
 * @brief Validates a registration's configuration and opens whatever storage it asks for.
 *
 * Reduced to exactly that. It used to also create download/content folders for file-based
 * downloaders; there are none left — content streams from the indexer straight into the sink — so
 * those folders were pure overhead and are gone.
 *
 * Everything this class rejects is rejected **at registration**, which is the only point where a
 * configuration error can still be reported to the host as an exception rather than having to be
 * flattened into a `CycleStatus::FailedConfig` on every cycle forever.
 */
class ExecutionContext final
{
public:
    std::string httpUserAgent;                          ///< `consumerName/<version>`.
    std::shared_ptr<Utils::RocksDBWrapper> database;    ///< Updater database, or null when unused.

    /**
     * @brief Validate @p configData and open its database if it has one.
     *
     * @param configData The `configData` object of the registration parameters.
     * @param topicName Topic name; part of the database file name.
     * @return The prepared context.
     * @throws std::invalid_argument if the configuration is not usable.
     */
    static ExecutionContext prepare(const nlohmann::json& configData, const std::string& topicName)
    {
        validate(configData);

        ExecutionContext context;
        context.httpUserAgent = configData.at("consumerName").get<std::string>() + "/" + __wazuh_version;

        const auto databasePath = configData.value("databasePath", std::string {});
        if (!databasePath.empty())
        {
            context.database = openDatabase(databasePath, topicName);
        }

        return context;
    }

    /**
     * @brief Check a registration's configuration without touching the filesystem.
     *
     * @param configData The `configData` object of the registration parameters.
     * @throws std::invalid_argument with a message naming the offending key.
     */
    static void validate(const nlohmann::json& configData)
    {
        if (!configData.is_object())
        {
            throw std::invalid_argument {"configData must be an object"};
        }

        if (!configData.contains("consumerName") || !configData.at("consumerName").is_string() ||
            configData.at("consumerName").get_ref<const std::string&>().empty())
        {
            throw std::invalid_argument {"Missing or empty consumerName"};
        }

        const auto changeDetection = configData.value("changeDetection", std::string {});
        if (changeDetection != "cursor" && changeDetection != "hash")
        {
            throw std::invalid_argument {"changeDetection must be either \"cursor\" or \"hash\""};
        }

        if (!configData.contains("indexer") || !configData.at("indexer").is_object())
        {
            throw std::invalid_argument {"Missing indexer configuration"};
        }
        const auto& indexer = configData.at("indexer");

        if (dataIndices(indexer).empty())
        {
            throw std::invalid_argument {"indexer must define a non-empty \"index\" or \"indices\""};
        }

        validateConsumerStatusIndex(indexer);

        if (changeDetection == "hash")
        {
            validateHashProbe(indexer);
        }

        validateQueryShape(indexer);
    }

    /**
     * @brief The indices a registration's PIT covers, excluding the consumer status index.
     *
     * @param indexer The `configData.indexer` object.
     * @return Index names, in configuration order.
     */
    static std::vector<std::string> dataIndices(const nlohmann::json& indexer)
    {
        std::vector<std::string> indices;

        if (indexer.contains("indices") && indexer.at("indices").is_array())
        {
            for (const auto& entry : indexer.at("indices"))
            {
                if (entry.is_string() && !entry.get_ref<const std::string&>().empty())
                {
                    indices.push_back(entry.get<std::string>());
                }
            }
        }
        else if (indexer.contains("index") && indexer.at("index").is_string() &&
                 !indexer.at("index").get_ref<const std::string&>().empty())
        {
            indices.push_back(indexer.at("index").get<std::string>());
        }

        return indices;
    }

private:
    /**
     * @brief Type-check the keys that shape the search request.
     *
     * These are read later with `json::value(key, default)`, which throws a `type_error` naming
     * nothing useful when the stored type does not match — and, worse, `sourceFilter` and `sortKeys`
     * are read behind an `is_object`/`is_array` test, so a mistyped one is silently *ignored*. For
     * `sourceFilter` that means quietly downloading every field of every document: the vulnerability
     * scanner's filter drops most of a CVE5 record, so losing it turns a feed update into a
     * multi-gigabyte transfer that still works and is therefore never noticed. Rejecting the
     * registration is the only point at which that is cheap to catch.
     *
     * @param indexer The `configData.indexer` object.
     */
    static void validateQueryShape(const nlohmann::json& indexer)
    {
        if (indexer.contains("numSlices"))
        {
            const auto& slices = indexer.at("numSlices");
            if (!slices.is_number_unsigned() || slices.get<std::size_t>() == 0)
            {
                throw std::invalid_argument {"indexer.numSlices must be a positive integer"};
            }
        }

        if (indexer.contains("pageSize") && !indexer.at("pageSize").is_number_unsigned())
        {
            throw std::invalid_argument {"indexer.pageSize must be a positive integer"};
        }

        if (indexer.contains("consumerStatusCacheSeconds") &&
            !indexer.at("consumerStatusCacheSeconds").is_number_unsigned())
        {
            throw std::invalid_argument {"indexer.consumerStatusCacheSeconds must be a non-negative integer"};
        }

        if (indexer.contains("keepAlive") &&
            (!indexer.at("keepAlive").is_string() || indexer.at("keepAlive").get_ref<const std::string&>().empty()))
        {
            throw std::invalid_argument {"indexer.keepAlive must be a non-empty duration string, e.g. \"5m\""};
        }

        if (indexer.contains("expandWildcards") && !indexer.at("expandWildcards").is_boolean())
        {
            throw std::invalid_argument {"indexer.expandWildcards must be a boolean"};
        }

        if (indexer.contains("sourceFilter") && !indexer.at("sourceFilter").is_object())
        {
            throw std::invalid_argument {"indexer.sourceFilter must be an object with \"includes\"/\"excludes\""};
        }

        if (indexer.contains("cursorField") &&
            (!indexer.at("cursorField").is_string() ||
             indexer.at("cursorField").get_ref<const std::string&>().empty()))
        {
            throw std::invalid_argument {"indexer.cursorField must be a non-empty field name"};
        }

        if (indexer.contains("sortKeys"))
        {
            const auto& sortKeys = indexer.at("sortKeys");
            if (!sortKeys.is_array() || sortKeys.empty())
            {
                throw std::invalid_argument {"indexer.sortKeys must be a non-empty array"};
            }
            for (const auto& key : sortKeys)
            {
                if (!key.is_object() || key.empty())
                {
                    throw std::invalid_argument {"indexer.sortKeys entries must be single-field objects"};
                }
            }
        }

        if (indexer.contains("requiredDocumentIds"))
        {
            const auto& ids = indexer.at("requiredDocumentIds");
            if (!ids.is_array())
            {
                throw std::invalid_argument {"indexer.requiredDocumentIds must be an array of document ids"};
            }
            for (const auto& id : ids)
            {
                if (!id.is_string() || id.get_ref<const std::string&>().empty())
                {
                    throw std::invalid_argument {"indexer.requiredDocumentIds entries must be non-empty strings"};
                }
            }
        }
    }

    /**
     * @brief The consumer status index must be one concrete index, not an alias or a pattern.
     *
     * Both defences against consumer documents leaking into the content — the query-side `must_not`
     * on `_index` and the hit-side drop — compare against the `_index` metafield, and that reports
     * the concrete backing index. A pattern or a comma list would simply never match, so the leak
     * would be silent. Rejecting it here is the only place it can be caught cheaply.
     */
    static void validateConsumerStatusIndex(const nlohmann::json& indexer)
    {
        const auto index = indexer.value("consumerStatusIndex", std::string {});
        if (index.empty())
        {
            return;
        }

        if (index.find('*') != std::string::npos || index.find(',') != std::string::npos || index.front() == '-')
        {
            throw std::invalid_argument {
                "indexer.consumerStatusIndex must be a concrete index name (no wildcard, comma list or exclusion): '" +
                index + "'"};
        }

        if (indexer.value("consumerStatusId", std::string {}).empty())
        {
            throw std::invalid_argument {"indexer.consumerStatusId is required when consumerStatusIndex is set"};
        }
    }

    static void validateHashProbe(const nlohmann::json& indexer)
    {
        const bool hasDocId = indexer.contains("hashDocId") && indexer.at("hashDocId").is_string() &&
                              !indexer.at("hashDocId").get_ref<const std::string&>().empty();
        const bool hasIndex = indexer.contains("hashIndex") && indexer.at("hashIndex").is_string() &&
                              !indexer.at("hashIndex").get_ref<const std::string&>().empty();

        if (hasDocId == hasIndex)
        {
            throw std::invalid_argument {
                "hash change detection requires exactly one of indexer.hashDocId or indexer.hashIndex"};
        }

        if (hasIndex && (!indexer.contains("hashQuery") || !indexer.at("hashQuery").is_object()))
        {
            throw std::invalid_argument {"indexer.hashQuery is required when indexer.hashIndex is set"};
        }

        if (!indexer.contains("hashPointers") || !indexer.at("hashPointers").is_array() ||
            indexer.at("hashPointers").empty())
        {
            throw std::invalid_argument {"indexer.hashPointers must be a non-empty array of JSON pointers"};
        }

        for (const auto& pointer : indexer.at("hashPointers"))
        {
            if (!pointer.is_string() || pointer.get_ref<const std::string&>().empty() ||
                pointer.get_ref<const std::string&>().front() != '/')
            {
                throw std::invalid_argument {"indexer.hashPointers entries must be JSON pointers starting with '/'"};
            }
        }

        if (!indexer.contains("dataQuery") || !indexer.at("dataQuery").is_object())
        {
            throw std::invalid_argument {"indexer.dataQuery is required for hash change detection"};
        }
    }

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
