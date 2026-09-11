/*
 * Wazuh content manager
 * Copyright (C) 2015, Wazuh Inc.
 * May 12, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _FACTORY_CONTENT_UPDATER_HPP
#define _FACTORY_CONTENT_UPDATER_HPP

#include "changeDetector.hpp"
#include "contentCycle.hpp"
#include "executionContext.hpp"
#include "loggerHelper.h"
#include "sharedDefs.hpp"
#include <algorithm>
#include <chrono>
#include <memory>
#include <string>
#include <utility>

/**
 * @brief Turns a registration's JSON into a runnable @ref ContentCycle.
 *
 * It became a real factory: it now dispatches on `configData.changeDetection`, where it used to
 * assemble one fixed two-element chain and ignore the (decorative) `contentSource` key entirely.
 */
class FactoryContentUpdater final
{
public:
    /**
     * @brief Build the cycle for a topic.
     *
     * @param configData The `configData` object of the registration parameters. Already validated
     *                   by @ref ExecutionContext::validate.
     * @param topicName Topic name.
     * @param sink Where the content goes.
     * @param tokenStore Where the token lives; may be null.
     * @param stop Cooperative stop flag.
     * @param port Indexer access.
     * @return The cycle.
     * @throws std::invalid_argument if the configuration is not usable.
     */
    static std::unique_ptr<ContentCycle> create(const nlohmann::json& configData,
                                                const std::string& topicName,
                                                std::shared_ptr<content_manager::IContentSink> sink,
                                                std::shared_ptr<content_manager::IContentTokenStore> tokenStore,
                                                std::shared_ptr<ConditionSync> stop,
                                                std::shared_ptr<IIndexerQueryPort> port)
    {
        const auto& indexer = configData.at("indexer");
        const auto changeDetection = configData.at("changeDetection").get<std::string>();

        ContentCycle::Config config;
        config.topic = topicName;

        config.pit.dataIndices = ExecutionContext::dataIndices(indexer);
        config.pit.consumerStatusIndex = indexer.value("consumerStatusIndex", std::string {});
        config.pit.consumerStatusId = indexer.value("consumerStatusId", std::string {});
        config.pit.keepAlive = indexer.value("keepAlive", std::string {"5m"});
        config.pit.expandWildcards = indexer.value("expandWildcards", false);

        config.fullSlices = std::max<std::size_t>(1, indexer.value("numSlices", 1U));
        config.consumerRetryInterval =
            std::chrono::seconds {std::max<std::size_t>(1, configData.value("consumerRetryIntervalSeconds", 60U))};
        config.consumerCacheTtl = std::chrono::seconds {indexer.value("consumerStatusCacheSeconds", 5U)};

        if (indexer.contains("requiredDocumentIds") && indexer.at("requiredDocumentIds").is_array())
        {
            config.requiredDocumentIds = indexer.at("requiredDocumentIds");
        }

        config.fetchTemplate.pageSize = readPageSize(indexer);
        if (indexer.contains("sourceFilter") && indexer.at("sourceFilter").is_object())
        {
            config.fetchTemplate.sourceFilter = indexer.at("sourceFilter");
        }

        std::unique_ptr<IChangeDetector> detector;
        if (changeDetection == "cursor")
        {
            auto cursorField = indexer.value("cursorField", std::string {"offset"});
            config.fetchTemplate.sort = buildSort(indexer, config.pit.consumerStatusIndex, cursorField);
            detector = std::make_unique<OffsetCursorDetector>(std::move(cursorField));
        }
        else
        {
            config.fetchTemplate.sort = buildSort(indexer, config.pit.consumerStatusIndex, {});
            detector = std::make_unique<ContentHashDetector>(buildHashConfig(indexer));
        }

        logDebug1(WM_CONTENTUPDATER,
                  "Content cycle for '%s' created (changeDetection=%s, indices=%zu, slices=%zu, pageSize=%zu)",
                  topicName.c_str(),
                  changeDetection.c_str(),
                  config.pit.dataIndices.size(),
                  config.fullSlices,
                  config.fetchTemplate.pageSize);

        return std::make_unique<ContentCycle>(std::move(config),
                                              std::move(port),
                                              std::move(detector),
                                              std::move(sink),
                                              std::move(tokenStore),
                                              std::move(stop));
    }

private:
    /**
     * @brief Build the sort array, making it safe for a PIT that also spans the consumer index.
     *
     * This is the one place that knows about a sharp edge of the in-PIT consistency model, and it is
     * worth stating precisely, because the imprecise version of it invites deleting the injection.
     *
     * OpenSearch requires a sort field to be mapped in **at least one** index of the search, not in
     * every one. So `.wazuh-cti-consumers` lacking `offset` is, on its own, harmless: documents from
     * it simply sort as missing, and the search succeeds. Verified against OpenSearch 3.7 by
     * `testtool/integration/query_contract_test.py`.
     *
     * What is not harmless is a **cold start**. A fresh install's data index holds no documents yet,
     * so nothing has triggered a dynamic mapping for the cursor field — and now the field is
     * unmapped across every index in the PIT, which OpenSearch does reject, failing the whole
     * search. That is precisely the first full load of a new manager: without this injection it
     * fails, and so does every cycle after it until something else creates the mapping.
     *
     * Metafields (`_id`, `_shard_doc`, …) are synthesised rather than mapped and are left alone,
     * which is why the Engine, which sorts on `_shard_doc`, is unaffected either way.
     */
    static nlohmann::json
    buildSort(const nlohmann::json& indexer, const std::string& consumerStatusIndex, const std::string& cursorField)
    {
        const auto unmappedType = indexer.value("sortUnmappedType", std::string {"long"});

        nlohmann::json configured;
        if (indexer.contains("sortKeys") && indexer.at("sortKeys").is_array() && !indexer.at("sortKeys").empty())
        {
            configured = indexer.at("sortKeys");
        }
        else if (!cursorField.empty())
        {
            configured = nlohmann::json::array(
                {nlohmann::json {{cursorField, "asc"}}, nlohmann::json {{"_id", "asc"}}});
        }
        else
        {
            configured = nlohmann::json::array(
                {nlohmann::json {{"_shard_doc", "asc"}}, nlohmann::json {{"_id", "asc"}}});
        }

        if (consumerStatusIndex.empty())
        {
            return configured;
        }

        auto sort = nlohmann::json::array();
        for (const auto& key : configured)
        {
            if (!key.is_object() || key.empty())
            {
                sort.push_back(key);
                continue;
            }

            const auto field = key.begin().key();
            if (isMetaField(field))
            {
                sort.push_back(key);
                continue;
            }

            const auto order = key.begin().value().is_string() ? key.begin().value().get<std::string>()
                                                               : key.begin().value().value("order", "asc");
            sort.push_back(nlohmann::json {{field, {{"order", order}, {"unmapped_type", unmappedType}}}});
        }
        return sort;
    }

    static bool isMetaField(const std::string& field) noexcept
    {
        return !field.empty() && field.front() == '_';
    }

    static ContentHashDetector::Config buildHashConfig(const nlohmann::json& indexer)
    {
        ContentHashDetector::Config config;
        config.hashDocId = indexer.value("hashDocId", std::string {});
        config.hashIndex = indexer.value("hashIndex", std::string {});
        config.hashQuery = indexer.value("hashQuery", nlohmann::json::object());
        config.dataQuery = indexer.at("dataQuery");

        for (const auto& pointer : indexer.at("hashPointers"))
        {
            config.hashPointers.push_back(pointer.get<std::string>());
        }

        if (indexer.contains("metadataPointers") && indexer.at("metadataPointers").is_object())
        {
            for (const auto& [name, pointer] : indexer.at("metadataPointers").items())
            {
                if (pointer.is_string())
                {
                    config.metadataPointers.emplace(name, pointer.get<std::string>());
                }
            }
        }

        return config;
    }

    /// A page size of 0 would make every search return an empty page, so the fetch would report
    /// "nothing to do" forever. Not every caller sanitises its own config, so it is guarded here.
    static std::size_t readPageSize(const nlohmann::json& indexer)
    {
        constexpr std::size_t DEFAULT_PAGE_SIZE {100};

        const auto pageSize = indexer.value("pageSize", 0U);
        if (pageSize == 0)
        {
            if (indexer.contains("pageSize"))
            {
                logWarn(WM_CONTENTUPDATER, "Invalid pageSize 0 — using the default %zu.", DEFAULT_PAGE_SIZE);
            }
            return DEFAULT_PAGE_SIZE;
        }
        return pageSize;
    }
};

#endif // _FACTORY_CONTENT_UPDATER_HPP
