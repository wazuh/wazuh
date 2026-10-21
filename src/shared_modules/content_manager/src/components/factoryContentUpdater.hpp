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

#ifndef _FACTORY_CONTENT_UPDATER_HPP
#define _FACTORY_CONTENT_UPDATER_HPP

#include "changeDetector.hpp"
#include "contentCycle.hpp"
#include "contentTopicSpec.hpp"
#include "loggerHelper.h"
#include "pitSession.hpp"
#include "sharedDefs.hpp"
#include <atomic>
#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <variant>

/**
 * @brief Turns a validated registration into a runnable @ref ContentCycle.
 */
class FactoryContentUpdater final
{
public:
    /**
     * @brief Build the cycle for a topic.
     *
     * @param spec The registration, already validated.
     * @param topicName Topic name.
     * @param sink Where the content goes.
     * @param tokenStore Where the token lives; may be null.
     * @param stop Cooperative stop flag; must outlive the cycle.
     * @param port Indexer access.
     * @return The cycle.
     */
    static std::unique_ptr<ContentCycle> create(const content_manager::TopicSpec& spec,
                                                const std::string& topicName,
                                                std::shared_ptr<content_manager::IContentSink> sink,
                                                std::shared_ptr<content_manager::IContentTokenStore> tokenStore,
                                                const std::atomic<bool>& stop,
                                                std::shared_ptr<content_manager::IContentIndexer> port)
    {
        ContentCycle::Config config;
        config.topic = topicName;

        config.pit.dataIndices = spec.source.indices;
        config.pit.keepAlive = spec.source.pitKeepAlive;
        config.pit.expandWildcards = spec.source.expandWildcards;
        if (spec.readiness.has_value())
        {
            config.pit.consumerStatusIndex = spec.readiness->consumerIndex;
            config.pit.consumerStatusId = spec.readiness->consumerId;
            config.consumerRetryInterval = std::chrono::seconds {spec.readiness->retrySeconds};
            config.consumerCacheTtl = std::chrono::seconds {spec.readiness->cacheSeconds};
        }

        config.fullSlices = spec.source.slices;
        config.requiredDocumentIds = spec.fullLoad.requiredDocumentIds;
        config.fetchTemplate.pageSize = spec.source.pageSize;
        config.fetchTemplate.sourceFilter = spec.source.sourceFilter;

        std::unique_ptr<IChangeDetector> detector;
        const char* strategy = "cursor";
        if (const auto* cursor = std::get_if<content_manager::CursorDetection>(&spec.detection))
        {
            config.fetchTemplate.sort = cursorSort(*cursor);
            detector = std::make_unique<OffsetCursorDetector>(cursor->field, spec.source.query);
        }
        else
        {
            strategy = "hash";
            config.fetchTemplate.sort = PitSession::docSort();
            detector = std::make_unique<ContentHashDetector>(
                hashConfig(std::get<content_manager::HashDetection>(spec.detection), spec.source.query));
        }

        logDebug1(WM_CONTENTUPDATER,
                  "Content cycle for '%s' created (detection=%s, indices=%zu, slices=%zu, pageSize=%zu)",
                  topicName.c_str(),
                  strategy,
                  config.pit.dataIndices.size(),
                  config.fullSlices,
                  config.fetchTemplate.pageSize);

        return std::make_unique<ContentCycle>(
            std::move(config), std::move(port), std::move(detector), std::move(sink), std::move(tokenStore), stop);
    }

private:
    /**
     * @brief The cursor field, with an `unmapped_type`, then `_id`.
     *
     * OpenSearch requires a sort field to be mapped in **at least one** index of the search, not in
     * every one, so a consumer index lacking the cursor field is harmless on its own (verified by
     * `testtool/integration/query_contract_test.py`). What is not harmless is a **cold start**: a
     * fresh install's data index holds no documents yet, so the field is unmapped across every index
     * of the search — consumer index or not — and OpenSearch rejects it. The `unmapped_type` makes a
     * new topic's first full load work.
     *
     * @param cursor The cursor detection.
     * @return The sort array.
     */
    static nlohmann::json cursorSort(const content_manager::CursorDetection& cursor)
    {
        const nlohmann::json field {{"order", "asc"}, {"unmapped_type", cursor.unmappedType}};
        return nlohmann::json::array({nlohmann::json {{cursor.field, field}}, nlohmann::json {{"_id", "asc"}}});
    }

    static ContentHashDetector::Config hashConfig(const content_manager::HashDetection& hash,
                                                  const std::optional<nlohmann::json>& sourceQuery)
    {
        ContentHashDetector::Config config;
        if (const auto* document = std::get_if<content_manager::DocumentProbe>(&hash.probe))
        {
            config.hashDocId = document->id;
        }
        else
        {
            config.hashQuery = std::get<content_manager::QueryProbe>(hash.probe).query;
        }
        config.hashPointers = hash.tokenPointers;
        config.metadataPointers = hash.metadata;
        config.dataQuery = sourceQuery.value_or(nlohmann::json {{"match_all", nlohmann::json::object()}});
        return config;
    }
};

#endif // _FACTORY_CONTENT_UPDATER_HPP
