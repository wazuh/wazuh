/*
 * Wazuh content manager
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INDEXER_DOWNLOADER_HPP
#define _INDEXER_DOWNLOADER_HPP

#include "componentsHelper.hpp"
#include "indexerConnector.hpp"
#include "sharedDefs.hpp"
#include "updaterContext.hpp"
#include "utils/chainOfResponsability.hpp"
#include "utils/timeHelper.h"
#include <memory>
#include <string>
#include <tuple>

/**
 * @class IndexerDownloader
 *
 * @brief Downloads CVE data from the Wazuh Indexer and feeds it directly to the
 *        fileProcessingCallback without writing intermediate files to disk.
 *
 * Replaces CtiOffsetDownloader and CtiSnapshotDownloader.
 *
 * Behaviour:
 *  - Initial load  (stored cursor is empty / "0"):
 *      Uses executeSearchQueryWithPagination with match_all sorted by offset.
 *      PIT (IndexerConnectorAsync) is not used because both connector types compete for
 *      an exclusive RocksDB lock on queue/indexer/, and the facade already holds one via
 *      its IndexerConnectorSync instance. search_after with a stable sort (offset, _id)
 *      is equivalent for this feed because the index is only updated in scheduled batches.
 *  - Incremental update (stored cursor is an integer offset):
 *      Uses an offset range query via IndexerConnectorSync::executeSearchQueryWithPagination.
 *      Fetches all documents whose offset field is greater than the stored value.
 *
 * For each page the downloader constructs a message of type "indexer" and invokes
 * fileProcessingCallback synchronously. The highest offset seen is stored in
 * context.data["cursor"] so that UpdateIndexerCursor can persist it to RocksDB.
 *
 * Configuration expected under configData["indexer"]:
 * {
 *   "index":    ".cti-cves",     // Indexer CVE index name
 *   "pageSize": 1000,            // Documents per page (optional, default 1000)
 *   <standard IndexerConnector SSL/auth config>
 * }
 */
class IndexerDownloader final : public AbstractHandler<std::shared_ptr<UpdaterContext>>
{
private:
    nlohmann::json m_config;

    /**
     * @brief Persists the cursor to RocksDB after each page so that a restart can resume
     *        from the last successfully processed page instead of from the beginning.
     *
     * Uses the same key/column scheme as UpdateIndexerCursor so that getStoredCursor
     * picks it up correctly on the next run via getLastKeyValue(CURRENT_OFFSET).
     */
    void persistCursor(const UpdaterContext& context, const std::string& cursor) const
    {
        if (!context.spUpdaterBaseContext->spRocksDB || cursor.empty())
        {
            return;
        }
        context.spUpdaterBaseContext->spRocksDB->put(
            Utils::getCompactTimestamp(std::time(nullptr)),
            cursor,
            Components::Columns::CURRENT_OFFSET);
    }

    /**
     * @brief Returns the last cursor persisted in RocksDB, or empty string on first run.
     */
    std::string getStoredCursor(const UpdaterContext& context) const
    {
        if (!context.spUpdaterBaseContext->spRocksDB)
        {
            return "";
        }
        try
        {
            const auto value =
                context.spUpdaterBaseContext->spRocksDB
                    ->getLastKeyValue(Components::Columns::CURRENT_OFFSET)
                    .second.ToString();
            // ExecutionContext writes "0" on the very first run — treat it as no cursor.
            return (value == "0") ? "" : value;
        }
        catch (const std::runtime_error&)
        {
            return "";
        }
    }

    /**
     * @brief Sends one page of Indexer hits to the fileProcessingCallback.
     *
     * Each hit is mapped to the format expected by EventDecoder:
     *  - resource key = hit _id for all types (e.g. "CVE-2026-23713", "FEED-GLOBAL", "TID-xxx").
     *  - CVE:          type = create|delete derived from _source.document.cveMetadata.state.
     *  - All others:   type = create (TID-*, FEED-GLOBAL, OSCPE-GLOBAL, CNA-MAPPING-GLOBAL).
     *  - TCPE/TVENDORS: skipped — not consumed by the VD scan.
     *
     * @param context  Updater context (contains the callback).
     * @param hits     Array of Indexer hit objects from a search response.
     * @param cursor   String representation of the highest offset seen in this page.
     */
    void processPage(UpdaterContext& context,
                     const nlohmann::json& hits,
                     const std::string& cursor) const
    {
        nlohmann::json message;
        message["type"]   = "indexer";
        message["cursor"] = cursor;
        message["data"]   = nlohmann::json::array();

        for (const auto& hit : hits)
        {
            const auto& source  = hit.value("_source", hit);
            const auto  docType = source.value("type", std::string {});

            // TCPE and TVENDORS are Indexer-only types not consumed by VD scan — skip silently.
            if (docType == "TCPE" || docType == "TVENDORS")
            {
                continue;
            }

            nlohmann::json resource;
            resource["offset"] = source.value("offset", 0);

            // The document _id is always the resource key (e.g. "CVE-2026-23713",
            // "FEED-GLOBAL", "TID-xxx"). EventDecoder identifies the resource type
            // by key prefix (startsWith "CVE-", "TID-", "FEED-GLOBAL", etc.).
            resource["resource"] = hit.value("_id", std::string {});
            resource["payload"]  = source.value("document", nlohmann::json::object());

            if (docType == "CVE")
            {
                // CVE state is stored inside the CVE5 payload under cveMetadata.state.
                const auto state = source.value("/document/cveMetadata/state"_json_pointer, std::string {});
                resource["type"] = (state == "REJECTED") ? "delete" : "create";
            }
            else
            {
                // TID-*, FEED-GLOBAL, OSCPE-GLOBAL, CNA-MAPPING-GLOBAL: always create.
                resource["type"] = "create";
            }

            message["data"].push_back(std::move(resource));
        }

        const auto result = context.spUpdaterBaseContext->fileProcessingCallback(message.dump());
        if (!std::get<2>(result))
        {
            throw std::runtime_error("IndexerDownloader: fileProcessingCallback returned failure");
        }
    }

    /**
     * @brief Full initial load using executeSearchQueryWithPagination with match_all
     *        sorted by offset (IndexerConnectorSync).
     *
     * Retries every INITIAL_LOAD_RETRY_INTERVAL seconds if the Indexer returns 0 documents
     * or is temporarily unavailable.  The sleep is interruptible: the retry loop exits
     * immediately when spStopCondition fires (agent shutdown).
     *
     * NOTE: PIT (IndexerConnectorAsync) cannot be used here due to an exclusive RocksDB
     * lock conflict on queue/indexer/ with the IndexerConnectorSync instance held by the
     * facade. search_after pagination with a stable sort (offset, _id) is equivalent for
     * this feed because the index is only updated in scheduled batches, not continuously.
     * Resolving this to use PIT would require the connector layer to support shared access
     * or separate RocksDB paths for sync and async connectors.
     */
    void initialLoad(UpdaterContext& context) const
    {
        static constexpr std::chrono::seconds INITIAL_LOAD_RETRY_INTERVAL {30};

        size_t attempt = 0;

        while (true)
        {
            if (attempt == 0)
            {
                logInfo(WM_CONTENTUPDATER, "IndexerDownloader: Starting initial full load");
            }
            else
            {
                logInfo(WM_CONTENTUPDATER,
                        "IndexerDownloader: Retrying initial full load (attempt %zu) ...",
                        attempt + 1);
            }

            const auto& indexName = m_config.at("indexer").at("index").get_ref<const std::string&>();
            const size_t pageSize = m_config.at("indexer").value("pageSize", 1000u);

            IndexerConnectorSync syncConnector(m_config.at("indexer"));

            nlohmann::json query;
            query["query"]["match_all"] = nlohmann::json::object();
            query["sort"]               = nlohmann::json::array({nlohmann::json {{"offset", "asc"}}, nlohmann::json {{"_id", "asc"}}});
            query["size"]               = pageSize;

            std::string lastCursor;
            size_t totalProcessed = 0;
            bool exceptionOccurred = false;

            try
            {
                syncConnector.executeSearchQueryWithPagination(
                    indexName,
                    query,
                    [&](const nlohmann::json& response)
                    {
                        if (!response.contains("hits") || !response.at("hits").contains("hits"))
                        {
                            return;
                        }
                        const auto& hits = response.at("hits").at("hits");
                        if (hits.empty())
                        {
                            return;
                        }

                        const auto& lastHit = hits.back();
                        if (lastHit.contains("_source") && lastHit.at("_source").contains("offset"))
                        {
                            lastCursor = std::to_string(lastHit.at("_source").at("offset").get<uint64_t>());
                        }

                        processPage(context, hits, lastCursor);
                        totalProcessed += hits.size();
                        persistCursor(context, lastCursor);

                        logDebug2(WM_CONTENTUPDATER,
                                  "IndexerDownloader: Initial load — %zu documents processed so far",
                                  totalProcessed);
                    });
            }
            catch (const std::exception& e)
            {
                exceptionOccurred = true;
                logWarn(WM_CONTENTUPDATER,
                        "IndexerDownloader: Initial load failed (%s) — retrying in %zu s.",
                        e.what(),
                        static_cast<size_t>(INITIAL_LOAD_RETRY_INTERVAL.count()));
            }

            if (totalProcessed > 0)
            {
                context.data["cursor"] = lastCursor;
                logInfo(WM_CONTENTUPDATER,
                        "IndexerDownloader: Initial load complete — %zu documents, cursor: '%s'",
                        totalProcessed,
                        lastCursor.c_str());
                return;
            }

            if (!exceptionOccurred)
            {
                logWarn(WM_CONTENTUPDATER,
                        "IndexerDownloader: Indexer index not ready (0 documents) — retrying in %zu s.",
                        static_cast<size_t>(INITIAL_LOAD_RETRY_INTERVAL.count()));
            }

            ++attempt;

            // waitFor returns true when spStopCondition is set (agent shutdown).
            if (context.spUpdaterBaseContext->spStopCondition->waitFor(
                    std::chrono::duration_cast<std::chrono::milliseconds>(INITIAL_LOAD_RETRY_INTERVAL)))
            {
                logInfo(WM_CONTENTUPDATER,
                        "IndexerDownloader: Stop requested during initial load retry — aborting.");
                return;
            }
        }
    }

    /**
     * @brief Incremental update using offset range query (IndexerConnectorSync).
     *
     * @param lastCursor String representation of the last persisted integer offset.
     */
    void incrementalUpdate(UpdaterContext& context, const std::string& lastCursor) const
    {
        logInfo(WM_CONTENTUPDATER,
                "IndexerDownloader: Starting incremental update from offset %s",
                lastCursor.c_str());

        const auto& indexName = m_config.at("indexer").at("index").get_ref<const std::string&>();
        const size_t pageSize = m_config.at("indexer").value("pageSize", 1000u);

        IndexerConnectorSync syncConnector(m_config.at("indexer"));

        nlohmann::json query;
        query["query"]["range"]["offset"]["gt"] = std::stoull(lastCursor);
        query["sort"]                           = nlohmann::json::array({nlohmann::json {{"offset", "asc"}}, nlohmann::json {{"_id", "asc"}}});
        query["size"]                           = pageSize;

        std::string newCursor  = lastCursor;
        size_t totalProcessed  = 0;

        syncConnector.executeSearchQueryWithPagination(
            indexName,
            query,
            [&](const nlohmann::json& response)
            {
                if (!response.contains("hits") || !response.at("hits").contains("hits"))
                {
                    return;
                }
                const auto& hits = response.at("hits").at("hits");
                if (hits.empty())
                {
                    return;
                }

                const auto& lastHit = hits.back();
                if (lastHit.contains("_source") && lastHit.at("_source").contains("offset"))
                {
                    newCursor = std::to_string(lastHit.at("_source").at("offset").get<uint64_t>());
                }

                processPage(context, hits, newCursor);
                totalProcessed += hits.size();
                persistCursor(context, newCursor);
            });

        context.data["cursor"] = newCursor;
        logInfo(WM_CONTENTUPDATER,
                "IndexerDownloader: Incremental update complete — %zu documents, new cursor: '%s'",
                totalProcessed,
                newCursor.c_str());
    }

public:
    /**
     * @brief Construct a new IndexerDownloader.
     *
     * @param config Full updater config JSON (must contain an "indexer" sub-object).
     */
    explicit IndexerDownloader(const nlohmann::json& config)
        : m_config(config)
    {
    }

    /**
     * @brief Execute the download step.
     *
     * Reads the stored cursor to decide between initial load and incremental update,
     * then delegates to the appropriate fetch strategy.
     */
    std::shared_ptr<UpdaterContext> handleRequest(std::shared_ptr<UpdaterContext> context) override
    {
        logDebug1(WM_CONTENTUPDATER, "IndexerDownloader - Starting process");

        auto lastCursor = getStoredCursor(*context);

        // Validate that the stored cursor is a valid integer before using it for an
        // incremental range query. A corrupt RocksDB entry could cause std::stoull to
        // throw std::invalid_argument, which would loop on every scheduler cycle.
        // In that case, discard the cursor and fall back to a full initial load.
        if (!lastCursor.empty())
        {
            try
            {
                std::stoull(lastCursor);
            }
            catch (const std::exception&)
            {
                logWarn(WM_CONTENTUPDATER,
                        "IndexerDownloader: stored cursor '%s' is not a valid integer — falling back to initial load.",
                        lastCursor.c_str());
                lastCursor.clear();
            }
        }

        if (lastCursor.empty())
        {
            initialLoad(*context);
        }
        else
        {
            incrementalUpdate(*context, lastCursor);
        }

        // If a shutdown was requested, skip the completion signal — no point reloading
        // maps or triggering a rescan if the agent is going down.
        if (context->spUpdaterBaseContext->spStopCondition->check())
        {
            return AbstractHandler<std::shared_ptr<UpdaterContext>>::handleRequest(std::move(context));
        }

        // Signal completion to DatabaseFeedManager so it can reload global maps and trigger
        // a full agent rescan exactly once — after all pages have been processed.
        // The "indexer_complete" type is handled by processMessage as a no-op (no documents
        // to store), but the fileProcessingCallback will call reloadGlobalMaps() +
        // postUpdateCallback() for this non-"indexer" message type.
        const auto cursor = context->data.value("cursor", std::string {});
        nlohmann::json finalMsg;
        finalMsg["type"]   = "indexer_complete";
        finalMsg["cursor"] = cursor;
        finalMsg["data"]   = nlohmann::json::array();
        const auto result = context->spUpdaterBaseContext->fileProcessingCallback(finalMsg.dump());
        if (!std::get<2>(result))
        {
            logWarn(WM_CONTENTUPDATER,
                    "IndexerDownloader: post-download reload/rescan signal returned failure (non-fatal).");
        }

        return AbstractHandler<std::shared_ptr<UpdaterContext>>::handleRequest(std::move(context));
    }
};

#endif // _INDEXER_DOWNLOADER_HPP
