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
#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <vector>

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
 *      Opens a PIT on the index, then paginates with match_all sorted by (offset, _id)
 *      using search_after.  Retries every 30 s while the index returns 0 documents.
 *  - Incremental update (stored cursor is an integer offset):
 *      Opens a PIT and fetches all documents whose offset is greater than the stored
 *      cursor, paginated with the same (offset, _id) sort and search_after.
 *
 * For each page the downloader constructs a message of type "indexer" and invokes
 * fileProcessingCallback synchronously. The highest offset seen is stored in
 * context.data["cursor"] so that UpdateIndexerCursor can persist it to RocksDB.
 *
 * Configuration expected under configData["indexer"]:
 * {
 *   "index":               ".cti-cves",               // Indexer CVE index name
 *   "consumerStatusIndex": ".cti-consumers",          // Consumer status index (optional)
 *   "consumerStatusId":    "vd_1.0.0_vd_4.8.0",       // Consumer status document id (optional)
 *   "pageSize":            250,                       // Documents per page (optional, default 250)
 *   "numSlices":           2,                         // Parallel PIT slices (optional, default 2)
 *   <standard IndexerConnector SSL/auth config>
 * }
 */
class IndexerDownloader final : public AbstractHandler<std::shared_ptr<UpdaterContext>>
{
private:
    enum class ConsumerStatus
    {
        Missing,
        Empty,
        Updating,
        Idle,
        Unknown
    };

    nlohmann::json m_config;
    mutable std::mutex m_callbackMutex; ///< Serializes processPage calls across parallel slices.

    /**
     * @brief Returns the _source.excludes filter for CVE search requests.
     *
     * Excludes CVE5 fields that are stored in the FlatBuffer but never read by the
     * scan pipeline (descriptions, references, credits, etc.).  This cuts ~34% of the
     * JSON transfer per CVE document, reducing network, parsing, and memory costs.
     * Note: an _source.includes approach is ~15% faster per query but breaks non-CVE
     * documents (FEED-GLOBAL, OSCPE-GLOBAL, CNA-MAPPING-GLOBAL, TID-*) whose document
     * structure doesn't match CVE5 paths.  Excludes is safe for all document types
     * because non-CVE docs simply don't have containers.cna/adp fields.
     */
    static const nlohmann::json& getSourceFilter()
    {
        static const nlohmann::json filter = {{"excludes",
                                               nlohmann::json::array({"document.containers.cna.descriptions",
                                                                      "document.containers.cna.references",
                                                                      "document.containers.cna.solutions",
                                                                      "document.containers.cna.rejectedReasons",
                                                                      "document.containers.cna.credits",
                                                                      "document.containers.cna.timeline",
                                                                      "document.containers.cna.impacts",
                                                                      "document.containers.cna.workarounds",
                                                                      "document.containers.cna.exploits",
                                                                      "document.containers.cna.configurations",
                                                                      "document.containers.cna.source",
                                                                      "document.containers.cna.tags",
                                                                      "document.containers.cna.taxonomyMappings",
                                                                      "document.containers.cna.datePublic",
                                                                      "document.containers.cna.title",
                                                                      "document.containers.cna.dateAssigned",
                                                                      "document.containers.cna.replacedBy",
                                                                      "document.containers.adp.descriptions",
                                                                      "document.containers.adp.references",
                                                                      "document.containers.adp.solutions",
                                                                      "document.containers.adp.rejectedReasons",
                                                                      "document.containers.adp.credits",
                                                                      "document.containers.adp.timeline",
                                                                      "document.containers.adp.impacts",
                                                                      "document.containers.adp.workarounds",
                                                                      "document.containers.adp.exploits",
                                                                      "document.containers.adp.configurations",
                                                                      "document.containers.adp.source",
                                                                      "document.containers.adp.tags",
                                                                      "document.containers.adp.taxonomyMappings",
                                                                      "document.containers.adp.datePublic",
                                                                      "document.containers.adp.title"})}};
        return filter;
    }

    /**
     * @brief Reads the current consumer status document from `.cti-consumers`.
     *
     * The indexer-side contract guarantees that the document status is:
     *   - empty / missing while the consumer is not ready yet,
     *   - "updating" while the feed is still being indexed,
     *   - "idle" only when the consumer can be queried safely.
     */
    ConsumerStatus readConsumerStatus(IndexerConnectorSync& syncConnector,
                                      std::string_view consumerStatusIndex,
                                      std::string_view consumerStatusId) const
    {
        const auto query =
            nlohmann::json {{"ids", {{"values", nlohmann::json::array({std::string {consumerStatusId}})}}}};
        const auto sourceFilter =
            nlohmann::json {{"includes", nlohmann::json::array({"status"})}, {"excludes", nlohmann::json::array()}};
        const auto searchQuery = nlohmann::json {{"size", 1}, {"query", query}, {"_source", sourceFilter}};

        const auto searchResult = syncConnector.executeSearchQuery(std::string {consumerStatusIndex}, searchQuery);
        if (!searchResult.contains("hits") || !searchResult.at("hits").is_object() ||
            !searchResult.at("hits").contains("hits") || !searchResult.at("hits").at("hits").is_array() ||
            searchResult.at("hits").at("hits").empty())
        {
            return ConsumerStatus::Missing;
        }

        const auto& hit = searchResult.at("hits").at("hits").front();
        if (!hit.contains("_source") || !hit.at("_source").is_object())
        {
            return ConsumerStatus::Empty;
        }

        const auto& source = hit.at("_source");
        if (!source.contains("status") || !source.at("status").is_string())
        {
            return ConsumerStatus::Empty;
        }

        std::string status;
        source.at("status").get_to(status);
        if (status.empty())
        {
            return ConsumerStatus::Empty;
        }
        if (status == "idle")
        {
            return ConsumerStatus::Idle;
        }
        if (status == "updating")
        {
            return ConsumerStatus::Updating;
        }

        return ConsumerStatus::Unknown;
    }

    /**
     * @brief Waits until the consumer status document becomes `idle`.
     *
     * If the consumer status settings are not configured, the wait is skipped so
     * non-VD users of IndexerDownloader keep the previous behaviour.
     */
    bool waitUntilConsumerIdle(UpdaterContext& context) const
    {
        static constexpr auto CONSUMER_STATUS_POLL_INTERVAL {std::chrono::minutes {1}};

        const auto consumerStatusIndex = m_config.at("indexer").value("consumerStatusIndex", std::string {});
        const auto consumerStatusId = m_config.at("indexer").value("consumerStatusId", std::string {});

        if (consumerStatusIndex.empty() || consumerStatusId.empty())
        {
            return true;
        }

        IndexerConnectorSync syncConnector(m_config.at("indexer"));

        while (true)
        {
            try
            {
                switch (readConsumerStatus(syncConnector, consumerStatusIndex, consumerStatusId))
                {
                    case ConsumerStatus::Idle:
                        logInfo(WM_CONTENTUPDATER,
                                "IndexerDownloader: Consumer '%s' in index '%s' is idle. Starting feed download.",
                                consumerStatusId.c_str(),
                                consumerStatusIndex.c_str());
                        return true;

                    case ConsumerStatus::Missing:
                        logInfo(WM_CONTENTUPDATER,
                                "IndexerDownloader: Consumer '%s' not found in '%s'. Waiting %zu s before retrying.",
                                consumerStatusId.c_str(),
                                consumerStatusIndex.c_str(),
                                static_cast<size_t>(
                                    std::chrono::duration_cast<std::chrono::seconds>(CONSUMER_STATUS_POLL_INTERVAL)
                                        .count()));
                        break;

                    case ConsumerStatus::Empty:
                        logInfo(WM_CONTENTUPDATER,
                                "IndexerDownloader: Consumer '%s' has empty status in '%s'. Waiting %zu s before "
                                "retrying.",
                                consumerStatusId.c_str(),
                                consumerStatusIndex.c_str(),
                                static_cast<size_t>(
                                    std::chrono::duration_cast<std::chrono::seconds>(CONSUMER_STATUS_POLL_INTERVAL)
                                        .count()));
                        break;

                    case ConsumerStatus::Updating:
                        logInfo(WM_CONTENTUPDATER,
                                "IndexerDownloader: Consumer '%s' is still updating in '%s'. Waiting %zu s before "
                                "retrying.",
                                consumerStatusId.c_str(),
                                consumerStatusIndex.c_str(),
                                static_cast<size_t>(
                                    std::chrono::duration_cast<std::chrono::seconds>(CONSUMER_STATUS_POLL_INTERVAL)
                                        .count()));
                        break;

                    case ConsumerStatus::Unknown:
                        logWarn(WM_CONTENTUPDATER,
                                "IndexerDownloader: Consumer '%s' in '%s' returned an unknown status. Waiting %zu s "
                                "before retrying.",
                                consumerStatusId.c_str(),
                                consumerStatusIndex.c_str(),
                                static_cast<size_t>(
                                    std::chrono::duration_cast<std::chrono::seconds>(CONSUMER_STATUS_POLL_INTERVAL)
                                        .count()));
                        break;
                }
            }
            catch (const std::exception& e)
            {
                logWarn(WM_CONTENTUPDATER,
                        "IndexerDownloader: Failed to query consumer '%s' in '%s' (%s). Waiting %zu s before "
                        "retrying.",
                        consumerStatusId.c_str(),
                        consumerStatusIndex.c_str(),
                        e.what(),
                        static_cast<size_t>(
                            std::chrono::duration_cast<std::chrono::seconds>(CONSUMER_STATUS_POLL_INTERVAL).count()));
            }

            if (context.spUpdaterBaseContext->spStopCondition->waitFor(
                    std::chrono::duration_cast<std::chrono::milliseconds>(CONSUMER_STATUS_POLL_INTERVAL)))
            {
                logInfo(WM_CONTENTUPDATER,
                        "IndexerDownloader: Stop requested while waiting for consumer '%s' to become idle.",
                        consumerStatusId.c_str());
                return false;
            }
        }
    }

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
            Utils::getCompactTimestamp(std::time(nullptr)), cursor, Components::Columns::CURRENT_OFFSET);
    }

    /**
     * @brief Invalidates the stored cursor so the next cycle is forced to perform a full load.
     */
    void invalidateCursor(UpdaterContext& context) const
    {
        context.data.erase("cursor");

        if (!context.spUpdaterBaseContext->spRocksDB)
        {
            return;
        }

        logWarn(WM_CONTENTUPDATER,
                "IndexerDownloader: invalidating stored cursor and forcing a full reload on the next attempt.");
        context.spUpdaterBaseContext->spRocksDB->put(
            Utils::getCompactTimestamp(std::time(nullptr)), "0", Components::Columns::CURRENT_OFFSET);
    }

    /**
     * @brief Sends the final completion signal so the consumer can validate the downloaded feed.
     *
     * Returns true only when the consumer confirms that the feed is ready to be used.
     */
    bool sendCompletionSignal(UpdaterContext& context, const size_t totalProcessed) const
    {
        const auto cursor = context.data.value("cursor", std::string {});
        nlohmann::json finalMsg;
        finalMsg["type"] = "indexer_complete";
        finalMsg["cursor"] = cursor;
        finalMsg["changed"] = (totalProcessed > 0);
        finalMsg["data"] = nlohmann::json::array();

        const auto result = context.spUpdaterBaseContext->fileProcessingCallback(std::move(finalMsg));
        return std::get<2>(result);
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
                context.spUpdaterBaseContext->spRocksDB->getLastKeyValue(Components::Columns::CURRENT_OFFSET)
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
    void processPage(UpdaterContext& context, const nlohmann::json& hits, const std::string& cursor) const
    {
        nlohmann::json message;
        message["type"] = "indexer";
        message["cursor"] = cursor;
        message["data"] = nlohmann::json::array();

        for (const auto& hit : hits)
        {
            const auto& source = hit.value("_source", hit);
            const auto docType = source.value("type", std::string {});

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
            resource["payload"] = source.value("document", nlohmann::json::object());

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

        FileProcessingResult result;
        {
            std::lock_guard<std::mutex> lock(m_callbackMutex);
            result = context.spUpdaterBaseContext->fileProcessingCallback(std::move(message));
        }
        if (!std::get<2>(result))
        {
            throw std::runtime_error("IndexerDownloader: fileProcessingCallback returned failure");
        }
    }

    /**
     * @brief Paginate through the index using PIT + search_after, calling processPage for
     *        each page and updating the cursor.
     *
     * Shared by initialLoad and incrementalUpdate — the only difference is the query.
     *
     * @param context   Updater context.
     * @param query     Elasticsearch query object (match_all or range).
     * @param startCursor  Starting cursor value (empty for initial load, lastCursor for incremental).
     * @return Number of documents processed.
     */
    size_t fetchWithPit(UpdaterContext& context, const nlohmann::json& query, const std::string& startCursor) const
    {
        static constexpr std::string_view PIT_KEEP_ALIVE {"5m"};

        const auto& indexName = m_config.at("indexer").at("index").get_ref<const std::string&>();
        const size_t pageSize = m_config.at("indexer").value("pageSize", 250u);

        const nlohmann::json sort =
            nlohmann::json::array({nlohmann::json {{"offset", "asc"}}, nlohmann::json {{"_id", "asc"}}});

        const auto& sourceFilter = getSourceFilter();

        IndexerConnectorSync syncConnector(m_config.at("indexer"));

        auto pit = syncConnector.createPointInTime({indexName}, PIT_KEEP_ALIVE);
        auto pitGuard = std::unique_ptr<PointInTime, std::function<void(PointInTime*)>>(
            &pit,
            [&syncConnector](auto* p)
            {
                try
                {
                    syncConnector.deletePointInTime(*p);
                }
                catch (const IndexerConnectorException& e)
                {
                    logWarn(WM_CONTENTUPDATER, "IndexerDownloader: Failed to delete PIT: %s", e.what());
                }
            });

        std::string currentCursor = startCursor;
        std::optional<nlohmann::json> searchAfter = std::nullopt;
        size_t totalProcessed = 0;

        while (true)
        {
            const auto hitsObj = syncConnector.search(pit, pageSize, query, sort, searchAfter, sourceFilter);
            const auto& hitArray = hitsObj.at("hits");

            if (!hitArray.is_array() || hitArray.empty())
            {
                break;
            }

            const auto& lastHit = hitArray.back();
            if (lastHit.contains("_source") && lastHit.at("_source").contains("offset"))
            {
                currentCursor = std::to_string(lastHit.at("_source").at("offset").get<uint64_t>());
            }

            processPage(context, hitArray, currentCursor);
            totalProcessed += hitArray.size();
            persistCursor(context, currentCursor);

            if (hitArray.size() < pageSize)
            {
                break;
            }

            searchAfter = lastHit.at("sort");
        }

        context.data["cursor"] = currentCursor;
        return totalProcessed;
    }

    /**
     * @brief Paginate through the index using a single shared PIT with N parallel slices.
     *
     * Each slice gets a disjoint subset of documents via OpenSearch's slice API
     * (hash-modulo on _id). Each slice paginates independently with search_after.
     * The callback is serialized via m_callbackMutex.
     *
     * Cursor is only persisted after all slices complete (crash = full restart).
     *
     * @param context    Updater context.
     * @param query      Elasticsearch query object.
     * @param startCursor Starting cursor value.
     * @param numSlices  Number of parallel slices.
     * @return Total number of documents processed across all slices.
     */
    size_t fetchWithSlicedPit(UpdaterContext& context,
                              const nlohmann::json& query,
                              const std::string& startCursor,
                              size_t numSlices) const
    {
        static constexpr std::string_view PIT_KEEP_ALIVE {"5m"};

        const auto& indexName = m_config.at("indexer").at("index").get_ref<const std::string&>();
        const size_t pageSize = m_config.at("indexer").value("pageSize", 250u);

        const nlohmann::json sort =
            nlohmann::json::array({nlohmann::json {{"offset", "asc"}}, nlohmann::json {{"_id", "asc"}}});

        const auto& sourceFilter = getSourceFilter();

        IndexerConnectorSync syncConnector(m_config.at("indexer"));

        auto pit = syncConnector.createPointInTime({indexName}, PIT_KEEP_ALIVE);
        auto pitGuard = std::unique_ptr<PointInTime, std::function<void(PointInTime*)>>(
            &pit,
            [&syncConnector](auto* p)
            {
                try
                {
                    syncConnector.deletePointInTime(*p);
                }
                catch (const IndexerConnectorException& e)
                {
                    logWarn(WM_CONTENTUPDATER, "IndexerDownloader: Failed to delete PIT: %s", e.what());
                }
            });

        std::atomic<size_t> totalProcessed {0};
        std::string maxCursor = startCursor;
        std::mutex cursorMutex;
        std::vector<std::thread> threads;
        std::vector<std::string> errors;
        std::mutex errorsMutex;

        logInfo(WM_CONTENTUPDATER,
                "IndexerDownloader: Starting sliced PIT download with %zu slices, pageSize=%zu",
                numSlices,
                pageSize);

        auto sliceWorker = [&](size_t sliceId)
        {
            try
            {
                // Each slice gets its own connector to avoid sharing HTTP state across threads.
                IndexerConnectorSync sliceConnector(m_config.at("indexer"));

                const nlohmann::json sliceParam = {{"id", sliceId}, {"max", numSlices}};
                std::optional<nlohmann::json> searchAfter = std::nullopt;
                size_t sliceProcessed = 0;
                std::string sliceCursor = startCursor;
                auto t0 = std::chrono::steady_clock::now();

                while (true)
                {
                    const auto hitsObj =
                        sliceConnector.search(pit, pageSize, query, sort, searchAfter, sourceFilter, sliceParam);
                    const auto& hitArray = hitsObj.at("hits");

                    if (!hitArray.is_array() || hitArray.empty())
                    {
                        break;
                    }

                    const auto& lastHit = hitArray.back();
                    if (lastHit.contains("_source") && lastHit.at("_source").contains("offset"))
                    {
                        sliceCursor = std::to_string(lastHit.at("_source").at("offset").get<uint64_t>());
                    }

                    processPage(context, hitArray, sliceCursor);
                    sliceProcessed += hitArray.size();

                    if (hitArray.size() < pageSize)
                    {
                        break;
                    }

                    searchAfter = lastHit.at("sort");
                }

                totalProcessed += sliceProcessed;

                // Update global max cursor
                {
                    std::lock_guard<std::mutex> lock(cursorMutex);
                    if (!sliceCursor.empty())
                    {
                        try
                        {
                            auto sliceVal = std::stoull(sliceCursor);
                            auto currentMax = maxCursor.empty() ? 0ULL : std::stoull(maxCursor);
                            if (sliceVal > currentMax)
                            {
                                maxCursor = sliceCursor;
                            }
                        }
                        catch (const std::exception& e)
                        {
                            logWarn(WM_CONTENTUPDATER,
                                    "IndexerDownloader: Slice %zu failed to parse cursor '%s': %s",
                                    sliceId,
                                    sliceCursor.c_str(),
                                    e.what());
                        }
                    }
                }

                auto elapsed =
                    std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0)
                        .count();
                logInfo(WM_CONTENTUPDATER,
                        "IndexerDownloader: Slice %zu/%zu complete — %zu docs in %ldms",
                        sliceId,
                        numSlices,
                        sliceProcessed,
                        elapsed);
            }
            catch (const std::exception& e)
            {
                std::lock_guard<std::mutex> lock(errorsMutex);
                errors.push_back("Slice " + std::to_string(sliceId) + ": " + e.what());
                logError(WM_CONTENTUPDATER, "IndexerDownloader: Slice %zu failed: %s", sliceId, e.what());
            }
        };

        for (size_t i = 0; i < numSlices; ++i)
        {
            threads.emplace_back(sliceWorker, i);
        }

        for (auto& t : threads)
        {
            t.join();
        }

        if (!errors.empty())
        {
            throw std::runtime_error("IndexerDownloader: " + std::to_string(errors.size()) +
                                     " slice(s) failed: " + errors.front());
        }

        // Persist cursor only after all slices complete
        context.data["cursor"] = maxCursor;
        persistCursor(context, maxCursor);

        return totalProcessed.load();
    }

    /**
     * @brief Full initial load using PIT + search_after (match_all, sorted by offset).
     *
     * Retries every INITIAL_LOAD_RETRY_INTERVAL seconds if the Indexer returns 0 documents
     * or is temporarily unavailable. The sleep is interruptible: exits immediately when
     * spStopCondition fires (agent shutdown).
     *
     * @return Number of documents processed.
     */
    size_t initialLoad(UpdaterContext& context) const
    {
        static constexpr std::chrono::seconds INITIAL_LOAD_RETRY_INTERVAL {30};

        const nlohmann::json query = {{"match_all", nlohmann::json::object()}};
        const size_t numSlices = m_config.at("indexer").value("numSlices", 2u);
        size_t attempt = 0;

        while (true)
        {
            if (attempt == 0)
            {
                logInfo(WM_CONTENTUPDATER, "IndexerDownloader: Starting initial full load (slices=%zu)", numSlices);
            }
            else
            {
                logInfo(
                    WM_CONTENTUPDATER, "IndexerDownloader: Retrying initial full load (attempt %zu) ...", attempt + 1);
            }

            size_t totalProcessed = 0;
            bool exceptionOccurred = false;

            try
            {
                if (numSlices > 1)
                {
                    totalProcessed = fetchWithSlicedPit(context, query, "", numSlices);
                }
                else
                {
                    totalProcessed = fetchWithPit(context, query, "");
                }
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
                logInfo(WM_CONTENTUPDATER,
                        "IndexerDownloader: Initial load download phase complete — %zu documents, cursor: '%s'",
                        totalProcessed,
                        context.data.value("cursor", std::string {}).c_str());
                return totalProcessed;
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
                logInfo(WM_CONTENTUPDATER, "IndexerDownloader: Stop requested during initial load retry — aborting.");
                return 0;
            }
        }
    }

    /**
     * @brief Incremental update using PIT + search_after (offset range query).
     *
     * @param lastCursor String representation of the last persisted integer offset.
     * @return Number of documents processed.
     */
    size_t incrementalUpdate(UpdaterContext& context, const std::string& lastCursor) const
    {
        logInfo(WM_CONTENTUPDATER, "IndexerDownloader: Starting incremental update from offset %s", lastCursor.c_str());

        const nlohmann::json query = {{"range", {{"offset", {{"gt", std::stoull(lastCursor)}}}}}};

        const size_t totalProcessed = fetchWithPit(context, query, lastCursor);

        logInfo(WM_CONTENTUPDATER,
                "IndexerDownloader: Incremental update download phase complete — %zu documents, new cursor: '%s'",
                totalProcessed,
                context.data.value("cursor", std::string {}).c_str());
        return totalProcessed;
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

        const bool forceInitialLoad = lastCursor.empty();
        if (!waitUntilConsumerIdle(*context))
        {
            return AbstractHandler<std::shared_ptr<UpdaterContext>>::handleRequest(std::move(context));
        }

        size_t totalProcessed = 0;
        if (forceInitialLoad)
        {
            totalProcessed = initialLoad(*context);
        }
        else
        {
            totalProcessed = incrementalUpdate(*context, lastCursor);
        }

        // If a shutdown was requested, skip the completion signal — no point reloading
        // maps or triggering a rescan if the agent is going down.
        if (context->spUpdaterBaseContext->spStopCondition->check())
        {
            return AbstractHandler<std::shared_ptr<UpdaterContext>>::handleRequest(std::move(context));
        }

        if (!sendCompletionSignal(*context, totalProcessed))
        {
            invalidateCursor(*context);
            logWarn(WM_CONTENTUPDATER,
                    "IndexerDownloader: downloaded feed is not ready after completion validation. "
                    "The stored cursor was invalidated and the next scheduler cycle will perform a full reload.");
        }

        return AbstractHandler<std::shared_ptr<UpdaterContext>>::handleRequest(std::move(context));
    }
};

#endif // _INDEXER_DOWNLOADER_HPP
