/*
 * Wazuh - Indexer connector.
 * Copyright (C) 2015, Wazuh Inc.
 * June 2, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INDEXER_CONNECTOR_HPP
#define _INDEXER_CONNECTOR_HPP

#include <functional>
#include <json.hpp>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#if __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

/**
 * @brief Logging context: pairs the caller module name with the log callback.
 *
 * The caller name is used to build the log tag as "<callerName>(indexer-connector)".
 */
using LoggingContext =
    std::pair<std::string,
              std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>>;

/**
 * @brief PointInTime class - Holds wazuh-indexer Point In Time data.
 *
 */
class EXPORTED PointInTime final
{
private:
    std::string m_pitId;
    uint64_t m_creationTime;
    std::string m_keepAlive;

public:
    /**
     * @brief Constructor for PointInTime.
     *
     * @param pitId The PIT identifier returned by the indexer.
     * @param creationTime The creation time of the PIT.
     * @param keepAlive The keep alive duration (e.g., "5m", "1h").
     */
    PointInTime(std::string pitId, uint64_t creationTime, std::string_view keepAlive)
        : m_pitId(std::move(pitId))
        , m_creationTime(creationTime)
        , m_keepAlive(keepAlive)
    {
    }

    /**
     * @brief Get the PIT identifier.
     *
     * @return The PIT identifier string.
     */
    const std::string& getPitId() const
    {
        return m_pitId;
    }

    /**
     * @brief Get the creation time.
     *
     * @return The creation time as a uint64_t timestamp.
     */
    uint64_t getCreationTime() const
    {
        return m_creationTime;
    }

    /**
     * @brief Get the keep alive duration.
     *
     * @return The keep alive string (e.g., "5m", "1h").
     */
    const std::string& getKeepAlive() const
    {
        return m_keepAlive;
    }
};

/// Implementation detail, defined only in src/. Declared here for IndexerSession's friend below.
struct IndexerSessionData;

/**
 * @brief Shareable indexer session: host health monitoring plus authenticated transport settings.
 *
 * Build ONE and hand it to several connectors in the same process so they share a single health
 * check thread, a single keystore read and a single CA merge, instead of one each. Without it, every
 * connector runs its own synchronous round of `GET /_cat/health` (5 s timeout per host) inside its
 * constructor, so a process holding both a sync and an async connector pays that cost twice.
 *
 * The constructor performs the SAME synchronous validation a connector's own constructor does --
 * `hosts` present, referenced CA files exist on disk, keystore credentials readable -- and throws
 * IndexerConnectorException the same way. A host that is merely UNREACHABLE does NOT throw: it just
 * stays unavailable until the monitor sees it come up. So a session constructs successfully against
 * an indexer that is still starting.
 *
 * LIFETIME: nothing retains the session. A connector copies the transport settings and takes a
 * counted reference to the monitor, so the session may be destroyed as soon as the connectors are
 * built; the monitoring thread lives until the last connector using it is gone.
 *
 * @note Every connector built from a session MUST be configured with the same `hosts` list -- see
 *       the session-taking constructors below.
 */
class EXPORTED IndexerSession final
{
private:
    class Impl;
    std::unique_ptr<Impl> m_impl;

    friend const IndexerSessionData& sessionData(const IndexerSession& session);

public:
    /**
     * @brief Builds the session: validates the configuration, resolves the credentials and starts
     *        one health monitor for the configured hosts.
     *
     * @param config Indexer configuration. `hosts` is required; `ssl.certificate_authorities`,
     *               `ssl.certificate` and `ssl.key` are optional.
     * @param logging Logging context pairing the caller module name and the log callback.
     *
     * @throws IndexerConnectorException if `hosts` is missing or empty, or if a configured CA root
     *         certificate file does not exist.
     */
    explicit IndexerSession(const nlohmann::json& config, LoggingContext logging = {});

    ~IndexerSession();

    IndexerSession(const IndexerSession&) = delete;
    IndexerSession& operator=(const IndexerSession&) = delete;
    IndexerSession(IndexerSession&&) = delete;
    IndexerSession& operator=(IndexerSession&&) = delete;
};

/**
 * @brief IndexerConnectorSync class - Facade for IndexerConnectorSyncImpl.
 *
 */

class EXPORTED IndexerConnectorSync final
{
private:
    class Impl;
    std::unique_ptr<Impl> m_impl;

public:
    /**
     * @brief Class constructor that initializes the publisher.
     *
     * @param config Indexer configuration, including database_path and servers.
     * @param logging Logging context pairing the caller module name and the log callback.
     *                The caller name is used to build the log tag as
     *                "<callerName>(indexer-connector)" (e.g. "vulnerability-scanner(indexer-connector)").
     *                If the caller name is empty, the tag falls back to "indexer-connector".
     */
    explicit IndexerConnectorSync(const nlohmann::json& config, LoggingContext logging = {});

    /**
     * @brief Class constructor that builds on a SHARED session instead of creating its own health
     *        monitor and resolving its own credentials.
     *
     * Use this when the process holds more than one connector: the session's single monitoring thread
     * and single startup health-check round are reused, so the second connector costs no extra
     * network I/O at construction.
     *
     * @param config Indexer configuration. Still supplies this connector's own tunables
     *               (`max_bulk_size`, `flush_interval_seconds`, `max_retry_delay_seconds`). Its
     *               `hosts` list MUST equal the session's: the monitor only knows the hosts it was
     *               built with, so a foreign host would throw std::out_of_range on the first request.
     * @param session Session to share. Not retained -- see IndexerSession's LIFETIME note.
     * @param logging Logging context pairing the caller module name and the log callback.
     *
     * @throws IndexerConnectorException if `hosts` is missing, empty, or does not match the
     *         session's host list, or if `max_retry_delay_seconds` is below the base retry delay.
     */
    IndexerConnectorSync(const nlohmann::json& config, const IndexerSession& session, LoggingContext logging = {});

    ~IndexerConnectorSync();

    /**
     * @brief Stage a delete-by-query for one agent.
     * @param index Target index name.
     * @param agentId wazuh.agent.id filter.
     * @param clusterName Manager-side cluster name; when set, also filters by wazuh.cluster.name.
     */
    void deleteByQuery(const std::string& index, const std::string& agentId, const std::string& clusterName = {});

    /**
     * @brief Execute an update by query operation on OpenSearch/Elasticsearch.
     *
     * This is a generic method that allows callers to execute arbitrary update_by_query
     * operations. The caller is responsible for constructing the appropriate query JSON
     * with the query structure and Painless script.
     *
     * @param indices List of indices to update (will be joined with commas).
     * @param updateQuery JSON object containing the complete update_by_query request body,
     *                    including "query" and "script" sections.
     *
     * Example updateQuery structure:
     * {
     *   "query": { "term": { "wazuh.agent.id": "001" } },
     *   "script": {
     *     "source": "ctx._source.field = params.value",
     *     "lang": "painless",
     *     "params": { "value": "new_value" }
     *   }
     * }
     */
    void executeUpdateByQuery(const std::vector<std::string>& indices, const nlohmann::json& updateQuery);

    /**
     * @brief Execute a search query on OpenSearch/Elasticsearch.
     *
     * This method allows callers to execute search queries with source filtering and sorting.
     *
     * @param index Index name to search.
     * @param searchQuery JSON object containing the search query body.
     * @return JSON response from the indexer containing search results.
     */
    nlohmann::json executeSearchQuery(const std::string& index, const nlohmann::json& searchQuery);

    /**
     * @brief Execute a search query with automatic pagination.
     *
     * This method performs a search query and automatically handles pagination using
     * the 'search_after' mechanism of the indexer. It retrieves all results
     * by making multiple search requests if necessary.
     *
     * @param index Index name to search.
     * @param query JSON object containing the initial search query.
     *              The query MUST include a "sort" field for pagination to work correctly.
     * @param onResponse Callback function executed for each page of results.
     *                   The function receives a JSON object with the response for one page.
     */
    void executeSearchQueryWithPagination(const std::string& index,
                                          const nlohmann::json& query,
                                          std::function<void(const nlohmann::json&)> onResponse);

    /**
     * @brief Create a Point In Time (PIT) for the specified indices.
     *
     * @param indices List of index names to include in the PIT.
     * @param keepAlive Time to keep the PIT alive (e.g., "5m").
     * @param expandWildcards If true, expands wildcard patterns to match indices.
     * @return A PointInTime object containing the PIT ID and creation time.
     * @throws IndexerConnectorException if the PIT creation fails.
     */
    PointInTime createPointInTime(const std::vector<std::string>& indices,
                                  std::string_view keepAlive,
                                  bool expandWildcards = false);

    /**
     * @brief Delete a Point In Time (PIT) on the server.
     *
     * @param pit The PointInTime object to delete.
     * @throws IndexerConnectorException if the PIT deletion fails.
     */
    void deletePointInTime(const PointInTime& pit);

    /**
     * @brief Execute a search query using Point In Time for consistent pagination.
     *
     * @param pit The PointInTime object to use for the search.
     * @param size Maximum number of documents to return per page.
     * @param query The query object.
     * @param sort The sort array.
     * @param searchAfter Optional search_after array for pagination.
     * @param source Optional source filtering configuration.
     * @param slice Optional slice object for parallel PIT consumption (e.g. {"id": 0, "max": 4}).
     * @return The hits object from the search response.
     * @throws IndexerConnectorException if the search fails.
     */
    nlohmann::json search(const PointInTime& pit,
                          std::size_t size,
                          const nlohmann::json& query,
                          const nlohmann::json& sort,
                          const std::optional<nlohmann::json>& searchAfter = std::nullopt,
                          const std::optional<nlohmann::json>& source = std::nullopt,
                          const std::optional<nlohmann::json>& slice = std::nullopt);

    /**
     * @brief Bulk delete.
     *
     * @param id ID.
     * @param index Index name.
     */
    void bulkDelete(std::string_view id, std::string_view index);

    /**
     * @brief Bulk index.
     *
     * @param id ID.
     * @param index Index name.
     * @param data Data.
     */
    void bulkIndex(std::string_view id, std::string_view index, std::string_view data);

    /**
     * @brief Bulk index with version.
     *
     * @param id ID.
     * @param index Index name.
     * @param data Data.
     * @param version Document version for external versioning.
     */
    void bulkIndex(std::string_view id, std::string_view index, std::string_view data, std::string_view version);

    /**
     * @brief Flush the bulk data.
     */
    void flush();

    /**
     * @brief Invoke pending callbacks registered via registerNotify().
     *
     * This method executes all callbacks that were registered and are pending
     * after bulk operations complete. It should be called after releasing any
     * locks acquired via scopeLock() to avoid deadlocks.
     */
    void invokePendingCallbacks();

    /**
     * @brief Acquires and returns a unique lock on the internal mutex.
     *
     * This method encapsulates the synchronization mechanism of the class by
     * returning a `std::unique_lock<std::mutex>` that locks the internal mutex
     * upon creation and automatically releases it when the lock object goes out
     * of scope.
     *
     * Using this method allows callers to perform multiple operations under a
     * single critical section without directly accessing the internal mutex,
     * preserving encapsulation while still enabling safe, multi-operation
     * sequences.
     *
     * @note The returned `std::unique_lock` is movable but not copyable.
     *       Callers should store it in a local variable for the duration of
     *       the operations that require mutual exclusion.
     *
     * @return A `std::unique_lock<std::mutex>` object that owns a lock on the
     *         internal mutex. The lock is released automatically when the
     *         returned object is destroyed.
     *
     */
    [[nodiscard]] std::unique_lock<std::mutex> scopeLock();

    /**
     * @brief Register a callback to be called when the indexer is flushed.
     *
     * @param callback Callback to be called when the indexer is flushed.
     */
    void registerNotify(std::function<void()> callback);

    /**
     * @brief Force a refresh on one or more indices so recently indexed documents
     * become immediately searchable.
     *
     * @param indexPattern Index name or wildcard pattern (e.g.
     *                     "wazuh-states-inventory-packages").
     */
    void refresh(std::string_view indexPattern);

    /**
     * @brief Check have a server available.
     *
     * @return true if have a server available, false otherwise.
     */
    bool isAvailable() const;
};

/**
 * @brief IndexerConnectorAsync class.
 *
 */
class IndexerConnectorAsync final
{
private:
    class Impl;
    std::unique_ptr<Impl> m_impl;

public:
    /**
     * @brief Class constructor that initializes the publisher.
     *
     * @param config Indexer configuration, including servers and SSL settings.
     * @param logging Logging context pairing the caller module name and the log callback.
     *                The caller name is used to build the log tag as
     *                "<callerName>(indexer-connector)" (e.g. "wazuh-manager-analysisd(indexer-connector)").
     *                If the caller name is empty, the tag falls back to "indexer-connector".
     */
    explicit IndexerConnectorAsync(const nlohmann::json& config, LoggingContext logging = {});

    /**
     * @brief Class constructor that builds on a SHARED session instead of creating its own health
     *        monitor and resolving its own credentials.
     *
     * Use this when the process holds more than one connector: the session's single monitoring thread
     * and single startup health-check round are reused, so the second connector costs no extra
     * network I/O at construction.
     *
     * @param config Indexer configuration. Still supplies this connector's own tunables
     *               (`bulk_max_bytes`, `flush_interval_seconds`, `max_retry_delay_seconds`,
     *               `max_queue_bytes`, `logger_queue_size`, `logger_threads`). Its `hosts` list MUST
     *               equal the session's: the monitor only knows the hosts it was built with, so a
     *               foreign host would throw std::out_of_range on the first request.
     * @param session Session to share. Not retained -- see IndexerSession's LIFETIME note.
     * @param logging Logging context pairing the caller module name and the log callback.
     *
     * @throws IndexerConnectorException if `hosts` is missing, empty, or does not match the
     *         session's host list, or if `max_retry_delay_seconds` is below the base retry delay.
     */
    IndexerConnectorAsync(const nlohmann::json& config, const IndexerSession& session, LoggingContext logging = {});

    ~IndexerConnectorAsync();

    /**
     * @brief Index a document.
     *
     * @param id ID of the document.
     * @param index Index name.
     * @param data Data.
     */
    void index(std::string_view id, std::string_view index, std::string_view data);

    /**
     * @brief Index a document with version.
     *
     * @param id ID of the document.
     * @param index Index name.
     * @param data Data.
     * @param version Document version for external versioning.
     */
    void index(std::string_view id, std::string_view index, std::string_view data, std::string_view version);

    /**
     * @brief Index a document.
     *
     * @param index Index name.
     * @param data Data.
     */
    void index(std::string_view index, std::string_view data);

    /**
     * @brief Index a document to a data stream.
     *
     * @param index Data stream name.
     * @param data Data.
     */
    void indexDataStream(std::string_view index, std::string_view data);

    /**
     * @brief Check have a server available.
     *
     * @return true if have a server available, false otherwise.
     */
    bool isAvailable() const;

    /**
     * @brief Get the current size of the indexing queue.
     *
     * @return The number of bytes pending in the queue.
     */
    uint64_t getQueueSize() const;

    /**
     * @brief Get the total number of dropped events.
     *
     * @return The number of events that have been dropped.
     */
    uint64_t getDroppedEvents() const;

    /**
     * @brief Create a Point In Time (PIT) for the specified indices.
     *
     * Creates a PIT context that can be used for consistent pagination across multiple search requests.
     * You must call deletePointInTime() when done to release the PIT on the server.
     *
     * @param indices List of index names or patterns to include in the PIT.
     * @param keepAlive Time to keep the PIT alive (e.g., "5m" for 5 minutes, "1h" for 1 hour).
     * @param expandWildcards If true, expands wildcard patterns to match indices.
     * @return A PointInTime object containing the PIT ID and creation time.
     * @throws IndexerConnectorException if the PIT creation fails.
     *
     * Example:
     * auto pit = connector.createPointInTime({"wazuh-threatintel-kvdbs", "wazuh-threatintel-decoders"}, "5m", true);
     * std::string pitId = pit.getPitId(); // Use for subsequent searches
     * // ... perform searches ...
     * connector.deletePointInTime(pit); // Clean up when done
     */
    PointInTime createPointInTime(const std::vector<std::string>& indices,
                                  std::string_view keepAlive,
                                  bool expandWildcards = false);

    /**
     * @brief Delete a Point In Time (PIT) on the server.
     *
     * @param pit The PointInTime object to delete.
     * @throws IndexerConnectorException if the PIT deletion fails.
     */
    void deletePointInTime(const PointInTime& pit);

    /**
     * @brief Execute a search query using Point In Time.
     *
     * @param pit The PointInTime object to use for the search.
     * @param size Maximum number of documents to return.
     * @param query The query object (must be valid JSON).
     * @param sort The sort array (must be valid JSON array).
     * @param searchAfter Optional search_after array for pagination (must be valid JSON array).
     * @param source Optional source filtering configuration (includes/excludes fields).
     * @return The hits object from the search response.
     * @throws IndexerConnectorException if the search fails.
     *
     * Example:
     * nlohmann::json query = {{"bool", {{"filter", {{{{"term", {{"space.name", "free"}}}}}}}}};
     * nlohmann::json sort = {{{{"_shard_doc", "asc"}}, {{"_id", "asc"}}}};
     * auto hits = connector.search(pit, 10, query, sort);
     * // For pagination:
     * nlohmann::json searchAfter = {2, "c66cd2fc-c612-4192-822d-c4da93f17cec"};
     * auto nextHits = connector.search(pit, 10, query, sort, searchAfter);
     */
    nlohmann::json search(const PointInTime& pit,
                          std::size_t size,
                          const nlohmann::json& query,
                          const nlohmann::json& sort,
                          const std::optional<nlohmann::json>& searchAfter = std::nullopt,
                          const std::optional<nlohmann::json>& source = std::nullopt,
                          const std::optional<nlohmann::json>& slice = std::nullopt);

    /**
     * @brief Execute a search query on an index or alias.
     *
     * Performs a simple search without using Point In Time. Useful for one-off queries
     * where you don't need consistent pagination across multiple requests.
     *
     * @param index Index or alias name to search.
     * @param size Maximum number of documents to return.
     * @param query The query object (must be valid JSON).
     * @param source Optional source filtering configuration (includes/excludes fields).
     * @return The hits object from the search response.
     * @throws IndexerConnectorException if the search fails.
     *
     * Example:
     * nlohmann::json query = {{"bool", {{"filter", {{{{"term", {{"space.name", "free"}}}}}}}}};
     * nlohmann::json source = {{"includes", {"space.hash.sha256"}}, {"excludes", nlohmann::json::array()}};
     * auto hits = connector.search("wazuh-threatintel-policies", 10, query, source);
     */
    nlohmann::json search(std::string_view index,
                          std::size_t size,
                          const nlohmann::json& query,
                          const std::optional<nlohmann::json>& source = std::nullopt);
};

class IndexerConnectorException : public std::exception
{
private:
    std::string m_message;

public:
    explicit IndexerConnectorException(std::string message)
        : m_message(std::move(message))
    {
    }

    const char* what() const noexcept override
    {
        return m_message.c_str();
    }
};

#endif // _INDEXER_CONNECTOR_HPP
