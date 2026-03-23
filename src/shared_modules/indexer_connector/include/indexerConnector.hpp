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
#include <string_view>

#if __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

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

/**
 * @brief IndexerConnectorSync class - Facade for IndexerConnectorSyncImpl.
 *
 */

constexpr auto IC_NAME {"IndexerConnector"};
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
     * @param logFunction Callback function to be called when trying to log a message.
     */
    explicit IndexerConnectorSync(
        const nlohmann::json& config,
        const std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>&
            logFunction = {});

    ~IndexerConnectorSync();

    /**
     * @brief Publish a message into the queue map.
     *
     * @param message Message to be published.
     * @param index Index name.
     */
    void deleteByQuery(const std::string& index, const std::string& agentId);

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
     * @param config Indexer configuration, including database_path and servers.
     * @param logFunction Callback function to be called when trying to log a message.
     * @param timeout Server selector time interval.
     */
    explicit IndexerConnectorAsync(
        const nlohmann::json& config,
        const std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>&
            logFunction = {});

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
     * @return The number of pending indexing operations in the queue.
     */
    uint64_t getQueueSize() const;

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
     * auto pit = connector.createPointInTime({".cti-kvdbs", ".cti-decoders"}, "5m", true);
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
                          const std::optional<nlohmann::json>& source = std::nullopt);

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
     * auto hits = connector.search(".cti-policies", 10, query, source);
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
