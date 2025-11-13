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
#include <string_view>

#if __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

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
     *   "query": { "term": { "agent.id": "001" } },
     *   "script": {
     *     "source": "ctx._source.field = params.value",
     *     "lang": "painless",
     *     "params": { "value": "new_value" }
     *   }
     * }
     */
    void executeUpdateByQuery(const std::vector<std::string>& indices, const nlohmann::json& updateQuery);

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
     * @brief Check have a server available.
     *
     * @return true if have a server available, false otherwise.
     */
    bool isAvailable() const;
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
