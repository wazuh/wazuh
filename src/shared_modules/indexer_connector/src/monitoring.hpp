/*
 * Wazuh content manager
 * Copyright (C) 2015, Wazuh Inc.
 * June 21, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _MONITORING_HPP
#define _MONITORING_HPP

#include "HTTPRequest.hpp"
#include "secureCommunication.hpp"
#include "shared_modules/content_manager/src/dataDecoder.hpp"
#include "stringHelper.h"
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

constexpr auto INTERVAL = 60u;

namespace HealthCheckRows
{
    enum Type : std::size_t
    {
        HEADER = 0,
        DATA,
        SIZE
    };
};

namespace HealthCheckColumns
{
    enum Type : std::size_t
    {
        EPOCH = 0,
        TIMESTAMP,
        CLUSTER,
        STATUS,
        NODE_TOTAL,
        NODE_DATA,
        DISCOVERED_CLUSTER_MANAGER,
        SHARDS,
        PRI,
        RELO,
        INIT,
        UNASSIGN,
        PENDING_TASKS,
        MAX_TASK_WAIT_TIME,
        ACTIVE_SHARDS_PERCENT,
        SIZE
    };
};

/**
 * @brief Monitoring class.
 *
 */
class Monitoring final
{
    std::map<std::string, bool> m_servers;
    std::thread m_thread;
    std::mutex m_mutex;
    std::condition_variable m_condition;
    std::atomic<bool> m_stop {false};
    uint32_t m_interval {INTERVAL};

    /**
     * @brief Checks the health of a server.
     *
     * @note It sends a request to the \p serverAddress and update the serverStatus (true if the server is
     * available, false otherwise). The \p authentication object is used to provide secure communication.
     *
     * @param serverAddress
     * @param authentication
     */
    void healthCheck(const std::string& serverAddress, const SecureCommunication& authentication)
    {
        auto& serverStatus = m_servers[serverAddress];

        // On success callback
        const auto onSuccess = [&serverStatus](std::string response)
        {
            // Remove the tabs and double spaces.
            Utils::replaceAll(response, "\t", " ");
            response = Utils::trimRepeated(response, ' ');

            // Split the response by rows.
            const auto rows {Utils::split(response, '\n')};

            // Check if the response has the expected number of rows.
            if (HealthCheckRows::SIZE == rows.size())
            {
                // Split the data row by spaces.
                const auto fields {Utils::split(rows.at(HealthCheckRows::DATA), ' ')};

                // Check if the response has the expected number of columns and if the status is green.
                if (fields.size() == HealthCheckColumns::SIZE &&
                    fields.at(HealthCheckColumns::STATUS).compare("green") == 0)
                {
                    serverStatus = true;
                }
                else
                {
                    serverStatus = false;
                }
            }
            else
            {
                serverStatus = false; // LCOV_EXCL_LINE
            }
        };

        // On error callback
        const auto onError = [&serverStatus](const std::string& /*error*/, const long /*statusCode*/)
        {
            serverStatus = false;
        };

        // Get the health of the server.
        HTTPRequest::instance().get(HttpURL(serverAddress + "/_cat/health?v"),
                                    onSuccess,
                                    onError,
                                    "",
                                    {"Accept-Charset: utf-8"},
                                    authentication);
    }

    /**
     * @brief Initializes the status of the servers.
     * 
     * @param serverAddresses Servers to be monitored.
     * @param secureCommunication Object that provides secure communication.
     */
    void initialize(const std::vector<std::string>& serverAddresses, const SecureCommunication& secureCommunication)
    {
        std::scoped_lock lock(m_mutex);

        // Initialize the status of the servers
        for (const auto& serverAddress : serverAddresses)
        {
            healthCheck(serverAddress, secureCommunication);
        }
    }

public:
    ~Monitoring()
    {
        m_stop = true;
        m_condition.notify_one();
        if (m_thread.joinable())
        {
            m_thread.join();
        }
    }

    /**
     * @brief Class constructor. Checks the servers' health.
     *
     * @param serverAddresses Servers to be monitored.
     * @param interval Interval for monitoring.
     * @param authentication Object that provides secure communication.
     */
    explicit Monitoring(const std::vector<std::string>& serverAddresses,
                        const uint32_t interval = INTERVAL,
                        const SecureCommunication& secureCommunication = {})
        : m_interval(interval)
    {
        initialize(serverAddresses, secureCommunication);

        // Start the thread, that will check the health of the servers.
        m_thread = std::thread(
            [this, &secureCommunication]()
            {
                while (!m_stop)
                {
                    // Wait for the interval.
                    std::unique_lock lock(m_mutex);
                    m_condition.wait_for(lock, std::chrono::seconds(m_interval), [this]() { return m_stop.load(); });

                    // If the thread is not stopped, check the health of the servers.
                    if (!m_stop)
                    {
                        // Check the health of the servers.
                        for (const auto& [serverAddress, _] : m_servers)
                        {
                            healthCheck(serverAddress, secureCommunication);
                        }
                    }
                }
            });
    }

    /**
     * @brief Checks whether a server is available or not.
     *
     * @param serverAddress Server's address.
     * @return true if available.
     * @return false if not available.
     */
    bool isAvailable(const std::string& serverAddress)
    {
        std::scoped_lock lock(m_mutex);
        return m_servers.at(serverAddress);
    }
};

#endif // _MONITORING_HPP
