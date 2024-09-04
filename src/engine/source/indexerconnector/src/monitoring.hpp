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
#include "base/utils/stringUtils.hpp"
#include "secureCommunication.hpp"
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
 * @note This class is used to monitor the health of the servers.
 * It checks the health of the servers and updates the status in the values map.
 * The class has a thread that checks the health of the servers at a given interval.
 *
 */

template<typename THTTPRequest = HTTPRequest>
class TMonitoring final
{
    std::map<std::string, bool, std::less<>> m_values;
    std::thread m_thread;
    std::mutex m_mutex;
    std::condition_variable m_condition;
    std::atomic<bool> m_stop {false};
    uint32_t m_interval {INTERVAL};

public:
    ~TMonitoring()
    {
        m_stop = true;
        m_condition.notify_one();
        if (m_thread.joinable())
        {
            m_thread.join();
        }
    }

    /**
     * @brief Class constructor. Initializes values map and check servers' health.
     *
     * @param values Servers to be monitored.
     * @param interval Interval for monitoring.
     * @param secureCommunication Object that provides secure communication.
     */
    explicit TMonitoring(const std::vector<std::string>& values,
                         const uint32_t interval = INTERVAL,
                         const SecureCommunication& secureCommunication = {})
        : m_interval(interval)
    {
        // Initialize the map with the values, all servers are available.
        for (auto& value : values)
        {
            m_values[value] = true;
        }

        // Start the thread, that will check the health of the servers.
        m_thread = std::thread(
            [this, secureCommunication]()
            {
                const std::unordered_set<std::string> headers {"Accept-Charset: utf-8"};
                while (!m_stop)
                {
                    std::unique_lock lock(m_mutex);
                    // Wait for the interval.
                    m_condition.wait_for(
                        lock, std::chrono::milliseconds(m_interval), [this]() { return m_stop.load(); });

                    // If the thread is not stopped, check the health of the servers.
                    if (!m_stop)
                    {
                        // Check the health of the servers.
                        for (auto& value : m_values)
                        {
                            // Get the health of the server.
                            THTTPRequest::instance().get(
                                {HttpURL(value.first + "/_cat/health?v"), {}, secureCommunication, headers},
                                {[&](std::string response)
                                 {
                                     // Remove the tabs and double spaces.
                                     base::utils::string::replaceAll(response, "\t", " ");
                                     base::utils::string::replaceAll(response, "  ", " ");
                                     // Split the response by rows.
                                     const auto rows {base::utils::string::split(response, '\n')};

                                     // Check if the response has the expected number of rows.
                                     if (HealthCheckRows::SIZE == rows.size())
                                     {
                                         // Split the data row by spaces.
                                         const auto fields {
                                             base::utils::string::split(rows.at(HealthCheckRows::DATA), ' ')};

                                         // Check if the response has the expected number of columns and if the status
                                         // is green.
                                         if (fields.size() == HealthCheckColumns::SIZE
                                             && fields.at(HealthCheckColumns::STATUS).compare("green") == 0)
                                         {
                                             value.second = true;
                                         }
                                         else
                                         {
                                             value.second = false;
                                         }
                                     }
                                     else
                                     {
                                         value.second = false; // LCOV_EXCL_LINE
                                     }
                                 },
                                 [&value](const std::string& /*error*/, const long /*statusCode*/)
                                 {
                                     value.second = false;
                                 }});
                        }
                    }
                }
            });
    }

    /**
     * @brief Checks whether a server is available or not.
     *
     * @param value Server's address.
     * @return true if available.
     * @return false if not available.
     */
    bool isAvailable(const std::string& value)
    {
        // Check if the server is available.
        std::scoped_lock lock(m_mutex);
        return m_values.at(value);
    }
};

using Monitoring = TMonitoring<>;

#endif // _MONITORING_HPP
