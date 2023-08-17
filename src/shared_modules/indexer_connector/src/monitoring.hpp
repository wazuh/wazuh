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
#include "shared_modules/content_manager/src/dataDecoder.hpp"
#include "stringHelper.h"
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

constexpr auto INTERVAL = 60;

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
 * @brief Monitoring
 *
 */
class Monitoring final
{
    std::map<std::string, bool> m_values;
    std::thread m_thread;
    std::mutex m_mutex;
    std::condition_variable m_condition;
    std::atomic<bool> m_stop {false};

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
     * @brief Construct a new Monitoring object
     *
     * @param values
     */
    explicit Monitoring(const std::vector<std::string>& values)
    {
        // Initialize the map with the values, all servers are available.
        for (auto& value : values)
        {
            m_values[value] = true;
        }

        // Start the thread, that will check the health of the servers.
        m_thread = std::thread(
            [this]()
            {
                while (!m_stop)
                {
                    std::unique_lock<std::mutex> lock(m_mutex);
                    // Wait for the interval.
                    m_condition.wait_for(lock, std::chrono::seconds(INTERVAL), [this]() { return m_stop.load(); });

                    // If the thread is not stopped, check the health of the servers.
                    if (!m_stop)
                    {
                        // Check the health of the servers.
                        for (auto& value : m_values)
                        {
                            // Get the health of the server.
                            HTTPRequest::instance().get(
                                HttpURL(value.first + "/_cat/health"),
                                [&](std::string response)
                                {
                                    // Remove the tabs and double spaces.
                                    Utils::replaceAll(response, "\t", " ");
                                    Utils::replaceAll(response, "  ", " ");
                                    // Split the response by rows.
                                    const auto rows {Utils::split(response, '\n')};

                                    // Check if the response has the expected number of rows.
                                    if (HealthCheckRows::SIZE == rows.size())
                                    {
                                        // Split the data row by spaces.
                                        const auto fields {Utils::split(rows.at(HealthCheckRows::DATA), ' ')};

                                        // Check if the response has the expected number of columns and if the status is
                                        // green.
                                        if (fields.size() == HealthCheckColumns::SIZE &&
                                            fields.at(HealthCheckColumns::STATUS).compare("green") == 0)
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
                                        value.second = false;
                                    }
                                },
                                [&](const std::string& error, const long /*statusCode*/) { value.second = false; });
                        }
                    }
                }
            });
    }

    /**
     * @brief
     *
     * @param value
     * @return true
     * @return false
     */
    bool isAvailable(const std::string& value)
    {
        // Check if the server is available.
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_values.at(value);
    }
};

#endif // _MONITORING_HPP
