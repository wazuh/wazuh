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
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <map>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>
#include <thread>
#include <vector>

// 60 seconds interval for monitoring
constexpr auto HEALTH_CHECK_INTERVAL_MS = 60000u;

// 5 seconds timeout for health check requests
constexpr auto HEALTH_CHECK_TIMEOUT_MS = 5000u;

// Name of the field that contains the server status
constexpr auto SERVER_HEALTH_FIELD_NAME {"status"};

/**
 * @brief Monitoring class.
 *
 * @tparam THTTPRequest Type of the HTTP request.
 *
 * @note This class is used to monitor the health of the servers.
 * It checks the health of the servers and updates the status in the values map.
 * The class has a thread that checks the health of the servers at a given interval.
 *
 */
template<typename THTTPRequest = HTTPRequest>
class TMonitoring final
{
    std::map<std::string, bool, std::less<>> m_servers;
    std::thread m_thread;
    std::mutex m_mutex;
    std::mutex m_mutex_wait;
    std::condition_variable m_condition;
    std::atomic<bool> m_stop {false};
    uint32_t m_interval {HEALTH_CHECK_INTERVAL_MS};

    /**
     * @brief Checks the health of a server.
     *
     * @note It sends a request to the \p serverAddress and update the serverStatus. The \p authentication object is
     * used to provide secure communication.
     *
     * @note The serverStatus is updated to true if the server is green or yellow, otherwise it is updated to false.
     *
     * @param serverAddress Server's address.
     * @param authentication Object that provides secure communication.
     */
    void healthCheck(const std::string& serverAddress, const SecureCommunication& authentication)
    {
        auto& serverStatus = m_servers[serverAddress];

        // Set the server status to unavailable by default
        serverStatus = false;

        // On success callback
        const auto onSuccess = [&serverStatus](std::string response)
        {
            // Parse the response without throwing exceptions
            // Response example:
            // [
            //     {
            //         "epoch": "1726271464",
            //         "timestamp": "23:51:04",
            //         "cluster": "wazuh-cluster",
            //         "status": "green",
            //         "node.total": "1",
            //         "node.data": "1",
            //         "discovered_cluster_manager": "true",
            //         "shards": "166",
            //         "pri": "166",
            //         "relo": "0",
            //         "init": "0",
            //         "unassign": "0",
            //         "pending_tasks": "0",
            //         "max_task_wait_time": "-",
            //         "active_shards_percent": "100.0%"
            //     }
            // ]

            const auto data = nlohmann::json::parse(response, nullptr, false).at(0);

            // Check if the server is green or yellow
            if (!data.is_discarded() && data.contains(SERVER_HEALTH_FIELD_NAME))
            {
                const auto& serverHealth = data.at(SERVER_HEALTH_FIELD_NAME).get_ref<const std::string&>();
                serverStatus = serverHealth.compare("green") == 0 || serverHealth.compare("yellow") == 0;
            }
        };

        // On error callback
        const auto onError = [&serverStatus](const std::string& /*error*/, const long /*statusCode*/)
        {
            serverStatus = false;
        };

        // Get the health of the server.
        THTTPRequest::instance().get(
            RequestParameters {.url = HttpURL(serverAddress + "/_cat/health"), .secureCommunication = authentication},
            PostRequestParameters {.onSuccess = onSuccess, .onError = onError},
            ConfigurationParameters {.timeout = HEALTH_CHECK_TIMEOUT_MS});
    }

    /**
     * @brief Initializes the status of the servers and adds them to the monitoring list.
     *
     * @param authentication Object that provides secure communication.
     */
    void initialize(const std::vector<std::string>& serverAddresses, const SecureCommunication& authentication)
    {
        std::scoped_lock lock(m_mutex);

        // Initialize the status of the servers
        for (const auto& serverAddress : serverAddresses)
        {
            if (m_stop)
            {
                // If the thread is stopped, break the loop.
                return;
            }
            healthCheck(serverAddress, authentication);
        }
    }

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
     * @brief Class constructor. Checks the servers' health.
     *
     * @param serverAddresses Servers to be monitored.
     * @param interval Interval for monitoring.
     * @param authentication Object that provides secure communication.
     */
    explicit TMonitoring(const std::vector<std::string>& serverAddresses,
                         const uint32_t interval = HEALTH_CHECK_INTERVAL_MS,
                         const SecureCommunication& authentication = {})
        : m_interval(interval)
    {
        // First, initialize the status of the servers.
        initialize(serverAddresses, authentication);

        // Start the thread, that will check the health of the servers.
        m_thread = std::thread(
            [this, authentication]()
            {
                while (!m_stop)
                {
                    // Wait for the interval.
                    std::unique_lock lock(m_mutex_wait);
                    m_condition.wait_for(
                        lock, std::chrono::milliseconds(m_interval), [this]() { return m_stop.load(); });

                    // If the thread is not stopped, check the health of the servers.
                    if (!m_stop)
                    {
                        // Check the health of the servers.
                        for (const auto& [serverAddress, _] : m_servers)
                        {
                            std::lock_guard lock(m_mutex);
                            healthCheck(serverAddress, authentication);
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
        std::lock_guard lock(m_mutex);
        return m_servers.at(serverAddress);
    }
};

using Monitoring = TMonitoring<>;

#endif // _MONITORING_HPP
