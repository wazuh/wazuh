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

#include "IURLRequest.hpp"
#include "secureCommunication.hpp"
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <json.hpp>
#include <loggerHelper.h>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

// 60 seconds interval for monitoring
constexpr auto INTERVAL = 60u;

// 5 seconds timeout for health check requests
constexpr auto HEALTH_CHECK_TIMEOUT_MS = 5000u;

// Name of the field that contains the server status
constexpr auto SERVER_HEALTH_FIELD_NAME {"status"};

auto constexpr MONITOR_NAME {"monitoring"};

/**
 * @brief Monitoring class.
 *
 * ## Why the availability bits are atomics and nothing is locked across a health check
 *
 * A round of health checks costs up to HEALTH_CHECK_TIMEOUT_MS **per host**, sequentially, and hosts
 * that accept a TCP connection and then never answer burn the whole timeout each. This class used to
 * hold one mutex for the entire round, and `isAvailable()` took that same mutex -- so every reader
 * queued behind the round.
 *
 * That mattered far beyond a slow status query, because `isAvailable()` sits in `TServerSelector`,
 * which every `getNext()` calls: it was on the path of every bulk, search and PIT of every consumer
 * (the engine, vulnerability_scanner, inventory_sync and inventory_sync_server). In
 * inventory_sync_server, whose `/stats` and `/config` handlers call it from an asio I/O thread, a
 * measured 3 unreachable hosts froze the entire HTTP transport for ~15 s out of every ~25 s.
 *
 * So: readers are wait-free, and no lock is ever held across an HTTP call.
 *
 * ## The invariant that makes the lock-free reads sound
 *
 * `m_servers`'s **structure is frozen** once the constructor returns: keys are inserted only by
 * `initialize()`, before the monitor thread exists and before this object can be reached by any
 * reader. Only the atomic values change afterwards. Do NOT insert into `m_servers` after
 * construction -- concurrent lookups would then race with a rehash/rebalance.
 */
template<typename THttpRequest>
class TMonitoring final
{
    /// Host -> availability. Structure frozen after construction; values published by the monitor
    /// thread with release and read wait-free with acquire. See the class comment.
    std::map<std::string, std::atomic<bool>, std::less<>> m_servers;
    std::thread m_thread;
    /// Guards ONLY the interval wait of the monitor thread. Deliberately never held across a health
    /// check: that is the whole point of this class's synchronisation. Named for what it protects so
    /// nobody widens it back.
    std::mutex m_sleepMutex;
    std::condition_variable m_condition;
    std::atomic<bool> m_stop {false};
    uint32_t m_interval {INTERVAL};
    THttpRequest* m_httpRequest;
    /// Diagnostic strings for the unavailable hosts, read only by getUnavailableServersDetails() --
    /// the cold "no available server" error path. Guarded by its own mutex, held for a map update or
    /// a read and NEVER across an HTTP call, so it cannot reintroduce the stall.
    std::mutex m_reasonsMutex;
    std::map<std::string, std::string, std::less<>> m_unavailableReasonByServer;
    /// Touched only by the thread running a round (the constructor's, then the monitor's), purely to
    /// make the "no longer available" / "available again" logging edge-triggered. Needs no
    /// synchronisation: no reader ever looks at it.
    std::map<std::string, bool, std::less<>> m_previousServerAvailability;

    /**
     * @brief Checks the health of a server.
     *
     * @note It sends a request to the \p serverAddress and update the serverStatus. The \p authentication object is
     * used to provide secure communication.
     *
     * @note The serverStatus is updated to true if the server is green or yellow, otherwise it is updated to false.
     *
     * @param serverAddress Server's address.
     * @param serverStatus The availability slot to publish into. Passed in rather than looked up so
     *                     this function can never insert into m_servers (see the class comment).
     * @param authentication Object that provides secure communication.
     */
    void healthCheck(const std::string& serverAddress,
                     std::atomic<bool>& serverStatus,
                     const SecureCommunication& authentication)
    {
        const auto previousAvailability = m_previousServerAvailability.find(serverAddress);
        const bool wasAvailable =
            previousAvailability == m_previousServerAvailability.end() || previousAvailability->second;
        std::string unavailableReason;

        /*
         * Computed into a local and published ONCE, at the end.
         *
         * Writing a pessimistic `false` here and the real answer later would make a healthy host read
         * as unavailable for the whole duration of its own check -- up to HEALTH_CHECK_TIMEOUT_MS. The
         * previous implementation did exactly that and got away with it only because it held a lock
         * that no reader could get past; with wait-free readers the transient becomes observable, and
         * it would make getNext() skip a healthy host, or answer 503 with one host configured.
         */
        bool available {false};

        // On success callback
        const auto onSuccess = [&available](std::string response)
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
                available = serverHealth.compare("green") == 0 || serverHealth.compare("yellow") == 0;
            }
        };

        // On error callback
        const auto onError = [&serverAddress, &unavailableReason](
                                 const std::string& error, const long statusCode, const std::string& errorBody)
        {
            // LCOV_EXCL_START
            //  Try to extract error details from JSON
            std::string errorType, errorReason;
            try
            {
                const auto errorJson = nlohmann::json::parse(errorBody);
                if (errorJson.contains("error"))
                {
                    const auto& err = errorJson.at("error");
                    if (err.contains("type"))
                    {
                        errorType = err.at("type").get_ref<const std::string&>();
                    }
                    if (err.contains("reason"))
                    {
                        errorReason = err.at("reason").get_ref<const std::string&>();
                    }
                }
            }
            catch (const nlohmann::json::exception&)
            {
                // Ignore JSON parsing errors
            }

            // Log based on status code
            if (statusCode == 401)
            {
                if (!errorType.empty() && !errorReason.empty())
                {
                    unavailableReason =
                        "Unauthorized (" + errorType + ": " + errorReason + ") - Check indexer credentials";
                }
                else
                {
                    unavailableReason = "Unauthorized - Check indexer credentials";
                }
            }
            else if (statusCode == 403)
            {
                if (!errorType.empty() && !errorReason.empty())
                {
                    unavailableReason = "Forbidden (" + errorType + ": " + errorReason + ") - Check user permissions";
                }
                else
                {
                    unavailableReason = "Forbidden - Check user permissions";
                }
            }
            else if (statusCode >= 500)
            {
                unavailableReason = "Server error (HTTP " + std::to_string(statusCode) + ")";
            }
            else
            {
                unavailableReason = error.empty() ? "status: " + std::to_string(statusCode) : error;
            }

            logDebug2(
                MONITOR_NAME, "Health check failed for '%s' - %s", serverAddress.c_str(), unavailableReason.c_str());
        };
        // LCOV_EXCL_STOP

        // Get the health of the server.
        thread_local std::string url;
        url = serverAddress + "/_cat/health";

        m_httpRequest->get(RequestParameters {.url = HttpURL(url), .secureCommunication = authentication},
                           PostRequestParameters {.onSuccess = onSuccess, .onError = onError},
                           ConfigurationParameters {.timeout = HEALTH_CHECK_TIMEOUT_MS});

        // The single publish. Everything below reads the local, so the log line, the stored reason and
        // the value readers see can never disagree.
        serverStatus.store(available, std::memory_order_release);

        if (!available && unavailableReason.empty())
        {
            unavailableReason = "Cluster reported unhealthy status";
        }

        {
            std::scoped_lock lock(m_reasonsMutex);
            if (!available)
            {
                m_unavailableReasonByServer[serverAddress] = unavailableReason;
            }
            else
            {
                m_unavailableReasonByServer.erase(serverAddress);
            }
        }

        if (wasAvailable && !available)
        {
            logInfo(MONITOR_NAME,
                    "Indexer node '%s' is no longer available. Reason: %s",
                    serverAddress.c_str(),
                    unavailableReason.c_str());
        }
        else if (!wasAvailable && available)
        {
            logInfo(MONITOR_NAME, "Indexer node '%s' is available again.", serverAddress.c_str());
        }

        m_previousServerAvailability[serverAddress] = available;
    }

    /**
     * @brief Initializes the status of the servers and adds them to the monitoring list.
     *
     * @param authentication Object that provides secure communication.
     */
    void initialize(const std::vector<std::string>& serverAddresses, const SecureCommunication& authentication)
    {
        // No lock: this runs from the constructor, so the monitor thread does not exist yet and no
        // reader can hold a reference to this object. It is also the ONLY place that inserts into
        // m_servers, which is what freezes the map's structure for the lock-free reads.
        for (const auto& serverAddress : serverAddresses)
        {
            if (m_stop)
            {
                // If the thread is stopped, break the loop.
                return;
            }
            const auto [entry, _] = m_servers.try_emplace(serverAddress, false);
            healthCheck(entry->first, entry->second, authentication);
        }
    }

public:
    ~TMonitoring()
    {
        // m_stop is atomic, so asking the monitor to stop needs no lock -- and must not take one.
        // Taking m_sleepMutex first used to mean the destructor itself waited out however much of the
        // current round was left (up to 5 s per host) before it could even set the flag, which put
        // that delay straight into modulesd's bounded shutdown budget.
        m_stop.store(true, std::memory_order_release);
        {
            // Empty critical section on purpose: it closes the window where the monitor has evaluated
            // its predicate but not yet slept, which would otherwise swallow the notify below.
            std::scoped_lock lock(m_sleepMutex);
        }
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
     * @param httpRequest Optional HTTP request instance for dependency injection (for testing).
     */
    explicit TMonitoring(const std::vector<std::string>& serverAddresses,
                         const uint32_t interval = INTERVAL,
                         const SecureCommunication& authentication = {},
                         THttpRequest* httpRequest = nullptr)
        : m_interval(interval)
        , m_httpRequest(httpRequest ? httpRequest : &THttpRequest::instance())
    {

        // First, initialize the status of the servers.
        initialize(serverAddresses, authentication);

        // Start the thread, that will check the health of the servers.
        m_thread = std::thread(
            [this, authentication]()
            {
                while (!m_stop)
                {
                    // The lock is scoped to the WAIT only. Holding it across the round below is the
                    // bug this class was rewritten to remove: see the class comment.
                    {
                        std::unique_lock lock(m_sleepMutex);
                        m_condition.wait_for(
                            lock, std::chrono::seconds(m_interval), [this]() { return m_stop.load(); });
                    }

                    // If the thread is not stopped, check the health of the servers.
                    if (!m_stop)
                    {
                        // Check the health of the servers. Iterating by reference to publish into each
                        // host's atomic; the map's structure is fixed, so this never inserts.
                        for (auto& [serverAddress, serverStatus] : m_servers)
                        {
                            healthCheck(serverAddress, serverStatus, authentication);
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
    bool isAvailable(std::string_view serverAddress)
    {
        // Wait-free, and on the hot path: TServerSelector::getNext() calls this for every operation
        // against the indexer. Safe without a lock because the map's structure is frozen after
        // construction and only the atomic value changes (see the class comment).
        auto it = m_servers.find(serverAddress);
        if (it == m_servers.end())
        {
            throw std::out_of_range("Server not found in monitoring");
        }
        return it->second.load(std::memory_order_acquire);
    }

    std::string getUnavailableServersDetails()
    {
        // The reasons lock is taken once, around the map reads only. The availability bits are read
        // from the atomics, so a host that flipped mid-call can pair with a reason from a moment
        // earlier; that is a diagnostic string on an error path, and it is worth far more than
        // blocking this call behind a health-check round to make it perfectly consistent.
        std::string result;
        std::scoped_lock lock(m_reasonsMutex);
        for (const auto& [serverAddress, available] : m_servers)
        {
            if (available.load(std::memory_order_acquire))
            {
                continue;
            }

            const auto unavailableReason = m_unavailableReasonByServer.find(serverAddress);
            if (!result.empty())
            {
                result += "; ";
            }
            result += serverAddress + ": " +
                      (unavailableReason == m_unavailableReasonByServer.end() ? std::string {"unknown"}
                                                                              : unavailableReason->second);
        }

        return result.empty() ? "no error details available" : result;
    }
};

#endif // _MONITORING_HPP
