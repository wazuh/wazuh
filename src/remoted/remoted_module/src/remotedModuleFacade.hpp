/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_MODULE_FACADE_HPP
#define _REMOTED_MODULE_FACADE_HPP

#include "loggerHelper.h"
#include "remoted_module.h"
#include "singleton.hpp"
#include <atomic>
#include <condition_variable>
#include <cstdarg>
#include <functional>
#include <mutex>
#include <thread>

constexpr auto REMOTED_MODULE_LOGTAG {"wazuh-manager-remoted:communication"}; ///< Tag used for remoted module logging.

// Heartbeat period for the skeleton worker loop.
constexpr auto REMOTED_MODULE_HEARTBEAT_SECS {60};

/**
 * @brief Internal engine of the remoted module.
 *
 * Owns the worker std::thread and implements the canonical cooperative-shutdown
 * lifecycle (atomic flag + condition_variable + join). This is the skeleton the
 * real logic hangs off of: today the worker just logs a heartbeat.
 */
class RemotedModuleFacade final : public Singleton<RemotedModuleFacade>
{
public:
    void start(
        const std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>&
            logFunction,
        const remoted_module_config_t& configuration)
    {
        std::lock_guard<std::mutex> lock(m_lifecycleMutex);

        // Route the module's LOGFN_* calls back through remoted's logger.
        Log::assignLogFunction(logFunction);

        if (m_running)
        {
            LOGFN_WARN(m_logFn, "remoted module already started, ignoring start request.");
            return;
        }

        m_config = configuration;
        m_stopping = false;
        m_running = true;

        LOGFN_INFO(m_logFn,
                   "Starting remoted module (workerThreads=%d, queueSize=%d, port=%d, cluster='%s', node='%s', "
                   "workerNode=%s).",
                   m_config.worker_threads,
                   m_config.queue_size,
                   m_config.port,
                   m_config.cluster_name,
                   m_config.node_name,
                   m_config.worker_node ? "true" : "false");

        m_worker = std::thread(&RemotedModuleFacade::run, this);
    }

    void stop()
    {
        std::thread workerToJoin;

        {
            std::lock_guard<std::mutex> lock(m_lifecycleMutex);

            if (!m_running)
            {
                return;
            }

            LOGFN_INFO(m_logFn, "Stopping remoted module.");

            {
                std::lock_guard<std::mutex> waitLock(m_waitMutex);
                m_stopping = true;
            }
            m_waitCv.notify_all();

            workerToJoin = std::move(m_worker);
            m_running = false;
        }

        // Join outside the lifecycle lock so a concurrent start() can't deadlock.
        if (workerToJoin.joinable())
        {
            workerToJoin.join();
        }

        LOGFN_INFO(m_logFn, "remoted module stopped.");
    }

private:
    void run()
    {
        LOGFN_INFO(m_logFn, "remoted module worker thread running.");

        std::unique_lock<std::mutex> lock(m_waitMutex);
        while (!m_stopping)
        {
            LOGFN_DEBUG1(m_logFn, "remoted module heartbeat.");
            m_waitCv.wait_for(
                lock, std::chrono::seconds(REMOTED_MODULE_HEARTBEAT_SECS), [this]() { return m_stopping.load(); });
        }

        LOGFN_INFO(m_logFn, "remoted module worker thread finished.");
    }

    const LogFn m_logFn {REMOTED_MODULE_LOGTAG};
    std::mutex m_lifecycleMutex;              ///< Serializes start()/stop().
    std::mutex m_waitMutex;                   ///< Guards the heartbeat wait.
    std::condition_variable m_waitCv;         ///< Wakes the worker on stop.
    std::atomic_bool m_stopping {false};      ///< Cooperative-shutdown flag.
    bool m_running {false};                   ///< Whether the worker is active.
    std::thread m_worker;                     ///< The C++ thread launched for remoted.
    remoted_module_config_t m_config {};      ///< Copy of the caller's configuration.
};

#endif // _REMOTED_MODULE_FACADE_HPP
