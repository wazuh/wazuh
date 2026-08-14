/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HC_CALLBACK_DISPATCHER_HPP
#define _HC_CALLBACK_DISPATCHER_HPP

#include "callbackSink.hpp"
#include "https_client.h"

#include <condition_variable>
#include <functional>
#include <mutex>
#include <queue>
#include <thread>

/**
 * @brief Serializes every C callback onto a single dedicated thread.
 *
 * Streams call the ICallbackSink from their own threads; the dispatcher
 * queues each call and runs it in submission order on one thread, so the C
 * handlers never see concurrent or reentrant callbacks. log is NOT routed
 * here: the agent logger is thread-safe and low-latency, matching
 * remoted_module. start() launches the thread; stop() drains the queue and
 * joins, so no callback outlives it.
 */
class CallbackDispatcher final : public ICallbackSink
{
    public:
        explicit CallbackDispatcher(const hc_callbacks_t& callbacks);
        ~CallbackDispatcher() override;

        CallbackDispatcher(const CallbackDispatcher&) = delete;
        CallbackDispatcher& operator=(const CallbackDispatcher&) = delete;

        void start();
        void stop(); ///< Drains queued callbacks, then joins. Idempotent.

        void onStartupResult(bool accepted, const std::string& handshakeJson) override;
        void onReenrollRequired() override;
        void onTask(const std::string& taskId, const std::string& taskType,
                    const std::string& payloadJson) override;
        void onConfigDownloaded(const std::string& configHash,
                                std::shared_ptr<SpoolFile> file) override;
        void onUpgradeReady(const std::string& taskId, const std::string& wpkFile,
                            std::shared_ptr<SpoolFile> file, const std::string& installer) override;
        void onTaskFailed(const std::string& taskId, const std::string& taskType,
                          const std::string& reason) override;
        void onManagerConfigHash(const std::string& configHash) override;
        void onAgentGroups(const std::string& groupsCsv) override;
        void onSyncResponse(const std::string& sessionId, int result, const std::string& body) override;
        void onStateChange(hc_conn_state_t state) override;
        void onBufferLevel(hc_buffer_level_t level) override;
        void onProducerPause(bool paused) override;

    private:
        void run();
        void enqueue(std::function<void()> task);

        hc_callbacks_t m_callbacks;
        std::thread m_worker;
        std::mutex m_mutex;
        std::condition_variable m_cv;
        std::queue<std::function<void()>> m_queue;
        bool m_running {false};
        bool m_draining {false};
};

#endif // _HC_CALLBACK_DISPATCHER_HPP
