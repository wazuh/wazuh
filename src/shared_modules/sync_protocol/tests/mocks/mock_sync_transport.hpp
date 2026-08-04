/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#pragma once

#include "inventorySync_generated.h"
#include "sync_socket_transport.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <vector>

/**
 * @brief Stands in for the queue-sync socket.
 *
 * Captures the session id the protocol picked, which the tests need: the id is
 * no longer a constant they choose, so an answer has to be addressed to
 * whatever the agent generated.
 */
class MockSyncTransport : public ISyncSessionTransport
{
    public:
        bool checkStatus() override
        {
            return m_available;
        }

        bool sendSession(uint64_t session, const std::vector<uint8_t>& message) override
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_session = session;
            m_lastMessage = message;
            m_sendCount++;
            m_cv.notify_all();
            return m_accept;
        }

        /// @brief Waits until the protocol has handed a session over.
        bool waitForSession(std::chrono::milliseconds timeout = std::chrono::seconds {5})
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            return m_cv.wait_for(lock, timeout, [this] { return m_sendCount > 0; });
        }

        uint64_t session() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_session;
        }

        std::vector<uint8_t> lastMessage() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_lastMessage;
        }

        int sendCount() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_sendCount;
        }

        void setAccept(bool accept)
        {
            m_accept = accept;
        }
        void setAvailable(bool available)
        {
            m_available = available;
        }

    private:
        mutable std::mutex m_mutex;
        std::condition_variable m_cv;
        uint64_t m_session {0};
        std::vector<uint8_t> m_lastMessage;
        int m_sendCount {0};
        // Atomic: the test thread flips these while the protocol's worker reads them.
        std::atomic<bool> m_accept {true};
        std::atomic<bool> m_available {true};
};

/// @brief Answers the session the protocol is waiting on, the way the manager does:
///        one HCRESULT carrying the raw HTTP status code (see
///        AgentSyncProtocol::applyHttpResult - there is no EndAck FlatBuffer message
///        anymore). forSession=0 skips the protocol's session-correlation check.
inline void answerSession(const std::shared_ptr<MockSyncTransport>& transport,
                          const std::function<void(const uint8_t*, size_t)>& feed,
                          int httpCode = 200, uint64_t forSession = 0)
{
    if (!transport->waitForSession())
    {
        return; // The caller's assertions report the timeout.
    }

    const std::string text = "HCRESULT:" + std::to_string(forSession) + ":" +
                             std::to_string(httpCode) + ":{}";
    feed(reinterpret_cast<const uint8_t*>(text.data()), text.size());
}

/// @brief The FullSession the protocol handed over, for tests that assert on
///        what a session actually carried.
inline const Wazuh::SyncSchema::FullSession* capturedSession(
    const std::shared_ptr<MockSyncTransport>& transport, std::vector<uint8_t>& keepAlive)
{
    keepAlive = transport->lastMessage();

    if (keepAlive.empty())
    {
        return nullptr;
    }

    const auto* message = Wazuh::SyncSchema::GetMessage(keepAlive.data());
    return message ? message->content_as<Wazuh::SyncSchema::FullSession>() : nullptr;
}

/// @brief The session's SyncData payload, or nullptr if it carries something else.
inline const Wazuh::SyncSchema::SyncData* syncData(const Wazuh::SyncSchema::FullSession* session)
{
    if (session && session->payload_type() == Wazuh::SyncSchema::SessionPayload::SyncData)
    {
        return session->payload_as_SyncData();
    }

    return nullptr;
}

/// @brief How many DataValue entries the session carried.
inline int countedDataValues(const Wazuh::SyncSchema::FullSession* session)
{
    const auto* data = syncData(session);
    return (data && data->values()) ? static_cast<int>(data->values()->size()) : 0;
}
