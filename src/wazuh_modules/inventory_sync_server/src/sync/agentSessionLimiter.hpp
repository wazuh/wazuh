/*
 * Wazuh inventory sync server module
 * Copyright (C) 2015, Wazuh Inc.
 * October 7, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVSYNC_SYNC_AGENT_SESSION_LIMITER_HPP
#define _INVSYNC_SYNC_AGENT_SESSION_LIMITER_HPP

#include <uds_http_server/IUdsHttpServer.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

namespace invsync::sync
{

    /**
     * @brief Bounds how many sessions ONE agent may have admitted and not yet answered (D28).
     *
     * remoted caps what an agent has open on ITS side, but it gives up on a /stateful request at
     * its downstream deadline and frees the agent's slot there, while this module keeps working on
     * the session: neither the pipeline nor the scan lane cancels admitted work. Without a count of
     * its own, one agent could keep re-sending into the global queue every time remoted timed out,
     * and fill it for everyone. The count is taken after validation and released when the session
     * is answered -- by the worker, which always answers, whether or not anyone is still listening.
     *
     * Only agents with a session pending have an entry; one mutex guards it, and the critical
     * section is one hash lookup, so it is safe on the I/O strand. A capacity of 0 disables it.
     *
     * Lifetime: a Slot co-owns its limiter. Create the limiter with std::make_shared.
     */
    class AgentSessionLimiter final : public std::enable_shared_from_this<AgentSessionLimiter>
    {
    public:
        /// @brief RAII token for one pending session. Movable, non-copyable, releases exactly once.
        class Slot final
        {
        public:
            Slot() = default;

            ~Slot()
            {
                release();
            }

            Slot(Slot&& other) noexcept
                : m_owner {std::move(other.m_owner)}
                , m_agentId {std::move(other.m_agentId)}
            {
            }

            Slot& operator=(Slot&& other) noexcept
            {
                if (this != &other)
                {
                    release();
                    m_owner = std::move(other.m_owner);
                    m_agentId = std::move(other.m_agentId);
                }
                return *this;
            }

            Slot(const Slot&) = delete;
            Slot& operator=(const Slot&) = delete;

            /// @brief Give the slot back now. Idempotent.
            void release() noexcept
            {
                if (m_owner != nullptr)
                {
                    m_owner->release(m_agentId);
                    m_owner.reset();
                }
            }

        private:
            friend class AgentSessionLimiter;

            Slot(std::shared_ptr<AgentSessionLimiter> owner, std::string agentId)
                : m_owner {std::move(owner)}
                , m_agentId {std::move(agentId)}
            {
            }

            std::shared_ptr<AgentSessionLimiter> m_owner;
            std::string m_agentId;
        };

        /// @param capacity Maximum pending sessions per agent. 0 disables the limit.
        explicit AgentSessionLimiter(std::size_t capacity) noexcept
            : m_capacity {capacity}
        {
        }

        AgentSessionLimiter(const AgentSessionLimiter&) = delete;
        AgentSessionLimiter& operator=(const AgentSessionLimiter&) = delete;

        /**
         * @brief Try to admit one more session for @p agentId.
         *
         * @param agentId The validated, padded agent id (ValidatedSession::agentId).
         * @return An engaged slot, or std::nullopt when the agent is at its cap. A disabled limiter
         *         returns an empty Slot, which is still a success.
         */
        std::optional<Slot> tryAcquire(std::string_view agentId)
        {
            if (m_capacity == 0)
            {
                return Slot {};
            }

            std::string key {agentId};
            {
                std::lock_guard lock {m_mutex};
                auto& pending = m_pending[key];
                if (pending >= m_capacity)
                {
                    ++m_rejectedTotal;
                    return std::nullopt;
                }
                ++pending;
            }
            return Slot {shared_from_this(), std::move(key)};
        }

        /// @brief Sessions @p agentId has pending right now (0 when it has none).
        std::size_t pendingSessions(std::string_view agentId) const
        {
            std::lock_guard lock {m_mutex};
            const auto it = m_pending.find(std::string {agentId});
            return it == m_pending.end() ? 0 : it->second;
        }

        /// @brief Agents with at least one session pending -- the table's size.
        std::size_t trackedAgents() const
        {
            std::lock_guard lock {m_mutex};
            return m_pending.size();
        }

        /// @brief Sessions tryAcquire() has refused since construction.
        std::uint64_t rejectedTotal() const
        {
            std::lock_guard lock {m_mutex};
            return m_rejectedTotal;
        }

        /// @brief Configured cap (0 == disabled).
        std::size_t capacity() const noexcept
        {
            return m_capacity;
        }

    private:
        void release(const std::string& agentId) noexcept
        {
            std::lock_guard lock {m_mutex};
            const auto it = m_pending.find(agentId);
            if (it != m_pending.end() && --it->second == 0)
            {
                m_pending.erase(it);
            }
        }

        const std::size_t m_capacity;
        mutable std::mutex m_mutex;
        std::unordered_map<std::string, std::size_t> m_pending; ///< Only agents with a session pending.
        std::uint64_t m_rejectedTotal {0};
    };

    /**
     * @brief Responder decorator that holds an agent's session Slot until the session is answered.
     *
     * Whoever answers -- the endpoint inline, a pipeline worker after its flush, the scan lane after
     * its scan, a shutdown abandoning the batch -- answers through this, so the slot follows the
     * session to its end on every path. A responder dropped unanswered releases it on destruction.
     *
     * send() may race (an answering thread against an error path): the inner responder's send-once
     * makes the reply safe, and m_answered makes the release so -- only the first caller touches the
     * Slot, which is not thread-safe on its own.
     */
    class AdmittedSessionResponder final : public wazuh::uds_http::IHttpResponder
    {
    public:
        AdmittedSessionResponder(std::shared_ptr<wazuh::uds_http::IHttpResponder> inner, AgentSessionLimiter::Slot slot)
            : m_inner {std::move(inner)}
            , m_slot {std::move(slot)}
        {
        }

        void send(wazuh::uds_http::HttpResponse response) override
        {
            m_inner->send(std::move(response));
            if (!m_answered.exchange(true))
            {
                m_slot.release();
            }
        }

    private:
        std::shared_ptr<wazuh::uds_http::IHttpResponder> m_inner;
        AgentSessionLimiter::Slot m_slot;
        std::atomic<bool> m_answered {false};
    };

} // namespace invsync::sync

#endif // _INVSYNC_SYNC_AGENT_SESSION_LIMITER_HPP
