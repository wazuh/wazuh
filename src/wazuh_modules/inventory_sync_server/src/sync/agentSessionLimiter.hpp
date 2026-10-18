/*
 * Wazuh inventory sync server module
 * Copyright (C) Wazuh Inc.
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
#include <unordered_set>
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
        /// @brief Reason tryAcquire() refused admission.
        enum class RejectionReason
        {
            CapacityExceeded,   ///< Agent reached max_sessions_per_agent (sync.agent_busy.total).
            DuplicateInProgress ///< A session with the same X-Session-Id is already running (sync.session.duplicate.rejected).
        };

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
                , m_sessionId {std::move(other.m_sessionId)}
            {
            }

            Slot& operator=(Slot&& other) noexcept
            {
                if (this != &other)
                {
                    release();
                    m_owner = std::move(other.m_owner);
                    m_agentId = std::move(other.m_agentId);
                    m_sessionId = std::move(other.m_sessionId);
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
                    m_owner->release(m_agentId, m_sessionId);
                    m_owner.reset();
                }
            }

            const std::string& sessionId() const noexcept
            {
                return m_sessionId;
            }

        private:
            friend class AgentSessionLimiter;

            Slot(std::shared_ptr<AgentSessionLimiter> owner, std::string agentId, std::string sessionId)
                : m_owner {std::move(owner)}
                , m_agentId {std::move(agentId)}
                , m_sessionId {std::move(sessionId)}
            {
            }

            std::shared_ptr<AgentSessionLimiter> m_owner;
            std::string m_agentId;
            std::string m_sessionId;
        };

        /// @param capacity Maximum pending sessions per agent. 0 disables the limit.
        explicit AgentSessionLimiter(std::size_t capacity) noexcept
            : m_capacity {capacity}
        {
        }

        AgentSessionLimiter(const AgentSessionLimiter&) = delete;
        AgentSessionLimiter& operator=(const AgentSessionLimiter&) = delete;

        /**
         * @brief Try to admit one more session for @p agentId, deduplicating on @p sessionId (D31).
         *
         * @param agentId The validated, padded agent id (ValidatedSession::agentId).
         * @param sessionId The optional X-Session-Id header from the agent.
         * @param outReason Optional pointer to store the rejection reason if admission fails.
         * @return An engaged slot, or std::nullopt when the agent is at its cap or duplicate is in flight.
         */
        std::optional<Slot> tryAcquire(std::string_view agentId,
                                       std::string_view sessionId = {},
                                       RejectionReason* outReason = nullptr)
        {
            if (m_capacity == 0)
            {
                return Slot {};
            }

            std::string agentKey {agentId};
            std::string sessionKey {sessionId};
            {
                std::lock_guard lock {m_mutex};
                auto& state = m_pending[agentKey];

                // D31: A duplicate session with the same session id already in flight on this node
                // is rejected so two copies never run the same by-query concurrently.
                if (!sessionKey.empty() && state.activeSessions.find(sessionKey) != state.activeSessions.end())
                {
                    ++m_duplicatesRejectedTotal;
                    if (outReason != nullptr)
                    {
                        *outReason = RejectionReason::DuplicateInProgress;
                    }
                    if (state.pendingCount == 0 && state.activeSessions.empty())
                    {
                        m_pending.erase(agentKey);
                    }
                    return std::nullopt;
                }

                if (state.pendingCount >= m_capacity)
                {
                    ++m_rejectedTotal;
                    if (outReason != nullptr)
                    {
                        *outReason = RejectionReason::CapacityExceeded;
                    }
                    if (state.pendingCount == 0 && state.activeSessions.empty())
                    {
                        m_pending.erase(agentKey);
                    }
                    return std::nullopt;
                }

                ++state.pendingCount;
                if (!sessionKey.empty())
                {
                    state.activeSessions.insert(sessionKey);
                }
            }
            return Slot {shared_from_this(), std::move(agentKey), std::move(sessionKey)};
        }

        /// @brief Sessions @p agentId has pending right now (0 when it has none).
        std::size_t pendingSessions(std::string_view agentId) const
        {
            std::lock_guard lock {m_mutex};
            const auto it = m_pending.find(std::string {agentId});
            return it == m_pending.end() ? 0 : it->second.pendingCount;
        }

        /// @brief Whether a session with @p sessionId is actively running for @p agentId.
        bool hasActiveSession(std::string_view agentId, std::string_view sessionId) const
        {
            if (sessionId.empty())
            {
                return false;
            }
            std::lock_guard lock {m_mutex};
            const auto it = m_pending.find(std::string {agentId});
            if (it == m_pending.end())
            {
                return false;
            }
            return it->second.activeSessions.find(std::string {sessionId}) != it->second.activeSessions.end();
        }

        /// @brief Agents with at least one session pending -- the table's size.
        std::size_t trackedAgents() const
        {
            std::lock_guard lock {m_mutex};
            return m_pending.size();
        }

        /// @brief Sessions tryAcquire() has refused due to capacity since construction.
        std::uint64_t rejectedTotal() const
        {
            std::lock_guard lock {m_mutex};
            return m_rejectedTotal;
        }

        /// @brief Duplicate sessions tryAcquire() has refused since construction (D31).
        std::uint64_t duplicatesRejectedTotal() const
        {
            std::lock_guard lock {m_mutex};
            return m_duplicatesRejectedTotal;
        }

        /// @brief Configured cap (0 == disabled).
        std::size_t capacity() const noexcept
        {
            return m_capacity;
        }

    private:
        void release(const std::string& agentId, const std::string& sessionId) noexcept
        {
            std::lock_guard lock {m_mutex};
            const auto it = m_pending.find(agentId);
            if (it != m_pending.end())
            {
                if (!sessionId.empty())
                {
                    it->second.activeSessions.erase(sessionId);
                }
                if (it->second.pendingCount > 0)
                {
                    --it->second.pendingCount;
                }
                if (it->second.pendingCount == 0 && it->second.activeSessions.empty())
                {
                    m_pending.erase(it);
                }
            }
        }

        struct AgentEntry
        {
            std::size_t pendingCount {0};
            std::unordered_set<std::string> activeSessions;
        };

        const std::size_t m_capacity;
        mutable std::mutex m_mutex;
        std::unordered_map<std::string, AgentEntry> m_pending; ///< Only agents with a session pending.
        std::uint64_t m_rejectedTotal {0};
        std::uint64_t m_duplicatesRejectedTotal {0};
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
