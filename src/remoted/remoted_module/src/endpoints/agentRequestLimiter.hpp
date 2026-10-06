/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * October 6, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_ENDPOINTS_AGENT_REQUEST_LIMITER_HPP
#define _REMOTED_ENDPOINTS_AGENT_REQUEST_LIMITER_HPP

#include "http_server/IHttpServer.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

namespace remoted::endpoints
{

    /**
     * @brief Bounds how many requests ONE authenticated agent may have open at once.
     *
     * Every other capacity limit of the listener (the in-flight byte budget, the deferred-work
     * limiter, the connection cap) is shared by the whole fleet, so without this one a single
     * enrolled agent -- which holds its own key and can mint as many bearers as it likes -- could
     * fill all of them and get every other agent a 503. The AuthGateway acquires a Slot right after
     * the bearer verifies and before the body is decoded, and wraps the responder in an
     * AdmittedResponder that releases it once the reply is handed to the transport, whatever the
     * route and however its handler manages the request object.
     *
     * Only agents with a request open have an entry: a count that drops to 0 is erased, so the table
     * grows with the requests in flight (bounded by max_parallel_connections), never with the
     * number of agents. One mutex guards it; the critical section is one hash lookup.
     *
     * A capacity of 0 disables the limit (every acquire succeeds, nothing is tracked).
     *
     * Lifetime: a Slot co-owns its limiter, so it may safely outlive the gateway that issued it.
     * Create the limiter with std::make_shared.
     */
    class AgentRequestLimiter final : public std::enable_shared_from_this<AgentRequestLimiter>
    {
    public:
        /**
         * @brief RAII token for one open request. Movable, non-copyable, releases exactly once.
         */
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

            /// @brief True while this token holds a slot.
            explicit operator bool() const noexcept
            {
                return m_owner != nullptr;
            }

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
            friend class AgentRequestLimiter;

            Slot(std::shared_ptr<AgentRequestLimiter> owner, std::string agentId)
                : m_owner {std::move(owner)}
                , m_agentId {std::move(agentId)}
            {
            }

            std::shared_ptr<AgentRequestLimiter> m_owner;
            std::string m_agentId;
        };

        /**
         * @brief Construct the limiter. Use std::make_shared: a Slot co-owns it.
         *
         * @param capacity Maximum open requests per agent. 0 disables the limit.
         */
        explicit AgentRequestLimiter(std::size_t capacity) noexcept
            : m_capacity {capacity}
        {
        }

        AgentRequestLimiter(const AgentRequestLimiter&) = delete;
        AgentRequestLimiter& operator=(const AgentRequestLimiter&) = delete;

        /**
         * @brief Try to open one more request for @p agentId.
         *
         * @param agentId The VERIFIED agent id (the token's `sub`), never a header value.
         * @return An engaged slot, or std::nullopt when the agent is at its cap. A disabled limiter
         *         returns an empty (disengaged) Slot, which is still a success.
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
                auto& open = m_open[key];
                if (open >= m_capacity)
                {
                    ++m_rejectedTotal;
                    return std::nullopt;
                }
                ++open;
            }
            return Slot {shared_from_this(), std::move(key)};
        }

        /// @brief Requests @p agentId has open right now (0 when it has none).
        std::size_t openRequests(std::string_view agentId) const
        {
            std::lock_guard lock {m_mutex};
            const auto it = m_open.find(std::string {agentId});
            return it == m_open.end() ? 0 : it->second;
        }

        /// @brief Agents with at least one request open -- the table's size.
        std::size_t trackedAgents() const
        {
            std::lock_guard lock {m_mutex};
            return m_open.size();
        }

        /// @brief Requests tryAcquire() has refused since construction.
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
            const auto it = m_open.find(agentId);
            if (it != m_open.end() && --it->second == 0)
            {
                m_open.erase(it);
            }
        }

        const std::size_t m_capacity;
        mutable std::mutex m_mutex;
        std::unordered_map<std::string, std::size_t> m_open; ///< Only agents with a request open.
        std::uint64_t m_rejectedTotal {0};
    };

    /**
     * @brief Responder decorator that holds an agent's Slot until the reply leaves.
     *
     * Releasing on send()/stream() rather than when the request object dies is deliberate: the
     * deferred forwarder drops the request at SEND time to free the byte budget, long before the
     * downstream answers, and /download releases its payload before streaming. Tying the slot to
     * the responder bounds the whole span the agent is waiting on, on every route. A responder
     * dropped without answering releases it in its destructor. A stream is counted until it is
     * handed to the transport, not until its last chunk: transfers are bounded by
     * max_parallel_connections already.
     */
    class AdmittedResponder final : public remoted::http::IHttpResponder
    {
    public:
        AdmittedResponder(std::shared_ptr<remoted::http::IHttpResponder> inner, AgentRequestLimiter::Slot slot)
            : m_inner {std::move(inner)}
            , m_slot {std::move(slot)}
        {
        }

        void send(remoted::http::HttpResponse response) override
        {
            m_inner->send(std::move(response));
            m_slot.release();
        }

        void stream(remoted::http::StreamResponse response) override
        {
            m_inner->stream(std::move(response));
            m_slot.release();
        }

    private:
        std::shared_ptr<remoted::http::IHttpResponder> m_inner;
        AgentRequestLimiter::Slot m_slot;
    };

} // namespace remoted::endpoints

#endif // _REMOTED_ENDPOINTS_AGENT_REQUEST_LIMITER_HPP
