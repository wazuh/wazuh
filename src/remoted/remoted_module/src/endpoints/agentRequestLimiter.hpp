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

#include <algorithm>
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

namespace remoted::endpoints
{

    /**
     * @brief Bounds what ONE authenticated agent may hold at once: open requests, and the bytes
     *        those requests carry.
     *
     * Every other capacity limit of the listener (the in-flight byte budget, the deferred-work
     * limiter, the connection cap) is shared by the whole fleet, so without this one a single
     * enrolled agent -- which holds its own key and can mint as many bearers as it likes -- could
     * fill all of them and get every other agent a 503. The AuthGateway acquires a Slot right after
     * the bearer verifies and before the body is decoded, charges the body to it AS it decodes (the
     * decoder offers each growth of its output before taking shared budget for it), and wraps
     * the responder in an AdmittedResponder that holds it until the reply has left: for a buffered
     * reply, when it is handed to the transport; for a stream, when the transport drops the stream
     * source (transfer finished, failed, peer gone, or server torn down).
     *
     * Two limits, either one sheds: `capacity` open requests, and `byteShare` bytes of decoded
     * bodies. The byte share is what lets one route accept a body far larger than every other
     * (an agent cannot split its vulnerability-detection inventory) without letting that agent hold
     * the whole budget: no matter how many requests or which routes, an agent holds at most its share.
     *
     * Only agents with something open have an entry: an entry back at zero is erased, so the table
     * grows with the requests in flight (bounded by max_parallel_connections), never with the
     * number of agents. One mutex guards it; the critical section is one hash lookup.
     *
     * A capacity of 0 disables the whole limiter (every acquire succeeds, nothing is tracked); a
     * byte share of 0 disables only the byte limit.
     *
     * Lifetime: a Slot co-owns its limiter, so it may safely outlive the gateway that issued it.
     * Create the limiter with std::make_shared.
     */
    class AgentRequestLimiter final : public std::enable_shared_from_this<AgentRequestLimiter>
    {
    public:
        /**
         * @brief RAII token for one open request and the bytes charged to it. Movable,
         *        non-copyable, releases exactly once.
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
                , m_bytes {std::exchange(other.m_bytes, 0)}
            {
            }

            Slot& operator=(Slot&& other) noexcept
            {
                if (this != &other)
                {
                    release();
                    m_owner = std::move(other.m_owner);
                    m_agentId = std::move(other.m_agentId);
                    m_bytes = std::exchange(other.m_bytes, 0);
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

            /**
             * @brief Charge @p bytes to this request's agent.
             *
             * @return false, charging nothing, when they would take the agent past its byte share.
             *         Always true for a disengaged slot (a disabled limiter).
             */
            bool charge(std::size_t bytes)
            {
                if (m_owner == nullptr)
                {
                    return true;
                }
                if (!m_owner->charge(m_agentId, bytes))
                {
                    return false;
                }
                m_bytes += bytes;
                return true;
            }

            /**
             * @brief Give back @p bytes of an earlier charge() whose allocation did not happen.
             *        Clamped to what this slot holds; the slot itself stays open.
             */
            void refund(std::size_t bytes) noexcept
            {
                if (m_owner == nullptr)
                {
                    return;
                }
                bytes = std::min(bytes, m_bytes);
                m_owner->refund(m_agentId, bytes);
                m_bytes -= bytes;
            }

            /// @brief Give the slot and its bytes back now. Idempotent.
            void release() noexcept
            {
                if (m_owner != nullptr)
                {
                    m_owner->release(m_agentId, m_bytes);
                    m_owner.reset();
                    m_bytes = 0;
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
            std::size_t m_bytes {0}; ///< Charged through this slot, returned with it.
        };

        /**
         * @brief Construct the limiter. Use std::make_shared: a Slot co-owns it.
         *
         * @param capacity  Maximum open requests per agent. 0 disables the whole limiter.
         * @param byteShare Maximum decoded-body bytes per agent across its open requests. 0
         *                  disables the byte limit only.
         */
        explicit AgentRequestLimiter(std::size_t capacity, std::size_t byteShare = 0) noexcept
            : m_capacity {capacity}
            , m_byteShare {byteShare}
        {
        }

        AgentRequestLimiter(const AgentRequestLimiter&) = delete;
        AgentRequestLimiter& operator=(const AgentRequestLimiter&) = delete;

        /**
         * @brief Try to open one more request for @p agentId.
         *
         * @param agentId The VERIFIED agent id (the token's `sub`), never a header value.
         * @return An engaged slot, or std::nullopt when the agent is at its request cap. A disabled
         *         limiter returns an empty (disengaged) Slot, which is still a success.
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
                auto& entry = m_open[key];
                if (entry.requests >= m_capacity)
                {
                    ++m_rejectedTotal;
                    return std::nullopt;
                }
                ++entry.requests;
            }
            return Slot {shared_from_this(), std::move(key)};
        }

        /// @brief Requests @p agentId has open right now (0 when it has none).
        std::size_t openRequests(std::string_view agentId) const
        {
            std::lock_guard lock {m_mutex};
            const auto it = m_open.find(std::string {agentId});
            return it == m_open.end() ? 0 : it->second.requests;
        }

        /// @brief Decoded-body bytes charged to @p agentId right now.
        std::size_t heldBytes(std::string_view agentId) const
        {
            std::lock_guard lock {m_mutex};
            const auto it = m_open.find(std::string {agentId});
            return it == m_open.end() ? 0 : it->second.bytes;
        }

        /// @brief Agents with at least one request open -- the table's size.
        std::size_t trackedAgents() const
        {
            std::lock_guard lock {m_mutex};
            return m_open.size();
        }

        /// @brief Acquires and charges refused since construction.
        std::uint64_t rejectedTotal() const
        {
            std::lock_guard lock {m_mutex};
            return m_rejectedTotal;
        }

        /// @brief Configured request cap (0 == disabled).
        std::size_t capacity() const noexcept
        {
            return m_capacity;
        }

        /// @brief Configured byte share (0 == no byte limit).
        std::size_t byteShare() const noexcept
        {
            return m_byteShare;
        }

    private:
        struct Entry
        {
            std::size_t requests {0};
            std::size_t bytes {0};
        };

        bool charge(const std::string& agentId, std::size_t bytes)
        {
            std::lock_guard lock {m_mutex};
            const auto it = m_open.find(agentId);
            if (it == m_open.end())
            {
                return false; // unreachable while the charging slot is alive
            }
            if (m_byteShare != 0 && bytes > m_byteShare - it->second.bytes)
            {
                ++m_rejectedTotal;
                return false;
            }
            it->second.bytes += bytes;
            return true;
        }

        void refund(const std::string& agentId, std::size_t bytes) noexcept
        {
            std::lock_guard lock {m_mutex};
            const auto it = m_open.find(agentId);
            if (it != m_open.end())
            {
                it->second.bytes -= bytes;
            }
        }

        void release(const std::string& agentId, std::size_t bytes) noexcept
        {
            std::lock_guard lock {m_mutex};
            const auto it = m_open.find(agentId);
            if (it == m_open.end())
            {
                return;
            }
            it->second.bytes -= bytes;
            if (--it->second.requests == 0)
            {
                m_open.erase(it);
            }
        }

        const std::size_t m_capacity;
        const std::size_t m_byteShare;
        mutable std::mutex m_mutex;
        std::unordered_map<std::string, Entry> m_open; ///< Only agents with a request open.
        std::uint64_t m_rejectedTotal {0};
    };

    /**
     * @brief Stream source that holds an agent's Slot for as long as the transport holds it.
     *
     * The transport's pump is the source's only owner and drops it when the transfer ends --
     * finished, failed, peer gone, or the server torn down -- so the slot lives exactly as long as
     * the download, however slowly the agent reads it.
     */
    class AdmittedByteSource final : public remoted::http::IByteSource
    {
    public:
        AdmittedByteSource(std::shared_ptr<remoted::http::IByteSource> inner, AgentRequestLimiter::Slot slot)
            : m_inner {std::move(inner)}
            , m_slot {std::move(slot)}
        {
        }

        std::size_t read(char* buffer, std::size_t capacity) override
        {
            return m_inner->read(buffer, capacity);
        }

    private:
        std::shared_ptr<remoted::http::IByteSource> m_inner;
        AgentRequestLimiter::Slot m_slot;
    };

    /**
     * @brief Responder decorator that holds an agent's Slot until the reply leaves.
     *
     * Releasing on the reply rather than when the request object dies is deliberate: the deferred
     * forwarder drops the request at SEND time to free the byte budget, long before the downstream
     * answers, and /download releases its payload before streaming. A buffered reply releases the
     * slot once it is handed to the transport; a streamed one hands the slot to the stream source
     * (AdmittedByteSource), so a slow download keeps counting until it ends. A responder dropped
     * without answering releases it in its destructor.
     *
     * send()/stream() may race -- the deferred forwarder's pool thread against the gateway's error
     * path after a handler throws. The inner responder's send-once makes the reply safe; m_answered
     * makes the slot so: only the first caller touches m_slot, which is not thread-safe on its own.
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
            if (!m_answered.exchange(true))
            {
                m_slot.release();
            }
        }

        void stream(remoted::http::StreamResponse response) override
        {
            if (m_answered.exchange(true))
            {
                m_inner->stream(std::move(response)); // already answered: the inner send-once drops it
                return;
            }
            if (response.source != nullptr)
            {
                response.source = std::make_shared<AdmittedByteSource>(std::move(response.source), std::move(m_slot));
            }
            m_inner->stream(std::move(response));
            m_slot.release(); // no-op once moved into the source
        }

    private:
        std::shared_ptr<remoted::http::IHttpResponder> m_inner;
        AgentRequestLimiter::Slot m_slot;
        std::atomic<bool> m_answered {false};
    };

} // namespace remoted::endpoints

#endif // _REMOTED_ENDPOINTS_AGENT_REQUEST_LIMITER_HPP
