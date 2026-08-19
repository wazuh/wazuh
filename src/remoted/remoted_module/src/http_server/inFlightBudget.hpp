/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * July 23, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_HTTP_IN_FLIGHT_BUDGET_HPP
#define _REMOTED_HTTP_IN_FLIGHT_BUDGET_HPP

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <optional>

namespace remoted::http
{

    /**
     * @brief Global byte budget for in-flight (unprocessed) request payloads.
     *
     * The transport reserves bytes the moment a request is admitted and holds the
     * reservation for the request's whole in-flight life (queued on the worker pool
     * + running the handler + waiting on a deferred response). When the budget is
     * exhausted the transport rejects new requests with 503 instead of letting the
     * worker-pool queue grow without bound -- the backpressure the raw asio pool
     * lacks.
     *
     * A reservation is an RAII token: it releases its bytes (and decrements the live
     * request counter) in its destructor, so accounting is automatic and
     * exception-safe no matter which queue/pipeline the request travels through.
     *
     * All operations are lock-free (atomics). A maxBytes of 0 disables the byte
     * limit (every request is admitted) while still keeping the live counter, so the
     * observability path works even when the limit is turned off.
     */
    class InFlightBudget final
    {
    public:
        /**
         * @brief RAII byte reservation. Movable, non-copyable, releases exactly once.
         */
        class Reservation final
        {
        public:
            Reservation() = default;

            ~Reservation()
            {
                releaseIfOwned();
            }

            Reservation(Reservation&& other) noexcept
                : m_owner {other.m_owner}
                , m_bytes {other.m_bytes}
                , m_countsRequest {other.m_countsRequest}
            {
                other.m_owner = nullptr;
                other.m_bytes = 0;
                other.m_countsRequest = false;
            }

            Reservation& operator=(Reservation&& other) noexcept
            {
                if (this != &other)
                {
                    releaseIfOwned();
                    m_owner = other.m_owner;
                    m_bytes = other.m_bytes;
                    m_countsRequest = other.m_countsRequest;
                    other.m_owner = nullptr;
                    other.m_bytes = 0;
                    other.m_countsRequest = false;
                }
                return *this;
            }

            Reservation(const Reservation&) = delete;
            Reservation& operator=(const Reservation&) = delete;

            /// @brief The number of bytes this reservation holds (0 when the budget is disabled).
            std::size_t bytes() const noexcept
            {
                return m_bytes;
            }

            /// @brief True when this token holds an active reservation.
            explicit operator bool() const noexcept
            {
                return m_owner != nullptr;
            }

            /**
             * @brief Try to grow this reservation by @p additionalBytes more, atomically, against
             *        the same owning budget.
             *
             * Lets a caller that doesn't know its final size upfront (e.g. streaming decompression)
             * reserve incrementally as more bytes materialize, instead of either over-reserving a
             * worst-case bound before starting or not tracking the bytes at all.
             *
             * @return true if granted -- bytes() increases by @p additionalBytes. false if the
             *         budget doesn't have that much room right now (this reservation is
             *         unchanged), or if this token holds no active reservation (moved-from/released).
             */
            bool grow(std::size_t additionalBytes) noexcept
            {
                if (additionalBytes == 0)
                {
                    return true;
                }
                if (m_owner == nullptr)
                {
                    return false;
                }
                if (!m_owner->enabled())
                {
                    // Same "admit unconditionally, still not tracked" semantics as tryReserve().
                    return true;
                }

                std::size_t current = m_owner->m_availableBytes.load(std::memory_order_relaxed);
                do
                {
                    if (additionalBytes > current)
                    {
                        return false; // would exceed the budget
                    }
                } while (!m_owner->m_availableBytes.compare_exchange_weak(
                    current, current - additionalBytes, std::memory_order_acq_rel, std::memory_order_relaxed));

                m_bytes += additionalBytes;
                return true;
            }

            /**
             * @brief Make this reservation carry the "one admitted request" count.
             *
             * Auxiliary reservations (tryReserveUncounted()) track bytes only. When one of
             * them becomes the request's resident body -- the decoder swaps the wire buffer
             * for the decoded one, whose reservation must inherit the request's identity --
             * promoting it keeps inFlightCount() at exactly one per request while the
             * original admission reservation is released. Idempotent; no-op on an empty or
             * already-counting token.
             */
            void promoteToRequest() noexcept
            {
                if (m_owner != nullptr && !m_countsRequest)
                {
                    m_owner->m_inFlightCount.fetch_add(1, std::memory_order_relaxed);
                    m_countsRequest = true;
                }
            }

        private:
            friend class InFlightBudget;

            Reservation(InFlightBudget* owner, std::size_t bytes, bool countsRequest) noexcept
                : m_owner {owner}
                , m_bytes {bytes}
                , m_countsRequest {countsRequest}
            {
            }

            void releaseIfOwned() noexcept
            {
                if (m_owner != nullptr)
                {
                    m_owner->release(m_bytes, m_countsRequest);
                    m_owner = nullptr;
                    m_bytes = 0;
                    m_countsRequest = false;
                }
            }

            InFlightBudget* m_owner {nullptr};
            std::size_t m_bytes {0};
            bool m_countsRequest {false}; ///< True only for request-admission reservations.
        };

        /**
         * @brief Construct the budget.
         *
         * @param maxBytes Maximum in-flight payload bytes. 0 disables the byte limit.
         */
        explicit InFlightBudget(std::size_t maxBytes) noexcept
            : m_maxBytes {maxBytes}
            , m_availableBytes {maxBytes}
        {
        }

        InFlightBudget(const InFlightBudget&) = delete;
        InFlightBudget& operator=(const InFlightBudget&) = delete;

        /**
         * @brief Try to reserve @p bytes for one request (admission).
         *
         * This is the request-admission path and the only one that touches the request
         * ledgers: success counts one more in-flight request, failure counts one shed
         * (rejectedTotal()) -- the decision the transport turns into a 503.
         *
         * @return An engaged reservation on success, std::nullopt when admitting the
         *         request would exceed the budget. When the budget is disabled the
         *         call always succeeds (reserving 0 tracked bytes).
         */
        std::optional<Reservation> tryReserve(std::size_t bytes) noexcept
        {
            return tryReserveImpl(bytes, /*countsRequest=*/true);
        }

        /**
         * @brief Try to reserve @p bytes of auxiliary memory for an already-admitted request.
         *
         * Same byte ledger as tryReserve(), but touches neither request ledger: success does
         * not count an extra in-flight request (the request already holds its admission
         * reservation) and failure is not a shed -- the caller answers the admitted request
         * itself (e.g. 413 when a decompression window does not fit), it does not turn away a
         * new one. Promote the token (Reservation::promoteToRequest()) if it later becomes
         * the request's resident body.
         */
        std::optional<Reservation> tryReserveUncounted(std::size_t bytes) noexcept
        {
            return tryReserveImpl(bytes, /*countsRequest=*/false);
        }

        /// @brief Remaining budget in bytes (meaningless while the budget is disabled).
        std::size_t availableBytes() const noexcept
        {
            return m_availableBytes.load(std::memory_order_relaxed);
        }

        /// @brief Admitted requests currently in memory. Counts requests, not reservations:
        ///        auxiliary (uncounted) reservations never show here unless promoted.
        std::size_t inFlightCount() const noexcept
        {
            return m_inFlightCount.load(std::memory_order_relaxed);
        }

        /// @brief Configured maximum in-flight payload bytes (0 == limit disabled).
        std::size_t maxBytes() const noexcept
        {
            return m_maxBytes;
        }

        /// @brief Requests tryReserve() has refused to admit since construction (0 while
        ///        disabled). Uncounted reservations and denied grows never show here.
        std::uint64_t rejectedTotal() const noexcept
        {
            return m_rejectedTotal.load(std::memory_order_relaxed);
        }

        /// @brief Whether the byte limit is enforced (false when constructed with 0).
        bool enabled() const noexcept
        {
            return m_maxBytes != 0;
        }

    private:
        std::optional<Reservation> tryReserveImpl(std::size_t bytes, bool countsRequest) noexcept
        {
            if (m_maxBytes == 0)
            {
                // Budget disabled: admit unconditionally, still count admitted requests.
                if (countsRequest)
                {
                    m_inFlightCount.fetch_add(1, std::memory_order_relaxed);
                }
                return Reservation {this, 0, countsRequest};
            }

            std::size_t current = m_availableBytes.load(std::memory_order_relaxed);
            do
            {
                if (bytes > current)
                {
                    // Counted here and only here, and only for admissions: this is the shed
                    // decision the transport turns into a 503. An uncounted (auxiliary)
                    // reservation failing is not a shed -- the admitted request is answered by
                    // its caller -- and neither is a denied Reservation::grow(). Touched only
                    // on the rejection path, so admissions stay at their current cost.
                    if (countsRequest)
                    {
                        m_rejectedTotal.fetch_add(1, std::memory_order_relaxed);
                    }
                    return std::nullopt; // would exceed the budget
                }
            } while (!m_availableBytes.compare_exchange_weak(
                current, current - bytes, std::memory_order_acq_rel, std::memory_order_relaxed));

            if (countsRequest)
            {
                m_inFlightCount.fetch_add(1, std::memory_order_relaxed);
            }
            return Reservation {this, bytes, countsRequest};
        }

        void release(std::size_t bytes, bool countsRequest) noexcept
        {
            if (bytes != 0)
            {
                m_availableBytes.fetch_add(bytes, std::memory_order_acq_rel);
            }
            if (countsRequest)
            {
                m_inFlightCount.fetch_sub(1, std::memory_order_relaxed);
            }
        }

        const std::size_t m_maxBytes;              ///< 0 => budget disabled.
        std::atomic<std::size_t> m_availableBytes; ///< Remaining bytes.
        std::atomic<std::size_t> m_inFlightCount {0};
        std::atomic<std::uint64_t> m_rejectedTotal {0}; ///< Admissions refused by tryReserve().
    };

} // namespace remoted::http

#endif // _REMOTED_HTTP_IN_FLIGHT_BUDGET_HPP
