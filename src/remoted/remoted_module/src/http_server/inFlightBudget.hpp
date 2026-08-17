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
#include <optional>

namespace remoted::http
{

    /**
     * @brief Global byte budget for in-flight (unprocessed) request payloads.
     *
     * The transport reserves bytes the moment a request is admitted and holds the
     * reservation for the request's whole in-flight life (queued on the worker pool
     * + running the handler + waiting on a deferred response). When the budget is
     * exhausted the transport rejects new requests with 429 instead of letting the
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
            {
                other.m_owner = nullptr;
                other.m_bytes = 0;
            }

            Reservation& operator=(Reservation&& other) noexcept
            {
                if (this != &other)
                {
                    releaseIfOwned();
                    m_owner = other.m_owner;
                    m_bytes = other.m_bytes;
                    other.m_owner = nullptr;
                    other.m_bytes = 0;
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

        private:
            friend class InFlightBudget;

            Reservation(InFlightBudget* owner, std::size_t bytes) noexcept
                : m_owner {owner}
                , m_bytes {bytes}
            {
            }

            void releaseIfOwned() noexcept
            {
                if (m_owner != nullptr)
                {
                    m_owner->release(m_bytes);
                    m_owner = nullptr;
                    m_bytes = 0;
                }
            }

            InFlightBudget* m_owner {nullptr};
            std::size_t m_bytes {0};
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
         * @brief Try to reserve @p bytes for one request.
         *
         * @return An engaged reservation on success, std::nullopt when admitting the
         *         request would exceed the budget. When the budget is disabled the
         *         call always succeeds (reserving 0 tracked bytes).
         */
        std::optional<Reservation> tryReserve(std::size_t bytes) noexcept
        {
            if (m_maxBytes == 0)
            {
                // Budget disabled: admit unconditionally, still count the request.
                m_inFlightCount.fetch_add(1, std::memory_order_relaxed);
                return Reservation {this, 0};
            }

            std::size_t current = m_availableBytes.load(std::memory_order_relaxed);
            do
            {
                if (bytes > current)
                {
                    return std::nullopt; // would exceed the budget
                }
            } while (!m_availableBytes.compare_exchange_weak(
                current, current - bytes, std::memory_order_acq_rel, std::memory_order_relaxed));

            m_inFlightCount.fetch_add(1, std::memory_order_relaxed);
            return Reservation {this, bytes};
        }

        /// @brief Remaining budget in bytes (meaningless while the budget is disabled).
        std::size_t availableBytes() const noexcept
        {
            return m_availableBytes.load(std::memory_order_relaxed);
        }

        /// @brief Number of requests currently in memory (reserved but not yet released).
        std::size_t inFlightCount() const noexcept
        {
            return m_inFlightCount.load(std::memory_order_relaxed);
        }

        /// @brief Whether the byte limit is enforced (false when constructed with 0).
        bool enabled() const noexcept
        {
            return m_maxBytes != 0;
        }

    private:
        void release(std::size_t bytes) noexcept
        {
            if (bytes != 0)
            {
                m_availableBytes.fetch_add(bytes, std::memory_order_acq_rel);
            }
            m_inFlightCount.fetch_sub(1, std::memory_order_relaxed);
        }

        const std::size_t m_maxBytes;              ///< 0 => budget disabled.
        std::atomic<std::size_t> m_availableBytes; ///< Remaining bytes.
        std::atomic<std::size_t> m_inFlightCount {0};
    };

} // namespace remoted::http

#endif // _REMOTED_HTTP_IN_FLIGHT_BUDGET_HPP
