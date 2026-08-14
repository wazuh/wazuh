/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * July 24, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_DOWNSTREAM_DEFERRED_WORK_LIMITER_HPP
#define _REMOTED_DOWNSTREAM_DEFERRED_WORK_LIMITER_HPP

#include <atomic>
#include <cstddef>
#include <optional>

namespace remoted::downstream
{

    /**
     * @brief Bounds how many requests are parked awaiting a downstream service.
     *
     * A count-based sibling of InFlightBudget (which bounds bytes): this bounds the
     * NUMBER of requests in the deferred/forwarding stage. A slot is acquired before
     * a request is forwarded downstream and held (RAII) until its reply is delivered,
     * so the server can shed load with 503 instead of parking unbounded outstanding
     * work when the downstream is slow. This is the second half of the two-phase
     * backpressure: the byte budget covers receive+send, this covers the wait.
     *
     * Lock-free (atomics). A capacity of 0 disables the limit (every acquire
     * succeeds) while still tracking the live count for observability.
     *
     * Lifetime: a Slot holds a raw pointer back to its limiter, so the limiter must
     * outlive every outstanding Slot (the facade guarantees this -- it stops the
     * downstream client, which releases parked slots, before destroying the limiter).
     */
    class DeferredWorkLimiter final
    {
    public:
        /**
         * @brief RAII slot. Movable, non-copyable, releases exactly once.
         */
        class Slot final
        {
        public:
            Slot() = default;

            ~Slot()
            {
                releaseIfOwned();
            }

            Slot(Slot&& other) noexcept
                : m_owner {other.m_owner}
            {
                other.m_owner = nullptr;
            }

            Slot& operator=(Slot&& other) noexcept
            {
                if (this != &other)
                {
                    releaseIfOwned();
                    m_owner = other.m_owner;
                    other.m_owner = nullptr;
                }
                return *this;
            }

            Slot(const Slot&) = delete;
            Slot& operator=(const Slot&) = delete;

            /// @brief True when this token holds an active slot.
            explicit operator bool() const noexcept
            {
                return m_owner != nullptr;
            }

        private:
            friend class DeferredWorkLimiter;

            explicit Slot(DeferredWorkLimiter* owner) noexcept
                : m_owner {owner}
            {
            }

            void releaseIfOwned() noexcept
            {
                if (m_owner != nullptr)
                {
                    m_owner->release();
                    m_owner = nullptr;
                }
            }

            DeferredWorkLimiter* m_owner {nullptr};
        };

        /**
         * @brief Construct the limiter.
         *
         * @param capacity Maximum concurrent deferred requests. 0 disables the limit.
         */
        explicit DeferredWorkLimiter(std::size_t capacity) noexcept
            : m_capacity {capacity}
        {
        }

        DeferredWorkLimiter(const DeferredWorkLimiter&) = delete;
        DeferredWorkLimiter& operator=(const DeferredWorkLimiter&) = delete;

        /**
         * @brief Try to acquire one slot.
         *
         * @return An engaged slot on success, std::nullopt when the limit is reached.
         *         When the limiter is disabled the call always succeeds.
         */
        std::optional<Slot> tryAcquire() noexcept
        {
            if (m_capacity == 0)
            {
                // Disabled: admit unconditionally, still count for observability.
                m_inFlight.fetch_add(1, std::memory_order_relaxed);
                return Slot {this};
            }

            std::size_t current = m_inFlight.load(std::memory_order_relaxed);
            do
            {
                if (current >= m_capacity)
                {
                    return std::nullopt; // limit reached
                }
            } while (!m_inFlight.compare_exchange_weak(
                current, current + 1, std::memory_order_acq_rel, std::memory_order_relaxed));

            return Slot {this};
        }

        /// @brief Number of deferred requests currently in flight.
        std::size_t inFlight() const noexcept
        {
            return m_inFlight.load(std::memory_order_relaxed);
        }

        /// @brief Configured maximum (0 == unlimited/disabled).
        std::size_t capacity() const noexcept
        {
            return m_capacity;
        }

        /// @brief Whether the limit is enforced (false when constructed with 0).
        bool enabled() const noexcept
        {
            return m_capacity != 0;
        }

    private:
        void release() noexcept
        {
            m_inFlight.fetch_sub(1, std::memory_order_acq_rel);
        }

        const std::size_t m_capacity;            ///< 0 => limit disabled.
        std::atomic<std::size_t> m_inFlight {0}; ///< Live count of parked deferred requests.
    };

} // namespace remoted::downstream

#endif // _REMOTED_DOWNSTREAM_DEFERRED_WORK_LIMITER_HPP
