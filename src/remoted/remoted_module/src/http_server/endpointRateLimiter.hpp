/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * September 14, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_HTTP_ENDPOINT_RATE_LIMITER_HPP
#define _REMOTED_HTTP_ENDPOINT_RATE_LIMITER_HPP

/**
 * @file endpointRateLimiter.hpp
 * @brief Token bucket for one endpoint as a whole: a ceiling on how fast a route may be served,
 *        whoever is asking.
 *
 * It exists for the two routes no credential can gate. `POST /enroll` cannot be gated: an enrolling
 * agent has no client.keys entry yet, so the bearer scheme has nothing to verify it against.
 * `GET /cacerts` cannot either: a caller fetching the trust anchor does not have one yet by
 * definition. Every other route is already bounded by what the presented agent key permits.
 *
 * What it bounds is the WORK BEHIND the route, not the transport. The in-flight byte budget
 * (inFlightBudget.hpp) and max_parallel_connections already bound memory server-wide, and they shed
 * with a 503 because the server ran out of a shared resource. This bounds the rate at which a route
 * may spend a downstream service -- for `/enroll`, an authd round trip and, on a worker, a cluster
 * round trip to the master -- and refuses the excess with a 429 and a Retry-After.
 *
 * The bucket is per ENDPOINT, not per caller: one counter for the route, so the limit is a property
 * of what the manager is willing to serve rather than of who is asking. That makes it uniform and
 * free of per-client state -- no table, no eviction, nothing that grows with the number of peers --
 * and it means the limit is a shared budget: a single noisy client can spend the whole route's
 * allowance, and a legitimate fleet-wide burst is paced by the same ceiling. Sizing it is therefore
 * a fleet-level decision (`remote.https.<endpoint>_rate_limit`), not a per-agent one.
 */

#include <chrono>
#include <cstdint>
#include <mutex>

namespace remoted::http
{

    /**
     * @brief One endpoint's token bucket. Thread-safe; one instance per route.
     *
     * Deliberately NOT shared between routes: /enroll and /cacerts cost very different things, so
     * they carry different rates, and separate instances also keep one route's traffic off the
     * other's mutex.
     */
    class EndpointRateLimiter final
    {
    public:
        /**
         * @brief Resolved limiter settings.
         *
         * A rate of 0 (or less) disables the limiter entirely: allow() then admits everything
         * without taking the lock, which is what makes "no limit" free rather than merely
         * permissive.
         */
        struct Settings
        {
            double ratePerSecond {0.0}; ///< Sustained requests/second for the whole route. <=0 -> disabled.
            double burst {0.0};         ///< Bucket capacity: requests servable back to back before the
                                        ///< rate paces them. <=0 -> the same value as the rate.
        };

        /// What the facade publishes as pull metrics. A snapshot, not live references.
        struct Diagnostics
        {
            double limitPerSecond {0.0};     ///< The configured ceiling (0 when disabled).
            double burst {0.0};              ///< The configured bucket capacity.
            double available {0.0};          ///< Tokens left right now: the route's remaining headroom.
            std::uint64_t rejectedTotal {0}; ///< Requests refused because the bucket was empty.
        };

        explicit EndpointRateLimiter(Settings settings);

        /**
         * @brief Charge one request to the endpoint's bucket.
         *
         * @return true when the request may proceed, false when it must be refused.
         */
        bool allow();

        /// Whether any accounting happens at all (a rate of 0 means every allow() is an
        /// unconditional, lock-free true).
        bool enabled() const noexcept
        {
            return m_enabled;
        }

        /// Seconds to advertise in `Retry-After` on a refusal: how long one token takes to refill,
        /// rounded up, never below 1 (the header's resolution is whole seconds).
        unsigned retryAfterSeconds() const noexcept
        {
            return m_retryAfterSeconds;
        }

        /// Reads the bucket WITHOUT charging it, so a metrics scrape never consumes an agent's
        /// allowance.
        Diagnostics diagnostics() const;

    private:
        using Clock = std::chrono::steady_clock;

        /// Tokens the bucket holds at @p now, saturating at the burst. Caller holds the mutex.
        double refilledAt(Clock::time_point now) const;

        const bool m_enabled;
        const double m_ratePerSecond;
        const double m_burst;
        const unsigned m_retryAfterSeconds;

        mutable std::mutex m_mutex;
        double m_tokens;
        Clock::time_point m_last {};
        std::uint64_t m_rejectedTotal {0};
    };

} // namespace remoted::http

#endif // _REMOTED_HTTP_ENDPOINT_RATE_LIMITER_HPP
