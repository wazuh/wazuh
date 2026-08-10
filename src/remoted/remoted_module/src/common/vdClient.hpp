/*
 * Wazuh remoted module - VD Client
 * Copyright (C) 2015, Wazuh Inc.
 * August 6, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef VD_CLIENT_HPP
#define VD_CLIENT_HPP

#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>

namespace remoted::common
{
    /**
     * @brief Client for querying VD module offset with caching.
     *
     * Implements caching with TTL to avoid excessive queries to VD module.
     *
     * The network call to VD never runs while holding the internal lock: getOffset() only takes
     * it to read/write the small cached-state fields, and releases it before the blocking UDS
     * round trip. A single-flight flag (m_refreshInProgress) ensures only one caller actually
     * queries VD when the cache is stale -- every other concurrent caller (e.g. other agents'
     * /control notify requests arriving at the same time) immediately gets the current
     * best-known value instead of queuing up behind the in-flight query. This matters because
     * getOffset() sits on the hot path of every agent's /control notify: without it, a slow or
     * hung VD module would serialize the whole node's control-plane throughput down to roughly
     * one request per query latency, for as long as the outage lasts.
     */
    class VdClient
    {
    public:
        /// How long a successfully obtained offset is served before the next getOffset() call
        /// re-queries VD. Milliseconds (rather than seconds) purely so tests can pass short
        /// values without truncating to zero; production always uses the default, in whole
        /// seconds.
        static constexpr std::chrono::milliseconds DEFAULT_CACHE_TTL {30000};

        /// How long a failed query blocks further attempts. Deliberately much shorter than
        /// DEFAULT_CACHE_TTL: a sustained VD outage should still recover quickly once VD comes
        /// back, but without this, every single getOffset() call during the outage would retry
        /// the query -- hammering VD and, before the single-flight mechanism, serializing every
        /// caller behind it.
        static constexpr std::chrono::milliseconds DEFAULT_FAILURE_RETRY_INTERVAL {5000};

        /**
         * @param socketPath VD module UDS endpoint, as a raw filesystem path (e.g.
         * "/queue/sockets/modulesd") -- NOT a "unix://" URI; httplib::Client's single-string
         * constructor only parses http(s) URLs, so the path is passed as-is together with
         * set_address_family(AF_UNIX). Defaults to the real modulesd socket; overridable so
         * tests can point this at a fake server instead.
         * @param cacheTtl See DEFAULT_CACHE_TTL. Overridable so tests can use a short/instant
         * value instead of waiting out the real default.
         * @param failureRetryInterval See DEFAULT_FAILURE_RETRY_INTERVAL. Same testability
         * rationale as cacheTtl.
         */
        explicit VdClient(std::string socketPath = "/queue/sockets/modulesd",
                          std::chrono::milliseconds cacheTtl = DEFAULT_CACHE_TTL,
                          std::chrono::milliseconds failureRetryInterval = DEFAULT_FAILURE_RETRY_INTERVAL);
        ~VdClient() = default;

        /**
         * @brief Get the current VD feed offset.
         *
         * Returns the cached value if still valid, otherwise triggers (or piggybacks on an
         * already in-flight) refresh from the VD module. On a failed refresh, falls back to the
         * last successfully obtained value (stale-but-known) instead of discarding it; returns 0
         * only if no value has ever been obtained. A failed refresh is retried at most once per
         * failureRetryInterval, rather than on every single call, so a sustained VD outage
         * doesn't turn every caller into a fresh query attempt.
         *
         * @return Current (or last known) VD feed offset, or 0 if never obtained.
         */
        uint64_t getOffset();

    private:
        struct QueryResult
        {
            bool success;
            uint64_t offset;
        };

        QueryResult queryVdModule() const;

        std::string m_socketPath;
        mutable std::mutex m_mutex;
        uint64_t m_cachedOffset;
        bool m_hasValue;
        bool m_hasAttempted;
        bool m_lastAttemptFailed;
        bool m_refreshInProgress;
        std::chrono::steady_clock::time_point m_cacheTime;
        std::chrono::milliseconds m_cacheTtl;
        std::chrono::milliseconds m_failureRetryInterval;
    };

} // namespace remoted::common

#endif // VD_CLIENT_HPP
