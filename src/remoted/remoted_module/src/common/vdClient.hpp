/*
 * Wazuh remoted module - VD Client
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef VD_CLIENT_HPP
#define VD_CLIENT_HPP

#include "common/installPaths.hpp"
#include "downstream/IDownstreamClient.hpp"
#include "downstream/downstreamConfig.hpp"
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
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

        /// Per-query socket deadlines for the offset request. Named rather than inlined at the call
        /// site because they are part of the budget of every request that gates on an offset: a
        /// stale cache makes getOffset() pay them synchronously before the caller's own downstream
        /// work starts (see ScanVdHandlerImpl::budgetMsFor()).
        static constexpr long OFFSET_READ_TIMEOUT_SECONDS = 1;
        static constexpr long OFFSET_WRITE_TIMEOUT_SECONDS = 1;

        /// Connect deadline of every call to VD's socket (the offset query here and the scan request in
        /// ScanVdHandlerImpl). A local socket either accepts at once or refuses at once -- a full accept
        /// backlog fails a non-blocking connect immediately -- so this only bounds the odd case.
        static constexpr int CONNECT_TIMEOUT_MS = 1000;

        /// Cap on VD's answer to either call. Both are a few bytes of JSON; anything near this is not VD.
        static constexpr std::size_t MAX_RESPONSE_BODY_BYTES = 64U * 1024U;

        /// How long a blocking call waits beyond its own deadlines before giving up on the client: the
        /// client's timers always fire first, this only bounds a client that never completes the call.
        static constexpr int BACKSTOP_MARGIN_MS = 1000;

        /**
         * @brief Configuration of the HTTP client the facade builds for VD's socket and hands to both
         * VdClient and ScanVdHandlerImpl: one I/O thread, CONNECT_TIMEOUT_MS and MAX_RESPONSE_BODY_BYTES.
         * Each call sets its own write and response deadlines; the configured ones are the offset
         * query's and only apply to a request that sets none.
         */
        static remoted::downstream::DownstreamConfig httpClientConfig();

        /**
         * @param httpClient Client for VD's socket, shared with ScanVdHandlerImpl (see httpClientConfig()).
         * Must not be null; it must stay running for as long as getOffset() can be called.
         * @param socketPath VD module UDS endpoint, as a raw filesystem path (e.g.
         * remoted::paths::kVdSocket, relative to remoted's cwd, the installation directory). Defaults to the
         * real modulesd socket; overridable so tests can point this at a fake server instead.
         * @param cacheTtl See DEFAULT_CACHE_TTL. Overridable so tests can use a short/instant
         * value instead of waiting out the real default.
         * @param failureRetryInterval See DEFAULT_FAILURE_RETRY_INTERVAL. Same testability
         * rationale as cacheTtl.
         */
        explicit VdClient(std::shared_ptr<remoted::downstream::IDownstreamClient> httpClient,
                          std::string socketPath = remoted::paths::kVdSocket,
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

        std::shared_ptr<remoted::downstream::IDownstreamClient> m_httpClient;
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
