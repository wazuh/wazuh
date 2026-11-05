/*
 * Wazuh remoted module - VD Client
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "vdClient.hpp"
#include "common/logThrottle.hpp"
#include "downstream/blockingCall.hpp"
#include "json.hpp"
#include "loggerHelper.h"
#include <stdexcept>
#include <utility>

namespace remoted::common
{
    namespace
    {
        constexpr auto VD_CLIENT_LOGTAG {"wazuh-manager-remoted:vd-client"};

        const LogFn& logFn()
        {
            static const LogFn instance {VD_CLIENT_LOGTAG};
            return instance;
        }

        // Shared across every "VD unreachable/malformed response" message below: the offset
        // query is single-flighted (see m_refreshInProgress in getOffset()) and gated by
        // m_failureRetryInterval, so it cannot fire more than once per retry interval anyway --
        // this only protects against a burst of concurrent callers all landing on the same
        // failed attempt.
        LogThrottle& queryFailureThrottle()
        {
            static LogThrottle instance;
            return instance;
        }
    } // namespace

    remoted::downstream::DownstreamConfig VdClient::httpClientConfig()
    {
        remoted::downstream::DownstreamConfig config;
        config.connectTimeoutMs = CONNECT_TIMEOUT_MS;
        config.writeTimeoutMs = static_cast<int>(OFFSET_WRITE_TIMEOUT_SECONDS * 1000);
        config.responseTimeoutMs = static_cast<int>(OFFSET_READ_TIMEOUT_SECONDS * 1000);
        config.ioThreads = 1;
        config.maxResponseBodySize = MAX_RESPONSE_BODY_BYTES;
        return config;
    }

    VdClient::VdClient(std::shared_ptr<remoted::downstream::IDownstreamClient> httpClient,
                       std::string socketPath,
                       std::chrono::milliseconds cacheTtl,
                       std::chrono::milliseconds failureRetryInterval)
        : m_httpClient(std::move(httpClient))
        , m_socketPath(std::move(socketPath))
        , m_cachedOffset(0)
        , m_cachedEnabled(true)
        , m_hasValue(false)
        , m_hasAttempted(false)
        , m_lastAttemptFailed(false)
        , m_refreshInProgress(false)
        , m_cacheTime(std::chrono::steady_clock::time_point::min())
        , m_cacheTtl(cacheTtl)
        , m_failureRetryInterval(failureRetryInterval)
    {
        if (!m_httpClient)
        {
            throw std::invalid_argument("VdClient needs an HTTP client for VD's socket");
        }
    }

    VdClient::FeedState VdClient::getFeedState()
    {
        {
            std::lock_guard<std::mutex> lock(m_mutex);

            const auto now = std::chrono::steady_clock::now();
            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - m_cacheTime);
            const auto ttl = m_lastAttemptFailed ? m_failureRetryInterval : m_cacheTtl;

            // Deliberately gated on m_hasAttempted rather than computing "elapsed since
            // construction" from m_cacheTime's initial time_point::min(): now - time_point::min()
            // is far larger than milliseconds (or even the clock's native duration) can represent,
            // so duration_cast of it is undefined behavior -- in practice it wraps around to a
            // small/negative value, which made the very first call ever spuriously look
            // "within TTL" and return immediately without ever querying VD. m_hasAttempted sidesteps
            // that entirely: it's only true once m_cacheTime holds an actual, real timestamp.
            //
            // Also deliberately NOT gated on m_hasValue: if VD has failed every single time since
            // startup, m_hasValue stays false forever, and gating on it too would mean every
            // caller retries immediately regardless of m_lastAttemptFailed/m_failureRetryInterval
            // -- exactly the hammering behavior this gate exists to prevent.
            if (m_hasAttempted && elapsed < ttl)
            {
                LOGFN_DEBUG2(logFn(), "Returning cached VD offset: %llu", m_cachedOffset);
                return cachedState();
            }

            // The cache needs a refresh. If another thread is already querying VD, don't queue
            // up behind it -- just serve the best value available right now. Only the thread
            // that wins this flag actually touches the network below.
            if (m_refreshInProgress)
            {
                LOGFN_DEBUG2(logFn(), "VD offset refresh already in progress, returning last known value");
                return cachedState();
            }
            m_refreshInProgress = true;
        }

        // m_mutex is intentionally released here: the UDS round trip (bounded by its connect, write
        // and response deadlines, see queryVdModule()) must never run while held, or every
        // concurrent caller of getFeedState() -- i.e. every agent's /control notify on this node --
        // would serialize behind it.
        const auto result = queryVdModule();

        std::lock_guard<std::mutex> lock(m_mutex);
        m_refreshInProgress = false;
        m_hasAttempted = true;

        if (result.success)
        {
            m_cachedOffset = result.offset;
            m_cachedEnabled = result.enabled;
            m_hasValue = true;
            m_lastAttemptFailed = false;
            m_cacheTime = std::chrono::steady_clock::now();
            LOGFN_DEBUG2(
                logFn(), "Queried VD module, offset: %llu, enabled: %d", result.offset, result.enabled ? 1 : 0);
            return {result.offset, result.enabled};
        }

        // Keep serving the last known-good offset — a transient failure shouldn't make this node
        // suddenly report offset 0 to every agent. m_cacheTime is refreshed here (unlike before)
        // so the next attempt is gated by m_failureRetryInterval instead of firing on every call.
        m_lastAttemptFailed = true;
        m_cacheTime = std::chrono::steady_clock::now();
        if (const auto throttle = queryFailureThrottle().record())
        {
            LOGFN_WARN(logFn(),
                       "Failed to query VD module, returning last known offset: %llu (%llu occurrence(s) %s).",
                       m_cachedOffset,
                       throttle.total,
                       throttle.period().c_str());
        }
        return cachedState();
    }

    VdClient::FeedState VdClient::cachedState() const
    {
        // Caller holds m_mutex. No value ever obtained -> {0, enabled}: an unreachable VD is not
        // a disabled one, and the agent treats an advertised 0 as "no feed yet".
        return m_hasValue ? FeedState {m_cachedOffset, m_cachedEnabled} : FeedState {0, true};
    }

    VdClient::QueryResult VdClient::queryVdModule() const
    {
        constexpr int writeTimeoutMs = static_cast<int>(OFFSET_WRITE_TIMEOUT_SECONDS * 1000);
        constexpr int responseTimeoutMs = static_cast<int>(OFFSET_READ_TIMEOUT_SECONDS * 1000);

        remoted::downstream::DownstreamRequest request;
        request.socketPath = m_socketPath;
        request.method = remoted::http::Method::Get;
        request.path = "/vulnerability-detector/offset";
        request.writeTimeoutMs = writeTimeoutMs;
        request.responseTimeoutMs = responseTimeoutMs;

        const auto result = remoted::downstream::sendBlocking(
            *m_httpClient,
            std::move(request),
            nullptr,
            std::chrono::milliseconds {CONNECT_TIMEOUT_MS + writeTimeoutMs + responseTimeoutMs + BACKSTOP_MARGIN_MS});

        if (result.error != remoted::downstream::DownstreamError::None)
        {
            // The error class tells "VD is not running" (connect_failed) apart from "VD did not answer in
            // time" (response_timeout) and the rest.
            if (const auto throttle = queryFailureThrottle().record())
            {
                LOGFN_WARN(logFn(),
                           "Failed to query VD offset: %s (%llu occurrence(s) %s).",
                           remoted::downstream::toString(result.error),
                           throttle.total,
                           throttle.period().c_str());
            }
            return {false, 0, true};
        }

        if (result.response.status != 200)
        {
            if (const auto throttle = queryFailureThrottle().record())
            {
                LOGFN_WARN(logFn(),
                           "Failed to query VD offset: status=%d (%llu occurrence(s) %s).",
                           result.response.status,
                           throttle.total,
                           throttle.period().c_str());
            }
            return {false, 0, true};
        }

        try
        {
            const auto json = nlohmann::json::parse(result.response.body);
            const uint64_t offset = json.value<uint64_t>("offset", 0);
            // Absent (or not a boolean) -> enabled: only an explicit `false` withdraws the
            // offset from agents.
            const auto enabledIt = json.find("enabled");
            const bool enabled = enabledIt == json.end() || !enabledIt->is_boolean() || enabledIt->get<bool>();
            return {true, offset, enabled};
        }
        catch (const std::exception& e)
        {
            if (const auto throttle = queryFailureThrottle().record())
            {
                LOGFN_WARN(logFn(),
                           "Failed to parse VD offset response: %s (%llu occurrence(s) %s).",
                           e.what(),
                           throttle.total,
                           throttle.period().c_str());
            }
            return {false, 0, true};
        }
    }

} // namespace remoted::common
