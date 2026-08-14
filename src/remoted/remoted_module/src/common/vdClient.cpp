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

#include "vdClient.hpp"
#include "json.hpp"
#include "loggerHelper.h"
#include <httplib.h>

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
    } // namespace

    VdClient::VdClient(std::string socketPath,
                       std::chrono::milliseconds cacheTtl,
                       std::chrono::milliseconds failureRetryInterval)
        : m_socketPath(std::move(socketPath))
        , m_cachedOffset(0)
        , m_hasValue(false)
        , m_hasAttempted(false)
        , m_lastAttemptFailed(false)
        , m_refreshInProgress(false)
        , m_cacheTime(std::chrono::steady_clock::time_point::min())
        , m_cacheTtl(cacheTtl)
        , m_failureRetryInterval(failureRetryInterval)
    {
    }

    uint64_t VdClient::getOffset()
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
                return m_hasValue ? m_cachedOffset : 0;
            }

            // The cache needs a refresh. If another thread is already querying VD, don't queue
            // up behind it -- just serve the best value available right now. Only the thread
            // that wins this flag actually touches the network below.
            if (m_refreshInProgress)
            {
                LOGFN_DEBUG2(logFn(), "VD offset refresh already in progress, returning last known value");
                return m_hasValue ? m_cachedOffset : 0;
            }
            m_refreshInProgress = true;
        }

        // m_mutex is intentionally released here: the UDS round trip (up to ~1s, see
        // queryVdModule()) must never run while held, or every concurrent caller of getOffset()
        // -- i.e. every agent's /control notify on this node -- would serialize behind it.
        const auto result = queryVdModule();

        std::lock_guard<std::mutex> lock(m_mutex);
        m_refreshInProgress = false;
        m_hasAttempted = true;

        if (result.success)
        {
            m_cachedOffset = result.offset;
            m_hasValue = true;
            m_lastAttemptFailed = false;
            m_cacheTime = std::chrono::steady_clock::now();
            LOGFN_DEBUG2(logFn(), "Queried VD module, offset: %llu", result.offset);
            return result.offset;
        }

        // Keep serving the last known-good offset — a transient failure shouldn't make this node
        // suddenly report offset 0 to every agent. m_cacheTime is refreshed here (unlike before)
        // so the next attempt is gated by m_failureRetryInterval instead of firing on every call.
        m_lastAttemptFailed = true;
        m_cacheTime = std::chrono::steady_clock::now();
        LOGFN_DEBUG1(logFn(), "Failed to query VD module, returning last known offset: %llu", m_cachedOffset);
        return m_hasValue ? m_cachedOffset : 0;
    }

    VdClient::QueryResult VdClient::queryVdModule() const
    {
        try
        {
            // httplib::Client's single-string constructor only parses "http(s)://host[:port]"
            // URLs -- a raw filesystem path (with embedded '/') does not match its scheme/host
            // regex and silently falls back to treating the whole string as a DNS hostname.
            // set_address_family(AF_UNIX) is what actually tells httplib to treat the path as a
            // Unix domain socket.
            httplib::Client client(m_socketPath);
            client.set_address_family(AF_UNIX);
            client.set_read_timeout(1, 0);
            client.set_write_timeout(1, 0);

            auto res = client.Get("/vulnerability-detector/offset");
            if (!res || res->status != 200)
            {
                LOGFN_DEBUG1(logFn(), "Failed to query VD offset: status=%d", res ? res->status : 0);
                return {false, 0};
            }

            try
            {
                const auto json = nlohmann::json::parse(res->body);
                const uint64_t offset = json.value<uint64_t>("offset", 0);
                return {true, offset};
            }
            catch (const std::exception& e)
            {
                LOGFN_DEBUG1(logFn(), "Failed to parse VD offset response: %s", e.what());
                return {false, 0};
            }
        }
        catch (const std::exception& e)
        {
            LOGFN_DEBUG1(logFn(), "Failed to connect to VD module: %s", e.what());
            return {false, 0};
        }
    }

} // namespace remoted::common
