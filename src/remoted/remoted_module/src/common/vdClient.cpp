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

        constexpr uint64_t DEFAULT_CACHE_TTL_SECONDS = 30;
    } // namespace

    VdClient::VdClient(std::string socketPath)
        : m_socketPath(std::move(socketPath))
        , m_cachedOffset(0)
        , m_hasValue(false)
        , m_cacheTime(std::chrono::steady_clock::time_point::min())
        , m_cacheTtl(DEFAULT_CACHE_TTL_SECONDS)
    {
    }

    uint64_t VdClient::getOffset()
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        const auto now = std::chrono::steady_clock::now();
        const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - m_cacheTime);

        if (m_hasValue && elapsed < m_cacheTtl)
        {
            LOGFN_DEBUG2(logFn(), "Returning cached VD offset: %llu", m_cachedOffset);
            return m_cachedOffset;
        }

        const auto result = queryVdModule();
        if (result.success)
        {
            m_cachedOffset = result.offset;
            m_hasValue = true;
            m_cacheTime = now;
            LOGFN_DEBUG2(logFn(), "Queried VD module, offset: %llu", result.offset);
            return result.offset;
        }
        else if (m_hasValue)
        {
            // Keep serving the last known-good offset — a transient failure right after the
            // cache expires shouldn't make this node suddenly report offset 0 to every agent.
            // Don't refresh m_cacheTime, so the next call retries the query immediately.
            LOGFN_DEBUG1(logFn(), "Failed to query VD module, returning last known offset: %llu", m_cachedOffset);
            return m_cachedOffset;
        }
        else
        {
            LOGFN_DEBUG1(logFn(), "Failed to query VD module, no prior value available, returning 0");
            return 0;
        }
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
