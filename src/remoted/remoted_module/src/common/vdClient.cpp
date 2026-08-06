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

    VdClient::VdClient()
        : m_cachedOffset(0)
        , m_cacheTime(std::chrono::steady_clock::time_point::min())
        , m_cacheTtl(DEFAULT_CACHE_TTL_SECONDS)
    {
    }

    uint64_t VdClient::getOffset()
    {
        std::lock_guard<std::mutex> lock(m_mutex);

        const auto now = std::chrono::steady_clock::now();
        const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - m_cacheTime);

        if (elapsed < m_cacheTtl)
        {
            LOGFN_DEBUG2(logFn(), "Returning cached VD offset: %llu", m_cachedOffset);
            return m_cachedOffset;
        }

        const auto result = queryVdModule();
        if (result.success)
        {
            m_cachedOffset = result.offset;
            m_cacheTime = now;
            LOGFN_DEBUG2(logFn(), "Queried VD module, offset: %llu", result.offset);
            return result.offset;
        }
        else
        {
            LOGFN_DEBUG1(logFn(), "Failed to query VD module, returning 0 without caching");
            return 0;
        }
    }

    VdClient::QueryResult VdClient::queryVdModule() const
    {
        try
        {
            httplib::Client client("unix://queue/sockets/modulesd");
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
                const uint64_t offset = json.value("offset", 0);
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
