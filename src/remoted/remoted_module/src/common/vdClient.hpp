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
     */
    class VdClient
    {
    public:
        /**
         * @param socketUri VD module UDS endpoint, as an httplib URI (e.g.
         * "unix://queue/sockets/modulesd"). Defaults to the real modulesd socket; overridable so
         * tests can point this at a fake server instead.
         */
        explicit VdClient(std::string socketUri = "unix://queue/sockets/modulesd");
        ~VdClient() = default;

        /**
         * @brief Get the current VD feed offset.
         *
         * Returns the cached value if still valid, otherwise queries the VD module.
         * On a failed refresh, falls back to the last successfully obtained value
         * (stale-but-known) instead of discarding it; returns 0 only if no value
         * has ever been obtained.
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

        std::string m_socketUri;
        mutable std::mutex m_mutex;
        uint64_t m_cachedOffset;
        bool m_hasValue;
        std::chrono::steady_clock::time_point m_cacheTime;
        std::chrono::seconds m_cacheTtl;
    };

} // namespace remoted::common

#endif // VD_CLIENT_HPP
