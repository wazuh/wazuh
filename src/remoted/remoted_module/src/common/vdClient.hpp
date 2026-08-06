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
        VdClient();
        ~VdClient() = default;

        /**
         * @brief Get the current VD feed offset.
         *
         * Returns cached value if still valid, otherwise queries VD module.
         * Only caches successful queries; communication failures return 0 without caching.
         *
         * @return Current VD feed offset, or 0 if unavailable.
         */
        uint64_t getOffset();

    private:
        struct QueryResult
        {
            bool success;
            uint64_t offset;
        };

        QueryResult queryVdModule() const;

        mutable std::mutex m_mutex;
        uint64_t m_cachedOffset;
        std::chrono::steady_clock::time_point m_cacheTime;
        std::chrono::seconds m_cacheTtl;
    };

} // namespace remoted::common

#endif // VD_CLIENT_HPP
