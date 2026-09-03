/*
 * Wazuh task manager module
 * Copyright (C) 2015, Wazuh Inc.
 * September 3, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _TASK_MANAGER_UPGRADE_VERSIONS_CACHE_HPP
#define _TASK_MANAGER_UPGRADE_VERSIONS_CACHE_HPP

#include "errorCodes.hpp"
#include "iWpkRepository.hpp"
#include "versionsFile.hpp"

#include <chrono>
#include <cstddef>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace task_manager::upgrade
{
    /**
     * @brief A short-lived cache of parsed `versions` files, keyed by URL.
     *
     * The single biggest waste in the retired implementation. It fetched the `versions` file inside
     * the per-agent loop, so a 500-agent batch made 500 identical HTTPS requests to
     * packages.wazuh.com -- each one a fresh curl handle and a fresh TLS handshake -- to obtain the
     * same few hundred bytes. Over a WAN that alone accounted for minutes of the request.
     *
     * Two mechanisms, and both are needed:
     *
     *  - A TTL, so a repository that publishes a new release is picked up without a restart while
     *    the common case costs nothing.
     *  - A per-URL lock, so the 500 agents of a COLD batch make one request between them rather
     *    than 500 concurrent ones. A TTL alone would not help there: none of them would have
     *    populated the entry yet.
     *
     * Thread-safe. One instance shared by every worker.
     */
    class VersionsCache
    {
    public:
        VersionsCache(IWpkRepository& repository, std::chrono::seconds ttl);

        struct Result
        {
            UpgradeError error {UpgradeError::Success};
            std::vector<VersionEntry> entries;
        };

        /**
         * @brief Parsed contents of a repository's `versions` file.
         *
         * @return Success with the entries, or UrlNotFound -- which covers every way the repository
         *         failed to answer usefully, because from the operator's side "unreachable",
         *         "404" and "served an empty file" are the same problem: check the URL.
         *
         * A failure is NOT cached. Caching it would keep a fleet-wide upgrade broken for the whole
         * TTL after a transient blip, and the retry cost is one HTTP request.
         */
        Result get(const std::string& versionsUrl);

        /// @brief Requests actually made to the repository. For metrics and the qa dedup assertion.
        std::size_t fetchCount() const;
        /// @brief Calls answered from the cache.
        std::size_t hitCount() const;

    private:
        struct Entry
        {
            std::chrono::steady_clock::time_point expiresAt;
            std::vector<VersionEntry> entries;
        };

        std::shared_ptr<std::mutex> lockFor(const std::string& url);

        IWpkRepository& m_repository;
        std::chrono::seconds m_ttl;

        mutable std::mutex m_stateMutex;
        std::map<std::string, Entry> m_cache;
        std::map<std::string, std::shared_ptr<std::mutex>> m_urlLocks;
        std::size_t m_fetches {0};
        std::size_t m_hits {0};
    };
} // namespace task_manager::upgrade

#endif // _TASK_MANAGER_UPGRADE_VERSIONS_CACHE_HPP
