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

#include "versionsCache.hpp"

namespace task_manager::upgrade
{
    VersionsCache::VersionsCache(IWpkRepository& repository, const std::chrono::seconds ttl)
        : m_repository {repository}
        , m_ttl {ttl}
    {
    }

    std::shared_ptr<std::mutex> VersionsCache::lockFor(const std::string& url)
    {
        std::lock_guard lock {m_stateMutex};

        auto& entry {m_urlLocks[url]};
        if (!entry)
        {
            entry = std::make_shared<std::mutex>();
        }

        // Never erased, for the same reason WpkCache's path locks are not: the key space is the
        // handful of repository paths one manager ever asks about.
        return entry;
    }

    VersionsCache::Result VersionsCache::get(const std::string& versionsUrl)
    {
        // Checked before taking the per-URL lock so a warm entry never queues behind a cold fetch
        // for the same URL -- which is the whole steady state.
        {
            std::lock_guard lock {m_stateMutex};
            if (const auto cached {m_cache.find(versionsUrl)};
                cached != m_cache.end() && std::chrono::steady_clock::now() < cached->second.expiresAt)
            {
                ++m_hits;
                return {UpgradeError::Success, cached->second.entries};
            }
        }

        const auto urlLock {lockFor(versionsUrl)};
        std::lock_guard held {*urlLock};

        // Re-checked under the lock: while we queued, the holder may have populated it. This is what
        // turns a cold 500-agent batch into ONE request instead of 500 concurrent ones.
        {
            std::lock_guard lock {m_stateMutex};
            if (const auto cached {m_cache.find(versionsUrl)};
                cached != m_cache.end() && std::chrono::steady_clock::now() < cached->second.expiresAt)
            {
                ++m_hits;
                return {UpgradeError::Success, cached->second.entries};
            }
        }

        std::string body;
        const auto fetched {m_repository.fetchVersions(versionsUrl, body)};

        {
            std::lock_guard lock {m_stateMutex};
            ++m_fetches;
        }

        if (!fetched.ok)
        {
            // Deliberately not cached -- see the header.
            return {UpgradeError::UrlNotFound, {}};
        }

        auto entries {parseVersionsFile(body)};
        if (entries.empty())
        {
            // A 2xx with nothing usable in it. Same operator problem as a 404, and treating it as a
            // successful empty list would cache "no version exists" and fail every agent for the TTL.
            return {UpgradeError::UrlNotFound, {}};
        }

        Result result {UpgradeError::Success, std::move(entries)};

        {
            std::lock_guard lock {m_stateMutex};
            m_cache[versionsUrl] = Entry {std::chrono::steady_clock::now() + m_ttl, result.entries};
        }

        return result;
    }

    std::size_t VersionsCache::fetchCount() const
    {
        std::lock_guard lock {m_stateMutex};
        return m_fetches;
    }

    std::size_t VersionsCache::hitCount() const
    {
        std::lock_guard lock {m_stateMutex};
        return m_hits;
    }
} // namespace task_manager::upgrade
