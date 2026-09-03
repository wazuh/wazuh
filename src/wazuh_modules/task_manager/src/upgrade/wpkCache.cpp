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

#include "wpkCache.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <thread>
#include <utility>

namespace
{
    /// @brief Subdirectory of upgradeDir that partial downloads land in, slash-terminated.
    constexpr const char* STAGING_DIR {".staging/"};

    bool isDirectory(const std::string& path)
    {
        struct stat info {};
        return ::stat(path.c_str(), &info) == 0 && S_ISDIR(info.st_mode);
    }
} // namespace

namespace task_manager::upgrade
{
    WpkCache::WpkCache(IWpkRepository& repository, Options options)
        : m_repository {repository}
        , m_options {std::move(options)}
    {
        if (!m_options.upgradeDir.empty() && m_options.upgradeDir.back() != '/')
        {
            m_options.upgradeDir += '/';
        }

        if (m_options.downloadAttempts < 1)
        {
            m_options.downloadAttempts = 1;
        }

        if (m_options.maxConcurrentDownloads < 1)
        {
            m_options.maxConcurrentDownloads = 1;
        }
    }

    std::string WpkCache::pathFor(const std::string& fileName) const
    {
        return m_options.upgradeDir + fileName;
    }

    std::shared_ptr<std::mutex> WpkCache::lockFor(const std::string& path)
    {
        std::lock_guard lock {m_stateMutex};

        auto& entry {m_pathLocks[path]};
        if (!entry)
        {
            entry = std::make_shared<std::mutex>();
        }

        // Never erased. The set is bounded by the number of distinct WPK file names a manager ever
        // serves -- a handful per release -- so reclaiming them would cost more care than it saves
        // memory, and erasing one a waiter still holds is a use-after-free waiting to happen.
        return entry;
    }

    bool WpkCache::acquireDownloadSlot(const std::chrono::steady_clock::time_point deadline, const StopToken& stop)
    {
        // Polled in short hops rather than waited on directly, because there are three things to
        // wake for and only one of them signals this condition variable. releaseDownloadSlot()
        // notifies it; the batch deadline and the stop token do not, and a StopToken is a bare
        // atomic with nothing to notify. A slot wait is at most twice per batch and each hop is a
        // predicate check, so the cost of polling is nothing next to the 100 MB transfer it is
        // waiting for.
        constexpr auto HOP {std::chrono::milliseconds {100}};

        std::unique_lock lock {m_slotMutex};

        while (m_downloadsInFlight >= m_options.maxConcurrentDownloads)
        {
            if (stop.stopRequested() || std::chrono::steady_clock::now() >= deadline)
            {
                return false;
            }

            m_slotAvailable.wait_for(lock, HOP);
        }

        ++m_downloadsInFlight;
        return true;
    }

    void WpkCache::releaseDownloadSlot()
    {
        {
            std::lock_guard lock {m_slotMutex};
            --m_downloadsInFlight;
        }
        m_slotAvailable.notify_one();
    }

    UpgradeError WpkCache::ensure(const Request& request, const StopToken& stop)
    {
        if (request.fileName.empty() || request.sha1.empty())
        {
            return UpgradeError::WpkFileDoesNotExist;
        }

        const auto destPath {pathFor(request.fileName)};
        const auto pathLock {lockFor(destPath)};
        std::lock_guard held {*pathLock};

        // Layer 2: the stamp memo. A matching (size, mtime) answers without reading the file, which
        // is what the 2nd..Nth caller in a batch hits.
        if (const auto stamp {stampOf(destPath)}; stamp.has_value())
        {
            {
                std::lock_guard lock {m_stateMutex};
                if (const auto memo {m_memo.find(destPath)};
                    memo != m_memo.end() && memo->second.stamp == *stamp && sha1Equals(memo->second.sha1, request.sha1))
                {
                    ++m_memoHits;
                    return UpgradeError::Success;
                }
            }

            // Layer 3: hash it. Either the memo is cold (first boot with a warm disk) or the file
            // changed under us.
            if (const auto digest {sha1OfFile(destPath)}; digest.has_value())
            {
                {
                    std::lock_guard lock {m_stateMutex};
                    m_memo[destPath] = MemoEntry {*stamp, *digest};
                }

                if (sha1Equals(*digest, request.sha1))
                {
                    return UpgradeError::Success;
                }
                // Wrong content at the right path: fall through and re-download over it.
            }
        }

        return fetch(request, destPath, stop);
    }

    UpgradeError WpkCache::fetch(const Request& request, const std::string& destPath, const StopToken& stop)
    {
        const auto stagingDir {m_options.upgradeDir + STAGING_DIR};
        // 0770 to match var/upgrade/ itself; a WPK is not world-readable. EEXIST is the normal case
        // after the first download, so the outcome is checked rather than mkdir's return value.
        ::mkdir(stagingDir.c_str(), 0770);
        if (!isDirectory(stagingDir))
        {
            return UpgradeError::WpkFileDoesNotExist;
        }

        // Named for the digest, not the file: the path lock already excludes a same-path racer, and
        // this keeps two DIFFERENT expected digests for one file name from colliding while staged.
        const auto stagingPath {stagingDir + request.sha1 + ".part"};

        if (!acquireDownloadSlot(request.deadline, stop))
        {
            // Never got a slot. Shutting down is retryable (error 4, which the Server API halves the
            // chunk on); otherwise the budget expired while we were queued behind other transfers,
            // which is the same "still waiting on the repository" that materialise() reports for a
            // group it skipped.
            return stop.stopRequested() ? UpgradeError::TaskManagerCommunication : UpgradeError::UrlNotFound;
        }

        UpgradeError result {UpgradeError::WpkFileDoesNotExist};

        for (int attempt = 1; attempt <= m_options.downloadAttempts; ++attempt)
        {
            if (stop.stopRequested())
            {
                // Shutting down BEFORE a transfer started. Error 4, so the Server API halves the
                // chunk and retries -- the same answer the queue-drain path gives for the same
                // event, which is the point: a client must not be able to tell where in the module
                // its request was when the manager began stopping.
                result = UpgradeError::TaskManagerCommunication;
                break;
            }

            // Checked between attempts, which is where it can be honoured: one transfer already in
            // flight has to run out its own libcurl timeout, but starting ANOTHER one the caller has
            // given up on is what turns a slow repository into a lost response.
            if (std::chrono::steady_clock::now() >= request.deadline)
            {
                result = UpgradeError::UrlNotFound;
                break;
            }

            const auto fetched {m_repository.download(request.url, stagingPath, stop)};

            {
                std::lock_guard lock {m_stateMutex};
                ++m_downloads;
            }

            if (fetched.aborted)
            {
                // Cut short by the shutdown, mid-transfer. Same reasoning as above: retryable, not
                // "the WPK does not exist".
                result = UpgradeError::TaskManagerCommunication;
                break;
            }

            if (fetched.ok)
            {
                const auto digest {sha1OfFile(stagingPath)};
                if (digest.has_value() && sha1Equals(*digest, request.sha1))
                {
                    // Rename LAST, and only over a verified file. Downloading straight to the final
                    // path -- which the retired code did -- lets remoted serve a WPK that is still
                    // growing; its download endpoint carries explicit defensive code for exactly
                    // that, which this makes unnecessary. rename(2) within one filesystem is atomic.
                    if (::rename(stagingPath.c_str(), destPath.c_str()) == 0)
                    {
                        if (const auto stamp {stampOf(destPath)}; stamp.has_value())
                        {
                            std::lock_guard lock {m_stateMutex};
                            m_memo[destPath] = MemoEntry {*stamp, *digest};
                        }
                        result = UpgradeError::Success;
                        break;
                    }

                    result = UpgradeError::WpkFileDoesNotExist;
                    break;
                }

                // The repository answered 2xx with the wrong bytes. Retrying will not change that,
                // and it is a materially different operator problem from an unreachable repository.
                result = UpgradeError::WpkSha1DoesNotMatch;
                break;
            }

            result = UpgradeError::WpkFileDoesNotExist;

            if (attempt < m_options.downloadAttempts)
            {
                // Linear backoff, as before, but interruptible: the retired sleep(attempts) ran on
                // the module's only thread and could not be cut short by a shutdown. Bounded by the
                // batch deadline as well, so the last thing a batch does is not sleep through the
                // budget it had left.
                const auto until {
                    std::min(std::chrono::steady_clock::now() + (m_options.retryBackoff * attempt), request.deadline)};
                while (std::chrono::steady_clock::now() < until && !stop.stopRequested())
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds {50});
                }
            }
        }

        releaseDownloadSlot();

        // Never leave a partial file where a later attempt might mistake it for a complete one.
        if (result != UpgradeError::Success)
        {
            ::unlink(stagingPath.c_str());
        }

        return result;
    }

    UpgradeError WpkCache::verifyLocal(const std::string& fileName, std::string& sha1)
    {
        const auto path {pathFor(fileName)};
        const auto stamp {stampOf(path)};
        if (!stamp.has_value())
        {
            return UpgradeError::WpkFileDoesNotExist;
        }

        {
            std::lock_guard lock {m_stateMutex};
            if (const auto memo {m_memo.find(path)}; memo != m_memo.end() && memo->second.stamp == *stamp)
            {
                ++m_memoHits;
                sha1 = memo->second.sha1;
                return UpgradeError::Success;
            }
        }

        const auto digest {sha1OfFile(path)};
        if (!digest.has_value())
        {
            return UpgradeError::WpkFileDoesNotExist;
        }

        {
            std::lock_guard lock {m_stateMutex};
            m_memo[path] = MemoEntry {*stamp, *digest};
        }

        sha1 = *digest;
        return UpgradeError::Success;
    }

    std::size_t WpkCache::downloadCount() const
    {
        std::lock_guard lock {m_stateMutex};
        return m_downloads;
    }

    std::size_t WpkCache::memoHitCount() const
    {
        std::lock_guard lock {m_stateMutex};
        return m_memoHits;
    }
} // namespace task_manager::upgrade
