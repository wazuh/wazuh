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

#include <cstdio>
#include <thread>
#include <utility>

namespace
{
    /// @brief Subdirectory of upgradeDir that partial downloads land in, slash-terminated.
    constexpr const char* STAGING_DIR {".staging/"};

    bool isDirectory(const std::string& path)
    {
        struct stat info
        {
        };
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

    void WpkCache::acquireDownloadSlot()
    {
        std::unique_lock lock {m_slotMutex};
        m_slotAvailable.wait(lock, [this] { return m_downloadsInFlight < m_options.maxConcurrentDownloads; });
        ++m_downloadsInFlight;
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

        acquireDownloadSlot();
        UpgradeError result {UpgradeError::WpkFileDoesNotExist};

        for (int attempt = 1; attempt <= m_options.downloadAttempts; ++attempt)
        {
            if (stop.stopRequested())
            {
                break;
            }

            const auto fetched {m_repository.download(request.url, stagingPath, stop)};

            {
                std::lock_guard lock {m_stateMutex};
                ++m_downloads;
            }

            if (fetched.aborted)
            {
                break; // Shutting down. Not a repository failure, and not worth another attempt.
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
                // the module's only thread and could not be cut short by a shutdown.
                const auto delay {m_options.retryBackoff * attempt};
                const auto deadline {std::chrono::steady_clock::now() + delay};
                while (std::chrono::steady_clock::now() < deadline && !stop.stopRequested())
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
