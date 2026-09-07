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

#ifndef _TASK_MANAGER_UPGRADE_WPK_CACHE_HPP
#define _TASK_MANAGER_UPGRADE_WPK_CACHE_HPP

#include "errorCodes.hpp"
#include "fileHash.hpp"
#include "iWpkRepository.hpp"

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <map>
#include <memory>
#include <mutex>
#include <string>

namespace task_manager::upgrade
{
    /**
     * @brief Makes sure a WPK is present, intact, and downloaded at most once.
     *
     * THIS IS WHERE THE BATCH WIN LIVES. The retired implementation took a process-global
     * `download_mutex` around every WPK operation, then -- for every agent in the request -- opened
     * the file, hashed all 50-100 MB of it, and downloaded it again if the digest did not match. A
     * 500-agent batch could therefore hash the same file 500 times in series. Here, the first caller
     * for a path does the work and the rest find it already done.
     *
     * THREE LAYERS, in the order they are consulted:
     *
     *  1. A per-destination-path mutex. Mutual exclusion, not a shared future, and keyed on the
     *     DESTINATION rather than the URL: two different `wpk_repo` values -- or the same one with
     *     use_http flipped -- resolve to the same file name, and two writers on one path is the one
     *     outcome that must be impossible. It also means two requests wanting different content at
     *     the same path serialise instead of interleaving, and the loser simply fails its digest.
     *  2. A stamp memo. Once a path's (size, mtime) is known to hash to a given digest, a matching
     *     stamp answers without reading the file. This is what turns the 2nd..500th caller into a
     *     stat().
     *  3. The file itself, hashed.
     *
     * DOWNLOADS ARE ALSO GLOBALLY CAPPED, separately from all of the above, because concurrent
     * batches for different platforms have different paths and would otherwise all download at once.
     *
     * Thread-safe. One instance shared by every worker.
     */
    class WpkCache
    {
    public:
        struct Options
        {
            /// @brief Directory the agents' WPKs are served from, slash-terminated.
            std::string upgradeDir {"var/upgrade/"};
            int downloadAttempts {3};
            /// @brief Backoff before retrying a failed download. Multiplied by the attempt number.
            std::chrono::milliseconds retryBackoff {1000};
            int maxConcurrentDownloads {2};
        };

        WpkCache(IWpkRepository& repository, Options options);

        struct Request
        {
            /// @brief Absolute URL of the WPK.
            std::string url;
            /// @brief Bare file name. Both delivery paths resolve it under `upgradeDir`.
            std::string fileName;
            /// @brief Expected digest, from the repository's `versions` file.
            std::string sha1;

            /**
             * @brief When the caller's batch stops being worth finishing.
             *
             * CARRIED HERE, rather than as a parameter, so the field can default to "no deadline"
             * for the unit tests without every one of them having to name a clock. Production has
             * exactly one caller (UpgradeOrchestrator::materialise) and it always sets this.
             *
             * It matters because the alternative is not a slow batch, it is a LOST one. Attempts
             * multiply: `upgrade_download_attempts` x `upgrade_download_timeout` plus linear
             * backoff is ~138 s per distinct WPK at the defaults, so a batch spanning three
             * platforms could spend over 400 s here -- past the 180 s batch deadline, and past the
             * transport's 300 s response backstop, at which point the connection is torn down and
             * the per-agent envelope this subsystem worked to produce is discarded. Honouring the
             * deadline between attempts bounds the overrun to one in-flight transfer.
             */
            std::chrono::steady_clock::time_point deadline {std::chrono::steady_clock::time_point::max()};
        };

        /**
         * @brief Ensure the WPK is on disk with the expected digest.
         *
         * @return Success, or:
         *         - WpkFileDoesNotExist  the download never produced a file (unreachable, 404 or
         *                                out of disk)
         *         - WpkSha1DoesNotMatch  it produced one whose digest is wrong -- which, unlike the
         *                                above, means something served the wrong bytes
         *         - UrlNotFound          the batch deadline expired while waiting on the repository
         *         - TaskManagerCommunication  the stop token fired; the manager is going down, so
         *                                the caller should retry rather than be told the WPK is
         *                                missing. This is the one code the Server API answers by
         *                                halving the chunk and trying again.
         */
        UpgradeError ensure(const Request& request, const StopToken& stop);

        /**
         * @brief Verify a file already on disk, used by the custom-WPK path, which downloads nothing.
         *
         * @param sha1 Receives the digest that was computed.
         */
        UpgradeError verifyLocal(const std::string& fileName, std::string& sha1);

        /// @brief Absolute path a bare WPK file name resolves to.
        std::string pathFor(const std::string& fileName) const;

        /// @brief Downloads actually performed. For metrics and for the qa suite's dedup assertion.
        std::size_t downloadCount() const;
        /// @brief Calls answered without touching the file, thanks to the stamp memo.
        std::size_t memoHitCount() const;

    private:
        struct MemoEntry
        {
            FileStamp stamp;
            std::string sha1;
        };

        std::shared_ptr<std::mutex> lockFor(const std::string& path);
        /**
         * @brief Wait for one of the global download slots.
         *
         * Bounded by BOTH the batch deadline and the stop token, and it has to be both. A wait that
         * honoured only the deadline would ignore a shutdown for up to the whole batch budget --
         * blocking UpgradeService::stop(), and with it modulesd's teardown, for three minutes -- and
         * a wait that honoured only the token would let a batch queue past the deadline it is about
         * to be judged against.
         *
         * @return false if the deadline passed, or a stop was requested, before a slot came free.
         */
        bool acquireDownloadSlot(std::chrono::steady_clock::time_point deadline, const StopToken& stop);
        void releaseDownloadSlot();
        UpgradeError fetch(const Request& request, const std::string& destPath, const StopToken& stop);

        IWpkRepository& m_repository;
        Options m_options;

        /// @brief mutable so the two counter accessors can stay const without a const_cast.
        mutable std::mutex m_stateMutex;
        std::map<std::string, std::shared_ptr<std::mutex>> m_pathLocks;
        std::map<std::string, MemoEntry> m_memo;
        std::size_t m_downloads {0};
        std::size_t m_memoHits {0};

        std::mutex m_slotMutex;
        std::condition_variable m_slotAvailable;
        int m_downloadsInFlight {0};
    };
} // namespace task_manager::upgrade

#endif // _TASK_MANAGER_UPGRADE_WPK_CACHE_HPP
