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

#ifndef _TASK_MANAGER_UPGRADE_HTTP_WPK_REPOSITORY_HPP
#define _TASK_MANAGER_UPGRADE_HTTP_WPK_REPOSITORY_HPP

#include "iWpkRepository.hpp"

#include <chrono>
#include <string>

namespace task_manager::upgrade
{
    /**
     * @brief A WPK-repository client built on shared_modules/http-request.
     *
     * WHY THIS LIBRARY, given the retired module used something else. It used wurl_http_get() and
     * wurl_request() from shared/src/url.c -- libwazuh, which this shared object must not link, so
     * some replacement was required either way. http-request is the tree's existing C++ HTTP client
     * (vulnerability_scanner and indexer_connector both use it), it pins the same C++17, and it
     * takes libcurl from the same `wazuhext` this module already links. Reusing it beats a second
     * hand-rolled client.
     *
     * THE ONE THING THAT HAD TO BE HANDLED. urlRequest.hpp probes a list of well-known CA bundle
     * paths and, if none exists, calls setOptionLong(OPT_VERIFYPEER, 0L) -- it fails OPEN, where
     * wurl_* failed closed. That would be a downgrade, and on the worst possible path: the SHA-1 a
     * WPK is checked against comes from the `versions` file fetched over the SAME channel, so an
     * unverified channel lets a man in the middle serve a matched (package, digest) pair and the
     * integrity check confirms his work rather than ours.
     *
     * So this class NEVER lets that branch be reached. It resolves the CA bundle itself, once, with
     * os_find_ca_bundle(), and passes it on every request through SecureCommunication's
     * CA_ROOT_CERTIFICATE -- which makes `m_certificate` non-empty and the fail-open branch dead
     * code. If no bundle exists on the host, requests are refused here rather than sent
     * unverified. Nothing in the library is modified, so vulnerability_scanner and
     * indexer_connector are unaffected.
     *
     * TWO COSTS WORTH KNOWING. First, cURLHandlerCache is a process-wide singleton holding at most
     * QUEUE_MAX_SIZE (5) handlers keyed only by (thread id, handler type), shared with those two
     * modules -- so a large upgrade worker pool would evict their handlers and cost them connection
     * reuse. That is why upgrade_workers defaults to 2 rather than to the core count. Second, the
     * library collapses every transport failure into responseCode -1 plus an English curl string;
     * that blocked it for the UDS consumer calls, which must tell "could not connect" from "died
     * mid-transfer", but it does not matter here, where an unreachable repository and a failed
     * transfer are the same operator problem and the same UpgradeError.
     *
     * THREAD SAFETY: safe to share. HTTPRequest is a singleton that caches a curl handle PER
     * THREAD, so one instance of this class serves the whole worker pool.
     */
    class HttpWpkRepository final : public IWpkRepository
    {
    public:
        struct Options
        {
            /// @brief Whole-transfer deadline for a `versions` GET. Small: a few hundred bytes.
            std::chrono::milliseconds versionsTimeout {20000};
            /// @brief Whole-transfer deadline for one WPK. Large: 50-100 MB over the internet.
            std::chrono::milliseconds downloadTimeout {45000};
            /**
             * @brief CA bundle to verify the repository against. Empty probes the well-known paths.
             *
             * Whatever the outcome, verification is never turned off; an unresolvable bundle makes
             * every request fail here instead.
             */
            std::string caBundlePath;
        };

        HttpWpkRepository();
        explicit HttpWpkRepository(Options options);
        ~HttpWpkRepository() override = default;

        HttpWpkRepository(const HttpWpkRepository&) = delete;
        HttpWpkRepository& operator=(const HttpWpkRepository&) = delete;

        RepoResult fetchVersions(const std::string& url, std::string& body) override;
        RepoResult download(const std::string& url, const std::string& destPath, const StopToken& stop) override;

        /**
         * @brief Cut every in-flight and future transfer short.
         *
         * Separate from the StopToken because of how the library takes its cancellation flag: a
         * cURLMultiHandler binds the `shouldRun` reference AT CONSTRUCTION and the handler cache
         * then reuses it for that (thread, type) pair without ever rebinding. A per-call flag would
         * therefore be read by later requests -- from other modules too -- long after it had gone
         * out of scope. The flag this flips is a function-local static with process lifetime, which
         * is the only shape that is safe to hand that cache.
         */
        void requestStop() override;

        /**
         * @brief Whether a CA bundle was located.
         *
         * False means every request will be refused. Reported once at start-up rather than
         * discovered per request -- and never used to relax verification.
         */
        bool hasCaBundle() const;

    private:
        Options m_options;
        std::string m_caBundle;
    };
} // namespace task_manager::upgrade

#endif // _TASK_MANAGER_UPGRADE_HTTP_WPK_REPOSITORY_HPP
