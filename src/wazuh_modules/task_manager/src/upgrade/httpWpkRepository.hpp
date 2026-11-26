/*
 * Wazuh task manager module
 * Copyright (C) Wazuh Inc.
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
#include <cstdint>
#include <string>
#include <string_view>

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
     * THE ONE THING THAT HAD TO BE HANDLED. Every request must verify the repository certificate:
     * the SHA-1 a WPK is checked against comes from the `versions` file fetched over the SAME
     * channel, so an unverified channel lets a man in the middle serve a matched (package, digest)
     * pair and the integrity check confirms his work rather than ours.
     *
     * So this class resolves the CA bundle itself, once, with os_find_ca_bundle(), and passes it
     * on every request through SecureCommunication's CA_ROOT_CERTIFICATE. If no bundle exists on
     * the host, requests are refused here. urlRequest.hpp also refuses an https request without a
     * CA, but this guarantee does not depend on it.
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
             * @brief Largest WPK accepted, in bytes. A WPK is 50-100 MB; the repository may be one the
             * requester named, so what it sends is not trusted to be one.
             *
             * A larger file is removed as soon as its transfer ends, so it can neither be served nor
             * pile up in `var/upgrade`. The transfer itself is bounded only by downloadTimeout: the
             * HTTP client enforces its response limit on bodies it keeps in memory, not on those it
             * writes to a file.
             */
            std::uintmax_t maxWpkSize {512ULL * 1024 * 1024};
            /**
             * @brief CA bundle to verify the repository against. Empty probes the well-known paths.
             *
             * Whatever the outcome, verification is never turned off; an unresolvable bundle makes
             * every request fail here instead.
             */
            std::string caBundlePath;
            /**
             * @brief The User-Agent sent on every request. Build it with userAgentFor().
             *
             * Never empty: with no CURLOPT_USERAGENT libcurl sends no header at all, and a CDN
             * whose WAF runs the AWS core rule set (NoUserAgent_HEADER) answers that with 403.
             */
            std::string userAgent {"wazuh-manager"};
        };

        /**
         * @brief The User-Agent for a manager of the given version: "wazuh-manager/5.0.0".
         *
         * @param managerVersion __wazuh_version as the shim hands it, e.g. "v5.0.0". The leading
         *                       `v` is dropped; an empty version yields the bare product name.
         */
        static std::string userAgentFor(std::string_view managerVersion);

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
