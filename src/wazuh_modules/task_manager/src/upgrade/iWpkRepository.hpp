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

#ifndef _TASK_MANAGER_UPGRADE_I_WPK_REPOSITORY_HPP
#define _TASK_MANAGER_UPGRADE_I_WPK_REPOSITORY_HPP

#include "handlers/iHandler.hpp"

#include <string>

namespace task_manager::upgrade
{
    /**
     * @brief Result of one repository call.
     *
     * The libcurl code is kept apart from the HTTP status deliberately, the same way
     * registry::TransportResult does: "could not reach the repository at all" and "the repository
     * answered 404" are different operator problems and map to different upgrade errors.
     */
    struct RepoResult
    {
        bool ok {false};
        int curlCode {0};
        int httpStatus {0};
        /// @brief The transfer was cut short by the StopToken rather than by a failure.
        bool aborted {false};
    };

    /**
     * @brief The outbound half of the upgrade path: fetching from a WPK repository.
     *
     * THE ONLY INTERFACE THIS SUBSYSTEM DEFINES, and it exists for exactly one reason: without it a
     * unit test reaches packages.wazuh.com. Everything else here is a concrete class with
     * constructor-injected dependencies.
     *
     * Implementations must be safe to share across the worker pool.
     */
    class IWpkRepository
    {
    public:
        virtual ~IWpkRepository() = default;

        /**
         * @brief Cut every in-flight and future transfer short, for shutdown.
         *
         * Separate from the StopToken passed to download(), because the real implementation cannot
         * use a per-call flag: the HTTP library binds its cancellation reference when it builds a
         * handler and its process-wide cache then reuses that handler without rebinding. See
         * httpWpkRepository.hpp.
         *
         * Idempotent, and not reversible for the life of the instance.
         */
        virtual void requestStop() = 0;

        /**
         * @brief GET a `versions` file into memory.
         *
         * @param url  Absolute URL, scheme included.
         * @param body Receives the response body on success; left untouched otherwise.
         */
        virtual RepoResult fetchVersions(const std::string& url, std::string& body) = 0;

        /**
         * @brief GET a WPK straight to a file.
         *
         * The implementation writes to `destPath` and nothing else -- staging, verification and the
         * atomic rename are WpkCache's job, so that a repository double in a test does not have to
         * reimplement them.
         *
         * @param stop Checked periodically during the transfer. A requested stop ends the download
         *             with `aborted` set, which the caller must NOT treat as a repository failure.
         */
        virtual RepoResult download(const std::string& url, const std::string& destPath, const StopToken& stop) = 0;
    };
} // namespace task_manager::upgrade

#endif // _TASK_MANAGER_UPGRADE_I_WPK_REPOSITORY_HPP
