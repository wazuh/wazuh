/*
 * Wazuh task manager module
 * Copyright (C) 2015, Wazuh Inc.
 * September 1, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _TASK_MANAGER_HANDLERS_UDS_HTTP_CLIENT_HPP
#define _TASK_MANAGER_HANDLERS_UDS_HTTP_CLIENT_HPP

#include "registry/httpResultMapper.hpp"

#include <chrono>
#include <cstddef>
#include <memory>
#include <string>

namespace task_manager::handlers
{
    /**
     * @brief A minimal HTTP-over-UDS POST client, one per worker.
     *
     * WHY NOT ONE OF THE TWO EXISTING CLIENTS.
     *
     * shared/include/http_op.h (uhttp_*) does exactly this and reports the libcurl code, but it
     * lives in libwazuh, which this shared object must not link.
     *
     * shared_modules/http-request's UNIXSocketRequest is linkable, and was the first choice, but it
     * collapses every transport failure into responseCode = -1 plus a human-readable curl string
     * (curlSingleHandler.hpp throws CurlException(curl_easy_strerror(...), NOT_USED)). This module
     * needs those apart: "could not connect" must DEFER, because the executor routinely starts
     * before its in-process consumers bind and a boot race must not spend the retry budget, while
     * a mid-transfer failure must RETRY. Recovering that distinction would mean matching on
     * libcurl's English error text. UNIXSocketRequest is also a Singleton, and a curl easy handle
     * is not thread-safe, so a shared one is the wrong shape for a worker pool regardless.
     *
     * So: a handle per worker, the libcurl code surfaced, and both deadlines set explicitly.
     *
     * NOT THREAD-SAFE. One instance per worker, never shared.
     */
    class UdsHttpClient
    {
    public:
        struct Options
        {
            std::string socketPath;
            std::chrono::milliseconds connectTimeout {2000};
            std::chrono::milliseconds requestTimeout {600000};
            /// @brief Response bytes kept. The body is only ever read for an error code, so this
            ///        is deliberately small; a truncated body is indistinguishable from an
            ///        unparseable one, and the result mapper treats both the same way.
            std::size_t maxResponseBytes {4096};
        };

        explicit UdsHttpClient(Options options);
        ~UdsHttpClient();

        UdsHttpClient(const UdsHttpClient&) = delete;
        UdsHttpClient& operator=(const UdsHttpClient&) = delete;
        UdsHttpClient(UdsHttpClient&&) noexcept;
        UdsHttpClient& operator=(UdsHttpClient&&) noexcept;

        /**
         * @brief POST a JSON body to `path` on the configured socket.
         *
         * @return Always fully populated -- the struct is zeroed before every call, which is what
         *         makes the mapper's "request was never sent" sentinel (-1 with an untouched
         *         result) safe to distinguish from a real libcurl code.
         */
        registry::TransportResult post(const std::string& path, const std::string& body);

    private:
        struct Impl;
        std::unique_ptr<Impl> m_impl;
    };
} // namespace task_manager::handlers

#endif // _TASK_MANAGER_HANDLERS_UDS_HTTP_CLIENT_HPP
