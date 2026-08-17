/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * July 25, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_DOWNSTREAM_ASIO_UDS_HTTP_CLIENT_HPP
#define _REMOTED_DOWNSTREAM_ASIO_UDS_HTTP_CLIENT_HPP

#include "IDownstreamClient.hpp"
#include "downstreamConfig.hpp"

#include <memory>

namespace remoted::downstream
{

    /**
     * @brief Async HTTP/1.1-over-UDS client (standalone Asio + llhttp), behind IDownstreamClient.
     *
     * Owns its own io_context and worker thread(s) -- RESTinio keeps its loop private, so the client
     * cannot share it. Each request connects fresh (connect-per-request), writes the head + body
     * (zero-copy from the caller's buffer), drops bodyKeepAlive on write-complete, then reads and
     * parses the response with llhttp. Each phase has its own deadline and its own error value
     * (DownstreamError::ConnectTimeout / WriteTimeout / ResponseTimeout), so a log line can name
     * the tunable that governs whichever one elapsed.
     * All Asio/llhttp types are hidden in the .cpp via PImpl.
     */
    class AsioUdsHttpClient final : public IDownstreamClient
    {
    public:
        explicit AsioUdsHttpClient(DownstreamConfig config);
        ~AsioUdsHttpClient() override;

        AsioUdsHttpClient(const AsioUdsHttpClient&) = delete;
        AsioUdsHttpClient& operator=(const AsioUdsHttpClient&) = delete;

        /// @brief Launch the io_context worker thread(s). Call once before sendAsync.
        void start();

        /// @brief Stop the io_context and join the thread(s). Safe if never started; idempotent.
        void stop() noexcept;

        void sendAsync(DownstreamRequest req,
                       std::shared_ptr<const void> bodyKeepAlive,
                       DownstreamCallback onComplete) override;

    private:
        struct Impl;
        std::unique_ptr<Impl> m_impl;
    };

} // namespace remoted::downstream

#endif // _REMOTED_DOWNSTREAM_ASIO_UDS_HTTP_CLIENT_HPP
