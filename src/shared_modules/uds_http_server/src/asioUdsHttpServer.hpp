/*
 * Wazuh shared UDS HTTP server library
 * Copyright (C) 2015, Wazuh Inc.
 * July 28, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _WAZUH_ASIO_UDS_HTTP_SERVER_HPP
#define _WAZUH_ASIO_UDS_HTTP_SERVER_HPP

#include <uds_http_server/IUdsHttpServer.hpp>

#include <memory>
#include <string>

namespace wazuh::uds_http
{

    /**
     * @brief HTTP/1.1-over-Unix-domain-socket server built on standalone Asio + llhttp.
     *
     * PImpl on purpose: neither asio nor llhttp appears here, so both stay PRIVATE link
     * dependencies and the transport really is swappable at makeUdsHttpServer().
     *
     * Asynchronous end to end. A request whose response is deferred costs one socket plus one queue
     * entry, never a blocked thread -- which is the whole reason this exists instead of a
     * blocking thread-per-request server. See IUdsHttpServer for the responder and shutdown
     * contracts, which are the load-bearing parts.
     */
    class AsioUdsHttpServer final : public IUdsHttpServer
    {
    public:
        AsioUdsHttpServer();
        ~AsioUdsHttpServer() override;

        AsioUdsHttpServer(const AsioUdsHttpServer&) = delete;
        AsioUdsHttpServer& operator=(const AsioUdsHttpServer&) = delete;

        using IUdsHttpServer::addRoute; // the bool compatibility spelling
        void addRoute(Method method, const std::string& path, RouteHandler handler, RouteOptions options) override;
        void start(const UdsHttpServerConfig& config) override;
        void stopAccepting() noexcept override;
        void stop() noexcept override;
        TransportDiagnostics diagnostics() const noexcept override;

    private:
        struct Impl;
        std::unique_ptr<Impl> m_impl;
    };

} // namespace wazuh::uds_http

#endif // _WAZUH_ASIO_UDS_HTTP_SERVER_HPP
