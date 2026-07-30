/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * July 21, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_RESTINIO_HTTP_SERVER_HPP
#define _REMOTED_RESTINIO_HTTP_SERVER_HPP

#include "IHttpServer.hpp"

#include <openssl/x509.h>

#include <memory>
#include <string>

namespace remoted::http
{
    /**
     * @brief Checks whether a peer IP address is listed in a certificate's subjectAltName.
     *
     * Split out of the TLS verify callback (RestinioHttpServer.cpp's ClientVerificationMode::Full
     * handling) so the actual IP-vs-certificate comparison is unit-testable without a live
     * socket or TLS handshake: it takes a plain X509* and a string, with no dependency on
     * asio/restinio.
     *
     * @param certificate Peer (leaf) certificate. Must not be null.
     * @param peerIp Textual IPv4 or IPv6 address to look up in the certificate's SAN.
     * @return true if certificate is non-null and peerIp matches an IP entry in its SAN.
     */
    bool certificateMatchesPeerIp(X509* certificate, const std::string& peerIp);

    /**
     * @brief RESTinio + OpenSSL implementation of IHttpServer.
     *
     * All RESTinio/asio types are hidden behind a PImpl so this header (and every
     * translation unit that owns the server, e.g. the facade) stays free of the
     * transport library. Handlers run on a bounded worker pool and complete their
     * responses via a deferred responder, so the RESTinio I/O threads are never
     * blocked by slow handler work.
     */
    class RestinioHttpServer final : public IHttpServer
    {
    public:
        RestinioHttpServer();
        ~RestinioHttpServer() override;

        RestinioHttpServer(const RestinioHttpServer&) = delete;
        RestinioHttpServer& operator=(const RestinioHttpServer&) = delete;

        void
        addRoute(Method method,
                 const std::string& path,
                 RouteHandler handler,
                 bool countAgainstBudget = true,
                 ResponseMode mode = ResponseMode::Buffered) override;
        void start(const HttpServerConfig& config) override;
        void stopAccepting() noexcept override;
        void stop() noexcept override;

    private:
        struct Impl;
        std::unique_ptr<Impl> m_impl;
    };

} // namespace remoted::http

#endif // _REMOTED_RESTINIO_HTTP_SERVER_HPP
