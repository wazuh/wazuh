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
#include <optional>
#include <string>

namespace remoted::http
{
    /**
     * @brief Whether a peer address is listed among a certificate's subjectAltName IP entries.
     *
     * Split out of ClientVerificationMode::Full's handling so the comparison itself is
     * unit-testable from a plain X509* and a string, with no socket, TLS handshake or on-disk
     * fixture involved.
     *
     * @param certificate Peer (leaf) certificate. A null pointer never matches.
     * @param peerIp Textual IPv4 or IPv6 address, as reported by the connection's remote endpoint.
     * @return true when the certificate is non-null and lists that address.
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
        std::optional<InFlightBudget::Reservation> tryReserveInFlightBytes(std::size_t bytes) override;
        void start(const HttpServerConfig& config) override;
        void stopAccepting() noexcept override;
        void stop() noexcept override;

    private:
        struct Impl;
        std::unique_ptr<Impl> m_impl;
    };

} // namespace remoted::http

#endif // _REMOTED_RESTINIO_HTTP_SERVER_HPP
