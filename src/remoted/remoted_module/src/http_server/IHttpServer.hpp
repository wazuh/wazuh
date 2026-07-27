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

#ifndef _REMOTED_HTTP_SERVER_INTERFACE_HPP
#define _REMOTED_HTTP_SERVER_INTERFACE_HPP

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace remoted::http
{

    /**
     * @brief HTTP verbs supported by the server abstraction.
     *
     * Library-neutral on purpose: it must never expose a RESTinio (or Boost.Beast)
     * type so the transport implementation can be swapped without touching handlers.
     */
    enum class Method
    {
        Get,
        Post,
        Put,
        Delete,
        Patch
    };

    /**
     * @brief Neutral view of an incoming HTTP request handed to a handler.
     */
    struct HttpRequest
    {
        Method method {Method::Get};
        std::string target;                                   ///< Request path (without query).
        std::string body;                                     ///< Raw request body.
        std::unordered_map<std::string, std::string> headers; ///< Lower-cased header name -> value.
        std::string remoteIp; ///< Client's connection IP (textual form; IPv4-mapped-IPv6 addresses
                              ///< are unmapped to plain IPv4 first). Not currently used by any
                              ///< handler; available for a future cross-check against client.keys.
    };

    /**
     * @brief Neutral HTTP response produced by a handler.
     */
    struct HttpResponse
    {
        int status {200};                                         ///< HTTP status code.
        std::string body;                                         ///< Response body.
        std::vector<std::pair<std::string, std::string>> headers; ///< Extra headers (verbatim order).

        /**
         * @brief Build a JSON response (sets Content-Type: application/json).
         */
        static HttpResponse json(int status, std::string body)
        {
            HttpResponse response;
            response.status = status;
            response.body = std::move(body);
            response.headers.emplace_back("Content-Type", "application/json");
            return response;
        }
    };

    /**
     * @brief Sink used by a handler to deliver its response, possibly later.
     *
     * The server hands one responder per request. A handler may either respond
     * inline or capture the shared_ptr, kick off blocking/async work (disk, another
     * API) off the I/O threads, and call send() once that work finishes -- from any
     * thread. This is what lets the I/O threads keep serving other requests while a
     * slow handler is in flight.
     *
     * Contract: send() is thread-safe and MUST be called exactly once per request.
     * Extra calls are ignored.
     */
    class IHttpResponder
    {
    public:
        virtual ~IHttpResponder() = default;

        /**
         * @brief Deliver the response for the associated request.
         *
         * @param response The response to send.
         */
        virtual void send(HttpResponse response) = 0;
    };

    /**
     * @brief Handler invoked for a matched route.
     *
     * Asynchronous by contract: the handler receives the request plus a responder
     * and is not required to have produced the response by the time it returns.
     *
     * The request is a shared_ptr<const> so a handler may retain it and let it
     * travel across deferred queues/pipelines; keeping it alive also keeps the
     * transport's in-flight byte reservation alive (released once the last owner --
     * handler and responder -- drops it).
     */
    using RouteHandler = std::function<void(std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder>)>;

    /**
     * @brief Client-certificate verification strictness for the HTTPS listener.
     *
     * Mirrors REMOTED_MODULE_HTTPS_VERIFY_* in remoted_module.h (the C-ABI) and
     * REMOTED_HTTPS_VERIFY_* in the config parser (src/config/include/remote-config.h).
     */
    enum class ClientVerificationMode
    {
        None,        ///< No client certificate is requested/verified.
        Certificate, ///< Client certificate chain is verified against the configured CA.
        Full         ///< Certificate chain verified, plus the peer IP must match the certificate.
    };

    /**
     * @brief Whether an IPv6 listener also accepts IPv4 clients on the same socket.
     *
     * Only meaningful when the listener binds to an IPv6 address; a no-op otherwise.
     * Mirrors REMOTED_MODULE_HTTPS_DUAL_STACK_* in remoted_module.h (the C-ABI) and
     * REMOTED_HTTPS_DUAL_STACK_* in the config parser (src/config/include/remote-config.h).
     */
    enum class DualStackMode
    {
        Unset,   ///< Not configured -> leave the OS default (dual-stack on Linux).
        Enabled, ///< Force dual-stack on (IPV6_V6ONLY=0): also accept IPv4.
        Disabled ///< Force IPv6-only (IPV6_V6ONLY=1): reject IPv4 on this socket.
    };

    /**
     * @brief Configuration for the HTTP(S) server, decoupled from the C ABI struct.
     */
    struct HttpServerConfig
    {
        std::string bindAddress {"127.0.0.1"}; ///< Listen address.
        std::uint16_t port {9443};             ///< Listen port.
        std::string certificatePath;           ///< TLS certificate chain (PEM) path.
        std::string privateKeyPath;            ///< TLS private key (PEM) path.
        std::string caPath;                    ///< CA bundle (PEM) used to verify client certificates.
        std::string ciphers;                   ///< OpenSSL cipher list override (empty -> library default).
        ClientVerificationMode verificationMode {ClientVerificationMode::None}; ///< Client-certificate strictness.
        DualStackMode dualStackMode {DualStackMode::Unset}; ///< IPV6_V6ONLY override (IPv6 bind only).
        std::size_t ioThreads {2};                          ///< RESTinio/asio I/O threads (accept + read/write).
        std::size_t workerThreads {4};                      ///< Handler worker-pool size (blocking work offload).
        std::size_t maxBodySize {50U * 1024U * 1024U}; ///< Transport hard cap (backstop above the auth body limit).
        std::size_t readTimeoutSec {10};               ///< Time to receive a full request on a connection (also covers
                                                       ///< the TLS handshake window).
        std::size_t writeTimeoutSec {10};              ///< Time allowed to write a response.
        std::size_t requestTimeoutSec {30};            ///< Time allowed to handle a request end-to-end.
        std::size_t maxUrlSize {2048};                 ///< Max URL size, bytes.
        std::size_t maxHeaderNameSize {256};           ///< Max HTTP header name size, bytes.
        std::size_t maxHeaderValueSize {8192};         ///< Max HTTP header value size, bytes.
        std::size_t maxHeaderCount {64};               ///< Max number of HTTP headers per request.
        std::size_t maxPipelinedRequests {4};          ///< Max in-flight unanswered requests per connection.
        std::size_t concurrentAccepts {2};             ///< Max concurrent in-progress TCP accepts.
        std::size_t bufferSize {8192};                 ///< Socket read buffer size, bytes.
        /// Max in-flight (unprocessed) request payload bytes before new requests get 503. 0 disables the limit.
        std::size_t maxInFlightBytes {256U * 1024U * 1024U};
        /// Max simultaneous TCP connections (bounds the read-phase peak: maxParallelConnections * maxBodySize).
        std::size_t maxParallelConnections {512};
    };

    /**
     * @brief Transport-agnostic HTTP(S) server interface.
     *
     * Concrete implementations (today RESTinio, tomorrow Boost.Beast + Boost.Asio)
     * live behind this interface so callers -- and every registered endpoint -- stay
     * independent of the underlying library. Routes are registered before start().
     */
    class IHttpServer
    {
    public:
        virtual ~IHttpServer() = default;

        /**
         * @brief Register a route. Must be called before start().
         *
         * @param method            HTTP verb to match.
         * @param path              Path to match (implementation routing syntax).
         * @param handler           Handler invoked on a match.
         * @param countAgainstBudget When false, the route is exempt from the in-flight byte budget
         *                           (no reservation, never shed with 503). Use for tiny liveness
         *                           probes so they stay available under memory pressure.
         */
        virtual void
        addRoute(Method method, const std::string& path, RouteHandler handler, bool countAgainstBudget = true) = 0;

        /**
         * @brief Start listening. Throws on bind/TLS/configuration failure.
         *
         * @param config Server configuration.
         */
        virtual void start(const HttpServerConfig& config) = 0;

        /**
         * @brief Stop ACCEPTING new connections/requests and drain the handler worker pool.
         *
         * Guarantees, once this returns: (1) no RouteHandler will ever be invoked again --
         * every handler dispatch that was already queued has completed; (2) the underlying
         * I/O runtime is deliberately left ALIVE, so a response to a request that was already
         * handed off before this call (e.g. to a downstream forwarder) can still be delivered
         * safely via IHttpResponder::send() from any thread, at any point afterward.
         *
         * Call this BEFORE tearing down anything an in-flight handler might still call into
         * (a downstream client/forwarder) -- that is what makes finishing that in-flight work
         * afterward, and only then calling stop(), safe. Idempotent; safe if never started.
         */
        virtual void stopAccepting() noexcept = 0;

        /**
         * @brief Fully stop: stopAccepting() (if not already done) plus release the I/O
         * runtime itself.
         *
         * @warning Once this returns (or once the IHttpServer is destroyed), any previously
         * handed-out IHttpResponder MUST NOT call send() again -- doing so is undefined
         * behavior (the connection's I/O runtime is gone). Callers that hand responders to
         * asynchronous work (e.g. a downstream forwarder) must ensure that work has already
         * completed -- via stopAccepting() plus draining that work -- before calling this.
         * Idempotent; safe if never started.
         */
        virtual void stop() noexcept = 0;
    };

} // namespace remoted::http

#endif // _REMOTED_HTTP_SERVER_INTERFACE_HPP
