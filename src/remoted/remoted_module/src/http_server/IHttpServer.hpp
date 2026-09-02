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

#include "inFlightBudget.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
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
        /// Raw request target (path + query, exactly as received on the wire), global endpoint
        /// prefix included when one is configured (HttpServerConfig::globalPrefix). Never normalized
        /// or rewritten: it is what the router matched and what AuthenticatedRequest carries.
        std::string target;
        std::string body; ///< Raw request body.
        /// Header name -> value, EXACTLY as the transport reports it (a well-known field name like
        /// "Authorization" or "Content-Type" is NOT necessarily lowercased -- see
        /// RestinioHttpServer.cpp's makeHttpRequest()). Always look these up via
        /// http_server/headerUtils.hpp's headerValue() (case-insensitive), never an exact-match
        /// find(): an exact match only happens to work against a handcrafted request that inserted
        /// an already-lowercase key directly, never having gone through the real transport.
        /// `authorization` and `protocol-version` are special: when a request carries either of them
        /// more than once (any case), the transport stores an EMPTY value, which the auth layer
        /// rejects as absent -- a duplicated credential header is never "first wins".
        std::unordered_map<std::string, std::string> headers;
        std::string remoteIp; ///< Client's connection IP (textual form; IPv4-mapped-IPv6 addresses
                              ///< are unmapped to plain IPv4 first). The auth gateway hands it to
                              ///< AuthMiddleware, which matches it against the agent's authorized
                              ///< address (client.keys' third column) before verifying the token.
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
     * @brief Pull-based byte source for a streamed (chunked) response body.
     *
     * The transport drives this, not the endpoint: it owns both the connection's I/O strand and
     * the handler worker pool, so it is the only layer that can read on a worker, write on the
     * strand, and wait for each write to complete before pulling again. That is what keeps a
     * transfer's memory flat (one chunk resident) and its worker-pool cost to a single slot held
     * only for the duration of one read -- neither of which an endpoint driving a push-style
     * writeChunk()/finish() API could achieve without blocking a worker for the whole transfer.
     *
     * It also keeps the source itself free of any HTTP concept, which is what makes a concrete
     * source (see FileByteSource) directly unit-testable.
     */
    class IByteSource
    {
    public:
        virtual ~IByteSource() = default;

        /**
         * @brief Produce the next slice of the body.
         *
         * Called on the server's worker pool -- never on an I/O thread, and never concurrently
         * with itself -- so a blocking read is expected and safe here.
         *
         * @param buffer   Destination.
         * @param capacity Maximum number of bytes to write into @p buffer.
         * @return Bytes written; 0 means end-of-stream. Throwing aborts the transfer: no
         *         terminating chunk is emitted, so the peer sees a truncated body and retries.
         */
        virtual std::size_t read(char* buffer, std::size_t capacity) = 0;
    };

    /**
     * @brief A response whose body is streamed with chunked transfer encoding.
     *
     * The transport emits `Transfer-Encoding: chunked` itself; do not put it in @ref headers.
     */
    struct StreamResponse
    {
        int status {200};                                         ///< HTTP status code.
        std::vector<std::pair<std::string, std::string>> headers; ///< Extra headers (verbatim order).
        std::shared_ptr<IByteSource> source;                      ///< Body producer; must not be null.
        /// Bytes pulled per chunk. 0 (the default) means "use the server's configured
        /// streamChunkSize", so an endpoint does not have to know about the tunable at all.
        std::size_t chunkSize {0};
    };

    /**
     * @brief Whether a route may answer with a streamed body.
     *
     * Not a per-response choice: the transport creates the underlying response builder when the
     * request is dispatched (which is what lets it release the received body before the request
     * is queued), and that builder's output mode is fixed at creation. So the mode has to be
     * declared at registration time. `Streamable` routes pay a slightly later release of the
     * received request in exchange -- negligible for a route whose requests are small, which is
     * the only kind that should be streaming a response anyway.
     */
    enum class ResponseMode
    {
        Buffered,  ///< Single in-memory body via IHttpResponder::send(). The default.
        Streamable ///< May additionally answer via IHttpResponder::stream().
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

        /**
         * @brief Deliver the response as a chunked stream, pulling from @p response.source.
         *
         * Shares send()'s exactly-once guarantee: send() and stream() together may be called once
         * per request, from any thread. Returns immediately -- the transfer proceeds asynchronously
         * and the source is drained on the worker pool.
         *
         * Only meaningful on a route registered with ResponseMode::Streamable. The default below
         * exists so that responders which never stream (and every test double) need no override;
         * it fails loudly rather than silently buffering the whole body, because a route that
         * reaches it is misregistered, and quietly materializing a multi-megabyte payload in
         * memory is the exact failure streaming exists to prevent.
         */
        virtual void stream(StreamResponse /*response*/)
        {
            send(HttpResponse::json(500, R"({"error":"Internal server error","code":500})"));
        }
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
        Full         ///< Certificate chain verified, plus the peer's address must appear in its SAN.
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
        Unset,   ///< Not configured anywhere (XML/env). Kept distinct from Disabled so the
                 ///< "dual_stack only applies to IPv6" warning doesn't fire for an IPv4
                 ///< bind_addr; RestinioHttpServer.cpp treats it the same as Disabled
                 ///< (IPv6-only) when actually setting the socket option.
        Enabled, ///< Force dual-stack on (IPV6_V6ONLY=0): also accept IPv4.
        Disabled ///< Force IPv6-only (IPV6_V6ONLY=1): reject IPv4 on this socket.
    };

    /**
     * @brief Configuration for the HTTP(S) server, decoupled from the C ABI struct.
     */
    struct HttpServerConfig
    {
        std::string bindAddress {"127.0.0.1"}; ///< Listen address.
        std::uint16_t port {1517};             ///< Listen port.
        /// Global endpoint prefix every registered route is served under (e.g.
        /// "/wazuh-manager"). Stored raw; RestinioHttpServer::start() canonicalizes it via
        /// normalizeGlobalPrefix() (leading '/', no trailing '/'; "" == "/" == no prefix) and
        /// throws std::invalid_argument for an invalid value. With a prefix set, unprefixed
        /// paths answer 404. The request target is NOT rewritten: handlers and the auth layer
        /// keep seeing the full path exactly as received, and agents sign that full (prefixed)
        /// target -- so a proxy must forward the path untouched, and a prefix mismatch between
        /// agent and manager surfaces as 404. Public HTTPS listener only (the local admin UDS
        /// server is never prefixed). Note: the prefix consumes part of maxUrlSize.
        std::string globalPrefix {};
        std::string certificatePath; ///< TLS certificate chain (PEM) path.
        std::string privateKeyPath;  ///< TLS private key (PEM) path.
        std::string caPath;          ///< CA bundle (PEM) used to verify client certificates.
        std::string ciphers;         ///< TLS 1.3 ciphersuite override
        ClientVerificationMode verificationMode {ClientVerificationMode::None}; ///< Client-certificate strictness.
        DualStackMode dualStackMode {DualStackMode::Unset}; ///< IPV6_V6ONLY override (IPv6 bind only).
        std::size_t ioThreads {2};                          ///< RESTinio/asio I/O threads (accept + read/write).
        std::size_t workerThreads {4};                      ///< Handler worker-pool size (blocking work offload).
        std::size_t maxBodySize {20U * 1024U * 1024U}; ///< Transport hard cap (backstop above the auth body limit).
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
        /// Bytes per chunk for a streamed response body. Per in-flight transfer, so the worst-case
        /// cost is this times the number of simultaneous streams. See remoted.http_stream_chunk_size.
        std::size_t streamChunkSize {64U * 1024U};
        /// Max in-flight (unprocessed) request payload bytes before new requests get 503. 0 disables the limit.
        std::size_t maxInFlightBytes {256U * 1024U * 1024U};
        /// Max simultaneous TCP connections (bounds the read-phase peak: maxParallelConnections * maxBodySize).
        std::size_t maxParallelConnections {512};
    };

    /**
     * @brief Point-in-time snapshot of the public transport's backpressure state.
     *
     * The remoted::http sibling of wazuh::uds_http::TransportDiagnostics (the admin plane
     * publishes that one): the facade adapts this into `remoted.server.budget.*` pull metrics,
     * read only at dump cadence. All zeros is the documented quiescent value -- a server that
     * was never started (or a default IHttpServer implementation) reports it.
     *
     * Accounting boundary: a request shed by the byte budget is refused on the transport's I/O
     * thread BEFORE any route handler runs, so budgetRejectedTotal is the ONLY place those 503s
     * are counted -- they never reach the per-endpoint `remoted.http.*.responses.*` cells.
     */
    struct TransportDiagnostics
    {
        std::size_t budgetAvailableBytes {0};  ///< Bytes the in-flight budget can still admit.
        std::size_t budgetInFlightBytes {0};   ///< Bytes currently reserved by admitted requests.
        std::size_t budgetInFlightCount {0};   ///< Requests currently holding a reservation.
        std::uint64_t budgetRejectedTotal {0}; ///< Requests the budget has shed (cumulative).
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
         * @param path              Path to match (implementation routing syntax). Must start with
         *                          '/'; it is the route's LOGICAL path -- the transport serves it
         *                          under HttpServerConfig::globalPrefix automatically, so callers
         *                          never prefix it themselves.
         * @param handler           Handler invoked on a match.
         * @param countAgainstBudget When false, the route is exempt from the in-flight byte budget
         *                           (no reservation, never shed with 503). Use for tiny liveness
         *                           probes so they stay available under memory pressure.
         * @param mode               Whether the route's handler may answer with a streamed body.
         *                           See ResponseMode: this cannot be decided per response, so a
         *                           route that ever streams must say so here.
         */
        virtual void addRoute(Method method,
                              const std::string& path,
                              RouteHandler handler,
                              bool countAgainstBudget = true,
                              ResponseMode mode = ResponseMode::Buffered) = 0;

        /**
         * @brief Try to reserve @p bytes against the in-flight byte budget, independent of any
         * request's own wire-body reservation.
         *
         * Lets a route handler charge memory it allocates itself (e.g. a decompressed request body)
         * against the same pool that bounds unprocessed request payloads, so concurrent handlers
         * genuinely contend for it instead of each independently reading a "free" figure and all
         * proceeding at once. For a size that isn't known upfront, reserve 0 bytes to obtain a
         * handle and grow it via InFlightBudget::Reservation::grow() as bytes materialize.
         *
         * The bytes stay charged for as long as the returned reservation is kept alive, so tie its
         * lifetime to whatever the reserved bytes actually back -- bundle it into that data's own
         * keep-alive to hold it, or let it fall out of scope to release it.
         *
         * This is an auxiliary (bytes-only) reservation for a request that was already admitted:
         * it neither counts toward the budget's in-flight request count nor, on failure, toward
         * its shed total -- the caller answers its own request (e.g. 413), it does not turn a new
         * one away. If the reservation later becomes the request's resident body (the wire buffer
         * is dropped in its favor), call InFlightBudget::Reservation::promoteToRequest() on it so
         * the request keeps counting as exactly one.
         *
         * @param bytes Bytes to reserve up front (0 is always granted).
         * @return An engaged reservation on success, `std::nullopt` if the budget doesn't have
         *         that much room right now, or if there is no live budget to reserve against (the
         *         server hasn't been started yet).
         */
        virtual std::optional<InFlightBudget::Reservation> tryReserveInFlightBytes(std::size_t bytes) = 0;

        /**
         * @brief Snapshot the transport's backpressure state, for the metrics dump.
         *
         * Callable from any thread at any point in the server's life; before start() (and on
         * implementations that track no budget, like the test fakes) it reports all zeros.
         * Dump-cadence only -- implementations may take a lock.
         */
        virtual TransportDiagnostics diagnostics() const
        {
            return {};
        }

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
