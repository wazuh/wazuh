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

#ifndef _WAZUH_UDS_HTTP_SERVER_INTERFACE_HPP
#define _WAZUH_UDS_HTTP_SERVER_INTERFACE_HPP

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace wazuh::uds_http
{

    /*
     * PEER CONTRACT -- do not change the wire behaviour without reading the client.
     *
     * The reference client of this server is remoted's AsioUdsHttpClient
     * (src/remoted/remoted_module/src/downstream/asioUdsHttpClient.cpp). The exact bytes it
     * puts on the wire are built by its buildRequestHead():
     *
     *   <METHOD> <path> HTTP/1.1\r\n
     *   Host: localhost\r\n
     *   [Content-Type: <ct>\r\n]        <- emitted ONLY when non-empty
     *   Content-Length: <n>\r\n
     *   Connection: close\r\n
     *   \r\n
     *   <body>
     *
     * One request per connection; the client closes after reading one response and ends the
     * response on either Content-Length or EOF. It caps the response body incrementally and
     * aborts past the cap.
     *
     * These types intentionally MIRROR remoted's own
     * src/remoted/remoted_module/src/http_server/IHttpServer.hpp so both sides of the socket read
     * alike. This library is the SHARED UDS-SERVER side, consumed by manager daemons
     * (inventory_sync_server, vulnerability_scanner, remoted_module's local admin socket).
     * remoted's agent-facing TCP/TLS server is a protocol PEER, not a layer of this stack, and
     * stays separate on purpose: its HttpServerConfig is TCP/TLS-shaped and a change one side
     * needs must not be a change the other side is forced to take.
     *
     * NORMATIVE where the two historically diverged (both divergences are this library's
     * behaviour): the request target is RAW with the query string included, and request header
     * names are lower-cased before the handler sees them.
     */

    /**
     * @brief HTTP verbs supported by the server abstraction.
     *
     * All five, not just Post: the peer's methodToString() can emit any of them, which is what
     * makes answering 405 (rather than 404) meaningful when a path matches but the verb does not.
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
        Method method {Method::Post};
        /// RAW request target exactly as received, query string INCLUDED. Same choice as remoted's
        /// RESTinio implementation (whose own header comment claims "without query" and does not
        /// match its code). Routing matches on the pre-'?' prefix only.
        std::string target;
        std::string body; ///< Raw request body.
        /// Header name LOWER-CASED, value verbatim. Unlike remoted's RESTinio implementation --
        /// which documents lower-casing but inserts the name as received -- this one actually
        /// normalizes, so a handler may look up "content-type" unconditionally.
        std::unordered_map<std::string, std::string> headers;
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
     * @brief Sink used by a handler to deliver its response, possibly much later.
     *
     * Contract:
     *   - send() is thread-safe and takes effect EXACTLY ONCE. Extra calls are ignored.
     *   - A handler may return WITHOUT having called it, retain this shared_ptr, and call it
     *     minutes later from any thread. That is the entire reason this transport exists rather
     *     than a blocking thread-per-request one: a pending response costs a socket, not a thread.
     *   - Calling send() after the server has been fully stopped, or even destroyed, is a
     *     well-defined NO-OP -- not undefined behaviour. remoted's RESTinio server cannot promise
     *     this; this one can, because a responder co-owns the I/O runtime.
     *
     * Dropping this shared_ptr without ever calling send() is a HANDLER BUG. The transport detects
     * it and answers 503, so the peer is never left hanging, and logs it (throttled).
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
     * @brief Handler invoked for a matched route. Asynchronous by contract.
     *
     * MUST NOT BLOCK. Handlers run inline on an I/O thread -- there is deliberately no handler
     * thread pool here, unlike remoted's server, because our handlers only hand the payload to the
     * ingestion pipeline and return. A handler that blocks stalls one I/O thread and
     * head-of-line-blocks the connections sharing its strand. Enqueue and return; reply through
     * the responder when the work finishes.
     *
     * The request is a shared_ptr<const> so it can travel across deferred queues. Keeping it alive
     * also keeps the transport's in-flight byte reservation alive; the responder does NOT co-own
     * it, so dropping the request releases the payload and its reservation independently of -- and
     * usually long before -- the reply.
     */
    using RouteHandler = std::function<void(std::shared_ptr<const HttpRequest>, std::shared_ptr<IHttpResponder>)>;

    /**
     * @brief Service class of a route, classified by its SHEDDING CONTRACT -- not by verb.
     *
     * - Data: bulk payloads with deferred completion, the reason the byte budget exists. Charged
     *   the budget; shed with 503 under pressure (the peer implements retry/backoff by design).
     * - Control: small-bodied requests other daemons depend on. NEVER shed by data-plane pressure
     *   (budget-exempt); bounded instead by their own small body cap and session cap. A Control
     *   route that does real work still sheds ITS OWN capacity module-side (a bounded queue
     *   answering 503) -- the class only guarantees the data plane cannot starve it.
     * - Liveness: answered from resident state; must respond under any pressure.
     */
    enum class RouteClass : std::uint8_t
    {
        Data = 0,
        Control = 1,
        Liveness = 2
    };

    /// Number of route classes, for per-class arrays.
    inline constexpr std::size_t ROUTE_CLASS_COUNT {3};

    /**
     * @brief Per-route registration options.
     *
     * The zeroes defer to the class policy in UdsHttpServerConfig, so a plain
     * `RouteOptions {RouteClass::Control}` is the common spelling.
     */
    struct RouteOptions
    {
        RouteClass cls {RouteClass::Data};
        /// Per-route body-cap override; 0 -> the class policy's cap. Checked against the DECLARED
        /// Content-Length at headers-complete: over it is a 413 (the peer is wrong), never a 503.
        std::size_t maxBodyBytes {0};
        /// Per-route concurrent-session cap, enforced with the route's own counter IN ADDITION to
        /// the class cap; 0 -> only the class cap applies.
        std::size_t maxSessions {0};
    };

    /**
     * @brief Admission policy of one route class.
     */
    struct ClassPolicy
    {
        bool chargeByteBudget {false}; ///< Reserve declared length + overhead from the byte budget.
        std::size_t maxBodyBytes {0};  ///< Declared-length cap -> 413. UNLIMITED_BODY_SIZE disables.
        std::size_t maxSessions {0};   ///< Concurrent classified sessions -> 503. 0 = resolved at start().
    };

    /**
     * @brief Server configuration, decoupled from the C-ABI struct.
     *
     * The in-struct values below ARE the module defaults; buildServerConfig() only overrides the
     * ones the caller set. Sentinel rule in the C-ABI, uniform: <=0 / empty -> keep the default.
     */
    struct UdsHttpServerConfig
    {
        /// No default: every consumer names its own socket. Empty makes start() throw with a
        /// message naming the problem. Consumers use a RELATIVE path on purpose: modulesd
        /// chdir()s to the install dir and remoted chroot()s into it, so a relative path is the
        /// only form both resolve to the same file.
        std::string socketPath {};
        /// bind() applies the umask, so an explicit chmod after bind is mandatory, not belt-and-braces.
        std::uint32_t socketMode {0660};

        /*
         * There is deliberately no socketGroup: modulesd runs with its effective group set to the
         * wazuh group, so the socket already belongs to it and 0660 suffices. Reinstating one would
         * need more than the field -- internal options can only carry ints, so the group would have
         * to arrive some other way.
         */

        std::size_t ioThreads {0}; ///< 0 -> cpp_get_nproc(). Reactor threads; they never block.
        std::size_t concurrentAccepts {2};
        std::size_t bufferSize {8192}; ///< Per-connection read buffer, bytes.

        /// Sentinel meaning "no body cap of this server's own".
        static constexpr std::size_t UNLIMITED_BODY_SIZE {static_cast<std::size_t>(-1)};
        /// No own cap BY DEFAULT: a session is bounded by the in-flight byte budget instead, and
        /// start() feeds that budget to the parser so a request that declares more than could ever
        /// be admitted is refused with 413 at headers-complete (the peer must split the session)
        /// rather than shed with a retriable 503 it would retry forever.
        std::size_t maxBodySize {UNLIMITED_BODY_SIZE};
        std::size_t maxUrlSize {2048};
        std::size_t maxHeaderNameSize {256};
        std::size_t maxHeaderValueSize {8192};
        /// Fixed at 32 everywhere (here, RequestParser::Limits and the builder): it is a term of
        /// the per-request memory overhead the in-flight byte budget charges for.
        std::size_t maxHeaderCount {32};

        std::size_t headerTimeoutSec {10}; ///< Accept -> full request head received.
        std::size_t bodyTimeoutSec {30};   ///< Head received -> full body received.
        /// Dispatch -> send(). A LEAK BACKSTOP, not a quality-of-service deadline: the peer sets
        /// its own, shorter, per-target deadline and gives up first. Its only job is to guarantee
        /// that a handler which loses a responder cannot hold an fd forever.
        std::size_t responseTimeoutSec {300};
        std::size_t writeTimeoutSec {10}; ///< Time allowed to write one response.
        /// stop(): how long to wait for already-dispatched requests to answer. Kept SHORT because
        /// modulesd calls every module's stop() sequentially before joining them under one shared
        /// budget, so a long drain here delays every other module's teardown.
        std::size_t drainTimeoutSec {2};

        /// One deferred response costs one fd, so this is the knob that bounds fd usage. Over it:
        /// an explicit 503, then close. Note the accepted-and-rejected connection also costs an
        /// fd briefly, so the true ceiling is maxConnections + concurrentAccepts.
        std::size_t maxConnections {1024};

        /*
         * Server identity, injected so diagnostics read in the consumer's own vocabulary and the
         * extraction of this library changed no log line of its first consumer.
         */
        /// Tag every log line is attributed to (the daemon:module:component convention).
        std::string logTag {"wazuh-manager:uds-http-server"};
        /// Short service name rendered into diagnostics as "<name> server", "<name> connection(s)"
        /// and "<name> request(s)". Example: "inventory sync".
        std::string serverName {"UDS HTTP"};
        /// Value of the "Server:" response header. Consumers that already have a wire contract
        /// keep their historical value; new servers pick their own daemon name.
        std::string serverHeader {"wazuh-manager-modulesd"};
        /// Name of the internal option that raises the in-flight byte budget, mentioned in the
        /// budget-exhausted diagnostic. Empty: the advice sentence is omitted.
        std::string budgetOptionHint {};
        /// Ditto for the connection cap diagnostic.
        std::string connectionCapOptionHint {};

        /*
         * Route-class admission policies (QoS). The defaults implement the model the classes were
         * designed for: the DATA plane can shed (503) and is the only class charged the byte
         * budget; CONTROL and LIVENESS are exempt from it and bounded by their own small body and
         * session caps instead, so a saturated data plane can never starve them. The decisive
         * mechanism is reservedControlConnections: Data's session cap resolves to
         * maxConnections - reserved, so Data ALONE can never drive occupancy up to the
         * accept-time cap -- headroom always remains for the other classes to be accepted,
         * classified and served.
         */
        ClassPolicy dataPolicy {true, UNLIMITED_BODY_SIZE, 0}; ///< maxSessions 0 -> maxConnections - reserved.
        ClassPolicy controlPolicy {false, 64U * 1024U, 256};
        ClassPolicy livenessPolicy {false, 4U * 1024U, 64};
        /// Accept-headroom the data plane can never consume. Clamped at start() to at most
        /// maxConnections / 4 (and to 0 when that quarter is 0, i.e. tiny test configs).
        std::size_t reservedControlConnections {64};
        /// Reserved from the declared Content-Length at headers-complete, so this bounds the
        /// read-phase peak as well as resident payloads. 0 disables. start() clamps it up to at
        /// least one maximum-size body, so a too-small value cannot reject everything.
        std::size_t maxInFlightBytes {256U * 1024U * 1024U};
    };

    /**
     * @brief Point-in-time snapshot of the transport's bounded resources.
     *
     * Produced by IUdsHttpServer::diagnostics() from relaxed atomic loads, so it is cheap enough
     * to be polled by a metrics collector (the intended use: each consumer publishes these as
     * wazuh_metrics pull metrics -- this library deliberately does not depend on wazuh_metrics).
     * With the byte budget disabled (maxInFlightBytes == 0) the three budget fields read 0.
     */
    struct TransportDiagnostics
    {
        std::size_t budgetAvailableBytes {0}; ///< Bytes still admittable right now.
        std::size_t budgetInFlightBytes {0};  ///< Bytes currently reserved by admitted requests.
        std::size_t budgetInFlightCount {0};  ///< Requests currently holding a reservation.
        std::size_t liveSessions {0};         ///< Open connections, deferred replies included.
        /// Classified sessions per class, indexed by RouteClass. Sums to at most liveSessions
        /// (connections still reading their head are counted only in liveSessions).
        std::size_t sessionsByClass[ROUTE_CLASS_COUNT] {0, 0, 0};
    };

    /**
     * @brief Transport-agnostic HTTP/1.1-over-Unix-domain-socket server.
     *
     * The concrete implementation (asio + llhttp) lives behind makeUdsHttpServer(), so the
     * transport library is swappable at one line and no caller or endpoint depends on it.
     * Routes are registered before start().
     */
    class IUdsHttpServer
    {
    public:
        virtual ~IUdsHttpServer() = default;

        /**
         * @brief Register a route. Must be called before start().
         *
         * @param method  HTTP verb to match.
         * @param path    Exact path to match (compared against the pre-'?' prefix of the request
         *                target; no wildcards or patterns).
         * @param handler Handler invoked on a match.
         * @param options Service class and per-route cap overrides (see RouteOptions).
         * @throws std::logic_error if called after start().
         */
        virtual void addRoute(Method method, const std::string& path, RouteHandler handler, RouteOptions options) = 0;

        /**
         * @brief Compatibility spelling of addRoute() predating the class model.
         *
         * true maps to Data (budget-charged, sheddable), false to Liveness (the exempt probes) --
         * exactly what the flag used to mean.
         */
        void addRoute(Method method, const std::string& path, RouteHandler handler, bool countAgainstBudget = true)
        {
            addRoute(method,
                     path,
                     std::move(handler),
                     RouteOptions {countAgainstBudget ? RouteClass::Data : RouteClass::Liveness});
        }

        /**
         * @brief Bind, chmod and start serving. Throws on any bind/permission/configuration
         *        failure, with a message that names the offending path.
         *
         * Also unlinks a stale socket file left by an unclean shutdown, but refuses to unlink a
         * path that exists and is NOT a socket -- a typo in the configured path must not delete an
         * operator's file.
         *
         * @param config Server configuration.
         */
        virtual void start(const UdsHttpServerConfig& config) = 0;

        /**
         * @brief PHASE 1. Stop accepting; deliberately do NOT tear the I/O runtime down.
         *
         * Guarantees, once this returns:
         *   S1 No RouteHandler will ever be invoked again, and every dispatch that had already
         *      started has RETURNED. Connections that had not yet reached a handler were answered
         *      503 and closed.
         *   S2 The I/O runtime is still RUNNING, so a response for a request already handed to the
         *      ingestion pipeline can still be written to its socket via IHttpResponder::send(),
         *      from any thread, at any point afterwards.
         *
         * Call this BEFORE tearing down anything a handler might still call into; that ordering is
         * what makes finishing the in-flight work, and only then calling stop(), safe.
         * Idempotent; safe if never started.
         */
        virtual void stopAccepting() noexcept = 0;

        /**
         * @brief PHASE 2. stopAccepting() (if needed), drain, then release the I/O runtime.
         *
         * Waits up to drainTimeoutSec for outstanding deferred replies to land, then force-closes
         * whatever is left so the peer observes EOF promptly instead of waiting out its own
         * response timeout.
         *
         * Guarantees, once this returns:
         *   S3 send() on any previously handed-out responder is a well-defined NO-OP, from any
         *      thread, at any time -- INCLUDING after this object has been destroyed. Responders
         *      co-own the I/O runtime, so nothing they touch is ever dangling. This is stronger
         *      than remoted's equivalent, which declares the same case undefined.
         *
         * Idempotent; safe if never started; called by the destructor.
         */
        virtual void stop() noexcept = 0;

        /**
         * @brief Snapshot the transport's bounded resources (relaxed atomic loads, lock-free).
         *
         * Callable from any thread at any point between construction and destruction --
         * including before start() (all zeros) and after stop() (the quiesced values).
         */
        virtual TransportDiagnostics diagnostics() const noexcept = 0;
    };

} // namespace wazuh::uds_http

#endif // _WAZUH_UDS_HTTP_SERVER_INTERFACE_HPP
