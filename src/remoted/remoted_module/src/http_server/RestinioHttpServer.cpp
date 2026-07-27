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

#include "RestinioHttpServer.hpp"
#include "common/logThrottle.hpp"
#include "httpServerFactory.hpp"
#include "inFlightBudget.hpp"

#include "loggerHelper.h"

#include <restinio/core.hpp>
#include <restinio/http_server_run.hpp>
#include <restinio/router/express.hpp>
#include <restinio/tls.hpp>

#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace
{
    constexpr auto HTTP_SERVER_LOGTAG {"wazuh-manager-remoted:http-server"};

    // File-local accessors rather than a member/captured pointer. Two reasons: LogFn holds a
    // std::string, so a temporary per log call would heap-allocate; and LogFn has hidden ELF
    // visibility (loggerHelper.h wraps everything in a visibility pragma), so storing one as a
    // member of -- or capturing one into -- a default-visibility class/lambda trips -Wattributes.
    const LogFn& logFn()
    {
        static const LogFn instance {HTTP_SERVER_LOGTAG};
        return instance;
    }

    // RESTinio's own diagnostics get a distinguishable sub-tag.
    const LogFn& restinioLogFn()
    {
        static const LogFn instance {LogFn {HTTP_SERVER_LOGTAG}.compose("restinio")};
        return instance;
    }

    // Fixed per-request memory charged on top of the body so that a flood of tiny-body
    // requests still consumes the in-flight budget (headers map, neutral request struct,
    // RESTinio handle bookkeeping). A coarse estimate on purpose.
    constexpr std::size_t PER_REQUEST_OVERHEAD {4U * 1024U};

    namespace asio = restinio::asio_ns;
    namespace router = restinio::router;

    using Router = router::express_router_t<>;

    /**
     * @brief Routes RESTinio's internal diagnostics into remoted's wazuh-manager.log , at debug level.
     *
     * This replaces restinio::null_logger_t, whose methods are `constexpr void {}` -- meaning every
     * RESTinio diagnostic was previously discarded AT COMPILE TIME. That hid TLS handshake errors
     * (bad client cert, protocol/cipher mismatch, plaintext sent to the TLS port), malformed HTTP,
     * `EADDRINUSE` on bind, and every breach of http_max_body_size / http_max_url_size /
     * http_max_header_{name,value}_size / http_max_header_count.
     *
     * Level mapping: error -> DEBUG1 (throttled), warn -> DEBUG1 (throttled). Nothing from RESTinio
     * itself appears in wazuh-manager.log  by default; see `remoted.debug` to enable it. trace and info are
     * not forwarded at all -- see note 2.
     *
     * Why DEBUG1 and not WARN/ERROR: reading `external/restinio/dev/restinio/impl/connection.hpp`
     * (trigger_error_and_close(), the sole path into logger().error()) shows every one of RESTinio's
     * own "error" calls is a PER-CONNECTION protocol/socket event -- a truncated read, a malformed
     * HTTP parse, a header/URL over its configured limit -- overwhelmingly driven by client behavior
     * (a portscanner, a buggy client, or deliberately-malformed negative-test traffic, e.g.
     * tools/send_stateless.py --all). None of that is "the manager is broken" in the sense this
     * module reserves ERROR for (AES-CMAC unavailable, the worker thread failing to launch); it is
     * the same "client fault" bucket as an auth rejection, just one layer lower in the stack. The one
     * event here that IS a genuine, rare, operator-facing problem -- the acceptor failing to bind
     * (port in use, TLS context rejected) -- is already surfaced distinctly and more clearly by our
     * own createTlsContext() checks and RemotedModuleFacade::start()'s catch block (which logs and
     * rethrows), so demoting RESTinio's own duplicate report of it costs nothing.
     *
     * Four things here are load-bearing:
     *
     * 1. The message is always passed as an ARGUMENT to "%s", never as the format string. LogFn
     *    forwards its format straight to _log()'s vfprintf/vsnprintf (shared/src/debug_op.c, which
     *    is even declared __attribute__((format(printf,...)))), and RESTinio's builders embed
     *    client-controlled data -- request target, header values, exception text. Passing that as a
     *    format would be a remote format-string vulnerability.
     *
     * 2. trace() and info() are `constexpr {}`, exactly like null_logger_t, so the compiler strips
     *    them and the ~30 trace call sites in RESTinio's connection handling cost nothing. This was
     *    measured, not assumed: forwarding them cost ~10% throughput on a keep-alive `GET /` (min
     *    89 ms -> 97 ms for 2000 requests, one I/O thread). The reason is structural rather than the
     *    body -- with a real logger type, RESTinio selects the generic log_trace_noexcept overload,
     *    which materializes a closure and a try/catch frame per site, instead of the empty
     *    null_logger_t overload. A runtime `if` inside the body cannot recover that.
     *
     * 3. Both warn() and error() are throttled -- and this matters even though the result is DEBUG1,
     *    not just "so wazuh-manager.log  doesn't flood under remoted.debug". Log::isDebugEnabled() filters
     *    NOTHING today: Log::GLOBAL_LOG_LEVEL is 0 and Log::setLogLevel() is never called anywhere in
     *    the tree, so LOGFN_DEBUG1's guard always passes and builder() (RESTinio's fmt::format call)
     *    ALWAYS runs -- the real filter against dbg_flag lives further downstream, inside
     *    mtLoggingFunctionsWrapper (shared/src/debug_op.c), AFTER that allocation already happened.
     *    Without the throttle, a burst of malformed connections would heap-allocate a string per
     *    event on a RESTinio I/O thread regardless of whether remoted.debug is even enabled. Two
     *    separate throttle instances (not one shared) so a storm of one kind (e.g. parser errors)
     *    can't suppress the other (e.g. write-to-closed-socket warnings) from ever getting its own
     *    "first occurrence" report.
     *
     * One accepted limitation: LOGFN_* captures __FILE__/__LINE__ at the call site, so every
     * RESTinio line is attributed to this adapter rather than to RESTinio's own source location.
     * RESTinio exposes no source location, and the message text is self-identifying.
     */
    class WazuhRestinioLogger final
    {
    public:
        // Stripped at compile time (see note 2 above). Signature matches null_logger_t's.
        template<typename Message_Builder>
        constexpr void trace(Message_Builder&&) const noexcept
        {
        }

        template<typename Message_Builder>
        constexpr void info(Message_Builder&&) const noexcept
        {
        }

        // Non-const to match ostream_logger_t (RESTinio invokes these on a non-const reference), so
        // the throttles need no `mutable`.
        template<typename Message_Builder>
        void warn(Message_Builder&& builder)
        {
            logThrottled(m_warnThrottle, std::forward<Message_Builder>(builder));
        }

        template<typename Message_Builder>
        void error(Message_Builder&& builder)
        {
            logThrottled(m_errorThrottle, std::forward<Message_Builder>(builder));
        }

    private:
        template<typename Message_Builder>
        void logThrottled(remoted::common::LogThrottle& throttle, Message_Builder&& builder)
        {
            if (const auto decision = throttle.record())
            {
                const auto message = builder();
                LOGFN_DEBUG1(restinioLogFn(),
                             "%s (%llu occurrence(s) in the last %d s)",
                             message.c_str(),
                             static_cast<unsigned long long>(decision.total),
                             remoted::common::LogThrottle::kDefaultWindowSeconds);
            }
        }

        remoted::common::LogThrottle m_warnThrottle;
        remoted::common::LogThrottle m_errorThrottle;
    };

    // Enable RESTinio's connection-count limiter so max_parallel_connections() is honored
    // (the default noop limiter turns that setter into a compile-time error).
    struct ServerTraits : public restinio::tls_traits_t<restinio::asio_timer_manager_t, WazuhRestinioLogger, Router>
    {
        static constexpr bool use_connection_count_limiter = true;
    };

    using ServerHandle = restinio::running_server_handle_t<ServerTraits>;

    // Map the neutral verb to a RESTinio method matcher.
    restinio::http_method_id_t toRestinioMethod(remoted::http::Method method)
    {
        switch (method)
        {
            case remoted::http::Method::Get: return restinio::http_method_get();
            case remoted::http::Method::Post: return restinio::http_method_post();
            case remoted::http::Method::Put: return restinio::http_method_put();
            case remoted::http::Method::Delete: return restinio::http_method_delete();
            case remoted::http::Method::Patch: return restinio::http_method_patch();
        }

        return restinio::http_method_get();
    }

    // Minimal reason-phrase table; unknown codes get a generic phrase.
    const char* reasonPhrase(int status)
    {
        switch (status)
        {
            case 200: return "OK";
            case 201: return "Created";
            case 202: return "Accepted";
            case 204: return "No Content";
            case 400: return "Bad Request";
            case 401: return "Unauthorized";
            case 403: return "Forbidden";
            case 404: return "Not Found";
            case 405: return "Method Not Allowed";
            case 413: return "Payload Too Large";
            case 429: return "Too Many Requests";
            case 500: return "Internal Server Error";
            case 503: return "Service Unavailable";
            default: return "Status";
        }
    }

    // TODO: Do we need to perform this transformation here? Or will the data already be in client.keys?
    std::string normalizeRemoteAddress(asio::ip::address address)
    {
        if (address.is_v6() && address.to_v6().is_v4_mapped())
        {
            address = asio::ip::make_address_v4(asio::ip::v4_mapped, address.to_v6());
        }

        return address.to_string();
    }

    // Bracket an IPv6 literal for URL-style display (RFC 3986); IPv4 and hostnames
    // pass through unchanged.
    std::string formatHostForDisplay(const std::string& address)
    {
        if (address.find(':') != std::string::npos)
        {
            return "[" + address + "]";
        }

        return address;
    }

    // Whether a bind address string is IPv6 -- parsed the same way RESTinio itself
    bool isIpv6Address(const std::string& address)
    {
        asio::error_code ec;
        const auto parsed = asio::ip::make_address(address, ec);
        return !ec && parsed.is_v6();
    }

    // Build the neutral request view from a RESTinio request handle.
    remoted::http::HttpRequest makeHttpRequest(remoted::http::Method method, const restinio::request_handle_t& req)
    {
        remoted::http::HttpRequest request;
        request.method = method;
        // Raw request target (path + query, exactly as received): the auth layer
        // signs it verbatim, so it must not be path-only or normalized.
        request.target = req->header().request_target();
        request.body = req->body();
        request.remoteIp = normalizeRemoteAddress(req->remote_endpoint().address());

        req->header().for_each_field(
            [&request](const restinio::http_header_field_t& field)
            { request.headers.emplace(std::string {field.name()}, std::string {field.value()}); });

        return request;
    }

    // Pre-check cert/key readability so the failure names the offending FILE. Asio's own exception
    // for a missing PEM is an opaque OpenSSL error string ("no start line", "system library"), which
    // gave the operator no way to tell "cert missing" from "key missing" from "port in use" -- they
    // all surfaced as the same generic retry warning.
    void checkTlsFileReadable(const std::string& path, const char* what)
    {
        std::ifstream file {path};
        if (!file.is_open())
        {
            throw std::runtime_error("The configured TLS " + std::string {what} + " '" + path +
                                     "' is missing or unreadable");
        }
    }

    // Client-certificate verify callback for ClientVerificationMode::Full: on top of the
    // standard chain-of-trust check (preverified), the peer's connection IP must also
    // match an IP entry in the leaf certificate's subjectAltName.
    bool verifyClientCertificateIp(bool preverified, asio::ssl::verify_context& verifyCtx)
    {
        if (!preverified)
        {
            return false;
        }

        X509_STORE_CTX* storeCtx = verifyCtx.native_handle();

        // Only the leaf (peer) certificate carries the IP the client connected from;
        // intermediate/CA certificates in the chain are only chain-validated.
        if (X509_STORE_CTX_get_error_depth(storeCtx) != 0)
        {
            return true;
        }

        auto* ssl = static_cast<SSL*>(X509_STORE_CTX_get_ex_data(storeCtx, SSL_get_ex_data_X509_STORE_CTX_idx()));

        if (ssl == nullptr)
        {
            return false;
        }

        const int fd = SSL_get_fd(ssl);
        sockaddr_storage peerAddress {};
        socklen_t peerAddressLen = sizeof(peerAddress);

        if (fd < 0 || getpeername(fd, reinterpret_cast<sockaddr*>(&peerAddress), &peerAddressLen) != 0)
        {
            return false;
        }

        char peerIp[INET6_ADDRSTRLEN] {};

        if (peerAddress.ss_family == AF_INET)
        {
            inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in*>(&peerAddress)->sin_addr, peerIp, sizeof(peerIp));
        }
        else if (peerAddress.ss_family == AF_INET6)
        {
            inet_ntop(AF_INET6, &reinterpret_cast<sockaddr_in6*>(&peerAddress)->sin6_addr, peerIp, sizeof(peerIp));
        }
        else
        {
            return false;
        }

        X509* peerCertificate = X509_STORE_CTX_get_current_cert(storeCtx);

        return peerCertificate != nullptr && X509_check_ip_asc(peerCertificate, peerIp, 0) == 1;
    }

    asio::ssl::context createTlsContext(const remoted::http::HttpServerConfig& config)
    {
        checkTlsFileReadable(config.certificatePath, "certificate");
        checkTlsFileReadable(config.privateKeyPath, "private key");

        asio::ssl::context context {asio::ssl::context::tls_server};

        context.set_options(asio::ssl::context::default_workarounds | asio::ssl::context::no_sslv2 |
                            asio::ssl::context::no_sslv3);

        // Require TLS 1.3 as the minimum protocol version.
        if (SSL_CTX_set_min_proto_version(context.native_handle(), TLS1_3_VERSION) != 1)
        {
            throw std::runtime_error("Unable to configure TLS 1.3 as the minimum protocol version");
        }

        if (!config.ciphers.empty() && SSL_CTX_set_cipher_list(context.native_handle(), config.ciphers.c_str()) != 1)
        {
            throw std::runtime_error("Unable to configure the requested TLS cipher list");
        }

        context.use_certificate_chain_file(config.certificatePath);
        context.use_private_key_file(config.privateKeyPath, asio::ssl::context::pem);

        if (SSL_CTX_check_private_key(context.native_handle()) != 1)
        {
            throw std::runtime_error("The configured TLS private key does not match the certificate");
        }

        // Client-certificate verification (mTLS). Both Certificate and Full modes
        // require a CA to validate the presented client certificate against; Full
        // additionally checks the peer IP against the certificate.
        if (config.verificationMode != remoted::http::ClientVerificationMode::None)
        {
            if (config.caPath.empty())
            {
                throw std::runtime_error("verification_mode requires a CA certificate (ca) to be configured");
            }

            context.load_verify_file(config.caPath);
            context.set_verify_mode(asio::ssl::verify_peer | asio::ssl::verify_fail_if_no_peer_cert);

            if (config.verificationMode == remoted::http::ClientVerificationMode::Full)
            {
                context.set_verify_callback(&verifyClientCertificateIp);
            }
        }

        return context;
    }

    /**
     * @brief The single owner of a request's payload buffer + its byte reservation.
     *
     * Holds the one physical copy of the request (body/target/headers, owned) plus
     * the in-flight byte reservation. Handed to handlers via a shared_ptr; the
     * neutral HttpRequest and the authenticated Payload are views/aliases onto it.
     * The instant the last owner drops it, the buffer is freed and the byte budget
     * is restored -- which is how a handler releases the payload early (drop the
     * request shared_ptr, or call Payload::release()) while the responder lives on.
     * The responder does NOT co-own it, so it is freed independently of the reply.
     */
    struct RequestContext
    {
        remoted::http::HttpRequest request;
        remoted::http::InFlightBudget::Reservation reservation;
    };

    using ResponseBuilder = restinio::response_builder_t<restinio::restinio_controlled_output_t>;

    /**
     * @brief Deferred responder that owns a pre-created RESTinio response builder.
     *
     * The builder is created up-front from the request: create_response() moves the
     * connection out of the request, so the RESTinio request handle -- and its body
     * buffer -- can be dropped immediately (before any handler runs), leaving no
     * second copy of the payload alive. The builder references nothing in the
     * request, so send() can complete the response later from any thread (RESTinio
     * marshals the write onto the connection's strand). send() is thread-safe and
     * only the first call takes effect.
     */
    class RestinioResponder final : public remoted::http::IHttpResponder
    {
    public:
        explicit RestinioResponder(const restinio::request_handle_t& request)
            : m_builder {request->create_response(restinio::status_ok())}
        {
        }

        void send(remoted::http::HttpResponse response) override
        {
            if (m_answered.test_and_set())
            {
                return; // Response already delivered; ignore extra calls.
            }

            m_builder.header().status_line(restinio::http_status_line_t {
                restinio::http_status_code_t {static_cast<std::uint16_t>(response.status)},
                reasonPhrase(response.status)});

            m_builder.append_header(restinio::http_field::server, "wazuh-manager-remoted");
            m_builder.append_header_date_field();

            for (const auto& [name, value] : response.headers)
            {
                m_builder.append_header(name, value);
            }

            m_builder.set_body(std::move(response.body));
            m_builder.done();
        }

    private:
        ResponseBuilder m_builder;
        std::atomic_flag m_answered = ATOMIC_FLAG_INIT;
    };

    struct Route
    {
        remoted::http::Method method;
        std::string path;
        remoted::http::RouteHandler handler;
        bool countAgainstBudget {true}; ///< When false, exempt from the in-flight byte budget (never 503'd).
    };

    // Last-resort 500 for the transport-level exception barriers below. Never throws: it is called
    // from catch handlers that may be dealing with bad_alloc, where a second throw would escape
    // onto a RESTinio I/O thread or the worker pool and terminate the process.
    void sendInternalErrorNoThrow(const std::shared_ptr<remoted::http::IHttpResponder>& responder) noexcept
    {
        if (!responder)
        {
            return;
        }
        try
        {
            // send-once: a no-op if the handler already answered before throwing.
            responder->send(remoted::http::HttpResponse::json(500, R"({"error":"Internal server error","code":500})"));
        }
        catch (...) // NOLINT(bugprone-empty-catch) -- nothing left to try; dropping the response
        {           // beats terminating the daemon. The connection closes on its own timeout.
        }
    }
} // namespace

namespace remoted::http
{

    struct RestinioHttpServer::Impl
    {
        std::mutex m_mutex;
        std::vector<Route> m_routes;
        HttpServerConfig m_config;
        ServerHandle m_server;
        std::unique_ptr<asio::thread_pool> m_workerPool;
        std::unique_ptr<InFlightBudget> m_budget;
        bool m_acceptingStopped {false}; ///< Guards stopAccepting()'s one-shot server->stop()/wait().

        /// Throttles the byte-budget rejection warning: it fires once per shed request, which under
        /// a real burst means thousands per second. One line per window, carrying the count.
        remoted::common::LogThrottle m_budgetRejectThrottle;

        std::unique_ptr<Router> buildRouter()
        {
            auto requestRouter = std::make_unique<Router>();

            for (const auto& route : m_routes)
            {
                auto* pool = m_workerPool.get();
                auto* budget = m_budget.get();
                auto* budgetThrottle = &m_budgetRejectThrottle;
                auto handler = route.handler;
                const auto method = route.method;
                const auto countAgainstBudget = route.countAgainstBudget;

                requestRouter->add_handler(
                    toRestinioMethod(method),
                    route.path,
                    [pool, budget, budgetThrottle, handler, method, countAgainstBudget](
                        auto request, auto) -> restinio::request_handling_status_t
                    {
                        // Transport-level exception barrier, covering every registered route at
                        // once (including the liveness probe, whose handler is a bare lambda).
                        // It MUST be catch (...): RESTinio's own after_read() already catches
                        // std::exception and closes the connection, so the only exposure left is a
                        // non-std::exception, which would reach a noexcept frame and terminate the
                        // whole daemon. Everything here runs on a RESTinio I/O thread.
                        std::shared_ptr<RestinioResponder> responder;
                        try
                        {
                            // Reserve the request's payload against the global in-flight budget
                            // before doing anything else. If it's exhausted, shed load with a plain
                            // 503 (the agent runs its own retry/backoff) instead of letting the
                            // worker-pool queue grow without bound. Routes flagged exempt (e.g. the
                            // liveness probe) skip it.
                            InFlightBudget::Reservation reservation;
                            if (countAgainstBudget)
                            {
                                auto reserved = budget->tryReserve(request->body().size() + PER_REQUEST_OVERHEAD);
                                if (!reserved)
                                {
                                    // Throttled: this fires once per shed request, so a real burst
                                    // would otherwise flood wazuh-manager.log  with thousands of identical
                                    // lines. The count tells the operator the scale of the shedding.
                                    if (const auto shed = budgetThrottle->record())
                                    {
                                        LOGFN_WARN(logFn(),
                                                   "In-flight request memory budget exhausted: shed %llu request(s) "
                                                   "with 503 in the last %d s (%zu request(s) currently resident, "
                                                   "%zu byte(s) still available). Consider increasing the value of "
                                                   "'max_inflight_bytes'.",
                                                   static_cast<unsigned long long>(shed.total),
                                                   remoted::common::LogThrottle::kDefaultWindowSeconds,
                                                   budget->inFlightCount(),
                                                   budget->availableBytes());
                                    }
                                    return request->create_response(restinio::status_service_unavailable())
                                        .append_header(restinio::http_field::content_type, "application/json")
                                        .set_body(R"({"error":"Service unavailable","code":503})")
                                        .connection_close()
                                        .done();
                                }
                                reservation = std::move(*reserved);
                            }

                            // Copy the payload ONCE into our own buffer (owned by the context) and attach
                            // the reservation (empty/no-op for exempt routes). This is the single resident copy.
                            auto context = std::make_shared<RequestContext>(
                                RequestContext {makeHttpRequest(method, request), std::move(reservation)});

                            // Create the response builder up-front (moves the connection out of
                            // the request), then drop the RESTinio handle right here -- freeing
                            // its body buffer on the I/O thread, before the request ever waits in
                            // the worker queue. Only our single copy remains.
                            responder = std::make_shared<RestinioResponder>(request);
                            request.reset();

                            // Hand off to a worker thread (deferred response) and cede SOLE
                            // ownership of the context to the handler, so a handler that drops the
                            // request (or releases its payload) frees the buffer + budget at once,
                            // while the responder lives on to reply.
                            //
                            // `responder` is captured by COPY, not moved: the barrier below needs it
                            // to still be valid to answer 500 when the handler throws. That costs one
                            // atomic refcount bump per request, and buys the alternative not being
                            // "agent's connection hangs until http_request_timeout".
                            asio::post(*pool,
                                       [handler, context = std::move(context), responder]() mutable
                                       {
                                           try
                                           {
                                               auto neutralRequest =
                                                   std::shared_ptr<const HttpRequest>(context, &context->request);
                                               context.reset(); // neutralRequest is now the sole context owner
                                               handler(std::move(neutralRequest), responder);
                                           }
                                           catch (const std::exception& e)
                                           {
                                               // asio::thread_pool terminates the process on any
                                               // exception escaping a posted handler.
                                               LOGFN_ERROR(logFn(), "Route handler threw, answering 500: %s", e.what());
                                               sendInternalErrorNoThrow(responder);
                                           }
                                           catch (...)
                                           {
                                               LOGFN_ERROR(logFn(),
                                                           "Route handler threw a non-standard exception, "
                                                           "answering 500.");
                                               sendInternalErrorNoThrow(responder);
                                           }
                                       });

                            return restinio::request_accepted();
                        }
                        catch (const std::exception& e)
                        {
                            LOGFN_ERROR(logFn(), "Could not dispatch the request: %s", e.what());
                        }
                        catch (...)
                        {
                            LOGFN_ERROR(logFn(), "Could not dispatch the request: non-standard exception.");
                        }

                        // Once the responder exists the connection has been moved into it, so that
                        // is the only way left to answer. If we threw before that, the request
                        // handle is still intact but we deliberately do not touch it here: RESTinio
                        // closes the connection on a rejected request, which is the safe outcome
                        // under the memory pressure that most plausibly got us here.
                        sendInternalErrorNoThrow(responder);
                        return restinio::request_rejected();
                    });
            }

            requestRouter->non_matched_request_handler(
                [](auto request)
                {
                    return request->create_response(restinio::status_not_found())
                        .append_header(restinio::http_field::content_type, "application/json")
                        .set_body(R"({"error":"not_found"})")
                        .connection_close()
                        .done();
                });

            return requestRouter;
        }
    };

    RestinioHttpServer::RestinioHttpServer()
        : m_impl {std::make_unique<Impl>()}
    {
    }

    RestinioHttpServer::~RestinioHttpServer()
    {
        stop();
    }

    void
    RestinioHttpServer::addRoute(Method method, const std::string& path, RouteHandler handler, bool countAgainstBudget)
    {
        std::lock_guard<std::mutex> lock {m_impl->m_mutex};

        if (m_impl->m_server)
        {
            throw std::logic_error("Cannot register a route while the HTTP server is running");
        }

        m_impl->m_routes.push_back(Route {method, path, std::move(handler), countAgainstBudget});
    }

    void RestinioHttpServer::start(const HttpServerConfig& config)
    {
        std::lock_guard<std::mutex> lock {m_impl->m_mutex};

        if (m_impl->m_server)
        {
            LOGFN_WARN(logFn(), "HTTP server is already running.");
            return;
        }

        m_impl->m_config = config;

        // Build the TLS context first: it validates cert/key and may throw before we
        // allocate any worker threads.
        auto tlsContext = createTlsContext(config);

        m_impl->m_workerPool = std::make_unique<asio::thread_pool>(config.workerThreads);

        // In-flight byte budget. Clamp it to at least one max-size request (+overhead) so a
        // misconfigured tiny value can't reject every request; 0 leaves the limit disabled.
        std::size_t maxInFlight = config.maxInFlightBytes;
        if (maxInFlight != 0 && maxInFlight < config.maxBodySize + PER_REQUEST_OVERHEAD)
        {
            LOGFN_WARN(logFn(),
                       "Configured in-flight budget (%zu bytes) is below one max-size request; raising it to %zu.",
                       maxInFlight,
                       config.maxBodySize + PER_REQUEST_OVERHEAD);
            maxInFlight = config.maxBodySize + PER_REQUEST_OVERHEAD;
        }
        m_impl->m_budget = std::make_unique<InFlightBudget>(maxInFlight);

        auto requestRouter = m_impl->buildRouter();

        const bool bindsIpv6 = isIpv6Address(config.bindAddress);

        if (config.dualStackMode != DualStackMode::Unset && !bindsIpv6)
        {
            LOGFN_WARN(logFn(),
                       "dual_stack is only meaningful for an IPv6 bind address; ignoring it for '%s'.",
                       config.bindAddress.c_str());
        }

        restinio::server_settings_t<ServerTraits> settings;

        settings.address(config.bindAddress)
            .port(config.port)
            // No .protocol() call: RESTinio derives the actual socket family from the
            // address itself (asio::ip::make_address() autodetects IPv4 vs IPv6), so
            // config.bindAddress works for either -- a literal .protocol(tcp::v4())
            // here would only matter if no address were ever set, which never happens.
            .acceptor_options_setter(
                [dualStackMode = config.dualStackMode, bindsIpv6](auto& options)
                {
                    // Set SO_REUSEADDR on the listening socket so a restart can rebind the
                    // port immediately instead of failing with EADDRINUSE while a previous
                    // socket lingers in TIME_WAIT. (RESTinio enables this by default; kept
                    // explicit for intent.)
                    options.set_option(asio::ip::tcp::acceptor::reuse_address(true));

                    // IPV6_V6ONLY only applies to an IPv6 socket; a no-op (and possibly an
                    // error) on IPv4, so only touch it when the bind address is IPv6.
                    if (bindsIpv6 && dualStackMode != DualStackMode::Unset)
                    {
                        options.set_option(asio::ip::v6_only(dualStackMode == DualStackMode::Disabled));
                    }
                })
            .request_handler(std::move(requestRouter))
            .tls_context(std::move(tlsContext))
            .buffer_size(config.bufferSize)
            // read_next_http_message_timelimit also stands in for a TLS handshake timeout:
            // it starts counting as soon as the connection is established, before anything
            // has been read, so it already bounds a stalled/never-completed handshake.
            .read_next_http_message_timelimit(std::chrono::seconds {config.readTimeoutSec})
            .write_http_response_timelimit(std::chrono::seconds {config.writeTimeoutSec})
            .handle_request_timeout(std::chrono::seconds {config.requestTimeoutSec})
            .max_pipelined_requests(config.maxPipelinedRequests)
            .concurrent_accepts_count(config.concurrentAccepts)
            // Bound simultaneous connections so the read-phase peak (bodies still being
            // received, before they reach the in-flight budget) can't grow unbounded.
            .max_parallel_connections(config.maxParallelConnections)
            .separate_accept_and_create_connect(true)
            .incoming_http_msg_limits(restinio::incoming_http_msg_limits_t {}
                                          .max_url_size(config.maxUrlSize)
                                          .max_field_name_size(config.maxHeaderNameSize)
                                          .max_field_value_size(config.maxHeaderValueSize)
                                          .max_field_count(config.maxHeaderCount)
                                          .max_body_size(config.maxBodySize));

        try
        {
            // run_async returns once the listener is up, or throws on bind/TLS failure.
            m_impl->m_server =
                restinio::run_async<ServerTraits>(restinio::own_io_context(), std::move(settings), config.ioThreads);
        }
        catch (...)
        {
            // Tear down the worker pool and budget so a failed start leaves nothing running.
            m_impl->m_workerPool->stop();
            m_impl->m_workerPool->join();
            m_impl->m_workerPool.reset();
            m_impl->m_budget.reset();
            throw;
        }

        const auto displayAddress = formatHostForDisplay(config.bindAddress);
        LOGFN_INFO(logFn(),
                   "HTTP server listening on https://%s:%u (%zu I/O thread(s), %zu worker thread(s), max body %zu "
                   "bytes, in-flight budget %zu bytes%s, max %zu connection(s)).",
                   displayAddress.c_str(),
                   static_cast<unsigned int>(config.port),
                   config.ioThreads,
                   config.workerThreads,
                   config.maxBodySize,
                   maxInFlight,
                   maxInFlight == 0 ? " (disabled)" : "",
                   config.maxParallelConnections);
    }

    void RestinioHttpServer::stopAccepting() noexcept
    {
        // IMPORTANT: swallowing an exception here voids the shutdown-ordering guarantee documented
        // on IHttpServer::stopAccepting() -- if server->wait() or workerPool->join() failed, a
        // RouteHandler may still be running when the caller proceeds to tear down the downstream
        // client, which is the exact use-after-free that shutdownRace_test.cpp exists to catch.
        // It is still the right call inside a noexcept teardown: the alternative is terminating
        // the daemon during a normal stop, and there is no recovery available here. Do not read
        // this catch as "the ordering guarantee is unconditional" -- it is best-effort.
        try
        {
            // Raw, non-owning: deliberately does NOT move m_server out, so the io_context it owns
            // stays alive. That's what lets a response racing this shutdown (already handed off to a
            // downstream forwarder before this call) still safely reach the connection's strand --
            // only stop() below actually tears the io_context down.
            decltype(m_impl->m_server.get()) server = nullptr;
            std::unique_ptr<asio::thread_pool> workerPool;
            std::string bindAddress;
            std::uint16_t port {0};

            {
                std::lock_guard<std::mutex> lock {m_impl->m_mutex};

                if (!m_impl->m_server || m_impl->m_acceptingStopped)
                {
                    return;
                }
                m_impl->m_acceptingStopped = true;

                bindAddress = m_impl->m_config.bindAddress;
                port = m_impl->m_config.port;
                server = m_impl->m_server.get();
                workerPool = std::move(m_impl->m_workerPool);
            }

            // Stop accepting/serving first, then drain in-flight handler work (context B). Once this
            // returns, no RouteHandler -- and therefore no downstream forward() -- will ever run again.
            server->stop();
            server->wait();

            if (workerPool)
            {
                workerPool->join();
            }

            LOGFN_INFO(logFn(),
                       "HTTP server no longer accepting on %s:%u.",
                       bindAddress.c_str(),
                       static_cast<unsigned int>(port));
        }
        catch (const std::exception& e)
        {
            LOGFN_ERROR(logFn(),
                        "Failure while stopping the HTTP server's acceptor: %s. In-flight requests may not have "
                        "been fully drained.",
                        e.what());
        }
        catch (...)
        {
            LOGFN_ERROR(logFn(),
                        "Non-standard exception while stopping the HTTP server's acceptor. In-flight requests may "
                        "not have been fully drained.");
        }
    }

    void RestinioHttpServer::stop() noexcept
    {
        stopAccepting(); // no-op if already done

        // noexcept: the lock, the ServerHandle destructor (which tears down the io_context) and the
        // logging call below can all throw.
        try
        {
            ServerHandle server;
            {
                std::lock_guard<std::mutex> lock {m_impl->m_mutex};
                if (!m_impl->m_server)
                {
                    return;
                }
                server = std::move(m_impl->m_server);
            }
            // server destructs here, releasing the io_context and any connections it still owns.
            // Safe now: stopAccepting() already guaranteed nothing will touch it again.
            LOGFN_INFO(logFn(), "HTTP server fully stopped.");
        }
        catch (const std::exception& e)
        {
            LOGFN_ERROR(logFn(), "Failure while tearing down the HTTP server: %s.", e.what());
        }
        catch (...)
        {
            LOGFN_ERROR(logFn(), "Non-standard exception while tearing down the HTTP server.");
        }
    }

    std::unique_ptr<IHttpServer> makeHttpServer()
    {
        return std::make_unique<RestinioHttpServer>();
    }

} // namespace remoted::http
