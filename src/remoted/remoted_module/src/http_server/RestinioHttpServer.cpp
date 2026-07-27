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
#include "httpServerFactory.hpp"
#include "inFlightBudget.hpp"

#include "loggerHelper.h"

#include <restinio/core.hpp>
#include <restinio/http_server_run.hpp>
#include <restinio/router/express.hpp>
#include <restinio/tls.hpp>

#include <openssl/ssl.h>

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

    // Fixed per-request memory charged on top of the body so that a flood of tiny-body
    // requests still consumes the in-flight budget (headers map, neutral request struct,
    // RESTinio handle bookkeeping). A coarse estimate on purpose.
    constexpr std::size_t PER_REQUEST_OVERHEAD {4U * 1024U};

    namespace asio = restinio::asio_ns;
    namespace router = restinio::router;

    using Router = router::express_router_t<>;

    // Enable RESTinio's connection-count limiter so max_parallel_connections() is honored
    // (the default noop limiter turns that setter into a compile-time error).
    struct ServerTraits : public restinio::tls_traits_t<restinio::asio_timer_manager_t, restinio::null_logger_t, Router>
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

    // Build the neutral request view from a RESTinio request handle.
    remoted::http::HttpRequest makeHttpRequest(remoted::http::Method method, const restinio::request_handle_t& req)
    {
        remoted::http::HttpRequest request;
        request.method = method;
        // Raw request target (path + query, exactly as received): the auth layer
        // signs it verbatim, so it must not be path-only or normalized.
        request.target = req->header().request_target();
        request.body = req->body();

        req->header().for_each_field(
            [&request](const restinio::http_header_field_t& field)
            { request.headers.emplace(std::string {field.name()}, std::string {field.value()}); });

        return request;
    }

    asio::ssl::context createTlsContext(const remoted::http::HttpServerConfig& config)
    {
        asio::ssl::context context {asio::ssl::context::tls_server};

        context.set_options(asio::ssl::context::default_workarounds | asio::ssl::context::no_sslv2 |
                            asio::ssl::context::no_sslv3);

        // Accept TLS 1.2 and, when available, TLS 1.3.
        if (SSL_CTX_set_min_proto_version(context.native_handle(), TLS1_2_VERSION) != 1)
        {
            throw std::runtime_error("Unable to configure TLS 1.2 as the minimum protocol version");
        }

        context.use_certificate_chain_file(config.certificatePath);
        context.use_private_key_file(config.privateKeyPath, asio::ssl::context::pem);

        if (SSL_CTX_check_private_key(context.native_handle()) != 1)
        {
            throw std::runtime_error("The configured TLS private key does not match the certificate");
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
} // namespace

namespace remoted::http
{

    struct RestinioHttpServer::Impl
    {
        const LogFn m_logFn {HTTP_SERVER_LOGTAG};

        std::mutex m_mutex;
        std::vector<Route> m_routes;
        HttpServerConfig m_config;
        ServerHandle m_server;
        std::unique_ptr<asio::thread_pool> m_workerPool;
        std::unique_ptr<InFlightBudget> m_budget;
        bool m_acceptingStopped {false}; ///< Guards stopAccepting()'s one-shot server->stop()/wait().

        std::unique_ptr<Router> buildRouter()
        {
            auto requestRouter = std::make_unique<Router>();

            for (const auto& route : m_routes)
            {
                auto* pool = m_workerPool.get();
                auto* budget = m_budget.get();
                auto handler = route.handler;
                const auto method = route.method;
                const auto countAgainstBudget = route.countAgainstBudget;

                requestRouter->add_handler(
                    toRestinioMethod(method),
                    route.path,
                    [pool, budget, handler, method, countAgainstBudget](auto request,
                                                                        auto) -> restinio::request_handling_status_t
                    {
                        // Reserve the request's payload against the global in-flight budget before
                        // doing anything else. If it's exhausted, shed load with a plain 503 (the
                        // agent runs its own retry/backoff) instead of letting the worker-pool queue
                        // grow without bound. Routes flagged exempt (e.g. the liveness probe) skip it.
                        InFlightBudget::Reservation reservation;
                        if (countAgainstBudget)
                        {
                            auto reserved = budget->tryReserve(request->body().size() + PER_REQUEST_OVERHEAD);
                            if (!reserved)
                            {
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
                        auto responder = std::make_shared<RestinioResponder>(request);
                        request.reset();

                        // Hand off to a worker thread (deferred response) and cede SOLE
                        // ownership of the context to the handler, so a handler that drops the
                        // request (or releases its payload) frees the buffer + budget at once,
                        // while the responder lives on to reply.
                        asio::post(*pool,
                                   [handler, context = std::move(context), responder = std::move(responder)]() mutable
                                   {
                                       auto neutralRequest =
                                           std::shared_ptr<const HttpRequest>(context, &context->request);
                                       context.reset(); // neutralRequest is now the sole context owner
                                       handler(std::move(neutralRequest), std::move(responder));
                                   });

                        return restinio::request_accepted();
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
            LOGFN_WARN(m_impl->m_logFn, "HTTP server is already running.");
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
            LOGFN_WARN(m_impl->m_logFn,
                       "Configured in-flight budget (%zu bytes) is below one max-size request; raising it to %zu.",
                       maxInFlight,
                       config.maxBodySize + PER_REQUEST_OVERHEAD);
            maxInFlight = config.maxBodySize + PER_REQUEST_OVERHEAD;
        }
        m_impl->m_budget = std::make_unique<InFlightBudget>(maxInFlight);

        auto requestRouter = m_impl->buildRouter();

        restinio::server_settings_t<ServerTraits> settings;

        settings.address(config.bindAddress)
            .port(config.port)
            .protocol(asio::ip::tcp::v4())
            // Set SO_REUSEADDR on the listening socket so a restart can rebind the port
            // immediately instead of failing with EADDRINUSE while a previous socket lingers
            // in TIME_WAIT. (RESTinio enables this by default; kept explicit for intent.)
            .acceptor_options_setter([](auto& options)
                                     { options.set_option(asio::ip::tcp::acceptor::reuse_address(true)); })
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

        LOGFN_INFO(m_impl->m_logFn,
                   "HTTP server listening on https://%s:%u (%zu I/O thread(s), %zu worker thread(s), max body %zu "
                   "bytes, in-flight budget %zu bytes%s, max %zu connection(s)).",
                   config.bindAddress.c_str(),
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

        LOGFN_INFO(m_impl->m_logFn,
                   "HTTP server no longer accepting on %s:%u.",
                   bindAddress.c_str(),
                   static_cast<unsigned int>(port));
    }

    void RestinioHttpServer::stop() noexcept
    {
        stopAccepting(); // no-op if already done

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
        LOGFN_INFO(m_impl->m_logFn, "HTTP server fully stopped.");
    }

    std::unique_ptr<IHttpServer> makeHttpServer()
    {
        return std::make_unique<RestinioHttpServer>();
    }

} // namespace remoted::http
