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

#include "loggerHelper.h"

#include <restinio/core.hpp>
#include <restinio/http_server_run.hpp>
#include <restinio/router/express.hpp>
#include <restinio/tls.hpp>

#include <openssl/ssl.h>

#include <algorithm>
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

namespace asio = restinio::asio_ns;
namespace router = restinio::router;

using Router = router::express_router_t<>;

using ServerTraits =
    restinio::tls_traits_t<restinio::asio_timer_manager_t, restinio::null_logger_t, Router>;

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
        {
            request.headers.emplace(std::string {field.name()}, std::string {field.value()});
        });

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
 * @brief Deferred responder wrapping a RESTinio request handle.
 *
 * send() may be called from any thread and only the first call takes effect, so
 * a handler can hold the responder, do slow work off the I/O threads, and reply
 * once it is done.
 */
class RestinioResponder final : public remoted::http::IHttpResponder
{
public:
    explicit RestinioResponder(restinio::request_handle_t request)
        : m_request {std::move(request)}
    {
    }

    void send(remoted::http::HttpResponse response) override
    {
        if (m_answered.test_and_set())
        {
            return; // Response already delivered; ignore extra calls.
        }

        auto restinioResponse = m_request->create_response(restinio::http_status_line_t {
            restinio::http_status_code_t {static_cast<std::uint16_t>(response.status)},
            reasonPhrase(response.status)});

        restinioResponse.append_header(restinio::http_field::server, "wazuh-manager-remoted");
        restinioResponse.append_header_date_field();

        for (const auto& [name, value] : response.headers)
        {
            restinioResponse.append_header(name, value);
        }

        restinioResponse.set_body(std::move(response.body));
        restinioResponse.done();
    }

private:
    restinio::request_handle_t m_request;
    std::atomic_flag m_answered = ATOMIC_FLAG_INIT;
};

struct Route
{
    remoted::http::Method method;
    std::string path;
    remoted::http::RouteHandler handler;
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

    std::unique_ptr<Router> buildRouter()
    {
        auto requestRouter = std::make_unique<Router>();

        for (const auto& route : m_routes)
        {
            auto* pool = m_workerPool.get();
            auto handler = route.handler;
            const auto method = route.method;

            requestRouter->add_handler(
                toRestinioMethod(method),
                route.path,
                [pool, handler, method](auto request, auto) -> restinio::request_handling_status_t
                {
                    // Hand the request off to a worker thread and free the I/O
                    // thread immediately (deferred response).
                    asio::post(*pool,
                               [handler, method, request = std::move(request)]() mutable
                               {
                                   auto responder = std::make_shared<RestinioResponder>(request);
                                   handler(makeHttpRequest(method, request), std::move(responder));
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

void RestinioHttpServer::addRoute(Method method, const std::string& path, RouteHandler handler)
{
    std::lock_guard<std::mutex> lock {m_impl->m_mutex};

    if (m_impl->m_server)
    {
        throw std::logic_error("Cannot register a route while the HTTP server is running");
    }

    m_impl->m_routes.push_back(Route {method, path, std::move(handler)});
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

    auto requestRouter = m_impl->buildRouter();

    restinio::server_settings_t<ServerTraits> settings;

    settings.address(config.bindAddress)
        .port(config.port)
        .protocol(asio::ip::tcp::v4())
        .request_handler(std::move(requestRouter))
        .tls_context(std::move(tlsContext))
        .buffer_size(8192)
        .read_next_http_message_timelimit(std::chrono::seconds {10})
        .write_http_response_timelimit(std::chrono::seconds {10})
        .handle_request_timeout(std::chrono::seconds {30})
        .max_pipelined_requests(4)
        .concurrent_accepts_count(std::min<std::size_t>(config.ioThreads, 8))
        .separate_accept_and_create_connect(true)
        .incoming_http_msg_limits(restinio::incoming_http_msg_limits_t {}
                                      .max_url_size(2048)
                                      .max_field_name_size(256)
                                      .max_field_value_size(8192)
                                      .max_field_count(64)
                                      .max_body_size(config.maxBodySize));

    try
    {
        // run_async returns once the listener is up, or throws on bind/TLS failure.
        m_impl->m_server = restinio::run_async<ServerTraits>(
            restinio::own_io_context(), std::move(settings), config.ioThreads);
    }
    catch (...)
    {
        // Tear down the worker pool so a failed start leaves nothing running.
        m_impl->m_workerPool->stop();
        m_impl->m_workerPool->join();
        m_impl->m_workerPool.reset();
        throw;
    }

    LOGFN_INFO(m_impl->m_logFn,
               "HTTP server listening on https://%s:%u (%zu I/O thread(s), %zu worker thread(s), max body %zu "
               "bytes).",
               config.bindAddress.c_str(),
               static_cast<unsigned int>(config.port),
               config.ioThreads,
               config.workerThreads,
               config.maxBodySize);
}

void RestinioHttpServer::stop() noexcept
{
    ServerHandle server;
    std::unique_ptr<asio::thread_pool> workerPool;
    std::string bindAddress;
    std::uint16_t port {0};

    {
        std::lock_guard<std::mutex> lock {m_impl->m_mutex};

        if (!m_impl->m_server)
        {
            return;
        }

        bindAddress = m_impl->m_config.bindAddress;
        port = m_impl->m_config.port;
        server = std::move(m_impl->m_server);
        workerPool = std::move(m_impl->m_workerPool);
    }

    // Stop accepting/serving first, then drain in-flight handler work.
    server->stop();
    server->wait();

    if (workerPool)
    {
        workerPool->join();
    }

    LOGFN_INFO(m_impl->m_logFn, "HTTP server stopped on %s:%u.", bindAddress.c_str(), static_cast<unsigned int>(port));
}

std::unique_ptr<IHttpServer> makeHttpServer()
{
    return std::make_unique<RestinioHttpServer>();
}

} // namespace remoted::http
