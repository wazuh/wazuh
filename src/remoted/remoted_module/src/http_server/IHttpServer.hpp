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
    std::string target;                                    ///< Request path (without query).
    std::string body;                                      ///< Raw request body.
    std::unordered_map<std::string, std::string> headers;  ///< Lower-cased header name -> value.
};

/**
 * @brief Neutral HTTP response produced by a handler.
 */
struct HttpResponse
{
    int status {200};                                          ///< HTTP status code.
    std::string body;                                          ///< Response body.
    std::vector<std::pair<std::string, std::string>> headers;  ///< Extra headers (verbatim order).

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
 */
using RouteHandler = std::function<void(const HttpRequest&, std::shared_ptr<IHttpResponder>)>;

/**
 * @brief Configuration for the HTTP(S) server, decoupled from the C ABI struct.
 */
struct HttpServerConfig
{
    std::string bindAddress {"127.0.0.1"};  ///< Listen address.
    std::uint16_t port {9443};              ///< Listen port.
    std::string certificatePath;            ///< TLS certificate chain (PEM) path.
    std::string privateKeyPath;             ///< TLS private key (PEM) path.
    std::size_t ioThreads {2};              ///< RESTinio/asio I/O threads (accept + read/write).
    std::size_t workerThreads {4};          ///< Handler worker-pool size (blocking work offload).
    std::size_t maxBodySize {16U * 1024U * 1024U}; ///< Transport hard cap (backstop above the auth body limit).
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
     * @param method  HTTP verb to match.
     * @param path    Path to match (implementation routing syntax).
     * @param handler Handler invoked on a match.
     */
    virtual void addRoute(Method method, const std::string& path, RouteHandler handler) = 0;

    /**
     * @brief Start listening. Throws on bind/TLS/configuration failure.
     *
     * @param config Server configuration.
     */
    virtual void start(const HttpServerConfig& config) = 0;

    /**
     * @brief Stop the server and release its threads. Safe if never started.
     */
    virtual void stop() noexcept = 0;
};

} // namespace remoted::http

#endif // _REMOTED_HTTP_SERVER_INTERFACE_HPP
