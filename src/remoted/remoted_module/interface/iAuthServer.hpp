/*
 * Wazuh auth middleware (framework-agnostic)
 * Copyright (C) 2015, Wazuh Inc.
 * July 20, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <functional>
#include <memory>
#include <string>
#include <string_view>

#include "authTypes.hpp"
#include "iAgentKeyResolver.hpp"
#include "serverConfig.hpp"

namespace wazuh_auth
{

    /// HTTP method of an authenticated request, as matched by IAuthServer::addRoute.
    enum class Method
    {
        GET,
        POST,
        PUT,
        DELETE,
        ERROR_METHOD
    };

    /**
     * @brief Render a Method as its HTTP verb string.
     *
     * @param method Method to render.
     * @return Static string; "ERROR_METHOD" for an out-of-range value.
     */
    constexpr const char* methodToStr(Method method)
    {
        switch (method)
        {
            case Method::GET: return "GET";
            case Method::POST: return "POST";
            case Method::PUT: return "PUT";
            case Method::DELETE: return "DELETE";
            default: return "ERROR_METHOD";
        }
    }

    /**
     * @brief Parse an HTTP verb string into a Method.
     *
     * @param str HTTP verb, as read from the request line (e.g. "POST").
     * @return The matching Method, or Method::ERROR_METHOD if unrecognized.
     */
    inline Method strToMethod(std::string_view str)
    {
        if (str == "GET")
            return Method::GET;
        if (str == "POST")
            return Method::POST;
        if (str == "PUT")
            return Method::PUT;
        if (str == "DELETE")
            return Method::DELETE;
        return Method::ERROR_METHOD;
    }

    /**
     * @brief Response an endpoint handler returns to be written back to the client.
     */
    struct HttpResponse
    {
        int status = 200;                             ///< HTTP status code.
        std::string body;                             ///< Response body, written verbatim.
        std::string contentType = "application/json"; ///< Value of the Content-Type header.

        /// Convenience for the common 200-with-empty-body case.
        static HttpResponse ok()
        {
            return HttpResponse {200, "", "application/json"};
        }
    };

    /**
     * @brief Endpoint callback, invoked only after authentication succeeds.
     *
     * Endpoint code never sees a request payload until the MAC has been
     * verified.
     */
    using EndpointHandler = std::function<HttpResponse(const AuthenticatedRequest&)>;

    /**
     * @brief CRTP contract every HTTP transport must implement identically.
     *
     * Swapping the HTTP library (a Beast server, a RESTinio server, or any
     * future replacement) means writing a new class that satisfies this
     * interface -- endpoint code registered via addRoute() and the
     * framework-agnostic AuthMiddleware never change.
     *
     * Guarantees an implementation MUST uphold:
     *   - The request target passed to the auth layer is the raw bytes from
     *     the HTTP parser: no percent-decoding, no query reordering, no path
     *     normalization, no trailing-slash changes.
     *   - The request body is authenticated using the exact bytes received,
     *     before any parsing, line-ending normalization or re-serialization.
     *   - The auth layer's canonical-request construction and MAC comparison
     *     run entirely inside AuthMiddleware; the transport only supplies raw
     *     method/target/headers/body chunks and relays the verdict.
     *
     * @tparam ServerImpl Concrete transport providing the methods below.
     */
    template<class ServerImpl>
    class IAuthServer
    {
    public:
        virtual ~IAuthServer() = default;

        /**
         * @brief Apply the server's network, TLS and auth-protocol configuration.
         *
         * @param serverConfig Threading model, header/body limits, timeouts, backlog.
         * @param tlsConfig    TLS certificate/key material and minimum version.
         * @param authConfig   Auth-protocol tunables (protocol version, timestamp window, max body size).
         */
        void configure(const ServerConfig& serverConfig, const TlsConfig& tlsConfig, const AuthConfig& authConfig)
        {
            static_cast<ServerImpl*>(this)->configure(serverConfig, tlsConfig, authConfig);
        }

        /**
         * @brief Set the resolver AuthMiddleware uses to look up agent keys.
         *
         * @param resolver Must outlive the server.
         */
        void setKeyResolver(std::shared_ptr<IAgentKeyResolver> resolver)
        {
            static_cast<ServerImpl*>(this)->setKeyResolver(std::move(resolver));
        }

        /**
         * @brief Register an endpoint handler for a method + path.
         *
         * @param method  HTTP method to match.
         * @param route   Matched against the raw request target's path component
         *                only (the query string is not part of route matching,
         *                but IS part of the MAC).
         * @param handler Called only once authentication succeeds.
         */
        void addRoute(Method method, const std::string& route, EndpointHandler handler)
        {
            static_cast<ServerImpl*>(this)->addRoute(method, route, std::move(handler));
        }

        /**
         * @brief Start listening.
         *
         * @param useThread When true, the server runs its io_context on background
         *                  thread(s) and start() returns immediately; when false,
         *                  it runs on the calling thread and start() blocks.
         */
        void start(bool useThread = true)
        {
            static_cast<ServerImpl*>(this)->start(useThread);
        }

        /// Stop listening and join any background threads.
        void stop()
        {
            static_cast<ServerImpl*>(this)->stop();
        }

        /// @return Whether the server is currently listening.
        bool isRunning() const
        {
            return static_cast<const ServerImpl*>(this)->isRunning();
        }
    };

} // namespace wazuh_auth
