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

#include "authGateway.hpp"

#include "loggerHelper.h"

#include <cctype>
#include <cstdint>
#include <ctime>
#include <exception>
#include <string>
#include <utility>
#include <variant>

namespace
{
    constexpr auto AUTH_GATEWAY_LOGTAG {"wazuh-manager-remoted:endpoints"};

    // Client-visible 500 body, matching the {error,code} shape of the auth errors.
    constexpr auto INTERNAL_ERROR_BODY {R"({"error":"Internal server error","code":500})"};

    // Canonical uppercase HTTP verb for the MAC's canonical request.
    const char* methodToCanonical(remoted::http::Method method)
    {
        switch (method)
        {
            case remoted::http::Method::Get: return "GET";
            case remoted::http::Method::Post: return "POST";
            case remoted::http::Method::Put: return "PUT";
            case remoted::http::Method::Delete: return "DELETE";
            case remoted::http::Method::Patch: return "PATCH";
        }
        return "GET";
    }

    // Case-insensitive header lookup (HTTP header names are case-insensitive).
    std::string headerValue(const std::unordered_map<std::string, std::string>& headers, const std::string& lowerName)
    {
        for (const auto& [name, value] : headers)
        {
            if (name.size() != lowerName.size())
            {
                continue;
            }
            bool equal = true;
            for (std::size_t i = 0; i < name.size(); ++i)
            {
                if (static_cast<char>(std::tolower(static_cast<unsigned char>(name[i]))) != lowerName[i])
                {
                    equal = false;
                    break;
                }
            }
            if (equal)
            {
                return value;
            }
        }
        return {};
    }

    remoted::http::HttpResponse errorResponse(remoted::auth::AuthError err)
    {
        const auto pe = remoted::auth::publicErrorFor(err);
        std::string body {R"({"error":")"};
        body += pe.message; // static, quote/backslash-free messages
        body += R"(","code":)";
        body += std::to_string(pe.status);
        body += "}";
        return remoted::http::HttpResponse::json(pe.status, std::move(body));
    }
} // namespace

namespace remoted::endpoints
{

    AuthGateway::AuthGateway(remoted::auth::AuthConfig config, std::shared_ptr<remoted::auth::IAgentKeystore> keystore)
        : m_middleware {std::make_shared<remoted::auth::AuthMiddleware>(std::move(config), std::move(keystore))}
    {
    }

    void AuthGateway::addAuthenticatedRoute(remoted::http::IHttpServer& server,
                                            Method method,
                                            const std::string& path,
                                            AuthenticatedHandler handler)
    {
        auto middleware = m_middleware;
        const char* methodStr = methodToCanonical(method);

        server.addRoute(
            method,
            path,
            [middleware, methodStr, handler = std::move(handler)](const HttpRequest& request,
                                                                  std::shared_ptr<IHttpResponder> responder)
            {
                const std::string protocolVersion = headerValue(request.headers, "protocol-version");
                const std::string authorization = headerValue(request.headers, "authorization");

                // Steps 1-5: protocol-version + Authorization + timestamp window + key + CMAC prefix.
                auto begin = middleware->beginSession(protocolVersion,
                                                      authorization,
                                                      methodStr,
                                                      request.target,
                                                      static_cast<std::int64_t>(std::time(nullptr)));

                if (std::holds_alternative<remoted::auth::AuthError>(begin))
                {
                    responder->send(errorResponse(std::get<remoted::auth::AuthError>(begin)));
                    return;
                }

                auto session = std::get<remoted::auth::AuthMiddleware::Session>(std::move(begin));

                // Step 6: feed the exact body bytes (enforces the max-body cap).
                if (!request.body.empty())
                {
                    const auto bodyError =
                        session.update(reinterpret_cast<const std::uint8_t*>(request.body.data()), request.body.size());
                    if (bodyError != remoted::auth::AuthError::None)
                    {
                        responder->send(errorResponse(bodyError));
                        return;
                    }
                }

                // Step 7: finalize + constant-time MAC comparison.
                auto finished = session.finish();
                if (std::holds_alternative<remoted::auth::AuthError>(finished))
                {
                    responder->send(errorResponse(std::get<remoted::auth::AuthError>(finished)));
                    return;
                }

                // Authenticated: hand the verified request AND the responder to the
                // endpoint handler, which now owns delivering the response (inline or
                // asynchronously). The gateway no longer sends on the success path.
                //
                // A handler that throws must not escape onto the worker-pool thread
                // (asio would std::terminate the process). Catch it, log a warning and
                // answer 500. If the handler already sent a response before throwing,
                // the responder's send-once guarantee makes this 500 a no-op.
                try
                {
                    handler(std::get<remoted::auth::AuthenticatedRequest>(finished), responder);
                }
                catch (const std::exception& e)
                {
                    LOGFN_WARN(LogFn {AUTH_GATEWAY_LOGTAG}, "Endpoint handler threw an exception: %s", e.what());
                    responder->send(remoted::http::HttpResponse::json(500, INTERNAL_ERROR_BODY));
                }
                catch (...)
                {
                    LOGFN_WARN(LogFn {AUTH_GATEWAY_LOGTAG}, "Endpoint handler threw a non-standard exception.");
                    responder->send(remoted::http::HttpResponse::json(500, INTERNAL_ERROR_BODY));
                }
            });
    }

} // namespace remoted::endpoints
