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

#include <cctype>
#include <cstdint>
#include <ctime>
#include <string>
#include <utility>
#include <variant>

namespace
{
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

remoted::http::HttpResponse errorResponse(wazuh_auth::AuthError err)
{
    const auto pe = wazuh_auth::publicErrorFor(err);
    std::string body {R"({"error":")"};
    body += pe.message; // static, quote/backslash-free messages
    body += R"(","code":)";
    body += std::to_string(pe.status);
    body += "}";
    return remoted::http::HttpResponse::json(pe.status, std::move(body));
}
} // namespace

namespace remoted::http
{

AuthGateway::AuthGateway(wazuh_auth::AuthConfig config, std::shared_ptr<wazuh_auth::IAgentKeyResolver> resolver)
    : m_middleware {std::make_shared<wazuh_auth::AuthMiddleware>(std::move(config), std::move(resolver))}
{
}

void AuthGateway::addAuthenticatedRoute(IHttpServer& server,
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

            if (std::holds_alternative<wazuh_auth::AuthError>(begin))
            {
                responder->send(errorResponse(std::get<wazuh_auth::AuthError>(begin)));
                return;
            }

            auto session = std::get<wazuh_auth::AuthMiddleware::Session>(std::move(begin));

            // Step 6: feed the exact body bytes (enforces the max-body cap).
            if (!request.body.empty())
            {
                const auto bodyError = session.update(reinterpret_cast<const std::uint8_t*>(request.body.data()),
                                                      request.body.size());
                if (bodyError != wazuh_auth::AuthError::None)
                {
                    responder->send(errorResponse(bodyError));
                    return;
                }
            }

            // Step 7: finalize + constant-time MAC comparison.
            auto finished = session.finish();
            if (std::holds_alternative<wazuh_auth::AuthError>(finished))
            {
                responder->send(errorResponse(std::get<wazuh_auth::AuthError>(finished)));
                return;
            }

            // Authenticated: hand the verified request to the endpoint handler.
            responder->send(handler(std::get<wazuh_auth::AuthenticatedRequest>(finished)));
        });
}

} // namespace remoted::http
