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
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace
{
    constexpr auto AUTH_GATEWAY_LOGTAG {"wazuh-manager-remoted:endpoints"};

    // One shared instance instead of a `LogFn {TAG}` temporary per log call. Beyond avoiding a
    // heap allocation per line, it matters here specifically because these call sites are inside
    // catch handlers that may be handling bad_alloc -- allocating there could throw again and
    // escape onto the worker pool. loggerHelper.h stays out of authGateway.hpp (test-visible).
    const LogFn& logFn()
    {
        static const LogFn instance {AUTH_GATEWAY_LOGTAG};
        return instance;
    }

    // Client-visible 500 body, matching the {error,code} shape of the auth errors.
    constexpr auto INTERNAL_ERROR_BODY {R"({"error":"Internal server error","code":500})"};

    // Answers 500 from inside a catch handler without ever throwing again. The catch handlers below
    // may be handling bad_alloc, and building/sending a response allocates -- a second throw there
    // would escape onto the worker-pool thread and terminate the process, which is exactly what the
    // surrounding try/catch exists to prevent.
    void sendInternalErrorNoThrow(const std::shared_ptr<remoted::http::IHttpResponder>& responder) noexcept
    {
        try
        {
            // send-once: a no-op if a response was already delivered before the throw.
            responder->send(remoted::http::HttpResponse::json(500, INTERNAL_ERROR_BODY));
        }
        catch (...) // NOLINT(bugprone-empty-catch) -- dropping one response beats killing the daemon
        {
        }
    }

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

} // namespace

namespace remoted::endpoints
{

    AuthGateway::AuthGateway(remoted::auth::AuthConfig config,
                             std::shared_ptr<remoted::auth::IAgentKeystore> keystore,
                             std::shared_ptr<const remoted::decoding::IBodyDecoder> bodyDecoder)
        : m_middleware {std::make_shared<remoted::auth::AuthMiddleware>(config, std::move(keystore))}
        , m_bodyDecoder {std::move(bodyDecoder)}
    {
    }

    void AuthGateway::addAuthenticatedRoute(remoted::http::IHttpServer& server,
                                            Method method,
                                            const std::string& path,
                                            AuthenticatedHandler handler,
                                            remoted::http::ResponseMode mode)
    {
        const char* methodStr = methodToCanonical(method);

        server.addRoute(
            method,
            path,
            // Both dependencies are captured as their own shared_ptr copy (a refcount bump), not by
            // reference to the member: the lambda lives in the server's route table and runs per
            // request, long after this call returns. Copying keeps each registered route
            // self-contained instead of tying its validity to this gateway still being alive.
            [middleware = m_middleware, methodStr, bodyDecoder = m_bodyDecoder, handler = std::move(handler)](
                std::shared_ptr<const HttpRequest> request, std::shared_ptr<IHttpResponder> responder)
            {
                // Everything below -- the AES-CMAC auth pipeline (steps 1-7) AND the endpoint
                // handler -- runs inside one try/catch. beginSession()/Session::update()/finish()
                // call into OpenSSL's EVP_MAC (via Cmac::update()/finalize()), which can throw on
                // an underlying failure; a handler can throw too. Either escaping onto this
                // worker-pool thread would std::terminate the whole process (asio::thread_pool's
                // handler wrapper does exactly that on any uncaught exception). Catch it, log a
                // warning and answer 500. If a response was already sent before the throw, the
                // responder's send-once guarantee makes this 500 a no-op.
                try
                {
                    const std::string protocolVersion = headerValue(request->headers, "protocol-version");
                    const std::string authorization = headerValue(request->headers, "authorization");
                    // Parsed once here, acted on only AFTER authentication succeeds (see below): the
                    // MAC always covers the wire bytes exactly as sent, compressed or not.
                    const auto contentEncoding =
                        remoted::decoding::parseContentEncoding(headerValue(request->headers, "content-encoding"));

                    // Steps 1-5: protocol-version + Authorization + timestamp window + key + CMAC prefix.
                    auto begin = middleware->beginSession(protocolVersion,
                                                          authorization,
                                                          methodStr,
                                                          request->target,
                                                          static_cast<std::int64_t>(std::time(nullptr)));

                    if (std::holds_alternative<remoted::auth::AuthError>(begin))
                    {
                        responder->send(errorResponseFor(std::get<remoted::auth::AuthError>(begin)));
                        return;
                    }

                    auto session = std::get<remoted::auth::AuthMiddleware::Session>(std::move(begin));

                    // Step 6: feed the exact body bytes (enforces the max-body cap).
                    if (!request->body.empty())
                    {
                        const auto bodyError = session.update(
                            reinterpret_cast<const std::uint8_t*>(request->body.data()), request->body.size());
                        if (bodyError != remoted::auth::AuthError::None)
                        {
                            responder->send(errorResponseFor(bodyError));
                            return;
                        }
                    }

                    // Step 7: finalize + constant-time MAC comparison.
                    auto finished = session.finish();
                    if (std::holds_alternative<remoted::auth::AuthError>(finished))
                    {
                        responder->send(errorResponseFor(std::get<remoted::auth::AuthError>(finished)));
                        return;
                    }

                    // Authenticated: hand the verified request AND the responder to the
                    // endpoint handler, which now owns delivering the response (inline or
                    // asynchronously). The gateway no longer sends on the success path.
                    //
                    // Attach the verified body as a zero-copy Payload: a view into the
                    // transport's single request buffer plus a keep-alive that pins that
                    // buffer (and its in-flight byte reservation). MOVE our request
                    // shared_ptr into the keep-alive so the handler becomes the sole owner
                    // -- dropping it (or calling payload.release()) then frees the buffer
                    // and restores the budget while the responder lives on to reply.
                    auto authRequest = std::get<remoted::auth::AuthenticatedRequest>(std::move(finished));
                    const std::string_view bodyView {request->body}; // capture BEFORE moving request
                    authRequest.payload = remoted::auth::Payload {bodyView, std::move(request)};

                    // Body decoding runs here, AFTER authentication: the MAC already covered the
                    // exact wire bytes above, so an unauthenticated peer never reaches a decoder --
                    // it cannot spend our CPU or memory on one. What the step actually does (which
                    // encodings are implemented, how a body is decoded, how the memory that costs is
                    // accounted for) is deliberately unknown here; see remoted::decoding::IBodyDecoder.
                    const auto decodeError = bodyDecoder->decode(contentEncoding, authRequest.payload);
                    if (decodeError != remoted::auth::AuthError::None)
                    {
                        responder->send(errorResponseFor(decodeError));
                        return;
                    }

                    // Hand the handler a shared_ptr<const> so it can retain the verified
                    // request across deferred pipeline stages without copying the payload.
                    handler(std::make_shared<const remoted::auth::AuthenticatedRequest>(std::move(authRequest)),
                            responder);
                }
                catch (const std::exception& e)
                {
                    // ERROR, not WARN: reaching here means the AES-CMAC pipeline itself failed
                    // (an EVP_MAC error, or bad_alloc), which is not routine.
                    LOGFN_ERROR(logFn(), "Auth pipeline threw an exception: %s", e.what());
                    sendInternalErrorNoThrow(responder);
                }
                catch (...)
                {
                    LOGFN_ERROR(logFn(), "Auth pipeline threw a non-standard exception.");
                    sendInternalErrorNoThrow(responder);
                }
            },
            /*countAgainstBudget=*/true,
            mode);
    }

} // namespace remoted::endpoints
