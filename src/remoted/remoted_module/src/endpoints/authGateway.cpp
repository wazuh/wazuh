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

#include "http_server/headerUtils.hpp"
#include "loggerHelper.h"

#include <chrono>
#include <cstdint>
#include <ctime>
#include <exception>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

using remoted::http::headerValue;

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

    // Canonical uppercase HTTP verb, as AuthenticatedRequest::method carries it.
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
                // Everything below -- authentication AND the endpoint handler -- runs inside one
                // try/catch. authenticate() calls into the keystore and OpenSSL (HMAC), either of
                // which can throw on an underlying failure; a handler can throw too. Either escaping
                // onto this worker-pool thread would std::terminate the whole process
                // (asio::thread_pool's handler wrapper does exactly that on any uncaught exception).
                // Catch it, log a warning and answer 500. If a response was already sent before the
                // throw, the responder's send-once guarantee makes this 500 a no-op.
                try
                {
                    // Stamped ONCE, before authentication: this is the origin of the
                    // remoted.http.<endpoint>.latency measurement (gateway receipt -> response
                    // delivery). One clock read per authenticated request, no atomics.
                    const auto receivedAt = std::chrono::steady_clock::now();

                    const std::string protocolVersion = headerValue(request->headers, "protocol-version");
                    const std::string authorization = headerValue(request->headers, "authorization");
                    // Parsed once here, acted on only AFTER authentication succeeds (see below): an
                    // unauthenticated peer never reaches a decoder.
                    const auto contentEncoding =
                        remoted::decoding::parseContentEncoding(headerValue(request->headers, "content-encoding"));

                    // Authentication is header-only: protocol-version, the bearer token, the key
                    // lookup + address rule, and the token's signature/claims/time policy. The body
                    // plays no part in it (the wazuh-agent+jwt profile authenticates identity; TLS
                    // protects the channel).
                    auto verified = middleware->authenticate(protocolVersion,
                                                             authorization,
                                                             request->remoteIp,
                                                             static_cast<std::int64_t>(std::time(nullptr)));
                    if (std::holds_alternative<remoted::auth::AuthError>(verified))
                    {
                        responder->send(errorResponseFor(std::get<remoted::auth::AuthError>(verified)));
                        return;
                    }

                    // The authenticated-body cap, enforced before the body is decoded or handed on.
                    if (request->body.size() > middleware->config().maxBodySize)
                    {
                        responder->send(errorResponseFor(remoted::auth::AuthError::BodyTooLarge));
                        return;
                    }

                    // Authenticated: hand the verified request AND the responder to the
                    // endpoint handler, which now owns delivering the response (inline or
                    // asynchronously). The gateway no longer sends on the success path.
                    //
                    // Attach the body as a zero-copy Payload: a view into the transport's single
                    // request buffer plus a keep-alive that pins that buffer (and its in-flight byte
                    // reservation). MOVE our request shared_ptr into the keep-alive so the handler
                    // becomes the sole owner -- dropping it (or calling payload.release()) then
                    // frees the buffer and restores the budget while the responder lives on to reply.
                    remoted::auth::AuthenticatedRequest authRequest;
                    authRequest.agentId = std::move(std::get<remoted::auth::VerifiedAgent>(verified).agentId);
                    authRequest.protocolVersion = protocolVersion;
                    authRequest.method = methodStr;
                    authRequest.requestTarget = request->target;
                    authRequest.receivedAt = receivedAt;
                    const std::string_view bodyView {request->body}; // capture BEFORE moving request
                    authRequest.payload = remoted::auth::Payload {bodyView, std::move(request)};

                    // Body decoding runs here, AFTER authentication, so an unauthenticated peer never
                    // reaches a decoder -- it cannot spend our CPU or memory on one. What the step
                    // actually does (which
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
                    // ERROR, not WARN: reaching here means the auth pipeline itself failed (a
                    // keystore or OpenSSL error, or bad_alloc), which is not routine.
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
