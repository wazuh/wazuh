/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "statelessEndpoint.hpp"

#include "httpsHeaderLine.hpp"

#include <optional>
#include <string_view>
#include <utility>

namespace remoted::endpoints::stateless
{

    remoted::downstream::DownstreamTarget target(const std::string& socketPath, const std::string& agentId)
    {
        remoted::downstream::DownstreamTarget result {
            socketPath, remoted::http::Method::Post, "/events/enriched", "application/x-ndjson"};
        // Written by us, never by the agent: the value comes from the Authorization header the
        // gateway already authenticated, so it cannot be used to inject headers downstream.
        result.headers.emplace_back("X-Wazuh-Agent-Id", agentId);
        result.serviceName = "engine event ingress";
        return result;
    }

    remoted::http::HttpResponse postProcess(remoted::downstream::DownstreamError error,
                                            const remoted::downstream::DownstreamResponse& response)
    {
        using remoted::downstream::DownstreamError;
        using remoted::http::HttpResponse;

        if (error != DownstreamError::None)
        {
            // Could not reach the engine / no timely answer -> the agent retries.
            return HttpResponse::json(503, R"({"error":"Service unavailable","code":503})");
        }

        const int status = response.status;
        if (status >= 200 && status < 300)
        {
            // The engine accepted/enqueued the batch (it does not fully process it here).
            return HttpResponse {202, "", {}};
        }
        if (status == 400)
        {
            return HttpResponse::json(400, R"({"error":"Invalid event batch","code":400})");
        }
        if (status == 413)
        {
            return HttpResponse::json(413, R"({"error":"Request payload is too large","code":413})");
        }
        // 5xx / unexpected -> treat as a transient server-side failure.
        return HttpResponse::json(503, R"({"error":"Service unavailable","code":503})");
    }

    namespace
    {
        // Bound the H-line metadata on the HTTPS path without parsing JSON. The engine validates
        // its contents and identity before enqueueing any events. The agent trims its H line to the
        // same shared limit, so the two cannot drift apart.
        constexpr std::size_t kMaxHeaderLineJsonSize = HTTPS_HEADER_LINE_JSON_MAX_BYTES;

        // Slices the H-line's JSON substring out of the whole H/E body. Per the event-protocol's own
        // parsing rule ("split by \n, check first char, extract payload after space (index 2)"): the
        // body must start with the two literal characters 'H',' '; the JSON runs to the first '\n'
        // (or to the end of the body if there is none -- e.g. a header-only body with no events).
        std::optional<std::string_view> headerLineJson(std::string_view body)
        {
            constexpr std::string_view kPrefix = "H ";
            if (body.size() < kPrefix.size() || body.substr(0, kPrefix.size()) != kPrefix)
            {
                return std::nullopt;
            }
            const std::string_view rest = body.substr(kPrefix.size());
            const auto newline = rest.find('\n');
            const std::string_view result = newline == std::string_view::npos ? rest : rest.substr(0, newline);
            if (result.size() > kMaxHeaderLineJsonSize)
            {
                return std::nullopt;
            }
            return result;
        }

    } // namespace

    remoted::auth::AuthError validatePayloadIdentity(const remoted::auth::AuthenticatedRequest& req)
    {
        using remoted::auth::AuthError;

        return headerLineJson(req.payload.bytes()) ? AuthError::None : AuthError::PayloadAgentMismatch;
    }

    remoted::endpoints::AuthenticatedHandler makeHandler(remoted::downstream::DeferredForwarder& forwarder,
                                                         std::string socketPath,
                                                         const remoted::metrics::EndpointHttpMetrics* metrics)
    {
        return [&forwarder, socketPath = std::move(socketPath), metrics](
                   std::shared_ptr<const remoted::auth::AuthenticatedRequest> authReq,
                   std::shared_ptr<remoted::http::IHttpResponder> responder)
        {
            const auto err = validatePayloadIdentity(*authReq);
            if (err != remoted::auth::AuthError::None)
            {
                // Pass the authenticated agent id: this rejection happens AFTER the MAC verified, so
                // naming the agent that signed the request is what makes the resulting warning
                // actionable (see errorResponseFor()). errorResponseFor() counts the WHY
                // (remoted.auth.reject.payload_mismatch); the WHAT -- this endpoint answered a 400 --
                // is counted here, the single place this response is sent.
                auto rejection = remoted::endpoints::errorResponseFor(err, authReq->agentId);
                if (metrics != nullptr)
                {
                    metrics->responses.count(rejection.status);
                }
                responder->send(std::move(rejection));
                return;
            }
            auto downstreamTarget = target(socketPath, authReq->agentId);
            downstreamTarget.httpMetrics = metrics;
            forwarder.forward(std::move(authReq), std::move(responder), std::move(downstreamTarget), postProcess);
        };
    }

} // namespace remoted::endpoints::stateless
