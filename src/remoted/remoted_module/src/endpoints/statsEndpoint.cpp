/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * July 30, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "statsEndpoint.hpp"

#include <utility>

namespace remoted::endpoints::stats
{

    remoted::downstream::DownstreamTarget target(const std::string& socketPath, const std::string& agentId)
    {
        remoted::downstream::DownstreamTarget result {
            socketPath, remoted::http::Method::Post, "/stats", "application/json"};
        // Written by us, never by the agent: the value comes from the Authorization header the
        // gateway already authenticated, so it cannot be used to inject headers downstream.
        result.headers.emplace_back("X-Wazuh-Agent-Id", agentId);
        result.serviceName = "inventory sync server";
        return result;
    }

    remoted::http::HttpResponse postProcess(remoted::downstream::DownstreamError error,
                                            const remoted::downstream::DownstreamResponse& response)
    {
        using remoted::downstream::DownstreamError;
        using remoted::http::HttpResponse;

        if (error != DownstreamError::None)
        {
            // Could not reach modulesd / no timely answer -> the agent retries.
            return HttpResponse::json(503, R"({"error":"Service unavailable","code":503})");
        }

        const int status = response.status;
        if (status >= 200 && status < 300)
        {
            // The protocol's acknowledgment, built here rather than forwarded: the agent has nothing
            // to read back, and a fixed body keeps an arbitrary downstream string off the wire.
            return HttpResponse::json(200, "{}");
        }
        if (status == 400)
        {
            // modulesd rejected the document.
            return HttpResponse::json(400, R"({"error":"Invalid stats document","code":400})");
        }
        if (status == 413)
        {
            return HttpResponse::json(413, R"({"error":"Request payload is too large","code":413})");
        }
        // 5xx / unexpected -> treat as a transient server-side failure.
        return HttpResponse::json(503, R"({"error":"Service unavailable","code":503})");
    }

    remoted::endpoints::AuthenticatedHandler makeHandler(remoted::downstream::DeferredForwarder& forwarder,
                                                         std::string socketPath)
    {
        return [&forwarder,
                socketPath = std::move(socketPath)](std::shared_ptr<const remoted::auth::AuthenticatedRequest> authReq,
                                                    std::shared_ptr<remoted::http::IHttpResponder> responder)
        {
            // The only content check done here. Parsing is modulesd's job -- doing it on both sides
            // would walk the whole payload twice on the hot path -- but an empty body cannot possibly
            // be a JSON object, and rejecting it here saves a deferred-work slot and a UDS round trip.
            if (authReq->payload.bytes().empty())
            {
                responder->send(remoted::http::HttpResponse::json(400, R"({"error":"Empty request body","code":400})"));
                return;
            }

            // Built BEFORE the move: argument evaluation order is unspecified, so reading
            // authReq->agentId in the same call that moves authReq could dereference a null pointer.
            auto downstreamTarget = target(socketPath, authReq->agentId);
            forwarder.forward(std::move(authReq), std::move(responder), std::move(downstreamTarget), postProcess);
        };
    }

} // namespace remoted::endpoints::stats
