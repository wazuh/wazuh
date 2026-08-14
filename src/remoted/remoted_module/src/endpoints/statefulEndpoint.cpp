/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * August 5, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "statefulEndpoint.hpp"

#include <algorithm>
#include <cctype>
#include <string_view>
#include <utility>

namespace remoted::endpoints::stateful
{
    namespace
    {
        /// The sync contract's status codes (inventory_sync_server doc 03 §6): what the server
        /// answers is what the agent must see. Anything else is not a session result.
        bool isContractStatus(const int status)
        {
            switch (status)
            {
                case 200: // applied and flushed (or noop)
                case 400: // invalid session
                case 403: // identity mismatch
                case 409: // checksum mismatch
                case 413: // session declares more than the total budget
                case 500: // scan/apply failed, nothing indexed
                case 503: // not ready / capacity / shutdown
                    return true;
                default: return false;
            }
        }

        /// Retry-After per the contract: a delay in whole seconds. Anything else (dates, huge or
        /// empty strings) is not something our own server produces, so it is dropped rather than
        /// reflected.
        bool isValidRetryAfter(const std::string_view value)
        {
            return !value.empty() && value.size() <= 6 &&
                   std::all_of(value.begin(), value.end(), [](const unsigned char c) { return std::isdigit(c) != 0; });
        }

        /// The one downstream header the contract defines: `Retry-After` on a 503 (vulnerability
        /// feed still downloading). Names arrive lower-cased from the client; the canonical casing
        /// is restored on the way out.
        void forwardRetryAfter(const remoted::downstream::DownstreamResponse& response,
                               remoted::http::HttpResponse& out)
        {
            for (const auto& [name, value] : response.headers)
            {
                if (name == "retry-after" && isValidRetryAfter(value))
                {
                    out.headers.emplace_back("Retry-After", value);
                    return;
                }
            }
        }
    } // namespace

    remoted::downstream::DownstreamTarget
    target(const std::string& socketPath, const std::string& agentId, const int responseTimeoutMs)
    {
        remoted::downstream::DownstreamTarget result {
            socketPath, remoted::http::Method::Post, "/stateful", "application/octet-stream"};
        // Written by us, never by the agent: the value comes from the Authorization header the
        // gateway already authenticated, so it cannot be used to inject headers downstream.
        result.headers.emplace_back("X-Wazuh-Agent-Id", agentId);
        result.serviceName = "inventory sync server";
        result.responseTimeoutMs = responseTimeoutMs;
        return result;
    }

    remoted::http::HttpResponse postProcess(remoted::downstream::DownstreamError error,
                                            const remoted::downstream::DownstreamResponse& response)
    {
        using remoted::downstream::DownstreamError;
        using remoted::http::HttpResponse;

        if (error != DownstreamError::None)
        {
            // Could not reach the sync server / no timely answer -> the agent retries next cycle.
            return HttpResponse::json(503, R"({"error":"Service unavailable","code":503})");
        }

        if (isContractStatus(response.status))
        {
            // The downstream result IS the session result (D2): status and body pass through
            // verbatim. Safe to reflect: the body is produced by the manager's own sync server
            // (controlled JSON), never echoed agent input -- and the agent needs it as-is (e.g.
            // {"status":"checksum_mismatch"} on 409 is what triggers its full resync).
            auto result = HttpResponse::json(response.status, response.body);
            if (response.status == 503)
            {
                forwardRetryAfter(response, result);
            }
            return result;
        }

        // Outside the contract (404/405 route mismatch, unexpected redirects...): a transient
        // manager-side problem as far as the agent is concerned. The forwarder already logged the
        // real status.
        return HttpResponse::json(503, R"({"error":"Service unavailable","code":503})");
    }

    remoted::endpoints::AuthenticatedHandler
    makeHandler(remoted::downstream::DeferredForwarder& forwarder, std::string socketPath, const int responseTimeoutMs)
    {
        return [&forwarder, socketPath = std::move(socketPath), responseTimeoutMs](
                   std::shared_ptr<const remoted::auth::AuthenticatedRequest> authReq,
                   std::shared_ptr<remoted::http::IHttpResponder> responder)
        {
            // The only content check done here. The body is an opaque FlatBuffer -- validation is
            // the sync server's job -- but an empty body cannot possibly be a FullSession, and
            // rejecting it here saves a deferred-work slot and a UDS round trip.
            if (authReq->payload.bytes().empty())
            {
                responder->send(remoted::http::HttpResponse::json(400, R"({"error":"Empty request body","code":400})"));
                return;
            }

            // Built BEFORE the move: argument evaluation order is unspecified, so reading
            // authReq->agentId in the same call that moves authReq could dereference a null pointer.
            auto downstreamTarget = target(socketPath, authReq->agentId, responseTimeoutMs);
            forwarder.forward(std::move(authReq), std::move(responder), std::move(downstreamTarget), postProcess);
        };
    }

} // namespace remoted::endpoints::stateful
