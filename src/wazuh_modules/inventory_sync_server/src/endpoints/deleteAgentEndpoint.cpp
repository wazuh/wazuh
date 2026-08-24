/*
 * Wazuh inventory sync server module
 * Copyright (C) 2015, Wazuh Inc.
 * August 5, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "deleteAgentEndpoint.hpp"

#include "endpoints/syncEndpoint.hpp" // agentIdHeader() -- one header name for every route
#include "loggerHelper.h"
#include "sync/fullSessionValidator.hpp" // isNumericAgentId(), padAgentId()
#include <uds_http_server/logThrottle.hpp>

#include <string>
#include <utility>

namespace
{
    constexpr auto DELETE_AGENT_LOGTAG {"wazuh-manager-modulesd:inventory-sync-server:endpoints"};

    const LogFn& logFn()
    {
        static const LogFn instance {DELETE_AGENT_LOGTAG};
        return instance;
    }

    wazuh::uds_http::HttpResponse errorResponse(int status, const std::string& reason)
    {
        return wazuh::uds_http::HttpResponse::json(
            status, std::string {R"({"error":")"} + reason + R"(","code":)" + std::to_string(status) + "}");
    }

    /// The admission answer. "queued" rather than "ok" on purpose: the body is the wire's own
    /// statement that the purge has NOT run yet, so a future reader of a capture cannot mistake it
    /// for a completion the way the old `{"status":"ok"}` invited.
    constexpr auto QUEUED_BODY {R"({"status":"queued"})"};
} // namespace

namespace invsync::endpoints::delete_agent
{

    wazuh::uds_http::RouteHandler makeHandler(Dependencies dependencies)
    {
        return [deps = std::move(dependencies)](std::shared_ptr<const wazuh::uds_http::HttpRequest> request,
                                                std::shared_ptr<wazuh::uds_http::IHttpResponder> responder)
        {
            if (!request)
            {
                // Every response of this route is counted here, the site that sends it: the route
                // answers at admission, so the pipeline has no responder to count for (Dependencies).
                deps.requestCounters.count(400);
                responder->send(errorResponse(400, "Empty request"));
                return;
            }

            // The target agent. NOT authenticated remote input: this route is UDS-local (D15) and
            // its caller is another manager daemon -- the validation guards against a caller bug,
            // not against spoofing.
            const auto agentIdIt = request->headers.find(sync::agentIdHeader());
            if (agentIdIt == request->headers.end() || !invsync::sync::isNumericAgentId(agentIdIt->second))
            {
                deps.requestCounters.count(400);
                responder->send(errorResponse(400, "Missing or non-numeric agent id header"));
                return;
            }

            // Admission availability gate, same rationale as the sync route: an unreachable
            // indexer makes the deletion a guaranteed failure, and a 503 NOW is what lets the
            // caller retry instead of losing the delete silently (the legacy behavior).
            const auto indexer = deps.indexer.lock();
            if (!indexer || !indexer->isAvailable())
            {
                deps.requestCounters.count(503);
                responder->send(errorResponse(503, "Service unavailable"));
                return;
            }

            const auto pipeline = deps.pipeline.lock();
            if (!pipeline)
            {
                deps.requestCounters.count(503);
                responder->send(errorResponse(503, "Service unavailable"));
                return;
            }

            invsync::sync::SyncPipeline::Item item;
            item.request = request;
            // NO responder on the item, and that is the whole point of answering at admission: the
            // queued deletion travels with nobody waiting on it. respond() already tolerates a null
            // responder (it still releases the agent from the in-flight registry), so the worker
            // needs no change.
            item.kind = invsync::sync::SyncPipeline::Item::Kind::DeleteAgent;
            // Padded like every document `_id` and query -- the deletion must match what indexing
            // wrote. The shard hash uses this same string, so the deletion lands on the SAME
            // worker queue as the agent's sessions (FIFO ordering is the whole point, doc 04 §1).
            const auto agentId = invsync::sync::padAgentId(agentIdIt->second);
            item.session.agentId = agentId;

            if (!pipeline->enqueue(std::move(item)))
            {
                deps.requestCounters.count(503);
                responder->send(errorResponse(503, "Service unavailable"));
                return;
            }

            // Both AFTER the enqueue: a 200 -- or a line claiming the deletion is queued -- sent
            // before it would promise a purge that the very next branch refuses.
            LOGFN_INFO(logFn(), "Deletion of agent %s queued.", agentId.c_str());
            deps.requestCounters.count(200);
            responder->send(wazuh::uds_http::HttpResponse::json(200, QUEUED_BODY));
        };
    }

} // namespace invsync::endpoints::delete_agent
