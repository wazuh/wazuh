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

#include "common/logThrottle.hpp"
#include "endpoints/syncEndpoint.hpp" // agentIdHeader() -- one header name for every route
#include "loggerHelper.h"
#include "sync/fullSessionValidator.hpp" // isNumericAgentId(), padAgentId()

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

    invsync::http::HttpResponse errorResponse(int status, const std::string& reason)
    {
        return invsync::http::HttpResponse::json(
            status, std::string {R"({"error":")"} + reason + R"(","code":)" + std::to_string(status) + "}");
    }
} // namespace

namespace invsync::endpoints::delete_agent
{

    http::RouteHandler makeHandler(Dependencies dependencies)
    {
        return [deps = std::move(dependencies)](std::shared_ptr<const http::HttpRequest> request,
                                                std::shared_ptr<http::IHttpResponder> responder)
        {
            if (!request)
            {
                responder->send(errorResponse(400, "Empty request"));
                return;
            }

            // The target agent. NOT authenticated remote input: this route is UDS-local (D15) and
            // its caller is another manager daemon -- the validation guards against a caller bug,
            // not against spoofing.
            const auto agentIdIt = request->headers.find(sync::agentIdHeader());
            if (agentIdIt == request->headers.end() || !invsync::sync::isNumericAgentId(agentIdIt->second))
            {
                responder->send(errorResponse(400, "Missing or non-numeric agent id header"));
                return;
            }

            // Admission availability gate, same rationale as the sync route: an unreachable
            // indexer makes the deletion a guaranteed failure, and a 503 NOW is what lets the
            // caller retry instead of losing the delete silently (the legacy behavior).
            const auto indexer = deps.indexer.lock();
            if (!indexer || !indexer->isAvailable())
            {
                responder->send(errorResponse(503, "Service unavailable"));
                return;
            }

            const auto pipeline = deps.pipeline.lock();
            if (!pipeline)
            {
                responder->send(errorResponse(503, "Service unavailable"));
                return;
            }

            invsync::sync::SyncPipeline::Item item;
            item.request = request;
            item.responder = responder;
            item.kind = invsync::sync::SyncPipeline::Item::Kind::DeleteAgent;
            // Padded like every document `_id` and query -- the deletion must match what indexing
            // wrote. The shard hash uses this same string, so the deletion lands on the SAME
            // worker queue as the agent's sessions (FIFO ordering is the whole point, doc 04 §1).
            item.session.agentId = invsync::sync::padAgentId(agentIdIt->second);

            LOGFN_INFO(logFn(), "Deletion of agent %s queued.", item.session.agentId.c_str());

            if (!pipeline->enqueue(std::move(item)))
            {
                responder->send(errorResponse(503, "Service unavailable"));
            }
        };
    }

} // namespace invsync::endpoints::delete_agent
