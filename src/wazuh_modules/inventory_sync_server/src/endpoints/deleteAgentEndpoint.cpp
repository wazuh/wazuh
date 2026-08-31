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
#include "sync/stateIndexAllowlist.hpp"  // AGENT_DELETION_SCOPE_BY_ID
#include <uds_http_server/logThrottle.hpp>

#include <exception>
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
            // Throttled and function-local, same rationale as the sync route: how often these fire
            // is driven by how often callers request deletions, so one line per request would be a
            // log-amplification vector. One slot per condition.
            static wazuh::uds_http::LogThrottle goneThrottle;
            static wazuh::uds_http::LogThrottle unavailableThrottle;
            static wazuh::uds_http::LogThrottle capacityThrottle;

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
            if (!indexer)
            {
                // The facade cleared the connector: stop() is running. Distinct from an outage.
                if (const auto decision = goneThrottle.record())
                {
                    LOGFN_DEBUG1(logFn(),
                                 "Rejected %llu agent deletion(s) with 503 in the last %d s: the module is shutting "
                                 "down and the indexer connector is already gone.",
                                 static_cast<unsigned long long>(decision.total),
                                 wazuh::uds_http::LogThrottle::kDefaultWindowSeconds);
                }
                deps.requestCounters.count(503);
                responder->send(errorResponse(503, "Service unavailable"));
                return;
            }
            if (!indexer->isAvailable())
            {
                if (const auto decision = unavailableThrottle.record())
                {
                    LOGFN_WARN(logFn(),
                               "Rejected %llu agent deletion(s) with 503 in the last %d s: no configured indexer "
                               "host is currently healthy. Check the <indexer> hosts and that the indexer is "
                               "running.",
                               static_cast<unsigned long long>(decision.total),
                               wazuh::uds_http::LogThrottle::kDefaultWindowSeconds);
                }
                deps.requestCounters.count(503);
                responder->send(errorResponse(503, "Service unavailable"));
                return;
            }

            const auto pipeline = deps.pipeline.lock();
            const auto asyncIndexer = deps.asyncIndexer.lock();
            if (!pipeline || !asyncIndexer)
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

            /*
             * The BY-ID half, and it goes FIRST.
             *
             * AGENT_DELETION_SCOPE_BY_ID holds one document per agent whose `_id` IS the agent id --
             * the padded form below, which is what POST /config and POST /stats write because
             * remoted authenticates and forwards the canonical 3-character id. They are written
             * through the async connector's accumulating queue, so queueing their deletes on that
             * same queue is what orders them after a report it has already accepted: the queue is
             * FIFO, so anything enqueued before this point is applied before it. First rather than
             * after the pipeline enqueue for exactly that reason -- every microsecond of delay here
             * is a microsecond in which one more report could slip in behind the deletion.
             *
             * A by-id delete also needs no index refresh (unlike the pipeline's delete-by-query), so
             * a report the queue pushed moments ago is still deletable, and deleting a document that
             * is not there is a no-op the whole chain ignores -- which is what makes authd's retry
             * of an already-purged agent free.
             *
             * If the pipeline then refuses the item below, these deletes have already been queued.
             * That is harmless: they are idempotent, the agent is gone from client.keys so nothing
             * will write those documents again, and authd retries the whole deletion until it is
             * accepted.
             */
            try
            {
                for (const auto& index : invsync::sync::AGENT_DELETION_SCOPE_BY_ID)
                {
                    asyncIndexer->bulkDelete(agentId, index);
                }
            }
            catch (const std::exception& e)
            {
                // Unreachable with the compile-time index names in that scope (the connector only
                // rejects an empty index or id), so this is the branch that keeps a future change
                // honest: the caller must hear about a deletion that was not fully queued.
                LOGFN_ERROR(logFn(),
                            "Could not queue the deletion of agent %s's configuration and statistics "
                            "documents: %s. The caller must retry.",
                            agentId.c_str(),
                            e.what());
                deps.requestCounters.count(503);
                responder->send(errorResponse(503, "Service unavailable"));
                return;
            }

            if (!pipeline->enqueue(std::move(item)))
            {
                if (const auto decision = capacityThrottle.record())
                {
                    LOGFN_WARN(logFn(),
                               "Rejected %llu agent deletion(s) with 503 in the last %d s: the sync pipeline queue "
                               "is full. Consider raising 'inventory_sync_server_sync_workers' or "
                               "'inventory_sync_server_sync_queue_bytes'.",
                               static_cast<unsigned long long>(decision.total),
                               wazuh::uds_http::LogThrottle::kDefaultWindowSeconds);
                }
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
