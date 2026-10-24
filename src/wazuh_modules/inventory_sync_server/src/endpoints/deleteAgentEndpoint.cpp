/*
 * Wazuh inventory sync server module
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "deleteAgentEndpoint.hpp"

#include "common/agentId.hpp"
#include "loggerHelper.h"
#include <uds_http_server/logThrottle.hpp>

#include <cstdint>
#include <json.hpp>
#include <optional>
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

    /**
     * @brief Read the target agent id out of the request body.
     *
     * The body, and only the body: the dispatcher POSTs a manager-task row's PAYLOAD verbatim and
     * adds no headers of its own, so it is the only channel there is. `X-Wazuh-Agent-Id` is ignored
     * even when present, because honouring it would hide a producer that forgot to write the id
     * into the payload.
     *
     * Not authenticated remote input: this route is UDS-local (D15) and its caller is another
     * manager daemon, so this guards against a caller bug, not against spoofing.
     *
     * @param[out] reason Caller-facing 400 message, set only on failure.
     * @return The id in its canonical spelling ("7" and "0007" -> "007"), or nullopt when it is
     *         absent or not an agent id (not digits, or out of the 32-bit range).
     */
    std::optional<std::string> resolveAgentId(const wazuh::uds_http::HttpRequest& request, const char*& reason)
    {
        // Non-throwing parse, like every other body-reading route here: a malformed body is
        // ordinary input, and letting nlohmann throw would cost an exception per bad request. A
        // discarded value is not an object, so the one check covers both.
        const auto document = nlohmann::json::parse(request.body, nullptr, /*allow_exceptions=*/false);
        if (!document.is_object())
        {
            reason = R"(Body must be a JSON object with an "agent_id" member)";
            return std::nullopt;
        }

        const auto agentIdIt = document.find("agent_id");
        if (agentIdIt == document.end())
        {
            reason = R"(Body must carry an "agent_id" member)";
            return std::nullopt;
        }

        // Both JSON spellings of a small integer are accepted. Not a second contract -- the same
        // value, written the two ways a producer can write it -- and the tolerance is what keeps a
        // producer that emits 7 instead of "7" from re-queueing forever: this type's descriptor sets
        // allow_terminal_failure = false, so its 400 comes back as retryable rather than dying.
        std::string agentId;
        if (agentIdIt->is_string())
        {
            agentId = agentIdIt->get<std::string>();
        }
        else if (agentIdIt->is_number_unsigned())
        {
            agentId = std::to_string(agentIdIt->get<std::uint64_t>());
        }

        auto canonical = invsync::common::canonicalAgentId(agentId);
        if (!canonical)
        {
            reason = R"("agent_id" must be a numeric agent id)";
            return std::nullopt;
        }

        return canonical;
    }

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
                // Counted here, the site that sends it. The terminal response is the pipeline's to
                // count, so a request is never counted twice (Dependencies).
                deps.requestCounters.count(400);
                responder->send(errorResponse(400, "Empty request"));
                return;
            }

            const char* rejectionReason = nullptr;
            const auto callerAgentId = resolveAgentId(*request, rejectionReason);
            if (!callerAgentId)
            {
                deps.requestCounters.count(400);
                responder->send(errorResponse(400, rejectionReason));
                return;
            }

            // The up-front availability gate, same rationale as the sync route: an unreachable
            // indexer makes the deletion a guaranteed failure, and a 503 NOW is what lets the caller
            // retry instead of losing the delete silently (the legacy behavior).
            //
            // Kept even though the worker re-checks at dispatch and would answer 503 anyway: this
            // refuses without occupying a lane slot and a shard queue slot for work that is going to
            // be refused. 503 rather than 409 -- the dispatcher reads a 5xx as retryable and backs
            // off, capped at 15 minutes, which is what backoff is for; 409 means "already running
            // this work" to it, and overloading that would make a real conflict unreadable.
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
            if (!pipeline)
            {
                deps.requestCounters.count(503);
                responder->send(errorResponse(503, "Service unavailable"));
                return;
            }

            invsync::sync::SyncPipeline::Item item;
            item.request = request;
            // The responder rides along, and that is the whole contract: the pipeline's own
            // respond() answers the caller after executeDeleteAgent() has flushed its
            // delete-by-query AND resolved its by-id deletes, which is what lets a manager-task row
            // read `completed` and mean purged.
            item.responder = responder;
            item.kind = invsync::sync::SyncPipeline::Item::Kind::DeleteAgent;
            // Canonical like every document `_id` and query -- the deletion must match what indexing
            // wrote. The shard hash uses this same string, so the deletion lands on the SAME
            // worker queue as the agent's sessions (FIFO ordering is the whole point, doc 04 §1).
            const auto& agentId = *callerAgentId;
            item.session.agentId = agentId;

            // Only the enqueue happens here. Both halves of the deletion run on the agent's shard worker
            // (SessionProcessor::executeDeleteAgent, I147c): the by-id deletes of AGENT_DELETION_SCOPE_BY_ID
            // on the `agent-state` bucket -- after cancel(agent) and ordered behind the agent's earlier
            // /stats and /config writes -- and the by-query over this cluster's `wazuh-states-*`. The
            // answer comes from the worker once both are done, so two deletions of one agent never
            // overlap and a refused enqueue below has queued nothing at all.
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

                // The handler keeps its own reference to the responder, independent of the copy that
                // went onto the item, so a refused enqueue still has someone to answer. And exactly
                // one answer: a refusal never enters a queue, so respond() cannot also fire.
                deps.requestCounters.count(503);
                responder->send(errorResponse(503, "Service unavailable"));
                return;
            }

            // AFTER the enqueue, and nothing is sent or counted here: the responder is on the item
            // now and the worker will answer through it. DEBUG rather than INFO because the pipeline
            // already logs the outcome of every deletion, and a second per-request line would double
            // the volume of a fleet-wide purge to say only that it started.
            LOGFN_DEBUG1(logFn(), "Deletion of agent %s queued for execution.", agentId.c_str());
        };
    }

} // namespace invsync::endpoints::delete_agent
