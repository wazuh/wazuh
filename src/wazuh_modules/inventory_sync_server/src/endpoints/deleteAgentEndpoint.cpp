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

#include <cstdint>
#include <exception>
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

    /// The admission answer. "queued" rather than "ok" on purpose: the body is the wire's own
    /// statement that the purge has NOT run yet, so a future reader of a capture cannot mistake it
    /// for a completion the way the old `{"status":"ok"}` invited.
    constexpr auto QUEUED_BODY {R"({"status":"queued"})"};

    /// Which of the two contracts a built handler follows. The work is identical; only who answers,
    /// when, and where the agent id is read from differ -- so they share one implementation and a
    /// reader can see the whole difference in one place instead of diffing two near-copies.
    enum class Answer
    {
        AtAdmission, ///< This handler sends the 200 as soon as the item is queued.
        AtCompletion ///< The item carries its responder; the pipeline answers after the flush.
    };

    /**
     * @brief Read the target agent id from wherever this route's caller puts it.
     *
     * At admission it is the `X-Wazuh-Agent-Id` header, which is what authd's relay sends. At
     * completion it is the request body, because the dispatcher POSTs a manager-task row's PAYLOAD
     * verbatim and adds no headers of its own -- the body is the only channel there is.
     *
     * Neither form is authenticated remote input: both routes are UDS-local (D15) and both callers
     * are other manager daemons, so this guards against a caller bug, not against spoofing.
     *
     * @param[out] reason Caller-facing 400 message, set only on failure.
     * @return The id as written by the caller (unpadded), or nullopt when it is absent or not an id.
     */
    std::optional<std::string>
    resolveAgentId(const wazuh::uds_http::HttpRequest& request, Answer answer, const char*& reason)
    {
        if (answer == Answer::AtAdmission)
        {
            const auto agentIdIt = request.headers.find(invsync::endpoints::sync::agentIdHeader());
            if (agentIdIt == request.headers.end() || !invsync::sync::isNumericAgentId(agentIdIt->second))
            {
                reason = "Missing or non-numeric agent id header";
                return std::nullopt;
            }
            return agentIdIt->second;
        }

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

        if (!invsync::sync::isNumericAgentId(agentId))
        {
            reason = R"("agent_id" must be a numeric agent id)";
            return std::nullopt;
        }

        return agentId;
    }

    /**
     * @brief Build one of the two agent-deletion handlers. See the Answer enum for what differs.
     */
    wazuh::uds_http::RouteHandler makeRouteHandler(invsync::endpoints::delete_agent::Dependencies dependencies,
                                                   Answer answer)
    {
        return [deps = std::move(dependencies), answer](std::shared_ptr<const wazuh::uds_http::HttpRequest> request,
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
                // Every response this handler sends is counted here, the site that sends it. At
                // admission that is all of them; at completion the terminal response is the
                // pipeline's to count, so a request is never counted twice (Dependencies).
                deps.requestCounters.count(400);
                responder->send(errorResponse(400, "Empty request"));
                return;
            }

            const char* rejectionReason = nullptr;
            const auto callerAgentId = resolveAgentId(*request, answer, rejectionReason);
            if (!callerAgentId)
            {
                deps.requestCounters.count(400);
                responder->send(errorResponse(400, rejectionReason));
                return;
            }

            // Admission availability gate, same rationale as the sync route: an unreachable
            // indexer makes the deletion a guaranteed failure, and a 503 NOW is what lets the
            // caller retry instead of losing the delete silently (the legacy behavior).
            //
            // The execution route keeps it even though the worker re-checks at dispatch and would
            // answer 503 anyway: this refuses without occupying a lane slot and a shard queue slot
            // for work that is going to be refused. 503 rather than 409 -- the dispatcher reads a
            // 5xx as retryable and backs off, capped at 15 minutes, which is what backoff is for;
            // 409 means "already running this work" to it, and overloading that would make a real
            // conflict unreadable.
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
            // WHO the item carries is the entire difference between the two contracts.
            //
            // At admission: no responder, and that is the whole point -- the queued deletion travels
            // with nobody waiting on it. respond() already tolerates a null responder (it still
            // releases the agent from the in-flight registry), so the worker needs no change.
            //
            // At completion: the responder rides along, so the SAME respond() answers the caller
            // after executeDeleteAgent() has flushed its delete-by-query. That is what lets a
            // manager-task row read `completed` and mean purged. It needs no change either -- the
            // worker has always answered a DeleteAgent item, there has just never been anyone to
            // answer -- which is why this route is additive rather than a rework of the pipeline.
            if (answer == Answer::AtCompletion)
            {
                item.responder = responder;
            }
            item.kind = invsync::sync::SyncPipeline::Item::Kind::DeleteAgent;
            // Padded like every document `_id` and query -- the deletion must match what indexing
            // wrote. The shard hash uses this same string, so the deletion lands on the SAME
            // worker queue as the agent's sessions (FIFO ordering is the whole point, doc 04 §1).
            const auto agentId = invsync::sync::padAgentId(*callerAgentId);
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
             * will write those documents again, and the caller -- authd's relay, or the dispatcher
             * on the execution route -- retries the whole deletion until it is accepted. Each retry
             * re-queues this pair for the same reason, which is bounded and free.
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

                // The handler keeps its own reference to the responder, independent of the copy that
                // went onto the item, so a refused enqueue still has someone to answer. And exactly
                // one answer: a refusal never enters a queue, so respond() cannot also fire.
                deps.requestCounters.count(503);
                responder->send(errorResponse(503, "Service unavailable"));
                return;
            }

            if (answer == Answer::AtCompletion)
            {
                // Nothing is sent and nothing is counted: the responder is on the item now, and the
                // worker will answer through it. DEBUG rather than INFO because the pipeline already
                // logs the outcome of every deletion, and a second per-request line would double the
                // volume of a fleet-wide purge to say only that it started.
                LOGFN_DEBUG1(logFn(), "Deletion of agent %s queued for execution.", agentId.c_str());
                return;
            }

            // Both AFTER the enqueue: a 200 -- or a line claiming the deletion is queued -- sent
            // before it would promise a purge that the very next branch refuses.
            LOGFN_INFO(logFn(), "Deletion of agent %s queued.", agentId.c_str());
            deps.requestCounters.count(200);
            responder->send(wazuh::uds_http::HttpResponse::json(200, QUEUED_BODY));
        };
    }

} // namespace

namespace invsync::endpoints::delete_agent
{

    wazuh::uds_http::RouteHandler makeHandler(Dependencies dependencies)
    {
        return makeRouteHandler(std::move(dependencies), Answer::AtAdmission);
    }

    wazuh::uds_http::RouteHandler makeCompletionHandler(Dependencies dependencies)
    {
        return makeRouteHandler(std::move(dependencies), Answer::AtCompletion);
    }

} // namespace invsync::endpoints::delete_agent
