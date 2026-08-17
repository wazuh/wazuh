/*
 * Wazuh inventory sync server module
 * Copyright (C) 2015, Wazuh Inc.
 * July 28, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "syncEndpoint.hpp"

#include "common/logThrottle.hpp"
#include "loggerHelper.h"
#include "sync/fullSessionValidator.hpp"

#include <chrono>
#include <string>
#include <utility>
#include <variant>

namespace
{
    constexpr auto SYNC_ENDPOINT_LOGTAG {"wazuh-manager-modulesd:inventory-sync-server:endpoints"};

    // One shared instance rather than a per-call temporary: this runs on EVERY request.
    // loggerHelper.h stays out of syncEndpoint.hpp, which the tests include.
    const LogFn& logFn()
    {
        static const LogFn instance {SYNC_ENDPOINT_LOGTAG};
        return instance;
    }

    invsync::http::HttpResponse errorResponse(int status, const std::string& reason)
    {
        return invsync::http::HttpResponse::json(
            status, std::string {R"({"error":")"} + reason + R"(","code":)" + std::to_string(status) + "}");
    }

    /// One body for every 503 cause on purpose: "stopping", "indexer unreachable" and "no
    /// capacity" are all "retry later" to the agent, and telling them apart would leak internal
    /// state. The causes are distinguished in the logs instead.
    invsync::http::HttpResponse serviceUnavailable()
    {
        return invsync::http::HttpResponse::json(503, R"({"error":"Service unavailable","code":503})");
    }
} // namespace

namespace invsync::endpoints::sync
{

    http::RouteHandler makeHandler(Dependencies dependencies)
    {
        return [deps = std::move(dependencies)](std::shared_ptr<const http::HttpRequest> request,
                                                std::shared_ptr<http::IHttpResponder> responder)
        {
            // Throttled and function-local: an agent (through remoted) controls how often these
            // fire, so one line per request would be a log-amplification vector. One slot per
            // condition, so a persistent one cannot mask a newly-appearing different one.
            static invsync::common::LogThrottle rejectedThrottle;
            static invsync::common::LogThrottle identityThrottle;
            static invsync::common::LogThrottle vdThrottle;
            static invsync::common::LogThrottle unavailableThrottle;
            static invsync::common::LogThrottle capacityThrottle;

            if (!request)
            {
                deps.requestCounters.count(400);
                responder->send(errorResponse(400, "Empty request"));
                return;
            }

            // remoted sets this from the identity it AUTHENTICATED via AES-CMAC. Its absence means
            // the request did not come through remoted's authenticated route -- a contract
            // violation, not agent input.
            const auto agentIdIt = request->headers.find(agentIdHeader());
            if (agentIdIt == request->headers.end() || agentIdIt->second.empty())
            {
                deps.requestCounters.count(400);
                responder->send(errorResponse(400, "Missing agent id header"));
                return;
            }

            if (request->body.empty())
            {
                deps.requestCounters.count(400);
                responder->send(errorResponse(400, "Empty body"));
                return;
            }

            // CPU-only validation (verifier + identity + shape), safe on the strand.
            auto result =
                invsync::sync::validateFullSession(request->body, agentIdIt->second, deps.cluster.clusterName);
            if (auto* failure = std::get_if<invsync::sync::ValidationFailure>(&result))
            {
                if (failure->status == 403)
                {
                    // WARN: a 403 here is an identity mismatch on an AUTHENTICATED channel --
                    // spoofing or a broken agent, either way operator-relevant.
                    if (const auto decision = identityThrottle.record())
                    {
                        LOGFN_WARN(logFn(),
                                   "Rejected %llu request(s) with 403 in the last %d s: the session's identity does "
                                   "not match the authenticated one (last: agent '%s').",
                                   static_cast<unsigned long long>(decision.total),
                                   invsync::common::LogThrottle::kDefaultWindowSeconds,
                                   agentIdIt->second.c_str());
                    }
                }
                else if (const auto decision = rejectedThrottle.record())
                {
                    LOGFN_DEBUG1(logFn(),
                                 "Rejected %llu invalid session(s) with 400 in the last %d s (last: %s).",
                                 static_cast<unsigned long long>(decision.total),
                                 invsync::common::LogThrottle::kDefaultWindowSeconds,
                                 failure->reason.c_str());
                }
                deps.requestCounters.count(failure->status);
                responder->send(errorResponse(failure->status, failure->reason));
                return;
            }

            auto& session = std::get<invsync::sync::ValidatedSession>(result);

            // VD DATA sessions ride the scan lane (D22: scan -> ok -> index -> 200). Only data
            // sessions: a Cleans/Check that happens to carry a VD option has nothing to scan and
            // follows the normal pipeline below.
            if (session.isVD && session.payloadType == invsync::schema::fb::SessionPayload_SyncData)
            {
                const auto scanner = deps.scanner.lock();
                const auto lane = deps.scanLane.lock();
                if (!scanner || !lane)
                {
                    deps.requestCounters.count(503);
                    responder->send(serviceUnavailable()); // stopping (or the lane never came up)
                    return;
                }

                // D17: while the CVE feed is downloading, VD sessions are rejected WITHOUT
                // processing -- the re-POST applies scan and ingest together, and nobody blocks
                // waiting for the feed (the lane re-checks at dispatch too).
                if (!scanner->feedReady())
                {
                    if (const auto decision = vdThrottle.record())
                    {
                        LOGFN_DEBUG1(logFn(),
                                     "Answered 503 + Retry-After to %llu vulnerability-detection session(s) in the "
                                     "last %d s: the CVE feed is not ready.",
                                     static_cast<unsigned long long>(decision.total),
                                     invsync::common::LogThrottle::kDefaultWindowSeconds);
                    }
                    auto response = errorResponse(503, "vulnerability feed not ready");
                    response.headers.emplace_back("Retry-After", std::to_string(deps.vdRetryAfterSeconds));
                    if (deps.retryAfterTotal)
                    {
                        deps.retryAfterTotal->add();
                    }
                    deps.requestCounters.count(503);
                    responder->send(std::move(response));
                    return;
                }

                switch (lane->tryEnqueue(
                    invsync::sync::SyncPipeline::Item {request,
                                                       responder,
                                                       std::move(session),
                                                       invsync::sync::SyncPipeline::Item::Kind::Session,
                                                       std::chrono::steady_clock::now()}))
                {
                    case invsync::vd::VdScanLane::Admission::Accepted:
                        return; // the lane worker owns the response from here
                    case invsync::vd::VdScanLane::Admission::Full:
                        if (const auto decision = vdThrottle.record())
                        {
                            LOGFN_WARN(logFn(),
                                       "Rejected %llu vulnerability-detection session(s) with 503 in the last %d s: "
                                       "the scan lane queue is full (scans are slow; the agents retry next cycle). "
                                       "Consider raising 'inventory_sync_server_vd_scan_queue_slots'.",
                                       static_cast<unsigned long long>(decision.total),
                                       invsync::common::LogThrottle::kDefaultWindowSeconds);
                        }
                        // The lane itself counts vd.capacity.503.total at the refusal.
                        deps.requestCounters.count(503);
                        responder->send(errorResponse(503, "scan capacity exhausted"));
                        return;
                    case invsync::vd::VdScanLane::Admission::Stopping:
                    default:
                        deps.requestCounters.count(503);
                        responder->send(serviceUnavailable());
                        return;
                }
            }

            // Admission availability gate (re-checked per session at dispatch by the worker): an
            // unreachable indexer turns every session into a guaranteed failure, so shedding here
            // is cheaper for both sides than queueing work that cannot complete.
            const auto indexer = deps.indexer.lock();
            if (!indexer)
            {
                // The facade cleared the connector: stop() is running. Distinct from an outage.
                deps.requestCounters.count(503);
                responder->send(serviceUnavailable());
                return;
            }
            if (!indexer->isAvailable())
            {
                if (const auto decision = unavailableThrottle.record())
                {
                    LOGFN_WARN(logFn(),
                               "Rejected %llu session(s) with 503 in the last %d s: no configured indexer host is "
                               "currently healthy. Check the <indexer> hosts and that the indexer is running.",
                               static_cast<unsigned long long>(decision.total),
                               invsync::common::LogThrottle::kDefaultWindowSeconds);
                }
                deps.requestCounters.count(503);
                responder->send(serviceUnavailable());
                return;
            }

            const auto pipeline = deps.pipeline.lock();
            if (!pipeline)
            {
                deps.requestCounters.count(503);
                responder->send(serviceUnavailable());
                return;
            }

            // The item COPIES the two shared_ptrs (cheap) so a refused enqueue can still answer
            // through the original responder. On success the strand's work is done: the worker
            // owns the response from here.
            if (!pipeline->enqueue(invsync::sync::SyncPipeline::Item {request,
                                                                      responder,
                                                                      std::move(session),
                                                                      invsync::sync::SyncPipeline::Item::Kind::Session,
                                                                      std::chrono::steady_clock::now()}))
            {
                if (const auto decision = capacityThrottle.record())
                {
                    LOGFN_WARN(logFn(),
                               "Rejected %llu session(s) with 503 in the last %d s: the sync pipeline queue is full. "
                               "Consider raising 'inventory_sync_server_sync_workers' or "
                               "'inventory_sync_server_sync_queue_bytes'.",
                               static_cast<unsigned long long>(decision.total),
                               invsync::common::LogThrottle::kDefaultWindowSeconds);
                }
                // The pipeline itself counts sync.pipeline.shed.total at the refusal.
                deps.requestCounters.count(503);
                responder->send(serviceUnavailable());
            }
        };
    }

} // namespace invsync::endpoints::sync
