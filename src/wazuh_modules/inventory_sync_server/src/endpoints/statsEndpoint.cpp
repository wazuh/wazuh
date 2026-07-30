/*
 * Wazuh inventory sync server module
 * Copyright (C) 2015, Wazuh Inc.
 * July 30, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "statsEndpoint.hpp"

#include "common/logThrottle.hpp"
#include "loggerHelper.h"
#include "timeHelper.h"

#include <exception>
#include <json.hpp>
#include <string>
#include <utility>

namespace
{
    constexpr auto STATS_ENDPOINT_LOGTAG {"wazuh-manager-modulesd:inventory-sync-server:endpoints"};

    // One shared instance rather than a per-call temporary: this runs on EVERY request.
    // loggerHelper.h stays out of statsEndpoint.hpp, which the tests include.
    const LogFn& logFn()
    {
        static const LogFn instance {STATS_ENDPOINT_LOGTAG};
        return instance;
    }

    invsync::http::HttpResponse badRequest(const char* reason)
    {
        return invsync::http::HttpResponse::json(400, std::string {R"({"error":")"} + reason + R"(","code":400})");
    }

    /// One body for both 503 causes on purpose: "the module is stopping" and "the indexer is
    /// unreachable" are the same thing to the caller (retry later), and telling them apart would leak
    /// internal state. The two are distinguished in the logs instead.
    invsync::http::HttpResponse serviceUnavailable()
    {
        return invsync::http::HttpResponse::json(503, R"({"error":"Service unavailable","code":503})");
    }
} // namespace

namespace invsync::endpoints::stats
{

    http::RouteHandler makeHandler(std::weak_ptr<invsync::indexer::IIndexerConnectorAsync> connector,
                                   invsync::common::ClusterIdentity cluster)
    {
        return [connector = std::move(connector), cluster = std::move(cluster)](
                   std::shared_ptr<const http::HttpRequest> request, std::shared_ptr<http::IHttpResponder> responder)
        {
            // Throttled and function-local: how often these fire is driven by how often agents report,
            // so one line per request would be a log-amplification vector against wazuh-manager.log.
            // One slot per condition, so a persistent one cannot mask a newly-appearing different one.
            static invsync::common::LogThrottle acceptedThrottle;
            static invsync::common::LogThrottle goneThrottle;
            static invsync::common::LogThrottle unavailableThrottle;

            if (!request)
            {
                responder->send(badRequest("Empty request"));
                return;
            }

            // remoted sets this from the identity it authenticated. Its absence means the request did
            // not come through remoted's authenticated route, so it is a contract violation, not agent
            // input -- hence a flat 400 rather than anything more specific.
            const auto agentIdIt = request->headers.find(agentIdHeader());
            if (agentIdIt == request->headers.end() || agentIdIt->second.empty())
            {
                responder->send(badRequest("Missing agent id header"));
                return;
            }

            // Non-throwing parse: a malformed document is ordinary input here, not an error condition,
            // and letting nlohmann throw would cost an exception per bad request.
            auto document = nlohmann::json::parse(request->body, nullptr, /*allow_exceptions=*/false);
            if (document.is_discarded() || !document.is_object())
            {
                responder->send(badRequest("Body must be a JSON object"));
                return;
            }

            /*
             * The indexer gate, deliberately AFTER every 400 above.
             *
             * Those rejections are the caller's fault and do not depend on the indexer, so they must
             * not be masked by an outage: with the checks the other way round, a malformed document
             * sent during an indexer outage would get a 503 and the agent would retry a payload that is
             * never going to work. Parsing a document we are about to drop is the cheaper mistake --
             * the 503 is the rare path.
             */
            const auto indexer = connector.lock();
            if (!indexer)
            {
                // The facade cleared the connector: stop() is running. Distinct from an outage.
                if (const auto decision = goneThrottle.record())
                {
                    LOGFN_DEBUG1(logFn(),
                                 "Rejected %llu stats document(s) with 503 in the last %d s: the module is shutting "
                                 "down and the indexer connector is already gone.",
                                 static_cast<unsigned long long>(decision.total),
                                 invsync::common::LogThrottle::kDefaultWindowSeconds);
                }
                responder->send(serviceUnavailable());
                return;
            }

            if (!indexer->isAvailable())
            {
                // WARN rather than debug: no healthy indexer host is an operator-actionable condition,
                // and it is the reason agents are being turned away.
                if (const auto decision = unavailableThrottle.record())
                {
                    LOGFN_WARN(logFn(),
                               "Rejected %llu stats document(s) with 503 in the last %d s: no configured indexer host "
                               "is currently healthy. Check the <indexer> hosts and that the indexer is running.",
                               static_cast<unsigned long long>(decision.total),
                               invsync::common::LogThrottle::kDefaultWindowSeconds);
                }
                responder->send(serviceUnavailable());
                return;
            }

            try
            {
                // JSON pointers rather than bracket chaining, so `wazuh.agent.id` reads the same way
                // it is spelled everywhere else in the schema. All four overwrite whatever the agent
                // sent: the authenticated id, this manager's own identity and the server's clock are
                // the authoritative ones.
                document["/wazuh/agent/id"_json_pointer] = agentIdIt->second;
                document["/wazuh/cluster/name"_json_pointer] = cluster.clusterName;
                document["/wazuh/cluster/node"_json_pointer] = cluster.nodeName;
                document["/@timestamp"_json_pointer] = Utils::getCurrentISO8601();

                if (const auto decision = acceptedThrottle.record())
                {
                    LOGFN_DEBUG1(logFn(),
                                 "Enriched and discarded %llu stats document(s) in the last %d s. This endpoint is a "
                                 "dummy: the document is echoed back but NOT indexed -- `indexer` is available and "
                                 "injected, but nothing writes through it yet.",
                                 static_cast<unsigned long long>(decision.total),
                                 invsync::common::LogThrottle::kDefaultWindowSeconds);
                }

                // Echoed back so the caller can see what was added; the document itself is dropped.
                responder->send(http::HttpResponse::json(200, document.dump()));
            }
            catch (const std::exception& e)
            {
                // Serializing back out can still fail on input we accepted -- e.g. a string field
                // holding invalid UTF-8, which nlohmann rejects at dump() time, not at parse time.
                LOGFN_DEBUG1(logFn(), "Could not serialize an enriched stats document: %s.", e.what());
                responder->send(badRequest("Body must be a JSON object"));
            }
        };
    }

} // namespace invsync::endpoints::stats
