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

    /// `state.document_version` versions the ENVELOPE this module builds -- `state`, `wazuh.cluster`,
    /// `wazuh.agent.id` and where the report is mounted -- not the report itself, whose shape is the
    /// agent's and which modulesd cannot track. Every push replaces the previous document whole, and
    /// OpenSearch's `_version` already counts the writes. Bump it when a reader must notice a change
    /// to the envelope.
    constexpr int STATS_DOCUMENT_VERSION {1};

    /// `wazuh.schema.version` is the schema-wide marker, a string keyword (not a number). The value
    /// matches `/config` and the stateful `wazuh-states-*` indices so the marker keeps one format
    /// across agent-scoped indices. Distinct from the layout version above: this one tracks the
    /// schema the document claims to follow.
    constexpr auto STATS_SCHEMA_VERSION {"1.0"};

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

    /**
     * @brief Whether the agent's `modules` object can be stored as it stands.
     *
     * Validation only: the object is indexed as it arrives, so this decides between storing it and
     * answering 400, and never rewrites it. An empty object is rejected because indexing it would
     * replace the agent's last good report with one carrying no statistics.
     *
     * @param modules The `modules` member of the agent's document.
     */
    bool isStorableReport(const nlohmann::json& modules)
    {
        if (!modules.is_object() || modules.empty())
        {
            return false;
        }

        // A scalar under a module key would be rejected by the index mapping anyway, silently: the
        // write is fire-and-forget, so catching it here is the only way the agent hears about it.
        for (const auto& body : modules)
        {
            if (!body.is_object())
            {
                return false;
            }
        }

        return true;
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
            static invsync::common::LogThrottle indexedThrottle;
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
            auto payload = nlohmann::json::parse(request->body, nullptr, /*allow_exceptions=*/false);
            if (payload.is_discarded() || !payload.is_object())
            {
                responder->send(badRequest("Body must be a JSON object"));
                return;
            }

            const auto modules = payload.find("modules");
            if (modules == payload.end() || !isStorableReport(*modules))
            {
                responder->send(badRequest("Body must carry a usable modules object"));
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
                // JSON pointers so `wazuh.agent.id` reads the way it is spelled everywhere else in
                // the schema.
                nlohmann::json document;
                document["/state/modified_at"_json_pointer] = Utils::getCurrentISO8601();
                document["/state/document_version"_json_pointer] = STATS_DOCUMENT_VERSION;
                document["/wazuh/schema/version"_json_pointer] = STATS_SCHEMA_VERSION;
                document["/wazuh/agent/id"_json_pointer] = agentIdIt->second;
                document["/wazuh/cluster/name"_json_pointer] = cluster.clusterName;
                // Moved, not copied: the payload is dead once the response is sent, and a copy would
                // be one allocation per node of every module's subtree, per agent report.
                document["/wazuh/agent/statistics"_json_pointer] = std::move(*modules);

                indexer->index(agentIdIt->second, indexName(), document.dump());

                if (const auto decision = indexedThrottle.record())
                {
                    LOGFN_DEBUG1(logFn(),
                                 "Queued %llu agent stats document(s) for indexing in the last %d s.",
                                 static_cast<unsigned long long>(decision.total),
                                 invsync::common::LogThrottle::kDefaultWindowSeconds);
                }

                // The protocol's acknowledgment: an empty object. The agent has nothing to read back.
                responder->send(http::HttpResponse::json(200, "{}"));
            }
            catch (const std::exception& e)
            {
                // Serializing can still fail on input we accepted -- invalid UTF-8 in the agent id
                // header or anywhere inside the report, which nlohmann rejects at dump() time rather
                // than at parse time.
                LOGFN_DEBUG1(logFn(), "Could not serialize an agent stats document: %s.", e.what());
                responder->send(badRequest("Report holds bytes that are not valid UTF-8"));
            }
        };
    }

} // namespace invsync::endpoints::stats
