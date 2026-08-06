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

#include "configEndpoint.hpp"

#include "common/logThrottle.hpp"
#include "loggerHelper.h"
#include "timeHelper.h"

#include <exception>
#include <json.hpp>
#include <string>
#include <utility>

namespace
{
    constexpr auto CONFIG_ENDPOINT_LOGTAG {"wazuh-manager-modulesd:inventory-sync-server:endpoints"};

    // This literal has to stay in sync with the wazuh-agent-config template's index_patterns.
    constexpr auto AGENT_CONFIG_INDEX_NAME {"wazuh-agent-config"};

    // WCS (Wazuh Common Schema) field naming convention, per docs/ref/glossary.md. Local to this
    // module: there is no shared cross-module constant for it (vulnerability_scanner defines its
    // own the same way).
    constexpr auto WAZUH_SCHEMA_VERSION {"1.0.0"};

    // Generation of the *layout* this handler produces under `wazuh.agent.configuration` -- bump
    // this if that shape ever changes, not on every report. Always 1 today: this is the first
    // layout.
    constexpr auto AGENT_CONFIG_DOCUMENT_VERSION {1};

    // One shared instance rather than a per-call temporary: this runs on EVERY request.
    // loggerHelper.h stays out of configEndpoint.hpp, which the tests include.
    const LogFn& logFn()
    {
        static const LogFn instance {CONFIG_ENDPOINT_LOGTAG};
        return instance;
    }

    invsync::http::HttpResponse badRequest(const char* reason)
    {
        return invsync::http::HttpResponse::json(400, nlohmann::json {{"error", reason}, {"code", 400}}.dump());
    }

    /// One body for both 503 causes on purpose: "the module is stopping" and "the indexer is
    /// unreachable" are the same thing to the caller (retry later), and telling them apart would leak
    /// internal state. The two are distinguished in the logs instead.
    invsync::http::HttpResponse serviceUnavailable()
    {
        return invsync::http::HttpResponse::json(503, R"({"error":"Service unavailable","code":503})");
    }

    /**
     * @brief Reduce the reported body to the `{"<module>": <config>}` object the wazuh-agent-config
     *        template expects for `configuration.content`, without judging the agent's data.
     *
     */
    nlohmann::json sanitizeReportedModules(const nlohmann::json& document)
    {
        auto content = nlohmann::json::object();
        if (!document.is_array())
        {
            return content;
        }

        for (const auto& element : document)
        {
            if (!element.is_object())
            {
                continue;
            }

            const auto moduleIt = element.find("module");
            if (moduleIt == element.end() || !moduleIt->is_string() || moduleIt->get<std::string>().empty())
            {
                continue;
            }

            const auto configIt = element.find("config");
            content[moduleIt->get<std::string>()] = (configIt != element.end()) ? *configIt : nlohmann::json::object();
        }

        return content;
    }
} // namespace

namespace invsync::endpoints::config
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
            if (document.is_discarded())
            {
                responder->send(badRequest("Malformed JSON body"));
                return;
            }

            auto sanitizedContent = sanitizeReportedModules(document);

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
                                 "Rejected %llu config document(s) with 503 in the last %d s: the module is shutting "
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
                               "Rejected %llu config document(s) with 503 in the last %d s: no configured indexer host "
                               "is currently healthy. Check the <indexer> hosts and that the indexer is running.",
                               static_cast<unsigned long long>(decision.total),
                               invsync::common::LogThrottle::kDefaultWindowSeconds);
                }
                responder->send(serviceUnavailable());
                return;
            }

            std::string serializedDocument;
            try
            {
                auto modules = nlohmann::json::array();
                for (const auto& entry : sanitizedContent.items())
                {
                    modules.push_back(entry.key());
                }

                nlohmann::json indexedDocument;
                indexedDocument["/wazuh/schema/version"_json_pointer] = WAZUH_SCHEMA_VERSION;
                indexedDocument["/wazuh/agent/id"_json_pointer] = agentIdIt->second;
                indexedDocument["/wazuh/agent/configuration/modules"_json_pointer] = modules;
                indexedDocument["/wazuh/agent/configuration/content"_json_pointer] = sanitizedContent;
                indexedDocument["/wazuh/cluster/name"_json_pointer] = cluster.clusterName;
                indexedDocument["/wazuh/cluster/node"_json_pointer] = cluster.nodeName;
                indexedDocument["/state/modified_at"_json_pointer] = Utils::getCurrentISO8601();
                indexedDocument["/state/document_version"_json_pointer] = AGENT_CONFIG_DOCUMENT_VERSION;

                serializedDocument = indexedDocument.dump();
            }
            catch (const std::exception& e)
            {
                // Serializing back out can still fail on input we accepted -- e.g. a string field
                // holding invalid UTF-8, which nlohmann rejects at dump() time, not at parse time.
                LOGFN_DEBUG1(logFn(), "Could not build an agent config document: %s.", e.what());
                responder->send(badRequest("Could not process the reported configuration"));
                return;
            }

            try
            {
                indexer->index(agentIdIt->second, AGENT_CONFIG_INDEX_NAME, serializedDocument);
            }
            catch (const std::exception& e)
            {
                LOGFN_DEBUG1(logFn(),
                             "Could not index agent config document for agent '%s': %s.",
                             agentIdIt->second.c_str(),
                             e.what());
                responder->send(serviceUnavailable());
                return;
            }

            if (const auto decision = acceptedThrottle.record())
            {
                LOGFN_DEBUG1(logFn(),
                             "Indexed %llu agent config document(s) in the last %d s.",
                             static_cast<unsigned long long>(decision.total),
                             invsync::common::LogThrottle::kDefaultWindowSeconds);
            }

            // The protocol-defined acknowledgment: an empty object, not the enriched document.
            responder->send(http::HttpResponse::json(200, "{}"));
        };
    }

} // namespace invsync::endpoints::config
