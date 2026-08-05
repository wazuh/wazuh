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
#include <optional>
#include <string>
#include <utility>

namespace
{
    constexpr auto CONFIG_ENDPOINT_LOGTAG {"wazuh-manager-modulesd:inventory-sync-server:endpoints"};

    // The wazuh-agent-config index template is dynamic:strict -- this literal has to stay in sync
    // with that template's index_patterns.
    constexpr auto AGENT_CONFIG_INDEX_NAME {"wazuh-agent-config"};

    // One shared instance rather than a per-call temporary: this runs on EVERY request.
    // loggerHelper.h stays out of configEndpoint.hpp, which the tests include.
    const LogFn& logFn()
    {
        static const LogFn instance {CONFIG_ENDPOINT_LOGTAG};
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
     * @brief Validate the reported body shape and reduce it to the sanitized `{module, config}` array
     *        the wazuh-agent-config template expects.
     *
     * Every element is rebuilt from scratch with exactly these two keys rather than validated in
     * place: the template is dynamic:strict, so any extra key the agent sent would otherwise reach
     * the (fire-and-forget) indexer write and fail it with no way to report that back to the caller.
     *
     * @return The sanitized array on success; std::nullopt if any element fails validation, in which
     * case @p reason is set to a caller-facing 400 message.
     */
    std::optional<nlohmann::json> sanitizeReportedModules(const nlohmann::json& document, const char*& reason)
    {
        if (!document.is_array())
        {
            reason = "Body must be a JSON array of {\"module\", \"config\"} entries";
            return std::nullopt;
        }

        auto sanitized = nlohmann::json::array();
        for (const auto& element : document)
        {
            if (!element.is_object())
            {
                reason = "Each entry must be a JSON object";
                return std::nullopt;
            }

            const auto moduleIt = element.find("module");
            if (moduleIt == element.end() || !moduleIt->is_string() || moduleIt->get<std::string>().empty())
            {
                reason = "Each entry must have a non-empty string \"module\"";
                return std::nullopt;
            }

            const auto configIt = element.find("config");
            if (configIt == element.end() || !configIt->is_object())
            {
                reason = "Each entry must have an object \"config\"";
                return std::nullopt;
            }

            sanitized.push_back({{"module", *moduleIt}, {"config", *configIt}});
        }

        return sanitized;
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

            const char* rejectionReason = nullptr;
            auto sanitizedContent = sanitizeReportedModules(document, rejectionReason);
            if (!sanitizedContent)
            {
                responder->send(badRequest(rejectionReason));
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

            try
            {
                // Blocking, and deliberately BEFORE the index() below: guarantees any document left
                // over for this agent (under whatever _id it was written with) is gone before the
                // fresh one lands, rather than racing the write against the connector's own bulk
                // queue. Indexing under the agent id as _id already makes this redundant in the
                // common case (index() upserts by id), but it is the only thing that also catches a
                // stray document under a different _id -- e.g. left over from a prior id scheme.
                indexer->deleteByQuery(AGENT_CONFIG_INDEX_NAME, agentIdIt->second, cluster.clusterName);
            }
            catch (const std::exception& e)
            {
                LOGFN_DEBUG1(logFn(),
                             "deleteByQuery failed for agent '%s' ahead of indexing its config: %s.",
                             agentIdIt->second.c_str(),
                             e.what());
                responder->send(serviceUnavailable());
                return;
            }

            try
            {
                // Shaped to match the wazuh-agent-config template exactly (dynamic:strict): the
                // authenticated id, this manager's own identity, the server's clock/version, plus the
                // sanitized module array -- nothing else.
                nlohmann::json indexedDocument;
                indexedDocument["/wazuh/agent/id"_json_pointer] = agentIdIt->second;
                indexedDocument["/wazuh/agent/configuration/content"_json_pointer] = *sanitizedContent;
                indexedDocument["/wazuh/cluster/name"_json_pointer] = cluster.clusterName;
                indexedDocument["/wazuh/cluster/node"_json_pointer] = cluster.nodeName;
                indexedDocument["/state/modified_at"_json_pointer] = Utils::getCurrentISO8601();
                // Always 1, never carried over from whatever deleteByQuery just removed: each report
                // replaces the previous document outright, there is no revision history to continue.
                indexedDocument["/state/document_version"_json_pointer] = 1;

                indexer->index(agentIdIt->second, AGENT_CONFIG_INDEX_NAME, indexedDocument.dump());

                if (const auto decision = acceptedThrottle.record())
                {
                    LOGFN_DEBUG1(logFn(),
                                 "Indexed %llu agent config document(s) in the last %d s.",
                                 static_cast<unsigned long long>(decision.total),
                                 invsync::common::LogThrottle::kDefaultWindowSeconds);
                }

                // The protocol-defined acknowledgment: an empty object, not the enriched document.
                responder->send(http::HttpResponse::json(200, "{}"));
            }
            catch (const std::exception& e)
            {
                // Building/serializing the document can still fail on input we accepted -- e.g. a
                // string field holding invalid UTF-8, which nlohmann rejects at dump() time.
                LOGFN_DEBUG1(logFn(), "Could not build an agent config document: %s.", e.what());
                responder->send(badRequest("Body must be a JSON array of {\"module\", \"config\"} entries"));
            }
        };
    }

} // namespace invsync::endpoints::config
