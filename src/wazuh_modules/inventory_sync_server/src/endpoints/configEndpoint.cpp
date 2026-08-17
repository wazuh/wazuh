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
#include "sync/stateIndexAllowlist.hpp" // AGENT_CONFIG_INDEX -- shared with the deletion scope
#include "timeHelper.h"

#include <exception>
#include <json.hpp>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace
{
    constexpr auto CONFIG_ENDPOINT_LOGTAG {"wazuh-manager-modulesd:inventory-sync-server:endpoints"};

    // Has to stay in sync with the wazuh-agent-config template's index_patterns. Taken from the
    // deletion scope rather than re-spelled here, so DELETE /agents can never miss this index.
    constexpr std::string_view AGENT_CONFIG_INDEX_NAME {invsync::sync::AGENT_CONFIG_INDEX};

    // `wazuh.schema.version` marker, a string keyword per WCS (docs/ref/glossary.md). The value
    // matches `/stats` and the stateful `wazuh-states-*` indices so the marker keeps one format
    // across agent-scoped indices. Local to this module: there is no shared cross-module constant.
    constexpr auto WAZUH_SCHEMA_VERSION {"1.0"};

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
     * @brief Validate the reported body and return the `{"<module>": <config>}` object the
     *        wazuh-agent-config template expects for `configuration.content`.
     *
     * The agent posts `{"modules": {"<module>": <config>, ...}}` -- the same envelope POST /stats
     * uses -- keyed by module name, which is exactly the shape the template maps `content` as (never
     * an array), with an explicit per-module sub-schema (`content.fim.syscheck.frequency`, etc.): a
     * module is unique per report by construction (object keys cannot repeat), so keying by module
     * name is what makes "does agent X have module Y" a single field lookup instead of a scan. The
     * template is `dynamic: false`: a field this handler emits that isn't in that per-module
     * sub-schema (a module the template doesn't know about yet, or a legacy/undeclared key within a
     * known module) still gets written and stored in `_source`, it just isn't indexed for search --
     * so nothing here validates individual `config` fields against that schema, only that every
     * module's value is an object.
     *
     * An empty `modules` object is rejected: every push replaces the agent's document whole (its
     * `_id` is the agent id), so indexing an empty report would erase the last good configuration.
     * The agent's own collector skips a cycle rather than send an empty report, so receiving one is
     * a protocol violation, not data to store -- the same rule POST /stats applies.
     *
     * @return The sanitized `{module: config}` object on success; std::nullopt on a shape violation,
     * in which case @p reason is set to a caller-facing 400 message.
     */
    std::optional<nlohmann::json> sanitizeReportedModules(const nlohmann::json& document, const char*& reason)
    {
        if (!document.is_object())
        {
            reason = "Body must be a JSON object with a \"modules\" member";
            return std::nullopt;
        }

        const auto modulesIt = document.find("modules");
        if (modulesIt == document.end() || !modulesIt->is_object() || modulesIt->empty())
        {
            reason = R"(Body must carry a non-empty "modules" object keyed by module name)";
            return std::nullopt;
        }

        for (const auto& entry : modulesIt->items())
        {
            if (!entry.value().is_object())
            {
                reason = "Each module's configuration must be a JSON object";
                return std::nullopt;
            }
        }

        return *modulesIt;
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

            std::string serializedDocument;
            try
            {
                // `modules` lists exactly the keys `content` ends up with -- derived from it rather
                // than collected while sanitizing, so the two can never drift apart (e.g. if a future
                // change dedupes or drops an entry in `content` alone).
                auto modules = nlohmann::json::array();
                for (const auto& entry : sanitizedContent->items())
                {
                    modules.push_back(entry.key());
                }

                // Shaped to match the wazuh-agent-config template: schema version, the
                // authenticated id, this manager's own identity, the server's clock, and the
                // sanitized configuration -- nothing else. `dynamic: false` means an unmapped field
                // here would not fail the write, but there is still no reason to send one.
                nlohmann::json indexedDocument;
                indexedDocument["/wazuh/schema/version"_json_pointer] = WAZUH_SCHEMA_VERSION;
                indexedDocument["/wazuh/agent/id"_json_pointer] = agentIdIt->second;
                indexedDocument["/wazuh/agent/configuration/modules"_json_pointer] = modules;
                indexedDocument["/wazuh/agent/configuration/content"_json_pointer] = *sanitizedContent;
                indexedDocument["/wazuh/cluster/name"_json_pointer] = cluster.clusterName;
                indexedDocument["/state/modified_at"_json_pointer] = Utils::getCurrentISO8601();
                indexedDocument["/state/document_version"_json_pointer] = AGENT_CONFIG_DOCUMENT_VERSION;

                serializedDocument = indexedDocument.dump();
            }
            catch (const std::exception& e)
            {
                // Building/serializing the document can still fail on input we accepted -- e.g. a
                // string field holding invalid UTF-8, which nlohmann rejects at dump() time. Still the
                // caller's fault.
                LOGFN_DEBUG1(logFn(), "Could not build an agent config document: %s.", e.what());
                responder->send(badRequest("Report holds bytes that are not valid UTF-8"));
                return;
            }

            try
            {
                // Indexed under the agent id as _id: each report replaces the previous one for that
                // agent by upsert, nothing else to do.
                indexer->index(agentIdIt->second, AGENT_CONFIG_INDEX_NAME, serializedDocument);
            }
            catch (const std::exception& e)
            {
                // The body was fine; the write to storage was not. A 400 here would tell the agent
                // to fix a payload that was never wrong; 503 correctly tells it to retry.
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
