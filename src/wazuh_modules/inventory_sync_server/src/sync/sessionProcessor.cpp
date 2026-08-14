/*
 * Wazuh inventory sync server module
 * Copyright (C) 2015, Wazuh Inc.
 * August 4, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "sync/sessionProcessor.hpp"

#include "sync/stateIndexAllowlist.hpp"
#include "sync/syncQueryBuilder.hpp"

#include "hashHelper.h"
#include "loggerHelper.h"
#include "stringHelper.h"

#include <json.hpp>

#include <set>
#include <string_view>

namespace
{
    constexpr auto PROCESSOR_LOGTAG {"wazuh-manager-modulesd:inventory-sync-server:sync"};

    const LogFn& logFn()
    {
        static const LogFn instance {PROCESSOR_LOGTAG};
        return instance;
    }

    namespace fb = invsync::schema::fb;

    constexpr auto OK_BODY {R"({"status":"ok"})"};
    constexpr auto NOOP_BODY {R"({"status":"ok","noop":true})"};
    constexpr auto CHECKSUM_MISMATCH_BODY {R"({"status":"checksum_mismatch"})"};

    invsync::sync::ProcessOutcome ok()
    {
        return {200, OK_BODY, false};
    }

    invsync::sync::ProcessOutcome noop()
    {
        return {200, NOOP_BODY, false};
    }

    std::string_view viewOf(const flatbuffers::String* value)
    {
        return value ? value->string_view() : std::string_view {};
    }

    /**
     * @brief Checksum-of-checksums, ported from the legacy facade (inventorySyncFacade.hpp:434-503).
     *
     * Pages the agent's documents by `checksum.hash.sha1 asc` (search_after, batches of 1000),
     * concatenates the checksums in that order and hashes the concatenation. The query shape and
     * the ordering are the CONTRACT with what the agent computes locally, so they are kept
     * byte-identical.
     */
    std::string calculateChecksumOfChecksums(invsync::indexer::IIndexerConnectorSync& connector,
                                             const std::string& index,
                                             const std::string& agentId,
                                             const std::string& clusterName)
    {
        std::string concatenatedChecksums;
        std::string searchAfter;
        constexpr std::size_t BATCH_SIZE = 1000;

        while (true)
        {
            nlohmann::json searchQuery;
            searchQuery["query"]["bool"]["must"] = nlohmann::json::array({{{"term", {{"wazuh.agent.id", agentId}}}}});
            invsync::sync::querybuilder::addClusterScope(searchQuery, clusterName);
            searchQuery["_source"] = nlohmann::json::array({"checksum.hash.sha1"});
            searchQuery["sort"] = nlohmann::json::array({nlohmann::json::object({{"checksum.hash.sha1", "asc"}})});
            searchQuery["size"] = BATCH_SIZE;

            if (!searchAfter.empty())
            {
                searchQuery["search_after"] = nlohmann::json::array({searchAfter});
            }

            const auto searchResult = connector.executeSearchQuery(index, searchQuery);

            if (!searchResult.contains("hits") || !searchResult["hits"].contains("hits") ||
                searchResult["hits"]["hits"].empty())
            {
                break;
            }

            const auto& hits = searchResult["hits"]["hits"];
            for (const auto& hit : hits)
            {
                if (hit.contains("_source") && hit["_source"].contains("checksum") &&
                    hit["_source"]["checksum"].contains("hash") && hit["_source"]["checksum"]["hash"].contains("sha1"))
                {
                    concatenatedChecksums += hit["_source"]["checksum"]["hash"]["sha1"].template get<std::string>();
                }

                if (hit.contains("sort") && !hit["sort"].empty())
                {
                    searchAfter = hit["sort"][0].template get<std::string>();
                }
            }

            if (hits.size() < BATCH_SIZE)
            {
                break;
            }
        }

        Utils::HashData hash(Utils::HashType::Sha1);
        hash.update(concatenatedChecksums.c_str(), concatenatedChecksums.length());
        const std::vector<unsigned char> hashResult = hash.hash();
        return Utils::asciiToHex(hashResult);
    }
} // namespace

namespace invsync::sync
{

    SessionKind classify(const ValidatedSession& session) noexcept
    {
        return session.payloadType == fb::SessionPayload_SyncData ? SessionKind::BulkData : SessionKind::Immediate;
    }

    ProcessOutcome SessionProcessor::stageBulk(const ValidatedSession& session,
                                               indexer::IIndexerConnectorSync& connector) const
    {
        const auto* payload = session.session->payload_as_SyncData();

        /*
         * Pre-scan pass: an operation outside the enum is a PROTOCOL error and must fail the
         * request with 400 -- but only if nothing was staged yet, or the poisoned staging would
         * drag the worker's whole open batch down with it. Scanning first keeps "reject" and
         * "stage" from interleaving. (Per-DOCUMENT problems, by contrast, are skip-with-WARN below
         * and never fail the request.)
         */
        for (const auto* value : *payload->values())
        {
            const auto operation = value->operation();
            if (operation != fb::Operation_Upsert && operation != fb::Operation_Delete)
            {
                return {400, R"({"error":"Invalid operation","code":400})", false};
            }
        }

        std::size_t staged {0};
        std::size_t skipped {0};
        std::size_t stagedBytes {0};

        for (const auto* value : *payload->values())
        {
            // Layer-2 allowlist, per document (legacy facade:1144-1166): the index must be in the
            // agent's own scope, and wazuh-states-vulnerabilities is clean-only (its documents are
            // produced by the manager's scanner, never by agents).
            const auto rawIndex = viewOf(value->index());
            if (!isAgentScopedStateIndex(rawIndex))
            {
                LOGFN_WARN(logFn(),
                           "Skipping bulk entry for agent %s: index '%.*s' does not belong to the wazuh-states-* "
                           "family.",
                           session.agentId.c_str(),
                           static_cast<int>(rawIndex.size()),
                           rawIndex.data());
                ++skipped;
                continue;
            }
            if (rawIndex == VULNERABILITIES_INDEX)
            {
                LOGFN_WARN(logFn(),
                           "Rejecting agent write to '%s' (agent %s): agents may clean it, never write it.",
                           std::string {VULNERABILITIES_INDEX}.c_str(),
                           session.agentId.c_str());
                ++skipped;
                continue;
            }

            if (viewOf(value->id()).empty())
            {
                LOGFN_WARN(logFn(),
                           "Skipping bulk entry for agent %s: DataValue is missing the required 'id' field.",
                           session.agentId.c_str());
                ++skipped;
                continue;
            }

            const bool isUpsert = value->operation() == fb::Operation_Upsert;

            // _id = {cluster}_{agent(3)}_{document id}: the cluster scoping that keeps two
            // same-numbered agents of different clusters from colliding (legacy facade:1236-1242).
            std::string elementId;
            elementId.reserve(session.clusterName.size() + session.agentId.size() + viewOf(value->id()).size() + 2);
            elementId.append(session.clusterName);
            elementId.append("_");
            elementId.append(session.agentId);
            elementId.append("_");
            elementId.append(viewOf(value->id()));

            if (isUpsert)
            {
                // Strict parse before staging: nlohmann rejects unescaped control characters
                // (literal newlines that would smuggle extra NDJSON actions into the bulk stream)
                // and trailing garbage; the object-root requirement closes the rest.
                if (value->data() == nullptr)
                {
                    LOGFN_WARN(logFn(),
                               "Skipping bulk entry for agent %s: DataValue is missing the 'data' field for Upsert.",
                               session.agentId.c_str());
                    ++skipped;
                    continue;
                }

                nlohmann::json document = nlohmann::json::parse(
                    std::string_view(reinterpret_cast<const char*>(value->data()->data()), value->data()->size()),
                    nullptr,
                    /*allow_exceptions=*/false);
                if (document.is_discarded() || !document.is_object())
                {
                    LOGFN_WARN(logFn(),
                               "Skipping bulk entry for agent %s: DataValue body is not a JSON object.",
                               session.agentId.c_str());
                    ++skipped;
                    continue;
                }

                // Overlay manager-controlled metadata on top of the agent payload. Any field the
                // agent tries to set under wazuh.* gets clobbered here, so the agent cannot
                // impersonate another agent or another cluster (legacy facade:1244-1258).
                document["wazuh"]["agent"]["id"] = session.agentId;
                document["wazuh"]["agent"]["name"] = session.agentName;
                document["wazuh"]["agent"]["version"] = session.agentVersion;
                document["wazuh"]["agent"]["groups"] = session.groups;
                document["wazuh"]["agent"]["host"]["architecture"] = session.architecture;
                document["wazuh"]["agent"]["host"]["hostname"] = session.hostname;
                document["wazuh"]["agent"]["host"]["os"]["name"] = session.osname;
                document["wazuh"]["agent"]["host"]["os"]["platform"] = session.osplatform;
                document["wazuh"]["agent"]["host"]["os"]["type"] = session.ostype;
                document["wazuh"]["agent"]["host"]["os"]["version"] = session.osversion;
                document["wazuh"]["cluster"]["name"] = session.clusterName;

                const auto dataString = document.dump();
                stagedBytes += dataString.size();

                // version > 0 rides the external_gte path (a scripted update that checks
                // state.document_version); 0/absent uses plain indexing (legacy facade:1263-1272).
                if (const auto version = value->version(); version > 0)
                {
                    connector.bulkIndex(elementId, rawIndex, dataString, std::to_string(version));
                }
                else
                {
                    connector.bulkIndex(elementId, rawIndex, dataString);
                }
            }
            else
            {
                connector.bulkDelete(elementId, rawIndex);
            }

            ++staged;
        }

        // DataContext items are deliberately NOT indexed: they exist to feed the vulnerability
        // scanner's context (the scan lane consumes them when it lands).

        if (m_docsIndexed)
        {
            m_docsIndexed->add(staged);
            m_docsSkipped->add(skipped);
            m_bytesIngested->add(stagedBytes);
        }

        if (staged == 0)
        {
            LOGFN_WARN(logFn(),
                       "Session from agent %s staged nothing (%zu document(s) skipped); answering no-op.",
                       session.agentId.c_str(),
                       skipped);
            return noop();
        }

        return {200, OK_BODY, true};
    }

    ProcessOutcome SessionProcessor::executeImmediate(const ValidatedSession& session,
                                                      indexer::IIndexerConnectorSync& connector) const
    {
        if (session.payloadType == fb::SessionPayload_Cleans)
        {
            return executeCleans(session, connector);
        }
        if (session.payloadType == fb::SessionPayload_ChecksumModule)
        {
            return executeChecksum(session, connector);
        }
        return executeMetadataOrGroups(session, connector);
    }

    ProcessOutcome SessionProcessor::executeCleans(const ValidatedSession& session,
                                                   indexer::IIndexerConnectorSync& connector) const
    {
        // Dedup with a set, like the legacy Context::dataCleanIndices: an agent may repeat an
        // index and each one must be deleted exactly once.
        std::set<std::string> indices;
        for (const auto* item : *session.session->payload_as_Cleans()->items())
        {
            const auto index = viewOf(item->index());
            if (index.empty() || !isAgentScopedStateIndex(index))
            {
                LOGFN_WARN(logFn(),
                           "Cleans from agent %s: ignoring index '%.*s' (not in the wazuh-states-* family).",
                           session.agentId.c_str(),
                           static_cast<int>(index.size()),
                           index.data());
                continue;
            }
            indices.emplace(index);
        }

        if (indices.empty())
        {
            return noop();
        }

        // deleteByQuery STAGES into the connector (it is flushed, not immediate), so the flush
        // right here is what makes "200 answered" mean "deletes applied" -- and what keeps a
        // follow-up SyncData of the same agent (a full resync's second request) from being
        // reordered ahead of the deletes.
        for (const auto& index : indices)
        {
            connector.deleteByQuery(index, session.agentId, m_managerClusterName);
        }
        connector.flush();

        return ok();
    }

    ProcessOutcome SessionProcessor::executeDeleteAgent(const std::string& agentId,
                                                        indexer::IIndexerConnectorSync& connector) const
    {
        // The whole scope, not just the states pattern: `wazuh-agent-config` and `wazuh-agent-stats`
        // sit outside the wazuh-states-* family and used to survive the agent. This is a whole-agent
        // deletion (the agent is GONE from client.keys), so it must reach every index holding its
        // documents, including ones no current session writes to. deleteByQuery stages; the flush is
        // the durability of the 200, exactly like executeCleans() -- a 404 for a not-yet-created
        // index counts as success inside the connector, so re-running a delete is harmless (that is
        // authd's retry contract).
        //
        // KNOWN LIMITATION, deliberate: a _delete_by_query is a SEARCH, so it only sees refreshed
        // segments. This deletion arrives immediately behind the agent's last session (authd removes
        // the key, then calls us), so whatever that session wrote inside the index refresh interval
        // is invisible to the query and survives -- and with the agent gone from client.keys nothing
        // ever overwrites it. Refreshing each index first would close that window, but `_refresh`
        // needs `indices:admin/refresh`, which the manager's least-privilege indexer role does not
        // grant: every deletion then failed with 403 instead of missing a few documents. Repeating
        // the deletion is the recovery meanwhile; see the follow-up to restore the refresh once the
        // privilege is in place.
        std::string scope;
        for (const auto& index : AGENT_DELETION_SCOPE)
        {
            connector.deleteByQuery(std::string {index}, agentId, m_managerClusterName);
            scope += scope.empty() ? "" : ", ";
            scope += index;
        }
        connector.flush();

        LOGFN_INFO(logFn(), "Deleted every document of agent %s (%s).", agentId.c_str(), scope.c_str());
        return ok();
    }

    ProcessOutcome SessionProcessor::executeChecksum(const ValidatedSession& session,
                                                     indexer::IIndexerConnectorSync& connector) const
    {
        const auto* payload = session.session->payload_as_ChecksumModule();
        const std::string index {viewOf(payload->index())};
        const std::string claimed {viewOf(payload->checksum())};

        // ONE attempt, no retries (D16): the worker already flushed this agent's earlier deltas
        // (same shard, batch cut), so the only staleness left is the indexer's refresh interval --
        // and a false mismatch there costs one full resync, which is correct, just expensive.
        const auto calculated = calculateChecksumOfChecksums(connector, index, session.agentId, m_managerClusterName);

        if (calculated != claimed)
        {
            LOGFN_DEBUG1(logFn(),
                         "Checksum mismatch for agent %s on '%s': agent claims %s, manager calculated %s.",
                         session.agentId.c_str(),
                         index.c_str(),
                         claimed.c_str(),
                         calculated.c_str());
            return {409, CHECKSUM_MISMATCH_BODY, false};
        }

        return ok();
    }

    ProcessOutcome SessionProcessor::executeMetadataOrGroups(const ValidatedSession& session,
                                                             indexer::IIndexerConnectorSync& connector) const
    {
        // Layer-1 allowlist applied to the DECLARED indices before they reach the update-by-query
        // URL: the painless scripts are agent-scoped by the query, but there is no reason to let a
        // session aim them at indices outside the agent-state family at all.
        std::vector<std::string> indices;
        indices.reserve(session.indices.size());
        for (const auto& index : session.indices)
        {
            if (!isAgentScopedStateIndex(index))
            {
                LOGFN_WARN(logFn(),
                           "Metadata/groups session from agent %s: ignoring declared index '%s' (not in the "
                           "wazuh-states-* family).",
                           session.agentId.c_str(),
                           index.c_str());
                continue;
            }
            indices.push_back(index);
        }

        if (indices.empty())
        {
            return noop();
        }

        nlohmann::json updateQuery;
        switch (session.mode)
        {
            case fb::Mode_MetadataDelta:
                updateQuery = querybuilder::buildMetadataUpdateQuery(session.agentId,
                                                                     session.agentName,
                                                                     session.agentVersion,
                                                                     session.architecture,
                                                                     session.hostname,
                                                                     session.osname,
                                                                     session.osplatform,
                                                                     session.ostype,
                                                                     session.osversion,
                                                                     session.globalVersion);
                break;
            case fb::Mode_GroupDelta:
                updateQuery =
                    querybuilder::buildGroupsUpdateQuery(session.agentId, session.groups, session.globalVersion);
                break;
            case fb::Mode_MetadataCheck:
                updateQuery = querybuilder::buildMetadataCheckQuery(session.agentId,
                                                                    session.agentName,
                                                                    session.agentVersion,
                                                                    session.architecture,
                                                                    session.hostname,
                                                                    session.osname,
                                                                    session.osplatform,
                                                                    session.ostype,
                                                                    session.osversion);
                break;
            default: updateQuery = querybuilder::buildGroupsCheckQuery(session.agentId, session.groups); break;
        }
        querybuilder::addClusterScope(updateQuery, m_managerClusterName);

        connector.executeUpdateByQuery(indices, updateQuery);

        return ok();
    }

} // namespace invsync::sync
