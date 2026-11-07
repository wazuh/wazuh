/*
 * Wazuh inventory sync server module
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "sync/sessionProcessor.hpp"

#include "common/jsonNestingDepth.hpp"
#include "indexer/indexerClientSyncAdapter.hpp" // translateCause
#include "sync/stateIndexAllowlist.hpp"
#include "sync/syncQueryBuilder.hpp"

#include "hashHelper.h"
#include "loggerHelper.h"
#include "wazuhCommon.hpp"

#include <algorithm>
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

    /// The indexer's limit on a document _id (D27).
    constexpr std::size_t MAX_DOCUMENT_ID_BYTES {512};

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
     * Pages the agent's documents by `checksum.hash.sha1 asc` (search_after, batches of
     * @p batchSize), concatenates the checksums in that order and hashes the concatenation. The
     * query shape and the ordering are the CONTRACT with what the agent computes locally, so they
     * are kept byte-identical.
     *
     * The single-field sort needs no tiebreaker: producers hash the whole item JSON, identity
     * fields included, so two documents of one agent in one index cannot share a value.
     */
    std::string calculateChecksumOfChecksums(invsync::indexer::IIndexerConnectorSync& connector,
                                             const std::string& index,
                                             const std::string& agentId,
                                             const std::string& clusterName,
                                             std::size_t batchSize)
    {
        std::string concatenatedChecksums;
        std::string searchAfter;

        while (true)
        {
            nlohmann::json searchQuery;
            searchQuery["query"]["bool"]["must"] = nlohmann::json::array({{{"term", {{"wazuh.agent.id", agentId}}}}});
            invsync::sync::querybuilder::addClusterScope(searchQuery, clusterName);
            searchQuery["_source"] = nlohmann::json::array({"checksum.hash.sha1"});
            searchQuery["sort"] = nlohmann::json::array({nlohmann::json::object({{"checksum.hash.sha1", "asc"}})});
            searchQuery["size"] = batchSize;

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

            if (hits.size() < batchSize)
            {
                break;
            }
        }

        Utils::HashData hash(Utils::HashType::Sha1);
        hash.update(concatenatedChecksums.c_str(), concatenatedChecksums.length());
        const std::vector<unsigned char> hashResult = hash.hash();
        return wazuh::hex_encode(hashResult.data(), hashResult.size());
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

        // Manager-controlled metadata, built once and merged over every upsert. Any field the agent
        // tries to set under these keys gets clobbered, so the agent cannot impersonate another agent
        // or another cluster (legacy facade:1244-1258). merge_patch() replaces whatever non-object
        // value the agent put on the path (`"wazuh":"x"`, `"wazuh":{"agent":[1]}`), where operator[]
        // would throw out of this function and fail every co-batched session with it (D29). Its
        // strings are the Start's, which validation proved serializable.
        nlohmann::json overlay;
        overlay["wazuh"]["agent"]["id"] = session.agentId;
        overlay["wazuh"]["agent"]["name"] = session.agentName;
        overlay["wazuh"]["agent"]["version"] = session.agentVersion;
        overlay["wazuh"]["agent"]["groups"] = session.groups;
        overlay["wazuh"]["agent"]["host"]["architecture"] = session.architecture;
        overlay["wazuh"]["agent"]["host"]["hostname"] = session.hostname;
        overlay["wazuh"]["agent"]["host"]["os"]["name"] = session.osname;
        overlay["wazuh"]["agent"]["host"]["os"]["platform"] = session.osplatform;
        overlay["wazuh"]["agent"]["host"]["os"]["type"] = session.ostype;
        overlay["wazuh"]["agent"]["host"]["os"]["version"] = session.osversion;
        overlay["wazuh"]["cluster"]["name"] = session.clusterName;

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

            // D27: the indexer refuses an _id over 512 bytes, and that one refused item would fail
            // the whole group commit -- every co-batched session with it, on every re-POST.
            if (elementId.size() > MAX_DOCUMENT_ID_BYTES)
            {
                LOGFN_WARN(logFn(),
                           "Skipping bulk entry for agent %s: its _id is %zu bytes, over the indexer's %zu-byte limit.",
                           session.agentId.c_str(),
                           elementId.size(),
                           MAX_DOCUMENT_ID_BYTES);
                ++skipped;
                continue;
            }

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

                const std::string_view rawData {reinterpret_cast<const char*>(value->data()->data()),
                                                value->data()->size()};

                // Before the parse, on the raw bytes (D24): dump() below recurses once per level, so
                // a deep enough document would overflow this worker's stack and take the whole of
                // modulesd down.
                if (common::exceedsNestingDepth(rawData))
                {
                    LOGFN_WARN(logFn(),
                               "Skipping bulk entry for agent %s: DataValue body nests deeper than %zu levels.",
                               session.agentId.c_str(),
                               common::MAX_JSON_NESTING_DEPTH);
                    ++skipped;
                    continue;
                }

                nlohmann::json document = nlohmann::json::parse(rawData, nullptr, /*allow_exceptions=*/false);
                if (document.is_discarded() || !document.is_object())
                {
                    LOGFN_WARN(logFn(),
                               "Skipping bulk entry for agent %s: DataValue body is not a JSON object.",
                               session.agentId.c_str());
                    ++skipped;
                    continue;
                }

                // Everything that can throw while BUILDING the document stays per-document (D29): an
                // exception out of stageBulk() fails the worker's whole open batch, because the
                // pipeline cannot tell it from a connector failure. Nothing has reached the connector
                // for this document yet, so skipping it leaves the staged state exact.
                std::string dataString;
                try
                {
                    document.merge_patch(overlay);
                    dataString = document.dump();
                }
                catch (const nlohmann::json::exception& e)
                {
                    LOGFN_WARN(logFn(),
                               "Skipping bulk entry for agent %s: DataValue body cannot be serialized: %s.",
                               session.agentId.c_str(),
                               e.what());
                    ++skipped;
                    continue;
                }
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

        // deleteByQuery is IMMEDIATE, not staged: it returns once the indexer applied it, so "200
        // answered" means "deletes applied" -- and, since the worker serves this agent's sessions
        // in order, a follow-up SyncData of the same agent (a full resync's second request) cannot
        // overtake the deletes. The connector first waits for every write it still has pending
        // (D49), so neither can the deletes overtake an earlier session's documents. The flush()
        // below sends nothing then; it stays as a harmless no-op so a connector that does stage
        // keeps the same durability contract.
        for (const auto& index : indices)
        {
            connector.deleteByQuery(index, session.agentId, m_managerClusterName);
        }
        connector.flush();

        return ok();
    }

    ProcessOutcome SessionProcessor::executeDeleteAgent(const std::string& agentId,
                                                        indexer::IIndexerConnectorSync& connector,
                                                        const AgentDeletionDeps& deletion,
                                                        std::chrono::steady_clock::time_point until) const
    {
        using Clock = std::chrono::steady_clock;
        using indexer::ConnectorError;

        // The two halves of a whole-agent deletion, both on the agent's own shard worker (I147c), so two deletions
        // of one agent never overlap and both are ordered behind the agent's in-flight sessions.
        //
        // BY-ID (AGENT_DELETION_SCOPE_BY_ID: `wazuh-agent-config`, `wazuh-agent-stats`, whose `_id` IS the agent id).
        // POST /config and POST /stats write them through the `agent-state` bucket, which is `ordered`: an op is
        // never sent before an earlier op of its (index, _id) has a final outcome. So:
        //  1. cancel(agent), not awaited: the agent's pending reports are dropped, an in-flight one is marked (it is
        //     never requeued; if its bulk succeeds it stays applied, and the ordered key keeps our delete behind it).
        //  2. ONE Group with both deletes, tagged with the agent and committed at once (I147d), so a refused add
        //     leaves nothing half-queued. A client closing between the adds and commit() is seen only in the
        //     ticket, after the by-query: harmless, the deletion is idempotent and answers 503 either way.
        //  3. Its ticket is awaited after the by-query, inside the same budget (`until`).
        //
        // The residual, named rather than implied (obj. 11): cancel(agent) also lifts the ambiguous-retry pin of a
        // report that timed out on a node (IC README § Ordered buckets, the D38 window, and § Cancellation), so the
        // ordered key no longer holds our delete behind it. That node may still apply the report after the delete
        // reached another one, and the document reappears. The sweeper note()d below deletes such late documents
        // by id one window later, best effort.
        std::shared_ptr<indexer_client::IWriter> writer;
        indexer_client::GroupTicket ticket;
        // Every failure after the cancel cancels again, without waiting: our own committed deletes are then
        // dropped instead of landing after the 503, and the dispatcher's retry starts from a clean key.
        const auto cancelAgent = [&writer, &agentId]()
        {
            try
            {
                static_cast<void>(writer->cancel(agentId));
            }
            catch (...) // LCOV_EXCL_LINE -- the library answers through the ticket; never let it escape.
            {
            }
        };

        if (deletion.byId)
        {
            writer = deletion.agentState.lock();
            if (!writer)
            {
                throw ConnectorError("the agent-state writer is gone (the module is stopping)",
                                     ConnectorError::Cause::Unavailable);
            }

            cancelAgent(); // Step 1: drop what the agent still has pending in the bucket.

            auto group = writer->group();
            for (const auto& index : AGENT_DELETION_SCOPE_BY_ID)
            {
                indexer_client::Op op;
                op.kind = indexer_client::Op::Kind::Delete;
                op.index = std::string {index};
                op.id = agentId;
                op.tag = agentId;
                if (const auto cause = group.add(std::move(op)); cause != indexer_client::Cause::None)
                {
                    const auto reason = group.lastAddReason();
                    cancelAgent(); // The Group is abandoned uncommitted when it goes out of scope.
                    throw ConnectorError(std::string {"by-id delete refused ("} + indexer_client::toString(cause) +
                                             (reason.empty() ? "" : ": " + reason) + ")",
                                         indexer::translateCause(cause));
                }
            }
            ticket = group.commit();
        }

        // BY-QUERY (AGENT_DELETION_SCOPE_BY_QUERY: this cluster's `wazuh-states-*`), written by the sync pipeline,
        // so this worker's connector deletes it in order.
        //
        // deleteAgentByQuery is immediate, exactly like executeCleans()'s deleteByQuery: it returns once applied
        // (the durability of the 200), after the connector waited for every write it still had pending (D49), and
        // it bounds itself with the deletion route's budget (I145, I145b) instead of an agent request's. A 404 for a
        // not-yet-created index counts as success inside the connector, so re-running a delete is harmless (that is
        // the dispatcher's retry contract). The trailing flush() is the same harmless no-op as in executeCleans().
        //
        // KNOWN LIMITATION, deliberate, and confined to this half: a _delete_by_query is a SEARCH,
        // so it only sees refreshed segments. This deletion arrives behind the agent's last session
        // (authd removes the key, then relays after its purge delay), so whatever that session wrote
        // inside the index refresh interval is invisible to the query and survives -- and with the
        // agent gone from client.keys nothing ever overwrites it. Refreshing each index first would
        // close it, and is deliberately not done: deferring the purge costs the indexer less under
        // load and lets the other workers' writes for this agent land first. Repeating the deletion
        // is the recovery.
        std::string scope;
        try
        {
            for (const auto& index : AGENT_DELETION_SCOPE_BY_QUERY)
            {
                connector.deleteAgentByQuery(std::string {index}, agentId, m_managerClusterName);
                scope += scope.empty() ? "" : ", ";
                scope += index;
            }
            connector.flush();
        }
        catch (...)
        {
            if (writer)
            {
                cancelAgent();
            }
            throw;
        }

        if (deletion.byId)
        {
            // The by-id wait, in slices so `closing` and the shared deadline are honoured while the bucket works.
            while (!ticket.ready())
            {
                if (deletion.closing && deletion.closing->load(std::memory_order_acquire))
                {
                    cancelAgent();
                    throw ConnectorError("the module is closing before the by-id deletes resolved",
                                         ConnectorError::Cause::Unavailable);
                }
                const auto now = Clock::now();
                if (now >= until)
                {
                    cancelAgent();
                    throw ConnectorError("the deletion budget ran out before the by-id deletes resolved",
                                         ConnectorError::Cause::Unavailable);
                }
                static_cast<void>(ticket.wait(std::min(now + deletion.slice, until)));
            }

            const auto results = ticket.wait(Clock::now());
            if (!results.ok())
            {
                cancelAgent();
                throw ConnectorError(std::string {"by-id deletes failed ("} + indexer_client::toString(results.cause) +
                                         (results.reason.empty() ? "" : ": " + results.reason) + ")",
                                     indexer::translateCause(results.cause));
            }
            for (const auto& result : results.value)
            {
                // Ok covers Deleted and NotFound (deleting an absent document is the idempotent retry). A missing
                // INDEX is a permanent item failure to the library, but here it means there is nothing to delete
                // -- the same answer the by-query half gives a 404 (I147b).
                const bool indexMissing = result.status == indexer_client::Status::Failed &&
                                          result.cause == indexer_client::Cause::ItemPermanent &&
                                          result.httpStatus == 404 &&
                                          result.itemErrorType == "index_not_found_exception";
                if (result.status != indexer_client::Status::Ok && !indexMissing)
                {
                    cancelAgent();
                    throw ConnectorError(std::string {"a by-id delete failed ("} +
                                             indexer_client::toString(result.cause) +
                                             (result.reason.empty() ? "" : ": " + result.reason) + ")",
                                         indexer::translateCause(result.cause));
                }
            }

            if (const auto sweeper = deletion.sweeper.lock())
            {
                sweeper->note(agentId);
            }
        }

        // "completed", not "deleted every": the refresh interval can hide what the agent's last session wrote (see
        // the KNOWN LIMITATION above), and a late report can outlive the by-id half until the sweep (see the top).
        LOGFN_INFO(logFn(),
                   "Deletion of agent %s %s completed (%s).",
                   agentId.c_str(),
                   deletion.byId ? "state, configuration and statistics documents" : "state documents",
                   scope.c_str());
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
        const auto calculated =
            calculateChecksumOfChecksums(connector, index, session.agentId, m_managerClusterName, m_queryBatchSize);

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
