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

#ifndef _INVSYNC_SYNC_STATE_INDEX_ALLOWLIST_HPP
#define _INVSYNC_SYNC_STATE_INDEX_ALLOWLIST_HPP

#include <array>
#include <string_view>

namespace invsync::sync
{

    /// The one index agents may clean (DataClean) but never write to (DataValue): its documents are
    /// produced exclusively by the vulnerability scanner on the manager.
    constexpr std::string_view VULNERABILITIES_INDEX {"wazuh-states-vulnerabilities"};

    /// Query scope of a whole-agent deletion (DELETE /agents): every state index at once, the same
    /// pattern the legacy module used. A pattern, not the allowlist above: deletion is
    /// manager-initiated (authd), not an agent session.
    constexpr std::string_view WAZUH_STATES_INDEX_PATTERN {"wazuh-states-*"};

    /// The index `POST /config` writes: one document per agent, agent id as `_id`.
    constexpr std::string_view AGENT_CONFIG_INDEX {"wazuh-agent-config"};

    /// The index `POST /stats` writes, same one-document-per-agent shape.
    constexpr std::string_view AGENT_STATS_INDEX {"wazuh-agent-stats"};

    /*
     * Everything a whole-agent deletion has to reach, split BY WRITER across the two lists below.
     *
     * A document can only be deleted in the right ORDER by the connector that writes it, and this
     * module writes through two: the sync pipeline (state documents) and the async connector (the
     * two `wazuh-agent-*` reports, which it accumulates and pushes in batches). So the deletion has
     * two halves, and each index belongs to exactly one of them -- see deleteAgentEndpoint.hpp.
     *
     * Both `wazuh-agent-*` indices are named exactly (not a `wazuh-agent-*` wildcard) so a future
     * index sharing that prefix is not wiped by accident, and the endpoints that WRITE them take
     * their names from here, so neither half can drift away from what is actually being written.
     *
     * They live OUTSIDE the `wazuh-states-*` family, which is why the states pattern alone once left
     * an agent's configuration and statistics behind forever. That is a DIFFERENT bug from the
     * ordering one, and both are closed: the pattern covers the state family, the by-id list covers
     * those two.
     */

    /// Deleted BY QUERY, on the sync pipeline's connector: one `deleteByQuery` per entry, on the
    /// agent's own worker shard so it orders after that agent's in-flight sessions. Cluster-scoped.
    /// A delete-by-query is a SEARCH, so this half carries the index-refresh window (the documents
    /// the agent's last session wrote may not be searchable yet).
    constexpr std::array<std::string_view, 1> AGENT_DELETION_SCOPE_BY_QUERY {WAZUH_STATES_INDEX_PATTERN};

    /**
     * @brief Deleted BY DOCUMENT ID, on the async connector: one `bulkDelete` per entry.
     *
     * These two hold exactly one document per agent, keyed by the agent id, which is what makes a
     * by-id delete possible -- and the reason it is used rather than a query:
     *
     *  - ORDER. The deletes are queued on the very queue that holds the agent's pending `/config`
     *    and `/stats` reports. It is FIFO, so a report accepted before the deletion is applied
     *    before it. Deleting these through the sync connector instead could not drain that queue,
     *    so a report in flight landed AFTER the purge and outlived the agent.
     *  - VISIBILITY. A by-id delete resolves against the live version map, so unlike the by-query
     *    half it is unaffected by the index refresh interval.
     *
     * Two properties the by-query half had are deliberately given up here, both without loss:
     * cluster scoping (these `_id`s carry no cluster prefix, so two clusters sharing one indexer
     * already collide on WRITE -- the scoping was never real) and reaching a document whose `_id` is
     * not the form this manager writes today (only ever produced by a caller that bypasses remoted,
     * which normalizes the agent id).
     */
    constexpr std::array<std::string_view, 2> AGENT_DELETION_SCOPE_BY_ID {AGENT_CONFIG_INDEX, AGENT_STATS_INDEX};

    /**
     * @brief Allowlist of state indices an agent session may target (its own scope).
     *
     * Same predicate as the legacy module's, relocated: this is the layer-2, per-document control
     * of the extraction's RNF-1 map, and it must survive the migration byte-for-byte so the set of
     * writable indices does not silently widen.
     */
    inline bool isAgentScopedStateIndex(std::string_view idx) noexcept
    {
        return idx.starts_with("wazuh-states-inventory-") || idx == VULNERABILITIES_INDEX ||
               idx.starts_with("wazuh-states-fim-") || idx == "wazuh-states-sca" ||
               idx.starts_with("wazuh-states-sca-");
    }

} // namespace invsync::sync

#endif // _INVSYNC_SYNC_STATE_INDEX_ALLOWLIST_HPP
