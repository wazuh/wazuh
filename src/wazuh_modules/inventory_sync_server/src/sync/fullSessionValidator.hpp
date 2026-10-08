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

#ifndef _INVSYNC_SYNC_FULL_SESSION_VALIDATOR_HPP
#define _INVSYNC_SYNC_FULL_SESSION_VALIDATOR_HPP

#include "schema/syncSchema.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace invsync::sync
{

    /// D26: Start.groups ceiling. Restates MAX_GROUPS_PER_MULTIGROUP (defs.h), which C++ does not
    /// include -- keep the two equal.
    constexpr std::size_t MAX_START_GROUPS {128};
    /// D26: one group name. Restates MAX_GROUP_NAME (defs.h).
    constexpr std::size_t MAX_START_GROUP_NAME_BYTES {255};
    /// D26: Start.index ceiling. The agent declares one entry per index a module syncs.
    constexpr std::size_t MAX_START_INDICES {64};
    /// D26: one index name -- the indexer's own limit on an index name.
    constexpr std::size_t MAX_START_INDEX_NAME_BYTES {255};

    /**
     * @brief A FullSession that passed every request-level validation, ready for a pipeline worker.
     *
     * The Start-derived fields are OWNED copies (they are small and outlive nothing), while the
     * payload is reached through the FlatBuffer pointer -- the potentially large vectors stay
     * zero-copy. That pointer aliases the HTTP request body, so whoever carries this struct across
     * threads must keep the originating HttpRequest alive alongside it (the pipeline queue item
     * does exactly that, and holding the request also holds its in-flight byte reservation).
     */
    struct ValidatedSession
    {
        const schema::fb::FullSession* session {nullptr};

        schema::fb::Mode mode {};
        schema::fb::Option option {};
        schema::fb::SessionPayload payloadType {};
        /// Whether the session asks for vulnerability-detection handling (option VDFirst/VDSync).
        bool isVD {false};

        std::string moduleName;
        /// The AUTHENTICATED agent id, in its canonical spelling (common/agentId.hpp) -- never the
        /// session's own claim, which only has to equal it. The form every document `_id` and every
        /// `wazuh.agent.id` field uses, consistently for indexing, queries and deletes.
        std::string agentId;
        std::string agentName;
        std::string agentVersion;
        std::string architecture;
        std::string hostname;
        std::string osname;
        std::string osplatform;
        std::string ostype;
        std::string osversion;
        std::vector<std::string> groups;
        std::vector<std::string> indices; ///< Start.index, verbatim (allowlist is applied at use).
        std::uint64_t globalVersion {0};
        /// Start.feed_offset, verbatim. Only meaningful when isVD is true: the agent's locally
        /// stored VD feed offset at the time it built this session, checked against this node's
        /// current offset before the scan lane runs the scan (see IVdScanner::currentFeedOffset).
        std::uint64_t feedOffset {0};
        /// EFFECTIVE cluster name: the session's when non-empty (it was validated against the
        /// manager's), the manager's otherwise -- the same fallback the legacy `_id` builder used.
        std::string clusterName;
    };

    /// A request-level rejection: 400 (protocol) or 403 (identity). The reason lands verbatim in
    /// the response body's "error" field, so keep it caller-actionable and secret-free.
    struct ValidationFailure
    {
        int status {400};
        std::string reason;
    };

    using ValidationResult = std::variant<ValidatedSession, ValidationFailure>;

    /**
     * @brief Runs every request-level validation, in order, CPU-only (safe on an I/O strand).
     *
     * Order (design doc 02 §4): FlatBuffers verifier -> root/content type must be FullSession ->
     * shape (start present, module non-empty) -> identity (header a canonical agent id, the claimed
     * agent id byte-equal to it, cluster byte-equal to the manager's) -> mode x payload matrix ->
     * per-payload rules (SyncData needs values >= 1; Cleans needs items >= 1; ChecksumModule needs
     * an allowlisted index and a checksum) -> Start list caps (D26) -> reachable-bytes budget (D25:
     * the objects the message reaches may not add up to more than the body, which is what catches
     * vector entries aliasing one string or table). Both run before any copy. Anything past this
     * point is per-document policy that runs on the worker (skip-with-WARN, never a request failure).
     *
     * @param body                 Raw request body (the FlatBuffer).
     * @param authenticatedAgentId Value of the X-Wazuh-Agent-Id header remoted authenticated.
     * @param managerClusterName   This manager's cluster name.
     */
    ValidationResult validateFullSession(std::string_view body,
                                         std::string_view authenticatedAgentId,
                                         const std::string& managerClusterName);

} // namespace invsync::sync

#endif // _INVSYNC_SYNC_FULL_SESSION_VALIDATOR_HPP
