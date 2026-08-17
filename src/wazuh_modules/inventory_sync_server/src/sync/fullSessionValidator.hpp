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

#include <cstdint>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace invsync::sync
{

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
        /// Agent id LEFT-PADDED to 3 characters -- the form every document `_id` and every
        /// `wazuh.agent.id` field has always used (inherited from the legacy module). Used
        /// consistently for indexing, queries and deletes.
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
     * shape (start present, module non-empty) -> identity (agent id numeric-equal to the
     * authenticated header value, cluster byte-equal to the manager's) -> mode x payload matrix ->
     * per-payload rules (SyncData needs values >= 1; Cleans needs items >= 1; ChecksumModule needs
     * an allowlisted index and a checksum). Anything past this point is per-document policy that
     * runs on the worker (skip-with-WARN, never a request failure).
     *
     * @param body                 Raw request body (the FlatBuffer).
     * @param authenticatedAgentId Value of the X-Wazuh-Agent-Id header remoted authenticated.
     * @param managerClusterName   This manager's cluster name.
     */
    ValidationResult validateFullSession(std::string_view body,
                                         std::string_view authenticatedAgentId,
                                         const std::string& managerClusterName);

    /// Shared with DELETE /agents, which validates the same header the same way.
    bool isNumericAgentId(std::string_view value);

    /// Left-pad to 3 characters, the historical `_id`/`wazuh.agent.id` form inherited from the
    /// legacy module. Every query, document id and deletion uses this form.
    std::string padAgentId(std::string_view agentId);

} // namespace invsync::sync

#endif // _INVSYNC_SYNC_FULL_SESSION_VALIDATOR_HPP
