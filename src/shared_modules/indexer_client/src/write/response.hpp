/*
 * Wazuh indexer client
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _INDEXER_CLIENT_WRITE_RESPONSE_HPP
#define _INDEXER_CLIENT_WRITE_RESPONSE_HPP

// Classification of a `_bulk` response (stage E3b-1, plan 18 I65). Pure: verdicts, no policy, no bucket type; the
// sender (E3b-2) applies the bucket's policies and E4 may reuse the request classifier. No simdjson type in this
// header. Normative contract: anexos/e2a-1/contrato-transport.md § Clasificación y carril.

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

#include "indexer_client/types.hpp"
#include "transport/transport.hpp"

namespace indexer_client::detail::write
{
    enum class RequestVerdict
    {
        Items,     ///< 2xx: classify the items.
        Failover,  ///< Node-attributable transport failure: another node (attempt iff mayHaveSent).
        Retry,     ///< 408, 5xx, 401, 403, TlsConfig, LocalError (cause InvalidState): retry with an attempt.
        Throttled, ///< 429: the node waits (retryAfter, if any); no attempt.
        Split,     ///< 413 or ResponseTooLarge with more than one op: halve the batch.
        FailBatch, ///< Every op Failed(cause): other 4xx (incl. 409), 3xx, 413/ResponseTooLarge of a single op.
        Ignore     ///< Cancelled, Shutdown: the sweep resolves the ops.
    };

    struct RequestOutcome final
    {
        RequestVerdict verdict {RequestVerdict::Items};
        Cause cause {Cause::None}; ///< For FailBatch, Retry and Failover (the op's lastCause).
        int httpStatus {0};
        std::string reason; ///< <= OpResult::MAX_REASON.
        std::optional<Duration> retryAfter;
        bool mayHaveSent {false}; ///< From HttpResult: E3b-2 counts a failover attempt, E3c decides I36 ambiguity.
    };

    /// I65 request table over a finished transfer of a batch of `batchSize` ops.
    RequestOutcome classifyRequest(const HttpResult& result, std::size_t batchSize);

    enum class ItemVerdict
    {
        Ok,       ///< 2xx; `outcome` from `result`.
        NotFound, ///< delete 404 `not_found` without `error`: idempotent success (ItemOutcome::NotFound).
        Retry,    ///< 429, 5xx, cluster_block_exception, es_rejected_execution_exception.
        Conflict, ///< 409 + version_conflict_engine_exception (status and type kept); the bucket's ConflictPolicy
                  ///< decides.
        Permanent ///< Any other 4xx, a 404 with index_not_found_exception, a malformed item.
    };

    struct ItemResult final
    {
        ItemVerdict verdict {ItemVerdict::Ok};
        ItemOutcome outcome {ItemOutcome::None};
        int httpStatus {0};
        std::string itemErrorType; ///< <= OpResult::MAX_ITEM_ERROR_TYPE.
        std::string reason;        ///< <= OpResult::MAX_REASON, `caused_by` appended as "type: reason".
    };

    /// I65 item table over a 2xx `_bulk` body, item i <-> op i. nullopt when the body is unreadable or does not hold
    /// exactly `expected` items. `body` is taken by mutable reference so the parser can add its padding when the
    /// transport did not (it normally did: RESPONSE_PADDING); its content is unchanged.
    /// When nullopt and `reason` is given, it receives why ("unreadable body: ...", "items: got N, expected M", ...):
    /// E3b-2 keeps it as the ops' last error (G-diff E3b-1 obj. 1).
    std::optional<std::vector<ItemResult>>
    classifyItems(std::string& body, std::size_t expected, std::string* reason = nullptr);
} // namespace indexer_client::detail::write

#endif // _INDEXER_CLIENT_WRITE_RESPONSE_HPP
