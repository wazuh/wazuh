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

#ifndef _INDEXER_CLIENT_QUERY_RESPONSE_HPP
#define _INDEXER_CLIENT_QUERY_RESPONSE_HPP

// Pure classifiers of a query response (stage E4a, I83-I86, 03 §4.16). The engine (query.hpp) calls them only for a
// transfer that got an HTTP response which classifyRequest(r, 1) did not already settle: a 2xx (verdict Items) or a
// 404 (FailBatch Client4xx). Every other status follows the I65 table in the engine. No network, no state.

#include <cstdint>
#include <string>

#include "json.hpp"

#include "indexer_client/types.hpp"
#include "transport/transport.hpp"

namespace indexer_client::detail::query
{
    enum class QueryVerdict
    {
        Ok,       ///< `body` holds the parsed response (search, DBQ, UBQ) and `exists` the HEAD answer.
        Conflict, ///< DBQ/UBQ: version conflicts (I86 budget); `versionConflicts` holds the count.
        Retry,    ///< DBQ/UBQ `timed_out`: retry under I82 with an attempt.
        Fail      ///< Final: `cause` (NotFound, Client4xx, ItemPermanent), `httpStatus`, `reason`.
    };

    struct QueryResponse final
    {
        QueryVerdict verdict {QueryVerdict::Ok};
        Cause cause {Cause::None};
        int httpStatus {0};
        std::string reason;
        nlohmann::json body;
        bool exists {false};
        std::uint64_t versionConflicts {0};
        bool tooLarge {false}; ///< Fail ItemPermanent because of the I84 size cap (queryStats().tooLarge).
    };

    /// `error.type` of an OpenSearch error body (also `error` as a plain string); empty when absent or unparsable.
    std::string errorType(const std::string& body);

    /// "<status> <type>: <at most REASON_BODY_BYTES of body>", within OpResult::MAX_REASON.
    std::string errorReason(long status, const std::string& body);

    /// search / searchAfter pages. 2xx: the parsed body, or Fail ItemPermanent when it is unparsable or
    /// body.size() * QUERY_DOM_FACTOR > maxResponseBytes. 404: index_not_found_exception ⇒ Fail NotFound, else Fail
    /// Client4xx.
    QueryResponse classifySearch(const HttpResult& result, std::uint64_t maxResponseBytes);

    /// deleteByQuery (isDelete) and updateByQuery, 03 §4.16. 2xx: unparsable or too large ⇒ Fail ItemPermanent;
    /// `failures` all version_conflict_engine_exception / status 409 ⇒ Conflict; any other `failures` ⇒ Fail
    /// ItemPermanent with the first failure in reason; `timed_out` ⇒ Retry; version_conflicts > 0 ⇒ Conflict; else
    /// Ok. 404: index_not_found_exception ⇒ Ok({}) for a delete, Fail NotFound for an update; any other 404 ⇒ Fail
    /// Client4xx.
    QueryResponse classifyByQuery(const HttpResult& result, bool isDelete, std::uint64_t maxResponseBytes);

    /// indexExists (HEAD, no body): 2xx ⇒ Ok exists = true; 404 ⇒ Ok exists = false.
    QueryResponse classifyExists(const HttpResult& result);
} // namespace indexer_client::detail::query

#endif // _INDEXER_CLIENT_QUERY_RESPONSE_HPP
