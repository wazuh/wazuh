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

#ifndef _INDEXER_CLIENT_QUERY_ENGINE_HPP
#define _INDEXER_CLIENT_QUERY_ENGINE_HPP

// The attempt loop shared by the queries (query.cpp) and the PIT (pit.cpp). NORMATIVE: the
// loop, its clocks and its verdicts are the ones of query.hpp; this header only exposes them and adds two hooks.
//
// HOOKS. Both optional; neither may block nor call back into the engine.
//   preAttempt()  runs before every attempt (also the first, and after every wait). A returned cause aborts the call
//                 at once with that cause and `reason`, without a request (PitExpired for an expired PIT).
//   observer(e)   runs once per admitted attempt with how it ended:
//                   Answered   an HTTP response arrived (any status; `result` set) and the engine classified it;
//                   Failed     a transport failure (`result` set; `result->mayHaveSent` tells an ambiguous one);
//                   Abandoned  the engine stopped waiting (deadline, page, close or shutdown) and cancelled it: the
//                              request may have been sent; no result yet.
//                   Late       the result of an Abandoned attempt, delivered later from the transport callback on a
//                              CPU-pool thread (`result` set; Cancelled when the cancel won), exactly once.
//                 Answered/Failed/Abandoned run on the calling consumer thread, in attempt order; Late may run after
//                 execute() returned, so whatever the observer captures must be owned (shared_ptr).

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>

#include "indexer_client/types.hpp"
#include "query/queryResponse.hpp"
#include "transport/transport.hpp"

namespace indexer_client::detail
{
    struct ClientState;
} // namespace indexer_client::detail

namespace indexer_client::detail::query
{
    /// What one attempt goes to: the method, the target appended to the node's host ("/<indices><route>?<qs>", or
    /// "<route>?<qs>" without indices) and the body, shared by every attempt.
    struct RouteSpec final
    {
        HttpMethod method {HttpMethod::Post};
        std::string target;
        std::shared_ptr<const std::string> body;
    };

    /// The operation's classifier (queryResponse.hpp), called for a 2xx or a 404.
    using Classifier = std::function<QueryResponse(const HttpResult&)>;

    struct AttemptEvent final
    {
        enum class Kind
        {
            Answered,
            Failed,
            Abandoned,
            Late
        };
        Kind kind {Kind::Answered};
        std::uint64_t attempt {0}; ///< 1-based, per execute() call.
        const HttpResult* result {nullptr};
    };

    struct PreAttemptAbort final
    {
        Cause cause {Cause::None};
        std::string reason;
    };

    struct EngineHooks final
    {
        std::function<std::optional<PreAttemptAbort>()> preAttempt;
        std::function<void(const AttemptEvent&)> observer;
    };

    /// "/<indices><route>[?p1&p2...]"; with empty `indices`, "<route>[?...]" (`route` starts with '/').
    std::string target(const std::string& indices, std::string_view route, const std::vector<std::string>& params);

    /// The loop of one page (query.hpp): attempts, clocks, verdicts, conflicts, plus the hooks above.
    Outcome<QueryResponse> execute(const std::shared_ptr<ClientState>& client,
                                   const QueryOptions& options,
                                   Deadline deadline,
                                   const RouteSpec& route,
                                   const Classifier& classify,
                                   const EngineHooks& hooks = {});
} // namespace indexer_client::detail::query

#endif // _INDEXER_CLIENT_QUERY_ENGINE_HPP
