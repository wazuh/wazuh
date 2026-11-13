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

#ifndef _INDEXER_CLIENT_NODE_SET_HPP
#define _INDEXER_CLIENT_NODE_SET_HPP

// Node health. The NodeSet owns the state of every configured node; the Prober feeds it
// complete probe rounds, the data path feeds it passive signals, the selector reads it. A 429 with
// Retry-After from any path parks the node (notBefore) for every consumer.

#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "indexer_client/types.hpp"
#include "transport/transport.hpp"

namespace indexer_client::detail
{
    class NodeSet final
    {
    public:
        using State = HealthView::NodeState;
        /// Called after every node transition, outside the NodeSet's mutex, on the thread that caused it.
        using TransitionHook = std::function<void(std::size_t index, State from, State to)>;

        /// Every node starts Down in view(); for the logs its previous state is Unknown, so the first round always
        /// logs. `hosts` in configuration order (the order of HealthView::nodes).
        explicit NodeSet(std::vector<std::string> hosts);

        NodeSet(const NodeSet&) = delete;
        NodeSet& operator=(const NodeSet&) = delete;

        std::size_t size() const;
        const std::string& host(std::size_t index) const;

        /// Applies one complete probe round under the mutex: `round[i]` is node i's probe result (round.size() ==
        /// size()). A round holding any Cancelled or Shutdown result is discarded (no transition, no log); a round
        /// holding a 2xx `red` puts every node Down and sets clusterRed. Returns false when discarded.
        bool applyRound(const std::vector<HttpResult>& round);

        /// Passive signal from the data path, applied at once: a node-attributable failure ⇒ Down; 429 from
        /// Available ⇒ Throttled; anything else is ignored (a passive success never promotes). A 429 with retryAfter
        /// (already capped at retryAfterMax) raises the node's notBefore to now + retryAfter in any state.
        void report(std::size_t index, const HttpResult& result);

        /// Round-robin among the Available nodes; a Throttled one only when none is Available; nullopt when all Down.
        /// A node whose notBefore is in force (> now) is skipped in both passes.
        std::optional<std::size_t> choose();
        /// As choose(), among the nodes `allowed(index)` accepts (the sender's window and notBefore). The filter
        /// runs under this NodeSet's mutex: it may take a leaf mutex (the sender's), never call back into the NodeSet.
        std::optional<std::size_t> choose(const std::function<bool(std::size_t)>& allowed);

        /// The node's notBefore: set by any 429 with Retry-After (report() or a probe round), only ever raised;
        /// in force while > now. A default TimePoint when none was ever set. The sender mirrors it.
        TimePoint notBefore(std::size_t index) const;
        /// The earliest notBefore in force (> now) among the nodes that are not Down; nullopt when none is parked.
        /// A reader with no node to choose waits until then, never past its own deadline.
        std::optional<TimePoint> earliestNotBefore() const;

        /// A copy, safe from any thread.
        HealthView view() const;

        /// +1 per node transition (the bulk sender waits on it).
        std::uint64_t generation() const;

        /// Transitions of one node so far (the load control reads them).
        std::uint64_t transitions(std::size_t index) const;

        /// Registered once by the runtime before the first round; never changed afterwards.
        void onTransition(TransitionHook hook);

    private:
        enum class LogState
        {
            Unknown,
            Available,
            Throttled,
            Down
        };

        struct Node final
        {
            std::string host;
            State state {State::Down};
            LogState logged {LogState::Unknown};
            /// Consecutive probe rounds, ending with the last one, whose own answer was a PERMANENT circuit breaker.
            std::uint32_t permanentStreak {0};
            std::string reason;
            std::uint64_t transitions {0};
            /// Cause of the node's last probe result or passive Down (the «every node Down by Tls» episode).
            TransportCause lastCause {TransportCause::None};
            int lastCurlCode {0};
            TimePoint notBefore {}; ///< Nothing is sent to the node before it (429 Retry-After); only raised.
        };

        /// Log lines and hook calls computed under the mutex, emitted after releasing it (defined in nodeSet.cpp).
        struct Pending;

        /// Under the mutex: moves node `index` to `to`, counting the transition and queueing its logs.
        void transition(std::size_t index, State to, std::string reason, Pending& pending);
        /// Under the mutex, once per probe round and node: extends or ends node `index`'s PERMANENT breaker streak and
        /// queues the WARN on the round that reaches the threshold.
        void countPermanentBreaker(std::size_t index, bool permanent, Pending& pending);
        /// Under the mutex: raises node `index`'s notBefore to `now + result.retryAfter` for a 429 that carries one.
        void park(std::size_t index, const HttpResult& result, TimePoint now);
        /// Under the mutex: enters or leaves the «every node Down by Tls» episode.
        void updateTlsEpisode(Pending& pending);
        /// Without the mutex: writes the queued logs, then calls the hook.
        void emit(Pending& pending) const;

        mutable std::mutex m_mutex;
        std::vector<Node> m_nodes;
        bool m_clusterRed {false};
        std::optional<std::string> m_localFault;
        bool m_allTls {false}; ///< Inside an «every node Down by Tls» episode (a hint for the log).
        std::uint64_t m_generation {0};
        std::size_t m_next {0};
        TransitionHook m_hook;
    };
} // namespace indexer_client::detail

#endif // _INDEXER_CLIENT_NODE_SET_HPP
