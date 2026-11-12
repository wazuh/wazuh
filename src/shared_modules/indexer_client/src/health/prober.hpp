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

#ifndef _INDEXER_CLIENT_PROBER_HPP
#define _INDEXER_CLIENT_PROBER_HPP

// The health probe (stage E2b, plan 18 I57): one `GET {host}/_cluster/health/wazuh-*,.wazuh-*` per node and round,
// through the transport, armed by a timer that lives on network loop 0 and is touched only from that loop. A round is
// applied to the NodeSet only once its K results are in; rounds never overlap. No asio type appears in this header.

#include <cstdint>
#include <memory>

#include "health/nodeSet.hpp"
#include "indexer_client/types.hpp"
#include "transport/transport.hpp"

namespace asio
{
    class io_context;
} // namespace asio

namespace indexer_client::detail
{
    /**
     * @brief The indices the probe asks about: everything the manager reads or writes.
     *
     * A cluster-wide `_cluster/health` turns red for one unassigned primary in ANY index (an alerting index, a user's
     * own), and red marks every node Down, so an index the manager never touches would stop all of its indexer
     * traffic. `wazuh-*` covers what it writes (the events and findings data streams, `wazuh-states-*`, metrics,
     * agent config and stats) and `.wazuh-*` what it reads (`.wazuh-cti-consumers`, `.wazuh-settings`,
     * `.wazuh-threatintel-*`); a wildcard resolves a data stream to its backing indices.
     *
     * Deliberately not configurable: a pattern that matches nothing makes `_cluster/health` answer `green` for an empty
     * index list, so the nodes would look healthy forever. A component test pins the exact URL.
     */
    inline constexpr const char* MANAGER_INDEX_PATTERN {"wazuh-*,.wazuh-*"};

    struct ProberStats final
    {
        std::uint64_t rounds {0};          ///< Rounds armed (every probe of the round submitted or refused).
        std::uint64_t roundsApplied {0};   ///< Rounds the NodeSet applied.
        std::uint64_t roundsDiscarded {0}; ///< Rounds dropped for a Cancelled/Shutdown result.
        std::uint64_t roundsSkipped {0};   ///< Timer ticks that found the previous round still in flight.
        std::uint64_t submitsRefused {0};  ///< Probes the transport did not admit.
        /// Probe results other than Shutdown that arrived once stop() had begun (the transport's Shutdown for a
        /// probe still in flight is expected and not counted).
        std::uint64_t resultsAfterStop {0};
    };

    class Prober
    {
    public:
        virtual ~Prober() = default;

        /// Arms the first round at once (no wait for `interval`) and then one per `interval`.
        virtual void start() = 0;

        /// Idempotent. Sets the stop flag, posts the timer's cancellation to loop 0 and waits for it; after it returns
        /// no round is armed and no probe is submitted. Called by the runtime before Transport::stop.
        virtual void stop() = 0;

        /// Tests: arms a round now (posted to loop 0) and re-arms the interval from it, so it shifts the schedule:
        /// nobody may rely on the tick phase. False when stopped or a round is in flight.
        virtual bool probeNow() = 0;

        virtual ProberStats stats() const = 0;

        /// `loop0` must outlive stop(); the transport and the NodeSet are shared with every probe callback. Destroying
        /// a Prober without stop() is a usage error (counted): its timer would die off loop 0. The runtime stops it in
        /// stopAndJoin, before the loops are joined.
        static std::shared_ptr<Prober> create(std::shared_ptr<NodeSet> nodes,
                                              std::shared_ptr<Transport> transport,
                                              asio::io_context& loop0,
                                              Duration interval,
                                              Duration timeout);
    };

    /// The running runtime's NodeSet / Prober, or null. For internal users (E3b, E4) and the component tests.
    std::shared_ptr<NodeSet> runtimeNodeSet();
    std::shared_ptr<Prober> runtimeProber();

} // namespace indexer_client::detail

#endif // _INDEXER_CLIENT_PROBER_HPP
