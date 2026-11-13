/*
 * Wazuh inventory sync server module
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVSYNC_INDEXER_AGENT_DELETE_SWEEPER_HPP
#define _INVSYNC_INDEXER_AGENT_DELETE_SWEEPER_HPP

#include "indexer_client/client.hpp"
#include "indexer_client/types.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_set>

namespace invsync::indexer
{

    /**
     * @brief Best-effort sweep of AGENT_DELETION_SCOPE_BY_ID after an agent deletion (I36, I146, I146b, I146c).
     *
     * The by-id deletes of a deletion ride the `agent-state` bucket, which is `ordered`: a delete is not sent before
     * the earlier ops of its key resolve. That still leaves one residual: cancel(agent) lifts the ambiguous-retry pin
     * of a report that timed out on a node (IC README § Ordered buckets), so that node may apply the report after the
     * delete reached another one. This sweeper removes what such a late write left behind.
     *
     * The pipeline worker calls note() once a deletion's by-id deletes succeeded. A fixed tick runs at most one pass
     * per `window` (= the runtime's request timeout + 5 s, I146b); a pass takes the ids whose note() is at least
     * `window` old, so each id waits between one and two windows. Each pass runs one delete-by-query PER INDEX (a
     * missing index does not void the other) with `terms` on `_id`, in chunks of at most MAX_IDS_PER_QUERY, without
     * a refresh (P21: the indexer role may lack `indices:admin/refresh`). The documents a pass deletes are the
     * residual. A chunk that fails is retried once on the next pass and then dropped; nothing is swept when no id is
     * due. stop() wakes the thread, joins it and drops what is pending. Nothing here guarantees zero residue.
     *
     * An agent id can be enrolled again as soon as its deletion answered, which is when its sweep is noted. forget()
     * withdraws that id: the `/config` and `/stats` endpoints call it once they accepted a write for the id, so the
     * sweep does not delete the documents of the new agent. The old agent's key is gone by then, so such a write comes
     * from the new one, and it replaces any late document of the old one (same `_id`).
     *
     * Thread-safe: note() from any pipeline worker; forget() from any endpoint thread; stop() from the module's stop().
     */
    class AgentDeleteSweeper final
    {
    public:
        static constexpr std::size_t MAX_IDS_PER_QUERY {10000};

        /// The clock that dates note() and judges an id's age.
        using NowFn = std::function<std::chrono::steady_clock::time_point()>;

        struct Stats
        {
            std::uint64_t runs {0};      ///< Passes that had at least one id due.
            std::uint64_t failures {0};  ///< Delete-by-query chunks that failed.
            std::uint64_t residual {0};  ///< Documents the passes deleted.
            std::uint64_t dropped {0};   ///< Ids abandoned: pending at stop(), or in a chunk that failed twice.
            std::uint64_t forgotten {0}; ///< forget() calls that withdrew a pending id (the agent reported again).
        };

        /**
         * @param query The module Client's query handle, taken once.
         * @param window Minimum age of an id before it is swept, and the tick.
         * @param deadline Deadline of each delete-by-query (the deletion budget, I146c).
         * @param closing The module's closing flag; a pass stops between chunks once it is set.
         * @param now The clock that dates note() and judges an id's age (empty: steady_clock::now). The tick
         * cadence always follows steady_clock, so a test can set the ages without stalling the thread.
         */
        AgentDeleteSweeper(std::shared_ptr<indexer_client::IQuery> query,
                           std::chrono::milliseconds window,
                           std::chrono::milliseconds deadline,
                           std::shared_ptr<const std::atomic<bool>> closing,
                           NowFn now = {});
        ~AgentDeleteSweeper();

        AgentDeleteSweeper(const AgentDeleteSweeper&) = delete;
        AgentDeleteSweeper& operator=(const AgentDeleteSweeper&) = delete;

        /// Records that @p agentId's by-id deletes succeeded now.
        void note(const std::string& agentId);

        /**
         * @brief Withdraws @p agentId from the sweep: a write for it was accepted after its deletion.
         *
         * Removes every pending note of the id and, when the pass in progress holds it, keeps the pass from sending it
         * in a chunk that has not been sent yet (a delete-by-query already in flight cannot be recalled). The id is not
         * retried later either. Cheap when nothing is pending: one atomic load, no lock. Counted in `forgotten` when it
         * withdrew something.
         */
        void forget(const std::string& agentId);

        /// Wakes, joins and drops what is pending (counted in `dropped`). Idempotent.
        void stop();

        Stats stats() const;

    private:
        struct Pending
        {
            std::string agentId;
            std::chrono::steady_clock::time_point notedAt;
            bool retried {false};
        };

        void run();
        /// Publishes m_tracked after m_pending or m_inPass changed. Under m_mutex.
        void updateTrackedLocked();

        std::shared_ptr<indexer_client::IQuery> m_query;
        std::chrono::milliseconds m_window;
        std::chrono::milliseconds m_deadline;
        std::shared_ptr<const std::atomic<bool>> m_closing;
        NowFn m_now;

        mutable std::mutex m_mutex;
        std::condition_variable m_cv;
        std::deque<Pending> m_pending;
        /// The ids of the pass in progress, and those of them that forget() withdrew meanwhile (both empty between
        /// passes).
        std::unordered_set<std::string> m_inPass;
        std::unordered_set<std::string> m_forgottenInPass;
        /// m_pending.size() + m_inPass.size(), so forget() skips the lock when there is nothing to withdraw.
        std::atomic<std::size_t> m_tracked {0};
        bool m_stopping {false};
        Stats m_stats;
        std::thread m_thread;
    };

} // namespace invsync::indexer

#endif // _INVSYNC_INDEXER_AGENT_DELETE_SWEEPER_HPP
