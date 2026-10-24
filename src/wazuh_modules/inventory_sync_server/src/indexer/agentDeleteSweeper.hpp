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
#include <memory>
#include <mutex>
#include <string>
#include <thread>

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
     * Thread-safe: note() from any pipeline worker; stop() from the module's stop().
     */
    class AgentDeleteSweeper final
    {
    public:
        static constexpr std::size_t MAX_IDS_PER_QUERY {10000};

        struct Stats
        {
            std::uint64_t runs {0};     ///< Passes that had at least one id due.
            std::uint64_t failures {0}; ///< Delete-by-query chunks that failed.
            std::uint64_t residual {0}; ///< Documents the passes deleted.
            std::uint64_t dropped {0};  ///< Ids abandoned: pending at stop(), or in a chunk that failed twice.
        };

        /**
         * @param query The module Client's query handle, taken once.
         * @param window Minimum age of an id before it is swept, and the tick.
         * @param deadline Deadline of each delete-by-query (the deletion budget, I146c).
         * @param closing The module's closing flag; a pass stops between chunks once it is set.
         */
        AgentDeleteSweeper(std::shared_ptr<indexer_client::IQuery> query,
                           std::chrono::milliseconds window,
                           std::chrono::milliseconds deadline,
                           std::shared_ptr<const std::atomic<bool>> closing);
        ~AgentDeleteSweeper();

        AgentDeleteSweeper(const AgentDeleteSweeper&) = delete;
        AgentDeleteSweeper& operator=(const AgentDeleteSweeper&) = delete;

        /// Records that @p agentId's by-id deletes succeeded now.
        void note(const std::string& agentId);

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

        std::shared_ptr<indexer_client::IQuery> m_query;
        std::chrono::milliseconds m_window;
        std::chrono::milliseconds m_deadline;
        std::shared_ptr<const std::atomic<bool>> m_closing;

        mutable std::mutex m_mutex;
        std::condition_variable m_cv;
        std::deque<Pending> m_pending;
        bool m_stopping {false};
        Stats m_stats;
        std::thread m_thread;
    };

} // namespace invsync::indexer

#endif // _INVSYNC_INDEXER_AGENT_DELETE_SWEEPER_HPP
