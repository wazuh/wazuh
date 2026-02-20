/**
 * @file agent_state.hpp
 * @brief C++17 replacement for state.h / state.c
 *
 * Encapsulates agent statistics (status, keepalive times, message
 * counters) behind a thread-safe class with std::mutex.
 *
 * A thin set of `extern "C"` free functions is provided so that the
 * preserved C headers (agentd.h, state.h) continue to expose the
 * original API (`w_agentd_state_init`, `w_agentd_state_update`, etc.).
 *
 * Copyright (C) 2015, Wazuh Inc.
 */

#ifndef AGENTD_AGENT_STATE_HPP
#define AGENTD_AGENT_STATE_HPP

#include "agentd_compat.hpp" // extern-C wrapped Wazuh headers + CJsonPtr

extern "C"
{
#include "agentd.h" // agt, w_agentd_get_buffer_lenght(), __local_name
#include "state.h"  // w_agentd_state_update_t, agent_state_t, agent_status_t
}

#include <ctime>

namespace agentd
{

    /**
     * @brief Thread-safe manager for agent runtime statistics.
     *
     * Replaces the C global `agent_state` + `state_mutex` with an
     * encapsulated class.  All public methods lock internally.
     */
    class AgentState
    {
    public:
        AgentState() = default;
        ~AgentState() = default;

        // Non-copyable, non-movable (owns a mutex)
        AgentState(const AgentState&) = delete;
        AgentState& operator=(const AgentState&) = delete;

        /** Initialise state (read config for file-write interval). */
        void init();

        /** Return the configured state-file write interval (seconds). */
        int getInterval() const noexcept
        {
            return interval_;
        }

        /**
         * Main loop: periodically writes the state file.
         * Designed to run in its own thread.
         */
        void run();

        /** Apply a state update (thread-safe). */
        void update(w_agentd_state_update_t type, void* data);

        /**
         * Return a JSON snapshot of the current state.
         * @return Heap-allocated string (caller frees with `free()`
         *         to stay compatible with the C callers).
         */
        char* getJson();

        /** Access the singleton instance. */
        static AgentState& instance();

    private:
        /** Format a time_t into the state-file time format.
         *  Returns an empty string when `t == 0`. */
        static std::string formatTime(std::time_t t);

        /** Map agent_status_t to a human-readable string. */
        static const char* statusToString(agent_status_t status);

        /** Atomically write the state file (Unix: write-to-temp + rename). */
        int writeFile();

        // ── State ────────────────────────────────────────────────
        mutable std::mutex mutex_;
        agent_state_t state_ {}; // zero-initialised; status = 0 == GA_STATUS_PENDING
        int interval_ {0};       // seconds between state-file writes
    };

} // namespace agentd

#endif // AGENTD_AGENT_STATE_HPP
