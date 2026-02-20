/**
 * @file notify_manager.hpp
 * @brief C++17 replacement for notify.c
 *
 * Handles periodic keepalive notifications to the manager,
 * including building the JSON keepalive message with agent
 * metadata, shared-file hashes, labels, and IP information.
 *
 * Copyright (C) 2015, Wazuh Inc.
 */

#ifndef AGENTD_NOTIFY_MANAGER_HPP
#define AGENTD_NOTIFY_MANAGER_HPP

#include "agentd_compat.hpp"

extern "C"
{
#include "agentd.h"
}

namespace agentd
{

    /**
     * @brief Manages periodic keepalive notifications to the manager.
     *
     * Replaces the C functions: run_notify(), getsharedfiles(),
     * get_agent_ip(), clear_merged_hash_cache(), format_labels().
     */
    class NotifyManager
    {
    public:
        NotifyManager() = default;
        ~NotifyManager() = default;

        NotifyManager(const NotifyManager&) = delete;
        NotifyManager& operator=(const NotifyManager&) = delete;

        /** Periodically send notification to server (called from main loop). */
        void runNotify();

        /** Return MD5 hash of the shared merged.mg file. Caller owns result. */
        char* getSharedFiles();

        /** Return the agent's own IP address. Caller owns result. */
        char* getAgentIp();

        /** Clear the cached merged.mg hash. */
        void clearMergedHashCache();

        /** Access the singleton. */
        static NotifyManager& instance();

    private:
        /** Build JSON keepalive message. Caller owns returned string. */
        char*
        buildJsonKeepalive(const char* agent_ip, const char* config_sum, const char* merged_sum, const char* labels);

        // ── Cached state ─────────────────────────────────────────
        char* shared_mg_file_hash_ {nullptr};
        time_t saved_time_ {0};
    };

} // namespace agentd

#endif // AGENTD_NOTIFY_MANAGER_HPP
