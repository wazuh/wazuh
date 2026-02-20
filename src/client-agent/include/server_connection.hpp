/**
 * @file server_connection.hpp
 * @brief C++17 replacement for start_agent.c
 *
 * Manages the agent-to-manager handshake, server connection cycling,
 * key initialization, enrollment, and startup messaging.
 *
 * Copyright (C) 2015, Wazuh Inc.
 */

#ifndef AGENTD_SERVER_CONNECTION_HPP
#define AGENTD_SERVER_CONNECTION_HPP

#include "agentd_compat.hpp"

extern "C"
{
#include "agentd.h"
}

#include <cstdint>

namespace agentd
{

    /**
     * @brief Manages the agent ↔ manager connection lifecycle.
     *
     * Replaces the C functions: connect_server(), start_agent(),
     * send_agent_stopped_message(), try_enroll_to_server(), and all
     * internal helpers (handshake, JSON parsing, key init, etc.).
     */
    class ServerConnection
    {
    public:
        ServerConnection() = default;
        ~ServerConnection() = default;

        ServerConnection(const ServerConnection&) = delete;
        ServerConnection& operator=(const ServerConnection&) = delete;

        /** Connect to a specific server by index. */
        bool connectServer(int server_id, bool verbose);

        /** Synchronize with the manager (handshake loop over all servers). */
        void startAgent(int is_startup);

        /** Send the "agent stopped" control message. */
        void sendAgentStoppedMessage();

        /** Attempt enrollment with a specific server. */
        int tryEnrollToServer(const char* server_rip, uint32_t network_interface);

        /** Access the singleton. */
        static ServerConnection& instance();

    private:
        // ── Constants ────────────────────────────────────────────────
        static constexpr int kEnrollmentRetryTimeMax = 60;
        static constexpr int kEnrollmentRetryTimeDelta = 5;

        // ── Internal helpers ─────────────────────────────────────────
        void keysInit();
        ssize_t receiveMessage(char* buffer, unsigned int max_length);
        bool handshakeToServer(int server_id, bool is_startup);
        void sendMsgOnStartup();

        // ── JSON parsing helpers ─────────────────────────────────────
        static bool getRequiredInt(const cJSON* parent, const char* name, int* value);
        static bool parseFimLimits(const cJSON* root, fim_limits_t* fim);
        static bool parseSyscollectorLimits(const cJSON* root, syscollector_limits_t* syscollector);
        static bool parseScaLimits(const cJSON* root, sca_limits_t* sca);
        static bool parseLimits(const cJSON* root, module_limits_t* limits);
        static bool parseClusterName(const cJSON* root, char* cluster_name, size_t cluster_name_size);
        static bool parseClusterNode(const cJSON* root, char* cluster_node, size_t cluster_node_size);
        static bool parseAgentGroups(const cJSON* root, char* agent_groups, size_t agent_groups_size);
        static int parseHandshakeJson(const char* json_str,
                                      module_limits_t* limits,
                                      char* cluster_name,
                                      size_t cluster_name_size,
                                      char* cluster_node,
                                      size_t cluster_node_size,
                                      char* agent_groups,
                                      size_t agent_groups_size);
    };

} // namespace agentd

#endif // AGENTD_SERVER_CONNECTION_HPP
