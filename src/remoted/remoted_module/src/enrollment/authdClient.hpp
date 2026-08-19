/*
 * Wazuh remoted module - authd enrollment bridge client
 * Copyright (C) 2015, Wazuh Inc.
 * August 19, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>

namespace remoted::enrollment
{

    /// Fields forwarded to authd's local socket "add" function. Deliberately does not include
    /// id/key/force: self-enrollment always gets an auto-assigned ID and an authd-generated key,
    /// and force-replace stays a manager-config decision -- see the Agent enrollment chapter of
    /// remoted_module/README.md.
    struct AuthdAddRequest
    {
        std::string name;
        std::string ip;
        std::optional<std::string> groups;
        std::optional<std::string> keyHash;
    };

    /**
     * @brief Outcome of an AuthdClient::addAgent() call.
     *
     * errorCode:
     *   - 0: success -- id/name/ip/key are populated, message is empty.
     *   - a positive authd error code (e.g. 9008 "Duplicate name"): authd responded with a
     *     well-formed business rejection -- message carries its (prefix-stripped) text.
     *   - -1: no well-formed answer was obtained at all -- connect/send/receive failure, a
     *     response timeout, or a malformed/unparseable reply. The endpoint layer maps this to
     *     the same HTTP status as authd's own 9016 (clustered-forward failure): both mean
     *     "the bridge did not get a clean answer", not a specific business outcome.
     */
    struct AuthdResult
    {
        int errorCode {-1};
        std::string message;
        std::string id;
        std::string name;
        std::string ip;
        std::string key;
    };

    /**
     * @brief Bridges an enrollment "add" request to authd's local Unix-domain socket
     *        (queue/sockets/auth by default), the same interface `manage_agents`/the framework
     *        already use. authd owns all enrollment business logic; this class only forwards.
     *
     * Connect-per-request, unlike WazuhDBClient/TaskClient's persistent connection: authd closes
     * its end of the socket after every single reply (see run_local_server's accept loop in
     * os_auth/src/local-server.c), so treating a post-reply disconnect as an error would
     * misreport every successful call. A single dedicated worker thread pulls from a bounded
     * queue, connecting fresh for each request in turn -- authd's own accept loop is
     * single-threaded anyway, so a larger client-side pool would only queue up behind it.
     *
     * The response timeout is worker-aware when the caller passes 0 (see
     * resolveResponseTimeoutMs()): authd's own worker-to-master cluster forward
     * (w_request_agent_add_clustered) can legitimately retry up to CLUSTER_SEND_MESSAGE_ATTEMPTS
     * (10) times with a 1 s sleep between failures on a flaky link, so a timeout shorter than
     * that would cut off a legitimate, still-in-progress worker enrollment as a spurious failure.
     *
     * NOTE: an absent authd (nothing listening on socketPath at all) is NOT distinguishable from
     * a slow/unresponsive one -- shared_modules/utils's SocketClient retries a failed connect()
     * silently on its own background thread rather than surfacing it, so there is no synchronous
     * "could not connect" signal to catch here. Both cases resolve only once the response timeout
     * above elapses, with the same errorCode (-1) and a "timed out" message. This is a limitation
     * of the shared primitive, not specific to AuthdClient -- WazuhDBClient/TaskClient have the
     * same exposure and have simply never been tested against a truly absent server.
     */
    class AuthdClient
    {
    public:
        static constexpr const char* kDefaultSocketPath = "queue/sockets/auth";
        static constexpr std::uint32_t kDefaultConnectTimeoutMs = 2000;
        static constexpr std::uint32_t kMasterDefaultResponseTimeoutMs = 5000;
        static constexpr std::uint32_t kWorkerDefaultResponseTimeoutMs = 15000;
        static constexpr std::uint32_t kDefaultMaxQueueSize = 256;

        /**
         * @param socketPath Path to authd's local socket.
         * @param isWorkerNode Selects the worker-aware default when responseTimeoutMs is 0.
         * @param connectTimeoutMs 0 -> kDefaultConnectTimeoutMs. NOTE: currently accepted but not
         *        enforced -- shared_modules/utils's SocketClient::connect() has no timeout hook,
         *        the same limitation WazuhDBClient/TaskClient already live with for the identical
         *        primitive. Kept in the signature so the ABI field it's sourced from
         *        (authd_connect_timeout) has somewhere to go if that primitive gains one later.
         * @param responseTimeoutMs 0 -> worker-aware default (see class comment and
         *        resolveResponseTimeoutMs()).
         * @param maxQueueSize 0 -> kDefaultMaxQueueSize; requests beyond this are rejected
         *        immediately with errorCode -1 rather than queued.
         */
        explicit AuthdClient(std::string socketPath = kDefaultSocketPath,
                             bool isWorkerNode = false,
                             std::uint32_t connectTimeoutMs = 0,
                             std::uint32_t responseTimeoutMs = 0,
                             std::uint32_t maxQueueSize = 0);
        ~AuthdClient();

        AuthdClient(const AuthdClient&) = delete;
        AuthdClient& operator=(const AuthdClient&) = delete;

        /// Enqueues an "add" request; callback runs on the internal worker thread, exactly once,
        /// even if the client is stopping or the queue is full (errorCode -1 in both cases).
        void addAgent(AuthdAddRequest request, std::function<void(AuthdResult)> callback);

        /// Resolves the effective response timeout for a configured value (0 = worker-aware
        /// default). A pure function of its arguments; exposed for unit testing.
        static std::uint32_t resolveResponseTimeoutMs(std::uint32_t configuredMs, bool isWorkerNode) noexcept;

        /// Stops the worker thread and fails any still-queued requests with errorCode -1. Safe to
        /// call more than once, and safe to skip -- the destructor calls it too.
        void stop();

    private:
        class Impl;
        std::unique_ptr<Impl> m_impl;
    };

} // namespace remoted::enrollment
