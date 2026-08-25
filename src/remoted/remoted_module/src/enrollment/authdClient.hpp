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

#include <cstddef>
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
     *        (queue/sockets/auth.sock by default), the same interface `manage_agents`/the framework
     *        already use. authd owns all enrollment business logic; this class only forwards.
     *
     * Connect-per-request, unlike WazuhDBClient/TaskClient's persistent connection: authd closes
     * its end of the socket after every single reply (see run_local_server's accept loop in
     * os_auth/src/local-server.c), so treating a post-reply disconnect as an error would
     * misreport every successful call.
     *
     * A small pool of dedicated worker threads (see workerThreads) pulls from one shared, bounded
     * queue, each connecting fresh for each request it picks up. authd's local-socket accept loop
     * (run_local_server, os_auth/src/local-server.c) hands each accepted connection to its own
     * detached thread rather than dispatching inline, so authd itself can now process several
     * requests concurrently too -- a single-worker AuthdClient would still only ever have ONE
     * request in flight, no matter how parallel authd can go, and would still pay a round trip of
     * pure connection-setup latency (connect + send + await reply + close) sitting on the critical
     * path *in addition to* authd's processing time, for every single request, serialized. With
     * several workers, authd can genuinely work on more than one at once, and another worker's
     * connection (already sent, already awaiting a reply) is normally already sitting in authd's
     * listen backlog (128 slots -- see OS_BindUnixDomainWithPerms in shared/os_net/os_net.c) by
     * the time authd finishes one and calls accept() again, so authd is essentially never left
     * idle waiting on remoted for the next request.
     *
     * Because of this, addAgent()'s callback can now run on ANY of the pool's threads, including
     * concurrently with another addAgent() call's callback on a different thread -- callers must
     * be safe under that (the enrollment endpoint's own callback already is: IHttpResponder::send()
     * is thread-safe by contract, and the metrics counters it also touches are relaxed atomics).
     *
     * Each worker thread also guards its own callback invocation with a catch-all (see
     * authdClient.cpp's workerLoop()): this runs on a bare std::thread that RestinioHttpServer's
     * own per-request try/catch never sees (addAgent() already returned by the time this fires,
     * on a different thread), so an uncaught exception here -- from performRequest() itself or
     * from the callback -- would otherwise std::terminate the entire remoted daemon instead of
     * just failing the one request.
     *
     * The response timeout is worker-aware when the caller passes 0 (see
     * resolveResponseTimeoutMs()): authd's own worker-to-master cluster forward
     * (w_request_agent_add_clustered) can legitimately retry up to CLUSTER_SEND_MESSAGE_ATTEMPTS
     * (10) times with a 1 s sleep between failures on a flaky link, so a timeout shorter than
     * that would cut off a legitimate, still-in-progress worker enrollment as a spurious failure.
     *
     * Connect() is deterministic and bounded (see authdClient.cpp's performRequest()) -- not
     * shared_modules/utils's SocketClient, whose async connect() starts a background thread and
     * returns before the connection exists. An earlier version of this class used SocketClient and
     * called send() immediately after connect() with no synchronization between them, which lost
     * the race against that background thread far more often than not: authd would receive and
     * successfully process the request, but the reply arrived on a connection this class was no
     * longer the one listening on (SocketClient had silently reconnected after treating the
     * original attempt as merely "still pending"), producing a client-visible timeout for a request
     * that actually succeeded. This class's connect() has no such race: internally it does a
     * non-blocking connect() plus poll() bounded by connectTimeoutMs, then restores the fd to
     * blocking mode before send()/read() -- it returns only once truly connected, or throws on a
     * real failure (e.g. ENOENT if socketPath doesn't exist) or on the connect timeout expiring
     * (e.g. authd's accept() backlog staying saturated) -- so an absent, refused, or overloaded
     * authd IS distinguishable from a slow/unresponsive one: it fails fast with a "could not
     * connect" message rather than waiting out the full response timeout.
     */
    class AuthdClient
    {
    public:
        static constexpr const char* kDefaultSocketPath = "queue/sockets/auth.sock";
        static constexpr std::uint32_t kDefaultConnectTimeoutMs = 2000;
        static constexpr std::uint32_t kMasterDefaultResponseTimeoutMs = 5000;
        static constexpr std::uint32_t kWorkerDefaultResponseTimeoutMs = 15000;
        static constexpr std::uint32_t kDefaultMaxQueueSize = 256;
        /// Deliberately a small, fixed number, not CPU-scaled like this module's other worker
        /// pools (e.g. http_worker_threads): bounded by authd's listen backlog (128 slots), not by
        /// the manager's CPU count, so scaling this with core count would just leave surplus
        /// workers unable to help. See the class comment for what this pool actually buys.
        static constexpr std::uint32_t kDefaultWorkerThreads = 8;

        /**
         * @param socketPath Path to authd's local socket.
         * @param isWorkerNode Selects the worker-aware default when responseTimeoutMs is 0.
         * @param connectTimeoutMs 0 -> kDefaultConnectTimeoutMs. Enforced via a non-blocking
         *        connect() plus poll() on the fd (see performRequest()): bounds the one scenario a
         *        plain blocking connect() couldn't -- authd's accept() backlog being saturated --
         *        so a stuck connect attempt fails with a timeout error after this many
         *        milliseconds instead of blocking the worker thread indefinitely.
         * @param responseTimeoutMs 0 -> worker-aware default (see class comment and
         *        resolveResponseTimeoutMs()).
         * @param maxQueueSize 0 -> kDefaultMaxQueueSize; requests beyond this are rejected
         *        immediately with errorCode -1 rather than queued.
         * @param workerThreads 0 -> kDefaultWorkerThreads. Keep well under authd's local-socket
         *        listen backlog (128) -- see the class comment; there is no benefit to more
         *        workers than that backlog can hold anyway.
         */
        explicit AuthdClient(std::string socketPath = kDefaultSocketPath,
                             bool isWorkerNode = false,
                             std::uint32_t connectTimeoutMs = 0,
                             std::uint32_t responseTimeoutMs = 0,
                             std::uint32_t maxQueueSize = 0,
                             std::uint32_t workerThreads = 0);
        ~AuthdClient();

        AuthdClient(const AuthdClient&) = delete;
        AuthdClient& operator=(const AuthdClient&) = delete;

        /// Enqueues an "add" request; the callback runs exactly once, on whichever pool thread
        /// picks the request up (see the class comment: with more than one worker, this may run
        /// concurrently with another call's callback on a different thread) -- even if the client
        /// is stopping or the queue is full (errorCode -1 in both cases).
        void addAgent(AuthdAddRequest request, std::function<void(AuthdResult)> callback);

        /// Resolves the effective response timeout for a configured value (0 = worker-aware
        /// default). A pure function of its arguments; exposed for unit testing.
        static std::uint32_t resolveResponseTimeoutMs(std::uint32_t configuredMs, bool isWorkerNode) noexcept;

        /// Stops every worker thread and fails any still-queued requests with errorCode -1. Safe
        /// to call more than once, and safe to skip -- the destructor calls it too.
        void stop();

        /// @brief Queue state behind the remoted.enroll.authd.queue.* metrics.
        struct QueueDiagnostics
        {
            std::size_t depth {0};           ///< Requests waiting for a worker right now.
            std::size_t capacity {0};        ///< Effective cap ('remoted.authd_max_queue_size').
            std::uint64_t rejectedTotal {0}; ///< Requests refused because the queue was full.
        };

        /**
         * @brief Snapshot the queue, for the metrics dump.
         *
         * Callable from any thread at any point in the client's life. Takes the same lock
         * addAgent() does -- acceptable because it runs at dump cadence only, the same trade-off
         * IHttpServer::diagnostics() already makes; the enrollment path itself gains no lock.
         *
         * `rejectedTotal` is what separates a saturated queue from an unreachable authd: both end
         * up in remoted.enroll.authd_unavailable, so authd_unavailable minus this counter is the
         * share that was NOT the queue's fault.
         */
        QueueDiagnostics queueDiagnostics() const;

    private:
        class Impl;
        std::unique_ptr<Impl> m_impl;
    };

} // namespace remoted::enrollment
