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

#ifndef _INDEXER_CLIENT_TRANSPORT_HPP
#define _INDEXER_CLIENT_TRANSPORT_HPP

// Internal HTTP transport. The probe,
// the bulk path and the queries build on it; nothing here is public API. Neither asio nor curl types
// appear in this header.

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "indexer_client/runtimeConfig.hpp"
#include "indexer_client/types.hpp"
#include "transport/tlsMaterial.hpp"

namespace asio
{
    class io_context;
} // namespace asio

namespace indexer_client::detail
{
    enum class HttpMethod
    {
        Get,
        Head,
        Post,
        Put,
        Delete
    };

    struct HttpRequest final
    {
        HttpMethod method {HttpMethod::Get};
        std::string url;                         ///< Scheme `http` or `https`; anything else is not admitted.
        std::shared_ptr<const std::string> body; ///< Shared, never copied per attempt; null = no body.
        std::string contentType {"application/json"};
        Duration timeout {Duration {0}}; ///< 0 = RuntimeConfig.requestTimeout.
    };

    /// Exhaustive classification of a finished transfer.
    enum class TransportCause
    {
        None,             ///< An HTTP response arrived (any status).
        Timeout,          ///< curl 28 (connect or total).
        Connect,          ///< curl 6, 7.
        SendError,        ///< curl 55.
        RecvError,        ///< curl 56, 52.
        PartialResponse,  ///< curl 18.
        ResponseTooLarge, ///< curl 23 with the response cap tripped (only then).
        LocalError,       ///< curl 2, 27, a curl_multi_socket_action error, a 23 without the cap flag, anything else.
        Cancelled,        ///< cancel(id) won the race.
        Shutdown,         ///< Resolved by stop().
        Tls,              ///< curl 35, 60, 98: the node's handshake or certificate was not accepted.
        TlsConfig         ///< curl 58, 77 (and 53, 54, 66, 83): local TLS material curl refused.
    };

    const char* toString(TransportCause cause) noexcept;

    /// True only for failures the node is responsible for: Timeout, Connect, SendError, RecvError, PartialResponse,
    /// Tls.
    bool nodeAttributable(TransportCause cause) noexcept;

    /// Maps a curl result code (CURLcode as int) to its cause. `capTripped` = the transfer's response cap fired.
    TransportCause classifyCurlCode(int curlCode, bool capTripped) noexcept;

    struct TransferTimings final
    {
        // Microseconds (a millisecond loses a loopback handshake). Filled on cancelled and stopped transfers too.
        std::chrono::microseconds total {0};
        std::chrono::microseconds connect {0};    ///< CURLINFO_CONNECT_TIME_T.
        std::chrono::microseconds appConnect {0}; ///< CURLINFO_APPCONNECT_TIME_T (0 in clear text).
    };

    struct HttpResult final
    {
        long status {0}; ///< HTTP status; 0 when no response arrived.
        TransportCause cause {TransportCause::None};
        bool nodeAttributable {false};
        int curlCode {0};
        /// CURLOPT_PREREQFUNCTION ran: the connection was ready and the request was about to be written. Conservative
        /// (true against a server that accepts and stays silent); reset on every use of an easy handle.
        bool mayHaveSent {false};
        std::optional<Duration> retryAfter; ///< Parsed Retry-After, capped at RuntimeConfig.retryAfterMax.
        std::string body;                   ///< Never larger than RuntimeConfig.maxResponseBytes.
        TransferTimings timings;
        /// Request bytes curl had sent (CURLINFO_SIZE_UPLOAD_T) when the transfer ended, also for Cancelled and
        /// Shutdown; 0 when the request never reached a loop.
        std::uint64_t uploadedBytes {0};
    };

    /// Spare capacity every HttpResult::body carries past its size (the bulk classifier parses in place).
    constexpr std::size_t RESPONSE_PADDING = 64;

    /// Runs on a CPU-pool thread (`ic-cpu-*`), exactly once per admitted request, never on a network thread.
    using ResultCallback = std::function<void(HttpResult&&)>;

    /// `id` is monotonic per runtime and never reused; 0 when not admitted. Not admitted ⇒ no callback, ever.
    struct Admission final
    {
        bool admitted {false};
        /// When not admitted: InvalidArgument (method, scheme, null callback), Shutdown (stop began) or InvalidState
        /// (the request could not be registered, e.g. out of memory).
        Cause cause {Cause::None};
        std::uint64_t id {0};
    };

    /// What the runtime lends the transport: one io_context per network thread (owned and run by the runtime) and a
    /// way to run a task on the CPU pool (false once the pool stopped accepting).
    struct TransportEnvironment final
    {
        std::vector<asio::io_context*> loops;
        std::function<bool(std::function<void()>)> postToPool;
    };

    struct TransportStats final
    {
        std::uint64_t admitted {0};
        std::uint64_t rejected {0};
        std::uint64_t completed {0}; ///< Resolved by curl or by a start failure, any cause (not only successes).
        std::uint64_t cancelled {0};
        std::uint64_t shutdown {0};
        /// Results the CPU pool refused, so their callback never ran. Never expected inside the runtime (the pool is
        /// stopped after the transport); non-zero breaks "one callback per admitted request" and must be investigated.
        std::uint64_t undelivered {0};
        std::vector<std::uint64_t> completedPerLoop;
        std::vector<std::uint64_t> inFlightPerLoop; ///< Easy handles currently inside each loop's multi.
        std::uint64_t postsRejected {0};            ///< posts refused because their loop had closed.
        /// Descriptors curl registered without opening them through the transport (the multi's wake-up pair, the
        /// resolver's): watched now, and released (deregistered, never closed) so far.
        std::uint64_t foreignWatched {0};
        std::uint64_t foreignReleased {0};
    };

    /// The transport. Created by RuntimeOwner::start after the runtime threads exist; owned by the RuntimeState and
    /// reached by internal users through runtimeTransport() (a weak view: it never keeps the runtime alive).
    class Transport
    {
    public:
        virtual ~Transport() = default;

        /// Synchronous admission. The id → transfer state is registered under the admission mutex before
        /// seams::afterAdmissionCheck(); stop() resolves every registered state, posted or not.
        virtual Admission submit(HttpRequest request, ResultCallback callback) = 0;

        /// Never blocks; any thread, runtime threads included. Unknown or already resolved id ⇒ false; also false when
        /// the owning loop has already closed (a stop is in progress and delivers Shutdown). Otherwise posts
        /// to the owning loop, where the first event touching the transfer (completion, cancellation, stop) wins; a
        /// cancellation removes the easy handle from the multi before resolving.
        virtual bool cancel(std::uint64_t id) = 0;

        /// Idempotent and safe to call concurrently (one cleanup, the other callers wait for it). Always completes:
        /// (1) closes admission, (2) removes every transfer from its multi and resolves it as Shutdown, (3) runs
        /// curl_multi_cleanup (CURLMOPT_QUICK_EXIT set) on each loop's own thread and waits for it. The runtime then
        /// joins the loops and drains the pool. Returns true when all of this finished within `deadline` (a measured
        /// objective, not a cut-off; the consumer-callback budget is the sender's). Called only by
        /// RuntimeOwner::shutdown and by the runtime state's destructor.
        virtual bool stop(TimePoint deadline) = 0;

        virtual TransportStats stats() const = 0;

        /// Builds the curl-based transport over the given environment.
        /// `tls` and `credentials` are kept for the transport's lifetime (curl reads the blobs until the last cleanup).
        static std::shared_ptr<Transport>
        create(const RuntimeConfig& config, TlsMaterial tls, Credentials credentials, TransportEnvironment environment);
    };

    /// The running runtime's transport, or null. For internal users and the component tests.
    std::shared_ptr<Transport> runtimeTransport();
} // namespace indexer_client::detail

#endif // _INDEXER_CLIENT_TRANSPORT_HPP
