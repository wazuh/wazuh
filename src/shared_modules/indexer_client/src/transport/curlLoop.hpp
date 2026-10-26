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

#ifndef _INDEXER_CLIENT_CURL_LOOP_HPP
#define _INDEXER_CLIENT_CURL_LOOP_HPP

// One network loop: a curl multi driven by multi_socket_action on the io_context the runtime runs on one network
// thread (sockets, timer with generation, easy-handle free-list). Owned by the Transport; everything in it runs on its
// io_context except the post*() / close() entry points, which may be called from any thread. Internal header: it is
// included only by transport.cpp and curlLoop.cpp.

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <curl/curl.h>

#include "transport/transport.hpp"

namespace indexer_client::detail
{
    /// One admitted request. Created and registered by Transport::submit; `claimed` decides the single resolution
    /// (completion, cancellation, start failure, multi error or stop: whoever sets it first delivers the result).
    struct TransferState final
    {
        std::uint64_t id {0};
        std::uint32_t loop {0};
        HttpRequest request;
        ResultCallback callback; ///< Moved out only by the claimer.
        std::uint64_t maxResponseBytes {0};
        Duration timeout {Duration {0}};
        std::atomic<bool> claimed {false};

        // Owning loop's thread only.
        CURL* easy {nullptr};
        curl_slist* headers {nullptr};
        std::string response;
        std::optional<std::string> retryAfter; ///< Raw header of the last response; handed to resolve().
        bool capTripped {false};
        bool mayHaveSent {false}; ///< CURLOPT_PREREQFUNCTION ran for this use of the easy (I36).
    };

    /// What the transport and its loops share. Captured by shared_ptr, never through a Transport pointer.
    struct TransportShared final
    {
        TransportShared(const RuntimeConfig& runtimeConfig,
                        std::function<bool(std::function<void()>)> pool,
                        std::size_t loopCount);
        /// Wipes the private key and the password (OPENSSL_cleanse, best effort: curl keeps its own copies).
        ~TransportShared();

        TransportShared(const TransportShared&) = delete;
        TransportShared& operator=(const TransportShared&) = delete;

        Duration retryAfterMax;
        /// Configured nodes (at least 1): sizes each multi's idle-connection pool (CURLMOPT_MAXCONNECTS).
        std::size_t hostCount;
        std::function<bool(std::function<void()>)> postToPool;
        TlsMaterial tls;         ///< I48; set once before any loop runs, read-only afterwards.
        Credentials credentials; ///< I55; set once before any loop runs, read-only afterwards.

        std::mutex mutex; ///< Admission: guards `accepting`, `nextId`, `cursor` and `registry`.
        bool accepting {true};
        std::uint64_t nextId {0};
        std::uint64_t cursor {0}; ///< Round-robin tie-break of the loop choice.
        std::unordered_map<std::uint64_t, std::shared_ptr<TransferState>> registry;

        /// Admitted and not yet resolved, per loop (the balance criterion, I22c).
        std::unique_ptr<std::atomic<std::uint64_t>[]> assigned;
        std::unique_ptr<std::atomic<std::uint64_t>[]> completedPerLoop;
        std::atomic<std::uint64_t> admitted {0};
        std::atomic<std::uint64_t> rejected {0};
        std::atomic<std::uint64_t> completed {0};
        std::atomic<std::uint64_t> cancelled {0};
        std::atomic<std::uint64_t> shutdown {0};
        std::atomic<std::uint64_t> undelivered {0}; ///< The pool refused a result (never expected; diagnostic).

        /// Resolves `state` with `result` if nobody did before: unregisters it and posts the callback to the CPU pool
        /// (where Retry-After, if any, is parsed after seams::beforeRetryAfterParse()). Any thread. False if the
        /// state was already resolved.
        bool resolve(const std::shared_ptr<TransferState>& state,
                     HttpResult&& result,
                     std::optional<std::string> retryAfter = std::nullopt) noexcept;
    };

    /// Handle of one loop. Its state (Impl) is reference-counted: every handler queued on the io_context holds a
    /// shared_ptr to it, never a raw pointer to the handle.
    class CurlLoop final
    {
    public:
        /// Builds the multi (throws std::runtime_error if curl cannot). Runs nothing yet.
        CurlLoop(asio::io_context& context, std::uint32_t index, std::shared_ptr<TransportShared> shared);
        ~CurlLoop();

        CurlLoop(const CurlLoop&) = delete;
        CurlLoop& operator=(const CurlLoop&) = delete;

        /// Any thread. False (and seams::onPostRejected()) once the loop is closed.
        bool postStart(std::shared_ptr<TransferState> state);
        bool postCancel(std::shared_ptr<TransferState> state);

        /// Any thread, once: refuses further posts and queues the loop's shutdown (remove and resolve every transfer
        /// as Shutdown, curl_multi_cleanup, release the remaining descriptors). The future is ready when it ran.
        std::shared_future<void> close();

        std::uint64_t inFlight() const;
        std::uint64_t postsRejected() const;
        std::uint64_t foreignWatched() const;
        std::uint64_t foreignReleased() const;

    private:
        struct Impl;
        std::shared_ptr<Impl> m_impl;
    };
} // namespace indexer_client::detail

#endif // _INDEXER_CLIENT_CURL_LOOP_HPP
