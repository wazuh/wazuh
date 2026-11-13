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

// The transport: admission, the spread of transfers over the K loops, cancel and stop. The loops themselves live in
// curlLoop.cpp.

#include "transport/transport.hpp"

#include <algorithm>
#include <chrono>
#include <ctime>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include <curl/curl.h>

#include "transport/curlLoop.hpp"
#include "transport/retryAfter.hpp"
#include "transport/seams.hpp"

namespace indexer_client::detail
{
    namespace
    {
        std::once_flag g_curlGlobalInit;
        CURLcode g_curlGlobalInitResult {CURLE_OK};

        bool admittedMethod(HttpMethod method)
        {
            switch (method)
            {
                case HttpMethod::Get:
                case HttpMethod::Head:
                case HttpMethod::Post:
                case HttpMethod::Put:
                case HttpMethod::Delete: return true;
            }
            return false; // Any other value (a cast, a future PATCH) is not admitted.
        }

        /// `url` starts with `prefix`, ASCII case-insensitively (RFC 3986 schemes), with something after it (the same
        /// comparison as tlsMaterial.cpp's hasScheme).
        bool startsWithScheme(std::string_view url, std::string_view prefix)
        {
            if (url.size() <= prefix.size())
            {
                return false;
            }
            for (std::size_t i = 0; i < prefix.size(); ++i)
            {
                const char c = url[i];
                if ((c >= 'A' && c <= 'Z' ? static_cast<char>(c + 32) : c) != prefix[i])
                {
                    return false;
                }
            }
            return true;
        }

        /// Schemes `http` and `https`; CURLOPT_PROTOCOLS_STR enforces the same set inside curl. https is
        /// admitted with or without a configured CA: the trust anchor is the policy loadTlsMaterial resolved
        /// (configured CA, system store or none), never curl's compiled-in bundle (curlLoop.cpp).
        bool admittedUrl(std::string_view url)
        {
            return startsWithScheme(url, "http://") || startsWithScheme(url, "https://");
        }

        class CurlTransport final : public Transport
        {
        public:
            CurlTransport(const RuntimeConfig& config,
                          TlsMaterial tls,
                          Credentials credentials,
                          TransportEnvironment environment)
                : m_shared(std::make_shared<TransportShared>(
                      config, std::move(environment.postToPool), environment.loops.size()))
                , m_requestTimeout(config.requestTimeout)
                , m_maxResponseBytes(config.maxResponseBytes)
            {
                // Kept for the transport's lifetime: curl reads the blobs (CURL_BLOB_NOCOPY) until the last cleanup.
                // Moved in before anything can throw, so that a failed construction wipes them (~TransportShared).
                m_shared->tls = std::move(tls);
                m_shared->credentials = std::move(credentials);
                if (environment.loops.empty() || !m_shared->postToPool)
                {
                    throw std::invalid_argument("the transport needs at least one loop and a CPU pool");
                }
                m_loops.reserve(environment.loops.size());
                for (std::size_t i = 0; i < environment.loops.size(); ++i)
                {
                    m_loops.push_back(
                        std::make_unique<CurlLoop>(*environment.loops[i], static_cast<std::uint32_t>(i), m_shared));
                }
            }

            Admission submit(HttpRequest request, ResultCallback callback) override
            {
                if (!admittedMethod(request.method) || !admittedUrl(request.url) || !callback)
                {
                    m_shared->rejected.fetch_add(1);
                    return Admission {false, Cause::InvalidArgument, 0};
                }

                auto state = std::make_shared<TransferState>();
                state->timeout = request.timeout > Duration {0} ? request.timeout : m_requestTimeout;
                state->maxResponseBytes = m_maxResponseBytes;
                state->request = std::move(request);
                state->callback = std::move(callback);

                std::uint64_t id = 0;
                {
                    std::lock_guard<std::mutex> lock(m_shared->mutex);
                    if (!m_shared->accepting)
                    {
                        m_shared->rejected.fetch_add(1);
                        return Admission {false, Cause::Shutdown, 0};
                    }
                    state->loop = pickLoop();
                    state->id = m_shared->nextId + 1;
                    try
                    {
                        m_shared->registry.emplace(state->id, state);
                    }
                    catch (...)
                    {
                        m_shared->rejected.fetch_add(1);
                        return Admission {false, Cause::InvalidState, 0};
                    }
                    id = ++m_shared->nextId;
                    m_shared->assigned[state->loop].fetch_add(1);
                    m_shared->admitted.fetch_add(1);
                }
                // Registered: from here on stop() resolves it even if the post below never reaches the loop.
                seams::afterAdmissionCheck();
                m_loops[state->loop]->postStart(state); // Refused only by a closed loop, whose stop resolves it.
                return Admission {true, Cause::None, id};
            }

            bool cancel(std::uint64_t id) override
            {
                std::shared_ptr<TransferState> state;
                {
                    std::lock_guard<std::mutex> lock(m_shared->mutex);
                    const auto it = m_shared->registry.find(id);
                    if (it == m_shared->registry.end())
                    {
                        return false; // Unknown or already resolved.
                    }
                    state = it->second;
                }
                if (state->claimed.load())
                {
                    return false;
                }
                return m_loops[state->loop]->postCancel(std::move(state));
            }

            bool stop(TimePoint deadline) override
            {
                std::lock_guard<std::mutex> stopLock(m_stopMutex); // One stop runs; concurrent callers wait for it.
                if (!m_stopped)
                {
                    // (1) Close admission.
                    {
                        std::lock_guard<std::mutex> lock(m_shared->mutex);
                        m_shared->accepting = false;
                    }
                    // (2)+(3) Each loop takes its transfers out of the multi, resolves them as Shutdown and cleans its
                    // multi up on its own thread; wait for every loop. Always completes: the deadline is measured.
                    std::vector<std::shared_future<void>> closed;
                    closed.reserve(m_loops.size());
                    for (auto& loop : m_loops)
                    {
                        closed.push_back(loop->close());
                    }
                    for (auto& done : closed)
                    {
                        done.wait();
                    }
                    // What is still registered never reached a loop (its post was refused or is yet to come).
                    std::vector<std::shared_ptr<TransferState>> remaining;
                    {
                        std::lock_guard<std::mutex> lock(m_shared->mutex);
                        remaining.reserve(m_shared->registry.size());
                        for (auto& [id, state] : m_shared->registry)
                        {
                            remaining.push_back(state);
                        }
                    }
                    for (auto& state : remaining)
                    {
                        HttpResult result;
                        result.cause = TransportCause::Shutdown;
                        m_shared->resolve(state, std::move(result));
                    }
                    m_finishedAt = std::chrono::steady_clock::now();
                    m_stopped = true;
                }
                return m_finishedAt <= deadline;
            }

            TransportStats stats() const override
            {
                TransportStats stats;
                stats.admitted = m_shared->admitted.load();
                stats.rejected = m_shared->rejected.load();
                stats.completed = m_shared->completed.load();
                stats.cancelled = m_shared->cancelled.load();
                stats.shutdown = m_shared->shutdown.load();
                stats.undelivered = m_shared->undelivered.load();
                for (std::size_t i = 0; i < m_loops.size(); ++i)
                {
                    stats.completedPerLoop.push_back(m_shared->completedPerLoop[i].load());
                    stats.inFlightPerLoop.push_back(m_loops[i]->inFlight());
                    stats.postsRejected += m_loops[i]->postsRejected();
                    stats.foreignWatched += m_loops[i]->foreignWatched();
                    stats.foreignReleased += m_loops[i]->foreignReleased();
                }
                return stats;
            }

        private:
            /// Under the admission mutex: the loop with the fewest admitted-and-unresolved transfers, ties broken
            /// round-robin.
            std::uint32_t pickLoop()
            {
                const auto count = m_loops.size();
                const auto first = static_cast<std::size_t>(m_shared->cursor++ % count);
                std::size_t best = first;
                auto bestLoad = m_shared->assigned[best].load();
                for (std::size_t step = 1; step < count; ++step)
                {
                    const auto candidate = (first + step) % count;
                    const auto load = m_shared->assigned[candidate].load();
                    if (load < bestLoad)
                    {
                        best = candidate;
                        bestLoad = load;
                    }
                }
                return static_cast<std::uint32_t>(best);
            }

            std::shared_ptr<TransportShared> m_shared;
            Duration m_requestTimeout;
            std::uint64_t m_maxResponseBytes;
            std::vector<std::unique_ptr<CurlLoop>> m_loops;

            std::mutex m_stopMutex;
            bool m_stopped {false};
            TimePoint m_finishedAt {};
        };
    } // namespace

    TransportShared::TransportShared(const RuntimeConfig& runtimeConfig,
                                     std::function<bool(std::function<void()>)> pool,
                                     std::size_t loopCount)
        : retryAfterMax(runtimeConfig.retryAfterMax)
        , hostCount(std::max<std::size_t>(1, runtimeConfig.hosts.size()))
        , postToPool(std::move(pool))
        , assigned(std::make_unique<std::atomic<std::uint64_t>[]>(loopCount))
        , completedPerLoop(std::make_unique<std::atomic<std::uint64_t>[]>(loopCount))
    {
    }

    TransportShared::~TransportShared()
    {
        // Best effort: curl and OpenSSL keep their own copies of the key and of the password.
        cleanseString(tls.privateKey);
        cleanseString(credentials.password);
    }

    bool TransportShared::resolve(const std::shared_ptr<TransferState>& state,
                                  HttpResult&& result,
                                  std::optional<std::string> retryAfter) noexcept
    {
        if (state->claimed.exchange(true))
        {
            return false; // Somebody else resolved it first.
        }
        try
        {
            std::lock_guard<std::mutex> lock(mutex);
            registry.erase(state->id);
        }
        catch (...)
        {
        }
        assigned[state->loop].fetch_sub(1);
        switch (result.cause)
        {
            case TransportCause::Cancelled: cancelled.fetch_add(1); break;
            case TransportCause::Shutdown: shutdown.fetch_add(1); break;
            default:
                completed.fetch_add(1);
                completedPerLoop[state->loop].fetch_add(1);
                break;
        }
        try
        {
            // Never run here: the callback, and the Retry-After parse, belong to the CPU pool.
            auto task = [callback = std::move(state->callback),
                         outcome = std::move(result),
                         header = std::move(retryAfter),
                         cap = retryAfterMax]() mutable
            {
                if (header)
                {
                    try
                    {
                        seams::beforeRetryAfterParse();
                        outcome.retryAfter = parseRetryAfter(*header, std::time(nullptr), cap);
                    }
                    catch (...)
                    {
                    }
                }
                try
                {
                    callback(std::move(outcome));
                }
                catch (...)
                {
                    // A callback must never take a pool thread down; the write path accounts for it.
                }
            };
            if (!postToPool(std::move(task)))
            {
                undelivered.fetch_add(1);
            }
        }
        catch (...)
        {
            undelivered.fetch_add(1);
        }
        return true;
    }

    std::shared_ptr<Transport> Transport::create(const RuntimeConfig& config,
                                                 TlsMaterial tls,
                                                 Credentials credentials,
                                                 TransportEnvironment environment)
    {
        std::call_once(g_curlGlobalInit, [] { g_curlGlobalInitResult = curl_global_init(CURL_GLOBAL_DEFAULT); });
        if (g_curlGlobalInitResult != CURLE_OK)
        {
            cleanseString(credentials.password); // The key is wiped by ~TlsMaterial.
            throw std::runtime_error(std::string("curl_global_init failed: ") +
                                     curl_easy_strerror(g_curlGlobalInitResult));
        }
        return std::make_shared<CurlTransport>(config, std::move(tls), std::move(credentials), std::move(environment));
    }
} // namespace indexer_client::detail
