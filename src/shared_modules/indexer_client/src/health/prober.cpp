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

#include "health/prober.hpp"

#include <future>
#include <mutex>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <asio/io_context.hpp>
#include <asio/post.hpp>
#include <asio/steady_timer.hpp>

#include "runtime/runtimeInternal.hpp"

// The health probe. The timer lives on network loop 0: it is created, armed, cancelled and destroyed
// only by handlers running there. Handlers and probe callbacks capture the shared state by shared_ptr, never `this`.
// A round is K probes (one per node); the last result applies the whole round to the NodeSet.

namespace indexer_client::detail
{
    namespace
    {
        struct ProberShared final
        {
            ProberShared(std::shared_ptr<NodeSet> nodeSet,
                         std::shared_ptr<Transport> httpTransport,
                         asio::io_context& loop,
                         Duration roundInterval,
                         Duration probeTimeout)
                : nodes(std::move(nodeSet))
                , transport(std::move(httpTransport))
                , loop0(loop)
                , interval(roundInterval)
                , timeout(probeTimeout)
            {
                urls.reserve(nodes->size());
                for (std::size_t i = 0; i < nodes->size(); ++i)
                {
                    auto host = nodes->host(i);
                    while (!host.empty() && host.back() == '/')
                    {
                        host.pop_back();
                    }
                    // No `local=true`: the answer comes from the elected cluster manager, so a node cut off from the
                    // cluster fails its probe instead of answering from its own stale copy of the cluster state. No
                    // `wait_for_*` either: that would turn the poll into a blocking wait of up to its own timeout.
                    urls.push_back(host + "/_cluster/health/" + MANAGER_INDEX_PATTERN);
                }
            }

            const std::shared_ptr<NodeSet> nodes;
            const std::shared_ptr<Transport> transport;
            asio::io_context& loop0;
            const Duration interval;
            const Duration timeout;
            std::vector<std::string> urls;

            /// Loop 0 only.
            std::unique_ptr<asio::steady_timer> timer;

            std::mutex mutex; ///< Guards everything below.
            bool stopped {false};
            bool inFlight {false};
            std::uint64_t round {0}; ///< Number of the round in flight (or of the last one).
            std::size_t missing {0}; ///< Results still expected for the round in flight.
            std::vector<HttpResult> results;
            ProberStats stats;
        };

        void armRound(const std::shared_ptr<ProberShared>& shared);

        /// Loop 0 only: (re)arms the timer to `interval`; a wait already pending is cancelled (operation_aborted).
        void armTimer(const std::shared_ptr<ProberShared>& shared)
        {
            if (!shared->timer)
            {
                return;
            }
            shared->timer->expires_after(shared->interval);
            shared->timer->async_wait(
                [shared](const std::error_code& error)
                {
                    if (!error)
                    {
                        armRound(shared);
                    }
                });
        }

        /// Stores node `index`'s result of round `round`; the last one applies the round outside the mutex.
        void
        deliver(const std::shared_ptr<ProberShared>& shared, std::uint64_t round, std::size_t index, HttpResult result)
        {
            std::vector<HttpResult> complete;
            {
                std::lock_guard<std::mutex> lock(shared->mutex);
                // A Shutdown result is the transport resolving a probe still in flight after stop(): expected. Any
                // other result after stop() is a real answer that raced the stop.
                if (shared->stopped && result.cause != TransportCause::Shutdown)
                {
                    ++shared->stats.resultsAfterStop;
                }
                if (!shared->inFlight || round != shared->round || index >= shared->results.size())
                {
                    return; // Never expected: the transport gives exactly one result per admitted id.
                }
                shared->results[index] = std::move(result);
                if (--shared->missing > 0)
                {
                    return;
                }
                complete = std::move(shared->results);
                shared->results.clear();
            }
            const bool applied = shared->nodes->applyRound(complete);
            std::lock_guard<std::mutex> lock(shared->mutex);
            ++(applied ? shared->stats.roundsApplied : shared->stats.roundsDiscarded);
            shared->inFlight = false;
        }

        /// Loop 0 only.
        void armRound(const std::shared_ptr<ProberShared>& shared)
        {
            std::uint64_t round = 0;
            {
                std::lock_guard<std::mutex> lock(shared->mutex);
                if (shared->stopped)
                {
                    return;
                }
                if (shared->urls.empty())
                {
                    return; // No node to probe (the configuration requires at least one host).
                }
                if (shared->inFlight)
                {
                    ++shared->stats.roundsSkipped;
                }
                else
                {
                    ++shared->stats.rounds;
                    shared->inFlight = true;
                    round = ++shared->round;
                    shared->missing = shared->urls.size();
                    shared->results.assign(shared->urls.size(), HttpResult {});
                }
            }
            if (round != 0)
            {
                for (std::size_t i = 0; i < shared->urls.size(); ++i)
                {
                    HttpRequest request;
                    request.method = HttpMethod::Get;
                    request.url = shared->urls[i];
                    request.timeout = shared->timeout;
                    const auto admission = shared->transport->submit(std::move(request),
                                                                     [shared, round, i](HttpResult&& result)
                                                                     { deliver(shared, round, i, std::move(result)); });
                    if (!admission.admitted)
                    {
                        {
                            std::lock_guard<std::mutex> lock(shared->mutex);
                            ++shared->stats.submitsRefused;
                        }
                        HttpResult synthetic;
                        if (admission.cause == Cause::Shutdown)
                        {
                            synthetic.cause = TransportCause::Shutdown;
                        }
                        else
                        {
                            synthetic.cause = TransportCause::LocalError;
                            synthetic.body = std::string("probe not admitted: ") + toString(admission.cause);
                        }
                        deliver(shared, round, i, std::move(synthetic));
                    }
                }
            }
            // Under the mutex: stop() either finds the timer armed (and its posted cancellation, queued behind this
            // handler on loop 0, cancels it) or this check sees `stopped` and leaves it idle.
            std::lock_guard<std::mutex> lock(shared->mutex);
            if (!shared->stopped)
            {
                armTimer(shared);
            }
        }

        class TimerProber final : public Prober
        {
        public:
            explicit TimerProber(std::shared_ptr<ProberShared> shared)
                : m_shared(std::move(shared))
            {
            }

            ~TimerProber() override
            {
                std::lock_guard<std::mutex> lock(m_shared->mutex);
                if (!m_shared->stopped)
                {
                    countUsageError();
                }
            }

            TimerProber(const TimerProber&) = delete;
            TimerProber& operator=(const TimerProber&) = delete;

            void start() override
            {
                asio::post(m_shared->loop0,
                           [shared = m_shared]()
                           {
                               {
                                   std::lock_guard<std::mutex> lock(shared->mutex);
                                   if (shared->stopped)
                                   {
                                       return;
                                   }
                               }
                               if (!shared->timer)
                               {
                                   shared->timer = std::make_unique<asio::steady_timer>(shared->loop0);
                               }
                               armRound(shared);
                           });
            }

            void stop() override
            {
                std::lock_guard<std::mutex> stopLock(m_stopMutex); // Concurrent callers wait for the first one.
                {
                    std::lock_guard<std::mutex> lock(m_shared->mutex);
                    if (m_shared->stopped)
                    {
                        return;
                    }
                    m_shared->stopped = true;
                }
                const auto dropTimer = [](ProberShared& shared)
                {
                    if (shared.timer)
                    {
                        shared.timer->cancel();
                        shared.timer.reset();
                    }
                };
                if (m_shared->loop0.get_executor().running_in_this_thread())
                {
                    dropTimer(*m_shared);
                    return;
                }
                auto done = std::make_shared<std::promise<void>>();
                auto future = done->get_future();
                asio::post(m_shared->loop0,
                           [shared = m_shared, done, dropTimer]()
                           {
                               dropTimer(*shared);
                               done->set_value();
                           });
                future.wait();
            }

            bool probeNow() override
            {
                {
                    std::lock_guard<std::mutex> lock(m_shared->mutex);
                    if (m_shared->stopped || m_shared->inFlight)
                    {
                        return false;
                    }
                }
                asio::post(m_shared->loop0, [shared = m_shared]() { armRound(shared); });
                return true;
            }

            ProberStats stats() const override
            {
                std::lock_guard<std::mutex> lock(m_shared->mutex);
                return m_shared->stats;
            }

        private:
            std::shared_ptr<ProberShared> m_shared;
            std::mutex m_stopMutex;
        };
    } // namespace

    std::shared_ptr<Prober> Prober::create(std::shared_ptr<NodeSet> nodes,
                                           std::shared_ptr<Transport> transport,
                                           asio::io_context& loop0,
                                           Duration interval,
                                           Duration timeout)
    {
        return std::make_shared<TimerProber>(
            std::make_shared<ProberShared>(std::move(nodes), std::move(transport), loop0, interval, timeout));
    }
} // namespace indexer_client::detail
