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

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "health/nodeSet.hpp"
#include "json.hpp"
#include "query/pit.hpp"
#include "runtime/backoff.hpp"
#include "runtime/runtimeInternal.hpp"
#include "transport/transport.hpp"
#include "write/response.hpp"

// The PitRegistry of pit.hpp (LIFETIME AND DELETE, SHUTDOWN, STATS): slots, reservations, the DELETE queue with its
// retries on a loop-0 timer, and the shutdown drain. `m_mutex` is a leaf: nothing is called under it (no transport,
// no NodeSet, no timer, no PitState), and only drain() blocks.

namespace indexer_client::detail::query
{
    namespace
    {
        /// Process-wide counters of every registry (pit.hpp STATS: never reset).
        std::atomic<std::uint64_t> g_created {0};
        std::atomic<std::uint64_t> g_deletesConfirmed {0};
        std::atomic<std::uint64_t> g_deletesExpired {0};
        std::atomic<std::uint64_t> g_deleteRetries {0};
        std::atomic<std::uint64_t> g_refusedFull {0};

        constexpr const char* DELETE_ROUTE = "/_search/point_in_time";

        Duration deleteBackoff(std::uint32_t attempts)
        {
            RetryPolicy policy;
            policy.base = DELETE_RETRY_BASE;
            policy.cap = DELETE_RETRY_CAP;
            return backoffDelay(policy, std::max<std::uint32_t>(attempts, 1), jitterDraw());
        }

        std::string deleteUrl(std::string host)
        {
            while (!host.empty() && host.back() == '/')
            {
                host.pop_back();
            }
            return host + DELETE_ROUTE;
        }

        class Registry final
            : public PitRegistry
            , public std::enable_shared_from_this<Registry>
        {
        public:
            explicit Registry(PitRegistryEnvironment environment)
                : m_env(std::move(environment))
            {
            }

            bool acquire(std::uint64_t& occupied) override
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                purgeLocked(std::chrono::steady_clock::now());
                occupied = m_open + m_reservations.size() + m_acquired;
                if (occupied < m_env.maxOpenPits)
                {
                    ++m_acquired;
                    return true;
                }
                g_refusedFull.fetch_add(1);
                return false;
            }

            void releaseSlot() override
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                takeAcquiredLocked();
            }

            void reserve(TimePoint until) override
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                takeAcquiredLocked();
                m_reservations.push_back(until);
            }

            void opened(const std::weak_ptr<PitState>& pit) override
            {
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    takeAcquiredLocked();
                    ++m_open;
                    g_created.fetch_add(1);
                    if (!m_draining)
                    {
                        m_live.erase(
                            std::remove_if(m_live.begin(), m_live.end(), [](const auto& w) { return w.expired(); }),
                            m_live.end());
                        m_live.push_back(pit);
                        return;
                    }
                }
                // The drain already took m_live (pit.hpp SHUTDOWN): mark it drained like the drain does, and delete it
                // within the drain while there is time; else it counts expired.
                auto state = pit.lock();
                Pending pending;
                if (state && !state->drained.exchange(true))
                {
                    {
                        std::lock_guard<std::mutex> pitLock(state->mutex);
                        pending.id = state->id;
                        pending.lastUse = state->lastUse;
                    }
                    pending.keepAlive = state->keepAlive;
                }
                const auto id = pending.id;
                std::optional<Duration> timeout;
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    const auto now = std::chrono::steady_clock::now();
                    if (!m_drainDone && now < m_drainEnd && enqueueLocked(std::move(pending)))
                    {
                        m_pending.at(id).inFlight = true;
                        const auto left = std::chrono::duration_cast<Duration>(m_drainEnd - now);
                        timeout = std::max(Duration {1}, std::min(m_env.requestTimeout, left));
                    }
                    else
                    {
                        finishLocked(false);
                    }
                }
                if (timeout)
                {
                    send(id, *timeout);
                }
            }

            void release(Pending pit) override
            {
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    if (m_draining)
                    {
                        // The runtime is going: no new request; keep_alive frees it.
                        finishLocked(false);
                        return;
                    }
                    if (!enqueueLocked(std::move(pit)))
                    {
                        return; // Already queued (idempotent per id).
                    }
                }
                arm(Duration::zero());
            }

            void drain(TimePoint drainEnd) override
            {
                std::vector<std::weak_ptr<PitState>> live;
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    if (m_draining)
                    {
                        return;
                    }
                    m_draining = true;
                    m_drainEnd = drainEnd;
                    live.swap(m_live);
                }
                // PITs whose handles are still alive: read them, mark them drained (their hand-over gives nothing).
                // The strong references are dropped outside the mutex: the last one runs the hand-over.
                std::vector<Pending> alive;
                for (const auto& weak : live)
                {
                    auto state = weak.lock();
                    if (!state || state->drained.exchange(true))
                    {
                        continue;
                    }
                    Pending pending;
                    {
                        std::lock_guard<std::mutex> pitLock(state->mutex);
                        pending.id = state->id;
                        pending.lastUse = state->lastUse;
                    }
                    pending.keepAlive = state->keepAlive;
                    alive.push_back(std::move(pending));
                }
                live.clear();

                std::vector<std::string> toSend;
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    for (auto& pending : alive)
                    {
                        enqueueLocked(std::move(pending));
                    }
                    for (auto& [id, entry] : m_pending)
                    {
                        if (!entry.inFlight)
                        {
                            entry.inFlight = true;
                            toSend.push_back(id);
                        }
                    }
                }
                for (const auto& id : toSend)
                {
                    const auto now = std::chrono::steady_clock::now();
                    if (now >= drainEnd)
                    {
                        expire(id);
                        continue;
                    }
                    const auto left = std::chrono::duration_cast<Duration>(drainEnd - now);
                    send(id, std::max(Duration {1}, std::min(m_env.requestTimeout, left)));
                }

                std::vector<std::uint64_t> toCancel;
                {
                    std::unique_lock<std::mutex> lock(m_mutex);
                    m_cv.wait_until(lock, drainEnd, [this] { return m_pending.empty(); });
                    for (auto& [id, entry] : m_pending)
                    {
                        if (entry.transferId != 0)
                        {
                            toCancel.push_back(entry.transferId);
                        }
                        finishLocked(false);
                    }
                    m_pending.clear();
                    m_drainDone = true;
                }
                if (auto transport = m_env.transport.lock())
                {
                    for (const auto id : toCancel)
                    {
                        transport->cancel(id);
                    }
                }
            }

            PitStats stats() override
            {
                PitStats stats;
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    purgeLocked(std::chrono::steady_clock::now());
                    stats.open = m_open;
                    stats.reserved = m_reservations.size();
                    stats.deletesPending = m_pending.size();
                }
                addCounters(stats);
                return stats;
            }

            static void addCounters(PitStats& stats)
            {
                stats.created = g_created.load();
                stats.deletesConfirmed = g_deletesConfirmed.load();
                stats.deletesExpired = g_deletesExpired.load();
                stats.deleteRetries = g_deleteRetries.load();
                stats.refusedFull = g_refusedFull.load();
            }

        private:
            struct Entry final
            {
                Duration keepAlive {Duration {0}};
                TimePoint expiresAt;        ///< lastUse + keepAlive: no request from then on.
                TimePoint nextAt;           ///< When the next attempt is due (not inFlight).
                std::uint32_t failures {0}; ///< Counted failures so far (the backoff exponent).
                bool inFlight {false};      ///< Being sent, or its DELETE awaits its result.
                bool retryPending {false};  ///< The next send is a counted retry (deleteRetries + 1).
                std::uint64_t token {0};    ///< Identifies the current send; a result with another one is stale.
                std::uint64_t transferId {0};
            };

            enum class Settle
            {
                Confirmed,
                Expired,
                Retry, ///< Counted: Failover, Retry, Throttled, a refused admission.
                NoNode ///< Not counted.
            };

            void takeAcquiredLocked()
            {
                if (m_acquired > 0)
                {
                    --m_acquired;
                }
            }

            void purgeLocked(TimePoint now)
            {
                m_reservations.erase(std::remove_if(m_reservations.begin(),
                                                    m_reservations.end(),
                                                    [now](TimePoint until) { return until <= now; }),
                                     m_reservations.end());
            }

            /// Frees one open slot and counts the delete's end. The caller removes the entry and notifies m_cv after
            /// unlocking.
            void finishLocked(bool confirmed)
            {
                if (m_open > 0)
                {
                    --m_open;
                }
                (confirmed ? g_deletesConfirmed : g_deletesExpired).fetch_add(1);
            }

            bool enqueueLocked(Pending pit)
            {
                if (pit.id.empty() || m_pending.count(pit.id) != 0)
                {
                    return false;
                }
                Entry entry;
                entry.keepAlive = pit.keepAlive;
                entry.expiresAt = addSaturated(pit.lastUse, pit.keepAlive);
                entry.nextAt = std::chrono::steady_clock::now();
                m_pending.emplace(std::move(pit.id), entry);
                return true;
            }

            /// Arms a loop-0 wake-up in `delay` unless an earlier one is armed. Never under the mutex.
            void arm(Duration delay)
            {
                const auto at = std::chrono::steady_clock::now() + delay;
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    if (m_draining || (m_armedAt && *m_armedAt <= at))
                    {
                        return;
                    }
                    m_armedAt = at;
                }
                std::weak_ptr<Registry> weak = shared_from_this();
                const bool armed = m_env.after && m_env.after(delay,
                                                              [weak]()
                                                              {
                                                                  if (auto self = weak.lock())
                                                                  {
                                                                      self->tick();
                                                                  }
                                                              });
                if (!armed)
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    if (m_armedAt == at)
                    {
                        m_armedAt.reset();
                    }
                }
            }

            /// Loop 0: sends the due deletes, expires the lapsed ones, re-arms for the next one.
            void tick()
            {
                std::vector<std::pair<std::string, Duration>> due; ///< Id and timeout (never past expiresAt).
                std::vector<std::string> lapsed;
                std::optional<TimePoint> next;
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    if (m_draining)
                    {
                        return;
                    }
                    const auto now = std::chrono::steady_clock::now();
                    if (m_armedAt && *m_armedAt <= now)
                    {
                        m_armedAt.reset();
                    }
                    for (auto& [id, entry] : m_pending)
                    {
                        if (entry.inFlight)
                        {
                            continue;
                        }
                        if (now >= entry.expiresAt)
                        {
                            lapsed.push_back(id);
                        }
                        else if (entry.nextAt <= now)
                        {
                            entry.inFlight = true;
                            const auto left = std::chrono::duration_cast<Duration>(entry.expiresAt - now);
                            due.emplace_back(id, std::max(Duration {1}, std::min(m_env.requestTimeout, left)));
                        }
                        else if (!next || entry.nextAt < *next)
                        {
                            next = entry.nextAt;
                        }
                    }
                }
                for (const auto& id : lapsed)
                {
                    expire(id);
                }
                for (const auto& [id, timeout] : due)
                {
                    send(id, timeout);
                }
                if (next)
                {
                    arm(std::chrono::duration_cast<Duration>(
                        std::max(*next - std::chrono::steady_clock::now(), TimePoint::duration::zero())));
                }
            }

            void expire(const std::string& id)
            {
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    auto it = m_pending.find(id);
                    if (it == m_pending.end())
                    {
                        return;
                    }
                    m_pending.erase(it);
                    finishLocked(false);
                }
                m_cv.notify_all();
            }

            /// Sends the DELETE of `id` (marked inFlight by the caller) with `timeout` (> 0).
            void send(const std::string& id, Duration timeout)
            {
                auto transport = m_env.transport.lock();
                if (!transport)
                {
                    expire(id);
                    return;
                }
                auto nodes = m_env.nodes.lock();
                const auto node = nodes ? nodes->choose() : std::nullopt;
                std::uint64_t token = 0;
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    auto it = m_pending.find(id);
                    if (it == m_pending.end())
                    {
                        return;
                    }
                    token = ++it->second.token;
                    if (node && it->second.retryPending)
                    {
                        it->second.retryPending = false;
                        g_deleteRetries.fetch_add(1);
                    }
                }
                if (!node)
                {
                    settle(id, token, Settle::NoNode, std::nullopt);
                    return;
                }

                HttpRequest request;
                request.method = HttpMethod::Delete;
                request.url = deleteUrl(nodes->host(*node));
                request.body = std::make_shared<const std::string>(nlohmann::json {{"pit_id", id}}.dump());
                request.timeout = timeout;
                std::weak_ptr<Registry> weak = shared_from_this();
                std::weak_ptr<NodeSet> weakNodes = nodes;
                const auto index = *node;
                const auto admission = transport->submit(std::move(request),
                                                         [weak, weakNodes, id, token, index](HttpResult&& result)
                                                         {
                                                             if (auto set = weakNodes.lock())
                                                             {
                                                                 set->report(index, result);
                                                             }
                                                             if (auto self = weak.lock())
                                                             {
                                                                 self->onResult(id, token, result);
                                                             }
                                                         });
                if (!admission.admitted)
                {
                    if (admission.cause == Cause::Shutdown)
                    {
                        expire(id);
                    }
                    else
                    {
                        settle(id, token, Settle::Retry, std::nullopt);
                    }
                    return;
                }
                bool cancelNow = false;
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    auto it = m_pending.find(id);
                    if (it != m_pending.end() && it->second.token == token && it->second.inFlight)
                    {
                        it->second.transferId = admission.id;
                    }
                    else if (it == m_pending.end() && m_draining)
                    {
                        cancelNow = true; // The drain ended (and gave it up) before the id was known.
                    }
                }
                if (cancelNow)
                {
                    transport->cancel(admission.id);
                }
            }

            /// CPU pool: one DELETE's result.
            void onResult(const std::string& id, std::uint64_t token, const HttpResult& result)
            {
                if (result.cause == TransportCause::None &&
                    ((result.status >= 200 && result.status < 300) || result.status == 404))
                {
                    settle(id, token, Settle::Confirmed, std::nullopt);
                    return;
                }
                const auto outcome = write::classifyRequest(result, 1);
                switch (outcome.verdict)
                {
                    case write::RequestVerdict::Throttled:
                    case write::RequestVerdict::Failover:
                    case write::RequestVerdict::Retry:
                        settle(id,
                               token,
                               Settle::Retry,
                               outcome.verdict == write::RequestVerdict::Throttled
                                   ? outcome.retryAfter.value_or(Duration::zero())
                                   : std::optional<Duration> {});
                        return;
                    default:
                        // Cancelled/Shutdown (drain or stop), or any other final answer (another 4xx, too large):
                        // given up at once (deletesExpired), keep_alive frees the PIT (pit.hpp LIFETIME).
                        settle(id, token, Settle::Expired, std::nullopt);
                        return;
                }
            }

            /// Settles the current send of `id` (`token`); stale tokens are ignored. `floor` = Retry-After.
            void settle(const std::string& id, std::uint64_t token, Settle how, std::optional<Duration> floor)
            {
                std::optional<Duration> rearm;
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    auto it = m_pending.find(id);
                    if (it == m_pending.end() || it->second.token != token)
                    {
                        return;
                    }
                    auto& entry = it->second;
                    const auto now = std::chrono::steady_clock::now();
                    if (how == Settle::Confirmed || how == Settle::Expired || m_draining || now >= entry.expiresAt)
                    {
                        m_pending.erase(it);
                        finishLocked(how == Settle::Confirmed);
                    }
                    else
                    {
                        auto delay = deleteBackoff(entry.failures + 1);
                        if (how == Settle::NoNode)
                        {
                            delay = std::min(delay, m_env.probeInterval);
                        }
                        else
                        {
                            ++entry.failures;
                            entry.retryPending = true;
                            if (floor)
                            {
                                delay = std::max(delay, *floor);
                            }
                        }
                        entry.inFlight = false;
                        entry.transferId = 0;
                        entry.nextAt = std::min(now + delay, entry.expiresAt);
                        rearm = std::chrono::duration_cast<Duration>(entry.nextAt - now);
                    }
                }
                if (rearm)
                {
                    arm(*rearm);
                }
                else
                {
                    m_cv.notify_all();
                }
            }

            const PitRegistryEnvironment m_env;

            std::mutex m_mutex;           ///< A leaf; guards everything below.
            std::condition_variable m_cv; ///< drain() waits on it for the queue to empty.
            std::uint64_t m_open {0};     ///< Open PITs, including those whose DELETE is pending.
            std::uint64_t m_acquired {0}; ///< Slots taken by a creation attempt not settled yet.
            std::vector<TimePoint> m_reservations;
            std::vector<std::weak_ptr<PitState>> m_live;
            std::map<std::string, Entry> m_pending;
            std::optional<TimePoint> m_armedAt;
            bool m_draining {false};
            bool m_drainDone {false}; ///< drain() gave up what was left: a later opened() counts it expired.
            TimePoint m_drainEnd;     ///< drain()'s end, set when m_draining is.
        };

        std::mutex g_liveMutex;
        std::weak_ptr<Registry> g_live;
    } // namespace

    std::shared_ptr<PitRegistry> makePitRegistry(PitRegistryEnvironment environment)
    {
        auto registry = std::make_shared<Registry>(std::move(environment));
        std::lock_guard<std::mutex> lock(g_liveMutex);
        g_live = registry;
        return registry;
    }

    PitStats registryStats()
    {
        std::shared_ptr<Registry> live;
        {
            std::lock_guard<std::mutex> lock(g_liveMutex);
            live = g_live.lock();
        }
        if (live)
        {
            return live->stats();
        }
        PitStats stats;
        Registry::addCounters(stats);
        return stats;
    }
} // namespace indexer_client::detail::query
