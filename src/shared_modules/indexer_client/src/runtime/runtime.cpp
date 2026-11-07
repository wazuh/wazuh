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

#include "indexer_client/runtime.hpp"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <csignal>
#include <deque>
#include <future>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <system_error>
#include <thread>
#include <utility>

#include <pthread.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <asio/executor_work_guard.hpp>
#include <asio/io_context.hpp>
#include <asio/post.hpp>
#include <asio/steady_timer.hpp>

#include "health/nodeSet.hpp"
#include "health/prober.hpp"
#include "loggerHelper.h"
#include "query/pit.hpp"
#include "query/query.hpp"
#include "runtime/logSummary.hpp"
#include "runtime/runtimeInternal.hpp"
#include "transport/seams.hpp"
#include "transport/transport.hpp"
#include "write/encoding.hpp"
#include "write/sender.hpp"
#include "write/writer.hpp"

#ifdef INDEXER_CLIENT_TESTING
#include "testing/hooks.hpp"
#endif

namespace indexer_client
{
    namespace
    {
        constexpr const char* TAG = "indexer-client";

        thread_local bool t_onRuntimeThread = false;

        /// Usage errors detected by the library (I37), process-wide; read through detail::testing::usageErrors().
        std::atomic<std::uint64_t> g_usageErrors {0};

        /// Internal invariants found broken and survived (issue 15, D64), process-wide; read by the test build only
        /// (testing_hooks::internalErrors()). The production signal is the ERROR line internalError() writes.
        std::atomic<std::uint64_t> g_internalErrors {0};

#ifdef INDEXER_CLIENT_TESTING
        /// testing_hooks::setProbeAutoStart (test build only).
        std::atomic<bool> g_probeAutoStart {true};
#endif

        /// Joins `thread` if it is joinable.
        void joinIfJoinable(std::thread& thread)
        {
            if (!thread.joinable())
            {
                return;
            }
            if (thread.get_id() == std::this_thread::get_id())
            {
                // Unreachable by construction: shutdown() refuses runtime threads and the owner holds the last
                // strong reference until every join has returned. A self-join would throw from a destructor, so
                // detach only avoids std::terminate; it is counted as a usage error, never a supported path.
                detail::countUsageError();
                thread.detach();
                return;
            }
            thread.join();
        }

        pid_t currentTid()
        {
            return static_cast<pid_t>(::syscall(SYS_gettid));
        }

        void nameThisThread(const char* prefix, std::size_t index)
        {
            const auto name = std::string(prefix) + std::to_string(index);
            // Linux limits names to 15 characters; a failure only loses a diagnostic label.
            pthread_setname_np(pthread_self(), name.substr(0, 15).c_str());
        }

        /// Every asynchronous signal: all of them except the synchronous ones a faulting thread cannot avoid and the
        /// real-time range (glibc reserves part of it for its own use).
        sigset_t asynchronousSignals()
        {
            sigset_t set;
            sigfillset(&set);
            for (const int sync : {SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGTRAP, SIGABRT})
            {
                sigdelset(&set, sync);
            }
            for (int rt = SIGRTMIN; rt <= SIGRTMAX; ++rt)
            {
                sigdelset(&set, rt);
            }
            return set;
        }

        /// Blocks every asynchronous signal on the calling thread for its lifetime and restores the previous mask on
        /// destruction, so that the threads created meanwhile inherit the blocked mask (k3-2).
        class ScopedSignalBlock final
        {
        public:
            ScopedSignalBlock()
            {
                const auto set = asynchronousSignals();
                m_active = pthread_sigmask(SIG_BLOCK, &set, &m_previous) == 0;
            }

            ~ScopedSignalBlock()
            {
                if (m_active)
                {
                    pthread_sigmask(SIG_SETMASK, &m_previous, nullptr);
                }
            }

            ScopedSignalBlock(const ScopedSignalBlock&) = delete;
            ScopedSignalBlock& operator=(const ScopedSignalBlock&) = delete;

            bool active() const
            {
                return m_active;
            }

        private:
            sigset_t m_previous {};
            bool m_active {false};
        };
    } // namespace

    namespace detail
    {
        /// One network thread: its own io_context, kept alive by a work guard until shutdown (I22c).
        struct IoLoop final
        {
            asio::io_context context {1};
            std::optional<asio::executor_work_guard<asio::io_context::executor_type>> guard {
                asio::make_work_guard(context)};
            std::thread thread;
        };

        /// The CPU pool: M threads over a single FIFO. On stop, queued tasks still run, then the workers exit.
        class CpuPool final
        {
        public:
            CpuPool() = default;
            CpuPool(const CpuPool&) = delete;
            CpuPool& operator=(const CpuPool&) = delete;

            /// Safety net: a pool destroyed with live workers (a failed or interrupted start) stops and joins them
            /// instead of letting a joinable std::thread terminate the process.
            ~CpuPool()
            {
                stopAndJoin();
            }

            void startWorkers(std::uint32_t count)
            {
                m_threads.reserve(count);
                for (std::uint32_t i = 0; i < count; ++i)
                {
                    m_threads.emplace_back(
                        [this, i]()
                        {
                            t_onRuntimeThread = true;
                            nameThisThread("ic-cpu-", i);
                            seams::onRuntimeThreadStart(currentTid());
                            work();
                        });
                }
            }

            bool post(std::function<void()> task)
            {
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    if (m_stop)
                    {
                        return false;
                    }
                    m_queue.push_back(std::move(task));
                    m_peakPending = std::max<std::uint64_t>(m_peakPending, m_queue.size());
                }
                m_cv.notify_one();
                return true;
            }

            /// Tasks queued and not yet taken by a worker, and the peak since the pool was created (E3a).
            PoolStats stats()
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                PoolStats stats;
                stats.postsPending = m_queue.size();
                stats.peakPostsPending = m_peakPending;
                return stats;
            }

            void stopAndJoin()
            {
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    m_stop = true;
                }
                m_cv.notify_all();
                for (auto& thread : m_threads)
                {
                    joinIfJoinable(thread);
                }
                m_threads.clear();
            }

        private:
            void work()
            {
                for (;;)
                {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lock(m_mutex);
                        m_cv.wait(lock, [this] { return m_stop || !m_queue.empty(); });
                        if (m_queue.empty())
                        {
                            return;
                        }
                        task = std::move(m_queue.front());
                        m_queue.pop_front();
                    }
                    try
                    {
                        task();
                    }
                    catch (...)
                    {
                        // A task must never take a pool thread down; E3a adds the callback accounting.
                    }
                }
            }

            std::mutex m_mutex;
            std::condition_variable m_cv;
            std::deque<std::function<void()>> m_queue;
            bool m_stop {false};
            std::uint64_t m_peakPending {0};
            std::vector<std::thread> m_threads;
        };

        /// The PIT registry's timers (E4b, I93): one steady_timer per after() on loop 0, all cancelled by stop(),
        /// which runs before the loops' work guards are released (a pending wait would keep a loop running).
        class LoopTimers final : public std::enable_shared_from_this<LoopTimers>
        {
        public:
            explicit LoopTimers(asio::io_context& loop)
                : m_loop(loop)
            {
            }

            /// Any thread: runs `task` on the loop once `delay` has passed; false once stopped.
            bool after(Duration delay, std::function<void()> task)
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                if (m_stopped)
                {
                    return false;
                }
                asio::post(m_loop,
                           [self = shared_from_this(), delay, task = std::move(task)]() mutable
                           {
                               std::shared_ptr<asio::steady_timer> timer;
                               {
                                   std::lock_guard<std::mutex> lock(self->m_mutex);
                                   if (self->m_stopped)
                                   {
                                       return;
                                   }
                                   timer = std::make_shared<asio::steady_timer>(self->m_loop, delay);
                                   self->m_timers.insert(timer);
                               }
                               timer->async_wait(
                                   [self, timer, task = std::move(task)](const std::error_code& error)
                                   {
                                       {
                                           std::lock_guard<std::mutex> lock(self->m_mutex);
                                           self->m_timers.erase(timer);
                                           if (error || self->m_stopped)
                                           {
                                               return;
                                           }
                                       }
                                       task();
                                   });
                           });
                return true;
            }

            /// Idempotent: no timer is armed afterwards; the pending ones are cancelled on the loop.
            void stop()
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                if (m_stopped)
                {
                    return;
                }
                m_stopped = true;
                asio::post(m_loop,
                           [self = shared_from_this()]()
                           {
                               std::set<std::shared_ptr<asio::steady_timer>> timers;
                               {
                                   std::lock_guard<std::mutex> lock(self->m_mutex);
                                   timers.swap(self->m_timers);
                               }
                               for (const auto& timer : timers)
                               {
                                   timer->cancel();
                               }
                           });
            }

        private:
            asio::io_context& m_loop;
            std::mutex m_mutex; ///< A leaf; guards the members below.
            bool m_stopped {false};
            std::set<std::shared_ptr<asio::steady_timer>> m_timers;
        };

        struct RuntimeState final
        {
            RuntimeState() = default;
            RuntimeState(const RuntimeState&) = delete;
            RuntimeState& operator=(const RuntimeState&) = delete;

            /// Safety net: if a RuntimeState is ever destroyed with runtime threads still joinable (a start() that
            /// failed half-way, a future early return), stop and join them rather than std::terminate.
            ~RuntimeState()
            {
                stopAndJoin();
            }

            RuntimeConfig config;
            /// Belt-and-braces only: the identity of a runtime is already given by the weak_ptr (a fresh RuntimeState
            /// per start(), destroyed at the end of shutdown()), so a stale RuntimeRef/ClientState fails on lock()
            /// before the epoch is compared. No test exercises a mismatching epoch; keep it as an extra guard.
            std::uint64_t epoch {0};
            std::uint32_t networkThreads {0}; ///< Fixed once start() has created the threads.
            std::uint32_t cpuThreads {0};
            std::vector<std::unique_ptr<IoLoop>> loops;
            CpuPool pool;

            std::mutex mutex; ///< Guards everything below.
            bool accepting {true};
            std::optional<TimePoint> shutdownDeadline;
            /// The live consumers (E5c, N23): raw name -> the client, weakly, and its sanitized metric name. Written by
            /// RuntimeRef::client() (which refuses a sanitized clash), erased by releaseClientName; read by
            /// runtimeLiveClients() (the log summary's per-client overruns).
            struct ClientEntry final
            {
                std::weak_ptr<ClientState> state;
                std::string metricName;
            };
            std::map<std::string, ClientEntry> clients;
            /// D133: the clients whose name was released once the stop began (a shutdown deadline is fixed or the
            /// admission is closed), kept strongly so that the last summary still counts what their close dropped:
            /// the close order (client.hpp) runs each consumer's awaitClosed, which releases the name, before
            /// shutdown(). runtimeLiveClients() returns them too; stopAndJoin releases them right after the last
            /// summary and keeps none afterwards (`closedReleased`). Only the ClientState and its buckets: awaitClosed
            /// already fixed its callback cutoff, so no callback of the consumer starts through them.
            std::vector<std::shared_ptr<ClientState>> closedClients;
            bool closedReleased {false};

            /// Created by start() once every runtime thread exists; stopped first by stopAndJoin() (I22c, D28).
            std::shared_ptr<Transport> transport;
            /// Node health (E2b, I57): created after the transport; the prober is stopped before it.
            std::shared_ptr<NodeSet> nodes;
            std::shared_ptr<Prober> prober;
            /// The write path (E3a, I62/I63) with the bulk sender (E3b-2): created after the prober and started before
            /// it; stopped first in stopAndJoin, right after the admission closes and before the probe.
            std::shared_ptr<write::WritePath> writePath;
            /// E4a (I87): the gate every query of this runtime waits on; stopAndJoin() wakes it first.
            std::shared_ptr<QueryGate> queryGate = std::make_shared<QueryGate>();
            /// E4b (I90, I93): the PIT registry, created after the transport and the NodeSet, drained by stopAndJoin
            /// after the write path and before the transport; its timers live on loop 0 and stop after the drain.
            std::shared_ptr<LoopTimers> pitTimers;
            std::shared_ptr<query::PitRegistry> pits;
            /// E5c (runtime/logSummary.hpp): the periodic log summary and its loop-0 timers, started last by start()
            /// and disarmed by stopAndJoin before the write path; its final summary runs after the PIT drain.
            std::shared_ptr<LoopTimers> summaryTimers;
            std::shared_ptr<logging::LogSummary> logSummary;

            bool sameEpoch(std::uint64_t other) const
            {
                return epoch == other;
            }

            /// Contract order (contrato-transport.md, stop): close admission, stop the write path (buckets closed and
            /// blocked producers woken, scheduler stopped, sink stopped, every unresolved op Dropped(Shutdown) while
            /// the pool still runs its completions), stop the prober (no round is armed and
            /// no probe submitted afterwards, I57), stop the transport (every transfer
            /// resolved, every multi cleaned up on its loop), release the work guards and join the loops, then drain
            /// and join the CPU pool. Never holds `mutex` while joining: a task may still need it (client registry,
            /// seams). The deadline (fixed here) is the shutdown deadline, else now + drain; the PIT drain (E4b, I93)
            /// runs after the write path and ends min(DRAIN_STOP_MARGIN, half of what is left) before it, then the
            /// transport stops. E5c: the log summary's timer stops before the write path; its last summary runs right
            /// after the PIT drain.
            void stopAndJoin()
            {
                std::optional<TimePoint> deadline;
                {
                    std::lock_guard<std::mutex> lock(mutex);
                    accepting = false;
                    deadline = shutdownDeadline;
                }
                const auto stopDeadline = deadline.value_or(std::chrono::steady_clock::now() + config.drain);
                {
                    // Queries waiting for a backoff or a node return Shutdown; one waiting for its result is resolved
                    // by transport->stop() below.
                    std::lock_guard<std::mutex> gate(queryGate->mutex);
                    queryGate->stopping = true;
                }
                queryGate->cv.notify_all();
                if (logSummary)
                {
                    logSummary->stop(); // No re-arm afterwards; the final summary comes after the PIT drain.
                }
                if (summaryTimers)
                {
                    summaryTimers->stop();
                }
                if (writePath)
                {
                    // I99: the completions still queued start no callback past stopDeadline - callbackBudget.
                    writePath->stop(stopDeadline - config.callbackBudget);
                }
                if (pits)
                {
                    // The margin is DRAIN_STOP_MARGIN, or half of what is left when that is shorter: a short deadline
                    // still sends the deletes (pit.hpp SHUTDOWN).
                    const auto left = std::chrono::duration_cast<Duration>(
                        std::max(stopDeadline - std::chrono::steady_clock::now(), TimePoint::duration::zero()));
                    pits->drain(stopDeadline - std::min(query::DRAIN_STOP_MARGIN, left / 2));
                }
                if (logSummary)
                {
                    // The last summary, synchronous (runtime/logSummary.hpp): after the sweep's Dropped(Shutdown) and
                    // the deletes the drain gave up. No mutex held; the loops still run, the timer is stopped.
                    logSummary->finish();
                }
                {
                    // D133: the clients closed during the stop were only kept for that summary. Dropped outside the
                    // mutex (their buckets die here unless something else still holds them).
                    std::vector<std::shared_ptr<ClientState>> closed;
                    {
                        std::lock_guard<std::mutex> lock(mutex);
                        closedReleased = true;
                        closed.swap(closedClients);
                    }
                }
                if (pitTimers)
                {
                    pitTimers->stop();
                }
                if (prober)
                {
                    prober->stop();
                }
                if (transport)
                {
                    transport->stop(stopDeadline);
                }
                for (auto& loop : loops)
                {
                    asio::post(loop->context, [g = &loop->guard]() { g->reset(); });
                }
                for (auto& loop : loops)
                {
                    joinIfJoinable(loop->thread);
                }
                pool.stopAndJoin();
            }
        };

        void releaseClientName(const std::weak_ptr<RuntimeState>& runtime, std::uint64_t epoch, const std::string& name)
        {
            if (auto state = runtime.lock(); state && state->sameEpoch(epoch))
            {
                std::lock_guard<std::mutex> lock(state->mutex);
                const auto found = state->clients.find(name);
                if (found == state->clients.end())
                {
                    return;
                }
                if ((state->shutdownDeadline || !state->accepting) && !state->closedReleased)
                {
                    // D133: kept for the last summary. lock() fails when the release comes from ~ClientState.
                    if (auto client = found->second.state.lock())
                    {
                        state->closedClients.push_back(std::move(client));
                    }
                }
                state->clients.erase(found);
            }
        }

        std::optional<TimePoint> runtimeShutdownDeadline(const std::weak_ptr<RuntimeState>& runtime,
                                                         std::uint64_t epoch)
        {
            if (auto state = runtime.lock(); state && state->sameEpoch(epoch))
            {
                std::lock_guard<std::mutex> lock(state->mutex);
                return state->shutdownDeadline;
            }
            return std::nullopt;
        }
    } // namespace detail

    namespace detail
    {
        std::vector<std::shared_ptr<ClientState>> runtimeLiveClients(const std::weak_ptr<RuntimeState>& runtime)
        {
            std::vector<std::weak_ptr<ClientState>> weak;
            std::vector<std::shared_ptr<ClientState>> alive;
            if (auto state = runtime.lock())
            {
                std::lock_guard<std::mutex> lock(state->mutex);
                weak.reserve(state->clients.size());
                for (const auto& entry : state->clients)
                {
                    weak.push_back(entry.second.state);
                }
                alive = state->closedClients; // D133: their names are released already.
            }
            // Locked outside the runtime mutex: a client whose last reference dies here releases its name under it.
            alive.reserve(alive.size() + weak.size());
            for (const auto& entry : weak)
            {
                if (auto client = entry.lock())
                {
                    alive.push_back(std::move(client));
                }
            }
            return alive;
        }
    } // namespace detail

    namespace
    {
        // Process-wide runtime (I37). `g_lifecycle` serializes the owner operations; `g_mutex` guards the pointers and
        // is never held while joining threads.
        std::mutex g_lifecycle;
        std::mutex g_mutex;
        std::shared_ptr<detail::RuntimeState> g_state;
        std::thread::id g_owner;
        std::uint64_t g_epoch {0};

        std::shared_ptr<detail::RuntimeState> current()
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            return g_state;
        }

        /// UsageError when the caller cannot run an owner operation: a runtime thread, or a thread that is not the
        /// owner of a running runtime. None otherwise.
        Cause ownerCheck()
        {
            if (t_onRuntimeThread)
            {
                return Cause::UsageError;
            }
            std::lock_guard<std::mutex> lock(g_mutex);
            if (g_state && g_owner != std::this_thread::get_id())
            {
                return Cause::UsageError;
            }
            return Cause::None;
        }

        std::string validateBucket(const BucketSpec& spec, std::size_t index, std::uint64_t globalQuotaBytes)
        {
            const auto field = [&](const char* name)
            {
                return "buckets[" + std::to_string(index) + "] ('" + spec.name + "')." + name;
            };
            if (spec.name.empty())
            {
                return "buckets[" + std::to_string(index) + "].name must not be empty";
            }
            if (spec.weight == 0)
            {
                return field("weight") + " must be > 0";
            }
            if (spec.quotaBytes == 0)
            {
                return field("quotaBytes") + " must be > 0";
            }
            if (spec.quotaBytes > globalQuotaBytes)
            {
                return field("quotaBytes") + " must be <= the runtime's global_quota_bytes (" +
                       std::to_string(globalQuotaBytes) + ")";
            }
            if (spec.bulk.maxBytes == 0)
            {
                return field("bulk.maxBytes") + " must be > 0";
            }
            if (spec.bulk.maxDocs == 0)
            {
                return field("bulk.maxDocs") + " must be > 0";
            }
            if (spec.bulk.maxAge <= Duration::zero())
            {
                return field("bulk.maxAge") + " must be > 0";
            }
            if (spec.bulk.maxBytes > spec.quotaBytes)
            {
                return field("bulk.maxBytes") + " must be <= quotaBytes";
            }
            // I62: the largest admissible op (a whole bulk) plus its result reserve must fit in the quota.
            if (static_cast<std::uint64_t>(spec.bulk.maxBytes) + detail::write::RESULT_RESERVE > spec.quotaBytes)
            {
                return field("bulk.maxBytes") + " + RESULT_RESERVE (" + std::to_string(detail::write::RESULT_RESERVE) +
                       ") must be <= quotaBytes";
            }
            if (spec.retry.base <= Duration::zero())
            {
                return field("retry.base") + " must be > 0";
            }
            if (spec.retry.cap <= Duration::zero())
            {
                return field("retry.cap") + " must be > 0";
            }
            if (!(spec.retry.jitter >= 0.0 && spec.retry.jitter <= 1.0)) // Also rejects NaN.
            {
                return field("retry.jitter") + " must be in [0, 1]";
            }
            if (spec.retry.maxAttempts && *spec.retry.maxAttempts == 0)
            {
                return field("retry.maxAttempts") + " must be > 0 (or unset for unlimited)";
            }
            if (spec.retry.maxDuration && *spec.retry.maxDuration <= Duration::zero())
            {
                return field("retry.maxDuration") + " must be > 0 (or unset for unlimited)";
            }
            if (spec.retry.base > spec.retry.cap)
            {
                return field("retry.base") + " must be <= retry.cap";
            }
            if (spec.overflow.kind == Overflow::Kind::Block && spec.overflow.blockTimeout <= Duration::zero())
            {
                return field("overflow.blockTimeout") + " must be > 0 with Overflow::Block";
            }
            if (spec.onConflict.kind == ConflictPolicy::Kind::Retry && spec.onConflict.retryOnConflict == 0)
            {
                return field("onConflict.retryOnConflict") + " must be > 0 with ConflictPolicy::Retry";
            }
            // I73: the same cap as an op's own onConflict (encoding.hpp).
            if (spec.onConflict.kind == ConflictPolicy::Kind::Retry &&
                spec.onConflict.retryOnConflict > detail::write::MAX_RETRY_ON_CONFLICT)
            {
                return field("onConflict.retryOnConflict") +
                       " must be <= " + std::to_string(detail::write::MAX_RETRY_ON_CONFLICT) +
                       " with ConflictPolicy::Retry";
            }
            return {};
        }
    } // namespace

    RuntimeRef::RuntimeRef(std::weak_ptr<detail::RuntimeState> state, std::uint64_t epoch)
        : m_state(std::move(state))
        , m_epoch(epoch)
    {
    }

    bool RuntimeRef::valid() const
    {
        auto state = m_state.lock();
        if (!state || !state->sameEpoch(m_epoch))
        {
            return false;
        }
        std::lock_guard<std::mutex> lock(state->mutex);
        return state->accepting;
    }

    Outcome<std::shared_ptr<Client>> RuntimeRef::client(std::string_view consumer,
                                                        std::vector<BucketSpec> buckets) const
    {
        using Result = Outcome<std::shared_ptr<Client>>;
        auto state = m_state.lock();
        if (!state || !state->sameEpoch(m_epoch))
        {
            return Result::failure(Cause::InvalidState, "the runtime is not running (stale or empty reference)");
        }
        if (consumer.empty())
        {
            return Result::failure(Cause::InvalidArgument, "consumer name must not be empty");
        }
        std::set<std::string_view> names;
        std::map<std::string, std::size_t> metricNames; // E5c (metrics.hpp CATALOG): sanitized name -> first index.
        for (std::size_t i = 0; i < buckets.size(); ++i)
        {
            if (auto reason = validateBucket(buckets[i], i, state->config.globalQuotaBytes); !reason.empty())
            {
                return Result::failure(Cause::InvalidArgument, std::move(reason));
            }
            if (!names.insert(buckets[i].name).second)
            {
                return Result::failure(Cause::InvalidArgument,
                                       "buckets[" + std::to_string(i) + "].name '" + buckets[i].name +
                                           "' is duplicated");
            }
            const auto [clash, fresh] = metricNames.emplace(sanitizeMetricName(buckets[i].name), i);
            if (!fresh)
            {
                return Result::failure(Cause::InvalidArgument,
                                       "buckets[" + std::to_string(i) + "].name '" + buckets[i].name +
                                           "' has the same metric name ('" + clash->first + "') as buckets[" +
                                           std::to_string(clash->second) + "]");
            }
        }
        auto metricName = sanitizeMetricName(consumer);

        auto clientState = std::make_shared<detail::ClientState>();
        clientState->runtime = state;
        clientState->epoch = m_epoch;
        clientState->consumer = std::string(consumer);
        clientState->buckets = std::move(buckets);
        clientState->drain = state->config.drain;
        clientState->queryGate = state->queryGate;
        clientState->requestTimeout = state->config.requestTimeout;
        clientState->callbackBudget = state->config.callbackBudget;
        clientState->probeInterval = state->config.probeInterval;
        clientState->maxResponseBytes = state->config.maxResponseBytes;
        {
            std::lock_guard<std::mutex> lock(state->mutex);
            if (!state->accepting)
            {
                clientState->nameReleased = true;
                return Result::failure(Cause::InvalidState, "the runtime is shutting down");
            }
            if (state->clients.count(clientState->consumer) != 0)
            {
                clientState->nameReleased = true;
                return Result::failure(Cause::InvalidArgument,
                                       "consumer '" + clientState->consumer + "' already has a live client");
            }
            for (const auto& [name, entry] : state->clients)
            {
                if (entry.metricName == metricName)
                {
                    clientState->nameReleased = true;
                    return Result::failure(Cause::InvalidArgument,
                                           "consumer '" + clientState->consumer + "' has the same metric name ('" +
                                               metricName + "') as the live consumer '" + name + "'");
                }
            }
            state->clients.emplace(clientState->consumer,
                                   detail::RuntimeState::ClientEntry {clientState, std::move(metricName)});
            // Under the runtime mutex: stopAndJoin closes the admission under it before stopping the write path, so
            // a registered client is always seen by the shutdown sweep.
            if (state->writePath)
            {
                try
                {
                    state->writePath->registerClient(clientState);
                }
                catch (...)
                {
                    state->clients.erase(clientState->consumer);
                    clientState->nameReleased = true;
                    return Result::failure(Cause::InvalidState, "cannot create the client's buckets");
                }
            }
        }
        return Result::success(std::make_shared<Client>(std::move(clientState)));
    }

    MetricsSnapshot RuntimeRef::snapshot() const
    {
        MetricsSnapshot snapshot;
        // Process-wide (metrics.hpp SCOPE): read even without a runtime.
        const auto queries = detail::query::queryStats();
        snapshot.queries.requests = queries.requests;
        snapshot.queries.failovers = queries.failovers;
        snapshot.queries.throttles = queries.throttles;
        snapshot.queries.unavailable = queries.unavailable;
        snapshot.queries.tooLarge = queries.tooLarge;
        snapshot.queries.conflictRetries = queries.conflictRetries;
        snapshot.queries.responseBytesInFlight = queries.responseBytesInFlight;
        snapshot.queries.peakResponseBytesInFlight = queries.peakResponseBytesInFlight;
        const auto pits = detail::query::pitStats();
        snapshot.pit.open = pits.open;
        snapshot.pit.reserved = pits.reserved;
        snapshot.pit.deletesPending = pits.deletesPending;
        snapshot.pit.created = pits.created;
        snapshot.pit.deletesConfirmed = pits.deletesConfirmed;
        snapshot.pit.deletesExpired = pits.deletesExpired;
        snapshot.pit.deleteRetries = pits.deleteRetries;
        snapshot.pit.expired = pits.expired;
        snapshot.pit.stale = pits.stale;
        snapshot.pit.refusedFull = pits.refusedFull;
        snapshot.usageErrors = g_usageErrors.load();

        auto state = m_state.lock();
        if (!state || !state->sameEpoch(m_epoch))
        {
            return snapshot;
        }
        snapshot.networkThreads = state->networkThreads;
        snapshot.cpuThreads = state->cpuThreads;
        snapshot.requestTimeout = state->config.requestTimeout;
        {
            std::lock_guard<std::mutex> lock(state->mutex);
            snapshot.clients = static_cast<std::uint32_t>(state->clients.size());
        }
        // Set by start() before the RuntimeRef exists and never reset: read without the runtime mutex.
        if (state->writePath)
        {
            snapshot.globalCharge = state->writePath->budget().charge();
            snapshot.globalQuotaBytes = state->writePath->budget().cap();
            snapshot.retainedBytes = state->writePath->retainedBytes();
        }
        if (state->nodes)
        {
            const auto view = state->nodes->view();
            const auto sink = state->writePath
                                  ? std::dynamic_pointer_cast<detail::write::BulkSink>(state->writePath->sink())
                                  : nullptr;
            const auto sender = sink ? sink->stats() : detail::write::SenderStats {};
            snapshot.nodes.resize(state->nodes->size());
            for (std::size_t i = 0; i < snapshot.nodes.size(); ++i)
            {
                auto& node = snapshot.nodes[i];
                node.host = state->nodes->host(i);
                if (i < view.nodes.size())
                {
                    node.state = view.nodes[i].state;
                }
                node.transitions = state->nodes->transitions(i);
                if (i < sender.nodes.size())
                {
                    const auto& slot = sender.nodes[i];
                    node.window = slot.window;
                    node.bulkTarget = slot.bulkTarget;
                    node.paceMs = static_cast<std::uint64_t>(slot.pace.count());
                    node.requests = slot.requests;
                    node.throttled = slot.throttled;
                    node.server5xx = slot.server5xx;
                    node.failures = slot.failures;
                    node.decreases429 = slot.decreases429;
                    node.decreasesThrottled = slot.decreasesThrottled;
                    node.decreasesLatency = slot.decreasesLatency;
                    node.latency = slot.latency;
                }
            }
        }
        return snapshot;
    }

    std::optional<TimePoint> RuntimeRef::shutdownDeadline() const
    {
        return detail::runtimeShutdownDeadline(m_state, m_epoch);
    }

    namespace
    {
        /// Wipes the key and the password copies of start() on every exit (I55, best effort).
        struct SecretsWiper final
        {
            std::string& key;
            std::string& password;
            ~SecretsWiper()
            {
                detail::cleanseString(key);
                detail::cleanseString(password);
            }
        };
    } // namespace

    Outcome<RuntimeRef> RuntimeOwner::start(ProcessId process, const IConfigSource& source)
    {
        using Result = Outcome<RuntimeRef>;
        if (t_onRuntimeThread)
        {
            return Result::failure(Cause::UsageError, "start() called from a runtime thread");
        }
        std::lock_guard<std::mutex> lifecycle(g_lifecycle);
        if (auto cause = ownerCheck(); cause != Cause::None)
        {
            return Result::failure(cause, "start() called from a thread that does not own the running runtime");
        }
        if (current())
        {
            return Result::failure(Cause::InvalidState, "the runtime is already running");
        }

        auto config = RuntimeConfig::from(process, source);
        if (!config.ok())
        {
            return Result::failure(config.cause, std::move(config.reason), config.httpStatus);
        }

        // TLS material and credentials are read and validated once, here, before any runtime thread exists (I48,
        // I55): a failure creates no thread. The reason never carries the password nor the key.
        auto tls = detail::loadTlsMaterial(config.value);
        if (!tls.ok())
        {
            return Result::failure(tls.cause, std::move(tls.reason));
        }
        // E11e: once per start, before any thread; nothing when every host is http.
        if (!tls.value.warning.empty())
        {
            logWarn(TAG, "%s", tls.value.warning.c_str());
        }
        if (!tls.value.notice.empty())
        {
            logInfo(TAG, "%s", tls.value.notice.c_str());
        }
        Credentials credentials;
        // Every exit that does not hand them to the transport wipes the local copies (best effort; empty once moved).
        const SecretsWiper wiper {tls.value.privateKey, credentials.password};
        try
        {
            credentials = source.credentials();
        }
        catch (...)
        {
            return Result::failure(Cause::InvalidConfig, "cannot read the indexer credentials");
        }
        if (credentials.user.empty() || credentials.password.empty())
        {
            return Result::failure(Cause::InvalidConfig,
                                   credentials.user.empty() ? "indexer credentials missing: user"
                                                            : "indexer credentials missing: password");
        }

        auto state = std::make_shared<detail::RuntimeState>();
        state->config = std::move(config.value);
        state->epoch = ++g_epoch;

        {
            ScopedSignalBlock blocked;
            if (!blocked.active())
            {
                return Result::failure(Cause::InvalidState, "pthread_sigmask failed: runtime threads not created");
            }
            try
            {
                for (std::uint32_t i = 0; i < state->config.networkThreads; ++i)
                {
                    auto loop = std::make_unique<detail::IoLoop>();
                    auto* raw = loop.get();
                    state->loops.push_back(std::move(loop));
                    raw->thread = std::thread(
                        [raw, i]()
                        {
                            t_onRuntimeThread = true;
                            nameThisThread("ic-io-", i);
                            detail::seams::onRuntimeThreadStart(currentTid());
                            for (;;)
                            {
                                try
                                {
                                    raw->context.run();
                                    return;
                                }
                                catch (...)
                                {
                                    // A handler must never take a network thread down.
                                }
                            }
                        });
                }
                state->pool.startWorkers(state->config.cpuThreads);
                state->networkThreads = state->config.networkThreads;
                state->cpuThreads = state->config.cpuThreads;
            }
            catch (const std::system_error& e)
            {
                state->stopAndJoin();
                return Result::failure(Cause::InvalidState, std::string("cannot create runtime threads: ") + e.what());
            }
            catch (...)
            {
                // E.g. std::bad_alloc from make_unique/reserve: join whatever was already created, never terminate.
                state->stopAndJoin();
                return Result::failure(Cause::InvalidState, "cannot create runtime threads: unexpected exception");
            }
        } // The owner's mask is restored here, after every thread exists.

        // The transport borrows the loops' io_contexts and the pool; it creates no thread of its own (curl's resolver
        // threads, auxiliary and outside K + M, start later from the network threads and inherit their mask).
        try
        {
            detail::TransportEnvironment environment;
            for (auto& loop : state->loops)
            {
                environment.loops.push_back(&loop->context);
            }
            // The pool outlives every use: the transport is stopped before the pool in stopAndJoin().
            environment.postToPool = [pool = &state->pool](std::function<void()> task)
            {
                return pool->post(std::move(task));
            };
            state->transport = detail::Transport::create(
                state->config, std::move(tls.value), std::move(credentials), std::move(environment));
            // Node health (I57): created after the transport, stopped before it (stopAndJoin).
            state->nodes = std::make_shared<detail::NodeSet>(state->config.hosts);
            // The PIT registry (E4b, I90): after the transport and the NodeSet; its retries run on loop 0 timers.
            state->pitTimers = std::make_shared<detail::LoopTimers>(state->loops.front()->context);
            {
                detail::query::PitRegistryEnvironment pitEnvironment;
                pitEnvironment.maxOpenPits = state->config.maxOpenPits;
                pitEnvironment.requestTimeout = state->config.requestTimeout;
                pitEnvironment.probeInterval = state->config.probeInterval;
                pitEnvironment.transport = state->transport;
                pitEnvironment.nodes = state->nodes;
                pitEnvironment.after = [timers = std::weak_ptr<detail::LoopTimers>(state->pitTimers)](
                                           Duration delay, std::function<void()> task)
                {
                    auto alive = timers.lock();
                    return alive && alive->after(delay, std::move(task));
                };
                state->pits = detail::query::makePitRegistry(std::move(pitEnvironment));
            }
            state->prober = detail::Prober::create(state->nodes,
                                                   state->transport,
                                                   state->loops.front()->context,
                                                   state->config.probeInterval,
                                                   state->config.probeTimeout);
            // The write path (I62/I63): its scheduler and the bulk sender's timer live on loop 0 like the probe; its
            // completions run on the pool, which outlives every completion the write path posts (stopAndJoin stops it
            // long before the pool). Started BEFORE the prober (E3b-2, I68): the sender's NodeSet hook must see the
            // first round's transitions.
            state->writePath = std::make_shared<detail::write::WritePath>(
                state->config.globalQuotaBytes,
                [pool = &state->pool](std::function<void()> task) { return pool->post(std::move(task)); });
            state->writePath->start(state->loops.front()->context, state->config, state->nodes, state->transport);
            // E5c: the log summary, after the write path, the NodeSet and the PIT registry; its timer on loop 0.
            state->summaryTimers = std::make_shared<detail::LoopTimers>(state->loops.front()->context);
            state->logSummary = detail::logging::makeLogSummary(state);
            state->logSummary->start();
            // The first round is armed at once on loop 0.
#ifdef INDEXER_CLIENT_TESTING
            if (g_probeAutoStart.load())
#endif
            {
                state->prober->start();
            }
        }
        catch (const std::exception& e)
        {
            state->stopAndJoin();
            return Result::failure(Cause::InvalidState,
                                   std::string("cannot create the transport, the health probe or the write path: ") +
                                       e.what());
        }
        catch (...)
        {
            state->stopAndJoin();
            return Result::failure(Cause::InvalidState,
                                   "cannot create the transport, the health probe or the write path: unexpected "
                                   "exception");
        }

        {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_state = state;
            g_owner = std::this_thread::get_id();
        }
        return Result::success(RuntimeRef(state, state->epoch));
    }

    Cause RuntimeOwner::beginShutdown(TimePoint deadline)
    {
        if (auto cause = ownerCheck(); cause != Cause::None)
        {
            return cause;
        }
        auto state = current();
        if (!state)
        {
            return Cause::InvalidState;
        }
        std::lock_guard<std::mutex> lock(state->mutex);
        if (!state->shutdownDeadline)
        {
            state->shutdownDeadline = deadline;
        }
        return Cause::None;
    }

    Cause RuntimeOwner::shutdown()
    {
        if (t_onRuntimeThread)
        {
            return Cause::UsageError;
        }
        std::lock_guard<std::mutex> lifecycle(g_lifecycle);
        if (auto cause = ownerCheck(); cause != Cause::None)
        {
            return cause;
        }
        std::shared_ptr<detail::RuntimeState> state;
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            state = std::move(g_state);
            g_state.reset();
            g_owner = std::thread::id {};
        }
        if (!state)
        {
            return Cause::None; // Not running (never started, or already shut down): no-op.
        }
        state->stopAndJoin();
        return Cause::None;
    }

    bool RuntimeOwner::running()
    {
        return current() != nullptr;
    }

    namespace detail
    {
        void countUsageError()
        {
            g_usageErrors.fetch_add(1);
        }

        void internalError(const char* what) noexcept
        {
            g_internalErrors.fetch_add(1);
            try
            {
                logError(TAG, "internal error (please report it): %s", what);
            }
            catch (...)
            {
                // Counted: a log sink that throws must not turn the recovery into a crash.
            }
        }

        bool withNoRuntime(const std::function<void()>& action)
        {
            if (t_onRuntimeThread)
            {
                return false;
            }
            std::lock_guard<std::mutex> lifecycle(g_lifecycle);
            if (current())
            {
                return false;
            }
            action();
            return true;
        }

        std::shared_ptr<Transport> runtimeTransport()
        {
            auto state = current();
            return state ? state->transport : nullptr;
        }

        std::shared_ptr<NodeSet> runtimeNodeSet()
        {
            auto state = current();
            return state ? state->nodes : nullptr;
        }

        std::shared_ptr<Prober> runtimeProber()
        {
            auto state = current();
            return state ? state->prober : nullptr;
        }

        PoolStats runtimePoolStats()
        {
            auto state = current();
            return state ? state->pool.stats() : PoolStats {};
        }

        namespace write
        {
            std::shared_ptr<WritePath> runtimeWritePath()
            {
                auto state = current();
                return state ? state->writePath : nullptr;
            }
        } // namespace write

        std::shared_ptr<NodeSet> runtimeNodeSet(const std::weak_ptr<RuntimeState>& runtime, std::uint64_t epoch)
        {
            auto state = runtime.lock();
            return (state && state->sameEpoch(epoch)) ? state->nodes : nullptr;
        }

        std::shared_ptr<Transport> runtimeTransport(const std::weak_ptr<RuntimeState>& runtime, std::uint64_t epoch)
        {
            auto state = runtime.lock();
            return (state && state->sameEpoch(epoch)) ? state->transport : nullptr;
        }

        std::shared_ptr<query::PitRegistry> runtimePitRegistry(const std::weak_ptr<RuntimeState>& runtime,
                                                               std::uint64_t epoch)
        {
            auto state = runtime.lock();
            return (state && state->sameEpoch(epoch)) ? state->pits : nullptr;
        }

        std::optional<LogSummarySources> runtimeLogSummarySources(const std::weak_ptr<RuntimeState>& runtime)
        {
            auto state = runtime.lock();
            if (!state)
            {
                return std::nullopt;
            }
            return LogSummarySources {state->config.logSummaryInterval, state->writePath, state->pits};
        }

        bool
        runtimeLogSummaryAfter(const std::weak_ptr<RuntimeState>& runtime, Duration delay, std::function<void()> task)
        {
            std::shared_ptr<LoopTimers> timers;
            if (auto state = runtime.lock())
            {
                timers = state->summaryTimers;
            }
            return timers && timers->after(delay, std::move(task));
        }
    } // namespace detail

#ifdef INDEXER_CLIENT_TESTING
    namespace testing_hooks
    {
        void setProbeAutoStart(bool enabled)
        {
            g_probeAutoStart.store(enabled);
        }

        std::uint64_t internalErrors()
        {
            return g_internalErrors.load();
        }
    } // namespace testing_hooks
#endif

    namespace detail::testing
    {
        bool postToPool(std::function<void()> task)
        {
            auto state = current();
            if (!state)
            {
                return false;
            }
            {
                std::lock_guard<std::mutex> lock(state->mutex);
                if (!state->accepting)
                {
                    return false;
                }
            }
            return state->pool.post(std::move(task));
        }

        bool postToIoLoop(std::function<void()> task, std::uint32_t loopIndex)
        {
            auto state = current();
            if (!state || loopIndex >= state->loops.size())
            {
                return false;
            }
            std::lock_guard<std::mutex> lock(state->mutex);
            if (!state->accepting)
            {
                return false;
            }
            asio::post(state->loops[loopIndex]->context, std::move(task));
            return true;
        }

        bool onRuntimeThread()
        {
            return t_onRuntimeThread;
        }

        std::uint64_t usageErrors()
        {
            return g_usageErrors.load();
        }

        bool flushLogSummary()
        {
            if (t_onRuntimeThread)
            {
                return false; // Waiting for loop 0 from a runtime thread could wait on itself.
            }
            auto state = current();
            if (!state)
            {
                return false;
            }
            auto done = std::make_shared<std::promise<void>>();
            auto future = done->get_future();
            {
                // Posted under the runtime mutex while accepting, as postToIoLoop: stopAndJoin clears `accepting`
                // under it before the loops are joined, so the task runs before they exit.
                std::lock_guard<std::mutex> lock(state->mutex);
                if (!state->accepting || !state->logSummary || state->loops.empty())
                {
                    return false;
                }
                asio::post(state->loops.front()->context,
                           [summary = state->logSummary, done]()
                           {
                               try
                               {
                                   summary->flush();
                               }
                               catch (...)
                               {
                                   // The seam still returns.
                               }
                               done->set_value();
                           });
            }
            future.wait();
            return true;
        }
    } // namespace detail::testing
} // namespace indexer_client
