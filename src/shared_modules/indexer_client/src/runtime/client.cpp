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

#include "indexer_client/client.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <mutex>
#include <utility>

#include "health/nodeSet.hpp"
#include "indexer_client/runtime.hpp"
#include "query/query.hpp"
#include "runtime/runtimeInternal.hpp"
#include "write/writer.hpp"

namespace indexer_client
{
    namespace
    {
        constexpr const char* E1_UNAVAILABLE = "data path not implemented yet (E3b/E4)";

        class StubWriter final : public IWriter
        {
        public:
            StubWriter(std::shared_ptr<detail::ClientState> client, std::string bucket)
                : m_client(std::move(client))
                , m_bucket(std::move(bucket))
            {
            }

            Submit submit(Op /*op*/, Callback /*cb*/) override
            {
                Submit result;
                result.accepted = false;
                result.cause = Cause::Unavailable;
                return result;
            }

            Group group() override
            {
                return Group(std::make_shared<detail::GroupState>());
            }

            CancelTicket cancel(std::string_view /*tag*/) override
            {
                auto state = std::make_shared<detail::CancelState>();
                state->complete(Outcome<Unit>::failure(Cause::Unavailable, E1_UNAVAILABLE));
                return CancelTicket(std::move(state));
            }

        private:
            std::shared_ptr<detail::ClientState> m_client;
            std::string m_bucket;
        };
    } // namespace

    namespace
    {
        /// requestClose() (D43, I99): the flag, the queries and blocked producers woken (ClientClosed), the admission
        /// of every bucket closed; the buckets keep draining. `sweep` (a Client destroyed on a runtime thread) also
        /// resolves what is queued now (WritePath::closeClient). Never blocks; takes no close mutex.
        void closeState(detail::ClientState& state, bool sweep)
        {
            // The flag first: a submit racing this close either is refused at its enqueue or was queued before.
            state.closeRequested.store(true);
            if (state.queryGate)
            {
                {
                    // Under the gate's mutex: a query that checked the flag is already waiting, so it sees this notify.
                    std::lock_guard<std::mutex> gate(state.queryGate->mutex);
                }
                state.queryGate->cv.notify_all(); // E4a: queries waiting on this client return ClientClosed.
            }
            if (auto path = state.writePath.lock())
            {
                path->closeClient(state, sweep);
            }
        }

        /// Σ retained of the client's buckets (pending + lane + delivered; I99 N4). Called under completionsMutex
        /// (lock order completionsMutex -> bucket mutex).
        std::uint64_t retainedOf(const detail::ClientState& state)
        {
            std::uint64_t retained = 0;
            for (const auto& bucket : state.bucketStates)
            {
                retained += bucket->retained();
            }
            return retained;
        }
    } // namespace

    namespace detail
    {
        std::shared_ptr<IWriter> makeStubWriter(std::shared_ptr<ClientState> client, std::string bucket)
        {
            return std::make_shared<StubWriter>(std::move(client), std::move(bucket));
        }
    } // namespace detail

    Client::Client(std::shared_ptr<detail::ClientState> state)
        : m_state(std::move(state))
    {
    }

    Client::Client(Client&&) noexcept = default;

    Client& Client::operator=(Client&& other) noexcept
    {
        if (this != &other)
        {
            // The handle being replaced closes exactly as a destroyed one would.
            Client discarded(std::move(*this));
            m_state = std::move(other.m_state);
        }
        return *this;
    }

    Client::~Client()
    {
        if (!m_state)
        {
            return;
        }
        if (detail::testing::onRuntimeThread())
        {
            // Usage error (I37): a runtime thread must never wait for a client to drain. Logged and counted
            // (detail::testing::usageErrors()); never an abort, not even in debug builds.
            detail::countUsageError();
            std::fprintf(stderr,
                         "indexer_client: usage error: client '%s' destroyed from a runtime thread; "
                         "requesting close without waiting\n",
                         m_state->consumer.c_str());
            // I99 (obj. 3): the old close, with the immediate sweep, so a usage error never loses a result or charge.
            closeState(*m_state, true);
            return;
        }
        requestClose();
        const auto deadline = detail::runtimeShutdownDeadline(m_state->runtime, m_state->epoch)
                                  .value_or(std::chrono::steady_clock::now() + m_state->drain);
        awaitClosed(deadline);
    }

    std::shared_ptr<IWriter> Client::writer(std::string_view bucket)
    {
        if (!m_state || m_state->closeRequested.load())
        {
            return nullptr; // A closing client hands out no new handles (I37).
        }
        const auto found = std::find_if(m_state->buckets.cbegin(),
                                        m_state->buckets.cend(),
                                        [bucket](const BucketSpec& spec) { return spec.name == bucket; });
        if (found == m_state->buckets.cend())
        {
            return nullptr;
        }
        const auto index = static_cast<std::size_t>(found - m_state->buckets.cbegin());
        auto path = m_state->writePath.lock();
        if (!path || index >= m_state->bucketStates.size())
        {
            // The runtime is gone (or never registered this client): the E1 stub answers Unavailable.
            return detail::makeStubWriter(m_state, found->name);
        }
        return detail::write::makeWriter(m_state, m_state->bucketStates[index], std::move(path));
    }

    std::shared_ptr<IQuery> Client::query()
    {
        if (!m_state || m_state->closeRequested.load())
        {
            return nullptr;
        }
        // With the runtime gone (or another epoch) every operation answers Shutdown without a request (I87 step 3).
        return detail::query::makeQuery(m_state);
    }

    HealthView Client::health() const
    {
        if (!m_state)
        {
            return {};
        }
        const auto nodes = detail::runtimeNodeSet(m_state->runtime, m_state->epoch);
        return nodes ? nodes->view() : HealthView {};
    }

    void Client::requestClose()
    {
        if (!m_state)
        {
            return;
        }
        closeState(*m_state, false);
    }

    Outcome<CloseReport> Client::awaitClosed(Deadline deadline)
    {
        if (detail::testing::onRuntimeThread())
        {
            return Outcome<CloseReport>::failure(Cause::Reentrancy, "awaitClosed() called from a runtime thread");
        }
        if (!m_state)
        {
            return Outcome<CloseReport>::failure(Cause::InvalidState, "empty client handle");
        }
        requestClose();
        auto& state = *m_state;
        // I99 (write/writer.hpp «Close»): serialized per client; the first call drains and sweeps, a concurrent one
        // waits for it and a later one only waits for the completions. The counters are read live every time (N3).
        std::lock_guard<std::mutex> closeLock(state.closeMutex);
        if (!state.closeReport)
        {
            const auto now = std::chrono::steady_clock::now();
            const auto left = std::max(deadline - now, TimePoint::duration::zero());
            const auto budget = std::chrono::duration_cast<TimePoint::duration>(state.callbackBudget);
            TimePoint drainEnd;
            TimePoint cutoff;
            if (left >= 2 * budget)
            {
                drainEnd = deadline - 2 * budget;
                cutoff = deadline - budget;
            }
            else
            {
                drainEnd = now + left / 2;
                cutoff = now + 3 * left / 4;
            }
            auto path = state.writePath.lock();
            {
                std::unique_lock<std::mutex> lock(state.completionsMutex);
                state.callbackCutoff = std::min(state.callbackCutoff, cutoff);
                if (path)
                {
                    // Every resolution of one of its ops notifies drainDone (WritePath::resolve). The drain keeps the
                    // node pace, notBefore and the bucket backoff: nothing here hurries it.
                    state.drainDone.wait_until(lock, drainEnd, [&state] { return retainedOf(state) == 0; });
                }
            }
            if (path)
            {
                // Outside completionsMutex (an inline completion relocks it). Inside a runtime shutdown the transfers
                // are bounded by transport->stop; outside one they are cancelled (N5).
                const bool runtimeShutdown = detail::runtimeShutdownDeadline(state.runtime, state.epoch).has_value();
                path->sweepClient(state, !runtimeShutdown); // Its Dropped are not part of `drained`.
            }
            state.closeReport = CloseReport {};
        }

        CloseReport report;
        {
            std::unique_lock<std::mutex> lock(state.completionsMutex);
            state.completionsDone.wait_until(lock, deadline, [&state] { return state.outstandingCompletions == 0; });
            // No callback starts after this returns: the gate (CallbackCompletion::run) reads the cutoff under this
            // mutex, so the callbacks that passed it are exactly those still running.
            state.callbackCutoff = std::min(state.callbackCutoff, std::chrono::steady_clock::now());
            report.callbacksInFlight = static_cast<std::size_t>(state.callbacksRunning);
        }
        report.droppedClientClosed = static_cast<std::size_t>(state.droppedClientClosed.load());
        report.droppedShutdown = static_cast<std::size_t>(state.droppedShutdown.load());
        report.callbacksSkipped = static_cast<std::size_t>(state.callbacksSkipped.load());
        report.callbackOverruns = static_cast<std::size_t>(state.callbackOverruns.load());
        report.drained = static_cast<std::size_t>(state.drained.load());
        // Closing frees the consumer name.
        state.releaseName();
        return Outcome<CloseReport>::success(report);
    }

    bool Client::valid() const noexcept
    {
        return m_state != nullptr;
    }
} // namespace indexer_client
