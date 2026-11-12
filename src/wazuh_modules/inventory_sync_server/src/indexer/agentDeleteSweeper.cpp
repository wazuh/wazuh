/*
 * Wazuh inventory sync server module
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "agentDeleteSweeper.hpp"

#include "loggerHelper.h"
#include "sync/stateIndexAllowlist.hpp" // AGENT_DELETION_SCOPE_BY_ID

#include <algorithm>
#include <exception>
#include <json.hpp>
#include <unordered_set>
#include <utility>
#include <vector>

namespace
{
    constexpr auto SWEEPER_LOGTAG {"wazuh-manager-modulesd:inventory-sync-server:indexer"};

    const LogFn& logFn()
    {
        static const LogFn instance {SWEEPER_LOGTAG};
        return instance;
    }
} // namespace

namespace invsync::indexer
{
    using Clock = std::chrono::steady_clock;

    AgentDeleteSweeper::AgentDeleteSweeper(std::shared_ptr<indexer_client::IQuery> query,
                                           std::chrono::milliseconds window,
                                           std::chrono::milliseconds deadline,
                                           std::shared_ptr<const std::atomic<bool>> closing)
        : m_query {std::move(query)}
        , m_window {window}
        , m_deadline {deadline}
        , m_closing {std::move(closing)}
    {
        // Last, once every member the thread reads is in place.
        m_thread = std::thread {&AgentDeleteSweeper::run, this};
    }

    AgentDeleteSweeper::~AgentDeleteSweeper()
    {
        stop();
    }

    void AgentDeleteSweeper::note(const std::string& agentId)
    {
        std::lock_guard lock {m_mutex};
        if (m_stopping)
        {
            // Nothing will sweep it any more: abandoned like what stop() found pending.
            ++m_stats.dropped;
            return;
        }
        m_pending.push_back(Pending {agentId, Clock::now(), false});
        updateTrackedLocked();
    }

    void AgentDeleteSweeper::forget(const std::string& agentId)
    {
        // Every /config and /stats write calls this: nothing pending (the usual case) costs no lock.
        if (m_tracked.load(std::memory_order_acquire) == 0)
        {
            return;
        }

        std::lock_guard lock {m_mutex};
        const auto before = m_pending.size();
        m_pending.erase(std::remove_if(m_pending.begin(),
                                       m_pending.end(),
                                       [&agentId](const Pending& pending) { return pending.agentId == agentId; }),
                        m_pending.end());
        bool withdrew {m_pending.size() != before};
        // The pass in progress reads this before each chunk it has not sent yet, and does not requeue the id.
        if (m_inPass.count(agentId) != 0 && m_forgottenInPass.insert(agentId).second)
        {
            withdrew = true;
        }
        if (withdrew)
        {
            ++m_stats.forgotten;
            updateTrackedLocked();
        }
    }

    void AgentDeleteSweeper::updateTrackedLocked()
    {
        m_tracked.store(m_pending.size() + m_inPass.size(), std::memory_order_release);
    }

    void AgentDeleteSweeper::stop()
    {
        {
            std::lock_guard lock {m_mutex};
            m_stopping = true;
        }
        m_cv.notify_all();

        if (m_thread.joinable() && m_thread.get_id() != std::this_thread::get_id())
        {
            m_thread.join();
        }

        std::lock_guard lock {m_mutex};
        m_stats.dropped += m_pending.size();
        m_pending.clear();
        updateTrackedLocked();
    }

    AgentDeleteSweeper::Stats AgentDeleteSweeper::stats() const
    {
        std::lock_guard lock {m_mutex};
        return m_stats;
    }

    void AgentDeleteSweeper::run()
    {
        std::unique_lock lock {m_mutex};
        auto nextTick = Clock::now() + m_window;

        while (!m_stopping)
        {
            if (m_cv.wait_until(lock, nextTick, [this]() { return m_stopping; }))
            {
                break;
            }

            // The tick: the next pass is due one window after this one starts (`now`, set below; the max keeps an
            // idle tick on its fixed cadence). A pass that outlasts the window (each delete-by-query may take up to
            // the deletion budget) is followed by the next one as soon as it ends: pass STARTS are never less than a
            // window apart (at most one pass per window, I146b).
            nextTick += m_window;
            const auto now = Clock::now();

            // The ids whose note() is at least one window old: by then a report that timed out before the delete
            // has either been applied or failed for good (window = request timeout + 5 s).
            std::vector<Pending> due;
            for (auto it = m_pending.begin(); it != m_pending.end();)
            {
                if (it->notedAt + m_window <= now)
                {
                    due.push_back(std::move(*it));
                    it = m_pending.erase(it);
                }
                else
                {
                    ++it;
                }
            }
            if (due.empty())
            {
                continue; // Nothing due: no delete-by-query, not a run.
            }
            ++m_stats.runs;
            for (const auto& pending : due)
            {
                m_inPass.insert(pending.agentId);
            }
            updateTrackedLocked();

            // The I/O runs without the lock, so note() never waits on the indexer.
            lock.unlock();

            std::uint64_t residual {0};
            std::uint64_t failures {0};
            std::unordered_set<std::size_t> failed; // Positions in `due` of the ids of a failed chunk, any index.
            std::vector<bool> withdrawn(due.size(), false); // forget() reached it before one of its chunks was sent.
            bool interrupted {false};

            for (const auto& index : invsync::sync::AGENT_DELETION_SCOPE_BY_ID)
            {
                // One delete-by-query PER INDEX: a missing index (a 404 the library answers as an empty success
                // for a delete-by-query) or a failure in one does not void the other.
                for (std::size_t first = 0; first < due.size() && !interrupted; first += MAX_IDS_PER_QUERY)
                {
                    if (m_closing && m_closing->load(std::memory_order_acquire))
                    {
                        interrupted = true;
                        break;
                    }

                    const auto last = std::min(due.size(), first + MAX_IDS_PER_QUERY);
                    auto ids = nlohmann::json::array();
                    {
                        // An id forget() withdrew belongs to an agent that reported again: its documents are the
                        // new agent's. Checked before EACH chunk, so a withdrawal between the two indices still
                        // spares the second one.
                        std::lock_guard withdrawals {m_mutex};
                        for (auto i = first; i < last; ++i)
                        {
                            if (!withdrawn[i] && m_forgottenInPass.count(due[i].agentId) != 0)
                            {
                                withdrawn[i] = true;
                            }
                            if (!withdrawn[i])
                            {
                                ids.push_back(due[i].agentId);
                            }
                        }
                    }
                    if (ids.empty())
                    {
                        continue; // Every id of the chunk was withdrawn: nothing to send.
                    }
                    nlohmann::json body;
                    body["query"]["terms"]["_id"] = std::move(ids);

                    bool ok {false};
                    std::string why;
                    try
                    {
                        // No refresh (P21: the indexer role may lack indices:admin/refresh), conflicts proceed: a
                        // document deleted meanwhile is not a failure. The default query retry policy applies.
                        const auto outcome = m_query->deleteByQuery({std::string {index}},
                                                                    body,
                                                                    indexer_client::DbqOptions {true},
                                                                    indexer_client::QueryOptions {},
                                                                    Clock::now() + m_deadline);
                        ok = outcome.ok();
                        if (ok)
                        {
                            residual += outcome.value.is_object() ? outcome.value.value("deleted", std::uint64_t {0})
                                                                  : std::uint64_t {0};
                        }
                        else
                        {
                            why = std::string {indexer_client::toString(outcome.cause)} +
                                  (outcome.reason.empty() ? "" : ": " + outcome.reason);
                        }
                    }
                    catch (const std::exception& e)
                    {
                        why = e.what();
                    }

                    if (!ok && m_closing && m_closing->load(std::memory_order_acquire))
                    {
                        // The module is stopping (requestClose() answers an in-flight query ClientClosed): not a
                        // failure of the sweep, and nothing will retry it. The ids go back and stop() drops them.
                        LOGFN_DEBUG1(logFn(),
                                     "Sweeping %zu deleted agent(s) from '%s' was cut by the module's stop (%s).",
                                     last - first,
                                     std::string {index}.c_str(),
                                     why.c_str());
                        interrupted = true;
                        break;
                    }
                    if (!ok)
                    {
                        ++failures;
                        for (auto i = first; i < last; ++i)
                        {
                            failed.insert(i);
                        }
                        LOGFN_WARN(logFn(),
                                   "Sweeping %zu deleted agent(s) from '%s' failed (%s); they are retried once on "
                                   "the next pass.",
                                   last - first,
                                   std::string {index}.c_str(),
                                   why.c_str());
                    }
                }
                if (interrupted)
                {
                    break;
                }
            }

            if (residual > 0)
            {
                LOGFN_DEBUG1(logFn(),
                             "The agent deletion sweep removed %llu document(s) written after their agent's deletion.",
                             static_cast<unsigned long long>(residual));
            }

            lock.lock();
            nextTick = std::max(nextTick, now + m_window);
            m_stats.residual += residual;
            m_stats.failures += failures;
            for (std::size_t i = 0; i < due.size(); ++i)
            {
                if (withdrawn[i] || m_forgottenInPass.count(due[i].agentId) != 0)
                {
                    // Withdrawn during the pass (before a chunk or after the last one): never retried.
                    continue;
                }
                if (failed.count(i) != 0)
                {
                    // An id counts once even if its chunks failed in both indices.
                    if (due[i].retried)
                    {
                        ++m_stats.dropped;
                    }
                    else
                    {
                        due[i].retried = true;
                        m_pending.push_back(std::move(due[i]));
                    }
                }
                else if (interrupted)
                {
                    // Closing cut the pass: not every index saw it. Back as it was; stop() counts it dropped.
                    m_pending.push_back(std::move(due[i]));
                }
            }
            m_inPass.clear();
            m_forgottenInPass.clear();
            updateTrackedLocked();
        }
    }

} // namespace invsync::indexer
