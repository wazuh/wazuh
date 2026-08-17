/*
 * Wazuh inventory sync server module
 * Copyright (C) 2015, Wazuh Inc.
 * August 5, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVSYNC_VD_AGENT_IN_FLIGHT_REGISTRY_HPP
#define _INVSYNC_VD_AGENT_IN_FLIGHT_REGISTRY_HPP

#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

namespace invsync::vd
{

    /**
     * @brief The shared per-agent exclusion between the sync pipeline and the VD scan lane (D22).
     *
     * One agent may have at most ONE session being APPLIED at a time, whichever lane it is on:
     * the pipeline skips (leaves queued) items of an agent whose scan is in flight, and the scan
     * lane does not dispatch an agent the pipeline is mid-applying. This is what keeps
     * delete-then-reindex and checksum-after-delta correct when a VD session rides between them,
     * and it replaces the legacy `m_activeVDFirstScans` dedup: two VDFirst of the same agent
     * serialize on the registry instead of one being dropped.
     *
     * `pause`/`resume` are the IScanCoordinator hooks VD's feed update uses to fence an agent
     * out of dispatch entirely (both lanes treat a paused agent as busy).
     *
     * Lock-per-call, no lock held while running callbacks: `release`/`resume` notify AFTER
     * dropping the mutex so a woken worker can re-acquire immediately.
     */
    class AgentInFlightRegistry final
    {
    public:
        enum class Lane
        {
            Pipeline,
            Scan
        };

        /**
         * @brief Try to mark @p agentId as being applied by @p lane.
         *
         * @param reentrant When true, a SECOND acquisition by the SAME lane is allowed
         *                  (refcounted). The pipeline needs this: with group commit, several
         *                  staged-but-unanswered sessions of one agent coexist on its (single,
         *                  sharded) worker, and each holds the agent until its own response. The
         *                  scan lane passes false -- at most one scan per agent in flight, which
         *                  is the legacy `m_activeVDFirstScans` dedup done right.
         *
         * @return false when the agent is paused, or held by the OTHER lane, or held by the same
         *         lane with @p reentrant false.
         */
        bool tryAcquire(const std::string& agentId, Lane lane, bool reentrant)
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_paused.count(agentId) != 0)
            {
                return false;
            }
            const auto it = m_inFlight.find(agentId);
            if (it == m_inFlight.end())
            {
                m_inFlight.emplace(agentId, Holder {lane, 1});
                return true;
            }
            if (it->second.lane != lane || !reentrant)
            {
                return false;
            }
            ++it->second.count;
            return true;
        }

        /**
         * @brief Undo ONE acquisition BY @p lane; the agent frees when the count reaches zero.
         *
         * Lane-checked so a caller that never acquired cannot damage the other lane's hold: the
         * pipeline's stop() drain answers QUEUED (never-acquired) items whose agent may be mid-scan,
         * and an unchecked decrement there would free the scan lane's exclusion under it.
         */
        void release(const std::string& agentId, Lane lane)
        {
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                const auto it = m_inFlight.find(agentId);
                if (it == m_inFlight.end() || it->second.lane != lane)
                {
                    return;
                }
                if (--it->second.count == 0)
                {
                    m_inFlight.erase(it);
                }
            }
            notifyWaiters();
        }

        /// @brief Whether @p agentId can be dispatched right now (not held, not paused).
        bool isFree(const std::string& agentId) const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_paused.count(agentId) == 0 && m_inFlight.count(agentId) == 0;
        }

        /// @brief Mirror of tryAcquire() WITHOUT acquiring -- for wait predicates. May go stale
        /// the moment the lock drops; the caller still needs the real tryAcquire() to dispatch.
        bool couldAcquire(const std::string& agentId, Lane lane, bool reentrant) const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_paused.count(agentId) != 0)
            {
                return false;
            }
            const auto it = m_inFlight.find(agentId);
            return it == m_inFlight.end() || (it->second.lane == lane && reentrant);
        }

        /// @brief Fence an agent out of BOTH lanes' dispatch (IScanCoordinator::pauseAgent).
        void pause(const std::string& agentId)
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_paused.insert(agentId);
        }

        void resume(const std::string& agentId)
        {
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_paused.erase(agentId);
            }
            notifyWaiters();
        }

        bool isPaused(const std::string& agentId) const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_paused.count(agentId) != 0;
        }

        /// @brief Block until @p agentId has nothing IN FLIGHT, or the deadline passes.
        ///
        /// Deliberately ignores the paused flag: the caller that pauses an agent then waits for
        /// its in-flight work to drain would otherwise wait on its own pause forever.
        /// @return true when the agent became idle.
        template<typename TRep, typename TPeriod>
        bool waitUntilIdle(const std::string& agentId, const std::chrono::duration<TRep, TPeriod>& timeout)
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            return m_freeCv.wait_for(lock, timeout, [this, &agentId] { return m_inFlight.count(agentId) == 0; });
        }

        /**
         * @brief Register a callback fired whenever an agent is released or resumed.
         *
         * The lanes park items of busy agents; this is how they learn "busy" may have ended
         * without polling. Called WITHOUT the registry mutex held. Registration happens at
         * construction time (facade gate), before any traffic.
         */
        void addReleaseListener(std::function<void()> listener)
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_listeners.push_back(std::move(listener));
        }

    private:
        void notifyWaiters()
        {
            m_freeCv.notify_all();
            std::vector<std::function<void()>> listeners;
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                listeners = m_listeners;
            }
            for (const auto& listener : listeners)
            {
                listener();
            }
        }

        struct Holder
        {
            Lane lane;
            std::size_t count;
        };

        mutable std::mutex m_mutex;
        std::condition_variable m_freeCv;
        std::unordered_map<std::string, Holder> m_inFlight;
        std::set<std::string> m_paused;
        std::vector<std::function<void()>> m_listeners;
    };

} // namespace invsync::vd

#endif // _INVSYNC_VD_AGENT_IN_FLIGHT_REGISTRY_HPP
