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

#ifndef _INVSYNC_VD_SERVER_SCAN_COORDINATOR_HPP
#define _INVSYNC_VD_SERVER_SCAN_COORDINATOR_HPP

#include "vd/agentInFlightRegistry.hpp"
#include "vd/vdScanLane.hpp"

#include "vulnerabilityScannerSync.hpp"

#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <utility>

namespace invsync::vd
{

    /**
     * @brief This server's side of the vulnerability scanner's NEUTRAL coordination boundary.
     *
     * The design's simplification (doc 06 §5) made concrete: with the scan synchronous, "session
     * in flight" and "scan in flight" are the same thing, so every question the scanner's feed
     * update asks is answered from the shared agent registry plus the lane's short queue -- no
     * session table, no ghost state between response and scan.
     *
     * The lane is held WEAKLY: the facade's stop() removes this coordinator from the scanner's
     * registry before tearing the lane down, but a scanner call already past the registry snapshot
     * may still land here, and it must degrade to "no sessions" instead of touching a dead lane.
     */
    class ServerScanCoordinator final : public vd_sync::IScanCoordinator
    {
    public:
        /// @param pauseQuiesceTimeout How long pauseAgent() waits for the agent's in-flight work
        ///        to drain before giving up (tests shrink it; production keeps the default).
        ServerScanCoordinator(std::shared_ptr<AgentInFlightRegistry> registry,
                              std::weak_ptr<VdScanLane> lane,
                              std::chrono::seconds pauseQuiesceTimeout = std::chrono::seconds {30})
            : m_registry {std::move(registry)}
            , m_lane {std::move(lane)}
            , m_pauseQuiesceTimeout {pauseQuiesceTimeout}
        {
        }

        bool hasActiveSessionForAgent(const std::string& agentId, std::chrono::seconds timeout) override
        {
            // Active = being applied (registry) OR still waiting in the lane's queue (the registry
            // cannot see queued items -- they acquire only at dispatch). Poll: the two signals live
            // behind different locks and the legacy behavior was a bounded poll too.
            const auto deadline = std::chrono::steady_clock::now() + timeout;
            while (true)
            {
                const auto lane = m_lane.lock();
                const bool queued = lane && lane->hasAgentQueued(agentId);
                if (!queued && m_registry->isFree(agentId))
                {
                    return false;
                }
                if (std::chrono::steady_clock::now() >= deadline)
                {
                    return true;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds {100});
            }
        }

        bool pauseAgent(const std::string& agentId, const std::string& /*reason*/) override
        {
            m_registry->pause(agentId);
            // Fenced means QUIESCED: whatever was already being applied must finish first. The
            // bound keeps a scan-length wait from stalling the whole fleet pass; on timeout the
            // fence comes off and the caller skips this agent.
            if (!m_registry->waitUntilIdle(agentId, m_pauseQuiesceTimeout))
            {
                m_registry->resume(agentId);
                return false;
            }
            return true;
        }

        void resumeAgent(const std::string& agentId) override
        {
            m_registry->resume(agentId);
        }

    private:
        std::shared_ptr<AgentInFlightRegistry> m_registry;
        std::weak_ptr<VdScanLane> m_lane;
        std::chrono::seconds m_pauseQuiesceTimeout;
    };

} // namespace invsync::vd

#endif // _INVSYNC_VD_SERVER_SCAN_COORDINATOR_HPP
