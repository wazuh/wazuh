/*
 * Wazuh inventory sync server module
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVSYNC_VD_SERVER_SCAN_COORDINATOR_HPP
#define _INVSYNC_VD_SERVER_SCAN_COORDINATOR_HPP

#include "vd/agentInFlightRegistry.hpp"

#include "vulnerabilityScannerSync.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <utility>

namespace invsync::vd
{

    /**
     * @brief This server's side of the vulnerability scanner's NEUTRAL coordination boundary.
     *
     * The design's simplification (doc 06 §5) made concrete: with the scan synchronous, "session
     * in flight" and "scan in flight" are the same thing, so the only question the scanner's feed
     * update asks -- fence this agent and wait for it to go quiet -- is answered from the shared
     * agent registry alone. No session table, no ghost state between response and scan.
     */
    class ServerScanCoordinator final : public vd_sync::IScanCoordinator
    {
    public:
        /// @param pauseQuiesceTimeout How long pauseAgent() waits for the agent's in-flight work
        ///        to drain before giving up (tests shrink it; production keeps the default).
        ServerScanCoordinator(std::shared_ptr<AgentInFlightRegistry> registry,
                              std::chrono::seconds pauseQuiesceTimeout = std::chrono::seconds {30})
            : m_registry {std::move(registry)}
            , m_pauseQuiesceTimeout {pauseQuiesceTimeout}
        {
        }

        bool
        pauseAgent(const std::string& agentId, const std::string& /*reason*/, const std::atomic<bool>* cancel) override
        {
            m_registry->pause(agentId);
            // Fenced means QUIESCED: whatever was already being applied must finish first. The
            // bound keeps a scan-length wait from stalling the whole fleet pass; on timeout the
            // fence comes off and the caller skips this agent. The wait goes in short slices so a
            // scanner that is stopping (cancel raised) is not held for the whole bound:
            // nothing notifies the registry's condition variable when cancel is raised.
            //
            // The caller's OWN scan-lane hold is not "in flight": an on-demand rescan reaches this
            // fence from the very lane worker that holds the agent, and that hold already keeps
            // every pipeline session of the agent out. Counting it made every on-demand scan wait
            // the whole bound for itself. Another thread's hold is still waited for.
            const auto deadline = std::chrono::steady_clock::now() + m_pauseQuiesceTimeout;
            while (cancel == nullptr || !cancel->load(std::memory_order_acquire))
            {
                const auto remaining =
                    std::chrono::ceil<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
                const auto slice = std::clamp(remaining, std::chrono::milliseconds::zero(), QUIESCE_SLICE);
                if (m_registry->waitUntilIdle(agentId, slice, /*ignoreCallersScanHold=*/true))
                {
                    return true;
                }
                if (std::chrono::steady_clock::now() >= deadline)
                {
                    break;
                }
            }
            m_registry->resume(agentId);
            return false;
        }

        void resumeAgent(const std::string& agentId) override
        {
            m_registry->resume(agentId);
        }

    private:
        /// Longest single wait between two looks at the caller's cancel flag.
        static constexpr std::chrono::milliseconds QUIESCE_SLICE {50};

        std::shared_ptr<AgentInFlightRegistry> m_registry;
        std::chrono::seconds m_pauseQuiesceTimeout;
    };

} // namespace invsync::vd

#endif // _INVSYNC_VD_SERVER_SCAN_COORDINATOR_HPP
