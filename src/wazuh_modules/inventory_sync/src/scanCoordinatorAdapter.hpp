/*
 * Wazuh inventory sync
 * Copyright (C) 2015, Wazuh Inc.
 * August 5, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVENTORY_SYNC_SCAN_COORDINATOR_ADAPTER_HPP
#define _INVENTORY_SYNC_SCAN_COORDINATOR_ADAPTER_HPP

#include "inventorySyncFacade.hpp"
#include "vulnerabilityScannerSync.hpp"

#include <algorithm>
#include <chrono>
#include <string>
#include <unordered_set>

/**
 * @brief This module's side of the vulnerability scanner's NEUTRAL coordination boundary.
 *
 * The scanner used to call InventorySyncFacade::instance() directly (five call sites); those now
 * go through vd_sync::ScanCoordinatorRegistry, and this adapter -- registered by
 * inventory_sync_start() and removed by inventory_sync_stop() -- answers them over the facade's
 * existing session/lock machinery. Behavior-preserving by construction: each method delegates to
 * the exact facade method the scanner used to call, with the legacy (timeout, retries) shape
 * rebuilt from the single total the neutral interface carries.
 */
class InventorySyncScanCoordinatorAdapter final : public vd_sync::IScanCoordinator
{
    /// The legacy call sites polled in 60-second slices; keep that granularity.
    static constexpr auto LEGACY_SLICE = std::chrono::seconds(60);

    static std::uint32_t retriesFor(std::chrono::seconds timeout)
    {
        const auto retries = timeout.count() / LEGACY_SLICE.count();
        return retries > 0 ? static_cast<std::uint32_t>(retries) : 1U;
    }

public:
    std::unordered_set<std::string> agentsWithActiveVDFirstSessions() const override
    {
        return InventorySyncFacade::instance().getAgentsWithActiveSessionForModule("syscollector_vd",
                                                                                   Wazuh::SyncSchema::Option_VDFirst);
    }

    bool waitForVDSyncSessionsToDrain(std::chrono::seconds timeout) override
    {
        return InventorySyncFacade::instance().waitForAllVDSyncSessions(LEGACY_SLICE, retriesFor(timeout));
    }

    bool hasActiveSessionForAgent(const std::string& agentId, std::chrono::seconds timeout) override
    {
        return InventorySyncFacade::instance().hasActiveSessionForModule(
            agentId, "syscollector_vd", LEGACY_SLICE, retriesFor(timeout));
    }

    bool pauseAgent(const std::string& agentId, const std::string& reason) override
    {
        return InventorySyncFacade::instance().lockAgent(agentId, reason);
    }

    void resumeAgent(const std::string& agentId) override
    {
        InventorySyncFacade::instance().unlockAgent(agentId);
    }
};

#endif // _INVENTORY_SYNC_SCAN_COORDINATOR_ADAPTER_HPP
