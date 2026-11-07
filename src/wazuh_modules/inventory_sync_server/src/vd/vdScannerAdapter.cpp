/*
 * Wazuh inventory sync server module
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "vd/vdScannerAdapter.hpp"
#include "vd/vdScannerFactory.hpp"
#include "vd/vdStopping.hpp"

#include "vulnerabilityScannerFacade.hpp"
#include "vulnerabilityScannerSync.hpp"

#include <functional>
#include <string_view>
#include <vector>

namespace invsync::vd
{

    bool vdWillRunHere(bool started, bool enabled, bool configuredEnabled)
    {
        return started ? enabled : configuredEnabled;
    }

    bool feedGateOpen(bool willRunHere, bool startFailed, bool initialized, bool feedReady)
    {
        if (!willRunHere || startFailed)
        {
            return true;
        }
        return initialized && feedReady;
    }

    bool vdStopping(bool started, bool enabled, bool startFailed, bool initialized)
    {
        return started && enabled && !startFailed && !initialized;
    }

    AgentScanOutcome onDemandVerdict(bool stopping, bool initialized, const std::function<AgentScanOutcome()>& scan)
    {
        if (stopping)
        {
            return AgentScanOutcome::NotReady;
        }
        if (!initialized)
        {
            return AgentScanOutcome::Skipped;
        }
        return scan();
    }

    using VdScannerAdapter = BasicVdScannerAdapter<VulnerabilityScannerFacade>;

    std::shared_ptr<IVdScanner> makeProductionVdScanner(bool vdConfiguredEnabled)
    {
        return std::make_shared<VdScannerAdapter>(vdConfiguredEnabled);
    }

} // namespace invsync::vd
