/*
 * Wazuh inventory sync server module
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVSYNC_VD_VD_STOPPING_HPP
#define _INVSYNC_VD_VD_STOPPING_HPP

#include "vd/IVdScanner.hpp"

#include <functional>

namespace invsync::vd
{

    /**
     * @brief Whether the vulnerability scanner is stopping or stopped (I167c).
     *
     * Pure, next to feedGateOpen(), so the decision is pinned by a unit test without a live
     * VulnerabilityScannerFacade. A scanner that ran here (started, enabled, its start() did not
     * fail) and is no longer initialized is going away: VulnerabilityScannerFacade::stop() lowers
     * isInitialized() first. The scanner's own startup window has the same inputs, but neither
     * caller reaches it: the lane's feedReady() gate defers a session or an on-demand scan with a
     * retryable 503 until the scanner is initialized.
     *
     * @param started Facade's hasStarted().
     * @param enabled Facade's isEnabled().
     * @param startFailed Facade's startFailed().
     * @param initialized Facade's isInitialized().
     * @return true when a scan must not be treated as a legitimate skip.
     */
    bool vdStopping(bool started, bool enabled, bool startFailed, bool initialized);

    /**
     * @brief Verdict of an on-demand scan (`scanAgent()`), pure (I167c).
     *
     * A stopping scanner answers NotReady (503, the task retries) rather than throwing: the lane's
     * caller of scanAgent() has no `try` (vdScanLane.cpp). A scanner that never runs here (not
     * initialized, not stopping) is Skipped. Otherwise @p scan runs and its outcome is the verdict;
     * it is never called in the other two cases.
     *
     * @param stopping vdStopping()'s result.
     * @param initialized Facade's isInitialized(), read once with the same snapshot as @p stopping.
     * @param scan Runs the scan and translates its result.
     */
    AgentScanOutcome onDemandVerdict(bool stopping, bool initialized, const std::function<AgentScanOutcome()>& scan);

} // namespace invsync::vd

#endif // _INVSYNC_VD_VD_STOPPING_HPP
