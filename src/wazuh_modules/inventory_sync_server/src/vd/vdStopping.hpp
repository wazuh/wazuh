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
#include <stdexcept>

namespace invsync::vd
{

    /**
     * @brief Whether the vulnerability scanner is stopping or stopped.
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
     * @brief Verdict of an on-demand scan (`scanAgent()`), pure.
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

    /// The four facade flags vdStopping() decides on, read once.
    struct VdGate
    {
        bool started {false};
        bool initialized {false};
        bool enabled {false};
        bool startFailed {false};
    };

    /**
     * @brief Reads the gate's flags off @p state in the order the decision needs.
     *
     * hasStarted() first: its acquire load orders the other reads after it; isInitialized() next, so a stop() that
     * lowers it between the two reads is seen as stopping, never as a legitimate skip. Sequenced statements, not
     * sibling call arguments, whose evaluation order is unspecified.
     *
     * @tparam TState VulnerabilityScannerFacade in production; a recording fake in the unit tests.
     */
    template<typename TState>
    VdGate readVdGate(const TState& state)
    {
        VdGate gate;
        gate.started = state.hasStarted();
        gate.initialized = state.isInitialized();
        gate.enabled = state.isEnabled();
        gate.startFailed = state.startFailed();
        return gate;
    }

    /// @throws std::runtime_error when @p gate says the scanner is stopping: the session fails (500, the
    ///         agent retries) instead of being indexed unscanned.
    inline void throwIfVdStopping(const VdGate& gate)
    {
        if (vdStopping(gate.started, gate.enabled, gate.startFailed, gate.initialized))
        {
            throw std::runtime_error("VD stopping");
        }
    }

    /**
     * @brief The gate of a session's scan(): throws when stopping, else whether the scanner runs here.
     *
     * @return The `initialized` read by readVdGate() (never a second read): false means Skipped.
     */
    template<typename TState>
    bool scanGate(const TState& state)
    {
        const auto gate = readVdGate(state);
        throwIfVdStopping(gate);
        return gate.initialized;
    }

} // namespace invsync::vd

#endif // _INVSYNC_VD_VD_STOPPING_HPP
