/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// Pins the two pure decisions of a stopping vulnerability scanner: vdStopping(), the predicate the
// adapter evaluates over the facade's four flags, and onDemandVerdict(), what an on-demand scan answers from it. Like
// feedGateOpen(), they are driven without a live VulnerabilityScannerFacade.

#include "vd/vdStopping.hpp"

#include <gtest/gtest.h>

#include <initializer_list>
#include <stdexcept>
#include <string>
#include <vector>

using invsync::vd::AgentScanOutcome;
using invsync::vd::onDemandVerdict;
using invsync::vd::vdStopping;

// Every combination of the four inputs: the scanner is stopping only when it ran here (started, enabled, its start()
// did not fail) and is no longer initialized.
TEST(VdStopping, Table)
{
    for (const bool started : {false, true})
    {
        for (const bool enabled : {false, true})
        {
            for (const bool startFailed : {false, true})
            {
                for (const bool initialized : {false, true})
                {
                    const bool expected = started && enabled && !startFailed && !initialized;
                    EXPECT_EQ(vdStopping(started, enabled, startFailed, initialized), expected)
                        << "started=" << started << " enabled=" << enabled << " startFailed=" << startFailed
                        << " initialized=" << initialized;
                }
            }
        }
    }
}

// The named rows the table is made of, so a failure reads as a sentence.
TEST(VdStopping, NamedRows)
{
    // Running: not stopping.
    EXPECT_FALSE(vdStopping(true, true, false, true));
    // Stop() lowered isInitialized() first: stopping.
    EXPECT_TRUE(vdStopping(true, true, false, false));
    // Never started here (a harness, or the window before start()): not stopping, the lane's feed gate handles it.
    EXPECT_FALSE(vdStopping(false, true, false, false));
    // Disabled: it never runs here, so it never stops here.
    EXPECT_FALSE(vdStopping(true, false, false, false));
    // A start() that failed outright: nothing to stop.
    EXPECT_FALSE(vdStopping(true, true, true, false));
}

// The on-demand verdict: a stopping scanner is NotReady (503: the task retries, and the caller has no `try`); one that
// never runs here is Skipped; otherwise the scan runs and its outcome is the verdict.
TEST(VdStopping, OnDemandVerdictTable)
{
    for (const bool stopping : {false, true})
    {
        for (const bool initialized : {false, true})
        {
            for (const auto outcome : {AgentScanOutcome::Ok,
                                       AgentScanOutcome::Skipped,
                                       AgentScanOutcome::NotReady,
                                       AgentScanOutcome::NotFound,
                                       AgentScanOutcome::Failed})
            {
                int calls = 0;
                const auto verdict = onDemandVerdict(stopping,
                                                     initialized,
                                                     [&]
                                                     {
                                                         ++calls;
                                                         return outcome;
                                                     });

                if (stopping)
                {
                    // Whatever `initialized` says (a stopping scanner is not initialized by definition), the scan is
                    // not run and the answer is retryable.
                    EXPECT_EQ(verdict, AgentScanOutcome::NotReady) << "initialized=" << initialized;
                    EXPECT_EQ(calls, 0);
                }
                else if (!initialized)
                {
                    EXPECT_EQ(verdict, AgentScanOutcome::Skipped);
                    EXPECT_EQ(calls, 0);
                }
                else
                {
                    EXPECT_EQ(verdict, outcome);
                    EXPECT_EQ(calls, 1);
                }
            }
        }
    }
}

// The verdict never throws: the lane's caller of scanAgent() has no `try`, so a scan that does throw is the scan's own
// business and propagates unchanged only when the scanner is running.
TEST(VdStopping, OnDemandVerdictDoesNotCallTheScanOfAStoppingScanner)
{
    const auto throwing = []() -> AgentScanOutcome
    {
        throw std::runtime_error("must not be called");
    };
    EXPECT_NO_THROW(EXPECT_EQ(onDemandVerdict(true, false, throwing), AgentScanOutcome::NotReady));
    EXPECT_NO_THROW(EXPECT_EQ(onDemandVerdict(false, false, throwing), AgentScanOutcome::Skipped));
    EXPECT_THROW(onDemandVerdict(false, true, throwing), std::runtime_error);
}

// ---- The adapter's wiring of vdStopping(), through readVdGate()/throwIfVdStopping()/scanGate() over a fake
// facade that records its reads. Mutants: arguments permuted (started/initialized; swapping started/enabled or
// startFailed/initialized is equivalent), the throw removed, the read order changed, `initialized` read twice.

namespace
{
    /// The four facade flags, with a log of the reads in the order they happened.
    struct RecordingState
    {
        bool started {false};
        bool enabled {false};
        bool failed {false};
        bool initialized {false};
        mutable std::vector<std::string> reads;

        bool hasStarted() const
        {
            reads.emplace_back("hasStarted");
            return started;
        }
        bool isInitialized() const
        {
            reads.emplace_back("isInitialized");
            return initialized;
        }
        bool isEnabled() const
        {
            reads.emplace_back("isEnabled");
            return enabled;
        }
        bool startFailed() const
        {
            reads.emplace_back("startFailed");
            return failed;
        }
    };

    const std::vector<std::string> EXPECTED_READS {"hasStarted", "isInitialized", "isEnabled", "startFailed"};

    /// Every combination of the four flags.
    std::vector<RecordingState> everyState()
    {
        std::vector<RecordingState> states;
        for (int bits = 0; bits < 16; ++bits)
        {
            RecordingState state;
            state.started = (bits & 1) != 0;
            state.enabled = (bits & 2) != 0;
            state.failed = (bits & 4) != 0;
            state.initialized = (bits & 8) != 0;
            states.push_back(state);
        }
        return states;
    }

    std::string describe(const RecordingState& state)
    {
        return "started=" + std::to_string(state.started) + " enabled=" + std::to_string(state.enabled) +
               " startFailed=" + std::to_string(state.failed) + " initialized=" + std::to_string(state.initialized);
    }
} // namespace

TEST(VdStoppingGateTest, ReadsEachFlagOnceInOrder)
{
    for (const auto& state : everyState())
    {
        state.reads.clear();
        const auto gate = invsync::vd::readVdGate(state);
        EXPECT_EQ(EXPECTED_READS, state.reads) << describe(state);
        EXPECT_EQ(state.started, gate.started) << describe(state);
        EXPECT_EQ(state.enabled, gate.enabled) << describe(state);
        EXPECT_EQ(state.failed, gate.startFailed) << describe(state);
        EXPECT_EQ(state.initialized, gate.initialized) << describe(state);
    }
}

TEST(VdStoppingGateTest, ThrowsOnlyWhenStopping)
{
    for (const auto& state : everyState())
    {
        invsync::vd::VdGate gate;
        gate.started = state.started;
        gate.enabled = state.enabled;
        gate.startFailed = state.failed;
        gate.initialized = state.initialized;
        if (vdStopping(state.started, state.enabled, state.failed, state.initialized))
        {
            EXPECT_THROW(invsync::vd::throwIfVdStopping(gate), std::runtime_error) << describe(state);
        }
        else
        {
            EXPECT_NO_THROW(invsync::vd::throwIfVdStopping(gate)) << describe(state);
        }
    }
}

// scan()'s gate: throws when stopping, else Skipped exactly when not initialized, with one read of each flag.
TEST(VdStoppingGateTest, ScanGate)
{
    for (const auto& state : everyState())
    {
        state.reads.clear();
        if (vdStopping(state.started, state.enabled, state.failed, state.initialized))
        {
            EXPECT_THROW(invsync::vd::scanGate(state), std::runtime_error) << describe(state);
        }
        else
        {
            EXPECT_EQ(state.initialized, invsync::vd::scanGate(state)) << describe(state);
        }
        EXPECT_EQ(EXPECTED_READS, state.reads) << describe(state) << ": a flag read twice, or out of order";
    }
}

// The race the order exists for: stop() lowers isInitialized() right after hasStarted() was read. Read in the real
// order, the session is failed as stopping; were `initialized` read first (still true), it would be scanned.
TEST(VdStoppingGateTest, StopBetweenTheReadsIsStopping)
{
    struct StoppingDuringRead : RecordingState
    {
        bool hasStarted() const
        {
            const auto result = RecordingState::hasStarted();
            stopped = true;
            return result;
        }
        bool isInitialized() const
        {
            reads.emplace_back("isInitialized");
            return !stopped;
        }
        mutable bool stopped {false};
    };

    StoppingDuringRead state;
    state.started = true;
    state.enabled = true;
    EXPECT_THROW(invsync::vd::scanGate(state), std::runtime_error);
}
