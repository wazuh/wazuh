/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// Pins the two pure decisions of a stopping vulnerability scanner (E8a, I167c): vdStopping(), the predicate the
// adapter evaluates over the facade's four flags, and onDemandVerdict(), what an on-demand scan answers from it. Like
// feedGateOpen(), they are driven without a live VulnerabilityScannerFacade.

#include "vd/vdStopping.hpp"

#include <gtest/gtest.h>

#include <initializer_list>

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
