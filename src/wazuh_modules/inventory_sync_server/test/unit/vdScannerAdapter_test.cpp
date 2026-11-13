/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// Pins VdScannerAdapter::feedReady()'s gate via its two extracted pure decisions, vdWillRunHere()
// and feedGateOpen() -- the adapter itself talks to the real VulnerabilityScannerFacade singleton,
// so this is the only seam this module can drive the gate through without a live facade.
#include "vd/vdScannerAdapter.hpp"
#include "vd/vdScannerFactory.hpp"

#include "sync/fullSessionValidator.hpp"
#include "testSessionBuilder.hpp"

#include <gtest/gtest.h>

#include <stdexcept>
#include <string>
#include <vector>

using invsync::vd::feedGateOpen;
using invsync::vd::vdWillRunHere;

TEST(VdWillRunHere, NeverStartedAndNotConfigured_False)
{
    EXPECT_FALSE(vdWillRunHere(/*started*/ false, /*enabled*/ false, /*configuredEnabled*/ false));
}

TEST(VdWillRunHere, NeverStartedButConfiguredEnabled_True)
{
    // The narrow window before wm_vulnerability_scanner's start() has even begun: this node's OWN
    // configuration already says VD will run here, so a session arriving now must not be treated
    // as "will never run here" -- it has to wait for the scanner, not skip past it.
    EXPECT_TRUE(vdWillRunHere(/*started*/ false, /*enabled*/ false, /*configuredEnabled*/ true));
}

TEST(VdWillRunHere, StartedButDisabled_IgnoresConfiguredEnabled)
{
    // Once started() is true, the scanner's own isEnabled() is authoritative -- configuredEnabled
    // was only ever a stand-in for the window before that.
    EXPECT_FALSE(vdWillRunHere(/*started*/ true, /*enabled*/ false, /*configuredEnabled*/ true));
}

TEST(VdWillRunHere, StartedAndEnabled_IgnoresConfiguredEnabled)
{
    EXPECT_TRUE(vdWillRunHere(/*started*/ true, /*enabled*/ true, /*configuredEnabled*/ false));
}

TEST(FeedGateOpen, NeverStartedAndNotConfigured_OpensGate)
{
    EXPECT_TRUE(feedGateOpen(/*willRunHere*/ false,
                             /*startFailed*/ false,
                             /*initialized*/ false,
                             /*feedReady*/ false));
}

TEST(FeedGateOpen, StartFailed_OpensGateEvenIfEnabled)
{
    EXPECT_TRUE(feedGateOpen(/*willRunHere*/ true,
                             /*startFailed*/ true,
                             /*initialized*/ false,
                             /*feedReady*/ false));
}

TEST(FeedGateOpen, EnabledStillStarting_Defers)
{
    EXPECT_FALSE(feedGateOpen(/*willRunHere*/ true,
                              /*startFailed*/ false,
                              /*initialized*/ false,
                              /*feedReady*/ false));
}

TEST(FeedGateOpen, InitializedButFeedNotReady_Defers)
{
    EXPECT_FALSE(feedGateOpen(/*willRunHere*/ true,
                              /*startFailed*/ false,
                              /*initialized*/ true,
                              /*feedReady*/ false));
}

TEST(FeedGateOpen, InitializedAndFeedReady_Passes)
{
    EXPECT_TRUE(feedGateOpen(/*willRunHere*/ true,
                             /*startFailed*/ false,
                             /*initialized*/ true,
                             /*feedReady*/ true));
}

namespace
{
    /// The facade's surface the adapter touches, with state the test sets. BasicVdScannerAdapter<> runs its REAL
    /// body over it (the adapter's only other collaborator in production is the VulnerabilityScannerFacade singleton).
    struct FakeFacade
    {
        enum class ScanTriggerResult
        {
            Success,
            NotInitialized,
            FeedNotReady,
            ScannerNotReady,
            IndexerUnavailable,
            AgentNotFound,
            ScanFailed
        };

        bool started {false};
        bool initialized {false};
        bool enabled {true};
        bool failed {false};
        bool runResult {true};
        mutable int runCalls {0};

        static FakeFacade& instance()
        {
            static FakeFacade facade;
            return facade;
        }

        static void reset()
        {
            instance() = FakeFacade {};
        }

        bool hasStarted() const
        {
            return started;
        }
        bool isInitialized() const
        {
            return initialized;
        }
        bool isEnabled() const
        {
            return enabled;
        }
        bool startFailed() const
        {
            return failed;
        }
        bool isFeedReady() const
        {
            return true;
        }
        std::uint64_t currentFeedOffset() const
        {
            return 0;
        }
        bool runScannerFromViews(const vd_sync::SessionInfoView&, const std::vector<vd_sync::SyncItemView>&) const
        {
            ++runCalls;
            return runResult;
        }
        ScanTriggerResult triggerAgentScan(const std::string&) const
        {
            return ScanTriggerResult::Success;
        }
    };

    /// The raw bytes must outlive the ValidatedSession (it points into them).
    struct VdSessionFixture
    {
        std::string body;
        invsync::sync::ValidatedSession session;

        VdSessionFixture()
        {
            invsync::test::SessionSpec spec;
            spec.option = invsync::test::fb::Option_VDFirst;
            invsync::test::ValueSpec value;
            value.id = "doc-1";
            body = invsync::test::buildSyncDataSession(spec, {value});
            auto result = invsync::sync::validateFullSession(body, "001", "test-cluster");
            auto* validated = std::get_if<invsync::sync::ValidatedSession>(&result);
            if (validated == nullptr)
            {
                throw std::runtime_error {"test session failed validation"};
            }
            session = *validated;
        }
    };

    class VdScannerAdapterScan : public ::testing::Test
    {
    protected:
        void SetUp() override
        {
            FakeFacade::reset();
        }

        VdSessionFixture m_fixture;
        invsync::vd::BasicVdScannerAdapter<FakeFacade> m_adapter {true};
    };
} // namespace

// Runs the adapter's own scan(), so removing or inverting its scanGate() call fails these: the gate is the one
// thing that turns a stopping scanner into a failed session (retried) instead of an inventory indexed unscanned.
TEST_F(VdScannerAdapterScan, StoppingScanner_ThrowsAndNeverScans)
{
    auto& facade = FakeFacade::instance();
    facade.started = true;
    facade.enabled = true;
    facade.failed = false;
    facade.initialized = false; // started, enabled, not failed, no longer initialized: stopping

    EXPECT_THROW(m_adapter.scan(m_fixture.session), std::runtime_error);
    EXPECT_EQ(facade.runCalls, 0);
}

TEST_F(VdScannerAdapterScan, ScannerThatNeverRuns_SkippedWithoutScanning)
{
    auto& facade = FakeFacade::instance();
    facade.started = true;
    facade.enabled = false; // ran and found VD disabled
    facade.initialized = false;

    EXPECT_EQ(m_adapter.scan(m_fixture.session), invsync::vd::ScanVerdict::Skipped);
    EXPECT_EQ(facade.runCalls, 0);
}

TEST_F(VdScannerAdapterScan, InitializedScanner_ScansAndReportsTheOutcome)
{
    auto& facade = FakeFacade::instance();
    facade.started = true;
    facade.initialized = true;

    EXPECT_EQ(m_adapter.scan(m_fixture.session), invsync::vd::ScanVerdict::Ok);
    EXPECT_EQ(facade.runCalls, 1);

    facade.runResult = false; // the scanner's own legitimate skip
    EXPECT_EQ(m_adapter.scan(m_fixture.session), invsync::vd::ScanVerdict::Skipped);
    EXPECT_EQ(facade.runCalls, 2);
}
