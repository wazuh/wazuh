/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// Pins VdScannerAdapter::feedReady()'s gate via its two extracted pure decisions, vdWillRunHere()
// and feedGateOpen() -- the adapter itself talks to the real VulnerabilityScannerFacade singleton,
// so this is the only seam this module can drive the gate through without a live facade.
#include "vd/vdScannerFactory.hpp"

#include <gtest/gtest.h>

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

TEST(FeedGateOpen, NeverStartedButConfiguredEnabled_Defers)
{
    EXPECT_FALSE(feedGateOpen(/*willRunHere*/ true,
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
