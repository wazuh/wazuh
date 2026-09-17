/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// Pins VdScannerAdapter::feedReady()'s gate via its extracted pure decision,
// feedGateOpen() -- the adapter itself talks to the real VulnerabilityScannerFacade singleton, so
// this is the only seam this module can drive the gate through without a live facade.
#include "vd/vdScannerFactory.hpp"

#include <gtest/gtest.h>

using invsync::vd::feedGateOpen;

TEST(FeedGateOpen, NeverStartedAndNotConfigured_OpensGate)
{
    EXPECT_TRUE(feedGateOpen(/*started*/ false,
                             /*enabled*/ false,
                             /*startFailed*/ false,
                             /*initialized*/ false,
                             /*feedReady*/ false,
                             /*configuredEnabled*/ false));
}

TEST(FeedGateOpen, NeverStartedButConfiguredEnabled_Defers)
{
    // The narrow window before wm_vulnerability_scanner's start() has even begun: this node's OWN
    // configuration already says VD will run here, so a session arriving now must not be treated
    // as "will never run here" -- it has to wait for the scanner, not skip past it.
    EXPECT_FALSE(feedGateOpen(/*started*/ false,
                              /*enabled*/ false,
                              /*startFailed*/ false,
                              /*initialized*/ false,
                              /*feedReady*/ false,
                              /*configuredEnabled*/ true));
}

TEST(FeedGateOpen, StartedButDisabled_OpensGateRegardlessOfConfiguredEnabled)
{
    // Once started() is true, the scanner's own isEnabled() is authoritative -- configuredEnabled
    // was only ever a stand-in for the window before that.
    EXPECT_TRUE(feedGateOpen(/*started*/ true,
                             /*enabled*/ false,
                             /*startFailed*/ false,
                             /*initialized*/ false,
                             /*feedReady*/ false,
                             /*configuredEnabled*/ true));
}

TEST(FeedGateOpen, StartFailed_OpensGateEvenIfEnabled)
{
    EXPECT_TRUE(feedGateOpen(/*started*/ true,
                             /*enabled*/ true,
                             /*startFailed*/ true,
                             /*initialized*/ false,
                             /*feedReady*/ false,
                             /*configuredEnabled*/ false));
}

TEST(FeedGateOpen, EnabledStillStarting_Defers)
{
    EXPECT_FALSE(feedGateOpen(/*started*/ true,
                              /*enabled*/ true,
                              /*startFailed*/ false,
                              /*initialized*/ false,
                              /*feedReady*/ false,
                              /*configuredEnabled*/ false));
}

TEST(FeedGateOpen, InitializedButFeedNotReady_Defers)
{
    EXPECT_FALSE(feedGateOpen(/*started*/ true,
                              /*enabled*/ true,
                              /*startFailed*/ false,
                              /*initialized*/ true,
                              /*feedReady*/ false,
                              /*configuredEnabled*/ false));
}

TEST(FeedGateOpen, InitializedAndFeedReady_Passes)
{
    EXPECT_TRUE(feedGateOpen(/*started*/ true,
                             /*enabled*/ true,
                             /*startFailed*/ false,
                             /*initialized*/ true,
                             /*feedReady*/ true,
                             /*configuredEnabled*/ false));
}
