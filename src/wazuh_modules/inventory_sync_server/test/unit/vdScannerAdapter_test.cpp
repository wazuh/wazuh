/*
 * Wazuh inventory sync server module - unit tests
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// Pins VdScannerAdapter::feedReady()'s gate via its extracted pure decision, feedGateOpen() -- the
// adapter itself talks to the real VulnerabilityScannerFacade singleton, so this is the only seam
// this module can drive the gate through without a live facade.
#include "vd/vdScannerFactory.hpp"

#include <gtest/gtest.h>

using invsync::vd::feedGateOpen;

TEST(FeedGateOpen, NeverStarted_OpensGate)
{
    EXPECT_TRUE(feedGateOpen(/*started*/ false, /*enabled*/ false, /*initialized*/ false, /*feedReady*/ false));
}

TEST(FeedGateOpen, StartedButDisabled_OpensGate)
{
    EXPECT_TRUE(feedGateOpen(/*started*/ true, /*enabled*/ false, /*initialized*/ false, /*feedReady*/ false));
}

TEST(FeedGateOpen, EnabledStillStarting_Defers)
{
    EXPECT_FALSE(feedGateOpen(/*started*/ true, /*enabled*/ true, /*initialized*/ false, /*feedReady*/ false));
}

TEST(FeedGateOpen, InitializedButFeedNotReady_Defers)
{
    EXPECT_FALSE(feedGateOpen(/*started*/ true, /*enabled*/ true, /*initialized*/ true, /*feedReady*/ false));
}

TEST(FeedGateOpen, InitializedAndFeedReady_Passes)
{
    EXPECT_TRUE(feedGateOpen(/*started*/ true, /*enabled*/ true, /*initialized*/ true, /*feedReady*/ true));
}
