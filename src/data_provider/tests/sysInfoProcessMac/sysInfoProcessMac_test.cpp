/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * September 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "sysInfoProcessMac_test.h"
#include "processInfoMac.h"
#include <string>
#include <unistd.h>

TEST_F(SysInfoProcessMacTest, ResolvesRealNameWhenPathLookupSucceeds)
{
    // Fallback mimics a truncated pbi_name; proc_pidpath() succeeds for this
    // live pid so the real path always wins.
    const std::string truncatedPbiName { "com.apple.accessibility.mediaac" };

    const auto name { resolveProcessName(getpid(), truncatedPbiName) };

    EXPECT_NE(truncatedPbiName, name);
    EXPECT_FALSE(name.empty());
}

TEST_F(SysInfoProcessMacTest, FallsBackToPbiNameWhenPathLookupFails)
{
    const std::string pbiName { "com.apple.accessibility.mediaac" };

    // pid 0 is the kernel task; proc_pidpath() cannot resolve it and returns 0.
    const auto name { resolveProcessName(0, pbiName) };

    EXPECT_EQ(pbiName, name);
}
