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
#include <string>

// getProcessInfo() has internal linkage and lives in a TU that pulls in the
// full macOS SDK, so this duplicates its name-resolution branch for isolated
// testing — keep the two in sync if that logic changes.
static std::string resolveProcessName(const int pathLen, const char* pathBuffer, const std::string& pbiName)
{
    if (pathLen > 0)
    {
        const std::string fullPath { pathBuffer };
        return fullPath.substr(fullPath.find_last_of('/') + 1);
    }

    return pbiName;
}

TEST_F(SysInfoProcessMacTest, LongProcessNameIsNotTruncated)
{
    const std::string fullPath { "/System/Library/PrivateFrameworks/TCC.framework/Support/com.apple.accessibility.mediaaccessibilityd" };
    const std::string truncatedPbiName { "com.apple.accessibility.mediaac" };

    const auto name { resolveProcessName(static_cast<int>(fullPath.size()), fullPath.c_str(), truncatedPbiName) };

    EXPECT_EQ("com.apple.accessibility.mediaaccessibilityd", name);
    EXPECT_GT(name.size(), 31u);
    EXPECT_NE(truncatedPbiName, name);
}

TEST_F(SysInfoProcessMacTest, ShortProcessNameIsUnaffected)
{
    const std::string fullPath { "/usr/sbin/cron" };
    const std::string pbiName { "cron" };

    const auto name { resolveProcessName(static_cast<int>(fullPath.size()), fullPath.c_str(), pbiName) };

    EXPECT_EQ("cron", name);
}

TEST_F(SysInfoProcessMacTest, FallsBackToPbiNameWhenPathLookupFails)
{
    const std::string pbiName { "com.apple.accessibility.mediaac" };

    const auto name { resolveProcessName(-1, "", pbiName) };

    EXPECT_EQ(pbiName, name);
}
