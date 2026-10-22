/*
 * Wazuh container_instances — the startup cgroup hierarchy report (#37203 O4).
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * On a cgroup v1 host this module returns real containers from the runtime
 * and then drops every running one, because its resolver parses only v2
 * `0::` lines. That was not logged anywhere — the operator saw a healthy
 * module and an inventory that never filled.
 *
 * So the report itself is the deliverable, and these pin the two things that
 * make it one: that a legacy host is ERROR rather than a warning nobody
 * reads, and that the text says what an operator needs in order to stop
 * looking in the wrong place.
 */

#include "core/cgroup_mode_report.hpp"

#include <gtest/gtest.h>

#include <string>

using namespace wazuh::container_instances;

namespace
{

    bool Mentions(const std::string& haystack, const std::string& needle)
    {
        return haystack.find(needle) != std::string::npos;
    }

} // namespace

TEST(CgroupModeReportTest, ALegacyHostIsReportedAsAnError)
{
    const auto report = describeCgroupHostMode(WZ_CGROUP_MODE_LEGACY);

    EXPECT_EQ(LogLevel::error, report.level)
        << "a host where the module cannot work at all, and will not recover, is not a warning";
}

TEST(CgroupModeReportTest, AUsableHostIsReportedAtInfo)
{
    EXPECT_EQ(LogLevel::info, describeCgroupHostMode(WZ_CGROUP_MODE_UNIFIED).level);

    // Hybrid correlates on the unified hierarchy's ids, so it works — the
    // separate mode exists to NAME it differently, not to degrade it.
    EXPECT_EQ(LogLevel::info, describeCgroupHostMode(WZ_CGROUP_MODE_HYBRID).level);
}

TEST(CgroupModeReportTest, EveryReportNamesWhichHierarchyWasFound)
{
    // "Which hierarchy did the agent think it was on?" is the first question
    // asked of any attribution bug. A message that only says "unsupported"
    // cannot answer it.
    for (const auto mode : {WZ_CGROUP_MODE_UNIFIED, WZ_CGROUP_MODE_LEGACY, WZ_CGROUP_MODE_HYBRID})
    {
        const auto report = describeCgroupHostMode(mode);
        EXPECT_TRUE(Mentions(report.message, wz_cgroup_mode_name(mode)))
            << "mode " << static_cast<int>(mode) << " message: " << report.message;
    }
}

TEST(CgroupModeReportTest, TheLegacyMessageWarnsThatANonEmptyListIsNotSuccess)
{
    // The trap this sentence exists for: since stopped containers became
    // visible, `listContainers()` hides only records that are unresolved AND
    // running. On a v1 host every record is unresolved, so the list contains
    // exactly the containers that are NOT running — it is non-empty, and an
    // operator checking "is the list empty?" concludes this works.
    const auto report = describeCgroupHostMode(WZ_CGROUP_MODE_LEGACY);

    EXPECT_TRUE(Mentions(report.message, "Exited containers may still be listed"))
        << "without this the most likely wrong conclusion is the one the message had a chance to prevent: "
        << report.message;
    EXPECT_TRUE(Mentions(report.message, "RUNNING")) << report.message;
}

TEST(CgroupModeReportTest, TheLegacyMessageNamesBothFeaturesThatStopWorking)
{
    const auto report = describeCgroupHostMode(WZ_CGROUP_MODE_LEGACY);

    // Both, because they fail for the same reason but are configured
    // separately, and an operator who reads only about one will go looking
    // for a second, different cause for the other.
    EXPECT_TRUE(Mentions(report.message, "inventory")) << report.message;
    EXPECT_TRUE(Mentions(report.message, "file integrity monitoring")) << report.message;
}
