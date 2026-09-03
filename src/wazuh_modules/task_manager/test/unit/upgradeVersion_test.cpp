/*
 * Wazuh task manager module
 * Copyright (C) 2015, Wazuh Inc.
 * September 3, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "upgrade/version.hpp"
#include "upgrade/versionPolicy.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <thread>
#include <vector>

using namespace task_manager::upgrade;

// ---- parsing ---------------------------------------------------------------------------------

TEST(UpgradeVersion, ParsesWithAndWithoutTheVPrefix)
{
    EXPECT_EQ(parseVersion("v4.14.0").major, 4);
    EXPECT_EQ(parseVersion("v4.14.0").minor, 14);
    EXPECT_EQ(parseVersion("v4.14.0").patch, 0);

    EXPECT_EQ(parseVersion("4.14.3").major, 4);
    EXPECT_EQ(parseVersion("4.14.3").minor, 14);
    EXPECT_EQ(parseVersion("4.14.3").patch, 3);
}

TEST(UpgradeVersion, AbsentComponentsAreZero)
{
    EXPECT_EQ(parseVersion("v4").minor, 0);
    EXPECT_EQ(parseVersion("v4").patch, 0);
    EXPECT_EQ(parseVersion("v4.14").patch, 0);
}

TEST(UpgradeVersion, AComponentStopsAtTheFirstNonDigit)
{
    // "4.14.0-rc1" is 4.14.0, not a parse failure.
    const auto parsed {parseVersion("v4.14.0-rc1")};
    EXPECT_EQ(parsed.major, 4);
    EXPECT_EQ(parsed.minor, 14);
    EXPECT_EQ(parsed.patch, 0);
}

TEST(UpgradeVersion, TheVMayBeAnywhere)
{
    // Copied warts and all from the retired strchr(ver, 'v') rule -- agent-reported version strings
    // have not always been bare, and narrowing this would change which agents look upgradable.
    const auto parsed {parseVersion("Wazuh v4.5.0")};
    EXPECT_EQ(parsed.major, 4);
    EXPECT_EQ(parsed.minor, 5);

    // The flip side of the same rule: a trailing 'v' consumes the whole string.
    EXPECT_EQ(parseVersion("4.0.0v").major, 0);
}

TEST(UpgradeVersion, UnreadableInputIsZeroNotAnError)
{
    // The callers depend on this: resolveRepositoryUrl() asks whether the target is below v4.0.0,
    // and an unreadable string answering "yes" is what sends it to the 3.x repository -- exactly
    // what the retired atoi()-based parser did.
    EXPECT_EQ(parseVersion("abc").major, 0);
    EXPECT_EQ(parseVersion("").major, 0);
}

// ---- comparison ------------------------------------------------------------------------------

TEST(UpgradeVersion, ComparesMajorThenMinorThenPatch)
{
    EXPECT_EQ(compareVersions("v4.14.0", "v4.14.0", true), 0);
    EXPECT_EQ(compareVersions("v5.0.0", "v4.14.0", true), 1);
    EXPECT_EQ(compareVersions("v4.14.0", "v5.0.0", true), -1);
    EXPECT_EQ(compareVersions("v4.14.0", "v4.13.9", true), 1);
    EXPECT_EQ(compareVersions("v4.14.1", "v4.14.2", true), -1);
}

TEST(UpgradeVersion, IsIndifferentToTheVPrefixOnEitherSide)
{
    EXPECT_EQ(compareVersions("4.14.0", "v4.14.0", true), 0);
    EXPECT_EQ(compareVersions("v4.14.0", "4.14.0", true), 0);
}

TEST(UpgradeVersion, PatchIsIgnoredWhenAsked)
{
    EXPECT_EQ(compareVersions("v4.14.1", "v4.14.9", false), 0);
    EXPECT_EQ(compareVersions("v4.14.1", "v4.14.9", true), -1);

    // A missing patch is zero, so a two-component version compares equal to its .0 form.
    EXPECT_EQ(compareVersions("v4.14", "v4.14.0", true), 0);
}

TEST(UpgradeVersion, DoesNotTruncateLongVersions)
{
    // THE REGRESSION THIS PORT EXISTS TO FIX. compare_wazuh_versions() copied each argument into a
    // char[10], so "v10.14.100" (ten characters) became "v10.14.10" and compared EQUAL to it --
    // reporting a lower version than the one it was handed.
    EXPECT_EQ(compareVersions("v10.14.100", "v10.14.10", true), 1);
    EXPECT_EQ(compareVersions("v10.14.10", "v10.14.100", true), -1);
    EXPECT_EQ(compareVersions("v123.456.789", "v123.456.789", true), 0);
}

TEST(UpgradeVersion, IsSafeToCallFromManyThreadsAtOnce)
{
    // The other reason this is a port and not a call: compare_wazuh_versions() splits with strtok(),
    // whose cursor is a process-global. It survived only because its one caller was single-threaded,
    // and this module runs a worker pool. A torn read here would surface as an agent being told its
    // version is greater or equal to the target when it is not.
    constexpr int THREAD_COUNT {8};
    constexpr int ITERATIONS {5000};

    std::atomic<int> mismatches {0};
    std::vector<std::thread> threads;
    threads.reserve(THREAD_COUNT);

    for (int index = 0; index < THREAD_COUNT; ++index)
    {
        threads.emplace_back(
            [&mismatches, index]
            {
                // Each thread compares a different pair, so any cross-thread state leak changes an
                // answer rather than merely racing on an identical one.
                const std::string left {"v4." + std::to_string(index) + ".0"};
                for (int iteration = 0; iteration < ITERATIONS; ++iteration)
                {
                    if (compareVersions(left, "v4.4.0", true) != (index > 4 ? 1 : (index < 4 ? -1 : 0)))
                    {
                        ++mismatches;
                    }
                }
            });
    }

    for (auto& thread : threads)
    {
        thread.join();
    }

    EXPECT_EQ(mismatches.load(), 0);
}

// ---- repository upgrade gates ------------------------------------------------------------------

namespace
{
    constexpr const char* MANAGER {"v5.0.0"};
}

TEST(UpgradeVersionPolicy, AcceptsASupportedAgentAndTargetsTheManagerVersion)
{
    const auto verdict {checkRepositoryUpgrade("v4.14.0", MANAGER, "", false)};
    EXPECT_EQ(verdict.error, UpgradeError::Success);
    EXPECT_EQ(verdict.wpkVersion, "v5.0.0");
}

TEST(UpgradeVersionPolicy, ACallerSuppliedVersionWinsOverTheManagerVersion)
{
    const auto verdict {checkRepositoryUpgrade("v4.0.0", MANAGER, "v4.14.0", false)};
    EXPECT_EQ(verdict.error, UpgradeError::Success);
    EXPECT_EQ(verdict.wpkVersion, "v4.14.0");
}

TEST(UpgradeVersionPolicy, RejectsAgentsBelowTheMinimumSupportedVersion)
{
    EXPECT_EQ(checkRepositoryUpgrade("v2.9.9", MANAGER, "", false).error, UpgradeError::NotMinimalVersionSupported);

    // v3.0.0 is exactly at the boundary and clears this gate -- shown against a pre-v5 manager,
    // because against a v5 manager it would clear the minimum only to be stopped by the NEXT gate.
    EXPECT_EQ(checkRepositoryUpgrade("v3.0.0", "v4.14.0", "", false).error, UpgradeError::Success);

    // That "next gate" is worth pinning down, since it is the more common answer in practice: any
    // agent below v4.14.0 is told to go there first, however far below it is.
    EXPECT_EQ(checkRepositoryUpgrade("v3.0.0", MANAGER, "", false).error, UpgradeError::IntermediateVersionRequired);
}

TEST(UpgradeVersionPolicy, AnUnreadableAgentVersionIsADatabaseFailure)
{
    // Neither 'v'-tagged nor digit-led: the agent never reported anything this code can act on, and
    // that is a different answer from "cannot be upgraded".
    EXPECT_EQ(checkRepositoryUpgrade("unknown", MANAGER, "", false).error, UpgradeError::GlobalDbFailure);
    EXPECT_EQ(checkRepositoryUpgrade("", MANAGER, "", false).error, UpgradeError::GlobalDbFailure);
}

TEST(UpgradeVersionPolicy, AManagerVersionWithNoVIsADatabaseFailure)
{
    // Faithful to the retired strchr(__wazuh_version, 'v') read, which simply did nothing when it
    // failed and left the caller holding the initial GlobalDbFailure.
    EXPECT_EQ(checkRepositoryUpgrade("v4.14.0", "5.0.0", "", false).error, UpgradeError::GlobalDbFailure);
}

TEST(UpgradeVersionPolicy, DirectUpgradeToFiveRequiresFourteenFirst)
{
    EXPECT_EQ(checkRepositoryUpgrade("v4.13.9", MANAGER, "", false).error, UpgradeError::IntermediateVersionRequired);
    EXPECT_EQ(checkRepositoryUpgrade("v4.14.0", MANAGER, "", false).error, UpgradeError::Success);
}

TEST(UpgradeVersionPolicy, TheIntermediateVersionRuleCannotBeForced)
{
    // Deliberate, and the one gate force does not open: a 5.x agent cannot re-enroll from a pre-4.14
    // state, so forcing it strands the agent rather than upgrading it.
    EXPECT_EQ(checkRepositoryUpgrade("v4.13.9", MANAGER, "", true).error, UpgradeError::IntermediateVersionRequired);
}

TEST(UpgradeVersionPolicy, RefusesToDowngradeOrReinstallUnlessForced)
{
    EXPECT_EQ(checkRepositoryUpgrade("v5.0.0", MANAGER, "", false).error,
              UpgradeError::NewVersionLessOrEqualThanCurrent);
    EXPECT_EQ(checkRepositoryUpgrade("v5.1.0", MANAGER, "", false).error,
              UpgradeError::NewVersionLessOrEqualThanCurrent);

    EXPECT_EQ(checkRepositoryUpgrade("v5.0.0", MANAGER, "", true).error, UpgradeError::Success);
}

TEST(UpgradeVersionPolicy, RefusesToOutrunTheManagerUnlessForced)
{
    EXPECT_EQ(checkRepositoryUpgrade("v4.14.0", MANAGER, "v5.1.0", false).error, UpgradeError::NewVersionGreaterMaster);
    EXPECT_EQ(checkRepositoryUpgrade("v4.14.0", MANAGER, "v5.1.0", true).error, UpgradeError::Success);
}

// ---- custom WPK gates --------------------------------------------------------------------------

TEST(UpgradeVersionPolicy, ParsesTheVersionOutOfACanonicalWpkName)
{
    EXPECT_EQ(parseWpkCustomVersion("/var/upgrade/wazuh_agent_v5.0.0_linux_x86_64.wpk").value_or(""), "v5.0.0");
    EXPECT_EQ(parseWpkCustomVersion("wazuh_agent_v4.14.0_windows.wpk").value_or(""), "v4.14.0");
}

TEST(UpgradeVersionPolicy, ANonCanonicalWpkNameCarriesNoVersionClaim)
{
    EXPECT_FALSE(parseWpkCustomVersion("/var/upgrade/renamed.wpk").has_value());
    EXPECT_FALSE(parseWpkCustomVersion("wazuh_agent_v5.0.0.wpk").has_value()); // no closing '_'
    EXPECT_FALSE(parseWpkCustomVersion("").has_value());

    // A directory containing "_v" must not be mistaken for the file name's version tag.
    EXPECT_EQ(parseWpkCustomVersion("/opt/build_v9/wazuh_agent_v5.0.0_linux_x86_64.wpk").value_or(""), "v5.0.0");
}

TEST(UpgradeVersionPolicy, TheCustomPathAppliesOnlyTheIntermediateRule)
{
    EXPECT_EQ(checkCustomUpgrade("v4.13.0", "/var/upgrade/wazuh_agent_v5.0.0_linux_x86_64.wpk").error,
              UpgradeError::IntermediateVersionRequired);
    EXPECT_EQ(checkCustomUpgrade("v4.14.0", "/var/upgrade/wazuh_agent_v5.0.0_linux_x86_64.wpk").error,
              UpgradeError::Success);

    // No "not newer than current" and no "greater than the manager": the operator chose this file.
    EXPECT_EQ(checkCustomUpgrade("v5.0.0", "/var/upgrade/wazuh_agent_v5.0.0_linux_x86_64.wpk").error,
              UpgradeError::Success);
    EXPECT_EQ(checkCustomUpgrade("v4.14.0", "/var/upgrade/wazuh_agent_v9.9.9_linux_x86_64.wpk").error,
              UpgradeError::Success);
}

TEST(UpgradeVersionPolicy, ANonCanonicalCustomNameFallsThroughToTheAgent)
{
    // The manager cannot know what a renamed file installs, so it does not guess -- the agent's own
    // preinst check becomes the only gate.
    EXPECT_EQ(checkCustomUpgrade("v4.13.0", "/var/upgrade/renamed.wpk").error, UpgradeError::Success);
}

TEST(UpgradeVersionPolicy, TheCustomPathStillEnforcesTheMinimumAndReadability)
{
    EXPECT_EQ(checkCustomUpgrade("v2.9.9", "/var/upgrade/renamed.wpk").error, UpgradeError::NotMinimalVersionSupported);
    EXPECT_EQ(checkCustomUpgrade("unknown", "/var/upgrade/renamed.wpk").error, UpgradeError::GlobalDbFailure);
}
