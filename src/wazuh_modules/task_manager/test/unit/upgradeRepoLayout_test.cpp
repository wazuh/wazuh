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

#include "upgrade/repoLayout.hpp"
#include "upgrade/versionsFile.hpp"

#include <gtest/gtest.h>

#include <string>
#include <vector>

using namespace task_manager::upgrade;

namespace
{
    AgentInfo agentOn(const char* platform,
                      const char* architecture,
                      const char* packageType,
                      const char* osMajor = "",
                      const char* osMinor = "")
    {
        AgentInfo agent;
        agent.agentId = 7;
        agent.platform = platform;
        agent.architecture = architecture;
        agent.packageType = packageType;
        agent.majorVersion = osMajor;
        agent.minorVersion = osMinor;
        return agent;
    }

    RepoRequest requestFor(const char* wpkVersion)
    {
        RepoRequest request;
        request.wpkVersion = wpkVersion;
        return request;
    }

    struct LayoutCase
    {
        const char* label;
        AgentInfo agent;
        const char* wpkVersion;
        const char* expectedPath;
        const char* expectedFile;
    };
} // namespace

// ---- the golden table ---------------------------------------------------------------------------

TEST(UpgradeRepoLayout, BuildsEveryPublishedRepositoryShape)
{
    // Six shapes across two version epochs. This table is the whole point of the file: the retired
    // implementation expressed it as nested snprintf() calls where a transposed pair of path
    // components would look perfectly reasonable in review and only fail against a live repository.
    const std::vector<LayoutCase> cases {
        {"windows",
         agentOn("windows", "x86_64", "msi"),
         "v5.0.0",
         "https://packages.wazuh.com/5.x/wpk/windows/",
         "wazuh_agent_v5.0.0_windows.wpk"},

        {"macOS, new structure: <pkg>/<translated arch>",
         agentOn("darwin", "x86_64", "pkg"),
         "v5.0.0",
         "https://packages.wazuh.com/5.x/wpk/macos/pkg/intel64/",
         "wazuh_agent_v5.0.0_macos_intel64.pkg.wpk"},

        {"macOS, old structure: <raw arch>/<pkg> -- the two components INVERT across v4.9.0",
         agentOn("darwin", "x86_64", "pkg"),
         "v4.8.0",
         "https://packages.wazuh.com/4.x/wpk/macos/x86_64/pkg/",
         "wazuh_agent_v4.8.0_macos_x86_64.wpk"},

        {"linux, new structure: <pkg>/<translated arch>",
         agentOn("ubuntu", "x86_64", "deb", "22", "04"),
         "v5.0.0",
         "https://packages.wazuh.com/5.x/wpk/linux/deb/amd64/",
         "wazuh_agent_v5.0.0_linux_amd64.deb.wpk"},

        {"linux, flat structure between v3.4.0 and v4.9.0",
         agentOn("centos", "x86_64", "rpm", "7"),
         "v4.8.0",
         "https://packages.wazuh.com/4.x/wpk/linux/x86_64/",
         "wazuh_agent_v4.8.0_linux_x86_64.wpk"},

        {"ubuntu below v3.4.0: <major>.<minor> and the 3.x repository",
         agentOn("ubuntu", "x86_64", "deb", "16", "04"),
         "v3.3.0",
         "https://packages.wazuh.com/wpk/ubuntu/16.04/x86_64/",
         "wazuh_agent_v3.3.0_ubuntu_16.04_x86_64.wpk"},

        {"other platform below v3.4.0: <platform>/<major>",
         agentOn("centos", "x86_64", "rpm", "7"),
         "v3.3.0",
         "https://packages.wazuh.com/wpk/centos/7/x86_64/",
         "wazuh_agent_v3.3.0_centos_7_x86_64.wpk"},
    };

    for (const auto& testCase : cases)
    {
        SCOPED_TRACE(testCase.label);

        const auto result {resolveRepoLayout(testCase.agent, requestFor(testCase.wpkVersion))};

        EXPECT_EQ(result.error, UpgradeError::Success);
        EXPECT_EQ(result.layout.pathUrl, testCase.expectedPath);
        EXPECT_EQ(result.layout.fileName, testCase.expectedFile);
        EXPECT_EQ(result.layout.versionsUrl, std::string {testCase.expectedPath} + "versions");
    }
}

// ---- repository resolution -----------------------------------------------------------------------

TEST(UpgradeRepoLayout, PicksTheDefaultRepositoryByTargetMajor)
{
    EXPECT_EQ(resolveRepositoryUrl(requestFor("v3.9.0")).value_or(""), "https://packages.wazuh.com/wpk/");
    EXPECT_EQ(resolveRepositoryUrl(requestFor("v4.0.0")).value_or(""), "https://packages.wazuh.com/4.x/wpk/");
    EXPECT_EQ(resolveRepositoryUrl(requestFor("v5.0.0")).value_or(""), "https://packages.wazuh.com/5.x/wpk/");
    EXPECT_EQ(resolveRepositoryUrl(requestFor("v10.1.2")).value_or(""), "https://packages.wazuh.com/10.x/wpk/");
}

TEST(UpgradeRepoLayout, TheRequestBeatsTheConfigWhichBeatsTheDefault)
{
    auto request {requestFor("v5.0.0")};
    request.configuredRepository = "repo.example/config/";
    EXPECT_EQ(resolveRepositoryUrl(request).value_or(""), "https://repo.example/config/");

    request.requestedRepository = "repo.example/request/";
    EXPECT_EQ(resolveRepositoryUrl(request).value_or(""), "https://repo.example/request/");
}

TEST(UpgradeRepoLayout, AddsTheMissingTrailingSlash)
{
    auto request {requestFor("v5.0.0")};
    request.requestedRepository = "repo.example/wpk";
    EXPECT_EQ(resolveRepositoryUrl(request).value_or(""), "https://repo.example/wpk/");
}

TEST(UpgradeRepoLayout, UseHttpOnlyAppliesWhenNoSchemeWasWritten)
{
    auto request {requestFor("v5.0.0")};
    request.useHttp = true;
    EXPECT_EQ(resolveRepositoryUrl(request).value_or(""), "http://packages.wazuh.com/5.x/wpk/");

    // An operator who spelled out https keeps it, even against use_http. Preserved deliberately:
    // silently downgrading a URL the operator wrote is not a reasonable reading of "use_http".
    request.requestedRepository = "https://repo.example/wpk/";
    EXPECT_EQ(resolveRepositoryUrl(request).value_or(""), "https://repo.example/wpk/");

    request.requestedRepository = "http://repo.example/wpk/";
    request.useHttp = false;
    EXPECT_EQ(resolveRepositoryUrl(request).value_or(""), "http://repo.example/wpk/");
}

TEST(UpgradeRepoLayout, AnUnreadableMajorOnlyMattersWhenTheDefaultIsNeeded)
{
    // parseVersion() searches for 'v' anywhere, so "Wazuh v5.0.0" compares as 5.0.0 and lands in the
    // >= v4.0.0 branch -- but the major extraction is ANCHORED, mirroring the retired sscanf("v%d"),
    // so it finds nothing and the request is refused rather than pointed at a nonsense URL.
    EXPECT_FALSE(resolveRepositoryUrl(requestFor("Wazuh v5.0.0")).has_value());

    const auto result {resolveRepoLayout(agentOn("windows", "x86_64", "msi"), requestFor("Wazuh v5.0.0"))};
    EXPECT_EQ(result.error, UpgradeError::WpkVersionDoesNotExist);

    // With an explicit repository the major is never needed, so the same version resolves fine.
    auto request {requestFor("Wazuh v5.0.0")};
    request.requestedRepository = "repo.example/wpk/";
    EXPECT_EQ(resolveRepositoryUrl(request).value_or(""), "https://repo.example/wpk/");
}

TEST(UpgradeRepoLayout, AnEmptyTargetVersionIsRefused)
{
    EXPECT_EQ(resolveRepoLayout(agentOn("windows", "x86_64", "msi"), requestFor("")).error,
              UpgradeError::WpkVersionDoesNotExist);
}

// ---- package-type reconciliation -----------------------------------------------------------------

TEST(UpgradeRepoLayout, TheAgentsOwnPackageTypeWinsAMismatchUnlessForced)
{
    auto agent {agentOn("almalinux", "x86_64", "rpm", "9")};
    auto request {requestFor("v5.0.0")};
    request.requestedPackageType = "deb";

    // Asymmetric on purpose, and preserved from the retired C: without force the caller's guess is
    // only a warning, because the agent knows what it actually installed.
    auto result {resolveRepoLayout(agent, request)};
    EXPECT_EQ(result.error, UpgradeError::Success);
    EXPECT_EQ(result.notice, PackageTypeNotice::MismatchIgnored);
    EXPECT_EQ(result.layout.packageType, "rpm");
    EXPECT_EQ(result.layout.pathUrl, "https://packages.wazuh.com/5.x/wpk/linux/rpm/x86_64/");

    request.forceUpgrade = true;
    result = resolveRepoLayout(agent, request);
    EXPECT_EQ(result.notice, PackageTypeNotice::ForcedOverride);
    EXPECT_EQ(result.layout.packageType, "deb");
    // Forcing deb also changes the architecture spelling, because translateArch keys on the family.
    EXPECT_EQ(result.layout.pathUrl, "https://packages.wazuh.com/5.x/wpk/linux/deb/amd64/");
    EXPECT_EQ(result.layout.fileName, "wazuh_agent_v5.0.0_linux_amd64.deb.wpk");
}

TEST(UpgradeRepoLayout, TheRequestSuppliesAPackageTypeTheDistributionDidNot)
{
    auto request {requestFor("v5.0.0")};
    request.requestedPackageType = "rpm";

    const auto result {resolveRepoLayout(agentOn("alpine", "x86_64", "", "3"), request)};
    EXPECT_EQ(result.error, UpgradeError::Success);
    EXPECT_EQ(result.notice, PackageTypeNotice::DefaultedFromRequest);
    EXPECT_EQ(result.layout.pathUrl, "https://packages.wazuh.com/5.x/wpk/linux/rpm/x86_64/");
}

TEST(UpgradeRepoLayout, AnUnknownDistributionWithNoPackageTypeHasNoUrlAtAll)
{
    // Only the >= v4.9.0 Linux shape can fail this way: it is the only one that puts the package
    // type in the path.
    EXPECT_EQ(resolveRepoLayout(agentOn("alpine", "x86_64", "", "3"), requestFor("v5.0.0")).error,
              UpgradeError::SystemNotSupported);

    // The pre-4.9 shape does not name the package type, so the same agent resolves fine there.
    EXPECT_EQ(resolveRepoLayout(agentOn("alpine", "x86_64", "", "3"), requestFor("v4.8.0")).error,
              UpgradeError::Success);
}

// ---- the versions file ---------------------------------------------------------------------------

TEST(UpgradeVersionsFile, ParsesTheOrdinaryCase)
{
    const auto entries {parseVersionsFile("v4.14.0 aaaa1111\nv5.0.0 bbbb2222\n")};

    ASSERT_EQ(entries.size(), 2U);
    EXPECT_EQ(entries[0].version, "v4.14.0");
    EXPECT_EQ(entries[0].sha1, "aaaa1111");
    EXPECT_EQ(entries[1].version, "v5.0.0");
    EXPECT_EQ(entries[1].sha1, "bbbb2222");
}

TEST(UpgradeVersionsFile, ReadsTheLastLineWithoutATrailingNewline)
{
    // The retired parser needed the entire match block repeated after its loop to reach this line.
    const auto entries {parseVersionsFile("v4.14.0 aaaa1111\nv5.0.0 bbbb2222")};

    ASSERT_EQ(entries.size(), 2U);
    EXPECT_EQ(entries[1].sha1, "bbbb2222");
}

TEST(UpgradeVersionsFile, StripsTheCarriageReturnFromCrlfFiles)
{
    // The retired parser split on '\n' only and carried the '\r' into the sha1, so a CRLF-served
    // repository failed every integrity check while reporting a sha1 mismatch -- the wrong cause.
    const auto entries {parseVersionsFile("v5.0.0 bbbb2222\r\n")};

    ASSERT_EQ(entries.size(), 1U);
    EXPECT_EQ(entries[0].sha1, "bbbb2222");
}

TEST(UpgradeVersionsFile, SkipsLinesThatCarryNoPair)
{
    // Empty lines, a line with no separator, a line whose separator is leading, and a line with an
    // empty sha1.
    const auto entries {parseVersionsFile("\nv5.0.0 bbbb2222\n\nnosha\n v0.0.0\nv1.0.0 \n")};

    ASSERT_EQ(entries.size(), 1U);
    EXPECT_EQ(entries[0].version, "v5.0.0");
}

TEST(UpgradeVersionsFile, SkipsLinesThatAreNotAVersionAndADigest)
{
    // A repository behind a proxy answers 200 with an HTML error page often enough to matter, and
    // prose contains spaces. The retired parser accepted any line with one, so this produced the
    // entry {"<html>404", "not"} -- which matches nothing, and therefore reported "that version does
    // not exist in the repository" when the truth was "the repository did not answer usefully".
    EXPECT_TRUE(parseVersionsFile("<html>404 not found</html>\n").empty());
    EXPECT_TRUE(parseVersionsFile("Error: repository unavailable\n").empty());

    // A digest must be hex...
    EXPECT_TRUE(parseVersionsFile("v5.0.0 not-a-digest\n").empty());
    // ...and a version must start with 'v' or a digit.
    EXPECT_TRUE(parseVersionsFile("latest bbbb2222\n").empty());

    // Both spellings of a real line survive, in either digest case.
    EXPECT_EQ(parseVersionsFile("v5.0.0 ABCDEF01\n").size(), 1U);
    EXPECT_EQ(parseVersionsFile("5.0.0 abcdef01\n").size(), 1U);
}

TEST(UpgradeVersionsFile, MatchesByVersionNotByString)
{
    // A repository listing bare "4.14.0" answers a request for "v4.14.0", and vice versa.
    const auto entries {parseVersionsFile("4.14.0 aaaa1111\nv5.0.0 bbbb2222\n")};

    EXPECT_EQ(findSha1(entries, "v4.14.0").value_or(""), "aaaa1111");
    EXPECT_EQ(findSha1(entries, "5.0.0").value_or(""), "bbbb2222");

    // Patches are compared, so a near miss is a miss.
    EXPECT_FALSE(findSha1(entries, "v4.14.1").has_value());
    EXPECT_FALSE(findSha1(entries, "v9.9.9").has_value());
}
