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

#include "upgrade/platform.hpp"

#include <gtest/gtest.h>

#include <string>
#include <vector>

using namespace task_manager::upgrade;

namespace
{
    struct PlatformCase
    {
        const char* platform;
        const char* osMajor;
        const char* osMinor;
        const char* architecture;
        UpgradeError expectedError;
        const char* expectedPackageType;
    };

    struct ArchCase
    {
        const char* platform;
        const char* packageType;
        const char* architecture;
        const char* expected;
    };
} // namespace

TEST(UpgradePlatform, ClassifiesEveryKnownShape)
{
    const std::vector<PlatformCase> cases {
        // Blacklist first, and unconditionally -- a full set of other facts does not rescue it.
        {"solaris", "11", "", "x86_64", UpgradeError::SystemNotSupported, ""},
        {"sunos", "", "", "", UpgradeError::SystemNotSupported, ""},
        {"aix", "7", "", "powerpc", UpgradeError::SystemNotSupported, ""},
        {"hp-ux", "", "", "", UpgradeError::SystemNotSupported, ""},
        {"bsd", "", "", "", UpgradeError::SystemNotSupported, ""},

        // Windows needs nothing else at all.
        {"windows", "", "", "", UpgradeError::Success, "msi"},

        // macOS needs an architecture and nothing else.
        {"darwin", "", "", "arm64", UpgradeError::Success, "pkg"},
        {"darwin", "", "", "", UpgradeError::GlobalDbFailure, ""},

        // Linux needs an architecture AND a major version...
        {"debian", "12", "", "x86_64", UpgradeError::Success, "deb"},
        {"centos", "7", "", "x86_64", UpgradeError::Success, "rpm"},
        {"rhel", "8", "", "", UpgradeError::GlobalDbFailure, ""},
        {"rhel", "", "", "x86_64", UpgradeError::GlobalDbFailure, ""},

        // ...and a MINOR version too, but only for ubuntu, whose repository path is <major>.<minor>.
        {"ubuntu", "22", "04", "x86_64", UpgradeError::Success, "deb"},
        {"ubuntu", "22", "", "x86_64", UpgradeError::GlobalDbFailure, ""},

        // Rolling releases have no version to report, so the version requirement is waived.
        {"arch", "", "", "x86_64", UpgradeError::Success, ""},
        {"opensuse-tumbleweed", "", "", "x86_64", UpgradeError::Success, "rpm"},

        // End-of-life majors are rejected despite satisfying everything above.
        {"sles", "11", "", "x86_64", UpgradeError::SystemNotSupported, ""},
        {"suse", "11", "", "x86_64", UpgradeError::SystemNotSupported, ""},
        {"ol", "5", "", "x86_64", UpgradeError::SystemNotSupported, ""},
        {"rhel", "5", "", "x86_64", UpgradeError::SystemNotSupported, ""},
        {"centos", "5", "", "x86_64", UpgradeError::SystemNotSupported, ""},
        // ...and only those exact majors.
        {"sles", "12", "", "x86_64", UpgradeError::Success, "rpm"},
        {"centos", "6", "", "x86_64", UpgradeError::Success, "rpm"},

        // A distribution in neither family is upgradable but has no package type of its own; the
        // repository layer decides whether that is fatal.
        {"alpine", "3", "", "x86_64", UpgradeError::Success, ""},

        // Nothing known at all is a database failure, NOT "unsupported".
        {"", "", "", "", UpgradeError::GlobalDbFailure, ""},
    };

    for (const auto& testCase : cases)
    {
        const auto verdict {
            resolvePackageType(testCase.platform, testCase.osMajor, testCase.osMinor, testCase.architecture)};

        SCOPED_TRACE(std::string {"platform="} + testCase.platform + " major=" + testCase.osMajor +
                     " minor=" + testCase.osMinor + " arch=" + testCase.architecture);
        EXPECT_EQ(verdict.error, testCase.expectedError);
        EXPECT_EQ(verdict.packageType, testCase.expectedPackageType);
    }
}

TEST(UpgradePlatform, AnEndOfLifePlatformReportsNoPackageType)
{
    // The family is resolved only after the verdict is Success, so a rejected agent carries none.
    // The orchestrator must not read packageType without checking error first.
    const auto verdict {resolvePackageType("centos", "5", "", "x86_64")};
    EXPECT_EQ(verdict.error, UpgradeError::SystemNotSupported);
    EXPECT_TRUE(verdict.packageType.empty());
}

TEST(UpgradePlatform, TranslatesOnlyWhatTheRepositoryRenames)
{
    const std::vector<ArchCase> cases {
        // deb renames both architectures.
        {"ubuntu", "deb", "x86_64", "amd64"},
        {"debian", "deb", "aarch64", "arm64"},

        // rpm renames neither.
        {"centos", "rpm", "x86_64", "x86_64"},
        {"centos", "rpm", "aarch64", "aarch64"},

        // macOS pkg has its own names.
        {"darwin", "pkg", "x86_64", "intel64"},
        {"darwin", "pkg", "aarch64", "arm64"},

        // Windows never renames.
        {"windows", "msi", "x86_64", "x86_64"},

        // An unrecognised architecture passes through, which is what makes this safe to call
        // unconditionally.
        {"ubuntu", "deb", "armv7l", "armv7l"},
        {"centos", "rpm", "s390x", "s390x"},

        // An empty package type must not be dereferenced -- the retired C strcmp'd it unguarded.
        {"alpine", "", "x86_64", "x86_64"},
    };

    for (const auto& testCase : cases)
    {
        SCOPED_TRACE(std::string {"platform="} + testCase.platform + " pkg=" + testCase.packageType +
                     " arch=" + testCase.architecture);
        EXPECT_EQ(translateArch(testCase.platform, testCase.packageType, testCase.architecture), testCase.expected);
    }
}
