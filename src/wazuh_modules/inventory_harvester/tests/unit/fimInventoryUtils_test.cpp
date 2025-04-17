/**
 * Wazuh Inventory Harvester - FimInventoryUtils Unit tests
 * Copyright (C) 2015, Wazuh Inc.
 * April 9, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "MockFimContext.hpp"
#include "fimInventory/fimContext.hpp"

class FimInventoryUtils : public ::testing::Test
{
protected:
    // LCOV_EXCL_START
    FimInventoryUtils() = default;
    ~FimInventoryUtils() override = default;
    // LCOV_EXCL_STOP
};

TEST_F(FimInventoryUtils, BasicNormalization)
{
    std::string registryPath = R"(HKEY_LOCAL_MACHINE\\Software\\MyApp)";
    FimContextUtils::sanitizeKeyPath(registryPath);
    EXPECT_EQ(registryPath, "Software\\MyApp");
}

TEST_F(FimInventoryUtils, BasicNormalizationAlternative)
{
    std::string registryPath = "HKEY_LOCAL_MACHINE//Software//MyApp";
    FimContextUtils::sanitizeKeyPath(registryPath);
    EXPECT_EQ(registryPath, "Software/MyApp");
}

TEST_F(FimInventoryUtils, NoHiveMatch)
{
    std::string registryPath = R"(CustomKey\\Data\\Stuff)";
    FimContextUtils::sanitizeKeyPath(registryPath);
    EXPECT_EQ(registryPath, "CustomKey\\Data\\Stuff");
}

TEST_F(FimInventoryUtils, RemovesKnownHivePrefix)
{
    std::string registryPath = "HKEY_LOCAL_MACHINE/Software/MyApp";
    FimContextUtils::sanitizeKeyPath(registryPath);
    EXPECT_EQ(registryPath, "Software/MyApp");
}

TEST_F(FimInventoryUtils, ReplacesDoubleSlashes)
{
    std::string registryPath = "HKEY_USERS//Software//App";
    FimContextUtils::sanitizeKeyPath(registryPath);
    EXPECT_EQ(registryPath, "Software/App");
}

TEST_F(FimInventoryUtils, ReplacesDoubleBackslashes)
{
    std::string registryPath = R"(HKEY_CURRENT_USER\\Software\\App)";
    FimContextUtils::sanitizeKeyPath(registryPath);
    EXPECT_EQ(registryPath, "Software\\App");
}

TEST_F(FimInventoryUtils, ReplacesBothBackslashAndDoubleSlash)
{
    std::string registryPath = "HKEY_CURRENT_CONFIG\\\\Software//App//Settings";
    FimContextUtils::sanitizeKeyPath(registryPath);
    EXPECT_EQ(registryPath, "Software/App/Settings");
}

TEST_F(FimInventoryUtils, NoHiveMatchShouldLeaveBase)
{
    std::string registryPath = "MY_UNKNOWN_HIVE/Path//SubPath";
    FimContextUtils::sanitizeKeyPath(registryPath);
    EXPECT_EQ(registryPath, "MY_UNKNOWN_HIVE/Path/SubPath");
}

TEST_F(FimInventoryUtils, EmptyregistryPathShouldRemainEmpty)
{
    std::string registryPath = "";
    FimContextUtils::sanitizeKeyPath(registryPath);
    EXPECT_EQ(registryPath, "");
}

TEST_F(FimInventoryUtils, OnlyHiveShouldBecomeEmpty)
{
    std::string registryPath = "HKEY_CLASSES_ROOT/";
    FimContextUtils::sanitizeKeyPath(registryPath);
    EXPECT_EQ(registryPath, "");
}

TEST_F(FimInventoryUtils, HiveIsPrefixButNotFullMatch)
{
    std::string registryPath = "HKEY_CURRENT_USER_ROOT/Extra";
    FimContextUtils::sanitizeKeyPath(registryPath);
    EXPECT_EQ(registryPath, "HKEY_CURRENT_USER_ROOT/Extra"); // Should not match partial
}

TEST_F(FimInventoryUtils, HiveWithoutSlashShouldNotBeRemoved)
{
    std::string registryPath = "HKEY_USERS";
    FimContextUtils::sanitizeKeyPath(registryPath);
    EXPECT_EQ(registryPath, "HKEY_USERS"); // No trailing slash, shouldn't match
}

TEST_F(FimInventoryUtils, BackslashAndSlashMixed)
{
    std::string registryPath = R"(HKEY_LOCAL_MACHINE\\Software//App\Config//)";
    FimContextUtils::sanitizeKeyPath(registryPath);
    EXPECT_EQ(registryPath, "Software/App\\Config/");
}

TEST_F(FimInventoryUtils, ReplacesHiveCorrectly)
{
    std::string registryPath = "HKEY_LOCAL_MACHINE\\Software\\MyApp";
    FimContextUtils::sanitizePath(registryPath, false);
    EXPECT_EQ(registryPath, "HKLM\\Software\\MyApp");
}

TEST_F(FimInventoryUtils, LeavesUnknownHiveUnchanged)
{
    std::string registryPath = "MY_HIVE\\Something";
    FimContextUtils::sanitizePath(registryPath, false);
    EXPECT_EQ(registryPath, "MY_HIVE\\Something");
}

TEST_F(FimInventoryUtils, DoubleBackslashesAreReduced)
{
    std::string registryPath = R"(HKEY_CURRENT_USER\\Software\\MyApp)";
    FimContextUtils::sanitizePath(registryPath, false);
    EXPECT_EQ(registryPath, "HKCU\\Software\\MyApp");
}

TEST_F(FimInventoryUtils, DoubleForwardSlashesAreReduced)
{
    std::string registryPath = "HKEY_CLASSES_ROOT//Software//MyApp";
    FimContextUtils::sanitizePath(registryPath, false);
    EXPECT_EQ(registryPath, "HKCR/Software/MyApp");
}

TEST_F(FimInventoryUtils, MixedSeparatorsAreNotUnified)
{
    std::string registryPath = "HKEY_CURRENT_CONFIG\\Software//MyApp";
    FimContextUtils::sanitizePath(registryPath, false);
    EXPECT_EQ(registryPath, "HKCC\\Software/MyApp");
}

TEST_F(FimInventoryUtils, AppendsValueNameIfRegistryOrigin)
{
    std::string registryPath = "HKEY_USERS\\App\\Settings";
    FimContextUtils::sanitizePath(registryPath, true, "DataValue");
    EXPECT_EQ(registryPath, "HKU\\App\\Settings\\DataValue");
}

TEST_F(FimInventoryUtils, AppendsValueNameIfRegistryOriginIsId)
{
    std::string registryPath = "HKEY_USERS\\App\\Settings";
    FimContextUtils::sanitizePath(registryPath, true, "DataValue", true);
    EXPECT_EQ(registryPath, "HKU/App/Settings/DataValue");
}

TEST_F(FimInventoryUtils, AppendsSlashEvenIfValueNameIsEmpty)
{
    std::string registryPath = "HKEY_USERS\\App\\Settings";
    FimContextUtils::sanitizePath(registryPath, true, "");
    EXPECT_EQ(registryPath, "HKU\\App\\Settings\\");
}

TEST_F(FimInventoryUtils, EmptyStringInput)
{
    std::string registryPath;
    FimContextUtils::sanitizePath(registryPath, true, "Value");
    EXPECT_EQ(registryPath, "\\Value");
}
