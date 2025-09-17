/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "browser_extensions_wrapper.hpp"
#include "firefox.hpp"
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "filesystemHelper.h"

class MockBrowserExtensionsWrapper : public IBrowserExtensionsWrapper
{
    public:
        MOCK_METHOD(std::string, getApplicationsPath, (), (override));
        MOCK_METHOD(std::string, getHomePath, (), (override));
        MOCK_METHOD(std::string, getUserId, (std::string), (override));
};

TEST(FirefoxAddonsTests, NumberOfExtensions)
{
    auto mockAddonsWrapper = std::make_shared<MockBrowserExtensionsWrapper>();
    std::string mockHomePath = Utils::joinPaths(Utils::getParentPath((__FILE__)), "darwin");

    EXPECT_CALL(*mockAddonsWrapper, getHomePath()).WillRepeatedly(::testing::Return(mockHomePath));
    EXPECT_CALL(*mockAddonsWrapper, getUserId(::testing::StrEq("mock-user"))).WillRepeatedly(::testing::Return("123"));

    FirefoxAddonsProvider firefoxAddonsProvider(mockAddonsWrapper);
    nlohmann::json extensionsJson = firefoxAddonsProvider.collect();
    ASSERT_EQ(extensionsJson.size(), static_cast<size_t>(9));
}

TEST(FirefoxAddonsTests, CollectReturnsExpectedJson)
{
    auto mockAddonsWrapper = std::make_shared<MockBrowserExtensionsWrapper>();
    std::string mockHomePath = Utils::joinPaths(Utils::getParentPath((__FILE__)), "darwin");

    EXPECT_CALL(*mockAddonsWrapper, getHomePath()).WillRepeatedly(::testing::Return(mockHomePath));
    EXPECT_CALL(*mockAddonsWrapper, getUserId(::testing::StrEq("mock-user"))).WillRepeatedly(::testing::Return("123"));

    FirefoxAddonsProvider firefoxAddonsProvider(mockAddonsWrapper);
    nlohmann::json extensionsJson = firefoxAddonsProvider.collect();

    for (const auto& jsonElement : extensionsJson)
    {
        if (jsonElement.contains("name") && jsonElement["name"] == "Add-ons Search Detection")
        {
            EXPECT_EQ(jsonElement["active"], true);
            EXPECT_EQ(jsonElement["autoupdate"], true);
            EXPECT_EQ(jsonElement["creator"], "");
            EXPECT_EQ(jsonElement["description"], "");
            EXPECT_EQ(jsonElement["disabled"], false);
            EXPECT_EQ(jsonElement["identifier"], "addons-search-detection@mozilla.com");
            EXPECT_EQ(jsonElement["location"], "app-builtin-addons");
            EXPECT_EQ(jsonElement["name"], "Add-ons Search Detection");
            EXPECT_EQ(jsonElement["path"], "");
            EXPECT_EQ(jsonElement["source_url"], "");
            EXPECT_EQ(jsonElement["type"], "extension");
            EXPECT_EQ(jsonElement["uid"], "123");
            EXPECT_EQ(jsonElement["version"], "2.0.0");
            EXPECT_EQ(jsonElement["visible"], true);
        }
    }
}
