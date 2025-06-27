/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "ibrowser_extensions_wrapper.hpp"
#include "safari_darwin.hpp"
#include <string>
#include "filesystemHelper.h"
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <unistd.h>

class MockBrowserExtensionsWrapper : public IBrowserExtensionsWrapper
{
    public:
        MOCK_METHOD(std::string, getApplicationsPath, (), (override));
};

TEST(BrowserExtensionsTests, IgnoresNonExtensionApp)
{
    auto mockExtensionsWrapper = std::make_shared<MockBrowserExtensionsWrapper>();
    std::string appsPath = Utils::getParentPath(__FILE__) + "/input_files/apps_mock_dir";
    EXPECT_CALL(*mockExtensionsWrapper, getApplicationsPath()).WillOnce(::testing::Return(appsPath));

    SafariExtensionsProvider safariExtensionsProvider(mockExtensionsWrapper);
    nlohmann::json extensionsJson = safariExtensionsProvider.collect();

    // It should only detect 2 safari extensions.
    ASSERT_EQ(extensionsJson.size(), static_cast<size_t>(2));
}

TEST(BrowserExtensionsTests, CollectReturnsExpectedJson)
{
    auto mockExtensionsWrapper = std::make_shared<MockBrowserExtensionsWrapper>();
    std::string appsPath = Utils::getParentPath(__FILE__) + "/input_files/apps_mock_dir";
    EXPECT_CALL(*mockExtensionsWrapper, getApplicationsPath()).WillOnce(::testing::Return(appsPath));

    SafariExtensionsProvider safariExtensionsProvider(mockExtensionsWrapper);
    nlohmann::json extensionsJson = safariExtensionsProvider.collect();

    std::string uidString = std::to_string(getuid());
    // The darker Info.plist file is in standard XML format
    std::string darkerPath = appsPath + "/darker.app/Contents/PlugIns/darker Extension.appex/Contents/Info.plist";
    // The JSONPeep Info.plist file is in binary format
    std::string jsonPeepsPath = appsPath + "/JSONPeep.app/Contents/PlugIns/JSONPeep Extension.appex/Contents/Info.plist";
    // Testing darker extension
    EXPECT_EQ(extensionsJson[0]["bundle_version"], "6");
    EXPECT_EQ(extensionsJson[0]["copyright"], "");
    EXPECT_EQ(extensionsJson[0]["description"], "");
    EXPECT_EQ(extensionsJson[0]["identifier"], "com.doukan.darker.Extension");
    EXPECT_EQ(extensionsJson[0]["name"], "darker Extension");
    EXPECT_EQ(extensionsJson[0]["path"], darkerPath);
    EXPECT_EQ(extensionsJson[0]["sdk"], "6.0");
    EXPECT_EQ(extensionsJson[0]["uid"], uidString);
    EXPECT_EQ(extensionsJson[0]["version"], "1.4");

    // Testing JSONPeep extension
    EXPECT_EQ(extensionsJson[1]["bundle_version"], "13");
    EXPECT_EQ(extensionsJson[1]["copyright"], "Copyright © 2019 Lev Bruk. All rights reserved.");
    EXPECT_EQ(extensionsJson[1]["description"], "A Safari Extension to view JSON in a readable format. Smooth and simple. Nothing more.");
    EXPECT_EQ(extensionsJson[1]["identifier"], "com.levbruk.JSONPeep.Extension");
    EXPECT_EQ(extensionsJson[1]["name"], "JSON Peep");
    EXPECT_EQ(extensionsJson[1]["path"], jsonPeepsPath);
    EXPECT_EQ(extensionsJson[1]["sdk"], "6.0");
    EXPECT_EQ(extensionsJson[1]["uid"], uidString);
    EXPECT_EQ(extensionsJson[1]["version"], "1.3.2");
}
