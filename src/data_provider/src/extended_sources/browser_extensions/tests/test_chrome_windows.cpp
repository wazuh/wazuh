/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "ibrowser_extensions_wrapper.hpp"
#include "chrome.hpp"
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "filesystemHelper.h"
#include <filesystem>
#include <fstream>

class MockBrowserExtensionsWrapper : public IBrowserExtensionsWrapper
{
    public:
        MOCK_METHOD(std::string, getApplicationsPath, (), (override));
        MOCK_METHOD(std::string, getHomePath, (), (override));
        MOCK_METHOD(std::string, getUserId, (std::string), (override));
};

TEST(ChromeExtensionsTests, NumberOfExtensions)
{
    auto mockExtensionsWrapper = std::make_shared<MockBrowserExtensionsWrapper>();
    std::string mockHomePath = Utils::joinPaths(Utils::getParentPath((__FILE__)), "windows");

    EXPECT_CALL(*mockExtensionsWrapper, getHomePath()).WillRepeatedly(::testing::Return(mockHomePath));
    EXPECT_CALL(*mockExtensionsWrapper, getUserId(::testing::StrEq("mock-user"))).WillOnce(::testing::Return("123"));

    chrome::ChromeExtensionsProvider chromeExtensionsProvider(mockExtensionsWrapper);
    nlohmann::json extensionsJson = chromeExtensionsProvider.collect();
    ASSERT_EQ(extensionsJson.size(), static_cast<size_t>(5));
}

TEST(ChromeExtensionsTests, CollectReturnsExpectedJson)
{
    auto mockExtensionsWrapper = std::make_shared<MockBrowserExtensionsWrapper>();
    std::string mockHomePath = Utils::joinPaths(Utils::getParentPath((__FILE__)), "windows");

    EXPECT_CALL(*mockExtensionsWrapper, getHomePath()).WillRepeatedly(::testing::Return(mockHomePath));
    EXPECT_CALL(*mockExtensionsWrapper, getUserId(::testing::StrEq("mock-user"))).WillOnce(::testing::Return("123"));

    chrome::ChromeExtensionsProvider chromeExtensionsProvider(mockExtensionsWrapper);
    nlohmann::json extensionsJson = chromeExtensionsProvider.collect();

    for (const auto& jsonElement : extensionsJson)
    {
        if (jsonElement.contains("manifest_hash") && jsonElement["manifest_hash"] == "ac233e626b47562d9ae982f21deea7a8367105b4784b69d62c807b54f072e89f")
        {
            EXPECT_EQ(jsonElement["author"], "");
            EXPECT_EQ(jsonElement["browser_type"], "chrome");
            EXPECT_EQ(jsonElement["current_locale"], "");
            EXPECT_EQ(jsonElement["default_locale"], "en");
            EXPECT_EQ(jsonElement["description"], "Do more in Google Chrome with Adobe Acrobat PDF tools. View, fill, comment, sign, and try convert and compress tools.");
            EXPECT_EQ(jsonElement["from_webstore"], "1");
            EXPECT_EQ(jsonElement["identifier"], "efaidnbmnnnibpcajpcglclefindmkaj");
            EXPECT_EQ(jsonElement["install_time"], "13398894114840641");
            EXPECT_EQ(jsonElement["install_timestamp"], "1754420514");
            EXPECT_EQ(jsonElement["manifest_hash"], "ac233e626b47562d9ae982f21deea7a8367105b4784b69d62c807b54f072e89f");
            EXPECT_EQ(jsonElement["name"], "Adobe Acrobat: PDF edit, convert, sign tools");
            EXPECT_EQ(jsonElement["optional_permissions"], "history, bookmarks");
            EXPECT_EQ(jsonElement["path"], Utils::joinPaths(mockHomePath, R"(mock-user\AppData\Local\Google\Chrome\User Data\Default\Extensions\ext1\1.2.3)"));
            EXPECT_EQ(jsonElement["permissions"],
                      "contextMenus, tabs, downloads, nativeMessaging, webRequest, webNavigation, storage, scripting, alarms, offscreen, cookies, sidePanel");
            EXPECT_EQ(jsonElement["persistent"], "0");
            EXPECT_EQ(jsonElement["profile"], "Seu Chrome");
            EXPECT_EQ(jsonElement["profile_path"], Utils::joinPaths(mockHomePath, R"(mock-user\AppData\Local\Google\Chrome\User Data\Default)"));
            EXPECT_EQ(jsonElement["referenced"], "1");
            EXPECT_EQ(jsonElement["referenced_identifier"], "efaidnbmnnnibpcajpcglclefindmkaj");
            EXPECT_EQ(jsonElement["state"], "1");
            EXPECT_EQ(jsonElement["uid"], "123");
            EXPECT_EQ(jsonElement["update_url"], "https://clients2.google.com/service/update2/crx");
            EXPECT_EQ(jsonElement["version"], "25.7.2.1");
            break;
        }
    }
}

TEST(ChromeExtensionsTests, AbsoluteExtensionPathMustBeOnLocalFixedDrive)
{
    const auto home {std::filesystem::temp_directory_path() / "wazuh_chrome_local_path_test"};
    const auto profile {home / "mock-user" / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default"};
    const auto extensionDir {home / "unpacked"};
    std::filesystem::remove_all(home);
    std::filesystem::create_directories(profile);
    std::filesystem::create_directories(extensionDir);
    std::ofstream(extensionDir / "manifest.json") << R"({"name":"unpacked","version":"1.0"})";

    const auto collectWithPath = [&](const std::string & extensionPath)
    {
        nlohmann::json preferences;
        preferences["extensions"]["settings"]["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]["path"] = extensionPath;
        std::ofstream(profile / "Preferences", std::ios::trunc) << preferences.dump();

        auto mockExtensionsWrapper = std::make_shared<MockBrowserExtensionsWrapper>();
        EXPECT_CALL(*mockExtensionsWrapper, getHomePath()).WillRepeatedly(::testing::Return(home.string()));
        EXPECT_CALL(*mockExtensionsWrapper, getUserId(::testing::_)).WillRepeatedly(::testing::Return(""));

        chrome::ChromeExtensionsProvider chromeExtensionsProvider(mockExtensionsWrapper);
        return chromeExtensionsProvider.collect().size();
    };

    EXPECT_EQ(collectWithPath(extensionDir.string()), static_cast<size_t>(1));
    EXPECT_EQ(collectWithPath(R"(\\?\)" + extensionDir.string()), static_cast<size_t>(0));
    EXPECT_EQ(collectWithPath(R"(\\10.0.0.5\share\ext)"), static_cast<size_t>(0));

    std::filesystem::remove_all(home);
}
