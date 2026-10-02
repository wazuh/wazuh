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
#include <filesystem>
#include <fstream>

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
    std::string mockHomePath = Utils::joinPaths(Utils::getParentPath((__FILE__)), "linux");

    EXPECT_CALL(*mockAddonsWrapper, getHomePath()).WillRepeatedly(::testing::Return(mockHomePath));
    EXPECT_CALL(*mockAddonsWrapper, getUserId(::testing::StrEq("mock-user"))).WillRepeatedly(::testing::Return("123"));

    FirefoxAddonsProvider firefoxAddonsProvider(mockAddonsWrapper);
    nlohmann::json extensionsJson = firefoxAddonsProvider.collect();
    ASSERT_EQ(extensionsJson.size(), static_cast<size_t>(10));
}

TEST(FirefoxAddonsTests, CollectReturnsExpectedJson)
{
    auto mockAddonsWrapper = std::make_shared<MockBrowserExtensionsWrapper>();
    std::string mockHomePath = Utils::joinPaths(Utils::getParentPath((__FILE__)), "linux");

    EXPECT_CALL(*mockAddonsWrapper, getHomePath()).WillRepeatedly(::testing::Return(mockHomePath));
    EXPECT_CALL(*mockAddonsWrapper, getUserId(::testing::StrEq("mock-user"))).WillRepeatedly(::testing::Return("123"));

    FirefoxAddonsProvider firefoxAddonsProvider(mockAddonsWrapper);
    nlohmann::json extensionsJson = firefoxAddonsProvider.collect();

    for (const auto& jsonElement : extensionsJson)
    {
        if (jsonElement.contains("creator") && jsonElement["creator"] == "mozilla.org")
        {
            EXPECT_EQ(jsonElement["active"], true);
            EXPECT_EQ(jsonElement["autoupdate"], true);
            EXPECT_EQ(jsonElement["creator"], "mozilla.org");
            EXPECT_EQ(jsonElement["description"], "Firefox Language Pack for English (US) (en-US)");
            EXPECT_EQ(jsonElement["disabled"], false);
            EXPECT_EQ(jsonElement["identifier"], "langpack-en-US@firefox.mozilla.org");
            EXPECT_EQ(jsonElement["location"], "app-profile");
            EXPECT_EQ(jsonElement["name"], "Language: English (US)");
            EXPECT_EQ(jsonElement["path"], "/linux/mock-user/snap/firefox/common/.mozilla/firefox/pwd5bwxx.default/extensions/langpack-en-US@firefox.mozilla.org.xpi");
            EXPECT_EQ(jsonElement["source_url"], "");
            EXPECT_EQ(jsonElement["type"], "locale");
            EXPECT_EQ(jsonElement["uid"], "123");
            EXPECT_EQ(jsonElement["version"], "141.0.20250806.102122");
            EXPECT_EQ(jsonElement["visible"], true);
        }
    }
}

TEST(FirefoxAddonsTests, UnexpectedFieldTypesDoNotDropOtherAddons)
{
    const auto homePath = std::filesystem::temp_directory_path() / "firefox_addons_test_unexpected_field_types";
    std::filesystem::remove_all(homePath);

    const auto writeFile = [&homePath](const std::string & relativePath, const std::string & content)
    {
        const auto fullPath = homePath / relativePath;
        std::filesystem::create_directories(fullPath.parent_path());
        std::ofstream file(fullPath);
        file << content;
    };

    writeFile("bad-user/.mozilla/firefox/abc.default/extensions.json", R"({"addons": [
        {"id": 5, "version": 1, "type": [], "sourceURI": 9, "location": 3, "path": false,
         "defaultLocale": {"name": ["x"], "creator": {"n": 1}, "description": 2},
         "softDisabled": "yes", "visible": "true", "active": 1, "applyBackgroundUpdates": "1"},
        {"id": "typed@addon", "version": "1.0", "defaultLocale": "not an object",
         "userDisabled": true, "visible": true, "active": true, "applyBackgroundUpdates": 1},
        {"id": "soft@addon", "version": "1.0", "softDisabled": true, "userDisabled": false, "appDisabled": false},
        "not an object"
    ]})");
    writeFile("good-user/.mozilla/firefox/def.default/extensions.json",
              R"({"addons": [{"id": "good@addon", "version": "2.0", "defaultLocale": {"name": "Good"}}]})");

    auto mockAddonsWrapper = std::make_shared<MockBrowserExtensionsWrapper>();
    EXPECT_CALL(*mockAddonsWrapper, getHomePath()).WillRepeatedly(::testing::Return(homePath.string()));
    EXPECT_CALL(*mockAddonsWrapper, getUserId(::testing::_)).WillRepeatedly(::testing::Return("1000"));

    FirefoxAddonsProvider firefoxAddonsProvider(mockAddonsWrapper);
    nlohmann::json extensionsJson;
    ASSERT_NO_THROW(extensionsJson = firefoxAddonsProvider.collect());
    std::filesystem::remove_all(homePath);

    ASSERT_EQ(extensionsJson.size(), static_cast<size_t>(5));

    const auto findById = [&extensionsJson](const std::string & id) -> const nlohmann::json *
    {
        for (const auto& extension : extensionsJson)
        {
            if (extension["identifier"] == id)
            {
                return &extension;
            }
        }

        return nullptr;
    };

    const auto* typed = findById("typed@addon");
    ASSERT_NE(typed, nullptr);
    EXPECT_EQ((*typed)["name"], "");
    EXPECT_EQ((*typed)["version"], "1.0");
    EXPECT_EQ((*typed)["disabled"], true);
    EXPECT_EQ((*typed)["visible"], true);
    EXPECT_EQ((*typed)["active"], true);
    EXPECT_EQ((*typed)["autoupdate"], true);

    const auto* soft = findById("soft@addon");
    ASSERT_NE(soft, nullptr);
    EXPECT_EQ((*soft)["disabled"], true);

    const auto* good = findById("good@addon");
    ASSERT_NE(good, nullptr);
    EXPECT_EQ((*good)["name"], "Good");
    EXPECT_EQ((*good)["version"], "2.0");

    size_t emptyIdentifiers = 0;

    for (const auto& extension : extensionsJson)
    {
        if (extension["identifier"] == "")
        {
            ++emptyIdentifiers;
            EXPECT_EQ(extension["name"], "");
            EXPECT_EQ(extension["version"], "");
            EXPECT_EQ(extension["creator"], "");
            EXPECT_EQ(extension["path"], "");
            EXPECT_EQ(extension["disabled"], false);
            EXPECT_EQ(extension["visible"], false);
            EXPECT_EQ(extension["active"], false);
            EXPECT_EQ(extension["autoupdate"], false);
        }
    }

    EXPECT_EQ(emptyIdentifiers, static_cast<size_t>(2));
}
