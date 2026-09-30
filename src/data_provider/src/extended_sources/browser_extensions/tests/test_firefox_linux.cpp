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

#include <cstdlib>
#include <fstream>
#include <unistd.h>

namespace
{
    // Creates a fake home with one Firefox profile whose extensions.json is either a regular file or a symlink.
    size_t collectFromTempHome(bool symlinkedAddonsFile)
    {
        char tmpl[] = "/tmp/firefox_ext_test_XXXXXX";

        if (mkdtemp(tmpl) == nullptr)
        {
            return static_cast<size_t>(-1);
        }

        const std::string root = tmpl;
        const std::string profile = root + "/home/user/snap/firefox/common/.mozilla/firefox/abc.default";
        const std::string mkdirCmd = "mkdir -p '" + profile + "'";
        (void)!std::system(mkdirCmd.c_str());

        const std::string source = Utils::joinPaths(Utils::getParentPath((__FILE__)),
                                                    "linux/mock-user/snap/firefox/common/.mozilla/firefox/pwd5bwxx.default/extensions.json");

        if (symlinkedAddonsFile)
        {
            (void)!symlink(source.c_str(), (profile + "/extensions.json").c_str());
        }
        else
        {
            std::ifstream in(source, std::ios::binary);
            std::ofstream out(profile + "/extensions.json", std::ios::binary);
            out << in.rdbuf();
        }

        auto mockAddonsWrapper = std::make_shared<MockBrowserExtensionsWrapper>();
        EXPECT_CALL(*mockAddonsWrapper, getHomePath()).WillRepeatedly(::testing::Return(root + "/home"));
        EXPECT_CALL(*mockAddonsWrapper, getUserId(::testing::_)).WillRepeatedly(::testing::Return("1000"));

        FirefoxAddonsProvider firefoxAddonsProvider(mockAddonsWrapper);
        const size_t count = firefoxAddonsProvider.collect().size();

        const std::string rmCmd = "rm -rf '" + root + "'";
        (void)!std::system(rmCmd.c_str());
        return count;
    }
}

TEST(FirefoxAddonsTests, RegularExtensionsFileInTempHomeIsReported)
{
    EXPECT_EQ(collectFromTempHome(false), static_cast<size_t>(10));
}

TEST(FirefoxAddonsTests, SymlinkedExtensionsFileIsNotFollowed)
{
    EXPECT_EQ(collectFromTempHome(true), static_cast<size_t>(0));
}
