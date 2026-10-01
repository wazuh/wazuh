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
    enum class AddonsLayout
    {
        REGULAR,
        SYMLINKED_FILE,
        SYMLINKED_PROFILE
    };

    // Creates a fake home with one Firefox profile, collects it and returns the number of add-ons reported.
    // Returns (size_t)-1 if the fake home cannot be created.
    size_t collectFromTempHome(AddonsLayout layout)
    {
        char tmpl[] = "/tmp/firefox_ext_test_XXXXXX";

        if (mkdtemp(tmpl) == nullptr)
        {
            return static_cast<size_t>(-1);
        }

        const std::string root = tmpl;
        const std::string firefoxDir = root + "/home/user/snap/firefox/common/.mozilla/firefox";
        const std::string profile = firefoxDir + "/abc.default";
        const std::string realProfile = layout == AddonsLayout::SYMLINKED_PROFILE ? root + "/outside/abc.default" : profile;
        const std::string mkdirCmd = "mkdir -p '" + firefoxDir + "' '" + realProfile + "'";

        const std::string source = Utils::joinPaths(Utils::getParentPath((__FILE__)),
                                                    "linux/mock-user/snap/firefox/common/.mozilla/firefox/pwd5bwxx.default/extensions.json");
        bool ready = std::system(mkdirCmd.c_str()) == 0;

        if (ready && layout == AddonsLayout::SYMLINKED_FILE)
        {
            ready = symlink(source.c_str(), (profile + "/extensions.json").c_str()) == 0;
        }
        else if (ready)
        {
            std::ifstream in(source, std::ios::binary);
            std::ofstream out(realProfile + "/extensions.json", std::ios::binary);
            out << in.rdbuf();
            out.close();
            ready = in.good() && out.good();

            if (ready && layout == AddonsLayout::SYMLINKED_PROFILE)
            {
                ready = symlink(realProfile.c_str(), profile.c_str()) == 0;
            }
        }

        size_t count = static_cast<size_t>(-1);

        if (ready)
        {
            auto mockAddonsWrapper = std::make_shared<MockBrowserExtensionsWrapper>();
            EXPECT_CALL(*mockAddonsWrapper, getHomePath()).WillRepeatedly(::testing::Return(root + "/home"));
            EXPECT_CALL(*mockAddonsWrapper, getUserId(::testing::_)).WillRepeatedly(::testing::Return("1000"));

            FirefoxAddonsProvider firefoxAddonsProvider(mockAddonsWrapper);
            count = firefoxAddonsProvider.collect().size();
        }

        const std::string rmCmd = "rm -rf '" + root + "'";
        (void)!std::system(rmCmd.c_str());
        return count;
    }
}

TEST(FirefoxAddonsTests, RegularExtensionsFileInTempHomeIsReported)
{
    EXPECT_EQ(collectFromTempHome(AddonsLayout::REGULAR), static_cast<size_t>(10));
}

TEST(FirefoxAddonsTests, SymlinkedExtensionsFileIsNotFollowed)
{
    EXPECT_EQ(collectFromTempHome(AddonsLayout::SYMLINKED_FILE), static_cast<size_t>(0));
}

TEST(FirefoxAddonsTests, SymlinkedProfileDirectoryIsNotFollowed)
{
    EXPECT_EQ(collectFromTempHome(AddonsLayout::SYMLINKED_PROFILE), static_cast<size_t>(0));
}
