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
    std::string mockHomePath = Utils::joinPaths(Utils::getParentPath((__FILE__)), "linux");

    EXPECT_CALL(*mockExtensionsWrapper, getHomePath()).WillRepeatedly(::testing::Return(mockHomePath));
    EXPECT_CALL(*mockExtensionsWrapper, getUserId(::testing::StrEq("mock-user"))).WillOnce(::testing::Return("123"));

    chrome::ChromeExtensionsProvider chromeExtensionsProvider(mockExtensionsWrapper);
    nlohmann::json extensionsJson = chromeExtensionsProvider.collect();
    ASSERT_EQ(extensionsJson.size(), static_cast<size_t>(5));
}

TEST(ChromeExtensionsTests, CollectReturnsExpectedJson)
{
    auto mockExtensionsWrapper = std::make_shared<MockBrowserExtensionsWrapper>();
    std::string mockHomePath = Utils::joinPaths(Utils::getParentPath((__FILE__)), "linux");

    EXPECT_CALL(*mockExtensionsWrapper, getHomePath()).WillRepeatedly(::testing::Return(mockHomePath));
    EXPECT_CALL(*mockExtensionsWrapper, getUserId(::testing::StrEq("mock-user"))).WillOnce(::testing::Return("123"));

    chrome::ChromeExtensionsProvider chromeExtensionsProvider(mockExtensionsWrapper);
    nlohmann::json extensionsJson = chromeExtensionsProvider.collect();

    for (const auto& jsonElement : extensionsJson)
    {
        if (jsonElement.contains("manifest_hash") && jsonElement["manifest_hash"] == "5dbdf0ed368be287abaff83d639b760fa5d7dc8a28e92387773b4fd3e1ba4f19")
        {
            EXPECT_EQ(jsonElement["author"], "");
            EXPECT_EQ(jsonElement["browser_type"], "chrome");
            EXPECT_EQ(jsonElement["current_locale"], "");
            EXPECT_EQ(jsonElement["default_locale"], "en");
            EXPECT_EQ(jsonElement["description"], "Chrome Web Store Payments");
            EXPECT_EQ(jsonElement["from_webstore"], "1");
            EXPECT_EQ(jsonElement["identifier"], "nmmhkkegccagdldgiimedpiccmgmieda");
            EXPECT_EQ(jsonElement["install_time"], "13394392373345452");
            EXPECT_EQ(jsonElement["install_timestamp"], "1749918773");
            EXPECT_EQ(jsonElement["manifest_hash"], "5dbdf0ed368be287abaff83d639b760fa5d7dc8a28e92387773b4fd3e1ba4f19");
            EXPECT_EQ(jsonElement["name"], "Chrome Web Store Payments");
            EXPECT_EQ(jsonElement["optional_permissions"], "");
            EXPECT_EQ(jsonElement["path"], Utils::joinPaths(mockHomePath, "mock-user/.config/google-chrome/Profile 1/Extensions/ext2/1.2.3"));
            EXPECT_EQ(jsonElement["permissions"],
                      "identity, webview, https://www.google.com/, https://www.googleapis.com/*, https://payments.google.com/payments/v4/js/integrator.js, https://sandbox.google.com/payments/v4/js/integrator.js");
            EXPECT_EQ(jsonElement["persistent"], "0");
            EXPECT_EQ(jsonElement["profile"], "Your Chrome");
            EXPECT_EQ(jsonElement["profile_path"], Utils::joinPaths(mockHomePath, "mock-user/.config/google-chrome/Profile 1"));
            EXPECT_EQ(jsonElement["referenced"], "1");
            EXPECT_EQ(jsonElement["referenced_identifier"], "nmmhkkegccagdldgiimedpiccmgmieda");
            EXPECT_EQ(jsonElement["state"], "1");
            EXPECT_EQ(jsonElement["uid"], "123");
            EXPECT_EQ(jsonElement["update_url"], "https://clients2.google.com/service/update2/crx");
            EXPECT_EQ(jsonElement["version"], "1.0.0.6");
        }
    }
}

#include <cstdlib>
#include <fstream>
#include <unistd.h>
#include <sys/stat.h>

namespace
{
    const char* const VALID_MANIFEST = R"({"name": "Fake Extension", "version": "1.0", "description": "fake"})";

    // Builds a fake home with one Chrome profile in a temporary directory and removes it afterwards.
    class ChromeTempHomeTests : public ::testing::Test
    {
        protected:
            void SetUp() override
            {
                char tmpl[] = "/tmp/chrome_ext_test_XXXXXX";
                ASSERT_NE(mkdtemp(tmpl), nullptr);
                m_root = tmpl;
                m_home = m_root + "/home";
                m_profile = m_home + "/user/.config/google-chrome/Default";
                m_outside = m_root + "/outside";
                makeDirs(m_profile + "/Extensions");
                makeDirs(m_outside);
                writeFile(m_profile + "/Preferences", R"({"profile": {"name": "Test"}, "extensions": {"settings": {}}})");
                writeFile(m_profile + "/Secure Preferences", "{}");
            }

            void TearDown() override
            {
                if (!m_root.empty())
                {
                    const std::string cmd = "rm -rf '" + m_root + "'";
                    (void)!std::system(cmd.c_str());
                }
            }

            static void makeDirs(const std::string& path)
            {
                const std::string cmd = "mkdir -p '" + path + "'";
                ASSERT_EQ(std::system(cmd.c_str()), 0);
            }

            static void writeFile(const std::string& path, const std::string& content)
            {
                std::ofstream file(path, std::ios::binary);
                file << content;
            }

            nlohmann::json collect()
            {
                auto mockWrapper = std::make_shared<MockBrowserExtensionsWrapper>();
                EXPECT_CALL(*mockWrapper, getHomePath()).WillRepeatedly(::testing::Return(m_home));
                EXPECT_CALL(*mockWrapper, getUserId(::testing::_)).WillRepeatedly(::testing::Return("1000"));
                chrome::ChromeExtensionsProvider provider(mockWrapper);
                return provider.collect();
            }

            std::string m_root;
            std::string m_home;
            std::string m_profile;
            std::string m_outside;
    };
}

TEST_F(ChromeTempHomeTests, UnreferencedRegularManifestIsReported)
{
    makeDirs(m_profile + "/Extensions/abc/1.0");
    writeFile(m_profile + "/Extensions/abc/1.0/manifest.json", VALID_MANIFEST);

    const auto result = collect();
    ASSERT_EQ(result.size(), static_cast<size_t>(1));
    EXPECT_EQ(result[0]["name"], "Fake Extension");
    EXPECT_EQ(result[0]["referenced"], "0");
    EXPECT_EQ(result[0]["manifest_hash"].get<std::string>().size(), static_cast<size_t>(64));
}

TEST_F(ChromeTempHomeTests, ReferencedAbsolutePathRegularManifestIsReported)
{
    makeDirs(m_outside + "/unpacked");
    writeFile(m_outside + "/unpacked/manifest.json", VALID_MANIFEST);
    writeFile(m_profile + "/Preferences",
              R"({"profile": {"name": "Test"}, "extensions": {"settings": {"abc": {"path": ")" + m_outside + R"(/unpacked"}}}})");

    const auto result = collect();
    ASSERT_EQ(result.size(), static_cast<size_t>(1));
    EXPECT_EQ(result[0]["referenced"], "1");
    EXPECT_EQ(result[0]["name"], "Fake Extension");
}

TEST_F(ChromeTempHomeTests, UnreferencedManifestSymlinkIsNotFollowed)
{
    writeFile(m_outside + "/manifest.json", VALID_MANIFEST);
    makeDirs(m_profile + "/Extensions/abc/1.0");
    ASSERT_EQ(symlink((m_outside + "/manifest.json").c_str(), (m_profile + "/Extensions/abc/1.0/manifest.json").c_str()), 0);

    EXPECT_EQ(collect().size(), static_cast<size_t>(0));
}

TEST_F(ChromeTempHomeTests, ReferencedManifestSymlinkIsNotFollowed)
{
    makeDirs(m_outside + "/unpacked");
    writeFile(m_outside + "/real.json", VALID_MANIFEST);
    ASSERT_EQ(symlink((m_outside + "/real.json").c_str(), (m_outside + "/unpacked/manifest.json").c_str()), 0);
    writeFile(m_profile + "/Preferences",
              R"({"profile": {"name": "Test"}, "extensions": {"settings": {"abc": {"path": ")" + m_outside + R"(/unpacked"}}}})");

    EXPECT_EQ(collect().size(), static_cast<size_t>(0));
}

TEST_F(ChromeTempHomeTests, SymlinkedExtensionDirectoryIsNotFollowed)
{
    makeDirs(m_outside + "/abc/1.0");
    writeFile(m_outside + "/abc/1.0/manifest.json", VALID_MANIFEST);
    ASSERT_EQ(symlink((m_outside + "/abc").c_str(), (m_profile + "/Extensions/abc").c_str()), 0);

    EXPECT_EQ(collect().size(), static_cast<size_t>(0));
}

TEST_F(ChromeTempHomeTests, SymlinkedVersionDirectoryIsNotFollowed)
{
    makeDirs(m_outside + "/1.0");
    writeFile(m_outside + "/1.0/manifest.json", VALID_MANIFEST);
    makeDirs(m_profile + "/Extensions/abc");
    ASSERT_EQ(symlink((m_outside + "/1.0").c_str(), (m_profile + "/Extensions/abc/1.0").c_str()), 0);

    EXPECT_EQ(collect().size(), static_cast<size_t>(0));
}

TEST_F(ChromeTempHomeTests, FifoManifestDoesNotBlock)
{
    makeDirs(m_profile + "/Extensions/abc/1.0");
    ASSERT_EQ(mkfifo((m_profile + "/Extensions/abc/1.0/manifest.json").c_str(), 0600), 0);

    EXPECT_EQ(collect().size(), static_cast<size_t>(0));
}

TEST_F(ChromeTempHomeTests, OversizedManifestIsSkipped)
{
    makeDirs(m_profile + "/Extensions/abc/1.0");
    const std::string manifest = m_profile + "/Extensions/abc/1.0/manifest.json";
    // Valid JSON padded with whitespace past the read limit.
    writeFile(manifest, VALID_MANIFEST + std::string(17 * 1024 * 1024, ' '));

    EXPECT_EQ(collect().size(), static_cast<size_t>(0));
}
