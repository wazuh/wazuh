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
#include "stringHelper.h"
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

class ChromeExtensionsMalformedFilesTests : public ::testing::Test
{
    protected:
        std::filesystem::path m_homePath;

        void SetUp() override
        {
            m_homePath = std::filesystem::temp_directory_path() /
                         ("chrome_extensions_test_" + std::string(::testing::UnitTest::GetInstance()->current_test_info()->name()));
            std::filesystem::remove_all(m_homePath);
        }

        void TearDown() override
        {
            std::filesystem::remove_all(m_homePath);
        }

        void writeFile(const std::filesystem::path& relativePath, const std::string& content)
        {
            const auto fullPath = m_homePath / relativePath;
            std::filesystem::create_directories(fullPath.parent_path());
            std::ofstream file(fullPath);
            file << content;
        }

        nlohmann::json collect()
        {
            auto mockExtensionsWrapper = std::make_shared<MockBrowserExtensionsWrapper>();
            EXPECT_CALL(*mockExtensionsWrapper, getHomePath()).WillRepeatedly(::testing::Return(m_homePath.string()));
            EXPECT_CALL(*mockExtensionsWrapper, getUserId(::testing::_)).WillRepeatedly(::testing::Return("1000"));

            chrome::ChromeExtensionsProvider chromeExtensionsProvider(mockExtensionsWrapper);
            return chromeExtensionsProvider.collect();
        }

        static const nlohmann::json* findByName(const nlohmann::json& extensions, const std::string& name)
        {
            for (const auto& extension : extensions)
            {
                if (extension["name"] == name)
                {
                    return &extension;
                }
            }

            return nullptr;
        }

        static const nlohmann::json* findByPathSuffix(const nlohmann::json& extensions, const std::string& suffix)
        {
            for (const auto& extension : extensions)
            {
                if (Utils::endsWith(extension["path"].get<std::string>(), suffix))
                {
                    return &extension;
                }
            }

            return nullptr;
        }
};

TEST_F(ChromeExtensionsMalformedFilesTests, UnexpectedFieldTypesDoNotDropOtherExtensions)
{
    const std::string profile = "bad-user/.config/google-chrome/Default/";

    writeFile(profile + "Preferences", R"({
        "profile": {"name": 5},
        "extensions": {"settings": {
            "refbad": {"path": "refbad/1.0", "state": "enabled", "from_webstore": "yes", "first_install_time": 13394392373345452},
            "refparent": {"path": "../../other"},
            "refnonstring": {"path": 42}
        }}
    })");
    writeFile(profile + "Secure Preferences", "{}");
    writeFile(profile + "Extensions/refbad/1.0/manifest.json", R"({"name": "Ref Bad", "version": "1.0", "background": {"persistent": "true"}})");
    writeFile(profile + "Extensions/unrefbad/1.0/manifest.json",
              R"({"name": ["x"], "version": 1, "description": {"a": 1}, "key": 7, "author": 3, "update_url": false, "default_locale": "en", "background": 1})");
    writeFile(profile + "Extensions/unrefbad/1.0/_locales/en/messages.json", "{not json");
    writeFile(profile + "Extensions/unreflocale/2.0/manifest.json", R"({"name": "__MSG_appName__", "version": "2.0", "default_locale": "en"})");
    writeFile(profile + "Extensions/unreflocale/2.0/_locales/en/messages.json", R"({"appName": "not an object"})");
    writeFile(profile + "Extensions/broken/1.0/manifest.json", "{not json");

    writeFile("good-user/.config/google-chrome/Default/Preferences", R"({"extensions": "not an object"})");
    writeFile("good-user/.config/google-chrome/Default/Secure Preferences", "{}");
    writeFile("good-user/.config/google-chrome/Default/Extensions/good/1.0/manifest.json", R"({"name": "Good", "version": "1.0"})");

    nlohmann::json extensionsJson;
    ASSERT_NO_THROW(extensionsJson = collect());
    ASSERT_EQ(extensionsJson.size(), static_cast<size_t>(4));

    const auto* refBad = findByName(extensionsJson, "Ref Bad");
    ASSERT_NE(refBad, nullptr);
    EXPECT_EQ((*refBad)["referenced"], "1");
    EXPECT_EQ((*refBad)["state"], "1");
    EXPECT_EQ((*refBad)["from_webstore"], "0");
    EXPECT_EQ((*refBad)["install_time"], "");
    EXPECT_EQ((*refBad)["persistent"], "0");
    EXPECT_EQ((*refBad)["profile"], "");

    const auto* unrefBad = findByPathSuffix(extensionsJson, "unrefbad/1.0");
    ASSERT_NE(unrefBad, nullptr);
    EXPECT_EQ((*unrefBad)["referenced"], "0");
    EXPECT_EQ((*unrefBad)["name"], "");
    EXPECT_EQ((*unrefBad)["version"], "");
    EXPECT_EQ((*unrefBad)["description"], "");
    EXPECT_EQ((*unrefBad)["author"], "");
    EXPECT_EQ((*unrefBad)["update_url"], "");
    EXPECT_EQ((*unrefBad)["identifier"], "");
    EXPECT_EQ((*unrefBad)["persistent"], "0");

    const auto* unrefLocale = findByPathSuffix(extensionsJson, "unreflocale/2.0");
    ASSERT_NE(unrefLocale, nullptr);
    EXPECT_EQ((*unrefLocale)["name"], "__MSG_appName__");
    EXPECT_EQ((*unrefLocale)["version"], "2.0");

    const auto* good = findByName(extensionsJson, "Good");
    ASSERT_NE(good, nullptr);
    EXPECT_EQ((*good)["version"], "1.0");
    EXPECT_EQ((*good)["uid"], "1000");

    EXPECT_EQ(findByPathSuffix(extensionsJson, "broken/1.0"), nullptr);
}

TEST_F(ChromeExtensionsMalformedFilesTests, InvalidManifestOnlySkipsThatExtension)
{
    const std::string profile = "user/.config/google-chrome/Default/";

    writeFile(profile + "Preferences", "{}");
    writeFile(profile + "Secure Preferences", "{}");
    writeFile(profile + "Extensions/broken/1.0/manifest.json", "{not json");
    writeFile(profile + "Extensions/array/1.0/manifest.json", "[1, 2, 3]");
    writeFile(profile + "Extensions/good/1.0/manifest.json", R"({"name": "Good", "version": "1.0"})");

    nlohmann::json extensionsJson;
    ASSERT_NO_THROW(extensionsJson = collect());
    ASSERT_EQ(extensionsJson.size(), static_cast<size_t>(2));

    const auto* arrayManifest = findByPathSuffix(extensionsJson, "array/1.0");
    ASSERT_NE(arrayManifest, nullptr);
    EXPECT_EQ((*arrayManifest)["name"], "");
    EXPECT_EQ((*arrayManifest)["version"], "");

    EXPECT_NE(findByName(extensionsJson, "Good"), nullptr);
    EXPECT_EQ(findByPathSuffix(extensionsJson, "broken/1.0"), nullptr);
}

TEST_F(ChromeExtensionsMalformedFilesTests, DefaultLocaleMustBeAPlainLocaleName)
{
    const std::string profile = "user/.config/google-chrome/Default/";
    const std::string messages = R"({"appName": {"message": "Localized"}})";

    writeFile(profile + "Preferences", "{}");
    writeFile(profile + "Secure Preferences", "{}");

    writeFile(profile + "Extensions/nested/1.0/manifest.json", R"({"name": "__MSG_appName__", "version": "1.0", "default_locale": "en/US"})");
    writeFile(profile + "Extensions/nested/1.0/_locales/en/US/messages.json", messages);
    writeFile(profile + "Extensions/empty/1.0/manifest.json", R"({"name": "__MSG_appName__", "version": "1.0", "default_locale": ""})");
    writeFile(profile + "Extensions/empty/1.0/_locales/messages.json", messages);
    writeFile(profile + "Extensions/valid/1.0/manifest.json", R"({"name": "__MSG_appName__", "version": "1.0", "default_locale": "pt_BR"})");
    writeFile(profile + "Extensions/valid/1.0/_locales/pt_BR/messages.json", messages);

    nlohmann::json extensionsJson;
    ASSERT_NO_THROW(extensionsJson = collect());
    ASSERT_EQ(extensionsJson.size(), static_cast<size_t>(3));

    const auto* nested = findByPathSuffix(extensionsJson, "nested/1.0");
    ASSERT_NE(nested, nullptr);
    EXPECT_EQ((*nested)["name"], "__MSG_appName__");

    const auto* empty = findByPathSuffix(extensionsJson, "empty/1.0");
    ASSERT_NE(empty, nullptr);
    EXPECT_EQ((*empty)["name"], "__MSG_appName__");

    const auto* valid = findByPathSuffix(extensionsJson, "valid/1.0");
    ASSERT_NE(valid, nullptr);
    EXPECT_EQ((*valid)["name"], "Localized");
}
