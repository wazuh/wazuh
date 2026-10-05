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
#include <unistd.h>
#include <sys/stat.h>
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


// The fixture files must belong to the profile owner, so the owner reported is whoever owns the checkout
static std::string fixtureOwner(const std::string& path)
{
    struct stat st {};
    return ::stat(path.c_str(), &st) == 0 ? std::to_string(st.st_uid) : "";
}

TEST(ChromeExtensionsTests, NumberOfExtensions)
{
    auto mockExtensionsWrapper = std::make_shared<MockBrowserExtensionsWrapper>();
    std::string mockHomePath = Utils::joinPaths(Utils::getParentPath((__FILE__)), "linux");

    EXPECT_CALL(*mockExtensionsWrapper, getHomePath()).WillRepeatedly(::testing::Return(mockHomePath));
    EXPECT_CALL(*mockExtensionsWrapper, getUserId(::testing::StrEq("mock-user"))).WillOnce(::testing::Return(fixtureOwner(mockHomePath)));

    chrome::ChromeExtensionsProvider chromeExtensionsProvider(mockExtensionsWrapper);
    nlohmann::json extensionsJson = chromeExtensionsProvider.collect();
    ASSERT_EQ(extensionsJson.size(), static_cast<size_t>(5));
}

TEST(ChromeExtensionsTests, CollectReturnsExpectedJson)
{
    auto mockExtensionsWrapper = std::make_shared<MockBrowserExtensionsWrapper>();
    std::string mockHomePath = Utils::joinPaths(Utils::getParentPath((__FILE__)), "linux");

    EXPECT_CALL(*mockExtensionsWrapper, getHomePath()).WillRepeatedly(::testing::Return(mockHomePath));
    EXPECT_CALL(*mockExtensionsWrapper, getUserId(::testing::StrEq("mock-user"))).WillOnce(::testing::Return(fixtureOwner(mockHomePath)));

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
            EXPECT_EQ(jsonElement["uid"], fixtureOwner(mockHomePath));
            EXPECT_EQ(jsonElement["update_url"], "https://clients2.google.com/service/update2/crx");
            EXPECT_EQ(jsonElement["version"], "1.0.0.6");
        }
    }
}

#include <cstdlib>
#include <fstream>
#include <stdexcept>

namespace
{
    const uid_t NOBODY_UID = 65534;
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

            // The helpers throw on failure, so that the calling test stops and is reported as failed
            static void makeDirs(const std::string& path)
            {
                const std::string cmd = "mkdir -p '" + path + "'";

                if (std::system(cmd.c_str()) != 0)
                {
                    throw std::runtime_error("cannot create " + path);
                }
            }

            static void writeFile(const std::string& path, const std::string& content)
            {
                std::ofstream file(path, std::ios::binary);
                file << content;
                file.close();

                if (!file)
                {
                    throw std::runtime_error("cannot write " + path);
                }
            }

            nlohmann::json collect()
            {
                auto mockWrapper = std::make_shared<MockBrowserExtensionsWrapper>();
                EXPECT_CALL(*mockWrapper, getHomePath()).WillRepeatedly(::testing::Return(m_home));
                EXPECT_CALL(*mockWrapper, getUserId(::testing::_)).WillRepeatedly(::testing::Return(m_uid));
                chrome::ChromeExtensionsProvider provider(mockWrapper);
                return provider.collect();
            }

            std::string m_root;
            std::string m_home;
            std::string m_profile;
            std::string m_outside;
            // Owner reported for the profile, the files of the fake home belong to the current user
            std::string m_uid = std::to_string(geteuid());
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

TEST_F(ChromeTempHomeTests, ReferencedRelativePathRegularManifestIsReported)
{
    makeDirs(m_profile + "/Extensions/abc/1.0");
    writeFile(m_profile + "/Extensions/abc/1.0/manifest.json", VALID_MANIFEST);
    writeFile(m_profile + "/Preferences",
              R"({"profile": {"name": "Test"}, "extensions": {"settings": {"abc": {"path": "abc/1.0"}}}})");

    const auto result = collect();
    ASSERT_EQ(result.size(), static_cast<size_t>(1));
    EXPECT_EQ(result[0]["referenced"], "1");
}

// Every directory of a relative path is checked, not only the last one
TEST_F(ChromeTempHomeTests, ReferencedRelativePathThroughSymlinkedDirectoryIsNotFollowed)
{
    makeDirs(m_outside + "/abc/1.0");
    writeFile(m_outside + "/abc/1.0/manifest.json", VALID_MANIFEST);
    ASSERT_EQ(symlink((m_outside + "/abc").c_str(), (m_profile + "/Extensions/abc").c_str()), 0);
    writeFile(m_profile + "/Preferences",
              R"({"profile": {"name": "Test"}, "extensions": {"settings": {"abc": {"path": "abc/1.0"}}}})");

    EXPECT_EQ(collect().size(), static_cast<size_t>(0));
}

// The reported hash is the SHA-256 of the manifest content that was parsed
TEST_F(ChromeTempHomeTests, ManifestHashMatchesManifestContent)
{
    makeDirs(m_profile + "/Extensions/abc/1.0");
    writeFile(m_profile + "/Extensions/abc/1.0/manifest.json", VALID_MANIFEST);

    const auto result = collect();
    ASSERT_EQ(result.size(), static_cast<size_t>(1));
    EXPECT_EQ(result[0]["manifest_hash"], "92e4e520f1143566b2603019e73cbcfa3a9bf61e17c7c47aa86acbf1bb85d9e3");
}

// Files that do not belong to the profile owner are not read
TEST_F(ChromeTempHomeTests, FilesOwnedByAnotherUserAreSkipped)
{
    makeDirs(m_profile + "/Extensions/abc/1.0");
    writeFile(m_profile + "/Extensions/abc/1.0/manifest.json", VALID_MANIFEST);
    m_uid = std::to_string(geteuid() + 1);

    EXPECT_EQ(collect().size(), static_cast<size_t>(0));
}

// A home directory whose name is not a known user name takes the owner of the directory as the profile owner
TEST_F(ChromeTempHomeTests, UnknownUserNameUsesHomeDirectoryOwner)
{
    makeDirs(m_profile + "/Extensions/abc/1.0");
    writeFile(m_profile + "/Extensions/abc/1.0/manifest.json", VALID_MANIFEST);
    m_uid = "";

    // A home directory owned by root is never used as the profile owner, so as root the home is given to nobody
    if (geteuid() == 0)
    {
        const std::string cmd = "chown -R " + std::to_string(NOBODY_UID) + " '" + m_home + "/user'";
        ASSERT_EQ(std::system(cmd.c_str()), 0);
    }

    const auto result = collect();
    ASSERT_EQ(result.size(), static_cast<size_t>(1));
    EXPECT_EQ(result[0]["uid"], "");
}

TEST_F(ChromeTempHomeTests, FifoPreferencesDoesNotBlock)
{
    makeDirs(m_profile + "/Extensions/abc/1.0");
    writeFile(m_profile + "/Extensions/abc/1.0/manifest.json", VALID_MANIFEST);
    ASSERT_EQ(::unlink((m_profile + "/Preferences").c_str()), 0);
    ASSERT_EQ(mkfifo((m_profile + "/Preferences").c_str(), 0600), 0);

    EXPECT_EQ(collect().size(), static_cast<size_t>(0));
}

TEST_F(ChromeTempHomeTests, ManifestAtTheSizeLimitIsReported)
{
    makeDirs(m_profile + "/Extensions/abc/1.0");
    const std::string manifest = VALID_MANIFEST;
    writeFile(m_profile + "/Extensions/abc/1.0/manifest.json", manifest + std::string(16 * 1024 * 1024 - manifest.size(), ' '));

    EXPECT_EQ(collect().size(), static_cast<size_t>(1));
}

TEST_F(ChromeTempHomeTests, DefaultLocaleIsLocalized)
{
    makeDirs(m_profile + "/Extensions/abc/1.0/_locales/en");
    writeFile(m_profile + "/Extensions/abc/1.0/manifest.json",
              R"({"name": "__MSG_appName__", "version": "1.0", "default_locale": "en"})");
    writeFile(m_profile + "/Extensions/abc/1.0/_locales/en/messages.json", R"({"appName": {"message": "Localized"}})");

    const auto result = collect();
    ASSERT_EQ(result.size(), static_cast<size_t>(1));
    EXPECT_EQ(result[0]["name"], "Localized");
}

// A default_locale that is not a single directory name is not used to build the messages path
TEST_F(ChromeTempHomeTests, DefaultLocaleOutsideTheExtensionIsNotRead)
{
    makeDirs(m_profile + "/Extensions/abc/1.0/_locales");
    writeFile(m_outside + "/messages.json", R"({"appName": {"message": "Outside"}})");

    // From <extension>/_locales, one ".." per directory up to the root of the fake home
    const std::string localesDir = m_profile + "/Extensions/abc/1.0/_locales";
    std::string upToRoot;

    for (size_t i = m_root.size(); i < localesDir.size(); ++i)
    {
        if (localesDir[i] == '/')
        {
            upToRoot += "../";
        }
    }

    writeFile(m_profile + "/Extensions/abc/1.0/manifest.json",
              R"({"name": "__MSG_appName__", "version": "1.0", "default_locale": ")" + upToRoot + R"(outside"})");

    const auto result = collect();
    ASSERT_EQ(result.size(), static_cast<size_t>(1));
    EXPECT_EQ(result[0]["name"], "__MSG_appName__");
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
            EXPECT_CALL(*mockExtensionsWrapper, getUserId(::testing::_)).WillRepeatedly(::testing::Return(std::to_string(geteuid())));

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
    EXPECT_EQ((*good)["uid"], std::to_string(geteuid()));

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

TEST_F(ChromeExtensionsMalformedFilesTests, ManifestAndMessagesWithCommentsAreParsed)
{
    const std::string profile = "user/.config/google-chrome/Default/";

    writeFile(profile + "Preferences", "{}");
    writeFile(profile + "Secure Preferences", "{}");
    writeFile(profile + "Extensions/commented/1.0/manifest.json", R"({
        // Line comment
        "name": "__MSG_appName__",
        /* Block comment */
        "version": "1.0",
        "default_locale": "en"
    })");
    writeFile(profile + "Extensions/commented/1.0/_locales/en/messages.json", R"({
        // Line comment
        "appName": {"message": "Commented"}
    })");

    nlohmann::json extensionsJson;
    ASSERT_NO_THROW(extensionsJson = collect());
    ASSERT_EQ(extensionsJson.size(), static_cast<size_t>(1));
    EXPECT_EQ(extensionsJson[0]["name"], "Commented");
    EXPECT_EQ(extensionsJson[0]["version"], "1.0");
}

TEST_F(ChromeExtensionsMalformedFilesTests, ProfileNameFallbackAndFloatState)
{
    const std::string profile = "user/.config/google-chrome/Default/";

    writeFile(profile + "Preferences", R"({
        "profile": {"name": 5},
        "extensions": {"settings": {
            "disabled": {"path": "disabled/1.0", "state": 0.0},
            "enabled": {"path": "enabled/1.0", "state": 1.0},
            "huge": {"path": "huge/1.0", "state": 1e300}
        }}
    })");
    writeFile(profile + "Secure Preferences", R"({"profile": {"name": "Work"}})");
    writeFile(profile + "Extensions/disabled/1.0/manifest.json", R"({"name": "Disabled", "version": "1.0"})");
    writeFile(profile + "Extensions/enabled/1.0/manifest.json", R"({"name": "Enabled", "version": "1.0"})");
    writeFile(profile + "Extensions/huge/1.0/manifest.json", R"({"name": "Huge", "version": "1.0"})");

    nlohmann::json extensionsJson;
    ASSERT_NO_THROW(extensionsJson = collect());
    ASSERT_EQ(extensionsJson.size(), static_cast<size_t>(3));

    const auto* disabled = findByName(extensionsJson, "Disabled");
    ASSERT_NE(disabled, nullptr);
    EXPECT_EQ((*disabled)["state"], "0");
    EXPECT_EQ((*disabled)["profile"], "Work");

    const auto* enabled = findByName(extensionsJson, "Enabled");
    ASSERT_NE(enabled, nullptr);
    EXPECT_EQ((*enabled)["state"], "1");

    const auto* huge = findByName(extensionsJson, "Huge");
    ASSERT_NE(huge, nullptr);
    EXPECT_EQ((*huge)["state"], "1");
}
