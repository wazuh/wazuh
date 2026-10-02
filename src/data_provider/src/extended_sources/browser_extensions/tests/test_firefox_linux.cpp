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
#include <unistd.h>
#include <sys/stat.h>
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

TEST(FirefoxAddonsTests, NumberOfExtensions)
{
    auto mockAddonsWrapper = std::make_shared<MockBrowserExtensionsWrapper>();
    std::string mockHomePath = Utils::joinPaths(Utils::getParentPath((__FILE__)), "linux");

    EXPECT_CALL(*mockAddonsWrapper, getHomePath()).WillRepeatedly(::testing::Return(mockHomePath));
    EXPECT_CALL(*mockAddonsWrapper, getUserId(::testing::StrEq("mock-user"))).WillRepeatedly(::testing::Return(fixtureOwner(mockHomePath)));

    FirefoxAddonsProvider firefoxAddonsProvider(mockAddonsWrapper);
    nlohmann::json extensionsJson = firefoxAddonsProvider.collect();
    ASSERT_EQ(extensionsJson.size(), static_cast<size_t>(10));
}

TEST(FirefoxAddonsTests, CollectReturnsExpectedJson)
{
    auto mockAddonsWrapper = std::make_shared<MockBrowserExtensionsWrapper>();
    std::string mockHomePath = Utils::joinPaths(Utils::getParentPath((__FILE__)), "linux");

    EXPECT_CALL(*mockAddonsWrapper, getHomePath()).WillRepeatedly(::testing::Return(mockHomePath));
    EXPECT_CALL(*mockAddonsWrapper, getUserId(::testing::StrEq("mock-user"))).WillRepeatedly(::testing::Return(fixtureOwner(mockHomePath)));

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
            EXPECT_EQ(jsonElement["uid"], fixtureOwner(mockHomePath));
            EXPECT_EQ(jsonElement["version"], "141.0.20250806.102122");
            EXPECT_EQ(jsonElement["visible"], true);
        }
    }
}

#include <cstdlib>
#include <fstream>

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
    // If `homeOwner` is not the current user, the fake home is given to that user before collecting.
    size_t collectFromTempHome(AddonsLayout layout, const std::string& ownerUid = std::to_string(geteuid()),
                               uid_t homeOwner = geteuid())
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

        if (ready && homeOwner != geteuid())
        {
            const std::string chownCmd = "chown -R " + std::to_string(homeOwner) + " '" + root + "/home/user'";
            ready = std::system(chownCmd.c_str()) == 0;
        }

        size_t count = static_cast<size_t>(-1);

        if (ready)
        {
            auto mockAddonsWrapper = std::make_shared<MockBrowserExtensionsWrapper>();
            EXPECT_CALL(*mockAddonsWrapper, getHomePath()).WillRepeatedly(::testing::Return(root + "/home"));
            EXPECT_CALL(*mockAddonsWrapper, getUserId(::testing::_)).WillRepeatedly(::testing::Return(ownerUid));

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

TEST(FirefoxAddonsTests, ExtensionsFileOwnedByAnotherUserIsSkipped)
{
    EXPECT_EQ(collectFromTempHome(AddonsLayout::REGULAR, std::to_string(geteuid() + 1)), static_cast<size_t>(0));
}

TEST(FirefoxAddonsTests, UnknownUserNameUsesHomeDirectoryOwner)
{
    // A home directory owned by root is never used as the profile owner, so as root the home is given to nobody
    const uid_t homeOwner = geteuid() == 0 ? 65534 : geteuid();

    EXPECT_EQ(collectFromTempHome(AddonsLayout::REGULAR, "", homeOwner), static_cast<size_t>(10));
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
         "softDisable": "yes", "visible": "true", "active": 1, "applyBackgroundUpdates": "1"},
        {"id": "typed@addon", "version": "1.0", "defaultLocale": "not an object",
         "userDisabled": true, "visible": true, "active": true, "applyBackgroundUpdates": 1},
        "not an object"
    ]})");
    writeFile("good-user/.mozilla/firefox/def.default/extensions.json",
              R"({"addons": [{"id": "good@addon", "version": "2.0", "defaultLocale": {"name": "Good"}}]})");

    auto mockAddonsWrapper = std::make_shared<MockBrowserExtensionsWrapper>();
    EXPECT_CALL(*mockAddonsWrapper, getHomePath()).WillRepeatedly(::testing::Return(homePath.string()));
    EXPECT_CALL(*mockAddonsWrapper, getUserId(::testing::_)).WillRepeatedly(::testing::Return(std::to_string(geteuid())));

    FirefoxAddonsProvider firefoxAddonsProvider(mockAddonsWrapper);
    nlohmann::json extensionsJson;
    ASSERT_NO_THROW(extensionsJson = firefoxAddonsProvider.collect());
    std::filesystem::remove_all(homePath);

    ASSERT_EQ(extensionsJson.size(), static_cast<size_t>(4));

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
