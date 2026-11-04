/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "sysInfoPackagesNPM_test.hpp"
#include <chrono>
#include <map>
#include <stdexcept>

using testing::_;
using testing::Return;
using testing::Throw;

class NPMScopedTest : public NPMTest
{
protected:
    void SetUp() override
    {
        NPMTest::SetUp();
        EXPECT_CALL(*npm, exists(_)).WillRepeatedly(Return(true));
        EXPECT_CALL(*npm, is_directory(_)).WillRepeatedly(Return(true));
        EXPECT_CALL(*npm, is_regular_file(_)).WillRepeatedly(Return(true));
        EXPECT_CALL(*npm, file_size(_)).WillRepeatedly(Return(1024));
        // Only explicitly listed directories may be traversed or metadata files read.
        EXPECT_CALL(*npm, directory_iterator(_)).Times(0);
        EXPECT_CALL(*npm, readJson(_)).Times(0);
    }

    void list(const std::filesystem::path& directory, const std::vector<std::filesystem::path>& entries)
    {
        EXPECT_CALL(*npm, directory_iterator(directory)).WillOnce(Return(entries));
    }

    void metadata(const std::filesystem::path& directory, const std::string& name, const std::string& version)
    {
        EXPECT_CALL(*npm, readJson(directory / "package.json"))
            .WillOnce(Return(nlohmann::json {{"name", name}, {"version", version}}));
    }

    std::vector<nlohmann::json> packages()
    {
        std::vector<nlohmann::json> result;
        npm->getPackages({"/fake"}, [&](nlohmann::json& package) { result.push_back(package); });
        return result;
    }
};

TEST_F(NPMScopedTest, ScopedAndUnscopedPackages)
{
    list("/fake/node_modules", {"/fake/node_modules/npm", "/fake/node_modules/@openai", "/fake/node_modules/@other"});
    list("/fake/node_modules/@openai", {"/fake/node_modules/@openai/codex", "/fake/node_modules/@openai/another"});
    list("/fake/node_modules/@other", {"/fake/node_modules/@other/tool"});
    metadata("/fake/node_modules/npm", "npm", "10.0.0");
    metadata("/fake/node_modules/@openai/codex", "@openai/codex", "1.0.0");
    metadata("/fake/node_modules/@openai/another", "@openai/another", "2.0.0");
    metadata("/fake/node_modules/@other/tool", "@other/tool", "3.0.0");

    const auto result = packages();
    ASSERT_EQ(result.size(), 4u);
    EXPECT_EQ(result[0].at("name"), "npm");
    EXPECT_EQ(result[1].at("name"), "@openai/codex");
    EXPECT_EQ(result[1].at("version"), "1.0.0");
    EXPECT_EQ(result[1].at("format"), "npm");
    EXPECT_EQ(result[1].at("location"),
              std::filesystem::path("/fake/node_modules/@openai/codex/package.json").string());
    EXPECT_EQ(result[2].at("name"), "@openai/another");
    EXPECT_EQ(result[3].at("name"), "@other/tool");
}

TEST_F(NPMScopedTest, EmptyScopeDoesNotHideUnscopedPackage)
{
    list("/fake/node_modules", {"/fake/node_modules/@empty", "/fake/node_modules/npm"});
    list("/fake/node_modules/@empty", {});
    metadata("/fake/node_modules/npm", "npm", "10.0.0");

    const auto result = packages();
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0].at("name"), "npm");
}

TEST_F(NPMScopedTest, NonDirectoryEntriesAreSkipped)
{
    list("/fake/node_modules", {"/fake/node_modules/@file", "/fake/node_modules/@openai"});
    EXPECT_CALL(*npm, is_directory(std::filesystem::path("/fake/node_modules/@file"))).WillOnce(Return(false));
    list("/fake/node_modules/@openai", {"/fake/node_modules/@openai/README", "/fake/node_modules/@openai/codex"});
    EXPECT_CALL(*npm, is_directory(std::filesystem::path("/fake/node_modules/@openai/README"))).WillOnce(Return(false));
    metadata("/fake/node_modules/@openai/codex", "@openai/codex", "1.0.0");

    const auto result = packages();
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0].at("name"), "@openai/codex");
}

TEST_F(NPMScopedTest, MissingMetadataIsSkipped)
{
    list("/fake/node_modules", {"/fake/node_modules/@openai"});
    list("/fake/node_modules/@openai", {"/fake/node_modules/@openai/missing", "/fake/node_modules/@openai/codex"});
    const std::filesystem::path missing {"/fake/node_modules/@openai/missing/package.json"};
    EXPECT_CALL(*npm, exists(missing)).WillRepeatedly(Return(false));
    EXPECT_CALL(*npm, is_regular_file(missing)).WillRepeatedly(Return(false));
    metadata("/fake/node_modules/@openai/codex", "@openai/codex", "1.0.0");

    const auto result = packages();
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0].at("name"), "@openai/codex");
}

TEST_F(NPMScopedTest, InvalidMetadataDoesNotHideValidSibling)
{
    const std::vector<nlohmann::json> invalid {{{"version", "1.0.0"}},
                                               {{"name", "@scope/tool"}},
                                               {{"name", 1}, {"version", "1.0.0"}},
                                               {{"name", "@scope/tool"}, {"version", 1}}};
    std::vector<std::filesystem::path> entries;

    for (std::size_t index = 0; index < invalid.size(); ++index)
    {
        const auto directory = std::filesystem::path("/fake/node_modules/@scope") / std::to_string(index);
        entries.push_back(directory);
        EXPECT_CALL(*npm, readJson(directory / "package.json")).WillOnce(Return(invalid[index]));
    }

    entries.emplace_back("/fake/node_modules/@scope/broken");
    EXPECT_CALL(*npm, readJson(std::filesystem::path("/fake/node_modules/@scope/broken/package.json")))
        .WillOnce(Throw(nlohmann::json::parse_error::create(101, 1, "invalid JSON", nullptr)));
    entries.emplace_back("/fake/node_modules/@scope/valid");
    metadata("/fake/node_modules/@scope/valid", "@scope/valid", "1.0.0");
    list("/fake/node_modules", {"/fake/node_modules/@scope"});
    list("/fake/node_modules/@scope", entries);

    const auto result = packages();
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0].at("name"), "@scope/valid");
}

TEST_F(NPMScopedTest, UnreadableScopeDoesNotHideOtherPackages)
{
    list("/fake/node_modules",
         {"/fake/node_modules/@unreadable", "/fake/node_modules/@openai", "/fake/node_modules/npm"});
    EXPECT_CALL(*npm, directory_iterator(std::filesystem::path("/fake/node_modules/@unreadable")))
        .WillOnce(Throw(std::runtime_error("Permission denied")));
    list("/fake/node_modules/@openai", {"/fake/node_modules/@openai/codex"});
    metadata("/fake/node_modules/@openai/codex", "@openai/codex", "1.0.0");
    metadata("/fake/node_modules/npm", "npm", "10.0.0");

    const auto result = packages();
    ASSERT_EQ(result.size(), 2u);
    EXPECT_EQ(result[0].at("name"), "@openai/codex");
    EXPECT_EQ(result[1].at("name"), "npm");
}

TEST_F(NPMScopedTest, UninspectablePackageDoesNotHideSibling)
{
    list("/fake/node_modules", {"/fake/node_modules/@openai"});
    list("/fake/node_modules/@openai", {"/fake/node_modules/@openai/broken", "/fake/node_modules/@openai/codex"});
    EXPECT_CALL(*npm, is_directory(std::filesystem::path("/fake/node_modules/@openai/broken")))
        .WillOnce(Throw(std::runtime_error("Permission denied")));
    metadata("/fake/node_modules/@openai/codex", "@openai/codex", "1.0.0");

    const auto result = packages();
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0].at("name"), "@openai/codex");
}

TEST_F(NPMScopedTest, DoesNotTraverseNestedDependenciesOrScopes)
{
    list("/fake/node_modules", {"/fake/node_modules/package", "/fake/node_modules/@scope"});
    list("/fake/node_modules/@scope", {"/fake/node_modules/@scope/tool", "/fake/node_modules/@scope/@nested"});
    metadata("/fake/node_modules/package", "package", "1.0.0");
    metadata("/fake/node_modules/@scope/tool", "@scope/tool", "2.0.0");
    const std::filesystem::path nested {"/fake/node_modules/@scope/@nested/package.json"};
    EXPECT_CALL(*npm, exists(nested)).WillRepeatedly(Return(false));
    EXPECT_CALL(*npm, is_regular_file(nested)).WillRepeatedly(Return(false));

    const auto result = packages();
    ASSERT_EQ(result.size(), 2u);
    EXPECT_EQ(result[0].at("name"), "package");
    EXPECT_EQ(result[1].at("name"), "@scope/tool");
}

class NPMFilesystemTest : public ::testing::Test
{
protected:
    std::filesystem::path m_root;

    void SetUp() override
    {
        const auto suffix {std::to_string(std::chrono::steady_clock::now().time_since_epoch().count())};
        m_root = std::filesystem::temp_directory_path() / ("npm_scoped_test_" + suffix);
        std::filesystem::create_directory(m_root);
    }

    void TearDown() override
    {
        std::error_code error;
        std::filesystem::remove_all(m_root, error);
    }

    void writePackage(const std::filesystem::path& relativePath, const std::string& name)
    {
        const auto directory {m_root / relativePath};
        std::filesystem::create_directories(directory);
        std::ofstream(directory / "package.json") << nlohmann::json {{"name", name}, {"version", "1.0.0"}};
    }

    std::map<std::string, nlohmann::json> packages(const std::filesystem::path& root)
    {
        NPM<> collector;
        std::map<std::string, nlohmann::json> result;
        collector.getPackages({root.string()},
                              [&](nlohmann::json& package)
                              { EXPECT_TRUE(result.emplace(package.at("name").get<std::string>(), package).second); });
        return result;
    }
};

TEST_F(NPMFilesystemTest, NvmPathsIncludeOnlyTopLevelPackages)
{
    const std::filesystem::path first {"versions/node/v22/lib/node_modules"};
    const std::filesystem::path second {"versions/node/v24/lib/node_modules"};
    writePackage(first / "npm", "npm");
    writePackage(first / "@openai/codex", "@openai/codex");
    writePackage(second / "@other/tool", "@other/tool");
    writePackage(first / "npm/node_modules/dependency", "unscoped-dependency");
    writePackage(first / "@openai/codex/node_modules/@nested/dependency", "@nested/dependency");
    std::filesystem::create_directories(m_root / first / "@empty");
    std::filesystem::create_directories(m_root / first / "@broken/tool");
    std::ofstream(m_root / first / "@broken/tool/package.json") << "{invalid json";
    std::ofstream(m_root / first / "@openai/README") << "not a package";

    const auto result = packages(m_root / "versions/node/v*/lib");
    ASSERT_EQ(result.size(), 3u);
    ASSERT_EQ(result.count("@openai/codex"), 1u);
    EXPECT_EQ(result.at("@openai/codex").at("version"), "1.0.0");
    EXPECT_EQ(result.at("@openai/codex").at("location"), (m_root / first / "@openai/codex/package.json").string());
    EXPECT_EQ(result.count("npm"), 1u);
    EXPECT_EQ(result.count("@other/tool"), 1u);
}

#ifndef _WIN32
TEST_F(NPMFilesystemTest, LinkedPackagesAndScopesAreSupported)
{
    writePackage("package-source", "@linked/package");
    writePackage("scope-source/tool", "@scope/tool");
    std::filesystem::create_directories(m_root / "lib/node_modules/@linked");
    std::filesystem::create_directory_symlink(m_root / "package-source", m_root / "lib/node_modules/@linked/package");
    std::filesystem::create_directory_symlink(m_root / "scope-source", m_root / "lib/node_modules/@scope");
    std::filesystem::create_directory_symlink(m_root / "missing", m_root / "lib/node_modules/@broken");

    const auto result = packages(m_root / "lib");
    ASSERT_EQ(result.size(), 2u);
    EXPECT_EQ(result.count("@linked/package"), 1u);
    EXPECT_EQ(result.count("@scope/tool"), 1u);
}
#endif
