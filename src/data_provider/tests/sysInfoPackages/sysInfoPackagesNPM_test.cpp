/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * July 16, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "sysInfoPackagesNPM_test.hpp"
#include "scopedTestDirectory.hpp"

using testing::_;
using testing::Return;
using testing::ReturnRef;

TEST_F(NPMTest, getPackages_ValidPackagesTest)
{
    std::vector<std::filesystem::path> fakePackages = {"/fake/node_modules/package1", "/fake/node_modules/package2"};

    EXPECT_CALL(*npm, exists(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*npm, is_directory(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*npm, is_regular_file(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*npm, file_size(_)).WillRepeatedly(Return(1024));
    EXPECT_CALL(*npm, directory_iterator(_)).WillRepeatedly(Return(fakePackages));

    nlohmann::json fakePackageJson1 = {{"name", "TestPackage1"}, {"version", "1.0.0"}};
    nlohmann::json fakePackageJson2 = {{"name", "TestPackage2"}, {"version", "2.0.0"}};

    EXPECT_CALL(*npm, readJson(std::filesystem::path("/fake/node_modules/package1/package.json")))
    .WillOnce(Return(fakePackageJson1));
    EXPECT_CALL(*npm, readJson(std::filesystem::path("/fake/node_modules/package2/package.json")))
    .WillOnce(Return(fakePackageJson2));

    bool foundPackage1 = false;
    bool foundPackage2 = false;

    auto callback = [&](nlohmann::json & json)
    {
        if (json.at("name") == "TestPackage1" && json.at("version") == "1.0.0")
        {
            foundPackage1 = true;
        }
        else if (json.at("name") == "TestPackage2" && json.at("version") == "2.0.0")
        {
            foundPackage2 = true;
        }
    };

    std::set<std::string> folders = {"/fake"};

    npm->getPackages(folders, callback);

    EXPECT_TRUE(foundPackage1);
    EXPECT_TRUE(foundPackage2);
}

TEST_F(NPMTest, getPackages_NoPackagesFoundTest)
{
    std::vector<std::filesystem::path> fakePackages = {};

    EXPECT_CALL(*npm, exists(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*npm, directory_iterator(_)).WillRepeatedly(Return(fakePackages));

    bool callbackCalled = false;

    std::set<std::string> folders = {"/fake"};

    npm->getPackages(folders, [&](nlohmann::json&)
    {
        callbackCalled = true;
    });

    EXPECT_FALSE(callbackCalled);
}

TEST_F(NPMTest, getPackages_NoPackageJsonTest)
{
    std::vector<std::filesystem::path> fakePackages = {"/fake/node_modules/package1"};

    EXPECT_CALL(*npm, exists(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*npm, is_directory(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*npm, is_regular_file(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*npm, file_size(_)).WillRepeatedly(Return(1024));
    EXPECT_CALL(*npm, directory_iterator(_)).WillRepeatedly(Return(fakePackages));

    EXPECT_CALL(*npm, readJson(std::filesystem::path("/fake/node_modules/package1/package.json")))
    .WillOnce(Return(nlohmann::json()));

    bool callbackCalled = false;

    std::set<std::string> folders = {"/fake"};

    npm->getPackages(folders, [&](nlohmann::json&)
    {
        callbackCalled = true;
    });

    EXPECT_FALSE(callbackCalled);
}

TEST_F(NPMTest, getPackages_InvalidPackageJsonNameTest)
{
    std::vector<std::filesystem::path> fakePackages = {"/fake/node_modules/package1"};

    EXPECT_CALL(*npm, exists(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*npm, is_directory(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*npm, is_regular_file(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*npm, file_size(_)).WillRepeatedly(Return(1024));
    EXPECT_CALL(*npm, directory_iterator(_)).WillRepeatedly(Return(fakePackages));

    EXPECT_CALL(*npm, readJson(std::filesystem::path("/fake/node_modules/package1/package.json")))
    .WillOnce(Return(nlohmann::json::parse(R"({"name": 1})")));

    bool callbackCalled = false;

    std::set<std::string> folders = {"/fake"};

    npm->getPackages(folders, [&](nlohmann::json&)
    {
        callbackCalled = true;
    });

    EXPECT_FALSE(callbackCalled);
}

TEST_F(NPMTest, getPackages_InvalidPackageJsonVersionTest)
{
    std::vector<std::filesystem::path> fakePackages = {"/fake/node_modules/package1"};

    EXPECT_CALL(*npm, exists(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*npm, is_directory(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*npm, is_regular_file(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*npm, file_size(_)).WillRepeatedly(Return(1024));
    EXPECT_CALL(*npm, directory_iterator(_)).WillRepeatedly(Return(fakePackages));

    EXPECT_CALL(*npm, readJson(std::filesystem::path("/fake/node_modules/package1/package.json")))
    .WillOnce(Return(nlohmann::json::parse(R"({"name": "TestPackage1", "version": 1})")));

    bool callbackCalled = false;

    std::set<std::string> folders = {"/fake"};

    npm->getPackages(folders, [&](nlohmann::json&)
    {
        callbackCalled = true;
    });

    EXPECT_FALSE(callbackCalled);
}

TEST_F(NPMTest, getPackages_ValidPackageJson2Test)
{
    std::vector<std::filesystem::path> fakePackages = {"/fake/node_modules/package1", "/fake/node_modules/package2"};

    EXPECT_CALL(*npm, exists(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*npm, is_directory(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*npm, is_regular_file(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*npm, file_size(_)).WillRepeatedly(Return(1024));
    EXPECT_CALL(*npm, directory_iterator(_)).WillOnce(Return(fakePackages));

    EXPECT_CALL(*npm, readJson(std::filesystem::path("/fake/node_modules/package1/package.json")))
    .WillOnce(Return(nlohmann::json::parse(R"({"name": "TestPackage1", "version": "1.0.0"})")));

    EXPECT_CALL(*npm, readJson(std::filesystem::path("/fake/node_modules/package2/package.json")))
    .WillOnce(Return(nlohmann::json::parse(R"({"name": "TestPackage2", "version": "1.0.0"})")));

    bool callbackCalledFirst = false;
    bool callbackCalledSecond = false;

    std::set<std::string> folders = {"/fake"};

    npm->getPackages(folders,
                     [&](nlohmann::json & j)
    {
        if (j.at("name") == "TestPackage1" && j.at("version") == "1.0.0")
        {
            callbackCalledFirst = true;
        }
        else if (j.at("name") == "TestPackage2" && j.at("version") == "1.0.0")
        {
            callbackCalledSecond = true;
        }
        else
        {
            FAIL();
        }
    });

    EXPECT_TRUE(callbackCalledFirst);
    EXPECT_TRUE(callbackCalledSecond);
}

TEST_F(NPMTest, getPackages_NonRegularPackageJsonIsSkipped)
{
    std::vector<std::filesystem::path> fakePackages = {"/fake/node_modules/package1"};

    EXPECT_CALL(*npm, exists(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*npm, is_directory(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*npm, is_regular_file(_)).WillRepeatedly(Return(false));
    EXPECT_CALL(*npm, directory_iterator(_)).WillRepeatedly(Return(fakePackages));
    EXPECT_CALL(*npm, readJson(_)).Times(0);

    bool callbackCalled = false;

    std::set<std::string> folders = {"/fake"};

    npm->getPackages(folders, [&](nlohmann::json&)
    {
        callbackCalled = true;
    });

    EXPECT_FALSE(callbackCalled);
}

TEST_F(NPMTest, getPackages_OversizedPackageJsonIsSkipped)
{
    std::vector<std::filesystem::path> fakePackages = {"/fake/node_modules/package1"};

    EXPECT_CALL(*npm, exists(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*npm, is_directory(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*npm, is_regular_file(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*npm, file_size(_)).WillRepeatedly(Return(PACKAGE_METADATA_MAX_FILE_SIZE + 1));
    EXPECT_CALL(*npm, directory_iterator(_)).WillRepeatedly(Return(fakePackages));
    EXPECT_CALL(*npm, readJson(_)).Times(0);

    bool callbackCalled = false;

    std::set<std::string> folders = {"/fake"};

    npm->getPackages(folders, [&](nlohmann::json&)
    {
        callbackCalled = true;
    });

    EXPECT_FALSE(callbackCalled);
}

TEST_F(NPMTest, getPackages_UnmountedAutomountedHomeIsNotExplored)
{
    const ScopedTestDirectory directory {"wazuh_npm_automount"};
    const auto& base {directory.path()};
    std::filesystem::create_directories(base / "home" / "alice" / ".npm-global" / "lib");
    std::filesystem::create_directories(base / "home" / "bob" / ".npm-global" / "lib");

    // The expansion asks the file system about each home directory; bob's home is not mounted
    EXPECT_CALL(*npm, is_unmounted_automount_point(_)).WillRepeatedly(Return(false));
    EXPECT_CALL(*npm, is_unmounted_automount_point(std::filesystem::path(base / "home" / "bob"))).WillOnce(Return(true));
    EXPECT_CALL(*npm, exists(base / "home" / "alice" / ".npm-global" / "lib" / "node_modules")).WillOnce(Return(false));
    EXPECT_CALL(*npm, exists(base / "home" / "bob" / ".npm-global" / "lib" / "node_modules")).Times(0);

    std::set<std::string> folders = {(base / "home" / "*" / ".npm-global" / "lib").string()};
    npm->getPackages(folders, [](nlohmann::json&) {});
}

TEST_F(NPMTest, DefaultHomePatternsHaveTheHomeAsFirstWildcard)
{
    // The collector only checks the first wildcard level for automount points that are not mounted
    // yet, so a per-user pattern with another wildcard before the home would mount every home again
    for (const auto& pattern : UNIX_NPM_DEFAULT_BASE_DIRS)
    {
        if (pattern.rfind("/home/", 0) == 0)
        {
            EXPECT_EQ(pattern.rfind("/home/*/", 0), 0u) << pattern;
        }
    }
}

TEST_F(NPMTest, getPackages_UnreadableScopeFolderDoesNotStopTheScanTest)
{
    const std::vector<std::filesystem::path> rootFolders = {"/fake/node_modules/@scope", "/fake/node_modules/package1"};

    EXPECT_CALL(*npm, exists(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*npm, is_directory(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*npm, is_regular_file(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*npm, file_size(_)).WillRepeatedly(Return(1024));
    EXPECT_CALL(*npm, directory_iterator(std::filesystem::path("/fake/node_modules"))).WillOnce(Return(rootFolders));
    EXPECT_CALL(*npm, directory_iterator(std::filesystem::path("/fake/node_modules/@scope")))
    .WillOnce(testing::Throw(std::filesystem::filesystem_error("denied", std::make_error_code(std::errc::permission_denied))));
    EXPECT_CALL(*npm, readJson(std::filesystem::path("/fake/node_modules/package1/package.json")))
    .WillOnce(Return(nlohmann::json::parse(R"({"name": "package1", "version": "1.0.0"})")));

    std::vector<std::string> found;

    npm->getPackages({"/fake"}, [&](nlohmann::json & j)
    {
        found.push_back(j.at("name"));
    });

    EXPECT_EQ(found, std::vector<std::string> {"package1"});
}

TEST(NPMRealFileSystemTest, getPackages_ScopedAndUnscopedPackagesTest)
{
    const ScopedTestDirectory directory {"wazuh_npm_scoped"};
    const auto nodeModules {directory.path() / "lib" / "node_modules"};
    const auto writePackage = [](const std::filesystem::path & folder, const std::string & content)
    {
        std::filesystem::create_directories(folder);
        std::ofstream {folder / "package.json"} << content;
    };

    writePackage(nodeModules / "npm", R"({"name": "npm", "version": "10.9.9"})");
    writePackage(nodeModules / "@openai" / "codex", R"({"name": "@openai/codex", "version": "0.172.0"})");
    writePackage(nodeModules / "@broken" / "invalid", "{not json");
    writePackage(nodeModules / "@nested" / "outer" / "node_modules" / "inner", R"({"name": "inner", "version": "1.0.0"})");
    std::filesystem::create_directories(nodeModules / "@empty");
    std::filesystem::create_directories(nodeModules / ".bin");

    std::map<std::string, std::string> found;

    NPM().getPackages({(directory.path() / "lib").string()}, [&](nlohmann::json & j)
    {
        found[j.at("name")] = j.at("version");
    });

    const std::map<std::string, std::string> expected {{"npm", "10.9.9"}, {"@openai/codex", "0.172.0"}};
    EXPECT_EQ(found, expected);
}
