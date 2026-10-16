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

using testing::_;
using testing::Return;
using testing::ReturnRef;

TEST_F(NPMTest, getPackages_ValidPackagesTest)
{
    std::vector<std::filesystem::path> fakePackages = {"/fake/node_modules/package1", "/fake/node_modules/package2"};

    EXPECT_CALL(*mockFileSystem, exists(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_directory(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_regular_file(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, list_directory(testing::_)).WillRepeatedly(Return(fakePackages));

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
        if (json.at("name") == "TestPackage1" && json.at("version_") == "1.0.0")
        {
            foundPackage1 = true;
        }
        else if (json.at("name") == "TestPackage2" && json.at("version_") == "2.0.0")
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

    EXPECT_CALL(*mockFileSystem, exists(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, list_directory(testing::_)).WillRepeatedly(Return(fakePackages));

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

    EXPECT_CALL(*mockFileSystem, exists(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_directory(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_regular_file(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, list_directory(testing::_)).WillRepeatedly(Return(fakePackages));

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

    EXPECT_CALL(*mockFileSystem, exists(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_directory(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_regular_file(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, list_directory(testing::_)).WillRepeatedly(Return(fakePackages));

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

    EXPECT_CALL(*mockFileSystem, exists(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_directory(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_regular_file(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, list_directory(testing::_)).WillRepeatedly(Return(fakePackages));

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

    EXPECT_CALL(*mockFileSystem, exists(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_directory(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_regular_file(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, list_directory(testing::_)).WillOnce(Return(fakePackages));

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
        if (j.at("name") == "TestPackage1" && j.at("version_") == "1.0.0")
        {
            callbackCalledFirst = true;
        }
        else if (j.at("name") == "TestPackage2" && j.at("version_") == "1.0.0")
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

    EXPECT_CALL(*mockFileSystem, exists(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_directory(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_regular_file(testing::_)).WillRepeatedly(Return(false));
    EXPECT_CALL(*mockFileSystem, list_directory(testing::_)).WillRepeatedly(Return(fakePackages));
    EXPECT_CALL(*npm, readJson(testing::_)).Times(0);

    bool callbackCalled = false;

    std::set<std::string> folders = {"/fake"};

    npm->getPackages(folders, [&](nlohmann::json&)
    {
        callbackCalled = true;
    });

    EXPECT_FALSE(callbackCalled);
}

TEST_F(NPMTest, getPackages_SizeIsTheMeasuredPackageFolder)
{
    const std::filesystem::path packageFolder {"/fake/node_modules/package1"};

    EXPECT_CALL(*mockFileSystem, exists(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_directory(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_regular_file(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, list_directory(testing::_))
    .WillRepeatedly(Return(std::vector<std::filesystem::path> {packageFolder}));
    EXPECT_CALL(*npm, readJson(packageFolder / "package.json"))
    .WillOnce(Return(nlohmann::json {{"name", "TestPackage1"}, {"version", "1.0.0"}}));
    EXPECT_CALL(*mockFileSystem, directory_size(packageFolder, PACKAGE_SIZE_MAX_ENTRIES, PACKAGE_SIZE_DEADLINE))
    .WillOnce(Return(std::optional<std::uintmax_t> {4096}));

    nlohmann::json capturedJson;
    npm->getPackages({"/fake"}, [&](nlohmann::json & json)
    {
        capturedJson = json;
    });

    EXPECT_EQ(capturedJson.at("name"), "TestPackage1");
    EXPECT_EQ(capturedJson.at("size"), 4096);
}

TEST_F(NPMTest, getPackages_UnmeasurableFolderSizeIsAbsent)
{
    const std::filesystem::path packageFolder {"/fake/node_modules/package1"};

    EXPECT_CALL(*mockFileSystem, exists(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_directory(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_regular_file(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, list_directory(testing::_))
    .WillRepeatedly(Return(std::vector<std::filesystem::path> {packageFolder}));
    EXPECT_CALL(*npm, readJson(packageFolder / "package.json"))
    .WillOnce(Return(nlohmann::json {{"name", "TestPackage1"}, {"version", "1.0.0"}}));
    // The walk hit the entry cap or the deadline, or failed
    EXPECT_CALL(*mockFileSystem, directory_size(packageFolder, testing::_, testing::_))
    .WillOnce(Return(std::nullopt));

    nlohmann::json capturedJson;
    npm->getPackages({"/fake"}, [&](nlohmann::json & json)
    {
        capturedJson = json;
    });

    // Unknown, never zero
    EXPECT_EQ(capturedJson.at("name"), "TestPackage1");
    EXPECT_FALSE(capturedJson.contains("size"));
}

TEST_F(NPMTest, getPackages_EmptyFolderSizeIsAbsent)
{
    const std::filesystem::path packageFolder {"/fake/node_modules/package1"};

    EXPECT_CALL(*mockFileSystem, exists(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_directory(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_regular_file(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, list_directory(testing::_))
    .WillRepeatedly(Return(std::vector<std::filesystem::path> {packageFolder}));
    EXPECT_CALL(*npm, readJson(packageFolder / "package.json"))
    .WillOnce(Return(nlohmann::json {{"name", "TestPackage1"}, {"version", "1.0.0"}}));
    EXPECT_CALL(*mockFileSystem, directory_size(packageFolder, testing::_, testing::_))
    .WillOnce(Return(std::optional<std::uintmax_t> {0}));

    nlohmann::json capturedJson;
    npm->getPackages({"/fake"}, [&](nlohmann::json & json)
    {
        capturedJson = json;
    });

    EXPECT_FALSE(capturedJson.contains("size"));
}

TEST_F(NPMTest, getPackages_LinkedPackageFolderSizeIsAbsent)
{
    // npm link: the package folder is a link to a whole checkout, which must not be walked
    const std::filesystem::path packageFolder {"/fake/node_modules/linked"};

    EXPECT_CALL(*mockFileSystem, exists(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_directory(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_regular_file(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, list_directory(testing::_))
    .WillRepeatedly(Return(std::vector<std::filesystem::path> {packageFolder}));
    EXPECT_CALL(*npm, readJson(packageFolder / "package.json"))
    .WillOnce(Return(nlohmann::json {{"name", "linked"}, {"version", "1.0.0"}}));
    EXPECT_CALL(*mockFileSystem, is_symlink(packageFolder)).WillOnce(Return(true));
    EXPECT_CALL(*mockFileSystem, directory_size(testing::_, testing::_, testing::_)).Times(0);

    nlohmann::json capturedJson;
    npm->getPackages({"/fake"}, [&](nlohmann::json & json)
    {
        capturedJson = json;
    });

    // Still inventoried, only its size is unknown
    EXPECT_EQ(capturedJson.at("name"), "linked");
    EXPECT_FALSE(capturedJson.contains("size"));
}

TEST_F(NPMTest, getPackages_UninspectableFolderIsReportedUnsized)
{
    const std::filesystem::path packageFolder {"/fake/node_modules/package1"};

    EXPECT_CALL(*mockFileSystem, exists(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_directory(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_regular_file(testing::_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, list_directory(testing::_))
    .WillRepeatedly(Return(std::vector<std::filesystem::path> {packageFolder}));
    EXPECT_CALL(*npm, readJson(packageFolder / "package.json"))
    .WillOnce(Return(nlohmann::json {{"name", "TestPackage1"}, {"version", "1.0.0"}}));
    EXPECT_CALL(*mockFileSystem, is_symlink(packageFolder))
    .WillOnce(testing::Throw(std::filesystem::filesystem_error("denied", std::make_error_code(std::errc::permission_denied))));
    EXPECT_CALL(*mockFileSystem, directory_size(testing::_, testing::_, testing::_)).Times(0);

    nlohmann::json capturedJson;
    npm->getPackages({"/fake"}, [&](nlohmann::json & json)
    {
        capturedJson = json;
    });

    EXPECT_EQ(capturedJson.at("name"), "TestPackage1");
    EXPECT_FALSE(capturedJson.contains("size"));
}
