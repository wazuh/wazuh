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

