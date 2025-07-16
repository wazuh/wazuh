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

#include "sysInfoPackagesPYPI_test.hpp"

using testing::_;
using testing::Return;
using testing::ReturnRef;

TEST_F(PYPITest, getPackagesTest)
{
    std::vector<std::filesystem::path> fakeFiles = {"/fake/dir/file1", "/fake/dir/file2", "/fake/dir/file3"};

    EXPECT_CALL(*mockFileSystem, exists(_)).WillRepeatedly(Return(true));

    EXPECT_CALL(*mockFileSystem, is_directory(_))
    .WillRepeatedly(Return(true));

    EXPECT_CALL(*mockFileSystem, list_directory(_))
    .WillRepeatedly(Return(fakeFiles));

    EXPECT_CALL(*mockFileIO, readLineByLine(_, _))
    .WillRepeatedly(Return());

    nlohmann::json capturedJson;
    auto callback = [&](nlohmann::json & j)
    {
        capturedJson = j;
    };

    std::set<std::string> folders = { "/usr/local/lib/python3.9/site-packages" };

    pypi->getPackages(folders, callback);

    EXPECT_TRUE(capturedJson.empty());
}

TEST_F(PYPITest, getPackages_NoFilesInDirectoryTest)
{
    std::vector<std::filesystem::path> fakeFiles = {};

    EXPECT_CALL(*mockFileSystem, exists(_)).WillRepeatedly(Return(true));

    EXPECT_CALL(*mockFileSystem, is_directory(_)).WillRepeatedly(Return(true));

    EXPECT_CALL(*mockFileSystem, list_directory(_)).WillRepeatedly(Return(fakeFiles));

    nlohmann::json capturedJson;
    auto callback = [&](nlohmann::json & j)
    {
        capturedJson = j;
    };

    std::set<std::string> folders = { "/usr/local/lib/python3.9/site-packages" };

    pypi->getPackages(folders, callback);

    EXPECT_TRUE(capturedJson.empty());
}

TEST_F(PYPITest, getPackages_NonDirectoryPathTest)
{
    EXPECT_CALL(*mockFileSystem, exists(_))
    .WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_directory(_))
    .WillRepeatedly(Return(false));

    std::set<std::string> folders = { "/usr/local/lib/python3.9/site-packages" };
    nlohmann::json capturedJson;
    auto callback = [&](nlohmann::json & j)
    {
        capturedJson = j;
    };
    pypi->getPackages(folders, callback);
    EXPECT_TRUE(capturedJson.empty());
}

TEST_F(PYPITest, getPackages_OneValidPackageTestEggInfo)
{
    std::vector<std::filesystem::path> fakeFiles = {"/fake/dir/egg-info"};

    EXPECT_CALL(*mockFileSystem, exists(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_directory(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, list_directory(_)).WillRepeatedly(Return(fakeFiles));
    EXPECT_CALL(*mockFileSystem, is_regular_file(_)).WillRepeatedly(Return(true));

    std::vector<std::string> fakePackageLines = {"Name: TestPackage", "Version: 1.0.0"};
    EXPECT_CALL(*mockFileIO, readLineByLine(std::filesystem::path("/fake/dir/egg-info"), _)).WillOnce([&](const std::filesystem::path&, const std::function<bool(const std::string&)>& callback)
    {
        for (const auto& line : fakePackageLines)
        {
            callback(line);
        }
    });

    nlohmann::json capturedJson;
    auto callback = [&](nlohmann::json & j)
    {
        capturedJson = j;
    };

    std::set<std::string> folders = { "/usr/local/lib/python3.9/site-packages" };

    pypi->getPackages(folders, callback);

    EXPECT_EQ(capturedJson.at("name"), "TestPackage");
    EXPECT_EQ(capturedJson.at("version"), "1.0.0");
}

TEST_F(PYPITest, getPackages_OneValidPackageTestNoRegularFileDistInfo)
{
    std::vector<std::filesystem::path> fakeFiles = {"/fake/dir/dist-info"};

    EXPECT_CALL(*mockFileSystem, exists(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_directory(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, list_directory(_)).WillRepeatedly(Return(fakeFiles));
    EXPECT_CALL(*mockFileSystem, is_regular_file(_)).WillRepeatedly(Return(false));

    std::vector<std::string> fakePackageLines = {"Name: TestPackage", "Version: 1.0.0"};
    EXPECT_CALL(*mockFileIO, readLineByLine(std::filesystem::path("/fake/dir/dist-info/METADATA"), _)).WillOnce([&](const std::filesystem::path&, const std::function<bool(const std::string&)>& callback)
    {
        for (const auto& line : fakePackageLines)
        {
            callback(line);
        }
    });

    nlohmann::json capturedJson;
    auto callback = [&](nlohmann::json & j)
    {
        capturedJson = j;
    };

    std::set<std::string> folders = { "/usr/local/lib/python3.9/site-packages" };

    pypi->getPackages(folders, callback);

    EXPECT_EQ(capturedJson.at("name"), "TestPackage");
    EXPECT_EQ(capturedJson.at("version"), "1.0.0");
}

TEST_F(PYPITest, getPackages_OneValidPackageTestDistInfo)
{
    std::vector<std::filesystem::path> fakeFiles = {"/fake/dir/dist-info"};

    EXPECT_CALL(*mockFileSystem, exists(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_directory(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, list_directory(_)).WillRepeatedly(Return(fakeFiles));
    EXPECT_CALL(*mockFileSystem, is_regular_file(_)).WillRepeatedly(Return(true));

    std::vector<std::string> fakePackageLines = {"Name: TestPackage", "Version: 1.0.0"};
    EXPECT_CALL(*mockFileIO, readLineByLine(std::filesystem::path("/fake/dir/dist-info"), _)).WillOnce([&](const std::filesystem::path&, const std::function<bool(const std::string&)>& callback)
    {
        for (const auto& line : fakePackageLines)
        {
            callback(line);
        }
    });

    nlohmann::json capturedJson;
    auto callback = [&](nlohmann::json & j)
    {
        capturedJson = j;
    };

    std::set<std::string> folders = { "/usr/local/lib/python3.9/site-packages" };

    pypi->getPackages(folders, callback);

    EXPECT_EQ(capturedJson.at("name"), "TestPackage");
    EXPECT_EQ(capturedJson.at("version"), "1.0.0");
}

TEST_F(PYPITest, getPackages_OneValidPackageTestNoRegularFileEggInfo)
{
    std::vector<std::filesystem::path> fakeFiles = {"/fake/dir/egg-info"};

    EXPECT_CALL(*mockFileSystem, exists(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_directory(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, list_directory(_)).WillRepeatedly(Return(fakeFiles));
    EXPECT_CALL(*mockFileSystem, is_regular_file(_)).WillRepeatedly(Return(false));

    std::vector<std::string> fakePackageLines = {"Name: TestPackage", "Version: 1.0.0"};
    EXPECT_CALL(*mockFileIO, readLineByLine(std::filesystem::path("/fake/dir/egg-info/PKG-INFO"), _)).WillOnce([&](const std::filesystem::path&, const std::function<bool(const std::string&)>& callback)
    {
        for (const auto& line : fakePackageLines)
        {
            callback(line);
        }
    });

    nlohmann::json capturedJson;
    auto callback = [&](nlohmann::json & j)
    {
        capturedJson = j;
    };

    std::set<std::string> folders = { "/usr/local/lib/python3.9/site-packages" };

    pypi->getPackages(folders, callback);

    EXPECT_EQ(capturedJson.at("name"), "TestPackage");
    EXPECT_EQ(capturedJson.at("version"), "1.0.0");
}


TEST_F(PYPITest, getPackages_MultipleValidPackagesTest)
{
    std::vector<std::filesystem::path> fakeFiles = {"/fake/dir1/egg-info", "/fake/dir2/dist-info"};

    EXPECT_CALL(*mockFileSystem, exists(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_directory(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, list_directory(_)).WillRepeatedly(Return(fakeFiles));
    EXPECT_CALL(*mockFileSystem, is_regular_file(_)).WillRepeatedly(Return(true));

    std::vector<std::string> fakePackageLines1 = {"Name: TestPackage1", "Version: 1.0.0"};
    std::vector<std::string> fakePackageLines2 = {"Name: TestPackage2", "Version: 2.0.0"};

    EXPECT_CALL(*mockFileIO, readLineByLine(std::filesystem::path("/fake/dir1/egg-info"), _)).WillOnce([&](const std::filesystem::path&, const std::function<bool(const std::string&)>& callback)
    {
        for (const auto& line : fakePackageLines1)
        {
            callback(line);
        }
    });

    EXPECT_CALL(*mockFileIO, readLineByLine(std::filesystem::path("/fake/dir2/dist-info"), _)).WillOnce([&](const std::filesystem::path&, const std::function<bool(const std::string&)>& callback)
    {
        for (const auto& line : fakePackageLines2)
        {
            callback(line);
        }
    });

    bool foundPackage1 = false;
    bool foundPackage2 = false;

    nlohmann::json capturedJson;
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

    std::set<std::string> folders = { "/usr/local/lib/python3.9/site-packages" };

    pypi->getPackages(folders, callback);

    EXPECT_TRUE(foundPackage1);
    EXPECT_TRUE(foundPackage2);
}

TEST_F(PYPITest, getPackages_InvalidPackageTest_NoLines)
{
    std::vector<std::filesystem::path> fakeFiles = {"/fake/dir/egg-info"};

    EXPECT_CALL(*mockFileSystem, exists(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_directory(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, list_directory(_)).WillRepeatedly(Return(fakeFiles));
    EXPECT_CALL(*mockFileSystem, is_regular_file(_)).WillRepeatedly(Return(true));

    std::vector<std::string> fakePackageLines = {};

    EXPECT_CALL(*mockFileIO, readLineByLine(std::filesystem::path("/fake/dir/egg-info"), _)).WillOnce([&](const std::filesystem::path&, const std::function<bool(const std::string&)>& callback)
    {
        for (const auto& line : fakePackageLines)
        {
            callback(line);
        }
    });

    nlohmann::json capturedJson;
    auto callback = [&](nlohmann::json & j)
    {
        capturedJson = j;
    };

    std::set<std::string> folders = { "/usr/local/lib/python3.9/site-packages" };

    pypi->getPackages(folders, callback);

    EXPECT_TRUE(capturedJson.empty());
}

TEST_F(PYPITest, getPackages_InvalidPackageTest_InvalidLines)
{
    std::vector<std::filesystem::path> fakeFiles = {"/fake/dir/dist-info"};

    EXPECT_CALL(*mockFileSystem, exists(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_directory(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, list_directory(_)).WillRepeatedly(Return(fakeFiles));
    EXPECT_CALL(*mockFileSystem, is_regular_file(_)).WillRepeatedly(Return(true));

    std::vector<std::string> fakePackageLines = {"Invalid: TestPackage", "Invalid: 1.0.0"};

    EXPECT_CALL(*mockFileIO, readLineByLine(std::filesystem::path("/fake/dir/dist-info"), _)).WillOnce([&](const std::filesystem::path&, const std::function<bool(const std::string&)>& callback)
    {
        for (const auto& line : fakePackageLines)
        {
            callback(line);
        }
    });

    nlohmann::json capturedJson;
    auto callback = [&](nlohmann::json & j)
    {
        capturedJson = j;
    };

    std::set<std::string> folders = { "/usr/local/lib/python3.9/site-packages" };

    pypi->getPackages(folders, callback);

    EXPECT_TRUE(capturedJson.empty());
}

TEST_F(PYPITest, getPackages_InvalidPackageTest_MissingName)
{
    std::vector<std::filesystem::path> fakeFiles = {"/fake/dir/dist-info"};

    EXPECT_CALL(*mockFileSystem, exists(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_directory(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, list_directory(_)).WillRepeatedly(Return(fakeFiles));
    EXPECT_CALL(*mockFileSystem, is_regular_file(_)).WillRepeatedly(Return(true));

    std::vector<std::string> fakePackageLines = {"Version: 1.0.0"};

    EXPECT_CALL(*mockFileIO, readLineByLine(std::filesystem::path("/fake/dir/dist-info"), _)).WillOnce([&](const std::filesystem::path&, const std::function<bool(const std::string&)>& callback)
    {
        for (const auto& line : fakePackageLines)
        {
            callback(line);
        }
    });

    nlohmann::json capturedJson;
    auto callback = [&](nlohmann::json & j)
    {
        capturedJson = j;
    };

    std::set<std::string> folders = { "/usr/local/lib/python3.9/site-packages" };

    pypi->getPackages(folders, callback);

    EXPECT_TRUE(capturedJson.empty());
}

TEST_F(PYPITest, getPackages_InvalidPackageTest_MissingVersion)
{
    std::vector<std::filesystem::path> fakeFiles = {"/fake/dir/dist-info"};

    EXPECT_CALL(*mockFileSystem, exists(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_directory(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, list_directory(_)).WillRepeatedly(Return(fakeFiles));
    EXPECT_CALL(*mockFileSystem, is_regular_file(_)).WillRepeatedly(Return(true));

    std::vector<std::string> fakePackageLines = {"Name: TestPackage"};

    EXPECT_CALL(*mockFileIO, readLineByLine(std::filesystem::path("/fake/dir/dist-info"), _)).WillOnce([&](const std::filesystem::path&, const std::function<bool(const std::string&)>& callback)
    {
        for (const auto& line : fakePackageLines)
        {
            callback(line);
        }
    });

    nlohmann::json capturedJson;
    auto callback = [&](nlohmann::json & j)
    {
        capturedJson = j;
    };

    std::set<std::string> folders = { "/usr/local/lib/python3.9/site-packages" };

    pypi->getPackages(folders, callback);

    std::cout << capturedJson.dump(4) << std::endl;
    EXPECT_TRUE(capturedJson.empty());
}
