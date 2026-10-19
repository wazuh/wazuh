/*
 * Wazuh SysInfo
 * Copyright (C) Wazuh Inc.
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
    EXPECT_EQ(capturedJson.at("version_"), "1.0.0");
}

TEST_F(PYPITest, getPackages_OneValidPackageTestNoRegularFileDistInfo)
{
    std::vector<std::filesystem::path> fakeFiles = {"/fake/dir/dist-info"};

    EXPECT_CALL(*mockFileSystem, exists(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_directory(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, list_directory(_)).WillRepeatedly(Return(fakeFiles));
    EXPECT_CALL(*mockFileSystem, is_regular_file(std::filesystem::path("/fake/dir/dist-info"))).WillRepeatedly(Return(false));
    EXPECT_CALL(*mockFileSystem, is_regular_file(std::filesystem::path("/fake/dir/dist-info/METADATA"))).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_regular_file(std::filesystem::path("/fake/dir/dist-info/RECORD"))).WillRepeatedly(Return(false));

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
    EXPECT_EQ(capturedJson.at("version_"), "1.0.0");
    EXPECT_FALSE(capturedJson.contains("size"));
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
    EXPECT_EQ(capturedJson.at("version_"), "1.0.0");
}

TEST_F(PYPITest, getPackages_OneValidPackageTestNoRegularFileEggInfo)
{
    std::vector<std::filesystem::path> fakeFiles = {"/fake/dir/egg-info"};

    EXPECT_CALL(*mockFileSystem, exists(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_directory(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, list_directory(_)).WillRepeatedly(Return(fakeFiles));
    EXPECT_CALL(*mockFileSystem, is_regular_file(std::filesystem::path("/fake/dir/egg-info"))).WillRepeatedly(Return(false));
    EXPECT_CALL(*mockFileSystem, is_regular_file(std::filesystem::path("/fake/dir/egg-info/PKG-INFO"))).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_regular_file(std::filesystem::path("/fake/dir/egg-info/installed-files.txt"))).WillRepeatedly(Return(false));

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
    EXPECT_EQ(capturedJson.at("version_"), "1.0.0");
    EXPECT_FALSE(capturedJson.contains("size"));
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
        if (json.at("name") == "TestPackage1" && json.at("version_") == "1.0.0")
        {
            foundPackage1 = true;
        }
        else if (json.at("name") == "TestPackage2" && json.at("version_") == "2.0.0")
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

TEST_F(PYPITest, getPackages_NonRegularMetadataFileInDistInfoIsSkipped)
{
    std::vector<std::filesystem::path> fakeFiles = {"/fake/dir/dist-info"};

    EXPECT_CALL(*mockFileSystem, exists(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_directory(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, list_directory(_)).WillRepeatedly(Return(fakeFiles));
    EXPECT_CALL(*mockFileSystem, is_regular_file(_)).WillRepeatedly(Return(false));
    EXPECT_CALL(*mockFileIO, readLineByLine(_, _)).Times(0);

    bool callbackCalled = false;
    std::set<std::string> folders = { "/usr/local/lib/python3.9/site-packages" };

    pypi->getPackages(folders, [&](nlohmann::json&)
    {
        callbackCalled = true;
    });

    EXPECT_FALSE(callbackCalled);
}

TEST_F(PYPITest, getPackages_NonRegularMetadataFileInEggInfoIsSkipped)
{
    std::vector<std::filesystem::path> fakeFiles = {"/fake/dir/egg-info"};

    EXPECT_CALL(*mockFileSystem, exists(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_directory(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, list_directory(_)).WillRepeatedly(Return(fakeFiles));
    EXPECT_CALL(*mockFileSystem, is_regular_file(_)).WillRepeatedly(Return(false));
    EXPECT_CALL(*mockFileIO, readLineByLine(_, _)).Times(0);

    bool callbackCalled = false;
    std::set<std::string> folders = { "/usr/local/lib/python3.9/site-packages" };

    pypi->getPackages(folders, [&](nlohmann::json&)
    {
        callbackCalled = true;
    });

    EXPECT_FALSE(callbackCalled);
}

TEST_F(PYPITest, getPackages_EntryNeitherFileNorDirectoryIsSkipped)
{
    std::vector<std::filesystem::path> fakeFiles = {"/fake/dir/dist-info"};

    EXPECT_CALL(*mockFileSystem, exists(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_directory(std::filesystem::path("/usr/local/lib/python3.9/site-packages"))).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_directory(std::filesystem::path("/fake/dir/dist-info"))).WillRepeatedly(Return(false));
    EXPECT_CALL(*mockFileSystem, list_directory(_)).WillRepeatedly(Return(fakeFiles));
    EXPECT_CALL(*mockFileSystem, is_regular_file(_)).WillRepeatedly(Return(false));
    EXPECT_CALL(*mockFileIO, readLineByLine(_, _)).Times(0);

    bool callbackCalled = false;
    std::set<std::string> folders = { "/usr/local/lib/python3.9/site-packages" };

    pypi->getPackages(folders, [&](nlohmann::json&)
    {
        callbackCalled = true;
    });

    EXPECT_FALSE(callbackCalled);
}

namespace
{
    const std::filesystem::path SITE_PACKAGES {"/usr/local/lib/python3.9/site-packages"};

    // Feeds the given lines to the readLineByLine callback
    auto feedLines(const std::vector<std::string>& lines)
    {
        return [lines](const std::filesystem::path&, const std::function<bool(const std::string&)>& callback)
        {
            for (const auto& line : lines)
            {
                if (!callback(line))
                {
                    break;
                }
            }
        };
    }
} // namespace

TEST_F(PYPITest, getPackages_DistInfoSizeIsSumOfRecordFilesOnDisk)
{
    const auto distInfo {SITE_PACKAGES / "pkg-1.0.0.dist-info"};

    EXPECT_CALL(*mockFileSystem, exists(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_directory(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, list_directory(_)).WillRepeatedly(Return(std::vector<std::filesystem::path> {distInfo}));
    EXPECT_CALL(*mockFileSystem, is_regular_file(distInfo)).WillRepeatedly(Return(false));
    EXPECT_CALL(*mockFileSystem, is_regular_file(distInfo / "METADATA")).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_regular_file(distInfo / "RECORD")).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_regular_file(distInfo / "direct_url.json")).WillRepeatedly(Return(false));

    EXPECT_CALL(*mockFileIO, readLineByLine(distInfo / "METADATA", _))
    .WillOnce(feedLines({"Name: pkg", "Version: 1.0.0"}));
    // The size column is ignored: the .pyc has none, and the module's is stale
    EXPECT_CALL(*mockFileIO, readLineByLine(distInfo / "RECORD", _))
    .WillOnce(feedLines({"pkg/__init__.py,sha256=abc,1",
                         "pkg/__pycache__/__init__.cpython-39.pyc,,",
                         "\"pkg/we,ird.py\",sha256=def,5\r",
                         "../../../bin/pkg-cli,sha256=ghi,7",
                         "pkg/gone.py,sha256=jkl,9",
                         "pkg-1.0.0.dist-info/RECORD,,"}));

    EXPECT_CALL(*mockFileSystem, file_size(_)).WillRepeatedly(Return(0));
    EXPECT_CALL(*mockFileSystem, file_size(SITE_PACKAGES / "pkg/__init__.py")).WillOnce(Return(100));
    EXPECT_CALL(*mockFileSystem, file_size(SITE_PACKAGES / "pkg/__pycache__/__init__.cpython-39.pyc")).WillOnce(Return(200));
    EXPECT_CALL(*mockFileSystem, file_size(SITE_PACKAGES / "pkg/we,ird.py")).WillOnce(Return(30));
    EXPECT_CALL(*mockFileSystem, file_size(std::filesystem::path("/usr/local/bin/pkg-cli"))).WillOnce(Return(4));
    EXPECT_CALL(*mockFileSystem, file_size(SITE_PACKAGES / "pkg-1.0.0.dist-info/RECORD")).WillOnce(Return(5));

    nlohmann::json capturedJson;
    pypi->getPackages({SITE_PACKAGES.string()}, [&](nlohmann::json & j)
    {
        capturedJson = j;
    });

    EXPECT_EQ(capturedJson.at("name"), "pkg");
    EXPECT_EQ(capturedJson.at("size"), 339);
}

TEST_F(PYPITest, getPackages_RecordPathsOutsideSitePackagesAreMeasured)
{
#ifdef _WIN32
    GTEST_SKIP() << "Apple's bytecode cache only exists on macOS";
#endif
    // Apple's Python keeps the bytecode under ~/Library/Caches, five levels above site-packages
    const std::filesystem::path sitePackages {"/Users/u/Library/Python/3.9/lib/python/site-packages"};
    const auto distInfo {sitePackages / "pkg-1.0.0.dist-info"};

    EXPECT_CALL(*mockFileSystem, exists(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_directory(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, list_directory(_)).WillRepeatedly(Return(std::vector<std::filesystem::path> {distInfo}));
    EXPECT_CALL(*mockFileSystem, is_regular_file(distInfo)).WillRepeatedly(Return(false));
    EXPECT_CALL(*mockFileSystem, is_regular_file(distInfo / "METADATA")).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_regular_file(distInfo / "RECORD")).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_regular_file(distInfo / "direct_url.json")).WillRepeatedly(Return(false));

    EXPECT_CALL(*mockFileIO, readLineByLine(distInfo / "METADATA", _))
    .WillOnce(feedLines({"Name: pkg", "Version: 1.0.0"}));
    EXPECT_CALL(*mockFileIO, readLineByLine(distInfo / "RECORD", _))
    .WillOnce(feedLines({"pkg/__init__.py,sha256=abc,10",
                         "../../../../../Caches/com.apple.python/Users/u/Library/Python/3.9/lib/python/site-packages/pkg/__init__.cpython-39.pyc,,",
                         "/opt/pkg/data.bin,sha256=def,3"}));

    EXPECT_CALL(*mockFileSystem, file_size(sitePackages / "pkg/__init__.py")).WillOnce(Return(10));
    EXPECT_CALL(*mockFileSystem,
                file_size(std::filesystem::path("/Users/u/Library/Caches/com.apple.python/Users/u/Library/Python/3.9/lib/python/site-packages/pkg/__init__.cpython-39.pyc")))
    .WillOnce(Return(200));
    // An absolute path is never touched
    EXPECT_CALL(*mockFileSystem, file_size(std::filesystem::path("/opt/pkg/data.bin"))).Times(0);

    nlohmann::json capturedJson;
    pypi->getPackages({sitePackages.string()}, [&](nlohmann::json & j)
    {
        capturedJson = j;
    });

    EXPECT_EQ(capturedJson.at("size"), 210);
}

TEST_F(PYPITest, getPackages_EggInfoSizeIsSumOfInstalledFiles)
{
    const auto eggInfo {SITE_PACKAGES / "pkg-1.0.0.egg-info"};

    EXPECT_CALL(*mockFileSystem, exists(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_directory(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, list_directory(_)).WillRepeatedly(Return(std::vector<std::filesystem::path> {eggInfo}));
    EXPECT_CALL(*mockFileSystem, is_regular_file(eggInfo)).WillRepeatedly(Return(false));
    EXPECT_CALL(*mockFileSystem, is_regular_file(eggInfo / "PKG-INFO")).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_regular_file(eggInfo / "installed-files.txt")).WillRepeatedly(Return(true));

    EXPECT_CALL(*mockFileIO, readLineByLine(eggInfo / "PKG-INFO", _))
    .WillOnce(feedLines({"Name: pkg", "Version: 1.0.0"}));
    // Paths are relative to the egg-info directory, scripts sit one level further up
    EXPECT_CALL(*mockFileIO, readLineByLine(eggInfo / "installed-files.txt", _))
    .WillOnce(feedLines({"../pkg/__init__.py", "", "../../../../bin/pkg-cli\r", "PKG-INFO"}));

    EXPECT_CALL(*mockFileSystem, file_size(SITE_PACKAGES / "pkg/__init__.py")).WillOnce(Return(100));
    EXPECT_CALL(*mockFileSystem, file_size(std::filesystem::path("/usr/local/bin/pkg-cli"))).WillOnce(Return(20));
    EXPECT_CALL(*mockFileSystem, file_size(eggInfo / "PKG-INFO")).WillOnce(Return(3));

    nlohmann::json capturedJson;
    pypi->getPackages({SITE_PACKAGES.string()}, [&](nlohmann::json & j)
    {
        capturedJson = j;
    });

    EXPECT_EQ(capturedJson.at("size"), 123);
}

TEST_F(PYPITest, getPackages_WithoutFileListSizeIsAbsent)
{
    const auto distInfo {SITE_PACKAGES / "pkg-1.0.0.dist-info"};

    EXPECT_CALL(*mockFileSystem, exists(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_directory(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, list_directory(_)).WillRepeatedly(Return(std::vector<std::filesystem::path> {distInfo}));
    EXPECT_CALL(*mockFileSystem, is_regular_file(distInfo)).WillRepeatedly(Return(false));
    EXPECT_CALL(*mockFileSystem, is_regular_file(distInfo / "METADATA")).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_regular_file(distInfo / "RECORD")).WillRepeatedly(Return(false));

    EXPECT_CALL(*mockFileIO, readLineByLine(distInfo / "METADATA", _))
    .WillOnce(feedLines({"Name: pkg", "Version: 1.0.0"}));
    EXPECT_CALL(*mockFileIO, readLineByLine(distInfo / "RECORD", _)).Times(0);

    nlohmann::json capturedJson;
    pypi->getPackages({SITE_PACKAGES.string()}, [&](nlohmann::json & j)
    {
        capturedJson = j;
    });

    // Unknown, never zero
    EXPECT_EQ(capturedJson.at("name"), "pkg");
    EXPECT_FALSE(capturedJson.contains("size"));
}

TEST_F(PYPITest, getPackages_NoListedFileOnDiskSizeIsAbsent)
{
    const auto distInfo {SITE_PACKAGES / "pkg-1.0.0.dist-info"};

    EXPECT_CALL(*mockFileSystem, exists(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_directory(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, list_directory(_)).WillRepeatedly(Return(std::vector<std::filesystem::path> {distInfo}));
    EXPECT_CALL(*mockFileSystem, is_regular_file(distInfo)).WillRepeatedly(Return(false));
    EXPECT_CALL(*mockFileSystem, is_regular_file(distInfo / "METADATA")).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_regular_file(distInfo / "RECORD")).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_regular_file(distInfo / "direct_url.json")).WillRepeatedly(Return(false));

    EXPECT_CALL(*mockFileIO, readLineByLine(distInfo / "METADATA", _))
    .WillOnce(feedLines({"Name: pkg", "Version: 1.0.0"}));
    EXPECT_CALL(*mockFileIO, readLineByLine(distInfo / "RECORD", _))
    .WillOnce(feedLines({"pkg/gone.py,sha256=abc,100"}));
    EXPECT_CALL(*mockFileSystem, file_size(_)).WillRepeatedly(Return(0));

    nlohmann::json capturedJson;
    pypi->getPackages({SITE_PACKAGES.string()}, [&](nlohmann::json & j)
    {
        capturedJson = j;
    });

    EXPECT_FALSE(capturedJson.contains("size"));
}

TEST_F(PYPITest, getPackages_SingleFileEggInfoSizeIsAbsent)
{
    const auto eggInfo {SITE_PACKAGES / "pkg-1.0.0.egg-info"};

    EXPECT_CALL(*mockFileSystem, exists(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, is_directory(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mockFileSystem, list_directory(_)).WillRepeatedly(Return(std::vector<std::filesystem::path> {eggInfo}));
    EXPECT_CALL(*mockFileSystem, is_regular_file(eggInfo)).WillRepeatedly(Return(true));

    // The lone file is the metadata itself, there is no list to read
    EXPECT_CALL(*mockFileIO, readLineByLine(eggInfo, _)).WillOnce(feedLines({"Name: pkg", "Version: 1.0.0"}));
    EXPECT_CALL(*mockFileSystem, file_size(_)).Times(0);

    nlohmann::json capturedJson;
    pypi->getPackages({SITE_PACKAGES.string()}, [&](nlohmann::json & j)
    {
        capturedJson = j;
    });

    EXPECT_EQ(capturedJson.at("name"), "pkg");
    EXPECT_FALSE(capturedJson.contains("size"));
}

namespace
{
    // Common expectations for a dist-info directory with a RECORD and the given direct_url.json presence
    void expectDistInfo(MockFileSystemWrapper& fs, const std::filesystem::path& distInfo, const bool hasDirectUrl)
    {
        EXPECT_CALL(fs, exists(_)).WillRepeatedly(Return(true));
        EXPECT_CALL(fs, is_directory(_)).WillRepeatedly(Return(true));
        EXPECT_CALL(fs, list_directory(_)).WillRepeatedly(Return(std::vector<std::filesystem::path> {distInfo}));
        EXPECT_CALL(fs, is_regular_file(distInfo)).WillRepeatedly(Return(false));
        EXPECT_CALL(fs, is_regular_file(distInfo / "METADATA")).WillRepeatedly(Return(true));
        EXPECT_CALL(fs, is_regular_file(distInfo / "RECORD")).WillRepeatedly(Return(true));
        EXPECT_CALL(fs, is_regular_file(distInfo / "direct_url.json")).WillRepeatedly(Return(hasDirectUrl));
    }
} // namespace

TEST_F(PYPITest, getPackages_RecordSymlinksAndRepeatedEntriesAreCountedOnce)
{
    const auto distInfo {SITE_PACKAGES / "pkg-1.0.0.dist-info"};
    expectDistInfo(*mockFileSystem, distInfo, false);

    EXPECT_CALL(*mockFileIO, readLineByLine(distInfo / "METADATA", _))
    .WillOnce(feedLines({"Name: pkg", "Version: 1.0.0"}));
    EXPECT_CALL(*mockFileIO, readLineByLine(distInfo / "RECORD", _))
    .WillOnce(feedLines({"pkg/__init__.py,,", "pkg/./__init__.py,,", "pkg/link.py,,", "pkg/data.bin,,"}));

    EXPECT_CALL(*mockFileSystem, is_symlink(_)).WillRepeatedly(Return(false));
    EXPECT_CALL(*mockFileSystem, is_symlink(SITE_PACKAGES / "pkg/link.py")).WillRepeatedly(Return(true));
    // The repeated entry normalizes to the same path and is sized once; the link is never sized
    EXPECT_CALL(*mockFileSystem, file_size(SITE_PACKAGES / "pkg/__init__.py")).WillOnce(Return(10));
    EXPECT_CALL(*mockFileSystem, file_size(SITE_PACKAGES / "pkg/link.py")).Times(0);
    EXPECT_CALL(*mockFileSystem, file_size(SITE_PACKAGES / "pkg/data.bin")).WillOnce(Return(5));

    nlohmann::json capturedJson;
    pypi->getPackages({SITE_PACKAGES.string()}, [&](nlohmann::json & j)
    {
        capturedJson = j;
    });

    EXPECT_EQ(capturedJson.at("size"), 15);
}

TEST_F(PYPITest, getPackages_UninspectableEntryIsSkipped)
{
    const auto distInfo {SITE_PACKAGES / "pkg-1.0.0.dist-info"};
    expectDistInfo(*mockFileSystem, distInfo, false);

    EXPECT_CALL(*mockFileIO, readLineByLine(distInfo / "METADATA", _))
    .WillOnce(feedLines({"Name: pkg", "Version: 1.0.0"}));
    EXPECT_CALL(*mockFileIO, readLineByLine(distInfo / "RECORD", _))
    .WillOnce(feedLines({"pkg/denied.py,,", "pkg/__init__.py,,"}));

    EXPECT_CALL(*mockFileSystem, is_symlink(SITE_PACKAGES / "pkg/denied.py"))
    .WillOnce(testing::Throw(std::filesystem::filesystem_error("denied", std::make_error_code(std::errc::permission_denied))));
    EXPECT_CALL(*mockFileSystem, is_symlink(SITE_PACKAGES / "pkg/__init__.py")).WillOnce(Return(false));
    EXPECT_CALL(*mockFileSystem, file_size(SITE_PACKAGES / "pkg/__init__.py")).WillOnce(Return(10));

    nlohmann::json capturedJson;
    pypi->getPackages({SITE_PACKAGES.string()}, [&](nlohmann::json & j)
    {
        capturedJson = j;
    });

    // One unreadable entry does not drop the package
    EXPECT_EQ(capturedJson.at("name"), "pkg");
    EXPECT_EQ(capturedJson.at("size"), 10);
}

TEST_F(PYPITest, getPackages_OverflowingSumSizeIsAbsent)
{
    const auto distInfo {SITE_PACKAGES / "pkg-1.0.0.dist-info"};
    expectDistInfo(*mockFileSystem, distInfo, false);

    EXPECT_CALL(*mockFileIO, readLineByLine(distInfo / "METADATA", _))
    .WillOnce(feedLines({"Name: pkg", "Version: 1.0.0"}));
    EXPECT_CALL(*mockFileIO, readLineByLine(distInfo / "RECORD", _))
    .WillOnce(feedLines({"pkg/a.bin,,", "pkg/b.bin,,"}));

    EXPECT_CALL(*mockFileSystem, is_symlink(_)).WillRepeatedly(Return(false));
    EXPECT_CALL(*mockFileSystem, file_size(SITE_PACKAGES / "pkg/a.bin"))
    .WillOnce(Return(static_cast<std::uintmax_t>(std::numeric_limits<int64_t>::max())));
    EXPECT_CALL(*mockFileSystem, file_size(SITE_PACKAGES / "pkg/b.bin")).WillOnce(Return(1));

    nlohmann::json capturedJson;
    pypi->getPackages({SITE_PACKAGES.string()}, [&](nlohmann::json & j)
    {
        capturedJson = j;
    });

    EXPECT_EQ(capturedJson.at("name"), "pkg");
    EXPECT_FALSE(capturedJson.contains("size"));
}

TEST_F(PYPITest, getPackages_EditableInstallSizeIsAbsent)
{
    const auto distInfo {SITE_PACKAGES / "pkg-1.0.0.dist-info"};
    expectDistInfo(*mockFileSystem, distInfo, true);

    EXPECT_CALL(*mockFileIO, readLineByLine(distInfo / "METADATA", _))
    .WillOnce(feedLines({"Name: pkg", "Version: 1.0.0"}));
    EXPECT_CALL(*mockFileIO, readLineByLine(distInfo / "direct_url.json", _))
    .WillOnce(feedLines({"{\"url\": \"file:///home/dev/pkg\",", " \"dir_info\": {\"editable\": true}}"}));
    // Its RECORD only lists the stub pointing at the source tree, so it is not measured
    EXPECT_CALL(*mockFileIO, readLineByLine(distInfo / "RECORD", _)).Times(0);
    EXPECT_CALL(*mockFileSystem, file_size(_)).Times(0);

    nlohmann::json capturedJson;
    pypi->getPackages({SITE_PACKAGES.string()}, [&](nlohmann::json & j)
    {
        capturedJson = j;
    });

    EXPECT_EQ(capturedJson.at("name"), "pkg");
    EXPECT_FALSE(capturedJson.contains("size"));
}

TEST_F(PYPITest, getPackages_NonEditableDirectUrlIsMeasured)
{
    const auto distInfo {SITE_PACKAGES / "pkg-1.0.0.dist-info"};
    expectDistInfo(*mockFileSystem, distInfo, true);

    EXPECT_CALL(*mockFileIO, readLineByLine(distInfo / "METADATA", _))
    .WillOnce(feedLines({"Name: pkg", "Version: 1.0.0"}));
    // Installed from a local directory without -e, and a malformed editable flag: both are measured
    EXPECT_CALL(*mockFileIO, readLineByLine(distInfo / "direct_url.json", _))
    .WillOnce(feedLines({"{\"url\": \"file:///home/dev/pkg\", \"dir_info\": {\"editable\": \"yes\"}}"}));
    EXPECT_CALL(*mockFileIO, readLineByLine(distInfo / "RECORD", _)).WillOnce(feedLines({"pkg/__init__.py,,"}));
    EXPECT_CALL(*mockFileSystem, is_symlink(_)).WillRepeatedly(Return(false));
    EXPECT_CALL(*mockFileSystem, file_size(SITE_PACKAGES / "pkg/__init__.py")).WillOnce(Return(10));

    nlohmann::json capturedJson;
    pypi->getPackages({SITE_PACKAGES.string()}, [&](nlohmann::json & j)
    {
        capturedJson = j;
    });

    EXPECT_EQ(capturedJson.at("size"), 10);
}

TEST_F(PYPITest, getPackages_RecordEntriesOutsideTheInstallationAreNeverTouched)
{
    const auto distInfo {SITE_PACKAGES / "pkg-1.0.0.dist-info"};
    expectDistInfo(*mockFileSystem, distInfo, false);

    EXPECT_CALL(*mockFileIO, readLineByLine(distInfo / "METADATA", _))
    .WillOnce(feedLines({"Name: pkg", "Version: 1.0.0"}));
    // RECORD is writable by whoever owns the installation: an absolute path, a network share and a
    // relative path climbing above the prefix must not reach the filesystem at all
    EXPECT_CALL(*mockFileIO, readLineByLine(distInfo / "RECORD", _))
    .WillOnce(feedLines({"pkg/__init__.py,,",
                         "/etc/shadow,,",
                         "//fileserver/share/x,,",
                         "../../../../../../../../net/fileserver/x,,",
                         "../../../../etc/passwd,,"}));

    EXPECT_CALL(*mockFileSystem, is_symlink(SITE_PACKAGES / "pkg/__init__.py")).WillOnce(Return(false));
    EXPECT_CALL(*mockFileSystem, file_size(SITE_PACKAGES / "pkg/__init__.py")).WillOnce(Return(10));
    // Only the entry inside the installation is ever inspected
    EXPECT_CALL(*mockFileSystem, is_symlink(testing::Ne(SITE_PACKAGES / "pkg/__init__.py"))).Times(0);
    EXPECT_CALL(*mockFileSystem, file_size(testing::Ne(SITE_PACKAGES / "pkg/__init__.py"))).Times(0);

    nlohmann::json capturedJson;
    pypi->getPackages({SITE_PACKAGES.string()}, [&](nlohmann::json & j)
    {
        capturedJson = j;
    });

    EXPECT_EQ(capturedJson.at("size"), 10);
}

TEST_F(PYPITest, getPackages_ScriptsInThePrefixBinAreMeasured)
{
    // <prefix>/lib/python3.9/site-packages -> <prefix>/bin is three levels up, inside the prefix
    const auto distInfo {SITE_PACKAGES / "pkg-1.0.0.dist-info"};
    expectDistInfo(*mockFileSystem, distInfo, false);

    EXPECT_CALL(*mockFileIO, readLineByLine(distInfo / "METADATA", _))
    .WillOnce(feedLines({"Name: pkg", "Version: 1.0.0"}));
    EXPECT_CALL(*mockFileIO, readLineByLine(distInfo / "RECORD", _))
    .WillOnce(feedLines({"../../../bin/pkg-cli,,", "../../../../bin/outside,,"}));

    EXPECT_CALL(*mockFileSystem, is_symlink(std::filesystem::path("/usr/local/bin/pkg-cli"))).WillOnce(Return(false));
    EXPECT_CALL(*mockFileSystem, file_size(std::filesystem::path("/usr/local/bin/pkg-cli"))).WillOnce(Return(7));
    // /usr/bin is above the /usr/local prefix
    EXPECT_CALL(*mockFileSystem, file_size(std::filesystem::path("/usr/bin/outside"))).Times(0);

    nlohmann::json capturedJson;
    pypi->getPackages({SITE_PACKAGES.string()}, [&](nlohmann::json & j)
    {
        capturedJson = j;
    });

    EXPECT_EQ(capturedJson.at("size"), 7);
}
