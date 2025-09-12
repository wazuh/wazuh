/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * January 28, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "sysInfoPackagesLinuxHelper_test.h"
#include "packages/packageLinuxParserHelper.h"
#include "packages/packageLinuxParserHelperExtra.h"
#include "packages/packageLinuxRpmParserHelper.h"
#include "packages/packageLinuxRpmParserHelperLegacy.h"
#include "packages/packageLinuxApkParserHelper.h"
#include "packages/rpmPackageManager.h"
#include <alpm.h>
#include <package.h>
#include <handle.h>
#include "sharedDefs.h"

using ::testing::_;
using ::testing::Return;

void SysInfoPackagesLinuxHelperTest::SetUp() {};
void SysInfoPackagesLinuxHelperTest::TearDown() {};

TEST_F(SysInfoPackagesLinuxHelperTest, parseRpmInformation)
{
    constexpr auto RPM_PACKAGE_CENTOS
    {
        "mktemp\tx86_64\tA small utility for safely making /tmp files.\t4111222333\t3\t24.el5\t1.5\tCentOS\t1425472738\tSystem Environment/Base\t"
    };

    const auto& jsPackageInfo { PackageLinuxHelper::parseRpm(RPM_PACKAGE_CENTOS) };
    EXPECT_FALSE(jsPackageInfo.empty());
    EXPECT_EQ("mktemp", jsPackageInfo["name"]);
    EXPECT_EQ(4111222333, jsPackageInfo["size"]);
    EXPECT_EQ("1425472738", jsPackageInfo["installed"]);
    EXPECT_EQ("System Environment/Base", jsPackageInfo["category"]);
    EXPECT_EQ("3:1.5-24.el5", jsPackageInfo["version"]);
    EXPECT_EQ("x86_64", jsPackageInfo["architecture"]);
    EXPECT_EQ("rpm", jsPackageInfo["type"]);
    EXPECT_EQ("CentOS", jsPackageInfo["vendor"]);
    EXPECT_EQ("A small utility for safely making /tmp files.", jsPackageInfo["description"]);
}

TEST_F(SysInfoPackagesLinuxHelperTest, parseRpmInformationLibRpm)
{
    RpmPackageManager::Package input;
    input.name = "mktemp";
    input.size = 4111222333;
    input.installTime = "1425472738";
    input.group = "System Environment/Base";
    input.version = "1.5";
    input.architecture = "x86_64";
    input.vendor = "CentOS";
    input.description = "A small utility for safely making /tmp files.";
    input.epoch = 3;
    input.release = "24.el5";

    const auto& jsPackageInfo { PackageLinuxHelper::parseRpm(input) };
    EXPECT_EQ("mktemp", jsPackageInfo["name"]);
    EXPECT_EQ(4111222333, jsPackageInfo["size"]);
    EXPECT_EQ("1425472738", jsPackageInfo["installed"]);
    EXPECT_EQ("System Environment/Base", jsPackageInfo["category"]);
    EXPECT_EQ("3:1.5-24.el5", jsPackageInfo["version"]);
    EXPECT_EQ("x86_64", jsPackageInfo["architecture"]);
    EXPECT_EQ("rpm", jsPackageInfo["type"]);
    EXPECT_EQ("CentOS", jsPackageInfo["vendor"]);
    EXPECT_EQ("A small utility for safely making /tmp files.", jsPackageInfo["description"]);
}

TEST_F(SysInfoPackagesLinuxHelperTest, parseRpmInformationGPG)
{
    constexpr auto RPM_PACKAGE_CENTOS
    {
        "gpg-pubkey\tx86_64\tA small utility for safely making /tmp files.\t15432\t3\t24.el5\t1.5\tCentOS\t1425472738\tSystem Environment/Base\t"
    };

    const auto& jsPackageInfo { PackageLinuxHelper::parseRpm(RPM_PACKAGE_CENTOS) };
    EXPECT_TRUE(jsPackageInfo.empty());
}

TEST_F(SysInfoPackagesLinuxHelperTest, parseRpmInformationGPGLibRPM)
{
    RpmPackageManager::Package input;
    input.name = "gpg-pubkey";

    const auto& jsPackageInfo { PackageLinuxHelper::parseRpm(input) };
    EXPECT_TRUE(jsPackageInfo.empty());
}

TEST_F(SysInfoPackagesLinuxHelperTest, parseRpmInformationUnknownInEmpty)
{
    constexpr auto RPM_PACKAGE_CENTOS
    {
        "curl\t\t\t\t\t\t\t\t\t\t"
    };

    const auto& jsPackageInfo { PackageLinuxHelper::parseRpm(RPM_PACKAGE_CENTOS) };
    EXPECT_FALSE(jsPackageInfo.empty());
    EXPECT_EQ("curl", jsPackageInfo["name"]);
    EXPECT_EQ(0, jsPackageInfo["size"]);
    EXPECT_EQ(UNKNOWN_VALUE, jsPackageInfo["installed"]);
    EXPECT_EQ(UNKNOWN_VALUE, jsPackageInfo["category"]);
    EXPECT_EQ(UNKNOWN_VALUE, jsPackageInfo["version"]);
    EXPECT_EQ(UNKNOWN_VALUE, jsPackageInfo["architecture"]);
    EXPECT_EQ("rpm", jsPackageInfo["type"]);
    EXPECT_EQ(UNKNOWN_VALUE, jsPackageInfo["vendor"]);
    EXPECT_EQ(UNKNOWN_VALUE, jsPackageInfo["description"]);
}


TEST_F(SysInfoPackagesLinuxHelperTest, parseRpmInformationNonEpoch)
{
    constexpr auto RPM_PACKAGE_CENTOS
    {
        "mktemp\tx86_64\tA small utility for safely making /tmp files.\t4111222333\t\t24.el5\t1.5\tCentOS\t1425472738\tSystem Environment/Base\t"
    };

    const auto& jsPackageInfo { PackageLinuxHelper::parseRpm(RPM_PACKAGE_CENTOS) };
    EXPECT_FALSE(jsPackageInfo.empty());
    EXPECT_EQ("mktemp", jsPackageInfo["name"]);
    EXPECT_EQ(4111222333, jsPackageInfo["size"]);
    EXPECT_EQ("1425472738", jsPackageInfo["installed"]);
    EXPECT_EQ("System Environment/Base", jsPackageInfo["category"]);
    EXPECT_EQ("1.5-24.el5", jsPackageInfo["version"]);
    EXPECT_EQ("x86_64", jsPackageInfo["architecture"]);
    EXPECT_EQ("rpm", jsPackageInfo["type"]);
    EXPECT_EQ("CentOS", jsPackageInfo["vendor"]);
    EXPECT_EQ("A small utility for safely making /tmp files.", jsPackageInfo["description"]);
}

TEST_F(SysInfoPackagesLinuxHelperTest, parseRpmNoEpochNoReleaseLibRpm)
{
    RpmPackageManager::Package input;
    input.name = "mktemp";
    input.size = 4111222333;
    input.installTime = "1425472738";
    input.group = "System Environment/Base";
    input.version = "4.16";
    input.architecture = "x86_64";
    input.vendor = "CentOS";
    input.description = "A small utility for safely making /tmp files.";

    const auto& jsPackageInfo { PackageLinuxHelper::parseRpm(input) };
    EXPECT_EQ("mktemp", jsPackageInfo["name"]);
    EXPECT_EQ(4111222333, jsPackageInfo["size"]);
    EXPECT_EQ("1425472738", jsPackageInfo["installed"]);
    EXPECT_EQ("System Environment/Base", jsPackageInfo["category"]);
    EXPECT_EQ("4.16", jsPackageInfo["version"]);
    EXPECT_EQ("x86_64", jsPackageInfo["architecture"]);
    EXPECT_EQ("rpm", jsPackageInfo["type"]);
    EXPECT_EQ("CentOS", jsPackageInfo["vendor"]);
    EXPECT_EQ("A small utility for safely making /tmp files.", jsPackageInfo["description"]);
}

TEST_F(SysInfoPackagesLinuxHelperTest, parseRpmNoEpochLibRpm)
{
    RpmPackageManager::Package input;
    input.name = "mktemp";
    input.size = 4111222333;
    input.installTime = "1425472738";
    input.group = "System Environment/Base";
    input.version = "4.16";
    input.architecture = "x86_64";
    input.vendor = "CentOS";
    input.description = "A small utility for safely making /tmp files.";
    input.epoch = 1;

    const auto& jsPackageInfo { PackageLinuxHelper::parseRpm(input) };
    EXPECT_EQ("mktemp", jsPackageInfo["name"]);
    EXPECT_EQ(4111222333, jsPackageInfo["size"]);
    EXPECT_EQ("1425472738", jsPackageInfo["installed"]);
    EXPECT_EQ("System Environment/Base", jsPackageInfo["category"]);
    EXPECT_EQ("1:4.16", jsPackageInfo["version"]);
    EXPECT_EQ("x86_64", jsPackageInfo["architecture"]);
    EXPECT_EQ("rpm", jsPackageInfo["type"]);
    EXPECT_EQ("CentOS", jsPackageInfo["vendor"]);
    EXPECT_EQ("A small utility for safely making /tmp files.", jsPackageInfo["description"]);
}

TEST_F(SysInfoPackagesLinuxHelperTest, parseRpmInformationNonEpochNonRelease)
{
    constexpr auto RPM_PACKAGE_CENTOS
    {
        "mktemp\tx86_64\tA small utility for safely making /tmp files.\t4111222333\t\t\t1.5\tCentOS\t1425472738\tSystem Environment/Base\t"
    };

    const auto& jsPackageInfo { PackageLinuxHelper::parseRpm(RPM_PACKAGE_CENTOS) };
    EXPECT_FALSE(jsPackageInfo.empty());
    EXPECT_EQ("mktemp", jsPackageInfo["name"]);
    EXPECT_EQ(4111222333, jsPackageInfo["size"]);
    EXPECT_EQ("1425472738", jsPackageInfo["installed"]);
    EXPECT_EQ("System Environment/Base", jsPackageInfo["category"]);
    EXPECT_EQ("1.5", jsPackageInfo["version"]);
    EXPECT_EQ("x86_64", jsPackageInfo["architecture"]);
    EXPECT_EQ("rpm", jsPackageInfo["type"]);
    EXPECT_EQ("CentOS", jsPackageInfo["vendor"]);
    EXPECT_EQ("A small utility for safely making /tmp files.", jsPackageInfo["description"]);
}

TEST_F(SysInfoPackagesLinuxHelperTest, parseRpmInformationNonRelease)
{
    constexpr auto RPM_PACKAGE_CENTOS
    {
        "mktemp\tx86_64\tA small utility for safely making /tmp files.\t4111222333\t3\t\t1.5\tCentOS\t1425472738\tSystem Environment/Base\t"
    };

    const auto& jsPackageInfo { PackageLinuxHelper::parseRpm(RPM_PACKAGE_CENTOS) };
    EXPECT_FALSE(jsPackageInfo.empty());
    EXPECT_EQ("mktemp", jsPackageInfo["name"]);
    EXPECT_EQ(4111222333, jsPackageInfo["size"]);
    EXPECT_EQ("1425472738", jsPackageInfo["installed"]);
    EXPECT_EQ("System Environment/Base", jsPackageInfo["category"]);
    EXPECT_EQ("3:1.5", jsPackageInfo["version"]);
    EXPECT_EQ("x86_64", jsPackageInfo["architecture"]);
    EXPECT_EQ("rpm", jsPackageInfo["type"]);
    EXPECT_EQ("CentOS", jsPackageInfo["vendor"]);
    EXPECT_EQ("A small utility for safely making /tmp files.", jsPackageInfo["description"]);
}

TEST_F(SysInfoPackagesLinuxHelperTest, parseRpmInformationNonEpochWithNone)
{
    constexpr auto RPM_PACKAGE_CENTOS
    {
        "mktemp\tx86_64\tA small utility for safely making /tmp files.\t4111222333\t(none)\t24.el5\t1.5\tCentOS\t1425472738\tSystem Environment/Base\t"
    };

    const auto& jsPackageInfo { PackageLinuxHelper::parseRpm(RPM_PACKAGE_CENTOS) };
    EXPECT_FALSE(jsPackageInfo.empty());
    EXPECT_EQ("mktemp", jsPackageInfo["name"]);
    EXPECT_EQ(4111222333, jsPackageInfo["size"]);
    EXPECT_EQ("1425472738", jsPackageInfo["installed"]);
    EXPECT_EQ("System Environment/Base", jsPackageInfo["category"]);
    EXPECT_EQ("1.5-24.el5", jsPackageInfo["version"]);
    EXPECT_EQ("x86_64", jsPackageInfo["architecture"]);
    EXPECT_EQ("rpm", jsPackageInfo["type"]);
    EXPECT_EQ("CentOS", jsPackageInfo["vendor"]);
    EXPECT_EQ("A small utility for safely making /tmp files.", jsPackageInfo["description"]);
}

TEST_F(SysInfoPackagesLinuxHelperTest, parseRpmInformationNonReleaseWithNone)
{
    constexpr auto RPM_PACKAGE_CENTOS
    {
        "mktemp\tx86_64\tA small utility for safely making /tmp files.\t4111222333\t3\t(none)\t1.5\tCentOS\t1425472738\tSystem Environment/Base\t"
    };

    const auto& jsPackageInfo { PackageLinuxHelper::parseRpm(RPM_PACKAGE_CENTOS) };
    EXPECT_FALSE(jsPackageInfo.empty());
    EXPECT_EQ("mktemp", jsPackageInfo["name"]);
    EXPECT_EQ(4111222333, jsPackageInfo["size"]);
    EXPECT_EQ("1425472738", jsPackageInfo["installed"]);
    EXPECT_EQ("System Environment/Base", jsPackageInfo["category"]);
    EXPECT_EQ("3:1.5", jsPackageInfo["version"]);
    EXPECT_EQ("x86_64", jsPackageInfo["architecture"]);
    EXPECT_EQ("rpm", jsPackageInfo["type"]);
    EXPECT_EQ("CentOS", jsPackageInfo["vendor"]);
    EXPECT_EQ("A small utility for safely making /tmp files.", jsPackageInfo["description"]);
}

TEST_F(SysInfoPackagesLinuxHelperTest, parseRpmInformationNonEpochNonReleaseWithNone)
{
    constexpr auto RPM_PACKAGE_CENTOS
    {
        "mktemp\tx86_64\tA small utility for safely making /tmp files.\t4111222333\t(none)\t(none)\t1.5\tCentOS\t1425472738\tSystem Environment/Base\t"
    };

    const auto& jsPackageInfo { PackageLinuxHelper::parseRpm(RPM_PACKAGE_CENTOS) };
    EXPECT_FALSE(jsPackageInfo.empty());
    EXPECT_EQ("mktemp", jsPackageInfo["name"]);
    EXPECT_EQ(4111222333, jsPackageInfo["size"]);
    EXPECT_EQ("1425472738", jsPackageInfo["installed"]);
    EXPECT_EQ("System Environment/Base", jsPackageInfo["category"]);
    EXPECT_EQ("1.5", jsPackageInfo["version"]);
    EXPECT_EQ("x86_64", jsPackageInfo["architecture"]);
    EXPECT_EQ("rpm", jsPackageInfo["type"]);
    EXPECT_EQ("CentOS", jsPackageInfo["vendor"]);
    EXPECT_EQ("A small utility for safely making /tmp files.", jsPackageInfo["description"]);
}

TEST_F(SysInfoPackagesLinuxHelperTest, parseDpkgInformation)
{
    constexpr auto PACKAGE_INFO     {"Package: zlib1g-dev"};
    constexpr auto STATUS_INFO      {"Status: install ok installed"};
    constexpr auto PRIORITY_INFO    {"Priority: optional"};
    constexpr auto SECTION_INFO     {"Section: libdevel"};
    constexpr auto SIZE_INFO        {"Installed-Size: 4014865"};
    constexpr auto VENDOR_INFO      {"Maintainer: Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>"};
    constexpr auto ARCH_INFO        {"Architecture: amd64"};
    constexpr auto MULTIARCH_INFO   {"Multi-Arch: same"};
    constexpr auto SOURCE_INFO      {"Source: zlib"};
    constexpr auto VERSION_INFO     {"Version: 1:1.2.11.dfsg-2ubuntu1.2"};
    constexpr auto DESCRIPTION_INFO
    {
        "Description: compression library - development\n\
         zlib is a library implementing the deflate compression method found\n\
         in gzip and PKZIP.  This package includes the development support\n\
         files."
    };
    std::vector<std::string> packagesList;
    packagesList.push_back(PACKAGE_INFO);
    packagesList.push_back(STATUS_INFO);
    packagesList.push_back(PRIORITY_INFO);
    packagesList.push_back(SECTION_INFO);
    packagesList.push_back(SIZE_INFO);
    packagesList.push_back(VENDOR_INFO);
    packagesList.push_back(ARCH_INFO);
    packagesList.push_back(MULTIARCH_INFO);
    packagesList.push_back(SOURCE_INFO);
    packagesList.push_back(VERSION_INFO);
    packagesList.push_back(DESCRIPTION_INFO);
    const auto& jsPackageInfo { PackageLinuxHelper::parseDpkg(packagesList) };
    EXPECT_FALSE(jsPackageInfo.empty());
    EXPECT_EQ("zlib1g-dev", jsPackageInfo["name"]);
    EXPECT_EQ("optional", jsPackageInfo["priority"]);
    EXPECT_EQ(4111221760, jsPackageInfo["size"]);
    EXPECT_EQ("libdevel", jsPackageInfo["category"]);
    EXPECT_EQ("same", jsPackageInfo["multiarch"]);
    EXPECT_EQ("1:1.2.11.dfsg-2ubuntu1.2", jsPackageInfo["version"]);
    EXPECT_EQ("amd64", jsPackageInfo["architecture"]);
    EXPECT_EQ("deb", jsPackageInfo["type"]);
    EXPECT_EQ("Ubuntu Developers", jsPackageInfo["vendor"]);
    EXPECT_EQ("compression library - development", jsPackageInfo["description"]);
    EXPECT_EQ("zlib", jsPackageInfo["source"]);
}

TEST_F(SysInfoPackagesLinuxHelperTest, parsePacmanInformation)
{
    __alpm_list_t   mock        {};
    __alpm_pkg_t    data        {};
    __alpm_handle_t dataHandle  {};
    __alpm_list_t   dataGroups  {};

    constexpr auto PKG_GROUP    {"wazuh"};
    constexpr auto PKG_ARCH     {"x86_64"};
    constexpr auto PKG_NAME     {"firefox"};
    constexpr auto PKG_DESC     {"Standalone web browser from mozilla.org"};
    constexpr auto PKG_VERSION  {"86.0-2"};

    data.handle        = &dataHandle;
    data.groups        = &dataGroups;
    data.isize         = 4111222333;
    data.installdate   = 0;
    data.groups->next  = nullptr;
    data.name          = const_cast<char*>(PKG_NAME);
    data.groups->data  = const_cast<char*>(PKG_GROUP);
    data.version       = const_cast<char*>(PKG_VERSION);
    data.arch          = const_cast<char*>(PKG_ARCH);
    data.desc          = const_cast<char*>(PKG_DESC);
    mock.data          = &data;
    data.ops           = &default_pkg_ops;

    const auto& jsPackageInfo { PackageLinuxHelper::parsePacman(&mock) };
    EXPECT_FALSE(jsPackageInfo.empty());
    EXPECT_EQ(PKG_NAME, jsPackageInfo["name"]);
    EXPECT_EQ(4111222333, jsPackageInfo["size"]);
    EXPECT_EQ("1970-01-01T00:00:00.000Z", jsPackageInfo["installed"]);
    EXPECT_EQ(PKG_GROUP, jsPackageInfo["category"]);
    EXPECT_EQ(PKG_VERSION, jsPackageInfo["version"]);
    EXPECT_EQ(PKG_ARCH, jsPackageInfo["architecture"]);
    EXPECT_EQ("pacman", jsPackageInfo["type"]);
    EXPECT_EQ("Arch Linux", jsPackageInfo["vendor"]);
    EXPECT_EQ(PKG_DESC, jsPackageInfo["description"]);
}

TEST_F(SysInfoPackagesLinuxHelperTest, parsePacmanMultipleGroups)
{
    __alpm_list_t   mock            {};
    __alpm_pkg_t    data            {};
    __alpm_handle_t dataHandle      {};
    __alpm_list_t   dataFirstGroup  {};
    __alpm_list_t   dataSecondGroup {};
    __alpm_list_t   dataThirdGroup  {};
    __alpm_list_t   dataFourthGroup {};

    dataFirstGroup.data    = const_cast<char*>("Wazuh");
    dataFirstGroup.next    = &dataSecondGroup;
    dataSecondGroup.data   = const_cast<char*>("test");
    dataSecondGroup.next   = &dataThirdGroup;
    dataThirdGroup.data    = const_cast<char*>("Arch");
    dataThirdGroup.next    = &dataFourthGroup;
    dataFourthGroup.data   = const_cast<char*>("lorem");
    dataFourthGroup.next   = nullptr;

    data.isize             = 0;
    data.installdate       = 0;
    data.name              = nullptr;
    data.version           = nullptr;
    data.arch              = nullptr;
    data.desc              = nullptr;
    data.handle            = &dataHandle;
    data.groups            = &dataFirstGroup;
    mock.data              = &data;
    data.ops               = &default_pkg_ops;

    const auto& jsPackageInfo { PackageLinuxHelper::parsePacman(&mock) };
    EXPECT_FALSE(jsPackageInfo.empty());
    EXPECT_EQ("Wazuh-test-Arch-lorem", jsPackageInfo["category"]);
}

TEST_F(SysInfoPackagesLinuxHelperTest, parsePacmanInformationNull)
{
    __alpm_list_t   mock        {};
    __alpm_pkg_t    data        {};
    __alpm_handle_t dataHandle  {};
    __alpm_list_t   dataGroups  {};

    data.handle        = &dataHandle;
    data.groups        = &dataGroups;
    data.isize         = 0;
    data.installdate   = 0;
    data.groups->next  = nullptr;
    data.name          = nullptr;
    data.groups->data  = nullptr;
    data.version       = nullptr;
    data.arch          = nullptr;
    data.desc          = nullptr;
    mock.data          = &data;
    data.ops           = &default_pkg_ops;

    const auto& jsPackageInfo { PackageLinuxHelper::parsePacman(&mock) };
    EXPECT_FALSE(jsPackageInfo.empty());
    EXPECT_EQ("", jsPackageInfo["name"]);
    EXPECT_EQ(0, jsPackageInfo["size"]);
    EXPECT_EQ("1970-01-01T00:00:00.000Z", jsPackageInfo["installed"]);
    EXPECT_EQ(UNKNOWN_VALUE, jsPackageInfo["category"]);
    EXPECT_EQ(UNKNOWN_VALUE, jsPackageInfo["version"]);
    EXPECT_EQ(UNKNOWN_VALUE, jsPackageInfo["architecture"]);
    EXPECT_EQ("pacman", jsPackageInfo["type"]);
    EXPECT_EQ("Arch Linux", jsPackageInfo["vendor"]);
    EXPECT_EQ(UNKNOWN_VALUE, jsPackageInfo["description"]);
}

TEST_F(SysInfoPackagesLinuxHelperTest, parseApkNameKeyNotFound)
{
    std::vector<std::pair<char, std::string>> input;
    input.push_back(std::pair<char, std::string>('V', "1.2.3-r4"));
    input.push_back(std::pair<char, std::string>('A', "x86_64"));
    input.push_back(std::pair<char, std::string>('I', "634880"));
    input.push_back(std::pair<char, std::string>('T', "the musl c library (libc) implementation"));

    const auto& jsPackageInfo { PackageLinuxHelper::parseApk(input) };
    EXPECT_EQ(true, jsPackageInfo.empty());
}

TEST_F(SysInfoPackagesLinuxHelperTest, parseApkVersionKeyNotFound)
{
    std::vector<std::pair<char, std::string>> input;
    input.push_back(std::pair<char, std::string>('P', "musl"));
    input.push_back(std::pair<char, std::string>('A', "x86_64"));
    input.push_back(std::pair<char, std::string>('I', "634880"));
    input.push_back(std::pair<char, std::string>('T', "the musl c library (libc) implementation"));

    const auto& jsPackageInfo { PackageLinuxHelper::parseApk(input) };
    EXPECT_EQ(true, jsPackageInfo.empty());
}

TEST_F(SysInfoPackagesLinuxHelperTest, parseApkArchitectureKeyNotFound)
{
    std::vector<std::pair<char, std::string>> input;
    input.push_back(std::pair<char, std::string>('P', "musl"));
    input.push_back(std::pair<char, std::string>('V', "1.2.3-r4"));
    input.push_back(std::pair<char, std::string>('I', "4111222333"));
    input.push_back(std::pair<char, std::string>('T', "the musl c library (libc) implementation"));

    const auto& jsPackageInfo { PackageLinuxHelper::parseApk(input) };
    EXPECT_EQ("musl", jsPackageInfo.at("name"));
    EXPECT_EQ("1.2.3-r4", jsPackageInfo.at("version"));
    EXPECT_EQ(UNKNOWN_VALUE, jsPackageInfo.at("architecture"));
    EXPECT_EQ(4111222333, jsPackageInfo.at("size"));
    EXPECT_EQ("the musl c library (libc) implementation", jsPackageInfo.at("description"));
    EXPECT_EQ("apk", jsPackageInfo.at("type"));
    EXPECT_EQ("Alpine Linux", jsPackageInfo.at("vendor"));
}

TEST_F(SysInfoPackagesLinuxHelperTest, parseApkNameValueEmpty)
{
    std::vector<std::pair<char, std::string>> input;
    input.push_back(std::pair<char, std::string>('P', ""));
    input.push_back(std::pair<char, std::string>('V', "1.2.3-r4"));
    input.push_back(std::pair<char, std::string>('A', "x86_64"));
    input.push_back(std::pair<char, std::string>('I', "634880"));
    input.push_back(std::pair<char, std::string>('T', "the musl c library (libc) implementation"));

    const auto& jsPackageInfo { PackageLinuxHelper::parseApk(input) };
    EXPECT_EQ(true, jsPackageInfo.empty());
}

TEST_F(SysInfoPackagesLinuxHelperTest, parseApkVersionValueEmpty)
{
    std::vector<std::pair<char, std::string>> input;
    input.push_back(std::pair<char, std::string>('P', "musl"));
    input.push_back(std::pair<char, std::string>('V', ""));
    input.push_back(std::pair<char, std::string>('A', "x86_64"));
    input.push_back(std::pair<char, std::string>('I', "634880"));
    input.push_back(std::pair<char, std::string>('T', "the musl c library (libc) implementation"));

    const auto& jsPackageInfo { PackageLinuxHelper::parseApk(input) };
    EXPECT_EQ(true, jsPackageInfo.empty());
}

TEST_F(SysInfoPackagesLinuxHelperTest, parseApkSizeValueEmpty)
{
    std::vector<std::pair<char, std::string>> input;
    input.push_back(std::pair<char, std::string>('P', "musl"));
    input.push_back(std::pair<char, std::string>('V', "1.2.3-r4"));
    input.push_back(std::pair<char, std::string>('A', "x86_64"));
    input.push_back(std::pair<char, std::string>('I', ""));
    input.push_back(std::pair<char, std::string>('T', "the musl c library (libc) implementation"));

    const auto& jsPackageInfo { PackageLinuxHelper::parseApk(input) };
    EXPECT_EQ("musl", jsPackageInfo.at("name"));
    EXPECT_EQ("1.2.3-r4", jsPackageInfo.at("version"));
    EXPECT_EQ("x86_64", jsPackageInfo.at("architecture"));
    EXPECT_EQ(0, jsPackageInfo.at("size"));
    EXPECT_EQ("the musl c library (libc) implementation", jsPackageInfo.at("description"));
    EXPECT_EQ("apk", jsPackageInfo.at("type"));
    EXPECT_EQ("Alpine Linux", jsPackageInfo.at("vendor"));
}

TEST_F(SysInfoPackagesLinuxHelperTest, parseApkSuccess)
{
    std::vector<std::pair<char, std::string>> input;
    input.push_back(std::pair<char, std::string>('P', "musl"));
    input.push_back(std::pair<char, std::string>('V', "1.2.3-r4"));
    input.push_back(std::pair<char, std::string>('A', "x86_64"));
    input.push_back(std::pair<char, std::string>('I', "4111222333"));
    input.push_back(std::pair<char, std::string>('T', "the musl c library (libc) implementation"));

    const auto& jsPackageInfo { PackageLinuxHelper::parseApk(input) };
    EXPECT_EQ("musl", jsPackageInfo.at("name"));
    EXPECT_EQ("1.2.3-r4", jsPackageInfo.at("version"));
    EXPECT_EQ(4111222333, jsPackageInfo.at("size"));
    EXPECT_EQ("the musl c library (libc) implementation", jsPackageInfo.at("description"));
    EXPECT_EQ("apk", jsPackageInfo.at("type"));
    EXPECT_EQ("Alpine Linux", jsPackageInfo.at("vendor"));
}

TEST_F(SysInfoPackagesLinuxHelperTest, parseSnapCorrectMapping)
{
    const auto& jsPackageInfo { PackageLinuxHelper::parseSnap( R"(
            {
            "id": "rw36mkAjdIKl13dzfwyxP87cejpyIcct",
            "title": "gnome-3-38-2004",
            "summary": "Shared GNOME 3.38 Ubuntu stack",
            "description": "This snap includes a GNOME 3.38 stack (the base libraries and desktop \nintegration components) and shares it through the content interface. \n",
            "icon": "/v2/icons/gnome-3-38-2004/icon",
            "installed-size": 4111222333,
            "name": "gnome-3-38-2004",
            "publisher": {
                "id": "canonical",
                "username": "canonical",
                "display-name": "Canonical",
                "validation": "verified"
            },
            "developer": "canonical",
            "status": "active",
            "type": "app",
            "base": "core20",
            "version": "0+git.6f39565",
            "channel": "latest/stable",
            "tracking-channel": "latest/stable/ubuntu-22.04",
            "ignore-validation": false,
            "revision": "119",
            "confinement": "strict",
            "private": false,
            "devmode": false,
            "jailmode": false,
            "contact": "",
            "mounted-from": "/var/lib/snapd/snaps/gnome-3-38-2004_119.snap",
            "media": [
                {
                "type": "icon",
                "url": "https://dashboard.snapcraft.io/site_media/appmedia/2021/01/icon_FvbmexL.png"
                }
            ],
            "install-date": "2022-11-23T20:33:59.025662696-03:00"
            }
        )"_json) };

    EXPECT_FALSE(jsPackageInfo.empty());
    EXPECT_EQ("gnome-3-38-2004", jsPackageInfo["name"]);
    EXPECT_EQ(4111222333, jsPackageInfo["size"]);
    EXPECT_EQ("2022-11-23T20:33:59.000Z", jsPackageInfo["installed"]);
    EXPECT_EQ(" ", jsPackageInfo["category"]);
    EXPECT_EQ("0+git.6f39565", jsPackageInfo["version"]);
    EXPECT_EQ(" ", jsPackageInfo["architecture"]);
    EXPECT_EQ("snap", jsPackageInfo["type"]);
    EXPECT_EQ("Canonical", jsPackageInfo["vendor"]);
    EXPECT_EQ("Shared GNOME 3.38 Ubuntu stack", jsPackageInfo["description"]);
}

TEST_F(SysInfoPackagesLinuxHelperTest, parseSnapInvalidInputName)
{
    const auto& jsPackageInfo { PackageLinuxHelper::parseSnap( R"(
            {
            "id": "rw36mkAjdIKl13dzfwyxP87cejpyIcct",
            "title": "gnome-3-38-2004",
            "summary": "Shared GNOME 3.38 Ubuntu stack",
            "description": "This snap includes a GNOME 3.38 stack (the base libraries and desktop \nintegration components) and shares it through the content interface. \n",
            "icon": "/v2/icons/gnome-3-38-2004/icon",
            "installed-size": 363151360,
            "publisher": {
                "id": "canonical",
                "username": "canonical",
                "display-name": "Canonical",
                "validation": "verified"
            },
            "developer": "canonical",
            "status": "active",
            "type": "app",
            "base": "core20",
            "version": "0+git.6f39565",
            "channel": "latest/stable",
            "tracking-channel": "latest/stable/ubuntu-22.04",
            "ignore-validation": false,
            "revision": "119",
            "confinement": "strict",
            "private": false,
            "devmode": false,
            "jailmode": false,
            "contact": "",
            "mounted-from": "/var/lib/snapd/snaps/gnome-3-38-2004_119.snap",
            "media": [
                {
                "type": "icon",
                "url": "https://dashboard.snapcraft.io/site_media/appmedia/2021/01/icon_FvbmexL.png"
                }
            ],
            "install-date": "2022-11-23T20:33:59.025662696-03:00"
            }
        )"_json) };

    EXPECT_TRUE(jsPackageInfo.empty());
}

TEST_F(SysInfoPackagesLinuxHelperTest, parseSnapInvalidInputVersion)
{
    const auto& jsPackageInfo { PackageLinuxHelper::parseSnap( R"(
            {
            "id": "rw36mkAjdIKl13dzfwyxP87cejpyIcct",
            "title": "gnome-3-38-2004",
            "summary": "Shared GNOME 3.38 Ubuntu stack",
            "description": "This snap includes a GNOME 3.38 stack (the base libraries and desktop \nintegration components) and shares it through the content interface. \n",
            "icon": "/v2/icons/gnome-3-38-2004/icon",
            "installed-size": 363151360,
            "name": "gnome-3-38-2004",
            "publisher": {
                "id": "canonical",
                "username": "canonical",
                "display-name": "Canonical",
                "validation": "verified"
            },
            "developer": "canonical",
            "status": "active",
            "type": "app",
            "base": "core20",
            "channel": "latest/stable",
            "tracking-channel": "latest/stable/ubuntu-22.04",
            "ignore-validation": false,
            "revision": "119",
            "confinement": "strict",
            "private": false,
            "devmode": false,
            "jailmode": false,
            "contact": "",
            "mounted-from": "/var/lib/snapd/snaps/gnome-3-38-2004_119.snap",
            "media": [
                {
                "type": "icon",
                "url": "https://dashboard.snapcraft.io/site_media/appmedia/2021/01/icon_FvbmexL.png"
                }
            ],
            "install-date": "2022-11-23T20:33:59.025662696-03:00"
            }
        )"_json) };

    EXPECT_TRUE(jsPackageInfo.empty());
}

TEST_F(SysInfoPackagesLinuxHelperTest, parseSnapValidSizeAsString)
{
    const auto& jsPackageInfo { PackageLinuxHelper::parseSnap( R"(
            {
            "id": "rw36mkAjdIKl13dzfwyxP87cejpyIcct",
            "title": "gnome-3-38-2004",
            "summary": "Shared GNOME 3.38 Ubuntu stack",
            "description": "This snap includes a GNOME 3.38 stack (the base libraries and desktop \nintegration components) and shares it through the content interface. \n",
            "icon": "/v2/icons/gnome-3-38-2004/icon",
            "installed-size": "4111222333",
            "name": "gnome-3-38-2004",
            "publisher": {
                "id": "canonical",
                "username": "canonical",
                "display-name": "Canonical",
                "validation": "verified"
            },
            "developer": "canonical",
            "status": "active",
            "type": "app",
            "base": "core20",
            "version": "0+git.6f39565",
            "channel": "latest/stable",
            "tracking-channel": "latest/stable/ubuntu-22.04",
            "ignore-validation": false,
            "revision": "119",
            "confinement": "strict",
            "private": false,
            "devmode": false,
            "jailmode": false,
            "contact": "",
            "mounted-from": "/var/lib/snapd/snaps/gnome-3-38-2004_119.snap",
            "media": [
                {
                "type": "icon",
                "url": "https://dashboard.snapcraft.io/site_media/appmedia/2021/01/icon_FvbmexL.png"
                }
            ],
            "install-date": "2022-11-23T20:33:59.025662696-03:00"
            }
        )"_json) };

    EXPECT_FALSE(jsPackageInfo.empty());
    EXPECT_EQ(4111222333, jsPackageInfo["size"]);
}

TEST_F(SysInfoPackagesLinuxHelperTest, parseSnapEmptyJSON)
{
    const auto& jsPackageInfo { PackageLinuxHelper::parseSnap( R"({})"_json) };

    EXPECT_TRUE(jsPackageInfo.empty());
}

TEST_F(SysInfoPackagesLinuxHelperTest, parseSnapWrongJSON)
{
    EXPECT_NO_THROW(
    {
        const auto& jsPackageInfo { PackageLinuxHelper::parseSnap( R"(curl: (7) Couldn't connect to server)") };
        EXPECT_TRUE(jsPackageInfo.empty());
    });
}

