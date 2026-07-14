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
#include "packages/packageLinuxRpmParserHelper.h"
#include "packages/packageLinuxRpmParserHelperLegacy.h"
#include "packages/rpmPackageManager.h"
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
    EXPECT_EQ("2015-03-04T12:38:58.000Z", jsPackageInfo["installed"]);
    EXPECT_EQ("System Environment/Base", jsPackageInfo["category"]);
    EXPECT_EQ("3:1.5-24.el5", jsPackageInfo["version_"]);
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
    EXPECT_EQ("2015-03-04T12:38:58.000Z", jsPackageInfo["installed"]);
    EXPECT_EQ("System Environment/Base", jsPackageInfo["category"]);
    EXPECT_EQ("3:1.5-24.el5", jsPackageInfo["version_"]);
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
    EXPECT_EQ(UNKNOWN_VALUE, jsPackageInfo["version_"]);
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
    EXPECT_EQ("2015-03-04T12:38:58.000Z", jsPackageInfo["installed"]);
    EXPECT_EQ("System Environment/Base", jsPackageInfo["category"]);
    EXPECT_EQ("1.5-24.el5", jsPackageInfo["version_"]);
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
    EXPECT_EQ("2015-03-04T12:38:58.000Z", jsPackageInfo["installed"]);
    EXPECT_EQ("System Environment/Base", jsPackageInfo["category"]);
    EXPECT_EQ("4.16", jsPackageInfo["version_"]);
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
    EXPECT_EQ("2015-03-04T12:38:58.000Z", jsPackageInfo["installed"]);
    EXPECT_EQ("System Environment/Base", jsPackageInfo["category"]);
    EXPECT_EQ("1:4.16", jsPackageInfo["version_"]);
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
    EXPECT_EQ("2015-03-04T12:38:58.000Z", jsPackageInfo["installed"]);
    EXPECT_EQ("System Environment/Base", jsPackageInfo["category"]);
    EXPECT_EQ("1.5", jsPackageInfo["version_"]);
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
    EXPECT_EQ("2015-03-04T12:38:58.000Z", jsPackageInfo["installed"]);
    EXPECT_EQ("System Environment/Base", jsPackageInfo["category"]);
    EXPECT_EQ("3:1.5", jsPackageInfo["version_"]);
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
    EXPECT_EQ("2015-03-04T12:38:58.000Z", jsPackageInfo["installed"]);
    EXPECT_EQ("System Environment/Base", jsPackageInfo["category"]);
    EXPECT_EQ("1.5-24.el5", jsPackageInfo["version_"]);
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
    EXPECT_EQ("2015-03-04T12:38:58.000Z", jsPackageInfo["installed"]);
    EXPECT_EQ("System Environment/Base", jsPackageInfo["category"]);
    EXPECT_EQ("3:1.5", jsPackageInfo["version_"]);
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
    EXPECT_EQ("2015-03-04T12:38:58.000Z", jsPackageInfo["installed"]);
    EXPECT_EQ("System Environment/Base", jsPackageInfo["category"]);
    EXPECT_EQ("1.5", jsPackageInfo["version_"]);
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
    EXPECT_EQ("1:1.2.11.dfsg-2ubuntu1.2", jsPackageInfo["version_"]);
    EXPECT_EQ("amd64", jsPackageInfo["architecture"]);
    EXPECT_EQ("deb", jsPackageInfo["type"]);
    EXPECT_EQ("Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>", jsPackageInfo["vendor"]);
    EXPECT_EQ("compression library - development", jsPackageInfo["description"]);
    EXPECT_EQ("zlib", jsPackageInfo["source"]);
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
    EXPECT_EQ("0+git.6f39565", jsPackageInfo["version_"]);
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
