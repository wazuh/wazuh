/*
 * Wazuh SysInfo
 * Copyright (C) 2015-2021, Wazuh Inc.
 * January 28, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "sysInfoPackagesLinuxHelper_test.h"
#include "packages/packagesLinuxParserHelper.h"

using ::testing::_;
using ::testing::Return;

void SysInfoPackagesLinuxHelperTest::SetUp() {};
void SysInfoPackagesLinuxHelperTest::TearDown() {};

TEST_F(SysInfoPackagesLinuxHelperTest, parseRpmInformationCentosGreaterThan5)
{
    constexpr auto RPM_PACKAGE_GREATER_THAN_CENTOS_5_INFORMATION
    {
        R"(
            Name        : libglvnd-glx
            Epoch       : 1
            Version     : 1.0.1
            Release     : 0.9.git5baa1e5.el8
            Architecture: x86_64
            Install Date: Wed 27 Jan 2021 01:37:42 PM PST
            Group       : Unspecified
            Size        : 665208
            License     : MIT
            Signature   : RSA/SHA256, Mon 01 Jul 2019 04:20:34 PM PDT, Key ID 05b555b38483c65d
            Source RPM  : libglvnd-1.0.1-0.9.git5baa1e5.el8.src.rpm
            Build Date  : Mon 13 May 2019 06:31:46 PM PDT
            Build Host  : x86-02.mbox.centos.org
            Relocations : (not relocatable)
            Packager    : CentOS Buildsys <bugs@centos.org>
            Vendor      : CentOS
            URL         : https://github.com/NVIDIA/libglvnd
            Summary     : GLX support for libglvnd
            Description :
            libGL and libGLX are the common dispatch interface for the GLX API.
        )"
    };
    const auto& jsPackageInfo { PackageLinuxHelper::parseRpm(RPM_PACKAGE_GREATER_THAN_CENTOS_5_INFORMATION) };
    EXPECT_FALSE(jsPackageInfo.empty());
    EXPECT_EQ("libglvnd-glx", jsPackageInfo["name"]);
    EXPECT_EQ("665208", jsPackageInfo["size"]);
    EXPECT_EQ("Wed 27 Jan 2021 01:37:42 PM PST", jsPackageInfo["install_time"]);
    EXPECT_EQ("Unspecified", jsPackageInfo["groups"]);
    EXPECT_EQ("1-0.9.git5baa1e5.el8-1.0.1", jsPackageInfo["version"]);
    EXPECT_EQ("x86_64", jsPackageInfo["architecture"]);
    EXPECT_EQ("rpm", jsPackageInfo["format"]);
    EXPECT_EQ(UNKNOWN_VALUE, jsPackageInfo["os_patch"]);
    EXPECT_EQ("CentOS", jsPackageInfo["vendor"]);
    EXPECT_EQ("GLX support for libglvnd", jsPackageInfo["description"]);
}

TEST_F(SysInfoPackagesLinuxHelperTest, parseRpmInformationCentos5)
{
    constexpr auto RPM_PACKAGE_CENTOS_5_INFORMATION
    {
        R"(
            Name        : bzip2-devel                  Relocations: (not relocatable)
            Version     : 1.0.3                             Vendor: CentOS
            Release     : 6.el5_5                       Build Date: Tue 21 Sep 2010 07:38:01 AM UTC
            Install Date: Fri 29 Jan 2021 07:57:22 PM UTC      Build Host: builder17.centos.org
            Group       : Development/Libraries         Source RPM: bzip2-1.0.3-6.el5_5.src.rpm
            Size        : 78835                            License: BSD
            Signature   : DSA/SHA1, Tue 21 Sep 2010 09:44:01 AM UTC, Key ID a8a447dce8562897
            URL         : http://sources.redhat.com/bzip2/
            Summary     : Header files and libraries for developing apps which will use bzip2.
            Description :

            Header files and a static library of bzip2 functions, for developing apps
            which will use the library.
        )"
    };
    const auto& jsPackageInfo { PackageLinuxHelper::parseRpm(RPM_PACKAGE_CENTOS_5_INFORMATION) };
    EXPECT_FALSE(jsPackageInfo.empty());
    EXPECT_EQ("bzip2-devel", jsPackageInfo["name"]);
    EXPECT_EQ("78835", jsPackageInfo["size"]);
    EXPECT_EQ("Fri 29 Jan 2021 07:57:22 PM UTC", jsPackageInfo["install_time"]);
    EXPECT_EQ("Development/Libraries", jsPackageInfo["groups"]);
    EXPECT_EQ("6.el5_5-1.0.3", jsPackageInfo["version"]);
    EXPECT_EQ(UNKNOWN_VALUE, jsPackageInfo["architecture"]);
    EXPECT_EQ("rpm", jsPackageInfo["format"]);
    EXPECT_EQ(UNKNOWN_VALUE, jsPackageInfo["os_patch"]);
    EXPECT_EQ("CentOS", jsPackageInfo["vendor"]);
    EXPECT_EQ("Header files and libraries for developing apps which will use bzip2.", jsPackageInfo["description"]);
}
