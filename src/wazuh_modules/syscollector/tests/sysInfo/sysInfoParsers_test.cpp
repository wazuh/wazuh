/*
 * Wazuh SysInfoParsers
 * Copyright (C) 2015-2020, Wazuh Inc.
 * October 19, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "sysInfoParsers_test.h"
#include "sysOsParsers.h"

void SysInfoParsersTest::SetUp() {};

void SysInfoParsersTest::TearDown()
{
};

TEST_F(SysInfoParsersTest, UnixLinux)
{
    constexpr auto UNIX_RELEASE_FILE
    {
        R"(
        NAME="Ubuntu"
        VERSION="20.04.1 LTS (Focal Fossa) "
        ID=ubuntu
        ID_LIKE=debian
        PRETTY_NAME="Ubuntu 20.04.1 LTS"
        VERSION_ID="20.04"
        HOME_URL="https://www.ubuntu.com/"
        SUPPORT_URL="https://help.ubuntu.com/"
        BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
        PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
        VERSION_CODENAME=focal
        UBUNTU_CODENAME=focal
        )"
    };
    nlohmann::json output;
    std::stringstream info{UNIX_RELEASE_FILE};
    const auto spParser{FactorySysOsParser::create("unix")};
    EXPECT_TRUE(spParser->parseFile(info, output));
    EXPECT_EQ("20.04.1 LTS (Focal Fossa)", output["os_version"]);
    EXPECT_EQ("Ubuntu", output["os_name"]);
    EXPECT_EQ("ubuntu", output["os_platform"]);
    EXPECT_EQ("focal", output["os_codename"]);
    EXPECT_EQ("20", output["os_major"]);
    EXPECT_EQ("04", output["os_minor"]);
}

TEST_F(SysInfoParsersTest, UnixCentos)
{
    constexpr auto UNIX_RELEASE_FILE
    {
        R"(
        NAME="CentOS Linux"
        VERSION="8 (Core) "
        ID="centos"
        ID_LIKE="rhel fedora"
        VERSION_ID="8"
        PLATFORM_ID="platform:el8"
        PRETTY_NAME="CentOS Linux 8 (Core) "
        ANSI_COLOR="0;31"
        CPE_NAME="cpe:/o:centos:centos:8"
        HOME_URL="https://www.centos.org/"
        BUG_REPORT_URL="https://bugs.centos.org/"

        CENTOS_MANTISBT_PROJECT="CentOS-8"
        CENTOS_MANTISBT_PROJECT_VERSION="8"
        REDHAT_SUPPORT_PRODUCT="centos"
        REDHAT_SUPPORT_PRODUCT_VERSION="8"
        )"
    };
    nlohmann::json output;
    std::stringstream info{UNIX_RELEASE_FILE};
    const auto spParser{FactorySysOsParser::create("unix")};
    EXPECT_TRUE(spParser->parseFile(info, output));
    EXPECT_EQ("8 (Core)", output["os_version"]);
    EXPECT_EQ("CentOS Linux", output["os_name"]);
    EXPECT_EQ("centos", output["os_platform"]);
    EXPECT_EQ("8", output["os_major"]);
}

TEST_F(SysInfoParsersTest, Ubuntu)
{
    constexpr auto UBUNTU_RELEASE_FILE
    {
        R"(DISTRIB_ID=Ubuntu
          DISTRIB_RELEASE=20.04
          DISTRIB_CODENAME=focal
          DISTRIB_DESCRIPTION='Ubuntu 20.04.1 LTS')"
    };
    nlohmann::json output;
    std::stringstream info{UBUNTU_RELEASE_FILE};
    const auto spParser{FactorySysOsParser::create("ubuntu")};
    EXPECT_TRUE(spParser->parseFile(info, output));
    EXPECT_EQ("20.04.1", output["os_version"]);
    EXPECT_EQ("Ubuntu", output["os_name"]);
    EXPECT_EQ("ubuntu", output["os_platform"]);
    EXPECT_EQ("focal", output["os_codename"]);
    EXPECT_EQ("20", output["os_major"]);
    EXPECT_EQ("04", output["os_minor"]);
}

TEST_F(SysInfoParsersTest, Centos)
{
    constexpr auto CENTOS_RELEASE_FILE
    {
        "CentOS Linux release 8.2.2004 (Core)"
    };
    nlohmann::json output;
    std::stringstream info{CENTOS_RELEASE_FILE};
    const auto spParser{FactorySysOsParser::create("centos")};
    EXPECT_TRUE(spParser->parseFile(info, output));
    EXPECT_EQ("8.2.2004", output["os_version"]);
    EXPECT_EQ("Centos Linux", output["os_name"]);
    EXPECT_EQ("centos", output["os_platform"]);
    EXPECT_EQ("Core", output["os_codename"]);
    EXPECT_EQ("8", output["os_major"]);
    EXPECT_EQ("2", output["os_minor"]);
}

TEST_F(SysInfoParsersTest, BSDFreeBSD)
{
    constexpr auto FREE_BSD_UNAME
    {
        "12.1-STABLE"
    };
    nlohmann::json output;
    const auto spParser{FactorySysOsParser::create("bsd")};
    EXPECT_TRUE(spParser->parseUname(FREE_BSD_UNAME, output));
    EXPECT_EQ("12.1", output["os_version"]);
    EXPECT_EQ("BSD", output["os_name"]);
    EXPECT_EQ("bsd", output["os_platform"]);
    EXPECT_EQ("12", output["os_major"]);
    EXPECT_EQ("1", output["os_minor"]);
}

TEST_F(SysInfoParsersTest, BSDOpenBSD)
{
    constexpr auto FREE_BSD_UNAME
    {
        "6.6"
    };
    nlohmann::json output;
    const auto spParser{FactorySysOsParser::create("bsd")};
    EXPECT_TRUE(spParser->parseUname(FREE_BSD_UNAME, output));
    EXPECT_EQ("6.6", output["os_version"]);
    EXPECT_EQ("BSD", output["os_name"]);
    EXPECT_EQ("bsd", output["os_platform"]);
    EXPECT_EQ("6", output["os_major"]);
    EXPECT_EQ("6", output["os_minor"]);
}

TEST_F(SysInfoParsersTest, RedHatCentos)
{
    constexpr auto REDHAT_RELEASE_FILE
    {
        "CentOS release 5.11 (Final)"
    };
    nlohmann::json output;
    std::stringstream info{REDHAT_RELEASE_FILE};
    const auto spParser{FactorySysOsParser::create("rhel")};
    EXPECT_TRUE(spParser->parseFile(info, output));
    EXPECT_EQ("5.11", output["os_version"]);
    EXPECT_EQ("Centos Linux", output["os_name"]);
    EXPECT_EQ("centos", output["os_platform"]);
    EXPECT_EQ("Final", output["os_codename"]);
    EXPECT_EQ("5", output["os_major"]);
    EXPECT_EQ("11", output["os_minor"]);
}

TEST_F(SysInfoParsersTest, Debian)
{
    constexpr auto DEBIAN_VERSION_FILE
    {
        "10.6"
    };
    nlohmann::json output;
    std::stringstream info{DEBIAN_VERSION_FILE};
    const auto spParser{FactorySysOsParser::create("debian")};
    EXPECT_TRUE(spParser->parseFile(info, output));
    EXPECT_EQ("10.6", output["os_version"]);
    EXPECT_EQ("Debian GNU/Linux", output["os_name"]);
    EXPECT_EQ("debian", output["os_platform"]);
    EXPECT_EQ("10", output["os_major"]);
    EXPECT_EQ("6", output["os_minor"]);
}

TEST_F(SysInfoParsersTest, Arch)
{
    constexpr auto ARCH_VERSION_FILE
    {
        "10.6"
    };
    nlohmann::json output;
    std::stringstream info{ARCH_VERSION_FILE};
    const auto spParser{FactorySysOsParser::create("arch")};
    EXPECT_TRUE(spParser->parseFile(info, output));
    EXPECT_EQ("10.6", output["os_version"]);
    EXPECT_EQ("Arch Linux", output["os_name"]);
    EXPECT_EQ("arch", output["os_platform"]);
    EXPECT_EQ("10", output["os_major"]);
    EXPECT_EQ("6", output["os_minor"]);
}

TEST_F(SysInfoParsersTest, Slackware)
{
    constexpr auto SLACKWARE_VERSION_FILE
    {
        "Slackware 14.1"
    };
    nlohmann::json output;
    std::stringstream info{SLACKWARE_VERSION_FILE};
    const auto spParser{FactorySysOsParser::create("slackware")};
    EXPECT_TRUE(spParser->parseFile(info, output));
    EXPECT_EQ("14.1", output["os_version"]);
    EXPECT_EQ("Slackware", output["os_name"]);
    EXPECT_EQ("slackware", output["os_platform"]);
    EXPECT_EQ("14", output["os_major"]);
    EXPECT_EQ("1", output["os_minor"]);
}

TEST_F(SysInfoParsersTest, Gentoo)
{
    constexpr auto GENTOO_VERSION_FILE
    {
        "Gentoo Base System release 2.6"
    };
    nlohmann::json output;
    std::stringstream info{GENTOO_VERSION_FILE};
    const auto spParser{FactorySysOsParser::create("gentoo")};
    EXPECT_TRUE(spParser->parseFile(info, output));
    EXPECT_EQ("2.6", output["os_version"]);
    EXPECT_EQ("Gentoo", output["os_name"]);
    EXPECT_EQ("gentoo", output["os_platform"]);
    EXPECT_EQ("2", output["os_major"]);
    EXPECT_EQ("6", output["os_minor"]);
}

TEST_F(SysInfoParsersTest, SuSE)
{
    constexpr auto OPENSUSE_VERSION_FILE
    {
        R"(
        openSUSE 13.1 (x86_64)
        VERSION = 13.1
        CODENAME = Bottle
        )"
    };
    nlohmann::json output;
    std::stringstream info{OPENSUSE_VERSION_FILE};
    const auto spParser{FactorySysOsParser::create("suse")};
    EXPECT_TRUE(spParser->parseFile(info, output));
    EXPECT_EQ("13.1", output["os_version"]);
    EXPECT_EQ("SuSE Linux", output["os_name"]);
    EXPECT_EQ("suse", output["os_platform"]);
    EXPECT_EQ("Bottle", output["os_codename"]);
    EXPECT_EQ("13", output["os_major"]);
    EXPECT_EQ("1", output["os_minor"]);
}

TEST_F(SysInfoParsersTest, Fedora)
{
    constexpr auto FEDORA_VERSION_FILE
    {
        "Fedora release 22 (Twenty Two)"
    };
    nlohmann::json output;
    std::stringstream info{FEDORA_VERSION_FILE};
    const auto spParser{FactorySysOsParser::create("fedora")};
    EXPECT_TRUE(spParser->parseFile(info, output));
    EXPECT_EQ("22", output["os_version"]);
    EXPECT_EQ("Fedora", output["os_name"]);
    EXPECT_EQ("fedora", output["os_platform"]);
    EXPECT_EQ("Twenty Two", output["os_codename"]);
    EXPECT_EQ("22", output["os_major"]);
}

TEST_F(SysInfoParsersTest, Solaris)
{
    constexpr auto SOLARIS_VERSION_FILE
    {
        R"(
                                     Oracle Solaris 11.3 X86
          Copyright (c) 1983, 2015, Oracle and/or its affiliates.  All rights reserved.
                                    Assembled 06 October 2015
        )"
    };
    nlohmann::json output;
    std::stringstream info{SOLARIS_VERSION_FILE};
    const auto spParser{FactorySysOsParser::create("solaris")};
    EXPECT_TRUE(spParser->parseFile(info, output));
    EXPECT_EQ("11.3", output["os_version"]);
    EXPECT_EQ("SunOS", output["os_name"]);
    EXPECT_EQ("sunos", output["os_platform"]);
    EXPECT_EQ("11", output["os_major"]);
    EXPECT_EQ("3", output["os_minor"]);
}

TEST_F(SysInfoParsersTest, Solaris1)
{
    constexpr auto SOLARIS_VERSION_FILE
    {
        R"(
                            Oracle Solaris 10 1/13 s10x_u11wos_24a X86
           Copyright (c) 1983, 2013, Oracle and/or its affiliates. All rights reserved.
                            Assembled 17 January 2013
        )"
    };
    nlohmann::json output;
    std::stringstream info{SOLARIS_VERSION_FILE};
    const auto spParser{FactorySysOsParser::create("solaris")};
    EXPECT_TRUE(spParser->parseFile(info, output));
    EXPECT_EQ("10", output["os_version"]);
    EXPECT_EQ("SunOS", output["os_name"]);
    EXPECT_EQ("sunos", output["os_platform"]);
    EXPECT_EQ("10", output["os_major"]);
}

TEST_F(SysInfoParsersTest, HPUX)
{
    // https://docstore.mik.ua/manuals/hp-ux/en/5992-4826/pr01s02.html
    constexpr auto HPUX_UNAME
    {
        "B.11.23"
    };
    nlohmann::json output;
    const auto spParser{FactorySysOsParser::create("hp-ux")};
    EXPECT_TRUE(spParser->parseUname(HPUX_UNAME, output));
    EXPECT_EQ("11.23", output["os_version"]);
    EXPECT_EQ("HP-UX", output["os_name"]);
    EXPECT_EQ("hp-ux", output["os_platform"]);
    EXPECT_EQ("11", output["os_major"]);
    EXPECT_EQ("23", output["os_minor"]);

}

TEST_F(SysInfoParsersTest, UknownPlatform)
{
    EXPECT_THROW(FactorySysOsParser::create("some unknown platform"), std::runtime_error);
}

TEST_F(SysInfoParsersTest, MacOS)
{
    constexpr auto MACOS_SW_VERSION
    {
        R"(
        ProductName:    Mac OS X
        ProductVersion: 10.12.6
        BuildVersion:   16G29
        )"
    };
    constexpr auto MACOS_UNAME
    {
        "16.7.0"
    };
    nlohmann::json output;
    MacOsParser parser;
    EXPECT_TRUE(parser.parseSwVersion(MACOS_SW_VERSION, output));
    EXPECT_TRUE(parser.parseUname(MACOS_UNAME, output));
    EXPECT_EQ("10.12.6", output["os_version"]);
    EXPECT_EQ("Mac OS X", output["os_name"]);
    EXPECT_EQ("darwin", output["os_platform"]);
    EXPECT_EQ("16G29", output["os_build"]);
    EXPECT_EQ("Sierra", output["os_codename"]);
    EXPECT_EQ("10", output["os_major"]);
    EXPECT_EQ("12", output["os_minor"]);
}
