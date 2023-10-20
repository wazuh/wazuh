/*
 * Wazuh SysInfoParsers
 * Copyright (C) 2015, Wazuh Inc.
 * October 19, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "sysInfoParsers_test.h"
#include "osinfo/sysOsParsers.h"

void SysInfoParsersTest::SetUp() {};

void SysInfoParsersTest::TearDown()
{
};

TEST_F(SysInfoParsersTest, BaseClass)
{
    ISysOsParser parser;
    nlohmann::json output;
    std::stringstream info;
    EXPECT_FALSE(parser.parseFile(info, output));
    EXPECT_FALSE(parser.parseUname("", output));
}

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

TEST_F(SysInfoParsersTest, UnixArch)
{
    constexpr auto UNIX_RELEASE_FILE
    {
        R"(
        NAME="Arch Linux"
        PRETTY_NAME="Arch Linux"
        ID=arch
        BUILD_ID=rolling
        ANSI_COLOR="38;2;23;147;209"
        HOME_URL="https://www.archlinux.org/"
        DOCUMENTATION_URL="https://wiki.archlinux.org/"
        SUPPORT_URL="https://bbs.archlinux.org/"
        BUG_REPORT_URL="https://bugs.archlinux.org/"
        LOGO=archlinux
        )"
    };
    nlohmann::json output;
    std::stringstream info{UNIX_RELEASE_FILE};
    const auto spParser{FactorySysOsParser::create("unix")};
    EXPECT_TRUE(spParser->parseFile(info, output));
    EXPECT_EQ("Arch Linux", output["os_name"]);
    EXPECT_EQ("arch", output["os_platform"]);
}

TEST_F(SysInfoParsersTest, UnixAlpine)
{
    constexpr auto UNIX_RELEASE_FILE
    {
        R"(
        NAME="Alpine Linux"
        ID=alpine
        VERSION_ID=3.17.1
        PRETTY_NAME="Alpine Linux v3.17"
        HOME_URL="https://alpinelinux.org/"
        BUG_REPORT_URL="https://gitlab.alpinelinux.org/alpine/aports/-/issues"
        )"
    };
    nlohmann::json output;
    std::stringstream info{UNIX_RELEASE_FILE};
    const auto spParser{FactorySysOsParser::create("unix")};
    EXPECT_TRUE(spParser->parseFile(info, output));
    EXPECT_EQ("3.17.1", output["os_version"]);
    EXPECT_EQ("Alpine Linux", output["os_name"]);
    EXPECT_EQ("alpine", output["os_platform"]);
    EXPECT_EQ("3", output["os_major"]);
    EXPECT_EQ("17", output["os_minor"]);
    EXPECT_EQ("1", output["os_patch"]);
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
    EXPECT_EQ("2004", output["os_patch"]);
}

TEST_F(SysInfoParsersTest, CentosStream)
{
    constexpr auto CENTOS_STREAM_RELEASE_FILE
    {
        "NAME=\"CentOS Stream\"\n"
        "VERSION=\"9\"\n"
        "ID=\"centos\"\n"
        "ID_LIKE=\"rhel fedora\"\n"
        "VERSION_ID=\"9\"\n"
        "PLATFORM_ID=\"platform:el9\"\n"
        "PRETTY_NAME=\"CentOS Stream 9\"\n"
        "ANSI_COLOR=\"0;31\"\n"
        "LOGO=\"fedora-logo-icon\"\n"
        "CPE_NAME=\"cpe:/o:centos:centos:9\"\n"
        "HOME_URL=\"https://centos.org/\"\n"
        "BUG_REPORT_URL=\"https://bugzilla.redhat.com/\"\n"
        "REDHAT_SUPPORT_PRODUCT=\"Red Hat Enterprise Linux 9\"\n"
        "REDHAT_SUPPORT_PRODUCT_VERSION=\"CentOS Stream\"\n"
    };
    nlohmann::json output;
    std::stringstream info{CENTOS_STREAM_RELEASE_FILE};
    const auto spParser1{FactorySysOsParser::create("unix")};
    EXPECT_TRUE(spParser1->parseFile(info, output));
    info.clear();
    info.seekg(0, std::ios::beg);
    info << CENTOS_STREAM_RELEASE_FILE;
    const auto spParser2{FactorySysOsParser::create("centos")};
    EXPECT_FALSE(spParser2->parseFile(info, output));
    EXPECT_EQ("9", output["os_major"]);
    EXPECT_EQ("CentOS Stream", output["os_name"]);
    EXPECT_EQ("centos", output["os_platform"]);
    EXPECT_EQ("9", output["os_version"]);
}

TEST_F(SysInfoParsersTest, CentosBased)
{
    constexpr auto ROCKY_LINUX_RELEASE_FILE
    {
        "NAME=\"Rocky Linux\"\n"
        "VERSION=\"8.8 (Green Obsidian)\"\n"
        "ID=\"rocky\"\n"
        "ID_LIKE=\"rhel centos fedora\"\n"
        "VERSION_ID=\"8.8\"\n"
        "PLATFORM_ID=\"platform:el8\"\n"
        "PRETTY_NAME=\"Rocky Linux 8.8 (Green Obsidian)\"\n"
        "ANSI_COLOR=\"0;32\"\n"
        "LOGO=\"fedora-logo-icon\"\n"
        "CPE_NAME=\"cpe:/o:rocky:rocky:8:GA\"\n"
        "HOME_URL=\"https://rockylinux.org/\"\n"
        "BUG_REPORT_URL=\"https://bugs.rockylinux.org/\"\n"
        "SUPPORT_END=\"2029-05-31\"\n"
        "ROCKY_SUPPORT_PRODUCT=\"Rocky-Linux-8\"\n"
        "ROCKY_SUPPORT_PRODUCT_VERSION=\"8.8\"\n"
        "REDHAT_SUPPORT_PRODUCT=\"Rocky Linux\"\n"
        "REDHAT_SUPPORT_PRODUCT_VERSION=\"8.8\"\n"
    };
    nlohmann::json output;
    std::stringstream info{ROCKY_LINUX_RELEASE_FILE};
    const auto spParser1{FactorySysOsParser::create("unix")};
    EXPECT_TRUE(spParser1->parseFile(info, output));
    info.clear();
    info.seekg(0, std::ios::beg);
    info << ROCKY_LINUX_RELEASE_FILE;
    const auto spParser2{FactorySysOsParser::create("centos")};
    EXPECT_TRUE(spParser2->parseFile(info, output));
    EXPECT_EQ("Green Obsidian", output["os_codename"]);
    EXPECT_EQ("8", output["os_major"]);
    EXPECT_EQ("8", output["os_minor"]);
    EXPECT_EQ("Rocky Linux", output["os_name"]);
    EXPECT_EQ("rocky", output["os_platform"]);
    EXPECT_EQ("8.8", output["os_version"]);
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
    EXPECT_EQ("CentOS", output["os_name"]);
    EXPECT_EQ("rhel", output["os_platform"]);
    EXPECT_EQ("Final", output["os_codename"]);
    EXPECT_EQ("5", output["os_major"]);
    EXPECT_EQ("11", output["os_minor"]);
}

TEST_F(SysInfoParsersTest, RedHatFedora)
{
    constexpr auto REDHAT_RELEASE_FILE
    {
        "Fedora release 22 (Twenty Two)"
    };
    nlohmann::json output;
    std::stringstream info{REDHAT_RELEASE_FILE};
    const auto spParser{FactorySysOsParser::create("rhel")};
    EXPECT_TRUE(spParser->parseFile(info, output));
    EXPECT_EQ("22", output["os_version"]);
    EXPECT_EQ("Fedora", output["os_name"]);
    EXPECT_EQ("rhel", output["os_platform"]);
    EXPECT_EQ("Twenty Two", output["os_codename"]);
    EXPECT_EQ("22", output["os_major"]);
}

TEST_F(SysInfoParsersTest, RedHatServer)
{
    constexpr auto REDHAT_RELEASE_FILE
    {
        "Red Hat Enterprise Linux Server release 7.2 (Maipo)"
    };
    nlohmann::json output;
    std::stringstream info{REDHAT_RELEASE_FILE};
    const auto spParser{FactorySysOsParser::create("rhel")};
    EXPECT_TRUE(spParser->parseFile(info, output));
    EXPECT_EQ("7.2", output["os_version"]);
    EXPECT_EQ("Red Hat Enterprise Linux Server", output["os_name"]);
    EXPECT_EQ("rhel", output["os_platform"]);
    EXPECT_EQ("Maipo", output["os_codename"]);
    EXPECT_EQ("7", output["os_major"]);
    EXPECT_EQ("2", output["os_minor"]);
}

TEST_F(SysInfoParsersTest, RedHatLinux)
{
    constexpr auto REDHAT_RELEASE_FILE
    {
        "Red Hat Enterprise Linux ES release 3 (Taroon Update 4)"
    };
    nlohmann::json output;
    std::stringstream info{REDHAT_RELEASE_FILE};
    const auto spParser{FactorySysOsParser::create("rhel")};
    EXPECT_TRUE(spParser->parseFile(info, output));
    EXPECT_EQ("3", output["os_version"]);
    EXPECT_EQ("Red Hat Enterprise Linux ES", output["os_name"]);
    EXPECT_EQ("rhel", output["os_platform"]);
    EXPECT_EQ("Taroon Update 4", output["os_codename"]);
    EXPECT_EQ("3", output["os_major"]);
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

TEST_F(SysInfoParsersTest, Solaris2)
{
    constexpr auto SOLARIS_VERSION_FILE
    {
        R"(
                            Solaris 10 5/09 s10x_u7wos_08 X86
           Copyright 2009 Sun Microsystems, Inc. All rights reserved.
                                Use is subject to license terms.
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

TEST_F(SysInfoParsersTest, Alpine)
{
    constexpr auto ALPINE_RELEASE_FILE
    {
        R"(
        3.17.1
        )"
    };
    nlohmann::json output;
    std::stringstream info{ALPINE_RELEASE_FILE};
    const auto spParser{FactorySysOsParser::create("alpine")};
    EXPECT_TRUE(spParser->parseFile(info, output));
    EXPECT_EQ("3.17.1", output["os_version"]);
    EXPECT_EQ("Alpine Linux", output["os_name"]);
    EXPECT_EQ("alpine", output["os_platform"]);
    EXPECT_EQ("3", output["os_major"]);
    EXPECT_EQ("17", output["os_minor"]);
    EXPECT_EQ("1", output["os_patch"]);
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
        ProductName:	Mac OS X
        ProductVersion:	10.14.6
        BuildVersion:	18G103
        )"
    };
    constexpr auto MACOS_SYSTEM_PROFILER
    {
        R"(
        Software:

          System Software Overview:

            System Version: macOS 10.14.6 (18G103)
            Kernel Version: Darwin 18.7.0
            Boot Volume: mojave
            Boot Mode: Normal
            Computer Name: macos-mojave-vm
            User Name: System Administrator (root)
            Secure Virtual Memory: Enabled
            System Integrity Protection: Enabled
            Time since boot: 58 minutes
        )"
    };
    constexpr auto MACOS_UNAME
    {
        "18.7.0"
    };
    nlohmann::json output;
    MacOsParser parser;
    EXPECT_TRUE(parser.parseSwVersion(MACOS_SW_VERSION, output));
    EXPECT_TRUE(parser.parseSystemProfiler(MACOS_SYSTEM_PROFILER, output));
    EXPECT_TRUE(parser.parseUname(MACOS_UNAME, output));
    EXPECT_EQ("10.14.6", output["os_version"]);
    EXPECT_EQ("macOS", output["os_name"]);
    EXPECT_EQ("darwin", output["os_platform"]);
    EXPECT_EQ("18G103", output["os_build"]);
    EXPECT_EQ("Mojave", output["os_codename"]);
    EXPECT_EQ("10", output["os_major"]);
    EXPECT_EQ("14", output["os_minor"]);
    EXPECT_EQ("6", output["os_patch"]);
}

TEST_F(SysInfoParsersTest, MacOSOsDefaultName)
{
    constexpr auto MACOS_SW_VERSION
    {
        R"(
        ProductName:	Mac OS X
        ProductVersion:	10.14.6
        BuildVersion:	18G103
        )"
    };
    constexpr auto MACOS_SYSTEM_PROFILER
    {
        R"(
        Software:

          System Software Overview:

            System Version: macOS (18G103)
            Kernel Version: Darwin 18.7.0
            Boot Volume: mojave
            Boot Mode: Normal
            Computer Name: macos-mojave-vm
            User Name: System Administrator (root)
            Secure Virtual Memory: Enabled
            System Integrity Protection: Enabled
            Time since boot: 58 minutes
        )"
    };
    constexpr auto MACOS_UNAME
    {
        "18.7.0"
    };
    nlohmann::json output;
    MacOsParser parser;
    EXPECT_TRUE(parser.parseSwVersion(MACOS_SW_VERSION, output));
    EXPECT_FALSE(parser.parseSystemProfiler(MACOS_SYSTEM_PROFILER, output));
    EXPECT_TRUE(parser.parseUname(MACOS_UNAME, output));
    // default name is responsability of the caller
    EXPECT_EQ(output["os_name"], nullptr);
    EXPECT_EQ("10.14.6", output["os_version"]);
    EXPECT_EQ("darwin", output["os_platform"]);
    EXPECT_EQ("18G103", output["os_build"]);
    EXPECT_EQ("Mojave", output["os_codename"]);
    EXPECT_EQ("10", output["os_major"]);
    EXPECT_EQ("14", output["os_minor"]);
    EXPECT_EQ("6", output["os_patch"]);
}
