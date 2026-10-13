/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * October 9, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "sysInfoHardwareLinux_test.h"
#include "hardware/cpuInfoLinux.h"

void SysInfoHardwareLinuxTest::SetUp() {};

void SysInfoHardwareLinuxTest::TearDown() {};

TEST_F(SysInfoHardwareLinuxTest, cpuNameFromModelName)
{
    const std::map<std::string, std::string> cpuInfo
    {
        {"processor", "1"},
        {"vendor_id", "GenuineIntel"},
        {"cpu family", "6"},
        {"model name", "Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz"},
        {"cpu MHz", "2499.998"}
    };

    EXPECT_EQ("Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz", CpuInfoLinux::cpuName(cpuInfo));
}

TEST_F(SysInfoHardwareLinuxTest, cpuNameFromPowerCpu)
{
    const std::map<std::string, std::string> cpuInfo
    {
        {"processor", "7"},
        {"cpu", "POWER9 (architected), altivec supported"},
        {"clock", "2200.000000MHz"},
        {"revision", "2.2 (pvr 004e 1202)"}
    };

    EXPECT_EQ("POWER9 (architected), altivec supported", CpuInfoLinux::cpuName(cpuInfo));
}

TEST_F(SysInfoHardwareLinuxTest, cpuNameFromArmIds)
{
    const std::map<std::string, std::string> cpuInfo
    {
        {"processor", "1"},
        {"BogoMIPS", "243.75"},
        {"Features", "fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp"},
        {"CPU implementer", "0x41"},
        {"CPU architecture", "8"},
        {"CPU variant", "0x3"},
        {"CPU part", "0xd0c"},
        {"CPU revision", "1"}
    };

    EXPECT_EQ("Neoverse-N1", CpuInfoLinux::cpuName(cpuInfo));
}

TEST_F(SysInfoHardwareLinuxTest, cpuNameFromArmIdsOtherImplementer)
{
    const std::map<std::string, std::string> cpuInfo
    {
        {"CPU implementer", "0xc0"},
        {"CPU part", "0xac3"}
    };

    EXPECT_EQ("Ampere-1", CpuInfoLinux::cpuName(cpuInfo));
}

TEST_F(SysInfoHardwareLinuxTest, cpuNameFromArmIdsUnknownPart)
{
    const std::map<std::string, std::string> cpuInfo
    {
        {"CPU implementer", "0x41"},
        {"CPU part", "0xfff"}
    };

    EXPECT_EQ("ARM 0xfff", CpuInfoLinux::cpuName(cpuInfo));
}

TEST_F(SysInfoHardwareLinuxTest, cpuNameFromArmIdsMissingPart)
{
    const std::map<std::string, std::string> cpuInfo
    {
        {"CPU implementer", "0x61"}
    };

    EXPECT_EQ("Apple", CpuInfoLinux::cpuName(cpuInfo));
}

TEST_F(SysInfoHardwareLinuxTest, cpuNameFromArmIdsUnknownImplementer)
{
    const std::map<std::string, std::string> cpuInfo
    {
        {"CPU implementer", "0x01"},
        {"CPU part", "0xd0c"}
    };

    EXPECT_EQ(UNKNOWN_VALUE, CpuInfoLinux::cpuName(cpuInfo));
}

TEST_F(SysInfoHardwareLinuxTest, cpuNameFromArmIdsMalformed)
{
    const std::map<std::string, std::string> cpuInfo
    {
        {"CPU implementer", "ARM"},
        {"CPU part", "0xd0c"}
    };

    EXPECT_EQ(UNKNOWN_VALUE, CpuInfoLinux::cpuName(cpuInfo));
}

TEST_F(SysInfoHardwareLinuxTest, cpuNameSkipsEmptyModelName)
{
    const std::map<std::string, std::string> cpuInfo
    {
        {"model name", ""},
        {"CPU implementer", "0x41"},
        {"CPU part", "0xd4f"}
    };

    EXPECT_EQ("Neoverse-V2", CpuInfoLinux::cpuName(cpuInfo));
}

TEST_F(SysInfoHardwareLinuxTest, cpuNameUnknown)
{
    EXPECT_EQ(UNKNOWN_VALUE, CpuInfoLinux::cpuName({}));
}
