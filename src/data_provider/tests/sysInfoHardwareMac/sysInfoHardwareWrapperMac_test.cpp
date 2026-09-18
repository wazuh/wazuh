/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * May 18, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <cstring>
#include "sysInfoHardwareWrapperMac_test.h"
#include "hardware/hardwareWrapperImplMac.h"
#include "osPrimitivesInterfaceMac.h"
#include "osPrimitives_mock.h"

void SysInfoHardwareWrapperMacTest::SetUp() {};

void SysInfoHardwareWrapperMacTest::TearDown() {};

using ::testing::_;
using ::testing::Return;

TEST_F(SysInfoHardwareWrapperMacTest, Test_CpuName_Succeed)
{
    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    EXPECT_CALL(*wrapper, sysctlbyname(_, _, _, _, _))
    .WillOnce([](const char* name, void* oldp, size_t* oldlenp, void* newp, size_t newlen)
    {
        (void)name;
        (void)oldp;
        (void)newp;
        (void)newlen;
        *oldlenp = 8;
        return 0;
    })
    .WillOnce([](const char* name, void* oldp, size_t* oldlenp, void* newp, size_t newlen)
    {
        (void)name;
        (void)newp;
        (void)newlen;
        strncpy(static_cast<char*>(oldp), "CpuName", 8);
        *oldlenp = 8;
        return 0;
    });
    std::string ret;
    EXPECT_NO_THROW(ret = wrapper->cpuName());
    EXPECT_STREQ(ret.c_str(), "CpuName");
}

TEST_F(SysInfoHardwareWrapperMacTest, Test_CpuName_Failed_Sysctl1)
{
    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    EXPECT_CALL(*wrapper, sysctlbyname(_, _, _, _, _))
    .WillOnce([](const char* name, void* oldp, size_t* oldlenp, void* newp, size_t newlen)
    {
        (void)name;
        (void)oldp;
        (void)newp;
        (void)newlen;
        *oldlenp = 0;
        return -1;
    });
    EXPECT_THROW(wrapper->cpuName(), std::system_error);
}

TEST_F(SysInfoHardwareWrapperMacTest, Test_CpuName_Failed_Sysctl2)
{
    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    EXPECT_CALL(*wrapper, sysctlbyname(_, _, _, _, _))
    .WillOnce([](const char* name, void* oldp, size_t* oldlenp, void* newp, size_t newlen)
    {
        (void)name;
        (void)oldp;
        (void)newp;
        (void)newlen;
        *oldlenp = 8;
        return 0;
    })
    .WillOnce([](const char* name, void* oldp, size_t* oldlenp, void* newp, size_t newlen)
    {
        (void)name;
        (void)oldp;
        (void)newp;
        (void)newlen;
        *oldlenp = 0;
        return -1;
    });
    EXPECT_THROW(wrapper->cpuName(), std::system_error);
}

TEST_F(SysInfoHardwareWrapperMacTest, Test_CpuCores_Succeed)
{
    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    EXPECT_CALL(*wrapper, sysctl(_, _, _, _, _, _))
    .WillOnce([](int* name, u_int namelen, void* oldp, size_t* oldlenp, void* newp, size_t newlen)
    {
        (void)name;
        (void)namelen;
        (void)newp;
        (void)newlen;
        *static_cast<int*>(oldp) = 8;
        *oldlenp = sizeof(int);
        return 0;
    });
    int ret = 0;
    EXPECT_NO_THROW(ret = wrapper->cpuCores());
    EXPECT_EQ(ret, 8);
}

TEST_F(SysInfoHardwareWrapperMacTest, Test_CpuCores_Failed_Sysctl)
{
    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    EXPECT_CALL(*wrapper, sysctl(_, _, _, _, _, _))
    .WillOnce([](int* name, u_int namelen, void* oldp, size_t* oldlenp, void* newp, size_t newlen)
    {
        (void)name;
        (void)namelen;
        (void)oldp;
        (void)newp;
        (void)newlen;
        *oldlenp = 0;
        return -1;
    });
    EXPECT_THROW(wrapper->cpuCores(), std::system_error);
}



TEST_F(SysInfoHardwareWrapperMacTest, Test_CpuMhz_WithCpuFrequency_Succeed)
{
    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    EXPECT_CALL(*wrapper, sysctlbyname("hw.cpufrequency", _, _, _, _))
    .WillOnce([](const char* name, void* oldp, size_t* oldlenp, void* newp, size_t newlen)
    {
        (void)name;
        (void)oldlenp;
        (void)newp;
        (void)newlen;
        *static_cast<uint64_t*>(oldp) = 3280896;
        return 0;
    });
    double ret = 0.0;
    EXPECT_NO_THROW(ret = wrapper->cpuMhz());
    EXPECT_DOUBLE_EQ(ret, (double)3280896 / 1000000);
}



TEST_F(SysInfoHardwareWrapperMacTest, Test_CpuMhz_WithoutCpuFrequency_Failed_Sysctlbyname)
{
    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    EXPECT_CALL(*wrapper, sysctlbyname("hw.cpufrequency", _, _, _, _))
    .WillOnce([](const char* name, void* oldp, size_t* oldlenp, void* newp, size_t newlen)
    {
        (void)name;
        (void)oldlenp;
        (void)newp;
        (void)newlen;
        *static_cast<uint64_t*>(oldp) = 0;
        return -1;
    });

    EXPECT_THROW(wrapper->cpuMhz(), std::system_error);
}

TEST_F(SysInfoHardwareWrapperMacTest, Test_RamTotal_Succeed)
{
    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    EXPECT_CALL(*wrapper, sysctlbyname("hw.memsize", _, _, _, _))
    .WillOnce([](const char* name, void* oldp, size_t* oldlenp, void* newp, size_t newlen)
    {
        (void)name;
        (void)oldlenp;
        (void)newp;
        (void)newlen;
        *static_cast<uint64_t*>(oldp) = 17179869184;
        return 0;
    });
    uint64_t ret = 0;
    EXPECT_NO_THROW(ret = wrapper->ramTotal());
    EXPECT_EQ(ret, (uint64_t)17179869184 / 1024);
}

TEST_F(SysInfoHardwareWrapperMacTest, Test_RamTotal_Failed_Sysctlbyname)
{
    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    EXPECT_CALL(*wrapper, sysctlbyname("hw.memsize", _, _, _, _))
    .WillOnce([](const char* name, void* oldp, size_t* oldlenp, void* newp, size_t newlen)
    {
        (void)name;
        (void)oldlenp;
        (void)newp;
        (void)newlen;
        *static_cast<uint64_t*>(oldp) = 0;
        return -1;
    });
    EXPECT_THROW(wrapper->ramTotal(), std::system_error);
}

namespace
{
    constexpr u_int TEST_PAGE_SIZE{16384};
    constexpr uint64_t TEST_RAM_TOTAL{4294967296};
    constexpr uint64_t TEST_FREE_COUNT{41839};
    constexpr uint64_t TEST_ACTIVE_COUNT{55000};
    constexpr uint64_t TEST_INACTIVE_COUNT{27790};
    constexpr uint64_t TEST_SPECULATIVE_COUNT{1200};
    constexpr uint64_t TEST_PURGEABLE_COUNT{3557};
    constexpr uint64_t TEST_EXTERNAL_PAGE_COUNT{79412};
    constexpr uint64_t TEST_AVAILABLE_KB{(TEST_FREE_COUNT + TEST_ACTIVE_COUNT + TEST_INACTIVE_COUNT)* TEST_PAGE_SIZE / 1024};

    void expectPageSize(OsPrimitivesMacMock& mock, u_int pageSize)
    {
        EXPECT_CALL(mock, sysctlbyname("vm.pagesize", _, _, _, _))
        .WillOnce([pageSize](const char* name, void* oldp, size_t* oldlenp, void* newp, size_t newlen)
        {
            (void)name;
            (void)oldlenp;
            (void)newp;
            (void)newlen;
            *static_cast<u_int*>(oldp) = pageSize;
            return 0;
        });
    }

    void expectHostStatistics64Succeed(OsPrimitivesMacMock& mock,
                                       uint64_t freeCount,
                                       uint64_t activeCount,
                                       uint64_t inactiveCount,
                                       uint64_t speculativeCount,
                                       uint64_t purgeableCount,
                                       uint64_t externalPageCount)
    {
        const mach_port_t hostPort{1};
        EXPECT_CALL(mock, mach_host_self()).WillOnce(Return(hostPort));
        EXPECT_CALL(mock, mach_port_deallocate(_, hostPort)).WillOnce(Return(KERN_SUCCESS));
        EXPECT_CALL(mock, host_statistics64(hostPort, HOST_VM_INFO64, _, _))
        .WillOnce([freeCount, activeCount, inactiveCount, speculativeCount, purgeableCount, externalPageCount]
                  (host_t, host_flavor_t, host_info64_t hostInfo64Out, mach_msg_type_number_t*)
        {
            auto* vmStat{reinterpret_cast<vm_statistics64_data_t*>(hostInfo64Out)};
            vmStat->free_count = static_cast<natural_t>(freeCount);
            vmStat->active_count = static_cast<natural_t>(activeCount);
            vmStat->inactive_count = static_cast<natural_t>(inactiveCount);
            vmStat->speculative_count = static_cast<natural_t>(speculativeCount);
            vmStat->purgeable_count = static_cast<natural_t>(purgeableCount);
            vmStat->external_page_count = static_cast<natural_t>(externalPageCount);
            return KERN_SUCCESS;
        });
    }
}

TEST_F(SysInfoHardwareWrapperMacTest, Test_RamFree_Succeed)
{
    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    expectPageSize(*wrapper, TEST_PAGE_SIZE);
    expectHostStatistics64Succeed(*wrapper, TEST_FREE_COUNT, TEST_ACTIVE_COUNT, TEST_INACTIVE_COUNT, TEST_SPECULATIVE_COUNT,
                                  TEST_PURGEABLE_COUNT, TEST_EXTERNAL_PAGE_COUNT);

    uint64_t ret = 0;
    EXPECT_NO_THROW(ret = wrapper->ramFree());
    EXPECT_EQ(ret, TEST_AVAILABLE_KB);
}

TEST_F(SysInfoHardwareWrapperMacTest, Test_RamFree_SpeculativeAlreadyInFreeCount_DoesNotChangeResult)
{
    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    expectPageSize(*wrapper, TEST_PAGE_SIZE);
    const uint64_t extraSpeculativePages{500};
    expectHostStatistics64Succeed(*wrapper, TEST_FREE_COUNT, TEST_ACTIVE_COUNT, TEST_INACTIVE_COUNT,
                                  TEST_SPECULATIVE_COUNT + extraSpeculativePages, TEST_PURGEABLE_COUNT, TEST_EXTERNAL_PAGE_COUNT);

    uint64_t ret = 0;
    EXPECT_NO_THROW(ret = wrapper->ramFree());
    EXPECT_EQ(ret, TEST_AVAILABLE_KB);
}

TEST_F(SysInfoHardwareWrapperMacTest, Test_RamFree_PurgeableAndExternalCounts_AreIgnored)
{
    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    expectPageSize(*wrapper, TEST_PAGE_SIZE);
    expectHostStatistics64Succeed(*wrapper, TEST_FREE_COUNT, TEST_ACTIVE_COUNT, TEST_INACTIVE_COUNT, TEST_SPECULATIVE_COUNT,
                                  TEST_PURGEABLE_COUNT * 10, TEST_EXTERNAL_PAGE_COUNT * 10);

    uint64_t ret = 0;
    EXPECT_NO_THROW(ret = wrapper->ramFree());
    EXPECT_EQ(ret, TEST_AVAILABLE_KB);
}

TEST_F(SysInfoHardwareWrapperMacTest, Test_RamFree_Failed_Sysctlbyname1)
{
    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    EXPECT_CALL(*wrapper, sysctlbyname("vm.pagesize", _, _, _, _))
    .WillOnce([](const char* name, void* oldp, size_t* oldlenp, void* newp, size_t newlen)
    {
        (void)name;
        (void)oldlenp;
        (void)newp;
        (void)newlen;
        *static_cast<uint64_t*>(oldp) = 0;
        return -1;
    });
    EXPECT_THROW(wrapper->ramFree(), std::system_error);
}

TEST_F(SysInfoHardwareWrapperMacTest, Test_RamFree_Failed_HostStatistics64)
{
    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    expectPageSize(*wrapper, TEST_PAGE_SIZE);

    const mach_port_t hostPort{1};
    EXPECT_CALL(*wrapper, mach_host_self()).WillOnce(Return(hostPort));
    EXPECT_CALL(*wrapper, mach_port_deallocate(_, hostPort)).WillOnce(Return(KERN_SUCCESS));
    EXPECT_CALL(*wrapper, host_statistics64(hostPort, HOST_VM_INFO64, _, _))
    .WillOnce(Return(KERN_FAILURE));

    EXPECT_THROW(wrapper->ramFree(), std::runtime_error);
}

TEST_F(SysInfoHardwareWrapperMacTest, Test_RamUsage_Succeed)
{
    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    EXPECT_CALL(*wrapper, sysctlbyname("hw.memsize", _, _, _, _))
    .WillOnce([](const char* name, void* oldp, size_t* oldlenp, void* newp, size_t newlen)
    {
        (void)name;
        (void)oldlenp;
        (void)newp;
        (void)newlen;
        *static_cast<uint64_t*>(oldp) = TEST_RAM_TOTAL;
        return 0;
    });
    expectPageSize(*wrapper, TEST_PAGE_SIZE);
    expectHostStatistics64Succeed(*wrapper, TEST_FREE_COUNT, TEST_ACTIVE_COUNT, TEST_INACTIVE_COUNT, TEST_SPECULATIVE_COUNT,
                                  TEST_PURGEABLE_COUNT, TEST_EXTERNAL_PAGE_COUNT);

    uint64_t ret = 0;
    EXPECT_NO_THROW(ret = wrapper->ramUsage());
    const uint64_t ramTotalKB{TEST_RAM_TOTAL / 1024};
    const uint64_t expected{100 - (100 * TEST_AVAILABLE_KB / ramTotalKB)};
    EXPECT_EQ(ret, expected);
}

TEST_F(SysInfoHardwareWrapperMacTest, Test_RamUsage_Succeed_TotalRamZero)
{
    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    EXPECT_CALL(*wrapper, sysctlbyname("hw.memsize", _, _, _, _))
    .WillOnce([](const char* name, void* oldp, size_t* oldlenp, void* newp, size_t newlen)
    {
        (void)name;
        (void)oldlenp;
        (void)newp;
        (void)newlen;
        *static_cast<uint64_t*>(oldp) = 0;
        return 0;
    });
    uint64_t ret = 0;
    EXPECT_NO_THROW(ret = wrapper->ramUsage());
    EXPECT_EQ(ret, (uint64_t)0);
}

TEST_F(SysInfoHardwareWrapperMacTest, Test_RamUsage_Failed_Sysctlbyname1)
{
    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    EXPECT_CALL(*wrapper, sysctlbyname("hw.memsize", _, _, _, _))
    .WillOnce([](const char* name, void* oldp, size_t* oldlenp, void* newp, size_t newlen)
    {
        (void)name;
        (void)oldlenp;
        (void)newp;
        (void)newlen;
        *static_cast<uint64_t*>(oldp) = 0;
        return -1;
    });
    EXPECT_THROW(wrapper->ramUsage(), std::system_error);
}

TEST_F(SysInfoHardwareWrapperMacTest, Test_RamUsage_Failed_Sysctlbyname2)
{
    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    EXPECT_CALL(*wrapper, sysctlbyname("hw.memsize", _, _, _, _))
    .WillOnce([](const char* name, void* oldp, size_t* oldlenp, void* newp, size_t newlen)
    {
        (void)name;
        (void)oldlenp;
        (void)newp;
        (void)newlen;
        *static_cast<uint64_t*>(oldp) = 17179869184;
        return 0;
    });
    EXPECT_CALL(*wrapper, sysctlbyname("vm.pagesize", _, _, _, _))
    .WillOnce([](const char* name, void* oldp, size_t* oldlenp, void* newp, size_t newlen)
    {
        (void)name;
        (void)oldlenp;
        (void)newp;
        (void)newlen;
        *static_cast<u_int*>(oldp) = 0;
        return -1;
    });
    EXPECT_THROW(wrapper->ramUsage(), std::system_error);
}

TEST_F(SysInfoHardwareWrapperMacTest, Test_RamUsage_Failed_HostStatistics64)
{
    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    EXPECT_CALL(*wrapper, sysctlbyname("hw.memsize", _, _, _, _))
    .WillOnce([](const char* name, void* oldp, size_t* oldlenp, void* newp, size_t newlen)
    {
        (void)name;
        (void)oldlenp;
        (void)newp;
        (void)newlen;
        *static_cast<uint64_t*>(oldp) = TEST_RAM_TOTAL;
        return 0;
    });
    expectPageSize(*wrapper, TEST_PAGE_SIZE);

    const mach_port_t hostPort{1};
    EXPECT_CALL(*wrapper, mach_host_self()).WillOnce(Return(hostPort));
    EXPECT_CALL(*wrapper, mach_port_deallocate(_, hostPort)).WillOnce(Return(KERN_SUCCESS));
    EXPECT_CALL(*wrapper, host_statistics64(hostPort, HOST_VM_INFO64, _, _))
    .WillOnce(Return(KERN_FAILURE));

    EXPECT_THROW(wrapper->ramUsage(), std::runtime_error);
}

TEST_F(SysInfoHardwareWrapperMacTest, Test_BoardSerial_Succeed)
{
    auto utils_mock { std::make_shared<UtilsMock>() };
    gs_utils_mock = utils_mock.get();

    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    EXPECT_CALL(*utils_mock, exec(_, _)).Times(1).WillOnce(Return("      Serial Number (system): H2WH91N3Q6NY\n"));

    std::string ret;
    EXPECT_NO_THROW(ret = wrapper->boardSerial());
    EXPECT_STREQ(ret.c_str(), "H2WH91N3Q6NY");
}

TEST_F(SysInfoHardwareWrapperMacTest, Test_BoardSerial_Failed_UnknowValue)
{
    auto utils_mock { std::make_shared<UtilsMock>() };
    gs_utils_mock = utils_mock.get();

    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    EXPECT_CALL(*utils_mock, exec(_, _)).Times(1).WillOnce(Return(""));

    std::string ret;
    EXPECT_NO_THROW(ret = wrapper->boardSerial());
    EXPECT_STREQ(ret.c_str(), UNKNOWN_VALUE);
}
