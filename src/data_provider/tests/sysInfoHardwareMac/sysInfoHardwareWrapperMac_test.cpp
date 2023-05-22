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
#include "IOKit/IOKitLib.h"
#include "CoreFoundation/CFBase.h"

void SysInfoHardwareWrapperMacTest::SetUp() {};

void SysInfoHardwareWrapperMacTest::TearDown() {};

using ::testing::_;
using ::testing::Return;

class UtilsMock
{
    public:
        MOCK_METHOD(std::string, exec, (const std::string&, const size_t));
};

static UtilsMock* gs_utils_mock = NULL;

std::string UtilsWrapperMac::exec(const std::string& cmd, const size_t bufferSize)
{
    return gs_utils_mock->exec(cmd, bufferSize);
}

class OsPrimitivesMacMock: public IOsPrimitivesMac
{
    public:
        OsPrimitivesMacMock() = default;
        virtual ~OsPrimitivesMacMock() = default;

        MOCK_METHOD(int, sysctl, (int* name, u_int namelen, void* oldp, size_t* oldlenp, void* newp, size_t newlen), (const override));
        MOCK_METHOD(int, sysctlbyname, (const char* name, void* oldp, size_t* oldlenp, void* newp, size_t newlen), (const override));

        MOCK_METHOD(CFMutableDictionaryRef, IOServiceMatching, (const char* name), (const override));
        MOCK_METHOD(kern_return_t, IOServiceGetMatchingServices, (mach_port_t mainPort, CFDictionaryRef matching, io_iterator_t* existing), (const override));
        MOCK_METHOD(io_object_t, IOIteratorNext, (io_iterator_t iterator), (const override));
        MOCK_METHOD(kern_return_t, IORegistryEntryGetName, (io_registry_entry_t entry, io_name_t name), (const override));
        MOCK_METHOD(kern_return_t, IORegistryEntryCreateCFProperties, (io_registry_entry_t entry, CFMutableDictionaryRef* properties, CFAllocatorRef allocator, IOOptionBits options), (const override));
        MOCK_METHOD(kern_return_t, IOObjectRelease, (io_object_t object), (const override));

        MOCK_METHOD(CFStringRef, CFStringCreateWithCString, (CFAllocatorRef alloc, const char* cStr, CFStringEncoding encoding), (const override));
        MOCK_METHOD(const void*, CFDictionaryGetValue, (CFDictionaryRef theDict, const void* key), (const override));
        MOCK_METHOD(CFTypeID, CFGetTypeID, (CFTypeRef cf), (const override));
        MOCK_METHOD(CFTypeID, CFDataGetTypeID, (), (const override));
        MOCK_METHOD(CFIndex, CFDataGetLength, (CFDataRef theData), (const override));
        MOCK_METHOD(void, CFDataGetBytes, (CFDataRef theData, CFRange range, UInt8* buffer), (const override));
        MOCK_METHOD(CFRange, CFRangeMake, (CFIndex loc, CFIndex len), (const override));
        MOCK_METHOD(void, CFRelease, (CFTypeRef cf), (const override));
};

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

TEST_F(SysInfoHardwareWrapperMacTest, Test_CpuName_Succeed)
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
        *oldlenp = 8;
        return 0;
    })
    .WillOnce([](int* name, u_int namelen, void* oldp, size_t* oldlenp, void* newp, size_t newlen)
    {
        (void)name;
        (void)namelen;
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
    EXPECT_THROW(wrapper->cpuName(), std::system_error);
}

TEST_F(SysInfoHardwareWrapperMacTest, Test_CpuName_Failed_Sysctl2)
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
        *oldlenp = 8;
        return 0;
    })
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

TEST_F(SysInfoHardwareWrapperMacTest, Test_GetCpuHzAarch64_Succeed)
{
    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    EXPECT_CALL(*wrapper, IOServiceMatching("AppleARMIODevice"))
    .WillOnce(Return(reinterpret_cast<CFMutableDictionaryRef>(1)));
    EXPECT_CALL(*wrapper, IOServiceGetMatchingServices(kIOMainPortDefault, _, _))
    .WillOnce(Return(KERN_SUCCESS));
    EXPECT_CALL(*wrapper, IOIteratorNext(_))
    .WillOnce(Return(1))
    .WillOnce(Return(0));
    EXPECT_CALL(*wrapper, IORegistryEntryGetName(_, _))
    .WillOnce([](io_registry_entry_t entry, io_name_t name)
    {
        (void)entry;
        strncpy(name, "pmgr", sizeof(io_name_t));
        return KERN_SUCCESS;
    });
    EXPECT_CALL(*wrapper, IORegistryEntryCreateCFProperties(_, _, kCFAllocatorDefault, kNilOptions))
    .WillOnce(Return(KERN_SUCCESS));
    EXPECT_CALL(*wrapper, CFStringCreateWithCString(kCFAllocatorDefault, "voltage-states5-sram", kCFStringEncodingUTF8))
    .WillOnce(Return(reinterpret_cast<CFStringRef>(1)));
    EXPECT_CALL(*wrapper, CFDictionaryGetValue(_, _))
    .WillOnce(Return(reinterpret_cast<void*>(1)));
    EXPECT_CALL(*wrapper, CFGetTypeID(_))
    .WillOnce(Return(1));
    EXPECT_CALL(*wrapper, CFDataGetTypeID())
    .WillOnce(Return(1));
    EXPECT_CALL(*wrapper, CFDataGetLength(_))
    .WillOnce(Return(32));
    EXPECT_CALL(*wrapper, CFRangeMake(_, sizeof(uint32_t)))
    .WillRepeatedly([](CFIndex loc, CFIndex len)
    {
        CFRange range;
        range.location = loc;
        range.length = len;
        return range;
    });
    EXPECT_CALL(*wrapper, CFDataGetBytes(_, _, _))
    .WillRepeatedly([](CFDataRef theData, CFRange range, UInt8 * buffer)
    {
        (void)theData;
        (void)range;
        *reinterpret_cast<uint32_t*>(buffer) = 3280896;
    });
    EXPECT_CALL(*wrapper, IOObjectRelease(_))
    .WillRepeatedly(Return(KERN_SUCCESS));
    EXPECT_CALL(*wrapper, CFRelease(_)).Times(2);

    uint64_t cpuHz;
    EXPECT_NO_THROW(cpuHz = wrapper->getCpuHzAarch64());
    EXPECT_EQ(cpuHz, (uint64_t)3280896);
}

TEST_F(SysInfoHardwareWrapperMacTest, Test_GetCpuHzAarch64_Failed_IOServiceMatching)
{
    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    EXPECT_CALL(*wrapper, IOServiceMatching("AppleARMIODevice"))
    .WillOnce(Return(nullptr));

    EXPECT_THROW(wrapper->getCpuHzAarch64(), std::system_error);
}

TEST_F(SysInfoHardwareWrapperMacTest, Test_GetCpuHzAarch64_Failed_IOServiceGetMatchingServices)
{
    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    EXPECT_CALL(*wrapper, IOServiceMatching("AppleARMIODevice"))
    .WillOnce(Return(reinterpret_cast<CFMutableDictionaryRef>(1)));
    EXPECT_CALL(*wrapper, IOServiceGetMatchingServices(kIOMainPortDefault, _, _))
    .WillOnce(Return(KERN_FAILURE));

    EXPECT_THROW(wrapper->getCpuHzAarch64(), std::system_error);
}

TEST_F(SysInfoHardwareWrapperMacTest, Test_GetCpuHzAarch64_Failed_IORegistryEntryCreateCFProperties)
{
    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    EXPECT_CALL(*wrapper, IOServiceMatching("AppleARMIODevice"))
    .WillOnce(Return(reinterpret_cast<CFMutableDictionaryRef>(1)));
    EXPECT_CALL(*wrapper, IOServiceGetMatchingServices(kIOMainPortDefault, _, _))
    .WillOnce(Return(KERN_SUCCESS));
    EXPECT_CALL(*wrapper, IOIteratorNext(_))
    .WillOnce(Return(1));
    EXPECT_CALL(*wrapper, IORegistryEntryGetName(_, _))
    .WillOnce([](io_registry_entry_t entry, io_name_t name)
    {
        (void)entry;
        strncpy(name, "pmgr", sizeof(io_name_t));
        return KERN_SUCCESS;
    });
    EXPECT_CALL(*wrapper, IORegistryEntryCreateCFProperties(_, _, kCFAllocatorDefault, kNilOptions))
    .WillOnce(Return(KERN_FAILURE));
    EXPECT_CALL(*wrapper, IOObjectRelease(_))
    .WillRepeatedly(Return(KERN_SUCCESS));

    EXPECT_THROW(wrapper->getCpuHzAarch64(), std::system_error);
}

TEST_F(SysInfoHardwareWrapperMacTest, Test_GetCpuHzAarch64_Failed_CFDictionaryGetValue)
{
    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    EXPECT_CALL(*wrapper, IOServiceMatching("AppleARMIODevice"))
    .WillOnce(Return(reinterpret_cast<CFMutableDictionaryRef>(1)));
    EXPECT_CALL(*wrapper, IOServiceGetMatchingServices(kIOMainPortDefault, _, _))
    .WillOnce(Return(KERN_SUCCESS));
    EXPECT_CALL(*wrapper, IOIteratorNext(_))
    .WillOnce(Return(1));
    EXPECT_CALL(*wrapper, IORegistryEntryGetName(_, _))
    .WillOnce([](io_registry_entry_t entry, io_name_t name)
    {
        (void)entry;
        strncpy(name, "pmgr", sizeof(io_name_t));
        return KERN_SUCCESS;
    });
    EXPECT_CALL(*wrapper, IORegistryEntryCreateCFProperties(_, _, kCFAllocatorDefault, kNilOptions))
    .WillOnce(Return(KERN_SUCCESS));
    EXPECT_CALL(*wrapper, CFStringCreateWithCString(kCFAllocatorDefault, "voltage-states5-sram", kCFStringEncodingUTF8))
    .WillOnce(Return(reinterpret_cast<CFStringRef>(1)));
    EXPECT_CALL(*wrapper, CFDictionaryGetValue(_, _))
    .WillOnce(Return(nullptr));
    EXPECT_CALL(*wrapper, IOObjectRelease(_))
    .WillRepeatedly(Return(KERN_SUCCESS));
    EXPECT_CALL(*wrapper, CFRelease(_)).Times(2);

    EXPECT_THROW(wrapper->getCpuHzAarch64(), std::system_error);
}

TEST_F(SysInfoHardwareWrapperMacTest, Test_GetCpuHzAarch64_Failed_CFGetTypeID)
{
    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    EXPECT_CALL(*wrapper, IOServiceMatching("AppleARMIODevice"))
    .WillOnce(Return(reinterpret_cast<CFMutableDictionaryRef>(1)));
    EXPECT_CALL(*wrapper, IOServiceGetMatchingServices(kIOMainPortDefault, _, _))
    .WillOnce(Return(KERN_SUCCESS));
    EXPECT_CALL(*wrapper, IOIteratorNext(_))
    .WillOnce(Return(1));
    EXPECT_CALL(*wrapper, IORegistryEntryGetName(_, _))
    .WillOnce([](io_registry_entry_t entry, io_name_t name)
    {
        (void)entry;
        strncpy(name, "pmgr", sizeof(io_name_t));
        return KERN_SUCCESS;
    });
    EXPECT_CALL(*wrapper, IORegistryEntryCreateCFProperties(_, _, kCFAllocatorDefault, kNilOptions))
    .WillOnce(Return(KERN_SUCCESS));
    EXPECT_CALL(*wrapper, CFStringCreateWithCString(kCFAllocatorDefault, "voltage-states5-sram", kCFStringEncodingUTF8))
    .WillOnce(Return(reinterpret_cast<CFStringRef>(1)));
    EXPECT_CALL(*wrapper, CFDictionaryGetValue(_, _))
    .WillOnce(Return(reinterpret_cast<void*>(1)));
    EXPECT_CALL(*wrapper, CFGetTypeID(_))
    .WillOnce(Return(2));
    EXPECT_CALL(*wrapper, CFDataGetTypeID())
    .WillOnce(Return(1));
    EXPECT_CALL(*wrapper, IOObjectRelease(_))
    .WillRepeatedly(Return(KERN_SUCCESS));
    EXPECT_CALL(*wrapper, CFRelease(_)).Times(2);

    EXPECT_THROW(wrapper->getCpuHzAarch64(), std::system_error);
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

TEST_F(SysInfoHardwareWrapperMacTest, Test_CpuMhz_WithoutCpuFrequency_Succeed)
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
    EXPECT_CALL(*wrapper, IOServiceMatching("AppleARMIODevice"))
    .WillOnce(Return(reinterpret_cast<CFMutableDictionaryRef>(1)));
    EXPECT_CALL(*wrapper, IOServiceGetMatchingServices(kIOMainPortDefault, _, _))
    .WillOnce(Return(KERN_SUCCESS));
    EXPECT_CALL(*wrapper, IOIteratorNext(_))
    .WillOnce(Return(1))
    .WillOnce(Return(0));
    EXPECT_CALL(*wrapper, IORegistryEntryGetName(_, _))
    .WillOnce([](io_registry_entry_t entry, io_name_t name)
    {
        (void)entry;
        strncpy(name, "pmgr", sizeof(io_name_t));
        return KERN_SUCCESS;
    });
    EXPECT_CALL(*wrapper, IORegistryEntryCreateCFProperties(_, _, kCFAllocatorDefault, kNilOptions))
    .WillOnce(Return(KERN_SUCCESS));
    EXPECT_CALL(*wrapper, CFStringCreateWithCString(kCFAllocatorDefault, "voltage-states5-sram", kCFStringEncodingUTF8))
    .WillOnce(Return(reinterpret_cast<CFStringRef>(1)));
    EXPECT_CALL(*wrapper, CFDictionaryGetValue(_, _))
    .WillOnce(Return(reinterpret_cast<void*>(1)));
    EXPECT_CALL(*wrapper, CFGetTypeID(_))
    .WillOnce(Return(1));
    EXPECT_CALL(*wrapper, CFDataGetTypeID())
    .WillOnce(Return(1));
    EXPECT_CALL(*wrapper, CFDataGetLength(_))
    .WillOnce(Return(32));
    EXPECT_CALL(*wrapper, CFRangeMake(_, sizeof(uint32_t)))
    .WillRepeatedly([](CFIndex loc, CFIndex len)
    {
        CFRange range;
        range.location = loc;
        range.length = len;
        return range;
    });
    EXPECT_CALL(*wrapper, CFDataGetBytes(_, _, _))
    .WillRepeatedly([](CFDataRef theData, CFRange range, UInt8 * buffer)
    {
        (void)theData;
        (void)range;
        *reinterpret_cast<uint32_t*>(buffer) = 3280896;
    });
    EXPECT_CALL(*wrapper, IOObjectRelease(_))
    .WillRepeatedly(Return(KERN_SUCCESS));
    EXPECT_CALL(*wrapper, CFRelease(_)).Times(2);

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
    EXPECT_CALL(*wrapper, IOServiceMatching("AppleARMIODevice"))
    .WillOnce(Return(nullptr));

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

TEST_F(SysInfoHardwareWrapperMacTest, Test_RamFree_Succeed)
{
    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    EXPECT_CALL(*wrapper, sysctlbyname("vm.pagesize", _, _, _, _))
    .WillOnce([](const char* name, void* oldp, size_t* oldlenp, void* newp, size_t newlen)
    {
        (void)name;
        (void)oldlenp;
        (void)newp;
        (void)newlen;
        *static_cast<u_int*>(oldp) = 16384;
        return 0;
    });
    EXPECT_CALL(*wrapper, sysctlbyname("vm.page_free_count", _, _, _, _))
    .WillOnce([](const char* name, void* oldp, size_t* oldlenp, void* newp, size_t newlen)
    {
        (void)name;
        (void)oldlenp;
        (void)newp;
        (void)newlen;
        *static_cast<uint64_t*>(oldp) = 342319;
        return 0;
    });
    uint64_t ret = 0;
    EXPECT_NO_THROW(ret = wrapper->ramFree());
    EXPECT_EQ(ret, (uint64_t)(16384) * 342319 / 1024);
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

TEST_F(SysInfoHardwareWrapperMacTest, Test_RamFree_Failed_Sysctlbyname2)
{
    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    EXPECT_CALL(*wrapper, sysctlbyname("vm.pagesize", _, _, _, _))
    .WillOnce([](const char* name, void* oldp, size_t* oldlenp, void* newp, size_t newlen)
    {
        (void)name;
        (void)oldlenp;
        (void)newp;
        (void)newlen;
        *static_cast<u_int*>(oldp) = 16384;
        return 0;
    });
    EXPECT_CALL(*wrapper, sysctlbyname("vm.page_free_count", _, _, _, _))
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

TEST_F(SysInfoHardwareWrapperMacTest, Test_RamUsage_Succeed)
{
    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    EXPECT_CALL(*wrapper, sysctlbyname("vm.pagesize", _, _, _, _))
    .WillOnce([](const char* name, void* oldp, size_t* oldlenp, void* newp, size_t newlen)
    {
        (void)name;
        (void)oldlenp;
        (void)newp;
        (void)newlen;
        *static_cast<u_int*>(oldp) = 16384;
        return 0;
    });
    EXPECT_CALL(*wrapper, sysctlbyname("vm.page_free_count", _, _, _, _))
    .WillOnce([](const char* name, void* oldp, size_t* oldlenp, void* newp, size_t newlen)
    {
        (void)name;
        (void)oldlenp;
        (void)newp;
        (void)newlen;
        *static_cast<uint64_t*>(oldp) = 342319;
        return 0;
    });
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
    EXPECT_NO_THROW(ret = wrapper->ramUsage());
    EXPECT_EQ(ret, (uint64_t)(100 - (100 * ((uint64_t)16384 * 342319 / 1024) / ((uint64_t)17179869184 / 1024))));
}

TEST_F(SysInfoHardwareWrapperMacTest, Test_RamUsage_Failed_Sysctlbyname1)
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
    EXPECT_THROW(wrapper->ramUsage(), std::system_error);
}

TEST_F(SysInfoHardwareWrapperMacTest, Test_RamUsage_Failed_Sysctlbyname2)
{
    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    EXPECT_CALL(*wrapper, sysctlbyname("vm.pagesize", _, _, _, _))
    .WillOnce([](const char* name, void* oldp, size_t* oldlenp, void* newp, size_t newlen)
    {
        (void)name;
        (void)oldlenp;
        (void)newp;
        (void)newlen;
        *static_cast<u_int*>(oldp) = 16384;
        return 0;
    });
    EXPECT_CALL(*wrapper, sysctlbyname("vm.page_free_count", _, _, _, _))
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

TEST_F(SysInfoHardwareWrapperMacTest, Test_RamUsage_Failed_Sysctlbyname3)
{
    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    EXPECT_CALL(*wrapper, sysctlbyname("vm.pagesize", _, _, _, _))
    .WillOnce([](const char* name, void* oldp, size_t* oldlenp, void* newp, size_t newlen)
    {
        (void)name;
        (void)oldlenp;
        (void)newp;
        (void)newlen;
        *static_cast<u_int*>(oldp) = 16384;
        return 0;
    });
    EXPECT_CALL(*wrapper, sysctlbyname("vm.page_free_count", _, _, _, _))
    .WillOnce([](const char* name, void* oldp, size_t* oldlenp, void* newp, size_t newlen)
    {
        (void)name;
        (void)oldlenp;
        (void)newp;
        (void)newlen;
        *static_cast<uint64_t*>(oldp) = 342319;
        return 0;
    });
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
