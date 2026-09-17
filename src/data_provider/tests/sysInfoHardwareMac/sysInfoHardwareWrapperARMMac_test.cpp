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

#include "sysInfoHardwareWrapperARMMac_test.h"
#include "hardware/hardwareWrapperImplMac.h"
#include "osPrimitivesInterfaceMac.h"
#include "osPrimitives_mock.h"
#include "IOKit/IOKitLib.h"
#include "CoreFoundation/CFBase.h"

using ::testing::_;
using ::testing::Return;

void SysInfoHardwareWrapperARMMacTest::SetUp() {};

void SysInfoHardwareWrapperARMMacTest::TearDown() {};

TEST_F(SysInfoHardwareWrapperARMMacTest, Test_CpuMhz_Succeed)
{
    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    EXPECT_CALL(*wrapper, sysctlbyname("hw.cpufrequency", _, _, _, _))
    .WillOnce(Return(1));
    EXPECT_CALL(*wrapper, IOServiceMatching("AppleARMIODevice"))
    .WillOnce(Return(reinterpret_cast<CFMutableDictionaryRef>(1)));
    EXPECT_CALL(*wrapper, IOServiceGetMatchingServices(_, _, _))
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

TEST_F(SysInfoHardwareWrapperARMMacTest, Test_CpuMhz_Failed_IOServiceMatching)
{
    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    EXPECT_CALL(*wrapper, sysctlbyname("hw.cpufrequency", _, _, _, _))
    .WillOnce(Return(1));
    EXPECT_CALL(*wrapper, IOServiceMatching("AppleARMIODevice"))
    .WillOnce(Return(nullptr));

    double ret = -1.0;
    EXPECT_NO_THROW(ret = wrapper->cpuMhz());
    EXPECT_DOUBLE_EQ(ret, 0.0);
}

TEST_F(SysInfoHardwareWrapperARMMacTest, Test_CpuMhz_Failed_IOServiceGetMatchingServices)
{
    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    EXPECT_CALL(*wrapper, sysctlbyname("hw.cpufrequency", _, _, _, _))
    .WillOnce(Return(1));
    EXPECT_CALL(*wrapper, IOServiceMatching("AppleARMIODevice"))
    .WillOnce(Return(reinterpret_cast<CFMutableDictionaryRef>(1)));
    EXPECT_CALL(*wrapper, IOServiceGetMatchingServices(_, _, _))
    .WillOnce(Return(KERN_FAILURE));

    double ret = -1.0;
    EXPECT_NO_THROW(ret = wrapper->cpuMhz());
    EXPECT_DOUBLE_EQ(ret, 0.0);
}

TEST_F(SysInfoHardwareWrapperARMMacTest, Test_CpuMhz_Failed_IORegistryEntryCreateCFProperties)
{
    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    EXPECT_CALL(*wrapper, sysctlbyname("hw.cpufrequency", _, _, _, _))
    .WillOnce(Return(1));
    EXPECT_CALL(*wrapper, IOServiceMatching("AppleARMIODevice"))
    .WillOnce(Return(reinterpret_cast<CFMutableDictionaryRef>(1)));
    EXPECT_CALL(*wrapper, IOServiceGetMatchingServices(_, _, _))
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
    .WillOnce(Return(KERN_FAILURE));
    EXPECT_CALL(*wrapper, IOObjectRelease(_))
    .WillRepeatedly(Return(KERN_SUCCESS));

    double ret = -1.0;
    EXPECT_NO_THROW(ret = wrapper->cpuMhz());
    EXPECT_DOUBLE_EQ(ret, 0.0);
}

TEST_F(SysInfoHardwareWrapperARMMacTest, Test_CpuMhz_Failed_CFDictionaryGetValue)
{
    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    EXPECT_CALL(*wrapper, sysctlbyname("hw.cpufrequency", _, _, _, _))
    .WillOnce(Return(1));
    EXPECT_CALL(*wrapper, IOServiceMatching("AppleARMIODevice"))
    .WillOnce(Return(reinterpret_cast<CFMutableDictionaryRef>(1)));
    EXPECT_CALL(*wrapper, IOServiceGetMatchingServices(_, _, _))
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
    EXPECT_CALL(*wrapper, CFStringCreateWithCString(kCFAllocatorDefault, "voltage-states1-sram", kCFStringEncodingUTF8))
    .WillOnce(Return(reinterpret_cast<CFStringRef>(2)));
    EXPECT_CALL(*wrapper, CFDictionaryGetValue(_, _))
    .WillOnce(Return(nullptr))
    .WillOnce(Return(nullptr));
    EXPECT_CALL(*wrapper, IOObjectRelease(_))
    .WillRepeatedly(Return(KERN_SUCCESS));
    EXPECT_CALL(*wrapper, CFRelease(_)).Times(3);

    double ret = -1.0;
    EXPECT_NO_THROW(ret = wrapper->cpuMhz());
    EXPECT_DOUBLE_EQ(ret, 0.0);
}

TEST_F(SysInfoHardwareWrapperARMMacTest, Test_CpuMhz_Failed_CFGetTypeID)
{
    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    EXPECT_CALL(*wrapper, sysctlbyname("hw.cpufrequency", _, _, _, _))
    .WillOnce(Return(1));
    EXPECT_CALL(*wrapper, IOServiceMatching("AppleARMIODevice"))
    .WillOnce(Return(reinterpret_cast<CFMutableDictionaryRef>(1)));
    EXPECT_CALL(*wrapper, IOServiceGetMatchingServices(_, _, _))
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
    EXPECT_CALL(*wrapper, CFStringCreateWithCString(kCFAllocatorDefault, "voltage-states1-sram", kCFStringEncodingUTF8))
    .WillOnce(Return(reinterpret_cast<CFStringRef>(2)));
    EXPECT_CALL(*wrapper, CFDictionaryGetValue(_, _))
    .WillOnce(Return(reinterpret_cast<void*>(1)))
    .WillOnce(Return(nullptr));
    EXPECT_CALL(*wrapper, CFGetTypeID(_))
    .WillOnce(Return(2));
    EXPECT_CALL(*wrapper, CFDataGetTypeID())
    .WillOnce(Return(1));
    EXPECT_CALL(*wrapper, IOObjectRelease(_))
    .WillRepeatedly(Return(KERN_SUCCESS));
    EXPECT_CALL(*wrapper, CFRelease(_)).Times(3);

    double ret = -1.0;
    EXPECT_NO_THROW(ret = wrapper->cpuMhz());
    EXPECT_DOUBLE_EQ(ret, 0.0);
}

TEST_F(SysInfoHardwareWrapperARMMacTest, Test_CpuMhz_NoPmgrEntry)
{
    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    EXPECT_CALL(*wrapper, sysctlbyname("hw.cpufrequency", _, _, _, _))
    .WillOnce(Return(1));
    EXPECT_CALL(*wrapper, IOServiceMatching("AppleARMIODevice"))
    .WillOnce(Return(reinterpret_cast<CFMutableDictionaryRef>(1)));
    EXPECT_CALL(*wrapper, IOServiceGetMatchingServices(_, _, _))
    .WillOnce(Return(KERN_SUCCESS));
    EXPECT_CALL(*wrapper, IOIteratorNext(_))
    .WillOnce(Return(1))
    .WillOnce(Return(0));
    EXPECT_CALL(*wrapper, IORegistryEntryGetName(_, _))
    .WillOnce([](io_registry_entry_t entry, io_name_t name)
    {
        (void)entry;
        strncpy(name, "not-pmgr", sizeof(io_name_t));
        return KERN_SUCCESS;
    });
    EXPECT_CALL(*wrapper, IOObjectRelease(_))
    .WillRepeatedly(Return(KERN_SUCCESS));

    double ret = -1.0;
    EXPECT_NO_THROW(ret = wrapper->cpuMhz());
    EXPECT_DOUBLE_EQ(ret, 0.0);
}

TEST_F(SysInfoHardwareWrapperARMMacTest, Test_CpuMhz_EmptyIterator)
{
    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    EXPECT_CALL(*wrapper, sysctlbyname("hw.cpufrequency", _, _, _, _))
    .WillOnce(Return(1));
    EXPECT_CALL(*wrapper, IOServiceMatching("AppleARMIODevice"))
    .WillOnce(Return(reinterpret_cast<CFMutableDictionaryRef>(1)));
    EXPECT_CALL(*wrapper, IOServiceGetMatchingServices(_, _, _))
    .WillOnce(Return(KERN_SUCCESS));
    EXPECT_CALL(*wrapper, IOIteratorNext(_))
    .WillOnce(Return(0));
    EXPECT_CALL(*wrapper, IOObjectRelease(_))
    .WillRepeatedly(Return(KERN_SUCCESS));

    double ret = -1.0;
    EXPECT_NO_THROW(ret = wrapper->cpuMhz());
    EXPECT_DOUBLE_EQ(ret, 0.0);
}

TEST_F(SysInfoHardwareWrapperARMMacTest, Test_CpuMhz_SysctlFallbackSucceeds)
{
    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    EXPECT_CALL(*wrapper, sysctlbyname("hw.cpufrequency", _, _, _, _))
    .WillOnce([](const char*, void* oldp, size_t*, void*, size_t)
    {
        *reinterpret_cast<uint64_t*>(oldp) = 3200000000;
        return 0;
    });

    double ret = 0.0;
    EXPECT_NO_THROW(ret = wrapper->cpuMhz());
    EXPECT_DOUBLE_EQ(ret, (double)3200000000 / 1000000);
}

TEST_F(SysInfoHardwareWrapperARMMacTest, Test_CpuMhz_SecondKeySucceeds)
{
    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    EXPECT_CALL(*wrapper, sysctlbyname("hw.cpufrequency", _, _, _, _))
    .WillOnce(Return(1));
    EXPECT_CALL(*wrapper, IOServiceMatching("AppleARMIODevice"))
    .WillOnce(Return(reinterpret_cast<CFMutableDictionaryRef>(1)));
    EXPECT_CALL(*wrapper, IOServiceGetMatchingServices(_, _, _))
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
    EXPECT_CALL(*wrapper, CFStringCreateWithCString(kCFAllocatorDefault, "voltage-states1-sram", kCFStringEncodingUTF8))
    .WillOnce(Return(reinterpret_cast<CFStringRef>(2)));
    EXPECT_CALL(*wrapper, CFDictionaryGetValue(_, _))
    .WillOnce(Return(nullptr))
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
        *reinterpret_cast<uint32_t*>(buffer) = 2016000;
    });
    EXPECT_CALL(*wrapper, IOObjectRelease(_))
    .WillRepeatedly(Return(KERN_SUCCESS));
    EXPECT_CALL(*wrapper, CFRelease(_)).Times(3);

    double ret = 0.0;
    EXPECT_NO_THROW(ret = wrapper->cpuMhz());
    EXPECT_DOUBLE_EQ(ret, (double)2016000 / 1000000);
}

TEST_F(SysInfoHardwareWrapperARMMacTest, Test_CpuMhz_DegenerateKeyLengthZero)
{
    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    EXPECT_CALL(*wrapper, sysctlbyname("hw.cpufrequency", _, _, _, _))
    .WillOnce(Return(1));
    EXPECT_CALL(*wrapper, IOServiceMatching("AppleARMIODevice"))
    .WillOnce(Return(reinterpret_cast<CFMutableDictionaryRef>(1)));
    EXPECT_CALL(*wrapper, IOServiceGetMatchingServices(_, _, _))
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
    EXPECT_CALL(*wrapper, CFStringCreateWithCString(kCFAllocatorDefault, "voltage-states1-sram", kCFStringEncodingUTF8))
    .WillOnce(Return(reinterpret_cast<CFStringRef>(2)));
    EXPECT_CALL(*wrapper, CFDictionaryGetValue(_, _))
    .WillOnce(Return(reinterpret_cast<void*>(1)))
    .WillOnce(Return(nullptr));
    EXPECT_CALL(*wrapper, CFGetTypeID(_))
    .WillOnce(Return(1));
    EXPECT_CALL(*wrapper, CFDataGetTypeID())
    .WillOnce(Return(1));
    EXPECT_CALL(*wrapper, CFDataGetLength(_))
    .WillOnce(Return(0));
    // A degenerate length must not enter the byte-parsing loop: this is the
    // regression guard for the size_t underflow in `length - 3`.
    EXPECT_CALL(*wrapper, CFDataGetBytes(_, _, _)).Times(0);
    EXPECT_CALL(*wrapper, IOObjectRelease(_))
    .WillRepeatedly(Return(KERN_SUCCESS));
    EXPECT_CALL(*wrapper, CFRelease(_)).Times(3);

    double ret = -1.0;
    EXPECT_NO_THROW(ret = wrapper->cpuMhz());
    EXPECT_DOUBLE_EQ(ret, 0.0);
}

TEST_F(SysInfoHardwareWrapperARMMacTest, Test_CpuMhz_DegenerateKeyLengthTwo)
{
    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    EXPECT_CALL(*wrapper, sysctlbyname("hw.cpufrequency", _, _, _, _))
    .WillOnce(Return(1));
    EXPECT_CALL(*wrapper, IOServiceMatching("AppleARMIODevice"))
    .WillOnce(Return(reinterpret_cast<CFMutableDictionaryRef>(1)));
    EXPECT_CALL(*wrapper, IOServiceGetMatchingServices(_, _, _))
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
    EXPECT_CALL(*wrapper, CFStringCreateWithCString(kCFAllocatorDefault, "voltage-states1-sram", kCFStringEncodingUTF8))
    .WillOnce(Return(reinterpret_cast<CFStringRef>(2)));
    EXPECT_CALL(*wrapper, CFDictionaryGetValue(_, _))
    .WillOnce(Return(reinterpret_cast<void*>(1)))
    .WillOnce(Return(nullptr));
    EXPECT_CALL(*wrapper, CFGetTypeID(_))
    .WillOnce(Return(1));
    EXPECT_CALL(*wrapper, CFDataGetTypeID())
    .WillOnce(Return(1));
    EXPECT_CALL(*wrapper, CFDataGetLength(_))
    .WillOnce(Return(2));
    // Same regression guard as the length-zero case: length 2 also underflows
    // `length - 3` and must not enter the byte-parsing loop either.
    EXPECT_CALL(*wrapper, CFDataGetBytes(_, _, _)).Times(0);
    EXPECT_CALL(*wrapper, IOObjectRelease(_))
    .WillRepeatedly(Return(KERN_SUCCESS));
    EXPECT_CALL(*wrapper, CFRelease(_)).Times(3);

    double ret = -1.0;
    EXPECT_NO_THROW(ret = wrapper->cpuMhz());
    EXPECT_DOUBLE_EQ(ret, 0.0);
}

TEST_F(SysInfoHardwareWrapperARMMacTest, Test_CpuMhz_FirstKeyDegenerateSecondKeySucceeds)
{
    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    EXPECT_CALL(*wrapper, sysctlbyname("hw.cpufrequency", _, _, _, _))
    .WillOnce(Return(1));
    EXPECT_CALL(*wrapper, IOServiceMatching("AppleARMIODevice"))
    .WillOnce(Return(reinterpret_cast<CFMutableDictionaryRef>(1)));
    EXPECT_CALL(*wrapper, IOServiceGetMatchingServices(_, _, _))
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
    EXPECT_CALL(*wrapper, CFStringCreateWithCString(kCFAllocatorDefault, "voltage-states1-sram", kCFStringEncodingUTF8))
    .WillOnce(Return(reinterpret_cast<CFStringRef>(2)));
    // Key 1 exists and is CFData-typed, but is empty of samples: it must not be
    // treated as success, or the caller would never try key 2.
    EXPECT_CALL(*wrapper, CFDictionaryGetValue(_, _))
    .WillOnce(Return(reinterpret_cast<void*>(1)))
    .WillOnce(Return(reinterpret_cast<void*>(2)));
    EXPECT_CALL(*wrapper, CFGetTypeID(_))
    .WillOnce(Return(1))
    .WillOnce(Return(1));
    EXPECT_CALL(*wrapper, CFDataGetTypeID())
    .WillOnce(Return(1))
    .WillOnce(Return(1));
    EXPECT_CALL(*wrapper, CFDataGetLength(_))
    .WillOnce(Return(0))
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
        *reinterpret_cast<uint32_t*>(buffer) = 2400000;
    });
    EXPECT_CALL(*wrapper, IOObjectRelease(_))
    .WillRepeatedly(Return(KERN_SUCCESS));
    EXPECT_CALL(*wrapper, CFRelease(_)).Times(3);

    double ret = 0.0;
    EXPECT_NO_THROW(ret = wrapper->cpuMhz());
    EXPECT_DOUBLE_EQ(ret, (double)2400000 / 1000000);
}
