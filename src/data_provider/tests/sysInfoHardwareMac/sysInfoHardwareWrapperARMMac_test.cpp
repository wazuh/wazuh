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
    EXPECT_CALL(*wrapper, IOServiceMatching("AppleARMIODevice"))
    .WillOnce(Return(nullptr));

    EXPECT_THROW(wrapper->cpuMhz(), std::system_error);
}

TEST_F(SysInfoHardwareWrapperARMMacTest, Test_CpuMhz_Failed_IOServiceGetMatchingServices)
{
    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    EXPECT_CALL(*wrapper, IOServiceMatching("AppleARMIODevice"))
    .WillOnce(Return(reinterpret_cast<CFMutableDictionaryRef>(1)));
    EXPECT_CALL(*wrapper, IOServiceGetMatchingServices(_, _, _))
    .WillOnce(Return(KERN_FAILURE));

    EXPECT_THROW(wrapper->cpuMhz(), std::system_error);
}

TEST_F(SysInfoHardwareWrapperARMMacTest, Test_CpuMhz_Failed_IORegistryEntryCreateCFProperties)
{
    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    EXPECT_CALL(*wrapper, IOServiceMatching("AppleARMIODevice"))
    .WillOnce(Return(reinterpret_cast<CFMutableDictionaryRef>(1)));
    EXPECT_CALL(*wrapper, IOServiceGetMatchingServices(_, _, _))
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

    EXPECT_THROW(wrapper->cpuMhz(), std::system_error);
}

TEST_F(SysInfoHardwareWrapperARMMacTest, Test_CpuMhz_Failed_CFDictionaryGetValue)
{
    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    EXPECT_CALL(*wrapper, IOServiceMatching("AppleARMIODevice"))
    .WillOnce(Return(reinterpret_cast<CFMutableDictionaryRef>(1)));
    EXPECT_CALL(*wrapper, IOServiceGetMatchingServices(_, _, _))
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

    EXPECT_THROW(wrapper->cpuMhz(), std::system_error);
}

TEST_F(SysInfoHardwareWrapperARMMacTest, Test_CpuMhz_Failed_CFGetTypeID)
{
    auto wrapper { std::make_shared<OSHardwareWrapperMac<OsPrimitivesMacMock>>() };
    EXPECT_CALL(*wrapper, IOServiceMatching("AppleARMIODevice"))
    .WillOnce(Return(reinterpret_cast<CFMutableDictionaryRef>(1)));
    EXPECT_CALL(*wrapper, IOServiceGetMatchingServices(_, _, _))
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

    EXPECT_THROW(wrapper->cpuMhz(), std::system_error);
}
