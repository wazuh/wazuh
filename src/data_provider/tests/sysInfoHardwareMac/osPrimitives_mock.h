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

#ifndef _OS_PRIMITIVES_MOCK_H
#define _OS_PRIMITIVES_MOCK_H

#include "gtest/gtest.h"
#include "gmock/gmock.h"

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

#endif //_OS_PRIMITIVES_MOCK_H
