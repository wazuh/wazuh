/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * September 17, 2026.
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
#include "osPrimitivesInterfaceMac.h"

// Local to this test target on purpose: shared_modules/utils/osPrimitivesInterfaceMac.h
// bundles process, sysctl and IOKit/CoreFoundation primitives into a single interface,
// so any mock of it has to stub every method regardless of which one a given test
// exercises. sysInfoHardwareMac/osPrimitives_mock.h also (re)defines
// UtilsWrapperMac::exec for its own hardware-info tests; duplicating a trimmed mock
// here keeps this target's dependencies scoped to process listing.
class OsPrimitivesMacMock: public IOsPrimitivesMac
{
    public:
        OsPrimitivesMacMock() = default;
        virtual ~OsPrimitivesMacMock() = default;

        MOCK_METHOD(int, sysctl, (int* name, u_int namelen, void* oldp, size_t* oldlenp, void* newp, size_t newlen), (const override));
        MOCK_METHOD(int, sysctlbyname, (const char* name, void* oldp, size_t* oldlenp, void* newp, size_t newlen), (const override));
        MOCK_METHOD(int, proc_listallpids, (void* buffer, int buffersize), (const override));

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
