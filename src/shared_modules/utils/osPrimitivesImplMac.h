/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 * May 11, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _OSPRIMITIVES_IMPL_MAC_H
#define _OSPRIMITIVES_IMPL_MAC_H

#include "osPrimitivesInterfaceMac.h"

class OsPrimitivesMac : public IOsPrimitivesMac
{
public:
    OsPrimitivesMac() = default;
    // LCOV_EXCL_START
    virtual ~OsPrimitivesMac() = default;
    // LCOV_EXCL_STOP

    int sysctl(int* name, u_int namelen, void* oldp, size_t* oldlenp, void* newp, size_t newlen) const
    {
        return ::sysctl(name, namelen, oldp, oldlenp, newp, newlen);
    }

    int sysctlbyname(const char* name, void* oldp, size_t* oldlenp, void* newp, size_t newlen) const
    {
        return ::sysctlbyname(name, oldp, oldlenp, newp, newlen);
    }

    CFMutableDictionaryRef IOServiceMatching(const char* name) const
    {
        return ::IOServiceMatching(name);
    }

    kern_return_t
    IOServiceGetMatchingServices(mach_port_t mainPort, CFDictionaryRef matching, io_iterator_t* existing) const
    {
        return ::IOServiceGetMatchingServices(mainPort, matching, existing);
    }

    io_object_t IOIteratorNext(io_iterator_t iterator) const
    {
        return ::IOIteratorNext(iterator);
    }

    kern_return_t IORegistryEntryGetName(io_registry_entry_t entry, io_name_t name) const
    {
        return ::IORegistryEntryGetName(entry, name);
    }

    kern_return_t IORegistryEntryCreateCFProperties(io_registry_entry_t entry,
                                                    CFMutableDictionaryRef* properties,
                                                    CFAllocatorRef allocator,
                                                    IOOptionBits options) const
    {
        return ::IORegistryEntryCreateCFProperties(entry, properties, allocator, options);
    }

    kern_return_t IOObjectRelease(io_object_t object) const
    {
        return ::IOObjectRelease(object);
    }

    CFStringRef CFStringCreateWithCString(CFAllocatorRef alloc, const char* cStr, CFStringEncoding encoding) const
    {
        return ::CFStringCreateWithCString(alloc, cStr, encoding);
    }

    const void* CFDictionaryGetValue(CFDictionaryRef theDict, const void* key) const
    {
        return ::CFDictionaryGetValue(theDict, key);
    }

    CFTypeID CFGetTypeID(CFTypeRef cf) const
    {
        return ::CFGetTypeID(cf);
    }

    CFTypeID CFDataGetTypeID(void) const
    {
        return ::CFDataGetTypeID();
    }

    CFIndex CFDataGetLength(CFDataRef theData) const
    {
        return ::CFDataGetLength(theData);
    }

    void CFDataGetBytes(CFDataRef theData, CFRange range, UInt8* buffer) const
    {
        return ::CFDataGetBytes(theData, range, buffer);
    }

    CFRange CFRangeMake(CFIndex loc, CFIndex len) const
    {
        return ::CFRangeMake(loc, len);
    }

    void CFRelease(CFTypeRef cf) const
    {
        ::CFRelease(cf);
    }
};

#endif // _OSPRIMITIVES_IMPL_MAC_H
