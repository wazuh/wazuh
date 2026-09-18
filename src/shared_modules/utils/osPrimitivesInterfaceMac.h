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

#ifndef _OSPRIMITIVES_INTERFACE_MAC_H
#define _OSPRIMITIVES_INTERFACE_MAC_H

#include "IOKit/IOKitLib.h"
#include "CoreFoundation/CFBase.h"
#include "mach/mach.h"
#include "mach/mach_host.h"

class IOsPrimitivesMac
{
    public:
        // LCOV_EXCL_START
        virtual ~IOsPrimitivesMac() = default;
        // LCOV_EXCL_STOP

        virtual int sysctl(int* name, u_int namelen, void* oldp, size_t* oldlenp, void* newp, size_t newlen) const = 0;
        virtual int sysctlbyname(const char* name, void* oldp, size_t* oldlenp, void* newp, size_t newlen) const = 0;
        virtual int proc_listallpids(void* buffer, int buffersize) const = 0;

        virtual kern_return_t host_statistics64(host_t hostPriv, host_flavor_t flavor, host_info64_t hostInfo64Out, mach_msg_type_number_t* hostInfo64OutCnt) const = 0;
        virtual mach_port_t mach_host_self() const = 0;
        virtual kern_return_t mach_port_deallocate(ipc_space_t task, mach_port_name_t name) const = 0;

        virtual CFMutableDictionaryRef IOServiceMatching(const char* name) const = 0;
        virtual kern_return_t IOServiceGetMatchingServices(mach_port_t mainPort, CFDictionaryRef matching, io_iterator_t* existing) const = 0;
        virtual io_object_t IOIteratorNext(io_iterator_t iterator) const = 0;
        virtual kern_return_t IORegistryEntryGetName(io_registry_entry_t entry, io_name_t name) const = 0;
        virtual kern_return_t IORegistryEntryCreateCFProperties(io_registry_entry_t entry, CFMutableDictionaryRef* properties, CFAllocatorRef allocator, IOOptionBits options) const = 0;
        virtual kern_return_t IOObjectRelease(io_object_t object) const = 0;

        virtual CFStringRef CFStringCreateWithCString(CFAllocatorRef alloc, const char* cStr, CFStringEncoding encoding) const = 0;
        virtual const void* CFDictionaryGetValue(CFDictionaryRef theDict, const void* key) const = 0;
        virtual CFTypeID CFGetTypeID(CFTypeRef cf) const = 0;
        virtual CFTypeID CFDataGetTypeID(void) const = 0;
        virtual CFIndex CFDataGetLength(CFDataRef theData) const = 0;
        virtual void CFDataGetBytes(CFDataRef theData, CFRange range, UInt8* buffer) const = 0;
        virtual CFRange CFRangeMake(CFIndex loc, CFIndex len) const = 0;
        virtual void CFRelease(CFTypeRef cf) const = 0;
};

#endif // _OSPRIMITIVES_INTERFACE_MAC_H
