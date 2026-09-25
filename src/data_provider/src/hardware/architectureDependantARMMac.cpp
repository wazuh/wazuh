/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 * May 4, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "hardwareWrapperImplMac.h"

#if (MAC_OS_X_VERSION_MAX_ALLOWED < 120000)
#define kIOMainPortDefault kIOMasterPortDefault
#endif

namespace
{
    constexpr const char* CPU_FREQ_KEYS[] = {"voltage-states5-sram", "voltage-states1-sram"};

    bool readMaxFrequency(IOsPrimitivesMac* osPrimitives, CFMutableDictionaryRef properties, const char* keyName, uint64_t& cpuHz)
    {
        CFStringRef cfkey = osPrimitives->CFStringCreateWithCString(kCFAllocatorDefault, keyName, kCFStringEncodingUTF8);
        DEFER([osPrimitives, cfkey]()
        {
            osPrimitives->CFRelease(cfkey);
        });

        auto p_cores_freq_property = static_cast<CFDataRef>(osPrimitives->CFDictionaryGetValue(properties, cfkey));

        if (p_cores_freq_property == nullptr)
        {
            return false;
        }

        auto p_cores_freq_type = osPrimitives->CFGetTypeID(p_cores_freq_property);

        if (p_cores_freq_type != osPrimitives->CFDataGetTypeID())
        {
            return false;
        }

        size_t length = osPrimitives->CFDataGetLength(p_cores_freq_property);
        uint64_t maxFreq = 0;

        // The frequencies are in hz, saved in an array as little endian 4 byte integers
        for (size_t i = 0; i + sizeof(uint32_t) <= length; i += sizeof(uint32_t))
        {
            uint32_t cur_freq = 0;
            osPrimitives->CFDataGetBytes(p_cores_freq_property, osPrimitives->CFRangeMake(i, sizeof(uint32_t)), reinterpret_cast<UInt8*>(&cur_freq));
            maxFreq = std::max(maxFreq, static_cast<uint64_t>(cur_freq));
        }

        if (maxFreq == 0)
        {
            return false;
        }

        cpuHz = maxFreq;
        return true;
    }
}

double getMhz(IOsPrimitivesMac* osPrimitives)
{
    constexpr auto MHz{1000000};
    uint64_t cpuHz = 0;

    size_t sysctlLen{sizeof(cpuHz)};
    int sysctlRet{osPrimitives->sysctlbyname("hw.cpufrequency", &cpuHz, &sysctlLen, nullptr, 0)};

    if (sysctlRet == 0 && cpuHz != 0)
    {
        return static_cast<double>(cpuHz) / MHz;
    }

    cpuHz = 0;

    auto matching = osPrimitives->IOServiceMatching("AppleARMIODevice");

    if (matching == nullptr)
    {
        return static_cast<double>(cpuHz) / MHz;
    }

    io_iterator_t device_it = 0;
    auto kr = osPrimitives->IOServiceGetMatchingServices(kIOMainPortDefault, matching, &device_it);

    if (kr != KERN_SUCCESS)
    {
        return static_cast<double>(cpuHz) / MHz;
    }

    DEFER([osPrimitives, device_it]()
    {
        osPrimitives->IOObjectRelease(device_it);
    });

    io_object_t device = 0;

    while ((device = osPrimitives->IOIteratorNext(device_it)))
    {
        DEFER([osPrimitives, device]()
        {
            osPrimitives->IOObjectRelease(device);
        });

        io_name_t buf;
        kr = osPrimitives->IORegistryEntryGetName(device, buf);

        if (kr != KERN_SUCCESS)
        {
            continue;
        }

        std::string name(buf);

        if (name.compare("pmgr"))
        {
            continue;
        }

        CFMutableDictionaryRef properties;
        kr = osPrimitives->IORegistryEntryCreateCFProperties(device, &properties, kCFAllocatorDefault, kNilOptions);

        if (kr != KERN_SUCCESS)
        {
            continue;
        }

        DEFER([osPrimitives, properties]()
        {
            osPrimitives->CFRelease(properties);
        });

        for (const auto& keyName : CPU_FREQ_KEYS)
        {
            if (readMaxFrequency(osPrimitives, properties, keyName, cpuHz))
            {
                break;
            }
        }
    }

    return static_cast<double>(cpuHz) / MHz;
}
