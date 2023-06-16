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

double getMhz(IOsPrimitivesMac* osPrimitives)
{
    constexpr auto MHz{1000000};
    uint64_t cpuHz = 0;

    auto matching = osPrimitives->IOServiceMatching("AppleARMIODevice");

    if (matching == nullptr)
    {
        throw std::system_error
        {
            0,
            std::system_category(),
            "Error on library function call IOServiceMatching."
        };
    }

    io_iterator_t device_it = 0;
    auto kr = osPrimitives->IOServiceGetMatchingServices(kIOMainPortDefault, matching, &device_it);

    if (kr != KERN_SUCCESS)
    {
        throw std::system_error
        {
            kr,
            std::system_category(),
            "Error on library function call IOServiceGetMatchingServices."
        };
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
            throw std::system_error
            {
                kr,
                std::system_category(),
                "Error on library function call IORegistryEntryCreateCFProperties."
            };
        }

        DEFER([osPrimitives, properties]()
        {
            osPrimitives->CFRelease(properties);
        });

        // voltage-states5-sram contains the performance cores available frequencies
        CFStringRef cfkey = osPrimitives->CFStringCreateWithCString(kCFAllocatorDefault, "voltage-states5-sram", kCFStringEncodingUTF8);
        DEFER([osPrimitives, cfkey]()
        {
            osPrimitives->CFRelease(cfkey);
        });

        auto p_cores_freq_property = static_cast<CFDataRef>(osPrimitives->CFDictionaryGetValue(properties, cfkey));

        if (p_cores_freq_property == nullptr)
        {
            throw std::system_error
            {
                0,
                std::system_category(),
                "Error on library function call CFDictionaryGetValue."
            };
        }

        auto p_cores_freq_type = osPrimitives->CFGetTypeID(p_cores_freq_property);

        if (p_cores_freq_type != osPrimitives->CFDataGetTypeID())
        {
            throw std::system_error
            {
                0,
                std::system_category(),
                "CF type id of p_cores_freq_property is not Data type id."
            };
        }

        size_t length = osPrimitives->CFDataGetLength(p_cores_freq_property);

        // The frequencies are in hz, saved in an array as little endian 4 byte integers
        for (size_t i = 0; i < length - 3; i += sizeof(uint32_t))
        {
            uint32_t cur_freq = 0;
            osPrimitives->CFDataGetBytes(p_cores_freq_property, osPrimitives->CFRangeMake(i, sizeof(uint32_t)), reinterpret_cast<UInt8*>(&cur_freq));
            cpuHz = std::max(cpuHz, static_cast<uint64_t>(cur_freq));
        }
    }

    return static_cast<double>(cpuHz) / MHz;
}
