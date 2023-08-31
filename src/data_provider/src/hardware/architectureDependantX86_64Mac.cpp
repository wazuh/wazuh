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

double getMhz(IOsPrimitivesMac* osPrimitives)
{
    constexpr auto MHz{1000000};
    uint64_t cpuHz{0};
    size_t len{sizeof(cpuHz)};
    int ret{osPrimitives->sysctlbyname("hw.cpufrequency", &cpuHz, &len, nullptr, 0)};

    if (ret)
    {
        throw std::system_error
        {
            ret,
            std::system_category(),
            "Error reading cpu frequency."
        };
    }

    return static_cast<double>(cpuHz) / MHz;
}
