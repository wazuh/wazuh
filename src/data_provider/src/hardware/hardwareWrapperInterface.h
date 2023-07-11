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

#ifndef _HARDWARE_WRAPPER_INTERFACE_H
#define _HARDWARE_WRAPPER_INTERFACE_H

#include <cstdint>
#include <string>

class IOSHardwareWrapper
{
    public:
        // LCOV_EXCL_START
        virtual ~IOSHardwareWrapper() = default;
        // LCOV_EXCL_STOP

        virtual std::string boardSerial() const = 0;
        virtual std::string cpuName() const = 0;
        virtual int cpuCores() const = 0;
        virtual double cpuMhz() = 0;
        virtual uint64_t ramTotal() const = 0;
        virtual uint64_t ramFree() const = 0;
        virtual uint64_t ramUsage() const = 0;
};
#endif // _HARDWARE_WRAPPER_INTERFACE_H
