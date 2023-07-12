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

#ifndef _HARDWARE_IMPL_MAC_H
#define _HARDWARE_IMPL_MAC_H

#include "hardwareInterface.h"
#include "hardwareWrapperInterface.h"

class OSHardwareMac final : public IOSHardware
{
        std::shared_ptr<IOSHardwareWrapper> m_wrapper;
    public:
        explicit OSHardwareMac(const std::shared_ptr<IOSHardwareWrapper>& wrapper)
            : m_wrapper(wrapper)
        { }
        // LCOV_EXCL_START
        ~OSHardwareMac() = default;
        // LCOV_EXCL_STOP

        void buildHardwareData(nlohmann::json& hardware) override
        {
            hardware["board_serial"] = m_wrapper->boardSerial();
            hardware["cpu_name"] = m_wrapper->cpuName();
            hardware["cpu_cores"] = m_wrapper->cpuCores();
            hardware["cpu_mhz"] = m_wrapper->cpuMhz();
            hardware["ram_total"] = m_wrapper->ramTotal();
            hardware["ram_free"] = m_wrapper->ramFree();
            hardware["ram_usage"] = m_wrapper->ramUsage();
        }
};

class FactoryBSDHardware final
{
    public:
        static std::shared_ptr<IOSHardware>create(const std::shared_ptr<IOSHardwareWrapper>& wrapper)
        {
            return std::make_shared<OSHardwareMac>(wrapper);
        }
};

#endif // _HARDWARE_IMPL_MAC_H
