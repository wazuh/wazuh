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

#ifndef _FACTORY_HARDWARE_FAMILY_CREATOR_H
#define _FACTORY_HARDWARE_FAMILY_CREATOR_H

#include <memory>
#include "json.hpp"
#include "hardwareInterface.h"
#include "hardwareWrapperInterface.h"
#include "hardwareImplMac.h"
#include "sharedDefs.h"

template <OSPlatformType osType>
class FactoryHardwareFamilyCreator final
{
    public:
        static std::shared_ptr<IOSHardware> create(const std::shared_ptr<IOSHardwareWrapper>& /*wrapperInterface*/)
        {
            throw std::runtime_error
            {
                "Error creating network data retriever."
            };
        }
};

template <>
class FactoryHardwareFamilyCreator<OSPlatformType::BSDBASED> final
{
    public:
        static std::shared_ptr<IOSHardware> create(const std::shared_ptr<IOSHardwareWrapper>& wrapperInterface)
        {
            return FactoryBSDHardware::create(wrapperInterface);
        }
};

#endif // _FACTORY_HARDWARE_FAMILY_CREATOR_H
