/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 * March 9, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PROCESS_FAMILY_DATA_AFACTORY_H
#define _PROCESS_FAMILY_DATA_AFACTORY_H

#include "processInterfaceSolaris.h"
#include "sharedDefs.h"

template <OSType osType>
class FactoryProcessFamilyCreator final
{
    public:
        static std::shared_ptr<IOSProcess> create(const std::shared_ptr<IProcessInterfaceWrapper>& /*interface*/)
        {
            throw std::runtime_error
            {
                "Error creating process data retriever."
            };
        }
};

template <>
class FactoryProcessFamilyCreator<OSType::SOLARIS> final
{
    public:
        static std::shared_ptr<IOSProcess> create(const std::shared_ptr<IProcessInterfaceWrapper>& interfaceWrapper)
        {
            return FactorySolarisProcess::create(interfaceWrapper);
        }
};

#endif // _PROCESS_FAMILY_DATA_AFACTORY_H
