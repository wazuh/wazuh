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

#ifndef _PROCESS_INTERFACE_SOLARIS_H
#define _PROCESS_INTERFACE_SOLARIS_H

#include "iprocessInterface.h"
#include "iprocessWrapper.h"

class FactorySolarisProcess
{
    public:
        static std::shared_ptr<IOSProcess>create(const std::shared_ptr<IProcessInterfaceWrapper>& interfaceWrapper);
};

class SolarisProcessImpl final : public IOSProcess
{
        std::shared_ptr<IProcessInterfaceWrapper> m_processWrapper;
    public:
        explicit SolarisProcessImpl(const std::shared_ptr<IProcessInterfaceWrapper>& processWrapper)
            : m_processWrapper(processWrapper)
        { }
        // LCOV_EXCL_START
        ~SolarisProcessImpl() = default;
        // LCOV_EXCL_STOP

        void buildProcessData(nlohmann::json& process) override;
};

#endif // _PROCESS_INTERFACE_SOLARIS_H
