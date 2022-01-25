/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * November 3, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SYS_OS_INFO_WINDOWS_H
#define _SYS_OS_INFO_WINDOWS_H

#include "sysOsInfoInterface.h"

class SysOsInfoProviderWindows final : public ISysOsInfoProvider
{
    public:
        SysOsInfoProviderWindows();
        ~SysOsInfoProviderWindows() = default;
        std::string name() const override;
        std::string version() const override;
        std::string majorVersion() const override;
        std::string minorVersion() const override;
        std::string build() const override;
        std::string release() const override;
        std::string displayVersion() const override;
        std::string machine() const override;
        std::string nodeName() const override;
    private:
        const std::string m_majorVersion;
        const std::string m_minorVersion;
        const std::string m_build;
        const std::string m_buildRevision;
        const std::string m_version;
        const std::string m_release;
        const std::string m_displayVersion;
        const std::string m_name;
        const std::string m_machine;
        const std::string m_nodeName;
};




#endif //_SYS_OS_INFO_WINDOWS_H