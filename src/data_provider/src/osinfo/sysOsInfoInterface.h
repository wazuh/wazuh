/*
 * Wazuh SysInfo
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SYS_OS_INFO_INTERFACE_H
#define _SYS_OS_INFO_INTERFACE_H

#include <string>
#include <memory>
#include "json.hpp"
#include "stringHelper.h"

class ISysOsInfoProvider
{
    public:
        // LCOV_EXCL_START
        virtual ~ISysOsInfoProvider() = default;
        virtual std::string name() const = 0;
        virtual std::string version() const = 0;
        virtual std::string majorVersion() const = 0;
        virtual std::string minorVersion() const = 0;
        virtual std::string build() const = 0;
        virtual std::string release() const = 0;
        virtual std::string displayVersion() const = 0;
        virtual std::string machine() const = 0;
        virtual std::string nodeName() const = 0;
        // LCOV_EXCL_STOP
};


class SysOsInfo
{
    public:
        SysOsInfo() =  default;
        ~SysOsInfo() = default;
        static void setOsInfo(const std::shared_ptr<ISysOsInfoProvider>& osInfoProvider,
                              nlohmann::json& output)
        {
            const auto version = osInfoProvider->version();
            const auto name = osInfoProvider->name();
            // DisplayVersion (20H2 onwards) wins over the release, because ReleaseId stays frozen at
            // 2009 since 20H2. The release covers the older versions: ReleaseId, the build table or
            // the service pack.
            auto displayVersion = osInfoProvider->displayVersion();

            if (displayVersion.empty())
            {
                displayVersion = Utils::trim(osInfoProvider->release());
            }

            // Trimmed like setOsFull() does on the other platforms.
            const auto fullName = Utils::trim(name);

            output["os_name"] = name;
            output["os_major"] = osInfoProvider->majorVersion();
            output["os_minor"] = osInfoProvider->minorVersion();
            output["os_build"] = osInfoProvider->build();
            output["os_version"] = version;
            output["hostname"] = osInfoProvider->nodeName();
            output["os_display_version"] = displayVersion;
            output["os_full"] = displayVersion.empty() ? fullName : fullName + " " + displayVersion;
            output["os_kernel_release"] = version;
            output["architecture"] = osInfoProvider->machine();
            output["os_platform"] = "windows";
        }
};

#endif //_SYS_OS_INFO_INTERFACE_H
