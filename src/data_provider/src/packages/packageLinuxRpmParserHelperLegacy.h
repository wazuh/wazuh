/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 * January 28, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PACKAGE_LINUX_RPM_PARSER_LEGACY_HELPER_H
#define _PACKAGE_LINUX_RPM_PARSER_LEGACY_HELPER_H

#include "sharedDefs.h"
#include "stringHelper.h"
#include "json.hpp"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"


namespace PackageLinuxHelper
{

    static nlohmann::json parseRpm(const std::string& packageInfo)
    {
        nlohmann::json ret;
        const auto fields { Utils::split(packageInfo, '\t') };
        constexpr auto DEFAULT_VALUE { "(none)" };

        if (RPMFields::RPM_FIELDS_SIZE <= fields.size())
        {
            std::string name             { fields.at(RPMFields::RPM_FIELDS_NAME) };

            if (name.compare("gpg-pubkey") != 0 && !name.empty())
            {
                std::string size         { fields.at(RPMFields::RPM_FIELDS_PACKAGE_SIZE) };
                std::string install_time { fields.at(RPMFields::RPM_FIELDS_INSTALLTIME) };
                std::string groups       { fields.at(RPMFields::RPM_FIELDS_GROUPS) };
                std::string version      { fields.at(RPMFields::RPM_FIELDS_VERSION) };
                std::string architecture { fields.at(RPMFields::RPM_FIELDS_ARCHITECTURE) };
                std::string vendor       { fields.at(RPMFields::RPM_FIELDS_VENDOR) };
                std::string description  { fields.at(RPMFields::RPM_FIELDS_SUMMARY) };

                std::string release      { fields.at(RPMFields::RPM_FIELDS_RELEASE) };
                std::string epoch        { fields.at(RPMFields::RPM_FIELDS_EPOCH) };

                if (!epoch.empty() && epoch.compare(DEFAULT_VALUE) != 0)
                {
                    version = epoch + ":" + version;
                }

                if (!release.empty() && release.compare(DEFAULT_VALUE) != 0)
                {
                    version += "-" + release;
                }

                ret["name"]         = name;
                ret["size"]         = size.empty() || size.compare(DEFAULT_VALUE) == 0 ? 0 : stoi(size);
                ret["install_time"] = install_time.empty() || install_time.compare(DEFAULT_VALUE) == 0 ? UNKNOWN_VALUE : install_time;
                ret["location"]     = UNKNOWN_VALUE;
                ret["groups"]       = groups.empty() || groups.compare(DEFAULT_VALUE) == 0 ? UNKNOWN_VALUE : groups;
                ret["version"]      = version.empty() || version.compare(DEFAULT_VALUE) == 0 ? UNKNOWN_VALUE : version;
                ret["priority"]     = UNKNOWN_VALUE;
                ret["architecture"] = architecture.empty() || architecture.compare(DEFAULT_VALUE) == 0 ? UNKNOWN_VALUE : architecture;
                ret["source"]       = UNKNOWN_VALUE;
                ret["format"]       = "rpm";
                ret["vendor"]       = vendor.empty() || vendor.compare(DEFAULT_VALUE) == 0 ? UNKNOWN_VALUE : vendor;
                ret["description"]  = description.empty() || description.compare(DEFAULT_VALUE) == 0 ? UNKNOWN_VALUE : description;
                // The multiarch field won't have a default value
            }
        }

        return ret;
    }

};

#pragma GCC diagnostic pop

#endif // _PACKAGE_LINUX_RPM_PARSER_LEGACY_HELPER_H
