/*
 * Wazuh SYSINFO
 * Copyright (C) 2015-2021, Wazuh Inc.
 * January 12, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SOLARIS_WRAPPER_H
#define _SOLARIS_WRAPPER_H

#include <fstream>
#include <map>
#include <regex>

#include "ipackageWrapper.h"
#include "sharedDefs.h"
#include "stringHelper.h"

constexpr auto NAME_FILE_INFO   { "pkginfo" };
constexpr auto EMPTY_VALUE      { "" };
constexpr auto NAME_FIELD       { "PKG" };
constexpr auto ARCH_FIELD       { "ARCH" };
constexpr auto VERSION_FIELD    { "VERSION" };
constexpr auto GROUPS_FIELD     { "CATEGORY" };
constexpr auto DESC_FIELD       { "NAME" };
constexpr auto LOCATION_FIELD   { "SUNW_PKG_DIR" };
constexpr auto VENDOR_FIELD     { "VENDOR" };
constexpr auto INSTALL_TIME_FIELD { "INSTDATE" };

static const std::map<std::string, std::string> MONTH =
{
    {"Jan", "01"},
    {"Feb", "02"},
    {"Mar", "03"},
    {"Apr", "04"},
    {"May", "05"},
    {"Jun", "06"},
    {"Jul", "07"},
    {"Aug", "08"},
    {"Sep", "09"},
    {"Oct", "10"},
    {"Nov", "11"},
    {"Dec", "12"}
};

class SolarisWrapper final : public IPackageWrapper
{
    public:
        SolarisWrapper(const std::string& pkgDirectory)
            : m_format{"pkg"}
        {
            getPkgData(pkgDirectory);
        }

        ~SolarisWrapper() = default;


        std::string name() const override
        {
            std::string name;
            auto it {m_data.find(NAME_FIELD)};

            if (it != m_data.end())
            {
                constexpr auto VENDOR_NAME_PKG_PATTERN  { "^[A-Z+-]{1,4}" };
                std::regex namePkgRegex { VENDOR_NAME_PKG_PATTERN };
                std::smatch match;
                name = it->second;

                if (std::regex_search(name, match, namePkgRegex))
                {
                    name = match.suffix();
                }
            }

            return name;
        }

        std::string version() const override
        {
            std::string version;
            auto it {m_data.find(VERSION_FIELD)};

            if (it != m_data.end())
            {
                version = it->second;
                const auto fields { Utils::split(version, ',') };

                if (fields.size() > 1)
                {
                    version = fields.at(0);
                }
            }

            return version;
        }

        std::string groups() const override
        {
            auto it {m_data.find(GROUPS_FIELD)};

            return it != m_data.end() ? it->second : EMPTY_VALUE;
        }

        std::string description() const override
        {
            auto it {m_data.find(DESC_FIELD)};

            return it != m_data.end() ? it->second : EMPTY_VALUE;
        }

        std::string architecture() const override
        {
            auto it {m_data.find(ARCH_FIELD)};

            return it != m_data.end() ? it->second : EMPTY_VALUE;
        }

        std::string format() const override
        {
            return m_format;
        }

        std::string osPatch() const override
        {
            return UNKNOWN_VALUE;
        }

        std::string source() const override
        {
            return UNKNOWN_VALUE;
        }

        std::string location() const override
        {
            auto it {m_data.find(LOCATION_FIELD)};

            return it != m_data.end() ? it->second : EMPTY_VALUE;
        }

        std::string priority() const override
        {
            return EMPTY_VALUE;
        }

        int size() const override
        {
            return 0;
        }

        std::string vendor() const override
        {
            auto it {m_data.find(VENDOR_FIELD)};

            return it != m_data.end() ? it->second : EMPTY_VALUE;
        }

        std::string install_time() const override
        {
            std::stringstream installTime;
            auto it { m_data.find(INSTALL_TIME_FIELD) };

            if (it != m_data.end())
            {
                // Date format is Oct 06 2015 08:51
                const  auto fields { Utils::split(it->second, ' ') };

                try
                {
                    if (fields.size() >= 4)
                    {
                        installTime << std::setw(4) << std::setfill('0') << fields[2];                  // Year
                        installTime << '/' << std::setw(2) << std::setfill('0') << MONTH.at(fields[0]); // Month
                        installTime << '/' << std::setw(2) << std::setfill('0') << fields[1];           // Day
                        installTime << ' ' << fields[3] << ":00";                                       // Time
                    }
                }
                catch (...)
                {
                }
            }

            return installTime.str();
        }

        std::string multiarch() const override
        {
            return EMPTY_VALUE;
        }

    private:
        std::string m_format;
        std::map<std::string, std::string> m_data;

        void getPkgData(const std::string& pkgDirectory)
        {
            std::fstream file { pkgDirectory + "/" + NAME_FILE_INFO, std::ios_base::in };

            if (file.is_open())
            {
                std::string line;

                while (file.good())
                {
                    std::getline(file, line);
                    const auto fields { Utils::split(line, '=') };

                    if (fields.size() > 1)
                    {
                        m_data[fields.at(0)] = fields.at(1);
                    }

                }
            }
        }
};

#endif // _SOLARIS_WRAPPER_H
