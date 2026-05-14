/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
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
constexpr auto NAME_FIELD       { "PKG" };
constexpr auto ARCH_FIELD       { "ARCH" };
constexpr auto VERSION_FIELD    { "VERSION" };
constexpr auto GROUPS_FIELD     { "CATEGORY" };
constexpr auto DESC_FIELD       { "NAME" };
constexpr auto LOCATION_FIELD   { "SUNW_PKG_DIR" };
constexpr auto VENDOR_FIELD     { "VENDOR" };
constexpr auto INSTALL_TIME_FIELD { "INSTDATE" };

// Date format is Oct 06 2015 08:51
enum DateFormat
{
    MONTH_INDEX,
    DAY_INDEX,
    YEAR_INDEX,
    TIME_INDEX,
    DATE_FORMAT_SIZE
};

// VERSION=1.2.3,REVISION=1234
enum VersionFields
{
    VERSION_VALUE_INDEX,
    REVISION_KEY_VALUE_INDEX
};

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
                    version = fields.at(VERSION_VALUE_INDEX);
                }
            }

            return version;
        }

        std::string groups() const override
        {
            auto it {m_data.find(GROUPS_FIELD)};

            return it != m_data.end() ? it->second : UNKNOWN_VALUE;
        }

        std::string description() const override
        {
            auto it {m_data.find(DESC_FIELD)};

            return it != m_data.end() ? it->second : UNKNOWN_VALUE;
        }

        std::string architecture() const override
        {
            auto it {m_data.find(ARCH_FIELD)};

            return it != m_data.end() ? it->second : UNKNOWN_VALUE;
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
            std::string retVal {UNKNOWN_VALUE};
            auto it {m_data.find(LOCATION_FIELD)};

            if (it != m_data.end() && !it->second.empty())
            {
                retVal = it->second;
            }

            return retVal;
        }

        std::string priority() const override
        {
            return UNKNOWN_VALUE;
        }

        int64_t size() const override
        {
            return 0;
        }

        std::string vendor() const override
        {
            auto it {m_data.find(VENDOR_FIELD)};

            return it != m_data.end() ? it->second : UNKNOWN_VALUE;
        }

        std::string install_time() const override
        {
            std::stringstream installTime;
            auto it { m_data.find(INSTALL_TIME_FIELD) };

            if (it != m_data.end())
            {
                const  auto fields { Utils::split(it->second, ' ') };

                try
                {
                    installTime << std::setw(4) << std::setfill('0') << fields.at(YEAR_INDEX);
                    installTime << '/' << std::setw(2) << std::setfill('0') << MONTH.at(fields.at(MONTH_INDEX));
                    installTime << '/' << std::setw(2) << std::setfill('0') << fields.at(DAY_INDEX);
                    installTime << ' ' << fields.at(TIME_INDEX) << ":00";
                }
                catch (...)
                {
                }
            }

            return installTime.str();
        }

        std::string multiarch() const override
        {
            return std::string();
        }

    private:
        std::string m_format;
        std::map<std::string, std::string> m_data;

        void getPkgData(const std::string& pkgDirectory)
        {
            std::fstream file { pkgDirectory + "/" + NAME_FILE_INFO, std::ios_base::in };
            constexpr auto KEY { 0 };
            constexpr auto VALUE { 1 };

            if (file.is_open())
            {
                std::string line;

                while (file.good())
                {
                    std::getline(file, line);
                    // Convert 'line' to UTF-8
                    Utils::ISO8859ToUTF8(line);
                    const auto fields { Utils::split(line, '=') };

                    if (fields.size() > 1)
                    {
                        m_data[fields.at(KEY)] = fields.at(VALUE);
                    }

                }
            }
        }
};

#endif // _SOLARIS_WRAPPER_H
