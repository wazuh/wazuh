/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 * February 06, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _MACPORTS_WRAPPER_H
#define _MACPORTS_WRAPPER_H

#include "ipackageWrapper.h"
#include "sqliteWrapperTemp.h"
#include "sharedDefs.h"

const std::map<std::string, int> columnIndexes
{
    {"name", 0},
    {"version", 1},
    {"date", 2},
    {"location", 3},
    {"archs", 4}
};

#define DATE_STR_SIZE 20

class MacportsWrapper final : public IPackageWrapper
{
    public:
        explicit MacportsWrapper(SQLite::IStatement& stmt)
            : m_version{UNKNOWN_VALUE}
            , m_groups {UNKNOWN_VALUE}
            , m_description {UNKNOWN_VALUE}
            , m_architecture{UNKNOWN_VALUE}
            , m_format{"macports"}
            , m_osPatch {UNKNOWN_VALUE}
            , m_source{UNKNOWN_VALUE}
            , m_location{UNKNOWN_VALUE}
            , m_priority{UNKNOWN_VALUE}
            , m_size{0}
            , m_vendor{UNKNOWN_VALUE}
            , m_installTime{UNKNOWN_VALUE}
        {
            getPkgData(stmt);
        }

        ~MacportsWrapper() = default;

        std::string name() const override
        {
            return m_name;
        }
        std::string version() const override
        {
            return m_version;
        }
        std::string groups() const override
        {
            return m_groups;
        }
        std::string description() const override
        {
            return m_description;
        }
        std::string architecture() const override
        {
            return m_architecture;
        }
        std::string format() const override
        {
            return m_format;
        }
        std::string osPatch() const override
        {
            return m_osPatch;
        }
        std::string source() const override
        {
            return m_source;
        }
        std::string location() const override
        {
            return m_location;
        }
        std::string vendor() const override
        {
            return m_vendor;
        }

        std::string priority() const override
        {
            return m_priority;
        }

        int size() const override
        {
            return m_size;
        }

        std::string install_time() const override
        {
            return m_installTime;
        }

        std::string multiarch() const override
        {
            return m_multiarch;
        }
    private:
        void getPkgData(SQLite::IStatement& stmt)
        {
            const int& columnsNumber = columnIndexes.size();

            if (stmt.columnsCount() == columnsNumber)
            {
                const auto& name {stmt.column(columnIndexes.at("name"))};
                const auto& version {stmt.column(columnIndexes.at("version"))};
                const auto& date {stmt.column(columnIndexes.at("date"))};
                const auto& location {stmt.column(columnIndexes.at("location"))};
                const auto& archs {stmt.column(columnIndexes.at("archs"))};

                if (name->hasValue())
                {
                    m_name = name->value(std::string {});
                }

                if (version->hasValue())
                {
                    const auto versionStr = version->value(std::string{});

                    if (!versionStr.empty())
                    {
                        m_version = versionStr;
                    }
                }

                if (date->hasValue())
                {
                    char formattedTime[DATE_STR_SIZE] {0};
                    const long epochTime = date->value(std::int64_t {});
                    std::strftime(formattedTime, sizeof(formattedTime), "%Y/%m/%d %H:%M:%S", std::localtime(&epochTime));
                    m_installTime = formattedTime;
                }

                if (location->hasValue())
                {
                    const auto locationStr = location->value(std::string {});

                    if (!locationStr.empty())
                    {
                        m_location = locationStr;
                    }
                }

                if (archs->hasValue())
                {
                    const auto archsStr = archs->value(std::string {});

                    if (!archsStr.empty())
                    {
                        m_architecture = archsStr;
                    }
                }
            }
        }

        std::string m_name;
        std::string m_version;
        std::string m_groups;
        std::string m_description;
        std::string m_architecture;
        const std::string m_format;
        std::string m_osPatch;
        std::string m_source;
        std::string m_location;
        std::string m_multiarch;
        std::string m_priority;
        int m_size;
        std::string m_vendor;
        std::string m_installTime;
};

# endif // _MACPORTS_WRAPPER_H
