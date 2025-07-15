/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 * December 14, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _BREW_WRAPPER_H
#define _BREW_WRAPPER_H

#include "ipackageWrapper.h"
#include "sharedDefs.h"
#include "stringHelper.h"
#include <file_io_utils.hpp>

class BrewWrapper final : public IPackageWrapper
{
    public:
        explicit BrewWrapper(const PackageContext& ctx)
            : m_name{ctx.package}
            , m_version{Utils::splitIndex(ctx.version, '_', 0)}
            , m_groups{UNKNOWN_VALUE}
            , m_description {UNKNOWN_VALUE}
            , m_architecture{UNKNOWN_VALUE}
            , m_format{"pkg"}
            , m_source{"homebrew"}
            , m_location{ctx.filePath}
            , m_priority{UNKNOWN_VALUE}
            , m_size{0}
            , m_vendor{UNKNOWN_VALUE}
            , m_installTime{UNKNOWN_VALUE}
        {
            const file_io::FileIOUtils ioUtils;
            const auto rows { Utils::split(ioUtils.getFileContent(ctx.filePath + "/" + ctx.package + "/" + ctx.version + "/.brew/" + ctx.package + ".rb"), '\n')};

            for (const auto& row : rows)
            {
                auto rowParsed { Utils::trim(row) };

                if (Utils::startsWith(rowParsed, "desc "))
                {
                    Utils::replaceFirst(rowParsed, "desc ", "");
                    Utils::replaceAll(rowParsed, "\"", "");
                    m_description = rowParsed;
                    break;
                }
            }

            /* Some brew packages have the version in the name separated by a '@'
              but we'll only remove the last occurrence if it matches with a version
              in case there is a '@' in the package name */
            const auto pos { m_name.rfind('@') };

            if (pos != std::string::npos)
            {
                if (std::isdigit(m_name[pos + 1]))
                {
                    m_name.resize(pos);
                }
            }
        }

        ~BrewWrapper() = default;

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

        int64_t size() const override
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
        std::string m_name;
        std::string m_version;
        std::string m_groups;
        std::string m_description;
        std::string m_architecture;
        const std::string m_format;
        std::string m_osPatch;
        const std::string m_source;
        const std::string m_location;
        std::string m_priority;
        int64_t m_size;
        std::string m_vendor;
        std::string m_installTime;
        std::string m_multiarch;
};


#endif //_BREW_WRAPPER_H
