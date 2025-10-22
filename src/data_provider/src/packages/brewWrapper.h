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
#include "filesystemHelper.h"
#include "json.hpp"

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
            const std::string packagePath = ctx.filePath + "/" + ctx.package + "/" + ctx.version;
            const std::string installReceiptPath = packagePath + "/INSTALL_RECEIPT.json";
            const std::string legacyBrewPath = packagePath + "/.brew/" + ctx.package + ".rb";

            // Try modern INSTALL_RECEIPT.json format first (Homebrew 2.0+)
            if (Utils::existsRegular(installReceiptPath))
            {
                try
                {
                    const auto jsonContent = Utils::getFileContent(installReceiptPath);
                    const auto jsonData = nlohmann::json::parse(jsonContent);

                    // Extract architecture (e.g., "arm64", "x86_64")
                    if (jsonData.contains("arch") && !jsonData["arch"].is_null())
                    {
                        m_architecture = jsonData["arch"].get<std::string>();
                    }

                    // Extract install time (Unix timestamp)
                    if (jsonData.contains("time") && !jsonData["time"].is_null())
                    {
                        m_installTime = std::to_string(jsonData["time"].get<int64_t>());
                    }

                    // Extract vendor/tap information
                    if (jsonData.contains("source") && jsonData["source"].contains("tap") && !jsonData["source"]["tap"].is_null())
                    {
                        m_vendor = jsonData["source"]["tap"].get<std::string>();
                    }

                    // Extract version from source if available (more accurate than directory name)
                    if (jsonData.contains("source") && jsonData["source"].contains("version") && !jsonData["source"]["version"].is_null())
                    {
                        const auto sourceVersion = jsonData["source"]["version"].get<std::string>();

                        if (!sourceVersion.empty())
                        {
                            m_version = sourceVersion;
                        }
                    }
                }
                catch (const std::exception& e)
                {
                    // If JSON parsing fails, continue with default values
                }
            }
            // Fallback to legacy .brew/*.rb format for older Homebrew versions
            else if (Utils::existsRegular(legacyBrewPath))
            {
                const auto rows { Utils::split(Utils::getFileContent(legacyBrewPath), '\n')};

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
