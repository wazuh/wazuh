/*
 * Wazuh SYSINFO
 * Copyright (C) 2015-2020, Wazuh Inc.
 * December 14, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PKG_WRAPPER_H
#define _PKG_WRAPPER_H

#include <fstream>
#include "stringHelper.h"
#include "ipackageWrapper.h"
#include "sharedDefs.h"
#include "timeHelper.h"
#include "plist/plist.h"

static const std::string APP_INFO_PATH      { "Contents/Info.plist" };
static const std::string PLIST_BINARY_START { "bplist00"            };

class PKGWrapper final : public IPackageWrapper
{
public:
    explicit PKGWrapper(const PackageContext& ctx)
      : m_name{UNKNOWN_VALUE}
      , m_version{UNKNOWN_VALUE}
      , m_groups{UNKNOWN_VALUE}
      , m_description{UNKNOWN_VALUE}
      , m_architecture{UNKNOWN_VALUE}
      , m_format{"pkg"}
      , m_osPatch{UNKNOWN_VALUE}
      , m_scanTime{Utils::getCurrentTimestamp()}
    {
        getPkgData(ctx.filePath+ "/" + ctx.package + "/" + APP_INFO_PATH);
    }

    ~PKGWrapper() = default;

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
    std::string scanTime() const override
    {
        return m_scanTime;
    }

private:
    void getPkgData(const std::string& filePath)
    {
        std::fstream file {filePath, std::ios_base::in};
        static const auto getValueFnc
        {
            [](const std::string& val)
            {
                const auto start{val.find(">")};
                const auto end{val.rfind("<")};
                return val.substr(start+1, end - start -1);
            }
        };
        if (file.is_open())
        {
            std::string line;
            if (std::getline(file, line) && Utils::startsWith(line, PLIST_BINARY_START))
            {
                // Apple binary plist - let's convert it to XML format
                binaryToXML();
            }

            while(!line.empty() && std::getline(file, line))
            {
                line = Utils::trim(line," \t");

                if (line == "<key>CFBundleName</key>" &&
                    std::getline(file, line))
                {
                    m_name = getValueFnc(line);
                }
                else if (line == "<key>CFBundleShortVersionString</key>" &&
                         std::getline(file, line))
                {
                    m_version = getValueFnc(line);
                }
                else if (line == "<key>LSApplicationCategoryType</key>" &&
                         std::getline(file, line))
                {
                    m_groups = getValueFnc(line);
                }
                else if (line == "<key>CFBundleIdentifier</key>" &&
                         std::getline(file, line))
                {
                    m_description = getValueFnc(line);
                }
            }
        }
    }

    void binaryToXML()
    {

        plist_t rootNode { nullptr };

        // plist_from_bin
        // plist_to_xml
    }

    std::string m_name;
    std::string m_version;
    std::string m_groups;
    std::string m_description;
    std::string m_architecture;
    const std::string m_format;
    std::string m_osPatch;
    const std::string m_scanTime;
};

#endif //_PKG_WRAPPER_H
